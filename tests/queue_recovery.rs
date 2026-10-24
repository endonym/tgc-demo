use constitutive_action::v1::DecisionKind;
use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};
use tgc_demo::{
    audit, canonical, digest,
    protocol::{Field, Route, Scene, Topology},
    scenario::{Fixture, change, constitute, facts, govern, instruction},
    store::{Host, State},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "tgc-queue-recovery-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        )))
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn write_state(root: &std::path::Path, state: &State) {
    fs::write(
        root.join("state.json"),
        canonical(&serde_json::json!({"checksum":digest(state),"value":state})),
    )
    .unwrap();
}

#[test]
fn crash_before_or_after_pending_commit_preserves_decision_queue_atomicity() {
    for point in ["before-pending-commit", "after-pending-commit"] {
        let temp = Temp::new();
        let result = Command::new(env!("CARGO_BIN_EXE_tgc-demo"))
            .args(["run", "--out", temp.0.to_str().unwrap()])
            .env("TGC_DEMO_CRASH_AT", format!("{point}:fork-collision"))
            .output()
            .unwrap();
        assert_eq!(
            result.status.code(),
            Some(86),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let root = temp.0.join("primary");
        let host = Host::open_existing(&root).unwrap();
        let state = host.state().unwrap();
        let committed = point == "after-pending-commit";
        assert_eq!(state.records.contains_key("fork-collision"), committed);
        assert_eq!(state.queue.contains_key("fork-collision"), committed);
        assert_eq!(
            state
                .events
                .iter()
                .filter(|e| e.kind == "queued" && e.data["proposal_id"] == "fork-collision")
                .count(),
            usize::from(committed)
        );
        audit::verify_transcript(&state.events).unwrap();
        let occurrences = host.occurrences().unwrap();
        let mut field = Field::reopen(&root).unwrap();
        assert_eq!(field.host().occurrences().unwrap(), occurrences);
        assert_eq!(
            field
                .host()
                .state()
                .unwrap()
                .queue
                .contains_key("fork-collision"),
            committed
        );
        if committed {
            let fixture = Fixture::new().unwrap();
            let mut resolution = change("resolve", &fixture.path.reference(), None);
            resolution.queue_id = Some("fork-collision".into());
            assert_eq!(
                govern(
                    &mut field,
                    &fixture,
                    &Scene::new("test", "resolve-after-crash"),
                    "recovered-resolution",
                    resolution,
                    &[&fixture.principal, &fixture.counterparty]
                )
                .unwrap(),
                DecisionKind::Permitted
            );
            drop(field);
            let field = Field::reopen(&root).unwrap();
            let state = field.host().state().unwrap();
            assert_eq!(state.queue["fork-collision"].status, "resolved");
            assert_eq!(
                state.queue["fork-collision"].resolution_proposal.as_deref(),
                Some("recovered-resolution")
            );
        }
    }
}

#[test]
fn reopen_repairs_legacy_missing_queue_and_preserves_confirmed_resolution() {
    let temp = Temp::new();
    let fixture = Fixture::new().unwrap();
    let mut field = fixture.field(&temp.0, Topology::Constitutive).unwrap();
    constitute(&mut field, &fixture).unwrap();
    let mut data = facts("venue-A", 600);
    data.remove("bond");
    let action = instruction(
        "unresolved",
        &fixture.agent,
        &fixture.path,
        Route::Ordinary,
        &data,
        0,
    );
    assert_eq!(
        field
            .execute(
                &Scene::new("test", "unknown"),
                &fixture.issuers,
                &action,
                20
            )
            .unwrap(),
        DecisionKind::Indeterminate
    );
    let mut state = field.host().state().unwrap();
    state.queue.clear();
    state
        .events
        .retain(|e| !(e.kind == "queued" && e.data["proposal_id"] == "unresolved"));
    for i in 0..state.events.len() {
        let previous = i.checked_sub(1).map(|j| state.events[j].clone());
        state.events[i].seal(previous.as_ref());
    }
    write_state(&temp.0, &state);
    drop(field);
    let mut field = Field::reopen(&temp.0).unwrap();
    let state = field.host().state().unwrap();
    assert_eq!(state.queue["unresolved"].status, "pending");
    assert_eq!(
        state.queue["unresolved"].context_ref,
        fixture.path.reference()
    );
    assert_eq!(
        state
            .events
            .iter()
            .filter(|e| e.kind == "queue_recovered")
            .count(),
        1
    );
    let mut resolution = change("resolve", &fixture.path.reference(), None);
    resolution.queue_id = Some("unresolved".into());
    assert_eq!(
        govern(
            &mut field,
            &fixture,
            &Scene::new("test", "resolve"),
            "resolved",
            resolution,
            &[&fixture.principal, &fixture.counterparty]
        )
        .unwrap(),
        DecisionKind::Permitted
    );
    // Also cover interruption after a confirmed resolution but before its
    // derived queue state was persisted by an older implementation.
    let mut state = field.host().state().unwrap();
    state.queue.clear();
    write_state(&temp.0, &state);
    drop(field);
    let field = Field::reopen(&temp.0).unwrap();
    let state = field.host().state().unwrap();
    assert_eq!(state.queue["unresolved"].status, "resolved");
    assert_eq!(
        state.queue["unresolved"].resolution_proposal.as_deref(),
        Some("resolved")
    );
    let count = state.events.len();
    drop(field);
    assert_eq!(
        Field::reopen(&temp.0)
            .unwrap()
            .host()
            .state()
            .unwrap()
            .events
            .len(),
        count
    );
}
