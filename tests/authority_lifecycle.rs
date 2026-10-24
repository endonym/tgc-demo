//! Requirements-derived authority tests. PoH verification is assumed sound;
//! these tests exercise whom the container requires and what survives recovery.
use constitutive_action::v1::{AcceptanceState, DecisionKind as D, ExecutionOutcome};
use serde_json::json;
use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};
use tgc_demo::{audit, canonical, identity::Participant, protocol::*, rules::Verdict, scenario::*};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Case {
    root: PathBuf,
    keep: bool,
}
impl Case {
    fn new(name: &str) -> Self {
        let configured = std::env::var_os("TGC_COVERAGE_EVIDENCE");
        let root = configured
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::temp_dir().join(format!(
                    "tgc-authority-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::SeqCst)
                ))
            })
            .join(name);
        assert!(
            !root.exists(),
            "case output must be fresh: {}",
            root.display()
        );
        fs::create_dir_all(&root).unwrap();
        Self {
            root,
            keep: configured.is_some(),
        }
    }
    fn save(&self, name: &str, field: &Field) {
        fs::write(
            self.root.join(format!("{name}-state.json")),
            canonical(&field.host().state().unwrap()),
        )
        .unwrap();
        fs::write(
            self.root.join(format!("{name}-discovery.json")),
            canonical(&field.discovery()),
        )
        .unwrap();
    }
}
impl Drop for Case {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
fn scene() -> Scene {
    Scene::new("coverage", "authority-lifecycle")
}
fn fixture() -> Fixture {
    let mut f = Fixture::new().unwrap();
    f.path.delegation.as_mut().unwrap().principal_seat = f.officer.seat(&f.path.context);
    assert!(!f.path.owners.contains(&f.officer.seat(&f.path.context)));
    f
}
fn consent(field: &mut Field, f: &Fixture) {
    for verb in ["propose", "accept"] {
        assert_eq!(
            govern(
                field,
                f,
                &scene(),
                &format!("initial-{verb}"),
                change(
                    verb,
                    &f.path.reference(),
                    (verb == "propose").then(|| f.path.clone())
                ),
                &[&f.principal, &f.counterparty, &f.officer, &f.agent]
            )
            .unwrap(),
            D::Permitted
        );
    }
}
fn execute(
    field: &mut Field,
    f: &Fixture,
    id: &str,
    actor: &Participant,
    path: &Commitment,
    expected: D,
) {
    let action = instruction(id, actor, path, Route::Ordinary, &facts("venue-A", 500), 0);
    assert_eq!(
        f.issuers.verify(
            &action.proof,
            &f.leads,
            &path.rulebook_ref,
            id,
            &action.intent.fingerprint(),
            &path.payoffs.on_violation,
            20
        ),
        Verdict::Pass
    );
    let before = field.host().occurrences().unwrap();
    assert_eq!(
        field.execute(&scene(), &f.issuers, &action, 20).unwrap(),
        expected,
        "{id}"
    );
    assert_eq!(
        field.host().occurrences().unwrap(),
        before + usize::from(expected == D::Permitted),
        "{id}: effect count"
    );
    let state = field.host().state().unwrap();
    let event = state
        .events
        .iter()
        .rev()
        .find(|e| e.kind == "decision" && e.data["intent"]["proposal_id"] == id)
        .unwrap();
    assert_eq!(
        event.data["accountable_proof"],
        tgc_demo::digest(&action.proof)
    );
    if let Some(d) = &path.delegation {
        assert_eq!(action.intent.represented_principal_id, d.principal_seat);
    } else {
        assert_eq!(
            action.intent.represented_principal_id,
            action.intent.actor_id
        );
    }
}

#[test]
fn grantor_consent_does_not_replace_owner_or_controller_approval() {
    for topology in [Topology::Control, Topology::Constitutive] {
        for verb in ["propose", "accept", "amend", "promote"] {
            // Control requires its controller; amendments/promotions also require owners.
            let missing: &[usize] =
                if topology == Topology::Control && matches!(verb, "propose" | "accept") {
                    &[2]
                } else if topology == Topology::Control {
                    &[0, 1, 2]
                } else {
                    &[0, 1]
                };
            for omitted in missing {
                let c = Case::new(&format!("approval-{topology:?}-{verb}-missing-{omitted}"));
                let f = fixture();
                let mut field = Field::new(
                    &c.root.join("field"),
                    topology,
                    f.discovery.clone(),
                    f.leads.clone(),
                    f.agent.seat(&f.path.context),
                )
                .unwrap();
                if verb == "accept" {
                    assert_eq!(
                        govern(
                            &mut field,
                            &f,
                            &scene(),
                            "initial-propose",
                            change("propose", &f.path.reference(), Some(f.path.clone())),
                            &[&f.principal, &f.counterparty, &f.officer, &f.agent]
                        )
                        .unwrap(),
                        D::Permitted
                    );
                } else if verb != "propose" {
                    consent(&mut field, &f);
                }
                let mut candidate = f.path.clone();
                candidate.parent_ref = Some(f.path.reference());
                candidate.window[1] = 80;
                let mut update = change(
                    verb,
                    &f.path.reference(),
                    if verb == "propose" {
                        Some(f.path.clone())
                    } else if matches!(verb, "amend" | "promote") {
                        Some(candidate.clone())
                    } else {
                        None
                    },
                );
                if verb == "promote" {
                    resolve(&mut field, &f);
                    update.queue_id = Some("collision".into());
                }
                let all = [&f.principal, &f.counterparty, &f.agent, &f.officer];
                let signers: Vec<_> = all
                    .iter()
                    .enumerate()
                    .filter_map(|(i, p)| (i != *omitted).then_some(*p))
                    .collect();
                let before = field.host().occurrences().unwrap();
                assert_eq!(
                    govern(
                        &mut field,
                        &f,
                        &scene(),
                        "missing-approval",
                        update.clone(),
                        &signers
                    )
                    .unwrap(),
                    D::DecisionRequired
                );
                assert_eq!(field.host().occurrences().unwrap(), before);
                if matches!(verb, "amend" | "promote") {
                    assert!(
                        !field
                            .discovery()
                            .commitments
                            .contains_key(&candidate.reference())
                    );
                }
                c.save("denied", &field);
                assert_eq!(
                    govern(&mut field, &f, &scene(), "all-approvals", update, &all).unwrap(),
                    D::Permitted
                );
                assert_eq!(field.host().occurrences().unwrap(), before + 1);
                audit::verify_transcript(&field.host().state().unwrap().events).unwrap();
                c.save("allowed", &field);
            }
        }
    }
}

#[test]
fn control_addition_requires_grant_then_executes_after_restart() {
    let c = Case::new("control-addition");
    let mut f = fixture();
    let delegation = f.path.delegation.take().unwrap();
    let mut field = f.field(&c.root.join("field"), Topology::Control).unwrap();
    consent(&mut field, &f);
    let mut candidate = f.path.clone();
    candidate.parent_ref = Some(f.path.reference());
    candidate.delegation = Some(delegation);
    let update = change("amend", &f.path.reference(), Some(candidate.clone()));
    let before = field.host().occurrences().unwrap();
    assert_eq!(
        govern(
            &mut field,
            &f,
            &scene(),
            "missing-grant",
            update.clone(),
            &[&f.principal, &f.counterparty]
        )
        .unwrap(),
        D::DecisionRequired
    );
    assert_eq!(field.host().occurrences().unwrap(), before);
    assert!(
        !field
            .discovery()
            .commitments
            .contains_key(&candidate.reference())
    );
    assert_eq!(
        govern(
            &mut field,
            &f,
            &scene(),
            "with-grant",
            update,
            &[&f.principal, &f.counterparty, &f.officer]
        )
        .unwrap(),
        D::Permitted
    );
    drop(field);
    let mut field = Field::reopen(&c.root.join("field")).unwrap();
    execute(
        &mut field,
        &f,
        "new-granted-action",
        &f.agent,
        &candidate,
        D::Permitted,
    );
    execute(
        &mut field,
        &f,
        "other-actor",
        &f.counterparty,
        &candidate,
        D::Prevented,
    );
    execute(
        &mut field,
        &f,
        "superseded-path",
        &f.agent,
        &f.path,
        D::Prevented,
    );
    audit::verify_transcript(&field.host().state().unwrap().events).unwrap();
    c.save("final", &field);
}
fn resolve(field: &mut Field, f: &Fixture) {
    let mut data = facts("venue-A", 500);
    data.remove("bond");
    let a = instruction("collision", &f.agent, &f.path, Route::Ordinary, &data, 0);
    assert_eq!(
        field.execute(&scene(), &f.issuers, &a, 20).unwrap(),
        D::Indeterminate
    );
    let mut r = change("resolve", &f.path.reference(), None);
    r.queue_id = Some("collision".into());
    assert_eq!(
        govern(
            field,
            f,
            &scene(),
            "resolve",
            r,
            &[&f.principal, &f.counterparty, &f.agent]
        )
        .unwrap(),
        D::Permitted
    );
}
fn replacement(f: &Fixture, variation: &str) -> Commitment {
    let mut p = f.path.clone();
    p.parent_ref = Some(f.path.reference());
    match variation {
        "delegate" => {
            p.delegation.as_mut().unwrap().delegate_seat = f.counterparty.seat(&p.context)
        }
        "principal" => p.delegation.as_mut().unwrap().principal_seat = f.agent.seat(&p.context),
        "remove" => p.delegation = None,
        _ => panic!("unknown variation"),
    }
    p
}
fn check_replacement(
    field: &mut Field,
    f: &Fixture,
    candidate: &Commitment,
    variation: &str,
    phase: &str,
) {
    execute(
        field,
        f,
        &format!("{phase}-old-path"),
        &f.agent,
        &f.path,
        D::Prevented,
    );
    if variation == "delegate" {
        execute(
            field,
            f,
            &format!("{phase}-old-delegate"),
            &f.agent,
            candidate,
            D::Prevented,
        );
        execute(
            field,
            f,
            &format!("{phase}-new-delegate"),
            &f.counterparty,
            candidate,
            D::Permitted,
        );
    } else {
        execute(
            field,
            f,
            &format!("{phase}-new-terms"),
            &f.agent,
            candidate,
            D::Permitted,
        );
        // A real, correctly bound proof cannot revive the old represented principal.
        let mut wrong = instruction(
            &format!("{phase}-old-principal"),
            &f.agent,
            candidate,
            Route::Ordinary,
            &facts("venue-A", 500),
            0,
        );
        wrong.intent.represented_principal_id = f.officer.seat(&candidate.context);
        wrong.proof = f.agent.prove(
            &wrong.intent.proposal_id,
            &wrong.intent.fingerprint(),
            &candidate.payoffs.on_violation,
            0,
        );
        assert_eq!(
            f.issuers.verify(
                &wrong.proof,
                &f.leads,
                &candidate.rulebook_ref,
                &wrong.intent.proposal_id,
                &wrong.intent.fingerprint(),
                &candidate.payoffs.on_violation,
                20
            ),
            Verdict::Pass
        );
        let before = field.host().occurrences().unwrap();
        assert_eq!(
            field.execute(&scene(), &f.issuers, &wrong, 20).unwrap(),
            D::Prevented
        );
        assert_eq!(field.host().occurrences().unwrap(), before);
    }
    audit::verify_transcript(&field.host().state().unwrap().events).unwrap();
}
fn changed_authority(verb: &str, variation: &str) {
    for topology in [Topology::Control, Topology::Constitutive] {
        let c = Case::new(&format!("execute-{topology:?}-{verb}-{variation}"));
        let f = fixture();
        let mut field = f.field(&c.root.join("field"), topology).unwrap();
        consent(&mut field, &f);
        if verb == "promote" {
            resolve(&mut field, &f);
        }
        let candidate = replacement(&f, variation);
        let mut update = change(verb, &f.path.reference(), Some(candidate.clone()));
        if verb == "promote" {
            update.queue_id = Some("collision".into());
        }
        assert_eq!(
            govern(
                &mut field,
                &f,
                &scene(),
                "change",
                update,
                &[&f.principal, &f.counterparty, &f.officer, &f.agent]
            )
            .unwrap(),
            D::Permitted
        );
        assert_eq!(field.discovery().commitments[&f.path.reference()], f.path);
        check_replacement(&mut field, &f, &candidate, variation, "live");
        c.save("live", &field);
        drop(field);
        let mut field = Field::reopen(&c.root.join("field")).unwrap();
        check_replacement(&mut field, &f, &candidate, variation, "reopened");
        c.save("reopened", &field);
    }
}
#[test]
fn amended_delegate_execution_and_restart() {
    changed_authority("amend", "delegate");
}
#[test]
fn amended_principal_execution_and_restart() {
    changed_authority("amend", "principal");
}
#[test]
fn removed_delegation_execution_and_restart() {
    changed_authority("amend", "remove");
}
#[test]
fn promoted_delegate_execution_and_restart() {
    changed_authority("promote", "delegate");
}
#[test]
fn promoted_principal_execution_and_restart() {
    changed_authority("promote", "principal");
}
#[test]
fn promoted_removal_execution_and_restart() {
    changed_authority("promote", "remove");
}

// Child process uses the real store crash hooks. No process-global environment
// mutation in this multi-threaded test binary.
#[test]
fn governance_crash_child() {
    let Some(root) = std::env::var_os("TGC_COVERAGE_CHILD_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let verb = std::env::var("TGC_COVERAGE_VERB").unwrap();
    let variation = std::env::var("TGC_COVERAGE_VARIATION").unwrap();
    let topology = if std::env::var("TGC_COVERAGE_TOPOLOGY").unwrap() == "Control" {
        Topology::Control
    } else {
        Topology::Constitutive
    };
    let f = fixture();
    let mut field = f.field(&root, topology).unwrap();
    let candidate = replacement(&f, &variation);
    if verb == "accept" {
        assert_eq!(
            govern(
                &mut field,
                &f,
                &scene(),
                "initial-propose",
                change("propose", &f.path.reference(), Some(f.path.clone())),
                &[&f.principal, &f.counterparty, &f.officer]
            )
            .unwrap(),
            D::Permitted
        );
    } else if verb != "propose" {
        consent(&mut field, &f);
    }
    if verb == "promote" {
        resolve(&mut field, &f);
    }
    let mut update = change(
        &verb,
        &f.path.reference(),
        if verb == "propose" {
            Some(f.path.clone())
        } else if verb == "accept" {
            None
        } else {
            Some(candidate)
        },
    );
    if verb == "promote" {
        update.queue_id = Some("collision".into());
    }
    govern(
        &mut field,
        &f,
        &scene(),
        "crash-change",
        update,
        &[&f.principal, &f.counterparty, &f.officer, &f.agent],
    )
    .unwrap();
    panic!("expected crash hook to terminate child");
}
fn crash_matrix(verb: &str) {
    let variations: &[&str] = if matches!(verb, "amend" | "promote") {
        &["delegate", "principal", "remove"]
    } else {
        &["delegate"]
    };
    for topology in [Topology::Control, Topology::Constitutive] {
        for variation in variations {
            for point in ["after-reservation", "after-external"] {
                let c = Case::new(&format!("crash-{topology:?}-{verb}-{variation}-{point}"));
                let root = c.root.join("field");
                let result = Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "governance_crash_child", "--nocapture"])
                    .env("TGC_COVERAGE_CHILD_ROOT", &root)
                    .env("TGC_COVERAGE_VERB", verb)
                    .env("TGC_COVERAGE_VARIATION", variation)
                    .env("TGC_COVERAGE_TOPOLOGY", format!("{topology:?}"))
                    .env("TGC_DEMO_CRASH_AT", "".to_owned() + point + ":crash-change")
                    .output()
                    .unwrap();
                fs::write(c.root.join("child.stdout"), &result.stdout).unwrap();
                fs::write(c.root.join("child.stderr"), &result.stderr).unwrap();
                assert_eq!(result.status.code(), Some(86));
                let host = tgc_demo::store::Host::open_existing(&root).unwrap();
                let before_state = host.state().unwrap();
                let ticket = before_state.records["crash-change"].ticket.clone().unwrap();
                assert!(before_state.records["crash-change"].receipt.is_none());
                let before = host.occurrences().unwrap();
                let mut field = Field::reopen(&root).unwrap();
                let state = field.host().state().unwrap();
                assert_eq!(state.records["crash-change"].ticket.as_ref(), Some(&ticket));
                assert!(matches!(
                    state.records["crash-change"]
                        .receipt
                        .as_ref()
                        .unwrap()
                        .outcome,
                    ExecutionOutcome::Confirmed { .. }
                ));
                assert_eq!(
                    field.host().occurrences().unwrap(),
                    before + usize::from(point == "after-reservation")
                );
                let f = fixture();
                let candidate = replacement(&f, variation);
                let grantor = f.officer.seat(&f.path.context);
                assert!(state.records["crash-change"].snapshot.acceptances.iter().any(|a| matches!(&a.state, AcceptanceState::Accepted { by_principal_id, .. } if by_principal_id == &grantor)));
                let mut update = change(
                    verb,
                    &f.path.reference(),
                    if verb == "propose" {
                        Some(f.path.clone())
                    } else if verb == "accept" {
                        None
                    } else {
                        Some(candidate.clone())
                    },
                );
                if verb == "promote" {
                    update.queue_id = Some("collision".into());
                }
                let count = field.host().occurrences().unwrap();
                // Identical confirmed act may be replayed without another grant/effect.
                assert_eq!(
                    govern(&mut field, &f, &scene(), "crash-change", update, &[]).unwrap(),
                    D::Permitted
                );
                assert_eq!(field.host().occurrences().unwrap(), count);
                if matches!(verb, "amend" | "promote") {
                    check_replacement(&mut field, &f, &candidate, variation, "recovered");
                } else {
                    execute(
                        &mut field,
                        &f,
                        "recovered-action",
                        &f.agent,
                        &f.path,
                        if verb == "accept" {
                            D::Permitted
                        } else {
                            D::Prevented
                        },
                    );
                }
                c.save("recovered", &field);
                let count = field.host().occurrences().unwrap();
                drop(field);
                let field = Field::reopen(&root).unwrap();
                assert_eq!(field.host().occurrences().unwrap(), count);
                audit::verify_transcript(&field.host().state().unwrap().events).unwrap();
                c.save("second-reopen", &field);
                fs::write(c.root.join("result.json"), canonical(&json!({"child_exit":86,"recovered_ticket":ticket,"count_before_recovery":before,"count_final":count,"status":"pass"}))).unwrap();
            }
        }
    }
}
#[test]
fn proposal_crash_recovery() {
    crash_matrix("propose");
}
#[test]
fn activation_crash_recovery() {
    crash_matrix("accept");
}
#[test]
fn amendment_crash_recovery() {
    crash_matrix("amend");
}
#[test]
fn promotion_crash_recovery() {
    crash_matrix("promote");
}

#[test]
fn legacy_history_is_preserved_and_future_delegation_requires_reconstitution() {
    let c = Case::new("legacy-history");
    let source =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pre-consent-delegation");
    let root = c.root.join("field");
    fs::create_dir_all(&root).unwrap();
    for name in ["state.json", "adapter.json"] {
        fs::copy(source.join(name), root.join(name)).unwrap();
    }
    let host = tgc_demo::store::Host::open_existing(&root).unwrap();
    let before = host.state().unwrap();
    let count = host.occurrences().unwrap();
    let mut field = Field::reopen(&root).unwrap();
    assert_eq!(field.host().occurrences().unwrap(), count);
    for (id, record) in &before.records {
        assert_eq!(
            canonical(record),
            canonical(&field.host().state().unwrap().records[id])
        );
    }
    let f = fixture();
    let grantor = f.officer.seat(&f.path.context);
    for record in before
        .records
        .values()
        .filter(|r| matches!(r.intent.effect.operation.as_str(), "propose" | "accept"))
    {
        assert!(!record.snapshot.acceptances.iter().any(|a| matches!(&a.state, AcceptanceState::Accepted { by_principal_id, .. } if by_principal_id == &grantor)));
    }
    let action = instruction(
        "fresh-after-upgrade",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &facts("venue-A", 500),
        0,
    );
    assert_eq!(
        f.issuers.verify(
            &action.proof,
            &f.leads,
            &f.path.rulebook_ref,
            &action.intent.proposal_id,
            &action.intent.fingerprint(),
            &f.path.payoffs.on_violation,
            20
        ),
        Verdict::Pass
    );
    let result = field.execute(&scene(), &f.issuers, &action, 20).unwrap();
    assert_eq!(result, D::Prevented);
    assert_eq!(field.host().occurrences().unwrap(), count);
    let observation = json!({"decision":result,"effect_delta":0,"history_preserved":true,"policy":"fresh delegated actions require confirmed grantor consent"});
    fs::write(c.root.join("observation.json"), canonical(&observation)).unwrap();
    // An exact replay of the historical action neither creates another effect
    // nor retroactively supplies consent to new actions.
    let original = instruction(
        "acts-for-nonconsenting-principal",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &facts("venue-A", 750),
        0,
    );
    assert_eq!(
        field.execute(&scene(), &f.issuers, &original, 20).unwrap(),
        D::Permitted
    );
    assert_eq!(field.host().occurrences().unwrap(), count);
    let own = instruction(
        "own-after-upgrade",
        &f.counterparty,
        &f.path,
        Route::Composition,
        &facts("venue-A", 500),
        0,
    );
    assert_eq!(
        field.execute(&scene(), &f.issuers, &own, 20).unwrap(),
        D::Permitted
    );
    let mut candidate = f.path.clone();
    candidate.parent_ref = Some(f.path.reference());
    candidate.window[1] = 90;
    let update = change("amend", &f.path.reference(), Some(candidate.clone()));
    assert_eq!(
        govern(
            &mut field,
            &f,
            &scene(),
            "missing-legacy-consent",
            update.clone(),
            &[&f.principal, &f.counterparty]
        )
        .unwrap(),
        D::DecisionRequired
    );
    assert_eq!(
        govern(
            &mut field,
            &f,
            &scene(),
            "reconstituted-grant",
            update,
            &[&f.principal, &f.counterparty, &f.officer]
        )
        .unwrap(),
        D::Permitted
    );
    execute(
        &mut field,
        &f,
        "new-authorized-action",
        &f.agent,
        &candidate,
        D::Permitted,
    );
    execute(
        &mut field,
        &f,
        "old-path-stays-closed",
        &f.agent,
        &f.path,
        D::Prevented,
    );
    drop(field);
    let mut field = Field::reopen(&root).unwrap();
    execute(
        &mut field,
        &f,
        "authorized-after-reopen",
        &f.agent,
        &candidate,
        D::Permitted,
    );
    for (id, record) in &before.records {
        assert_eq!(
            canonical(record),
            canonical(&field.host().state().unwrap().records[id])
        );
    }
    audit::verify_transcript(&field.host().state().unwrap().events).unwrap();
    c.save("final", &field);
}

#[test]
fn legacy_inflight_recovery_cannot_create_an_unconsented_effect() {
    for already_occurred in [false, true] {
        let c = Case::new(&format!("legacy-inflight-{already_occurred}"));
        let root = c.root.join("field");
        fs::create_dir_all(&root).unwrap();
        let source =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pre-consent-delegation");
        // Project the authentic saved attempt onto the two durable crash gaps:
        // reservation persisted, with or without the external occurrence. This
        // is a test fixture transformation, not a rewrite performed by migration.
        let mut state: tgc_demo::store::State = serde_json::from_value(
            serde_json::from_slice::<serde_json::Value>(
                &fs::read(source.join("state.json")).unwrap(),
            )
            .unwrap()["value"]
                .clone(),
        )
        .unwrap();
        let id = "acts-for-nonconsenting-principal";
        let ticket = state.records[id].ticket.clone().unwrap();
        state.records.get_mut(id).unwrap().receipt = None;
        state.events.retain(|e| {
            !((e.kind == "receipt" && e.data["receipt"]["proposal_id"] == id)
                || (e.kind == "action_complete" && e.data["proposal_id"] == id))
        });
        for i in 0..state.events.len() {
            let previous = i.checked_sub(1).map(|j| state.events[j].clone());
            state.events[i].seal(previous.as_ref());
        }
        let mut effects: std::collections::BTreeMap<String, constitutive_action::v1::Effect> =
            serde_json::from_value(
                serde_json::from_slice::<serde_json::Value>(
                    &fs::read(source.join("adapter.json")).unwrap(),
                )
                .unwrap()["value"]
                    .clone(),
            )
            .unwrap();
        if !already_occurred {
            effects.remove(&ticket.replay_id);
        }
        fs::write(
            root.join("state.json"),
            canonical(&json!({"checksum":tgc_demo::digest(&state),"value":state})),
        )
        .unwrap();
        fs::write(
            root.join("adapter.json"),
            canonical(&json!({"checksum":tgc_demo::digest(&effects),"value":effects})),
        )
        .unwrap();
        let before = effects.len();
        let raw = tgc_demo::store::Host::open_existing(&root).unwrap();
        assert!(
            raw.recover().is_err(),
            "generic recovery bypassed activity migration"
        );
        assert_eq!(raw.occurrences().unwrap(), before);
        Field::recover_host(&raw).unwrap();
        let mut field = Field::reopen(&root).unwrap();
        assert_eq!(field.host().occurrences().unwrap(), before);
        let recovered = field.host().state().unwrap();
        assert_eq!(recovered.records[id].ticket.as_ref(), Some(&ticket));
        let outcome = &recovered.records[id].receipt.as_ref().unwrap().outcome;
        assert!(if already_occurred {
            matches!(outcome, ExecutionOutcome::Confirmed { .. })
        } else {
            matches!(outcome, ExecutionOutcome::Rejected { .. })
        });
        let f = fixture();
        let a = instruction(
            id,
            &f.agent,
            &f.path,
            Route::Ordinary,
            &facts("venue-A", 750),
            0,
        );
        field.execute(&scene(), &f.issuers, &a, 20).unwrap();
        assert_eq!(field.host().occurrences().unwrap(), before);
        audit::verify_transcript(&field.host().state().unwrap().events).unwrap();
        c.save("final", &field);
        drop(field);
        assert_eq!(
            Field::reopen(&root).unwrap().host().occurrences().unwrap(),
            before
        );
    }
}
