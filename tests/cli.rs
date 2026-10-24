use constitutive_action::v1::ExecutionOutcome;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};
use tgc_demo::{audit, scenario::Report, store::Host};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "tgc-cli-{}-{}",
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
fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_tgc-demo"))
        .args(args)
        .output()
        .unwrap()
}
fn path(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn cli_run_inspect_verify_and_actual_replay() {
    let t = Temp::new();
    let run = t.0.join("run");
    let replay = t.0.join("replay");
    let result = cli(&["run", "--out", path(&run), "--json"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: Report = serde_json::from_slice(&result.stdout).unwrap();
    assert!(report.all_four_outcomes);
    for args in [
        vec!["verify", path(&run)],
        vec!["inspect", path(&run), "stub:0"],
        vec!["inspect", path(&run), "queue"],
        vec!["inspect", path(&run), "exception"],
    ] {
        let result = cli(&args);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let result = cli(&["replay", path(&run), "2b", "--out", path(&replay)]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("DecisionRequired"));
    assert!(!String::from_utf8_lossy(&result.stdout).contains("Permission_Required"));
    assert!(
        report.primary_metrics["kernel_decisions"]
            .get("DecisionRequired")
            .is_some()
    );
    assert!(
        report.primary_metrics["kernel_decisions"]
            .get("Permission_Required")
            .is_none()
    );
    let repeated: Report =
        serde_json::from_slice(&fs::read(replay.join("report.json")).unwrap()).unwrap();
    assert_eq!(report.semantic_hash, repeated.semantic_hash);
    assert!(!cli(&["run", "--out", path(&run)]).status.success()); // preserve existing output
}

#[test]
fn historical_outcome_spelling_verifies_and_replays_without_rewriting() {
    use serde_json::{Value, json};
    use tgc_demo::{digest, scenario, store::State};
    let t = Temp::new();
    let run = t.0.join("historical");
    let replay = t.0.join("replay");
    assert!(cli(&["run", "--out", path(&run)]).status.success());
    let mut report: Value =
        serde_json::from_slice(&fs::read(run.join("report.json")).unwrap()).unwrap();
    let mut semantic = Vec::new();
    let mut preserved = Vec::new();
    // Construct the old representation only in this disposable test run.
    for (stream, log, metrics) in [
        ("primary", "events.jsonl", "primary_metrics"),
        ("peer", "peer-events.jsonl", "peer_metrics"),
    ] {
        let file = run.join(stream).join("state.json");
        let mut envelope: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
        let mut state: State = serde_json::from_value(envelope["value"].clone()).unwrap();
        for event in &mut state.events {
            if event.outcome.as_deref() == Some("DecisionRequired") {
                event.outcome = Some("Permission_Required".into());
                assert_eq!(event.data["decision"]["kind"], "decision_required");
            }
            if event.kind == "action_complete" && event.data["outcome"] == "DecisionRequired" {
                event.data["outcome"] = json!("Permission_Required");
            }
        }
        for i in 0..state.events.len() {
            let previous = i.checked_sub(1).map(|j| state.events[j].clone());
            state.events[i].seal(previous.as_ref());
        }
        audit::verify_transcript(&state.events).unwrap();
        report[metrics] = audit::metrics(&state.events);
        semantic.extend(state.events.iter().map(audit::Event::semantic));
        envelope["value"] = serde_json::to_value(&state).unwrap();
        envelope["checksum"] = json!(digest(&state));
        fs::write(&file, serde_json::to_vec(&envelope).unwrap()).unwrap();
        scenario::export_events(&run.join(log), &state.events).unwrap();
        preserved.extend([file, run.join(log)]);
    }
    report["semantic_hash"] = json!(digest(&semantic));
    fs::write(
        run.join("semantic.json"),
        serde_json::to_vec(&semantic).unwrap(),
    )
    .unwrap();
    fs::write(
        run.join("report.json"),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
    preserved.extend([run.join("semantic.json"), run.join("report.json")]);
    let before: Vec<_> = preserved.iter().map(|f| fs::read(f).unwrap()).collect();
    for args in [
        vec!["verify", path(&run)],
        vec!["replay", path(&run), "2b", "--out", path(&replay)],
    ] {
        let result = cli(&args);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let output = fs::read_to_string(replay.join("events.jsonl")).unwrap();
    assert!(output.contains("DecisionRequired"));
    assert!(!output.contains("Permission_Required"));
    for (file, bytes) in preserved.iter().zip(before) {
        assert_eq!(
            fs::read(file).unwrap(),
            bytes,
            "{} was rewritten",
            file.display()
        );
    }
    // A label migration must not hide an unrelated change in replay semantics.
    let mut altered = serde_json::to_value(&semantic).unwrap();
    altered[0]["data"]["unexpected"] = json!(true);
    assert_ne!(
        audit::replay_semantics(serde_json::to_value(&semantic).unwrap()),
        audit::replay_semantics(altered.clone())
    );
    fs::write(
        run.join("semantic.json"),
        serde_json::to_vec(&altered).unwrap(),
    )
    .unwrap();
    let rejected = t.0.join("rejected-replay");
    assert!(
        !cli(&["replay", path(&run), "2b", "--out", path(&rejected)])
            .status
            .success()
    );
    assert!(!rejected.exists());
}

#[test]
fn process_crashes_recover_original_attempt_without_double_effects() {
    for point in ["after-reservation", "after-external"] {
        let t = Temp::new();
        let result = Command::new(env!("CARGO_BIN_EXE_tgc-demo"))
            .args(["run", "--out", path(&t.0)])
            .env("TGC_DEMO_CRASH_AT", format!("{point}:ordinary"))
            .output()
            .unwrap();
        assert_eq!(
            result.status.code(),
            Some(86),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let host = Host::open(t.0.join("primary")).unwrap();
        let state = host.state().unwrap();
        let record = &state.records["ordinary"];
        assert!(record.receipt.is_none());
        let ticket = record.ticket.clone().unwrap();
        let before = host.occurrences().unwrap();
        let result = cli(&["recover", path(&t.0)]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let reopened = Host::open(t.0.join("primary")).unwrap();
        let recovered = reopened.state().unwrap();
        let record = &recovered.records["ordinary"];
        assert_eq!(record.ticket.as_ref(), Some(&ticket));
        assert!(matches!(
            record.receipt.as_ref().unwrap().outcome,
            ExecutionOutcome::Confirmed { .. }
        ));
        assert_eq!(
            reopened.occurrences().unwrap(),
            before + usize::from(point == "after-reservation")
        );
        let count = reopened.occurrences().unwrap();
        assert!(cli(&["recover", path(&t.0)]).status.success());
        assert_eq!(reopened.occurrences().unwrap(), count);
        audit::verify_transcript(&recovered.events).unwrap();
    }
}

#[test]
fn cli_reports_invalid_selections() {
    assert!(!cli(&["run", "--topology", "unrecognized"]).status.success());
    assert!(!cli(&["run", "--composition"]).status.success());
    assert!(!cli(&["unrecognized"]).status.success());
    assert!(cli(&["--help"]).status.success());
}
