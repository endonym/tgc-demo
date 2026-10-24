use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};
use tgc_demo::{
    digest, local_audit,
    protocol::{RecipientPolicy, Topology},
    scenario::{self, Composition, Config},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "tgc-local-audit-{}-{}",
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
fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for item in fs::read_dir(from).unwrap() {
        let item = item.unwrap();
        if item.file_type().unwrap().is_dir() {
            copy_tree(&item.path(), &to.join(item.file_name()));
        } else {
            fs::copy(item.path(), to.join(item.file_name())).unwrap();
        }
    }
}
fn edit_json(path: &Path, change: impl FnOnce(&mut Value)) {
    let mut value: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    change(&mut value);
    fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
}
fn edit_store(path: &Path, change: impl FnOnce(&mut Value)) {
    edit_json(path, |envelope| {
        change(&mut envelope["value"]);
        envelope["checksum"] = json!(digest(&envelope["value"]));
    });
}

#[test]
fn all_completed_branches_reconcile_local_records_effects_and_reports() {
    let t = Temp::new();
    for topology in [Topology::Control, Topology::Constitutive] {
        for composition in [Composition::Reuse, Composition::Fork] {
            for downstream in [
                RecipientPolicy::Refuse,
                RecipientPolicy::Honour,
                RecipientPolicy::Unresolved,
            ] {
                let run =
                    t.0.join(format!("{topology:?}-{composition:?}-{downstream:?}"));
                scenario::run(
                    &run,
                    Config {
                        topology,
                        composition,
                        downstream,
                        ..Config::default()
                    },
                )
                .unwrap();
                local_audit::verify_run(&run).unwrap();
            }
        }
    }
}

#[test]
fn cli_verification_rejects_missing_local_stores_without_recreating_them() {
    let t = Temp::new();
    let original = t.0.join("original");
    scenario::run(&original, Config::default()).unwrap();
    for missing in [
        "primary/adapter.json",
        "peer/adapter.json",
        "primary/state.json",
        "peer/state.json",
    ] {
        let copy = t.0.join(missing.replace('/', "-"));
        copy_tree(&original, &copy);
        fs::remove_file(copy.join(missing)).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_tgc-demo"))
            .args(["verify", copy.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(!result.status.success(), "accepted missing {missing}");
        assert!(!String::from_utf8_lossy(&result.stdout).contains("Verified"));
        assert!(
            !copy.join(missing).exists(),
            "verification recreated {missing}"
        );
    }
}

#[test]
fn coherent_local_mutations_are_rejected_without_changing_the_event_log() {
    let t = Temp::new();
    let original = t.0.join("original");
    scenario::run(&original, Config::default()).unwrap();
    let original_events = fs::read(original.join("events.jsonl")).unwrap();
    for case in [
        "missing-records",
        "changed-intent",
        "changed-snapshot",
        "changed-ticket",
        "changed-receipt",
        "missing-queue",
        "changed-queue-status",
        "changed-effect",
        "missing-effect",
        "orphan-effect",
        "false-pending-count",
        "false-outcome-count",
        "false-metrics",
        "changed-semantic-export",
        "empty-discovery",
        "missing-stub",
        "extra-stub",
        "changed-discovery-epoch",
    ] {
        let copy = t.0.join(case);
        copy_tree(&original, &copy);
        match case {
            "empty-discovery" => edit_json(&copy.join("discovery.json"), |s| {
                *s = json!({"rulebooks":{},"interpretations":{},"commitments":{},"seats":{},
                    "moderators":[],"stubs":[],"revocation_epoch":0,"revocation_ref":""});
            }),
            "missing-stub" => edit_json(&copy.join("discovery.json"), |s| {
                s["stubs"].as_array_mut().unwrap().pop();
            }),
            "extra-stub" => edit_json(&copy.join("discovery.json"), |s| {
                let duplicate = s["stubs"][0].clone();
                s["stubs"].as_array_mut().unwrap().push(duplicate);
            }),
            "changed-discovery-epoch" => edit_json(&copy.join("discovery.json"), |s| {
                s["revocation_epoch"] = json!(999);
            }),
            "missing-records" => edit_store(&copy.join("primary/state.json"), |s| {
                s["records"] = json!({})
            }),
            "changed-intent" => edit_store(&copy.join("primary/state.json"), |s| {
                s["records"]["ordinary"]["intent"]["effect"]["destination"] =
                    json!("other-resource")
            }),
            "changed-snapshot" => edit_store(&copy.join("primary/state.json"), |s| {
                s["records"]["ordinary"]["snapshot"]["sequence"] = json!(999)
            }),
            "changed-ticket" => edit_store(&copy.join("primary/state.json"), |s| {
                s["records"]["ordinary"]["ticket"]["attempt_id"] = json!("different-attempt")
            }),
            "changed-receipt" => edit_store(&copy.join("primary/state.json"), |s| {
                s["records"]["ordinary"]["receipt"]["attempt_id"] = json!("different-attempt")
            }),
            "missing-queue" => {
                edit_store(&copy.join("primary/state.json"), |s| s["queue"] = json!({}))
            }
            "changed-queue-status" => edit_store(&copy.join("primary/state.json"), |s| {
                s["queue"]["fork-collision"]["status"] = json!("pending")
            }),
            "changed-effect" => edit_store(&copy.join("primary/adapter.json"), |s| {
                s.as_object_mut().unwrap().values_mut().next().unwrap()["destination"] =
                    json!("other-resource");
            }),
            "missing-effect" => edit_store(&copy.join("primary/adapter.json"), |s| {
                let key = s.as_object().unwrap().keys().next().unwrap().clone();
                s.as_object_mut().unwrap().remove(&key);
            }),
            "orphan-effect" => edit_store(&copy.join("primary/adapter.json"), |s| {
                let effect = s.as_object().unwrap().values().next().unwrap().clone();
                s["replay:unreserved"] = effect;
            }),
            "false-pending-count" => edit_json(&copy.join("report.json"), |s| {
                s["pending_queue_items"] = json!(999)
            }),
            "false-outcome-count" => edit_json(&copy.join("report.json"), |s| {
                s["all_four_outcomes"] = json!(false)
            }),
            "false-metrics" => edit_json(&copy.join("report.json"), |s| {
                s["primary_metrics"]["exception_accountability_records"] = json!(999)
            }),
            "changed-semantic-export" => edit_json(&copy.join("semantic.json"), |s| {
                s.as_array_mut().unwrap().remove(0);
            }),
            _ => unreachable!(),
        }
        assert_eq!(
            fs::read(copy.join("events.jsonl")).unwrap(),
            original_events
        );
        let state_before = fs::read(copy.join("primary/state.json")).unwrap();
        assert!(local_audit::verify_run(&copy).is_err(), "accepted {case}");
        assert_eq!(
            fs::read(copy.join("primary/state.json")).unwrap(),
            state_before
        );
    }
}

#[test]
fn inspection_and_recovery_do_not_initialize_a_missing_run() {
    let t = Temp::new();
    for args in [
        vec!["inspect", t.0.to_str().unwrap(), "queue"],
        vec!["recover", t.0.to_str().unwrap()],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_tgc-demo"))
            .args(args)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(!t.0.exists());
    }
}

#[test]
fn usage_count_is_rederived_from_reservations_even_in_a_consistent_transcript() {
    use constitutive_action::v1::{EvaluationSnapshot, evaluate};
    use tgc_demo::{audit, store::Host};
    let t = Temp::new();
    scenario::run(&t.0, Config::default()).unwrap();
    local_audit::verify_run(&t.0).unwrap();
    let mut state = Host::open_existing(t.0.join("primary"))
        .unwrap()
        .state()
        .unwrap();
    let index = state
        .events
        .iter()
        .position(|event| {
            event.kind == "decision" && event.data["intent"]["proposal_id"] == "ordinary"
        })
        .unwrap();
    let event = &mut state.events[index];
    let mut snapshot: EvaluationSnapshot =
        serde_json::from_value(event.data["snapshot"].clone()).unwrap();
    let evidence = snapshot
        .evidence
        .iter_mut()
        .find(|e| e.kind == "interpretation")
        .unwrap();
    let old_key = evidence.content_sha256.clone();
    let mut content = event.data["evidence_objects"][&old_key].clone();
    assert_eq!(content["facts"]["host.count"], json!(2));
    content["facts"]["host.count"] = json!(1);
    let key = digest(&content);
    evidence.content_sha256 = key.clone();
    evidence.evidence_id = format!("evidence:{key}");
    let evidence_id = evidence.evidence_id.clone();
    snapshot
        .assessments
        .iter_mut()
        .find(|a| a.condition_id == "interpretation")
        .unwrap()
        .evidence_ids = vec![evidence_id];
    event.data["evidence_objects"]
        .as_object_mut()
        .unwrap()
        .remove(&old_key);
    event.data["evidence_objects"][&key] = content.clone();
    state.objects.insert(key, content);
    let decision = evaluate(&state.records["ordinary"].intent, &snapshot).decision;
    event.data["snapshot"] = serde_json::to_value(&snapshot).unwrap();
    event.data["decision"] = serde_json::to_value(&decision).unwrap();
    let record = state.records.get_mut("ordinary").unwrap();
    record.snapshot = snapshot;
    record.decision = decision.clone();
    record.receipt.as_mut().unwrap().decision = decision.clone();
    for event in &mut state.events {
        if event.kind == "receipt" && event.data["receipt"]["proposal_id"] == "ordinary" {
            event.data["receipt"]["decision"] = serde_json::to_value(&decision).unwrap();
        }
    }
    for index in 0..state.events.len() {
        let previous = index.checked_sub(1).map(|i| state.events[i].clone());
        state.events[index].seal(previous.as_ref());
    }
    // Every individual predicate still passes with the lowered positive count.
    // Kernel, local assessment, receipt and hash-chain verification all agree.
    audit::verify_transcript(&state.events).unwrap();
    edit_store(&t.0.join("primary/state.json"), |value| {
        *value = serde_json::to_value(&state).unwrap()
    });
    scenario::export_events(&t.0.join("events.jsonl"), &state.events).unwrap();
    let peer = Host::open_existing(t.0.join("peer"))
        .unwrap()
        .state()
        .unwrap();
    let semantic: Vec<_> = state
        .events
        .iter()
        .chain(&peer.events)
        .map(audit::Event::semantic)
        .collect();
    fs::write(
        t.0.join("semantic.json"),
        serde_json::to_vec(&semantic).unwrap(),
    )
    .unwrap();
    edit_json(&t.0.join("report.json"), |report| {
        report["semantic_hash"] = json!(digest(&semantic));
        report["primary_metrics"] = audit::metrics(&state.events);
    });
    let error = local_audit::verify_run(&t.0).unwrap_err().to_string();
    assert!(
        error.contains("host.count differs from local reservation history"),
        "{error}"
    );
}
