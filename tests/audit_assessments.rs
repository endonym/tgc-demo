use constitutive_action::v1::{self, ActionIntent, CheckResult, EvaluationSnapshot};
use serde_json::json;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
use tgc_demo::{
    audit::{self, Event},
    protocol::{Field, Route, Scene, Topology},
    scenario::{Fixture, constitute, facts, instruction},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn setup() -> (Temp, Fixture, Field) {
    let t = Temp(std::env::temp_dir().join(format!(
        "tgc-audit-assessment-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    )));
    let f = Fixture::new().unwrap();
    let mut field = f.field(&t.0, Topology::Constitutive).unwrap();
    constitute(&mut field, &f).unwrap();
    (t, f, field)
}
fn decision(field: &Field, id: &str) -> Event {
    field
        .host()
        .state()
        .unwrap()
        .events
        .into_iter()
        .find(|e| e.kind == "decision" && e.data["intent"]["proposal_id"] == id)
        .unwrap()
}
fn reseal(event: &mut Event) {
    let action: ActionIntent = serde_json::from_value(event.data["intent"].clone()).unwrap();
    let snapshot: EvaluationSnapshot =
        serde_json::from_value(event.data["snapshot"].clone()).unwrap();
    let admission = v1::evaluate(&action, &snapshot);
    event.data["decision"] = serde_json::to_value(&admission.decision).unwrap();
    event.outcome = Some(audit::outcome(admission.decision.kind).into());
    event.seal(None);
}
fn assert_rejected(event: Event, expected: &str) {
    // The altered log is internally hashed and its kernel decision reproduces.
    audit::verify_events(std::slice::from_ref(&event)).unwrap();
    let error = audit::verify_transcript(&[event]).unwrap_err().to_string();
    assert!(error.contains(expected), "{error}");
}
fn change_assessment(event: &mut Event, name: &str, value: CheckResult) {
    let assessment = event.data["snapshot"]["assessments"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|a| a["condition_id"] == name)
        .unwrap();
    assessment["result"] = serde_json::to_value(value).unwrap();
}

#[test]
fn audit_rejects_coherent_false_pass_for_prohibited_effect() {
    let (_t, f, mut field) = setup();
    let action = instruction(
        "temptation",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &facts("venue-B", 750),
        0,
    );
    assert_eq!(
        field
            .execute(&Scene::new("test", "audit"), &f.issuers, &action, 20)
            .unwrap(),
        v1::DecisionKind::Prevented
    );
    audit::verify_transcript(&field.host().state().unwrap().events).unwrap();
    let original = decision(&field, "temptation");
    let mut forged = original.clone();
    change_assessment(&mut forged, "scope", CheckResult::Pass);
    change_assessment(&mut forged, "delegation", CheckResult::Pass);
    reseal(&mut forged);
    assert_eq!(forged.data["decision"]["kind"], "permitted");
    assert_rejected(forged, "scope");
    // Delegation's local scope condition remains checkable without reconstructing PoH ownership.
    let mut forged = original;
    change_assessment(&mut forged, "delegation", CheckResult::Pass);
    reseal(&mut forged);
    assert_rejected(forged, "delegation");
}

#[test]
fn audit_checks_conditions_interpretation_and_bound_evidence() {
    let (_t, f, mut field) = setup();
    let scene = Scene::new("test", "audit");
    let mut missing = facts("venue-A", 600);
    missing.remove("capital_attestation");
    let action = instruction(
        "missing-fact",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &missing,
        0,
    );
    assert_eq!(
        field.execute(&scene, &f.issuers, &action, 20).unwrap(),
        v1::DecisionKind::Indeterminate
    );
    let mut forged = decision(&field, "missing-fact");
    change_assessment(&mut forged, "conditions", CheckResult::Pass);
    reseal(&mut forged);
    assert_rejected(forged, "conditions");

    let mut invalid = facts("venue-A", 600);
    invalid.insert("amount".into(), json!(1001));
    let action = instruction("bad-rule", &f.agent, &f.path, Route::Ordinary, &invalid, 0);
    field.execute(&scene, &f.issuers, &action, 20).unwrap();
    let mut forged = decision(&field, "bad-rule");
    change_assessment(&mut forged, "interpretation", CheckResult::Pass);
    reseal(&mut forged);
    assert_rejected(forged, "interpretation");

    let action = instruction(
        "honest",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &facts("venue-A", 600),
        0,
    );
    field.execute(&scene, &f.issuers, &action, 20).unwrap();
    audit::verify_transcript(&field.host().state().unwrap().events).unwrap();
    let mut forged = decision(&field, "honest");
    let intent: ActionIntent = serde_json::from_value(forged.data["intent"].clone()).unwrap();
    let mut payload: serde_json::Value =
        serde_json::from_slice(&intent.effect.canonical_payload).unwrap();
    payload["facts"]["amount"] = json!(799);
    forged.data["intent"]["effect"]["canonical_payload"] =
        serde_json::to_value(tgc_demo::canonical(&payload)).unwrap();
    reseal(&mut forged);
    assert_rejected(forged, "assessment facts differ");
}

#[test]
fn audit_cannot_skip_checks_by_removing_or_relinking_assessments() {
    let (_t, f, mut field) = setup();
    let action = instruction(
        "honest",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &facts("venue-A", 600),
        0,
    );
    field
        .execute(&Scene::new("test", "audit"), &f.issuers, &action, 20)
        .unwrap();
    let original = decision(&field, "honest");
    let mut forged = original.clone();
    forged.data["snapshot"]["assessments"]
        .as_array_mut()
        .unwrap()
        .retain(|a| a["condition_id"] != "scope");
    reseal(&mut forged);
    assert_rejected(forged, "assessment set changed");
    let mut forged = original.clone();
    let evidence = forged.data["snapshot"]["assessments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["condition_id"] == "conditions")
        .unwrap()["evidence_ids"]
        .clone();
    forged.data["snapshot"]["assessments"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|a| a["condition_id"] == "scope")
        .unwrap()["evidence_ids"] = evidence;
    reseal(&mut forged);
    assert_rejected(forged, "unrelated evidence");
    let mut forged = original.clone();
    forged.data["intent"]["effect"]["profile_id"] = json!("substituted-profile/v1");
    forged.data["snapshot"]["profile"]["effect_profile_id"] = json!("substituted-profile/v1");
    let changed: ActionIntent = serde_json::from_value(forged.data["intent"].clone()).unwrap();
    for evidence in forged.data["snapshot"]["evidence"].as_array_mut().unwrap() {
        evidence["action_fingerprint"] = json!(changed.fingerprint());
    }
    reseal(&mut forged);
    assert_eq!(forged.data["decision"]["kind"], "permitted");
    assert_rejected(forged, "effect profile was substituted");
    let mut forged = original;
    forged.data["governance_material"]["local_assessment_version"] = json!(1);
    forged.data["governance_material"]
        .as_object_mut()
        .unwrap()
        .remove("active_paths");
    reseal(&mut forged);
    assert_rejected(forged, "missing local active-path snapshot");
}

#[test]
fn historical_local_evidence_is_checked_without_claiming_missing_state() {
    let (_t, f, mut field) = setup();
    let action = instruction(
        "historical",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &facts("venue-A", 600),
        0,
    );
    field
        .execute(&Scene::new("test", "audit"), &f.issuers, &action, 20)
        .unwrap();
    let mut event = decision(&field, "historical");
    let material = event.data["governance_material"].as_object_mut().unwrap();
    material.remove("local_assessment_version");
    material.remove("active_paths");
    material.remove("commitments");
    reseal(&mut event);
    audit::verify_transcript(std::slice::from_ref(&event)).unwrap();
    change_assessment(&mut event, "scope", CheckResult::Fail);
    reseal(&mut event);
    assert_rejected(event, "scope");
}

#[test]
fn audit_accepts_absent_delegation_as_recorded_null_evidence() {
    let t = Temp(std::env::temp_dir().join(format!(
        "tgc-audit-no-delegation-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    )));
    let mut f = Fixture::new().unwrap();
    f.path.delegation = None;
    let mut field = f.field(&t.0, Topology::Constitutive).unwrap();
    constitute(&mut field, &f).unwrap();
    let action = instruction(
        "own-authority",
        &f.principal,
        &f.path,
        Route::Ordinary,
        &facts("venue-A", 600),
        0,
    );
    assert_eq!(
        field
            .execute(&Scene::new("test", "audit"), &f.issuers, &action, 20)
            .unwrap(),
        v1::DecisionKind::Permitted
    );
    audit::verify_transcript(&field.host().state().unwrap().events).unwrap();
    let mut forged = decision(&field, "own-authority");
    let evidence_id = forged.data["snapshot"]["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "delegation")
        .unwrap()["content_sha256"]
        .as_str()
        .unwrap()
        .to_string();
    forged.data["evidence_objects"]
        .as_object_mut()
        .unwrap()
        .remove(&evidence_id);
    reseal(&mut forged);
    assert_rejected(forged, "evidence missing");
}

#[test]
fn audit_requires_recorded_grant_evidence_not_a_coherent_false_pass() {
    let (_t, f, mut field) = setup();
    let a = instruction(
        "grant-audit",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &facts("venue-A", 500),
        0,
    );
    field
        .execute(&Scene::new("test", "grant-audit"), &f.issuers, &a, 20)
        .unwrap();
    let mut original = decision(&field, "grant-audit");
    original.seal(None);
    audit::verify_transcript(std::slice::from_ref(&original)).unwrap();
    let mut forged = original.clone();
    let null_hash = tgc_demo::digest(&serde_json::Value::Null);
    forged.data["evidence_objects"][&null_hash] = serde_json::Value::Null;
    let evidence = forged.data["snapshot"]["evidence"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|e| e["kind"] == "delegation-grant")
        .unwrap();
    evidence["content_sha256"] = json!(null_hash);
    reseal(&mut forged);
    assert_rejected(forged, "delegation-grant");
    let mut forged = original;
    forged.data["snapshot"]["assessments"]
        .as_array_mut()
        .unwrap()
        .retain(|a| a["condition_id"] != "delegation-grant");
    reseal(&mut forged);
    assert_rejected(forged, "assessment set changed");
}
