mod local;

use crate::{Result, digest, ensure};
use constitutive_action::v1::{DecisionKind, evaluate, validate_receipt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

pub fn outcome(kind: DecisionKind) -> &'static str {
    match kind {
        DecisionKind::Permitted => "Permitted",
        DecisionKind::Prevented => "Prevented",
        DecisionKind::DecisionRequired => "DecisionRequired",
        DecisionKind::Indeterminate => "Indeterminate",
    }
}

/// Accept the historical summary spelling without changing stored event bytes.
pub fn outcome_matches(recorded: &str, kind: DecisionKind) -> bool {
    recorded == outcome(kind)
        || (kind == DecisionKind::DecisionRequired && recorded == "Permission_Required")
}

/// Compare verified replay transcripts, tolerating only the old summary spelling.
/// Nested kernel decisions, payloads and other evidence remain exact.
pub fn replay_semantics(mut value: Value) -> Value {
    if let Some(events) = value.as_array_mut() {
        for event in events {
            if event["kind"] == "decision" && event["outcome"] == "Permission_Required" {
                event["outcome"] = json!("DecisionRequired");
            }
            if event["kind"] == "action_complete"
                && event["data"]["outcome"] == "Permission_Required"
            {
                event["data"]["outcome"] = json!("DecisionRequired");
            }
        }
    }
    value
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub sequence: u64,
    pub timestamp_unix_ns: String,
    pub movement: String,
    pub beat: String,
    pub topology: String,
    pub kind: String,
    pub outcome: Option<String>,
    pub latency_ns: Option<u128>,
    pub data: Value,
    pub previous_hash: String,
    pub hash: String,
}
impl Event {
    pub fn new(movement: &str, beat: &str, topology: &str, kind: &str, data: Value) -> Self {
        Self {
            sequence: 0,
            timestamp_unix_ns: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .to_string(),
            movement: movement.into(),
            beat: beat.into(),
            topology: topology.into(),
            kind: kind.into(),
            outcome: None,
            latency_ns: None,
            data,
            previous_hash: String::new(),
            hash: String::new(),
        }
    }
    pub fn seal(&mut self, previous: Option<&Event>) {
        self.sequence = previous.map_or(1, |e| e.sequence + 1);
        self.previous_hash = previous.map_or(String::new(), |e| e.hash.clone());
        self.hash.clear();
        self.hash = digest(self);
    }
    pub fn semantic(&self) -> Value {
        json!({"sequence":self.sequence,"movement":self.movement,"beat":self.beat,"topology":self.topology,"kind":self.kind,"outcome":self.outcome,"data":self.data})
    }
}

pub fn verify_events(events: &[Event]) -> Result<()> {
    for (i, event) in events.iter().enumerate() {
        let mut copy = event.clone();
        copy.seal(i.checked_sub(1).map(|j| &events[j]));
        ensure(
            copy.hash == event.hash
                && copy.sequence == event.sequence
                && copy.previous_hash == event.previous_hash,
            "audit chain invalid",
        )?;
    }
    Ok(())
}

pub fn metrics(events: &[Event]) -> Value {
    let mut kinds = BTreeMap::<String, u64>::new();
    let mut outcomes = BTreeMap::<String, u64>::new();
    let mut latencies = Vec::new();
    for e in events {
        *kinds.entry(e.kind.clone()).or_default() += 1;
        if e.kind == "decision" {
            if let Some(o) = &e.outcome {
                *outcomes.entry(o.clone()).or_default() += 1;
            }
        }
        if e.kind == "composition_complete" {
            latencies.push(e.latency_ns.unwrap_or(0));
        }
    }
    let count = |name: &str| *kinds.get(name).unwrap_or(&0);
    json!({
        "schema_version": 2,
        "event_counts": kinds, "kernel_decisions":outcomes,
        "path_activation_composition_and_promotion_events":count("path_active") + count("composition_complete") + count("promotion_complete"),
        "path_activation_exception_and_promotion_events":count("path_active") + count("override_accountability_complete") + count("promotion_complete"),
        "decision_discovery_and_recipient_validation_events":count("decision") + count("discovery_read") + count("recipient_validation"),
        "prevented_decisions":outcomes.get("Prevented").copied().unwrap_or(0),
        "discretionary_onboarding_events":count("discretionary_onboarding"),
        "composition_latency_ns":latencies,
        "fork_events":count("fork_published"), "promotions":count("promotion_complete"),
        "indeterminate_in":count("queued"), "indeterminate_out":count("resolution_complete"),
        "override_requests":count("override_requested"), "exception_accountability_records":count("override_accountability_complete"),
        "latency_scope":"local in-process arrival through first confirmed action; not network performance",
        "anonymity_scope":"unsigned simulation; public references identify acts and seats, not civil identities"
    })
}

/// Read-only compatibility for historical reports; new runs emit v2 names.
pub(crate) fn metrics_for_report(
    events: &[Event],
    report: &serde_json::Value,
) -> Result<serde_json::Value> {
    let mut value = metrics(events);
    match report.get("schema_version") {
        Some(version) if version == 2 => Ok(value),
        None => {
            let object = value.as_object_mut().ok_or("metrics must be an object")?;
            object.remove("schema_version");
            for (current, legacy) in [
                (
                    "path_activation_composition_and_promotion_events",
                    "actions_expanded",
                ),
                (
                    "path_activation_exception_and_promotion_events",
                    "commitments_strengthened",
                ),
                (
                    "decision_discovery_and_recipient_validation_events",
                    "legibility_events",
                ),
                ("prevented_decisions", "enforcements_applied"),
                ("discretionary_onboarding_events", "coordination_events"),
                ("exception_accountability_records", "liability_completion"),
            ] {
                let count = object.remove(current).ok_or("missing metric")?;
                object.insert(legacy.into(), count);
            }
            Ok(value)
        }
        _ => Err("unsupported metrics schema".into()),
    }
}

#[cfg(test)]
mod metric_tests {
    use super::*;

    #[test]
    fn historical_spelling_only_matches_decision_required() {
        assert_eq!(outcome(DecisionKind::DecisionRequired), "DecisionRequired");
        for kind in [
            DecisionKind::Permitted,
            DecisionKind::Prevented,
            DecisionKind::Indeterminate,
        ] {
            assert!(!outcome_matches("Permission_Required", kind));
        }
        assert!(outcome_matches(
            "Permission_Required",
            DecisionKind::DecisionRequired
        ));
        assert!(!outcome_matches(
            "PermissionRequired",
            DecisionKind::DecisionRequired
        ));
        assert_eq!(
            serde_json::to_value(DecisionKind::DecisionRequired).unwrap(),
            "decision_required"
        );
    }

    #[test]
    fn replay_alias_does_not_normalize_payloads_or_other_event_kinds() {
        let original = json!([
            {"kind":"decision", "outcome":"Permission_Required", "data":{"payload":"Permission_Required"}},
            {"kind":"action_complete", "data":{"outcome":"Permission_Required"}},
            {"kind":"other", "outcome":"Permission_Required", "data":{"outcome":"Permission_Required"}}
        ]);
        let normalized = replay_semantics(original.clone());
        assert_eq!(normalized[0]["outcome"], "DecisionRequired");
        assert_eq!(normalized[0]["data"], original[0]["data"]);
        assert_eq!(normalized[1]["data"]["outcome"], "DecisionRequired");
        assert_eq!(normalized[2], original[2]);
    }

    #[test]
    fn new_metrics_name_literal_counts_and_keep_legacy_read_compatibility() {
        let events: Vec<_> = [
            "path_active",
            "promotion_complete",
            "composition_complete",
            "override_accountability_complete",
            "discretionary_onboarding",
        ]
        .into_iter()
        .map(|kind| Event::new("test", "metrics", "test", kind, Value::Null))
        .collect();
        let current = metrics(&events);
        assert_eq!(current["schema_version"], 2);
        assert_eq!(
            current["path_activation_composition_and_promotion_events"],
            3
        );
        assert_eq!(current["path_activation_exception_and_promotion_events"], 3);
        assert_eq!(current["exception_accountability_records"], 1);
        assert_eq!(current["discretionary_onboarding_events"], 1);
        assert!(current.get("liability_completion").is_none());
        assert!(current.get("commitments_strengthened").is_none());
        let legacy = metrics_for_report(&events, &json!({})).unwrap();
        assert_eq!(legacy["liability_completion"], 1);
        assert_eq!(legacy["coordination_events"], 1);
        assert!(legacy.get("schema_version").is_none());
        assert!(metrics_for_report(&events, &json!({"schema_version":99})).is_err());
    }
}

/// Recompute kernel decisions/receipts and the container's recorded local
/// calculations. PoH authenticity, standing and seat ownership remain supplied
/// proof-system claims; this verifier does not replace PoH verification.
/// Historical events without a local-state snapshot receive the checks their
/// evidence supports, including predicates, interpretation and binding checks.
pub fn verify_transcript(events: &[Event]) -> Result<()> {
    verify_events(events)?;
    let mut decisions = BTreeMap::new();
    for event in events {
        if event.kind == "decision" {
            let intent = serde_json::from_value(event.data["intent"].clone())?;
            let snapshot = serde_json::from_value(event.data["snapshot"].clone())?;
            let admission = evaluate(&intent, &snapshot);
            for evidence in &snapshot.evidence {
                let content = event.data["evidence_objects"]
                    .get(&evidence.content_sha256)
                    .ok_or("self-contained evidence missing or changed")?;
                ensure(
                    digest(content) == evidence.content_sha256,
                    "self-contained evidence missing or changed",
                )?;
            }
            if let Some(books) = event.data["governance_material"]["rulebooks"].as_object() {
                for (reference, book) in books {
                    let book: crate::rules::Rulebook = serde_json::from_value(book.clone())?;
                    book.validate()?;
                    ensure(book.hash() == *reference, "rulebook material hash mismatch")?;
                }
            }
            local::verify(event, &intent, &snapshot)?;
            ensure(
                serde_json::to_value(&admission.decision)? == event.data["decision"],
                "decision does not reproduce",
            )?;
            ensure(
                event
                    .outcome
                    .as_deref()
                    .is_some_and(|recorded| outcome_matches(recorded, admission.decision.kind)),
                "outcome mapping mismatch",
            )?;
            decisions.insert(intent.proposal_id.clone(), (intent, snapshot));
        }
        if event.kind == "receipt" {
            let receipt: constitutive_action::v1::ActionReceipt =
                serde_json::from_value(event.data["receipt"].clone())?;
            let (intent, snapshot) = decisions
                .get(&receipt.proposal_id)
                .ok_or("receipt missing decision")?;
            validate_receipt(intent, &evaluate(intent, snapshot), &receipt)
                .map_err(|e| format!("invalid receipt: {e:?}"))?;
        }
    }
    Ok(())
}
