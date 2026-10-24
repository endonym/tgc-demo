//! Reconcile a completed local demo run. This checks the container's own stored
//! evidence and mock adapter; it does not attest external resources or replace PoH.
use crate::{
    Result, audit, digest, ensure,
    protocol::{Change, Discovery, Payload},
    scenario::Report,
    store::{Host, QueueItem, State},
};
use constitutive_action::v1::{
    ActionIntent, ActionReceipt, DecisionKind, Effect, EvaluationSnapshot, ExecutionOutcome,
    GateDecision,
};
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

fn same(a: &impl Serialize, b: &impl Serialize, message: &str) -> Result<()> {
    ensure(
        serde_json::to_value(a)? == serde_json::to_value(b)?,
        message,
    )
}

fn read_events(path: &Path) -> Result<Vec<audit::Event>> {
    fs::read_to_string(path)?
        .lines()
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn queue_context(intent: &ActionIntent) -> Result<String> {
    if intent.effect.operation == "apply" {
        Ok(serde_json::from_slice::<Payload>(&intent.effect.canonical_payload)?.path_ref)
    } else {
        Ok(serde_json::from_slice::<Change>(&intent.effect.canonical_payload)?.target)
    }
}

/// Check materialized records against the authoritative local event history and
/// the actual contents of this demo's adapter map. Completed runs must have a
/// receipt for every admitted dispatch; unresolved decisions may remain queued.
fn reconcile(state: &State, effects: &BTreeMap<String, Effect>) -> Result<()> {
    audit::verify_transcript(&state.events)?;
    let mut decisions = BTreeMap::<String, (ActionIntent, EvaluationSnapshot, GateDecision)>::new();
    let mut receipts = BTreeMap::<String, ActionReceipt>::new();
    let mut profiles = BTreeMap::new();
    let mut queue = BTreeMap::<String, QueueItem>::new();
    for event in &state.events {
        if event.kind == "decision" {
            let intent: ActionIntent = serde_json::from_value(event.data["intent"].clone())?;
            let snapshot: EvaluationSnapshot =
                serde_json::from_value(event.data["snapshot"].clone())?;
            let decision: GateDecision = serde_json::from_value(event.data["decision"].clone())?;
            ensure(
                !receipts.contains_key(&intent.proposal_id),
                "decision recorded after dispatch receipt",
            )?;
            if let Some((old, _, _)) = decisions.get(&intent.proposal_id) {
                same(old, &intent, "proposal changed within decision history")?;
            }
            for evidence in &snapshot.evidence {
                let object = state
                    .objects
                    .get(&evidence.content_sha256)
                    .ok_or("decision evidence missing from local objects")?;
                same(
                    object,
                    &event.data["evidence_objects"][&evidence.content_sha256],
                    "journal evidence differs from exported decision evidence",
                )?;
            }
            if intent.effect.profile_id == "generic-record/v1" && intent.effect.operation == "apply"
            {
                // Usage is a local historical fact, not a PoH claim. Include
                // reservations already ordered when this snapshot was taken,
                // including uncertain attempts; exclude this or later tickets.
                let expected = state
                    .records
                    .values()
                    .filter(|record| {
                        record.intent.authority_id == intent.authority_id
                            && record
                                .ticket
                                .as_ref()
                                .is_some_and(|ticket| ticket.order <= snapshot.sequence)
                    })
                    .count()
                    .checked_add(1)
                    .ok_or("local usage count overflow")?;
                let assessment = snapshot
                    .assessments
                    .iter()
                    .find(|assessment| assessment.condition_id == "interpretation")
                    .ok_or("missing local usage assessment")?;
                let evidence_id = assessment
                    .evidence_ids
                    .first()
                    .ok_or("missing local usage evidence binding")?;
                let evidence = snapshot
                    .evidence
                    .iter()
                    .find(|evidence| &evidence.evidence_id == evidence_id)
                    .ok_or("missing local usage evidence")?;
                let actual =
                    event.data["evidence_objects"][&evidence.content_sha256]["facts"]["host.count"]
                        .as_u64();
                ensure(
                    actual == Some(u64::try_from(expected)?),
                    "host.count differs from local reservation history",
                )?;
            }
            if decision.kind == DecisionKind::Indeterminate {
                queue
                    .entry(intent.proposal_id.clone())
                    .or_insert(QueueItem {
                        proposal_id: intent.proposal_id.clone(),
                        context_ref: queue_context(&intent)?,
                        reason: decision.reasons.join("; "),
                        status: "pending".into(),
                        resolution_proposal: None,
                    });
            }
            profiles.insert(intent.authority_id.clone(), snapshot.profile.fingerprint());
            decisions.insert(intent.proposal_id.clone(), (intent, snapshot, decision));
        } else if event.kind == "receipt" {
            let receipt: ActionReceipt = serde_json::from_value(event.data["receipt"].clone())?;
            let (intent, _, _) = decisions
                .get(&receipt.proposal_id)
                .ok_or("receipt has no local decision")?;
            if let Some(previous) = receipts.get(&receipt.proposal_id) {
                ensure(
                    !matches!(
                        previous.outcome,
                        ExecutionOutcome::Confirmed { .. } | ExecutionOutcome::Rejected { .. }
                    ),
                    "receipt appended after terminal outcome",
                )?;
            }
            if intent.effect.operation == "resolve"
                && matches!(receipt.outcome, ExecutionOutcome::Confirmed { .. })
            {
                let change: Change = serde_json::from_slice(&intent.effect.canonical_payload)?;
                let item = queue
                    .get_mut(
                        change
                            .queue_id
                            .as_deref()
                            .ok_or("resolution has no queue ID")?,
                    )
                    .ok_or("confirmed resolution has no queued decision")?;
                ensure(
                    item.status == "pending" && item.context_ref == change.target,
                    "resolution does not match pending local queue item",
                )?;
                item.status = "resolved".into();
                item.resolution_proposal = Some(intent.proposal_id.clone());
            }
            receipts.insert(receipt.proposal_id.clone(), receipt);
        }
    }
    ensure(
        state.records.len() == decisions.len(),
        "local records do not cover decision history",
    )?;
    same(
        &state.profiles,
        &profiles,
        "local profile index differs from decision history",
    )?;
    same(
        &state.queue,
        &queue,
        "local queue differs from decision and resolution history",
    )?;
    for (reference, object) in &state.objects {
        ensure(
            digest(object) == *reference,
            "content-addressed local object mismatch",
        )?;
    }
    let mut reserved_ids = BTreeSet::new();
    let mut orders = BTreeSet::new();
    for (id, (intent, snapshot, decision)) in &decisions {
        let record = state
            .records
            .get(id)
            .ok_or("decision missing local action record")?;
        same(
            &record.intent,
            intent,
            "local intent differs from decision history",
        )?;
        same(
            &record.snapshot,
            snapshot,
            "local snapshot differs from decision history",
        )?;
        same(
            &record.decision,
            decision,
            "local decision differs from decision history",
        )?;
        same(
            &record.receipt.as_ref(),
            &receipts.get(id),
            "local receipt differs from receipt history",
        )?;
        if decision.kind != DecisionKind::Permitted {
            ensure(
                record.ticket.is_none() && record.receipt.is_none(),
                "non-permitted action has a reservation or receipt",
            )?;
            continue;
        }
        let ticket = record
            .ticket
            .as_ref()
            .ok_or("completed run has admitted action without reservation")?;
        ensure(
            ticket.proposal_id == *id
                && ticket.fingerprint == intent.fingerprint()
                && ticket.attempt_id == format!("attempt:{}", digest(intent))
                && ticket.replay_id == format!("replay:{}", digest(intent))
                && ticket.order
                    == snapshot
                        .sequence
                        .checked_add(1)
                        .ok_or("reservation order overflow")?
                && ticket.order <= state.order
                && orders.insert(ticket.order)
                && reserved_ids.insert(ticket.replay_id.clone()),
            "local reservation does not match admitted action or ordering",
        )?;
        let receipt = record
            .receipt
            .as_ref()
            .ok_or("completed run has reserved action without receipt")?;
        ensure(
            receipt.attempt_id.as_ref() == Some(&ticket.attempt_id)
                && receipt.executor_id.as_deref() == Some("adapter:local"),
            "local receipt does not match reservation or adapter",
        )?;
        match &receipt.outcome {
            ExecutionOutcome::Confirmed { occurrence_id } => {
                ensure(
                    occurrence_id == &format!("occurrence:{}", digest(&ticket.replay_id)),
                    "confirmed occurrence ID does not match local replay identity",
                )?;
                let actual = effects
                    .get(&ticket.replay_id)
                    .ok_or("confirmed local occurrence missing from adapter")?;
                same(
                    actual,
                    &intent.effect,
                    "local adapter effect differs from admitted effect",
                )?;
            }
            ExecutionOutcome::Rejected { .. } => ensure(
                !effects.contains_key(&ticket.replay_id),
                "rejected action has a local occurrence",
            )?,
            ExecutionOutcome::Uncertain { .. } => {
                // An uncertain response does not establish absence. Any observed
                // local occurrence must still be this exact reserved effect.
                if let Some(actual) = effects.get(&ticket.replay_id) {
                    same(
                        actual,
                        &intent.effect,
                        "uncertain local effect differs from admitted effect",
                    )?;
                }
            }
            ExecutionOutcome::NotDispatched => {
                return Err("reserved action has not-dispatched receipt".into());
            }
        }
    }
    ensure(
        effects.keys().all(|id| reserved_ids.contains(id)),
        "local adapter contains an occurrence without a reservation",
    )?;
    Ok(())
}

/// Verify a completed exported run against both local stores, including report
/// counters. PoH assurance remains supplied by its verification boundary.
pub fn verify_run(root: &Path) -> Result<()> {
    let report: Report = serde_json::from_slice(&fs::read(root.join("report.json"))?)?;
    let mut semantic = Vec::new();
    let mut states = Vec::new();
    for (directory, filename, expected_metrics) in [
        ("primary", "events.jsonl", &report.primary_metrics),
        ("peer", "peer-events.jsonl", &report.peer_metrics),
    ] {
        let events = read_events(&root.join(filename))?;
        let host = Host::open_existing(root.join(directory))?;
        let state = host.state()?;
        let effects = host.recorded_effects()?;
        same(
            &state.events,
            &events,
            "exported log differs from persisted journal",
        )?;
        reconcile(&state, &effects)?;
        same(
            &audit::metrics_for_report(&events, expected_metrics)?,
            expected_metrics,
            "report metrics differ from local event history",
        )?;
        let bootstrap = state
            .field_bootstrap
            .as_ref()
            .ok_or("missing field bootstrap")?;
        same(
            &bootstrap["topology"],
            &serde_json::to_value(report.config.topology)?,
            "report topology differs from local bootstrap",
        )?;
        // A completed offline export must not change under verification.
        same(
            &state,
            &host.state()?,
            "local journal changed during verification",
        )?;
        semantic.extend(events.iter().map(audit::Event::semantic));
        states.push(state);
    }
    ensure(
        digest(&semantic) == report.semantic_hash,
        "semantic transcript hash mismatch",
    )?;
    let stored_semantic: Value = serde_json::from_slice(&fs::read(root.join("semantic.json"))?)?;
    same(
        &semantic,
        &stored_semantic,
        "semantic export differs from local event history",
    )?;
    let all_four = [
        "Permitted",
        "Prevented",
        "DecisionRequired",
        "Indeterminate",
    ]
    .iter()
    .all(|outcome| {
        states.iter().flat_map(|s| &s.events).any(|e| {
            e.outcome.as_deref().is_some_and(|name| {
                name == *outcome
                    || (*outcome == "DecisionRequired" && name == "Permission_Required")
            })
        })
    });
    ensure(
        all_four == report.all_four_outcomes,
        "report outcome count differs from local event history",
    )?;
    let pending = states
        .iter()
        .flat_map(|s| s.queue.values())
        .filter(|q| q.status == "pending")
        .count();
    ensure(
        pending == report.pending_queue_items,
        "report pending queue count differs from local state",
    )?;
    let discovery: Discovery = serde_json::from_slice(&fs::read(root.join("discovery.json"))?)?;
    for stub in &discovery.stubs {
        discovery.inspect(stub)?;
    }
    same(
        &discovery,
        &Discovery::from_state(&states[0])?,
        "discovery export differs from confirmed local history",
    )?;
    Ok(())
}
