//! Flat activity protocol. Participants supply proofs; fields and independent
//! recipients validate them. All consequential changes pass the real kernel.
use crate::{
    Result,
    audit::{Event, outcome},
    canonical, digest, ensure,
    identity::{Issuers, Moderator, Proof},
    rules::{Facts, Interpretation, Predicate, Resolved, Rulebook, Verdict},
    store::{Host, QueueItem, Reservation},
};
use constitutive_action::v1::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::Instant,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Topology {
    Control,
    Constitutive,
}
impl Topology {
    pub fn label(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Constitutive => "constitutive",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payoffs {
    pub on_exceed_scope: String,
    pub on_violation: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegation {
    pub principal_seat: String,
    pub delegate_seat: String,
    pub scope: Predicate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commitment {
    pub context: String,
    pub rulebook_ref: String,
    pub interpretation_ref: String,
    pub rule_payload: Vec<crate::rules::Rule>,
    pub owners: Vec<String>,
    pub scope: Predicate,
    pub conditions: Predicate,
    pub composition: Predicate,
    pub exception: Predicate,
    pub approver_seat: String,
    pub delegation: Option<Delegation>,
    pub payoffs: Payoffs,
    pub window: [u64; 2],
    pub parent_ref: Option<String>,
}
impl Commitment {
    pub fn reference(&self) -> String {
        digest(self)
    }
}

/// Structured six-part stub: URNs contain ':' so delimiter splitting would be
/// ambiguous. A JSON object is the canonical representation of the six fields.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stub {
    pub rulebook_id: String,
    pub lead_id: String,
    pub mod_id: String,
    pub rule_interpretation_hash: String,
    pub commitment_ref: String,
    pub transaction_hash: String,
}
impl Stub {
    pub fn governance_hash(&self) -> String {
        digest(&(
            &self.rulebook_id,
            &self.lead_id,
            &self.mod_id,
            &self.rule_interpretation_hash,
            &self.commitment_ref,
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SeatRecord {
    pub path_ref: String,
    pub proof_ref: String,
    pub seat_ref: String,
    pub payoff_ref: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Discovery {
    pub rulebooks: BTreeMap<String, Rulebook>,
    pub interpretations: BTreeMap<String, Interpretation>,
    pub commitments: BTreeMap<String, Commitment>,
    pub seats: BTreeMap<String, SeatRecord>,
    pub moderators: Vec<Moderator>,
    pub stubs: Vec<Stub>,
    pub revocation_epoch: u64,
    pub revocation_ref: String,
}
impl Discovery {
    fn publish_record(&mut self, path: &Commitment, proof: &Proof, action: &ActionIntent) -> Stub {
        let seat = SeatRecord {
            path_ref: path.reference(),
            proof_ref: digest(proof),
            seat_ref: proof.seat_ref.clone(),
            payoff_ref: proof.payoff_ref.clone(),
        };
        let seat_ref = digest(&seat);
        self.seats.insert(seat_ref.clone(), seat);
        let stub = Stub {
            rulebook_id: path.rulebook_ref.clone(),
            lead_id: proof.lead_urn.clone(),
            mod_id: proof.moderator_urn.clone(),
            rule_interpretation_hash: path.interpretation_ref.clone(),
            commitment_ref: seat_ref,
            transaction_hash: digest(action),
        };
        self.stubs.push(stub.clone());
        stub
    }
    /// Reconstruct public discovery without recovery, writes or issuer secrets.
    /// Only confirmed acts add commitments, interpretations and publications.
    pub(crate) fn from_state(state: &crate::store::State) -> Result<Self> {
        let bootstrap = state
            .field_bootstrap
            .as_ref()
            .ok_or("missing field bootstrap")?;
        let mut discovery: Self = serde_json::from_value(bootstrap["discovery"].clone())?;
        let mut decisions = BTreeMap::<String, (ActionIntent, Proof)>::new();
        let mut confirmed = BTreeSet::new();
        for event in &state.events {
            if event.kind == "decision" {
                let material = &event.data["governance_material"];
                if let Some(value) = material.get("moderators") {
                    discovery.moderators = serde_json::from_value(value.clone())?;
                }
                if let Some(value) = material.get("revocation_epoch") {
                    discovery.revocation_epoch = serde_json::from_value(value.clone())?;
                }
                if let Some(value) = material.get("revocation_ref") {
                    discovery.revocation_ref = serde_json::from_value(value.clone())?;
                }
                let action: ActionIntent = serde_json::from_value(event.data["intent"].clone())?;
                let proof: Proof = serde_json::from_value(event.data["proof"].clone())?;
                decisions.insert(action.proposal_id.clone(), (action, proof));
            } else if event.kind == "receipt" {
                let receipt: ActionReceipt = serde_json::from_value(event.data["receipt"].clone())?;
                if !matches!(receipt.outcome, ExecutionOutcome::Confirmed { .. })
                    || !confirmed.insert(receipt.proposal_id.clone())
                {
                    continue;
                }
                let (action, proof) = decisions
                    .get(&receipt.proposal_id)
                    .ok_or("publication has no decision")?;
                if action.effect.operation == "apply" {
                    let payload: Payload =
                        serde_json::from_slice(&action.effect.canonical_payload)?;
                    let path = discovery
                        .commitments
                        .get(&payload.path_ref)
                        .ok_or("missing published path")?
                        .clone();
                    discovery.publish_record(&path, proof, action);
                    continue;
                }
                let change: Change = serde_json::from_slice(&action.effect.canonical_payload)?;
                match change.verb.as_str() {
                    "propose" | "accept" | "amend" | "promote" => {
                        let path = change
                            .candidate
                            .or_else(|| discovery.commitments.get(&change.target).cloned())
                            .ok_or("missing confirmed commitment")?;
                        discovery.commitments.insert(path.reference(), path);
                    }
                    "publish" => {
                        let path = discovery
                            .commitments
                            .get(&change.target)
                            .ok_or("missing published commitment")?
                            .clone();
                        discovery.publish_record(&path, proof, action);
                    }
                    "fork" => {
                        let child = change
                            .interpretation
                            .ok_or("missing confirmed interpretation")?;
                        discovery
                            .resolve(&child.rulebook_ref, &child.parent_ref)?
                            .extend(&child)?;
                        discovery.interpretations.insert(digest(&child), child);
                    }
                    _ => {}
                }
            }
        }
        Ok(discovery)
    }
    pub fn resolve(&self, book_ref: &str, interpretation_ref: &str) -> Result<Resolved> {
        let book = self.rulebooks.get(book_ref).ok_or("missing rulebook")?;
        ensure(book.hash() == book_ref, "rulebook hash mismatch")?;
        let mut chain = Vec::new();
        let mut cursor = interpretation_ref;
        let mut seen = BTreeSet::new();
        while cursor != book_ref {
            ensure(
                seen.insert(cursor.to_string()) && chain.len() < 4,
                "interpretation cycle/depth",
            )?;
            let next = self
                .interpretations
                .get(cursor)
                .ok_or("missing interpretation")?;
            ensure(digest(next) == cursor, "interpretation hash mismatch")?;
            chain.push(next);
            cursor = &next.parent_ref;
        }
        let mut resolved = Resolved::base(book)?;
        for child in chain.into_iter().rev() {
            resolved = resolved.extend(child)?;
        }
        Ok(resolved)
    }
    pub fn inspect(&self, stub: &Stub) -> Result<&Commitment> {
        let seat = self
            .seats
            .get(&stub.commitment_ref)
            .ok_or("missing anonymous seat record")?;
        ensure(digest(seat) == stub.commitment_ref, "seat hash mismatch")?;
        let path = self.commitments.get(&seat.path_ref).ok_or("missing path")?;
        ensure(
            path.reference() == seat.path_ref
                && path.rulebook_ref == stub.rulebook_id
                && path.interpretation_ref == stub.rule_interpretation_hash,
            "stub governance mismatch",
        )?;
        ensure(
            self.moderators.iter().any(|m| {
                m.urn == stub.mod_id
                    && m.lead_urn == stub.lead_id
                    && m.rulebook_ref == stub.rulebook_id
            }),
            "unrecognized Lead/Moderator relationship",
        )?;
        let resolved = self.resolve(&stub.rulebook_id, &stub.rule_interpretation_hash)?;
        ensure(
            resolved.rules == path.rule_payload,
            "path rule payload differs from interpretation",
        )?;
        Ok(path)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Route {
    Ordinary,
    Exception,
    Composition,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Endorsement {
    pub scoped_seat: String,
    pub proof: Proof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Instruction {
    pub intent: ActionIntent,
    pub path_ref: String,
    pub interpretation_ref: String,
    pub rule_payload: Vec<crate::rules::Rule>,
    pub route: Route,
    pub proof: Proof,
    pub endorsements: Vec<Endorsement>,
    pub delegate_kind: String,
    pub upstream: Option<Box<Instruction>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    pub facts: Facts,
    pub path_ref: String,
    pub interpretation_ref: String,
    pub rule_payload: Vec<crate::rules::Rule>,
    pub route: Route,
    pub upstream_ref: Option<String>,
}
impl Instruction {
    pub fn payload(&self, facts: Facts) -> Payload {
        Payload {
            facts,
            path_ref: self.path_ref.clone(),
            interpretation_ref: self.interpretation_ref.clone(),
            rule_payload: self.rule_payload.clone(),
            route: self.route,
            upstream_ref: self.upstream.as_ref().map(digest),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Change {
    pub verb: String,
    pub target: String,
    pub candidate: Option<Commitment>,
    pub queue_id: Option<String>,
    pub recipient_policy: Option<RecipientPolicy>,
    pub interpretation: Option<Interpretation>,
}

pub fn intent(
    id: &str,
    actor: &str,
    principal: &str,
    authority: &str,
    context: &str,
    operation: &str,
    destination: &str,
    payload: &impl Serialize,
) -> ActionIntent {
    ActionIntent {
        schema_version: 1,
        proposal_id: id.into(),
        actor_id: actor.into(),
        represented_principal_id: principal.into(),
        authority_id: authority.into(),
        context_id: context.into(),
        context_version: 1,
        effect: Effect {
            profile_id: "generic-record/v1".into(),
            profile_version: 1,
            operation: operation.into(),
            destination: destination.into(),
            canonical_payload: canonical(payload),
        },
    }
}

#[derive(Clone)]
pub struct Scene {
    pub movement: String,
    pub beat: String,
}
impl Scene {
    pub fn new(movement: &str, beat: &str) -> Self {
        Self {
            movement: movement.into(),
            beat: beat.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum RecipientPolicy {
    Refuse,
    Honour,
    Unresolved,
}

pub struct Field {
    host: Host,
    pub topology: Topology,
    discovery: Discovery,
    accepted_leads: BTreeSet<String>,
    controller_seat: String,
    active: BTreeSet<String>,
    recipient_policy: Option<RecipientPolicy>,
    last_confirmation: Cell<Option<Instant>>,
}

#[derive(Serialize, Deserialize)]
struct Bootstrap {
    topology: Topology,
    discovery: Discovery,
    accepted_leads: BTreeSet<String>,
    controller_seat: String,
    active: BTreeSet<String>,
    recipient_policy: Option<RecipientPolicy>,
}

impl Field {
    pub fn new(
        root: &Path,
        topology: Topology,
        discovery: Discovery,
        leads: BTreeSet<String>,
        controller_seat: String,
    ) -> Result<Self> {
        for (book, value) in &discovery.rulebooks {
            ensure(value.hash() == *book, "bad initial rulebook hash")?;
            value.validate()?;
        }
        let result = Self {
            host: Host::open_field(root, false)?,
            topology,
            discovery,
            accepted_leads: leads,
            controller_seat,
            active: BTreeSet::new(),
            recipient_policy: None,
            last_confirmation: Cell::new(None),
        };
        ensure(
            result.host.state()?.field_bootstrap.is_none(),
            "field exists; use Field::reopen",
        )?;
        result.save_bootstrap()?;
        Ok(result)
    }
    pub fn peer(
        root: &Path,
        topology: Topology,
        discovery: Discovery,
        leads: BTreeSet<String>,
        controller: String,
        policy: RecipientPolicy,
    ) -> Result<Self> {
        for stub in &discovery.stubs {
            discovery.inspect(stub)?;
        }
        let active = discovery
            .stubs
            .iter()
            .map(|s| discovery.inspect(s).map(Commitment::reference))
            .collect::<Result<BTreeSet<_>>>()?;
        let mut field = Self::new(root, topology, discovery, leads, controller)?;
        field.active = active;
        field.recipient_policy = Some(policy);
        field.save_bootstrap()?;
        Ok(field)
    }
    fn save_bootstrap(&self) -> Result<()> {
        let bootstrap = Bootstrap {
            topology: self.topology,
            discovery: self.discovery.clone(),
            accepted_leads: self.accepted_leads.clone(),
            controller_seat: self.controller_seat.clone(),
            active: self.active.clone(),
            recipient_policy: self.recipient_policy,
        };
        self.host.transaction(|s| {
            s.field_bootstrap = Some(serde_json::to_value(bootstrap)?);
            Ok(())
        })
    }
    /// Reconcile reserved effects, then rebuild derived field state from the
    /// confirmed immutable action log. No new governance decision is fabricated.
    /// Apply the container's migration policy before generic host recovery.
    /// Already observed effects are reconciled; unexecuted legacy attempts
    /// cannot acquire their first effect through a retry after upgrade.
    pub fn recover_host(host: &Host) -> Result<Vec<ActionReceipt>> {
        let owned = host.claim_field()?;
        Self::recover_owned_host(&owned)
    }
    fn recover_owned_host(host: &Host) -> Result<Vec<ActionReceipt>> {
        ensure(
            host.state()?.field_bootstrap.is_some(),
            "missing field bootstrap",
        )?;
        let state = host.state()?;
        let effects = host.recorded_effects()?;
        let mut outcomes = Vec::new();
        for record in state.records.values() {
            let Some(ticket) = &record.ticket else {
                continue;
            };
            if record.receipt.as_ref().is_some_and(|r| {
                matches!(
                    r.outcome,
                    ExecutionOutcome::Confirmed { .. } | ExecutionOutcome::Rejected { .. }
                )
            }) || effects.contains_key(&ticket.replay_id)
                || record.intent.effect.operation != "apply"
            {
                continue;
            }
            let payload: Payload = serde_json::from_slice(&record.intent.effect.canonical_payload)?;
            if payload.route != Route::Ordinary {
                continue;
            }
            let source = state
                .events
                .iter()
                .rev()
                .find(|e| {
                    e.kind == "decision"
                        && e.data["intent"]["proposal_id"].as_str()
                            == Some(&record.intent.proposal_id)
                })
                .ok_or("missing legacy decision material")?;
            let value = &source.data["governance_material"]["commitments"][&payload.path_ref];
            let path: Commitment = if value.is_null() {
                // Older records also carry the exact path in scope evidence.
                let evidence = record
                    .snapshot
                    .evidence
                    .iter()
                    .find(|e| e.kind == "scope")
                    .ok_or("missing legacy scope evidence")?;
                serde_json::from_value(
                    source.data["evidence_objects"][&evidence.content_sha256]["path"].clone(),
                )?
            } else {
                serde_json::from_value(value.clone())?
            };
            if path.delegation.is_some()
                && !state.records.values().any(|r| grants_delegation(&path, r))
            {
                outcomes.push(host.finish(ticket, ExecutionOutcome::Rejected { reason: "delegation lacks confirmed grantor consent; reconstitute before a new action".into() })?);
            }
        }
        outcomes.extend(host.recover_after_field_policy()?);
        Ok(outcomes)
    }
    pub fn reopen(root: &Path) -> Result<Self> {
        let host = Host::open_field(root, true)?;
        Self::recover_owned_host(&host)?;
        Self::restore_pending_work(&host)?;
        let state = host.state()?;
        let bootstrap: Bootstrap =
            serde_json::from_value(state.field_bootstrap.clone().ok_or("no field bootstrap")?)?;
        let mut field = Self {
            host,
            topology: bootstrap.topology,
            discovery: bootstrap.discovery,
            accepted_leads: bootstrap.accepted_leads,
            controller_seat: bootstrap.controller_seat,
            active: bootstrap.active,
            recipient_policy: bootstrap.recipient_policy,
            last_confirmation: Cell::new(None),
        };
        let mut records: Vec<_> = state
            .records
            .values()
            .filter(|r| {
                r.receipt
                    .as_ref()
                    .is_some_and(|r| matches!(r.outcome, ExecutionOutcome::Confirmed { .. }))
            })
            .collect();
        records.sort_by_key(|r| r.ticket.as_ref().map(|t| t.order));
        for record in records {
            let action = &record.intent;
            let source = state
                .events
                .iter()
                .rev()
                .find(|e| {
                    e.kind == "decision"
                        && e.data["intent"]["proposal_id"].as_str() == Some(&action.proposal_id)
                })
                .ok_or("missing decision material")?;
            // This is the complete issuer view recorded with the confirmed act.
            if source.data["governance_material"]["moderators"].is_array() {
                field.discovery.moderators = serde_json::from_value(
                    source.data["governance_material"]["moderators"].clone(),
                )?;
            }
            let proof: Proof = serde_json::from_value(source.data["proof"].clone())?;
            if action.effect.operation == "apply" {
                let payload: Payload = serde_json::from_slice(&action.effect.canonical_payload)?;
                let path = field
                    .discovery
                    .commitments
                    .get(&payload.path_ref)
                    .ok_or("missing recovered path")?
                    .clone();
                field.publish(&path, &proof, action)?;
                continue;
            }
            let change: Change = serde_json::from_slice(&action.effect.canonical_payload)?;
            let path = change
                .candidate
                .clone()
                .or_else(|| field.discovery.commitments.get(&change.target).cloned())
                .ok_or("missing recovered governance")?;
            match change.verb.as_str() {
                "propose" => {
                    field.discovery.commitments.insert(path.reference(), path);
                }
                "accept" | "amend" | "promote" => {
                    if change.verb != "accept" {
                        field.active.remove(&change.target);
                    }
                    field.active.insert(path.reference());
                    field.discovery.commitments.insert(path.reference(), path);
                }
                "publish" => {
                    field.publish(&path, &proof, action)?;
                }
                "fork" => {
                    field.publish_interpretation(
                        change
                            .interpretation
                            .ok_or("missing recovered interpretation")?,
                    )?;
                }
                "withdraw" => {
                    field.active.remove(&change.target);
                    for route in ["Ordinary", "Exception", "Composition"] {
                        field
                            .host
                            .effective_revoke(&format!("{}:{route}", change.target))?;
                    }
                }
                "resolve" => {
                    if let Some(policy) = change.recipient_policy {
                        field.recipient_policy = Some(policy);
                    }
                    if let Some(id) = change.queue_id {
                        field.host.transaction(|s| {
                            if let Some(q) = s.queue.get_mut(&id) {
                                q.status = "resolved".into();
                                q.resolution_proposal = Some(action.proposal_id.clone());
                            }
                            Ok(())
                        })?;
                    }
                }
                _ => {}
            }
        }
        field.discovery = Discovery::from_state(&state)?;
        Ok(field)
    }
    /// Repair the pre-atomic-write crash gap from committed decisions. Queue
    /// entries are derived local work; a confirmed resolution remains resolved.
    fn restore_pending_work(host: &Host) -> Result<()> {
        host.transaction(|s| {
            crate::audit::verify_events(&s.events)?;
            let mut repaired = Vec::new();
            for event in &s.events {
                if event.kind != "decision" {
                    continue;
                }
                let decision: GateDecision =
                    serde_json::from_value(event.data["decision"].clone())?;
                if decision.kind != DecisionKind::Indeterminate {
                    continue;
                }
                let action: ActionIntent = serde_json::from_value(event.data["intent"].clone())?;
                if s.queue.contains_key(&action.proposal_id) {
                    continue;
                }
                let context_ref = if action.effect.operation == "apply" {
                    serde_json::from_slice::<Payload>(&action.effect.canonical_payload)?.path_ref
                } else {
                    serde_json::from_slice::<Change>(&action.effect.canonical_payload)?.target
                };
                s.queue.insert(
                    action.proposal_id.clone(),
                    QueueItem {
                        proposal_id: action.proposal_id.clone(),
                        context_ref,
                        reason: decision.reasons.join("; "),
                        status: "pending".into(),
                        resolution_proposal: None,
                    },
                );
                repaired.push(action.proposal_id);
            }
            let mut resolutions: Vec<_> = s
                .records
                .values()
                .filter(|r| {
                    r.intent.effect.operation == "resolve"
                        && r.receipt.as_ref().is_some_and(|receipt| {
                            matches!(receipt.outcome, ExecutionOutcome::Confirmed { .. })
                        })
                })
                .collect();
            resolutions.sort_by_key(|r| r.ticket.as_ref().map(|t| t.order));
            for record in resolutions {
                let change: Change =
                    serde_json::from_slice(&record.intent.effect.canonical_payload)?;
                let id = change
                    .queue_id
                    .as_ref()
                    .ok_or("confirmed resolution missing queue reference")?;
                let item = s
                    .queue
                    .get_mut(id)
                    .ok_or("confirmed resolution missing pending decision")?;
                ensure(
                    item.context_ref == change.target,
                    "resolution queue context mismatch",
                )?;
                item.status = "resolved".into();
                item.resolution_proposal = Some(record.intent.proposal_id.clone());
            }
            if !repaired.is_empty() {
                let mut event = Event::new(
                    "host",
                    "recovery",
                    "host",
                    "queue_recovered",
                    json!({"proposals":repaired}),
                );
                event.seal(s.events.last());
                s.events.push(event);
            }
            Ok(())
        })
    }
    pub fn last_confirmation(&self) -> Option<Instant> {
        self.last_confirmation.get()
    }
    pub fn host(&self) -> &Host {
        &self.host
    }
    pub fn discovery(&self) -> Discovery {
        self.discovery.clone()
    }
    pub fn event(&self, scene: &Scene, kind: &str, data: Value) -> Result<()> {
        self.host.note(Event::new(
            &scene.movement,
            &scene.beat,
            self.topology.label(),
            kind,
            data,
        ))
    }
    pub fn measured_event(
        &self,
        scene: &Scene,
        kind: &str,
        data: Value,
        latency_ns: u128,
    ) -> Result<()> {
        let mut event = Event::new(
            &scene.movement,
            &scene.beat,
            self.topology.label(),
            kind,
            data,
        );
        event.latency_ns = Some(latency_ns);
        self.host.note(event)
    }
    fn replay(
        &self,
        scene: &Scene,
        action: &ActionIntent,
        proof: &Proof,
    ) -> Result<Option<DecisionKind>> {
        let state = self.host.state()?;
        if let Some(record) = state.records.get(&action.proposal_id) {
            ensure(
                record.intent == *action,
                "proposal ID reused for different effect",
            )?;
            if let Some(ticket) = &record.ticket {
                ensure(
                    state.events.iter().any(|e| {
                        e.kind == "decision"
                            && e.data["intent"]["proposal_id"].as_str() == Some(&action.proposal_id)
                            && e.data["accountable_proof"].as_str() == Some(&digest(proof))
                    }),
                    "replay proof differs from original accountable proof",
                )?;
                let receipt = self.host.dispatch(ticket, &action.effect, false)?;
                self.event(scene,"replayed",json!({"proposal_id":action.proposal_id,"original_receipt":receipt,"new_authority":false}))?;
                return Ok(Some(record.decision.kind));
            }
        }
        Ok(None)
    }
    fn verify(
        &self,
        issuers: &Issuers,
        proof: &Proof,
        action: &ActionIntent,
        book: &str,
        payoff: &str,
        tick: u64,
    ) -> Verdict {
        if proof.seat_ref != action.actor_id {
            return Verdict::Fail;
        }
        issuers.verify(
            proof,
            &self.accepted_leads,
            book,
            &action.proposal_id,
            &action.fingerprint(),
            payoff,
            tick,
        )
    }
    fn snapshot(
        &self,
        action: &ActionIntent,
        checks: Vec<(&str, Verdict, Value)>,
        requirements: Vec<AcceptanceRequirement>,
        acceptances: Vec<AcceptanceRecord>,
    ) -> Result<EvaluationSnapshot> {
        let state = self.host.state()?;
        let sequence = state.order;
        let mut evidence = Vec::new();
        let mut objects = Vec::new();
        let mut assessments = Vec::new();
        let mut conditions = Vec::new();
        for (name, verdict, content) in checks {
            let key = digest(&content);
            objects.push((key.clone(), content.clone()));
            let id = format!("evidence:{name}:{key}");
            evidence.push(Evidence {
                evidence_id: id.clone(),
                kind: name.into(),
                schema_version: 1,
                subject_id: action.actor_id.clone(),
                issuer_id: "verifier:portable".into(),
                content_sha256: digest(&content),
                verifier_id: Some("verifier:portable".into()),
                verification: VerificationStatus::Verified,
                observed_at_sequence: sequence,
                valid_through_sequence: sequence + 100,
                action_fingerprint: Some(action.fingerprint()),
            });
            conditions.push(ConditionRequirement {
                condition_id: name.into(),
                version: 1,
            });
            assessments.push(ConditionAssessment {
                condition_id: name.into(),
                version: 1,
                assessor_id: "verifier:portable".into(),
                result: match verdict {
                    Verdict::Pass => CheckResult::Pass,
                    Verdict::Fail => CheckResult::Fail,
                    Verdict::Unknown => CheckResult::Unknown,
                },
                reason: format!("{name}: {verdict:?}"),
                evidence_ids: vec![id],
            });
        }
        self.host.transaction(|s| {
            s.objects.extend(objects);
            Ok(())
        })?;
        Ok(EvaluationSnapshot {
            schema_version: 1,
            context_id: action.context_id.clone(),
            context_version: action.context_version,
            sequence,
            valid_through_sequence: sequence + 100,
            profile: GateProfile {
                profile_id: action.authority_id.clone(),
                version: 1,
                effect_profile_id: action.effect.profile_id.clone(),
                effect_profile_version: action.effect.profile_version,
                conditions: ConditionPolicy::Require(conditions),
                required_acceptances: requirements,
            },
            evidence,
            assessments,
            acceptances,
            revocation: state
                .revocations
                .get(&action.authority_id)
                .cloned()
                .unwrap_or_default(),
        })
    }
    fn endorsements(
        &self,
        issuers: &Issuers,
        action: &ActionIntent,
        book: &str,
        payoff: &str,
        scope: &str,
        required: &[String],
        supplied: &[Endorsement],
        tick: u64,
    ) -> (Vec<AcceptanceRequirement>, Vec<AcceptanceRecord>) {
        let terms = digest(&(&action.effect, payoff));
        let requirements: Vec<_> = required
            .iter()
            .map(|seat| AcceptanceRequirement {
                requirement_id: format!("accept:{seat}"),
                principal_id: seat.clone(),
                terms_digest: terms.clone(),
            })
            .collect();
        let acceptances = requirements
            .iter()
            .filter_map(|r| {
                supplied
                    .iter()
                    .find(|e| {
                        e.scoped_seat == r.principal_id
                            && issuers.owns_seat(&e.proof, scope, &e.scoped_seat)
                            && issuers.verify(
                                &e.proof,
                                &self.accepted_leads,
                                book,
                                &action.proposal_id,
                                &action.fingerprint(),
                                payoff,
                                tick,
                            ) == Verdict::Pass
                    })
                    .map(|_| AcceptanceRecord {
                        requirement_id: r.requirement_id.clone(),
                        state: AcceptanceState::Accepted {
                            by_principal_id: r.principal_id.clone(),
                            action_fingerprint: action.fingerprint(),
                            terms_digest: terms.clone(),
                            at_sequence: 0,
                            valid_through_sequence: u64::MAX,
                        },
                    })
            })
            .collect();
        (requirements, acceptances)
    }
    fn gate(
        &self,
        scene: &Scene,
        action: &ActionIntent,
        snapshot: &EvaluationSnapshot,
        proof: &Proof,
        started: Instant,
    ) -> Result<DecisionKind> {
        let mut event = Event::new(
            &scene.movement,
            &scene.beat,
            self.topology.label(),
            "decision",
            json!({"accountable_proof":digest(proof),"proof":proof,"anonymous_seat":proof.seat_ref,"payoff_ref":proof.payoff_ref,"governance_material":{"local_assessment_version":3,"commitments":self.discovery.commitments,"active_paths":self.active,"rulebooks":self.discovery.rulebooks,"interpretations":self.discovery.interpretations,"moderators":self.discovery.moderators,"revocation_epoch":self.discovery.revocation_epoch,"revocation_ref":self.discovery.revocation_ref}}),
        );
        event.latency_ns = Some(started.elapsed().as_nanos());
        let queue_context = if action.effect.operation == "apply" {
            serde_json::from_slice::<Payload>(&action.effect.canonical_payload)?.path_ref
        } else {
            serde_json::from_slice::<Change>(&action.effect.canonical_payload)?.target
        };
        let decision =
            self.host
                .prepare_with_queue(action, snapshot, event, started, &queue_context)?;
        if decision.kind == DecisionKind::Permitted {
            let ticket = match self.host.reserve(&action.proposal_id)? {
                Reservation::New(t) | Reservation::Replay(t) => t,
                Reservation::Denied => return Err("live state denied reservation".into()),
            };
            self.host.dispatch(&ticket, &action.effect, false)?;
            self.last_confirmation.set(Some(Instant::now()));
        }
        Ok(decision.kind)
    }
    pub fn govern(
        &mut self,
        scene: &Scene,
        issuers: &Issuers,
        action: &ActionIntent,
        proof: &Proof,
        endorsements: &[Endorsement],
        tick: u64,
    ) -> Result<DecisionKind> {
        let start = Instant::now();
        self.discovery.revocation_epoch = issuers.epoch();
        self.discovery.revocation_ref = issuers.revocation_ref();
        self.discovery.moderators = issuers.published();
        let change: Change = serde_json::from_slice(&action.effect.canonical_payload)?;
        ensure(
            action.effect.operation == change.verb && action.effect.destination == change.target,
            "governance effect mismatch",
        )?;
        ensure(
            action.authority_id == format!("govern:{}", change.target),
            "governance authority mismatch",
        )?;
        ensure(
            action.effect.profile_id == "generic-record/v1"
                && action.effect.profile_version == 1
                && action.context_id == "activity:governance",
            "unsupported governance profile",
        )?;
        ensure(
            change.interpretation.is_some() == (change.verb == "fork"),
            "fork must carry exactly one interpretation",
        )?;
        if let Some(kind) = self.replay(scene, action, proof)? {
            return Ok(kind);
        }
        if change.verb == "resolve" {
            let state = self.host.state()?;
            ensure(
                change
                    .queue_id
                    .as_ref()
                    .and_then(|id| state.queue.get(id))
                    .is_some_and(|q| q.status == "pending" && q.context_ref == change.target),
                "resolution needs a pending queue item",
            )?;
        } else {
            ensure(
                change.recipient_policy.is_none(),
                "policy change requires constituted resolution",
            )?;
        }
        if change.verb == "promote" {
            let state = self.host.state()?;
            let queued = change
                .queue_id
                .as_ref()
                .and_then(|id| state.queue.get(id))
                .ok_or("promotion requires a side-environment trail")?;
            ensure(
                queued.status == "resolved" && queued.context_ref == change.target,
                "promotion requires resolution of this path's collision",
            )?;
            let resolution = queued
                .resolution_proposal
                .as_ref()
                .and_then(|id| state.records.get(id))
                .ok_or("missing resolution act")?;
            ensure(
                resolution
                    .receipt
                    .as_ref()
                    .is_some_and(|r| matches!(r.outcome, ExecutionOutcome::Confirmed { .. })),
                "resolution was not confirmed",
            )?;
            let original = state
                .records
                .get(&queued.proposal_id)
                .ok_or("missing collision action")?;
            let offered: Payload =
                serde_json::from_slice(&original.intent.effect.canonical_payload)?;
            ensure(
                change
                    .candidate
                    .as_ref()
                    .is_some_and(|p| p.interpretation_ref == offered.interpretation_ref),
                "promotion differs from resolved interpretation",
            )?;
        }
        let previous = self.discovery.commitments.get(&change.target);
        let path = change
            .candidate
            .as_ref()
            .or(previous)
            .ok_or("missing governed commitment")?
            .clone();
        ensure(
            path.owners.len() >= 2
                && path.owners.iter().collect::<BTreeSet<_>>().len() == path.owners.len(),
            "commitment needs distinct affected parties",
        )?;
        ensure(path.window[0] <= path.window[1], "invalid window")?;
        match change.verb.as_str() {
            "propose" => ensure(
                change.candidate.is_some() && path.reference() == change.target,
                "proposal must name its exact candidate",
            )?,
            "amend" | "promote" => ensure(
                change.candidate.is_some() && path.parent_ref.as_deref() == Some(&change.target),
                "changed path must reference its predecessor",
            )?,
            _ => ensure(
                change.candidate.is_none(),
                "this verb cannot substitute path terms",
            )?,
        }
        let resolved = self
            .discovery
            .resolve(&path.rulebook_ref, &path.interpretation_ref)
            .and_then(|r| {
                ensure(
                    r.rules == path.rule_payload,
                    "path must carry its exact interpreted rules",
                )?;
                if let Some(child) = &change.interpretation {
                    ensure(
                        change.verb == "fork",
                        "interpretation publication requires fork act",
                    )?;
                    r.extend(child)
                } else {
                    Ok(r)
                }
            });
        let structure = if resolved.is_ok() {
            Verdict::Pass
        } else {
            Verdict::Fail
        };
        let owners = previous.map_or(&path.owners, |p| &p.owners);
        let mut required = match self.topology {
            Topology::Control => vec![self.controller_seat.clone()],
            Topology::Constitutive => owners.clone(),
        };
        if matches!(change.verb.as_str(), "amend" | "promote") {
            required.extend(owners.iter().cloned());
            required.extend(path.owners.iter().cloned());
            required.sort();
            required.dedup();
        }
        if change.verb == "withdraw" {
            required = owners
                .iter()
                .filter(|s| issuers.owns_seat(proof, &path.context, s))
                .cloned()
                .collect();
        }
        if matches!(change.verb.as_str(), "contest" | "escalate" | "fork") {
            required.clear();
        }
        if change.verb == "promote" && self.topology == Topology::Control {
            required.extend(owners.iter().cloned());
            required.sort();
            required.dedup();
        }
        // Environment authority and path ownership cannot grant another
        // principal's delegation. The grantor must consent to the exact path
        // terms, including activation and every amendment/promotion. Retain
        // the old grantor when replacing or removing a delegation as well.
        if matches!(
            change.verb.as_str(),
            "propose" | "accept" | "amend" | "promote"
        ) {
            let old_delegation = previous
                .filter(|_| matches!(change.verb.as_str(), "amend" | "promote"))
                .and_then(|p| p.delegation.as_ref());
            for delegation in path.delegation.iter().chain(old_delegation) {
                if !required.contains(&delegation.principal_seat) {
                    required.push(delegation.principal_seat.clone());
                }
            }
        }
        let known = matches!(
            change.verb.as_str(),
            "propose"
                | "accept"
                | "publish"
                | "amend"
                | "withdraw"
                | "contest"
                | "escalate"
                | "resolve"
                | "promote"
                | "fork"
        );
        let authorised = known
            && (change.verb != "withdraw" || !required.is_empty())
            && (previous.is_some() || change.verb == "propose");
        let standing = self.verify(
            issuers,
            proof,
            action,
            &path.rulebook_ref,
            "payoff:governance",
            tick,
        );
        let (requirements, acceptances) = self.endorsements(
            issuers,
            action,
            &path.rulebook_ref,
            "payoff:governance",
            &path.context,
            &required,
            endorsements,
            tick,
        );
        self.event(scene,"recipient_validation",json!({"proposal_id":action.proposal_id,"result":standing,"governance":true,"revocation_epoch":issuers.epoch()}))?;
        let mut checks = vec![
            ("standing", standing, json!(proof)),
            (
                "inheritance",
                structure,
                json!({"path":path,"error":resolved.err().map(|e|e.to_string())}),
            ),
            (
                "lifecycle",
                if authorised {
                    Verdict::Pass
                } else {
                    Verdict::Fail
                },
                json!(change),
            ),
            (
                "acceptance-presentations",
                Verdict::Pass,
                json!(endorsements),
            ),
        ];
        if let Some(child) = &change.interpretation {
            checks.push((
                "interpretation-authorship",
                if issuers.owns_interpretation_author(proof, &child.rulebook_ref, &child.author_urn)
                {
                    Verdict::Pass
                } else {
                    Verdict::Fail
                },
                json!({"author_urn":child.author_urn,"rulebook_ref":child.rulebook_ref,
                    "publisher_proof":digest(proof)}),
            ));
        }
        let snapshot = self.snapshot(action, checks, requirements, acceptances)?;
        let kind = self.gate(scene, action, &snapshot, proof, start)?;
        if kind != DecisionKind::Permitted {
            return Ok(kind);
        }
        let reference = path.reference();
        self.host.object(&path)?;
        match change.verb.as_str() {
            "propose" => {
                self.discovery.commitments.insert(reference, path);
            }
            "accept" | "amend" | "promote" => {
                if matches!(change.verb.as_str(), "amend" | "promote") {
                    self.active.remove(&change.target);
                }
                self.active.insert(reference.clone());
                self.discovery.commitments.insert(reference.clone(), path);
                self.event(scene, if change.verb == "promote" { "promotion_complete" } else { "path_active" }, json!({"path_ref":reference,"previous_ref":change.target,"authority_source":self.topology,"acceptances":snapshot.acceptances,"trail_complete":true,"governance_proposal":action.proposal_id}))?;
            }
            "withdraw" => {
                self.active.remove(&change.target);
                self.host
                    .effective_revoke(&format!("{}:Ordinary", change.target))?;
                self.host
                    .effective_revoke(&format!("{}:Exception", change.target))?;
                self.host
                    .effective_revoke(&format!("{}:Composition", change.target))?;
                self.event(
                    scene,
                    "withdrawal_effective",
                    json!({"path_ref":change.target,"proof_ref":digest(proof)}),
                )?;
            }
            "resolve" => {
                let id = change
                    .queue_id
                    .as_ref()
                    .ok_or("resolution needs queue item")?;
                self.host.transaction(|s| {
                    let item = s.queue.get_mut(id).ok_or("unknown queue item")?;
                    ensure(item.status == "pending", "queue already resolved")?;
                    item.status = "resolved".into();
                    item.resolution_proposal = Some(action.proposal_id.clone());
                    Ok(())
                })?;
                self.event(scene, "resolution_complete", json!({"queue_id":id,"resolution_proposal":action.proposal_id,"trail_complete":true}))?;
                if let Some(policy) = change.recipient_policy {
                    self.recipient_policy = Some(policy);
                }
            }
            "publish" => {
                self.publish(&path, proof, action)?;
            }
            "fork" => {
                let interpretation = change.interpretation.ok_or("fork needs interpretation")?;
                let reference = self.publish_interpretation(interpretation)?;
                self.event(scene,"fork_published",json!({"parent_ref":path.interpretation_ref,"fork_ref":reference,"author_proof":digest(proof),"governance_proposal":action.proposal_id,"trail_complete":true}))?;
            }
            _ => {}
        }
        Ok(kind)
    }
    fn publish(&mut self, path: &Commitment, proof: &Proof, action: &ActionIntent) -> Result<Stub> {
        let stub = self.discovery.publish_record(path, proof, action);
        self.host
            .object(&self.discovery.seats[&stub.commitment_ref])?;
        self.host.object(&stub)?;
        Ok(stub)
    }
    fn publish_interpretation(&mut self, interpretation: Interpretation) -> Result<String> {
        let parent = self
            .discovery
            .resolve(&interpretation.rulebook_ref, &interpretation.parent_ref)?;
        parent.extend(&interpretation)?;
        let reference = self.host.object(&interpretation)?;
        self.discovery
            .interpretations
            .insert(reference.clone(), interpretation);
        Ok(reference)
    }
    pub fn execute(
        &mut self,
        scene: &Scene,
        issuers: &Issuers,
        instruction: &Instruction,
        tick: u64,
    ) -> Result<DecisionKind> {
        let start = Instant::now();
        self.discovery.revocation_epoch = issuers.epoch();
        self.discovery.revocation_ref = issuers.revocation_ref();
        self.discovery.moderators = issuers.published();
        let action = &instruction.intent;
        let path = self
            .discovery
            .commitments
            .get(&instruction.path_ref)
            .ok_or("unknown path")?
            .clone();
        ensure(
            path.reference() == instruction.path_ref
                && action.authority_id
                    == format!("{}:{:?}", instruction.path_ref, instruction.route)
                && action.context_id == path.context,
            "action/path binding mismatch",
        )?;
        let payload: Payload = serde_json::from_slice(&action.effect.canonical_payload)?;
        ensure(
            action.effect.canonical_payload
                == canonical(&instruction.payload(payload.facts.clone())),
            "instruction metadata changed outside effect binding",
        )?;
        ensure(
            action.effect.profile_id == "generic-record/v1"
                && action.effect.profile_version == 1
                && action.effect.operation == "apply"
                && action.effect.destination == "endpoint:existing-rail",
            "unsupported effect profile",
        )?;
        if let Some(kind) = self.replay(scene, action, &instruction.proof)? {
            return Ok(kind);
        }
        ensure(
            !payload.facts.keys().any(|k| k.starts_with("host.")),
            "host facts cannot be supplied by a participant",
        )?;
        let mut facts = payload.facts;
        let state = self.host.state()?;
        let count = state
            .records
            .values()
            .filter(|r| r.intent.authority_id == action.authority_id && r.ticket.is_some())
            .count() as i64;
        facts.insert("host.count".into(), json!(count + 1));
        facts.insert("host.tick".into(), json!(tick));
        let payoff = match instruction.route {
            Route::Ordinary | Route::Composition => &path.payoffs.on_violation,
            Route::Exception => &path.payoffs.on_exceed_scope,
        };
        let standing = self.verify(
            issuers,
            &instruction.proof,
            action,
            &path.rulebook_ref,
            payoff,
            tick,
        );
        let interpreted = self
            .discovery
            .resolve(&path.rulebook_ref, &path.interpretation_ref)?
            .evaluate(&facts);
        let carried = self
            .discovery
            .resolve(&path.rulebook_ref, &instruction.interpretation_ref)
            .map(|r| {
                if r.rules == instruction.rule_payload {
                    Verdict::Pass
                } else {
                    Verdict::Fail
                }
            })
            .unwrap_or(Verdict::Unknown);
        let compatible = if instruction.interpretation_ref == path.interpretation_ref {
            Verdict::Pass
        } else {
            Verdict::Unknown
        };
        let scope = match instruction.route {
            Route::Ordinary | Route::Composition => path.scope.evaluate(&facts),
            Route::Exception => path.exception.evaluate(&facts),
        };
        let active = self.active.contains(&instruction.path_ref)
            && tick >= path.window[0]
            && tick <= path.window[1];
        let delegated = if instruction.route == Route::Composition {
            if action.represented_principal_id == action.actor_id {
                path.composition.evaluate(&facts)
            } else {
                Verdict::Fail
            }
        } else if let Some(d) = &path.delegation {
            if instruction.route == Route::Exception {
                if issuers.owns_seat(&instruction.proof, &path.context, &path.approver_seat) {
                    Verdict::Pass
                } else {
                    Verdict::Fail
                }
            } else if issuers.owns_seat(&instruction.proof, &path.context, &d.delegate_seat)
                && action.represented_principal_id == d.principal_seat
            {
                d.scope.evaluate(&facts)
            } else {
                Verdict::Fail
            }
        } else if action.represented_principal_id == action.actor_id {
            Verdict::Pass
        } else {
            Verdict::Fail
        };
        let mut checks = vec![
            ("standing", standing, json!(&instruction.proof)),
            (
                "interpretation",
                interpreted,
                json!({"interpretation_ref":path.interpretation_ref,"facts":facts}),
            ),
            (
                "scope",
                scope,
                json!({"route":instruction.route,"path":path}),
            ),
            (
                "conditions",
                path.conditions.evaluate(&facts),
                json!(path.conditions),
            ),
            (
                "active",
                if active { Verdict::Pass } else { Verdict::Fail },
                json!({"tick":tick,"window":path.window}),
            ),
            ("delegation", delegated, json!(path.delegation)),
        ];
        if instruction.route == Route::Ordinary && path.delegation.is_some() {
            let grant = state.records.values().find(|r| grants_delegation(&path, r));
            checks.push((
                "delegation-grant",
                if grant.is_some() {
                    Verdict::Pass
                } else {
                    Verdict::Fail
                },
                json!(grant),
            ));
        }
        checks.push((
            "interpretation-agreement",
            compatible,
            json!({"offered":instruction.interpretation_ref,"adopted":path.interpretation_ref}),
        ));
        checks.push(("rules-in-message",carried,json!({"interpretation_ref":instruction.interpretation_ref,"rules":instruction.rule_payload})));
        if let Some(upstream) = &instruction.upstream {
            let up = self
                .discovery
                .commitments
                .get(&upstream.path_ref)
                .ok_or("missing upstream governance")?;
            let valid = self.verify_upstream(issuers, upstream, up, tick)?;
            checks.push(("upstream-accountability", valid, json!(upstream)));
            let disposition = match self.recipient_policy.unwrap_or(RecipientPolicy::Unresolved) {
                RecipientPolicy::Refuse => Verdict::Fail,
                RecipientPolicy::Honour => Verdict::Pass,
                RecipientPolicy::Unresolved => Verdict::Unknown,
            };
            checks.push(("recipient-payoff-policy", disposition, json!({"policy":self.recipient_policy,"upstream_proof":digest(&upstream.proof),"upstream_payoff":upstream.proof.payoff_ref,"own_proof":digest(&instruction.proof)})));
        }
        let required = if instruction.route == Route::Exception {
            vec![path.approver_seat.clone()]
        } else {
            vec![]
        };
        let (requirements, acceptances) = self.endorsements(
            issuers,
            action,
            &path.rulebook_ref,
            payoff,
            &path.context,
            &required,
            &instruction.endorsements,
            tick,
        );
        checks.push((
            "acceptance-presentations",
            Verdict::Pass,
            json!(instruction.endorsements),
        ));
        self.event(scene, "recipient_validation", json!({"proposal_id":action.proposal_id,"checks":checks,"revocation_epoch":issuers.epoch(),"outside_origin":self.recipient_policy.is_some()}))?;
        let snapshot = self.snapshot(action, checks, requirements, acceptances)?;
        let kind = self.gate(scene, action, &snapshot, &instruction.proof, start)?;
        if kind == DecisionKind::Permitted {
            self.publish(&path, &instruction.proof, action)?;
            if instruction.route == Route::Exception {
                self.event(scene, "override_accountability_complete", json!({"proposal_id":action.proposal_id,"accountable_proof":digest(&instruction.proof),"seat_ref":instruction.proof.seat_ref,"payoff_ref":payoff,"acceptances":snapshot.acceptances}))?;
            }
        }
        self.event(
            scene,
            "action_complete",
            json!({"proposal_id":action.proposal_id,"outcome":outcome(kind),"delegate_kind":instruction.delegate_kind}),
        )?;
        Ok(kind)
    }
    fn verify_upstream(
        &self,
        issuers: &Issuers,
        instruction: &Instruction,
        path: &Commitment,
        tick: u64,
    ) -> Result<Verdict> {
        let a = &instruction.intent;
        let payload: Payload = match serde_json::from_slice(&a.effect.canonical_payload) {
            Ok(p) => p,
            Err(_) => return Ok(Verdict::Fail),
        };
        let bound = instruction.upstream.is_none()
            && instruction.route == Route::Exception
            && instruction.path_ref == path.reference()
            && instruction.interpretation_ref == path.interpretation_ref
            && instruction.rule_payload == path.rule_payload
            && a.authority_id == format!("{}:Exception", path.reference())
            && a.context_id == path.context
            && a.effect.operation == "apply"
            && a.effect.destination == "endpoint:existing-rail"
            && canonical(&instruction.payload(payload.facts.clone())) == a.effect.canonical_payload
            && issuers.owns_seat(&instruction.proof, &path.context, &path.approver_seat);
        let standing = self.verify(
            issuers,
            &instruction.proof,
            a,
            &path.rulebook_ref,
            &path.payoffs.on_exceed_scope,
            tick,
        );
        let (requirements, acceptances) = self.endorsements(
            issuers,
            a,
            &path.rulebook_ref,
            &path.payoffs.on_exceed_scope,
            &path.context,
            std::slice::from_ref(&path.approver_seat),
            &instruction.endorsements,
            tick,
        );
        let snapshot = self.snapshot(
            a,
            vec![
                (
                    "upstream-binding",
                    if bound { Verdict::Pass } else { Verdict::Fail },
                    json!(instruction),
                ),
                ("upstream-standing", standing, json!(&instruction.proof)),
                (
                    "upstream-eligibility",
                    path.exception.evaluate(&payload.facts),
                    json!(path.exception),
                ),
                (
                    "upstream-conditions",
                    path.conditions.evaluate(&payload.facts),
                    json!(path.conditions),
                ),
                (
                    "upstream-interpretation",
                    self.discovery
                        .resolve(&path.rulebook_ref, &path.interpretation_ref)?
                        .evaluate(&payload.facts),
                    json!(path.interpretation_ref),
                ),
                (
                    "upstream-window",
                    if tick >= path.window[0] && tick <= path.window[1] {
                        Verdict::Pass
                    } else {
                        Verdict::Fail
                    },
                    json!(path.window),
                ),
            ],
            requirements,
            acceptances,
        )?;
        Ok(match evaluate(a, &snapshot).decision.kind {
            DecisionKind::Permitted => Verdict::Pass,
            DecisionKind::Indeterminate => Verdict::Unknown,
            _ => Verdict::Fail,
        })
    }
}

/// A fresh local delegated execution needs confirmed activation of these exact
/// terms with the grantor's bound acceptance. Historical acts stay immutable.
pub(crate) fn grants_delegation(path: &Commitment, record: &crate::store::Record) -> bool {
    let Some(delegation) = &path.delegation else {
        return false;
    };
    let Ok(change) = serde_json::from_slice::<Change>(&record.intent.effect.canonical_payload)
    else {
        return false;
    };
    let activates = match change.verb.as_str() {
        "accept" => change.candidate.is_none() && change.target == path.reference(),
        "amend" | "promote" => change.candidate.as_ref() == Some(path),
        _ => false,
    };
    if !activates || record.intent.effect.operation != change.verb {
        return false;
    }
    let admission = evaluate(&record.intent, &record.snapshot);
    let confirmed = record.receipt.as_ref().is_some_and(|receipt| {
        matches!(receipt.outcome, ExecutionOutcome::Confirmed { .. })
            && validate_receipt(&record.intent, &admission, receipt).is_ok()
    });
    if !confirmed || admission.decision.kind != DecisionKind::Permitted {
        return false;
    }
    let terms = digest(&(&record.intent.effect, "payoff:governance"));
    record.snapshot.profile.required_acceptances.iter().any(|requirement| {
        requirement.principal_id == delegation.principal_seat && requirement.terms_digest == terms
        && record.snapshot.acceptances.iter().any(|response| {
            response.requirement_id == requirement.requirement_id && matches!(&response.state,
                AcceptanceState::Accepted { by_principal_id, action_fingerprint, terms_digest, at_sequence, valid_through_sequence }
                if by_principal_id == &delegation.principal_seat && action_fingerprint == &record.intent.fingerprint()
                && terms_digest == &terms && *at_sequence <= record.snapshot.sequence && record.snapshot.sequence <= *valid_through_sequence)
        })
    })
}
