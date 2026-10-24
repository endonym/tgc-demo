//! Versioned v1 action and evidence contract.
//!
//! This module binds an exact effect, profile, evidence and acceptance to a
//! four-way gate decision. The host supplies authoritative current snapshots,
//! authenticates participants, reserves dispatch and keeps effectful capabilities
//! behind controlled adapters.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const SCHEMA_VERSION: u16 = 1;

fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn append_field(bytes: &mut Vec<u8>, field: &[u8]) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field);
}

fn hash_sorted_records<T>(hasher: &mut Sha256, records: &[T], encode: impl Fn(&T) -> Vec<u8>) {
    let mut encoded: Vec<_> = records.iter().map(encode).collect();
    encoded.sort();
    hasher.update((encoded.len() as u64).to_be_bytes());
    for record in encoded {
        hash_field(hasher, &record);
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// An effect profile defines the meaning and canonical encoding of payload.
/// The host and its adapter must agree on that encoding and compare the actual
/// operation with this complete binding immediately before dispatch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Effect {
    pub profile_id: String,
    pub profile_version: u32,
    pub operation: String,
    pub destination: String,
    pub canonical_payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionIntent {
    pub schema_version: u16,
    pub proposal_id: String,
    pub actor_id: String,
    pub represented_principal_id: String,
    pub authority_id: String,
    pub context_id: String,
    pub context_version: u64,
    pub effect: Effect,
}

impl ActionIntent {
    /// Domain-separated, length-prefixed binding of the exact proposed effect.
    /// An integrity identifier for the proposed effect; the host separately
    /// resolves the authority that governs it.
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, b"constitutive-action.experimental.v1.intent");
        hasher.update(self.schema_version.to_be_bytes());
        for value in [
            self.proposal_id.as_str(),
            self.actor_id.as_str(),
            self.represented_principal_id.as_str(),
            self.authority_id.as_str(),
            self.context_id.as_str(),
            self.effect.profile_id.as_str(),
            self.effect.operation.as_str(),
            self.effect.destination.as_str(),
        ] {
            hash_field(&mut hasher, value.as_bytes());
        }
        hasher.update(self.context_version.to_be_bytes());
        hasher.update(self.effect.profile_version.to_be_bytes());
        hash_field(&mut hasher, &self.effect.canonical_payload);
        format!("{:x}", hasher.finalize())
    }

    fn structurally_valid(&self) -> bool {
        self.schema_version == SCHEMA_VERSION
            && !self.proposal_id.is_empty()
            && !self.actor_id.is_empty()
            && !self.represented_principal_id.is_empty()
            && !self.authority_id.is_empty()
            && !self.context_id.is_empty()
            && !self.effect.profile_id.is_empty()
            && self.effect.profile_version > 0
            && !self.effect.operation.is_empty()
            && !self.effect.destination.is_empty()
    }
}

/// No implicit permission arises from an empty check list. Profiles with no
/// required conditions must select ExplicitOpen; required profiles must name
/// at least one condition. The host establishes that profile choice's authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionPolicy {
    ExplicitOpen,
    Require(Vec<ConditionRequirement>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionRequirement {
    pub condition_id: String,
    pub version: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceRequirement {
    pub requirement_id: String,
    pub principal_id: String,
    /// SHA-256 of canonical consequential terms supplied by the host.
    pub terms_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateProfile {
    pub profile_id: String,
    pub version: u32,
    /// The exact effect vocabulary to which this gate profile applies.
    pub effect_profile_id: String,
    pub effect_profile_version: u32,
    pub conditions: ConditionPolicy,
    pub required_acceptances: Vec<AcceptanceRequirement>,
}

impl GateProfile {
    /// Binds the profile ID, version and content, not the ID/version alone.
    /// A host must treat an ID/version as immutable and expose the *current*
    /// fingerprint in live state before dispatch.
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hash_field(
            &mut hasher,
            b"constitutive-action.experimental.v1.gate-profile",
        );
        hash_field(&mut hasher, self.profile_id.as_bytes());
        hasher.update(self.version.to_be_bytes());
        hash_field(&mut hasher, self.effect_profile_id.as_bytes());
        hasher.update(self.effect_profile_version.to_be_bytes());
        match &self.conditions {
            ConditionPolicy::ExplicitOpen => hash_field(&mut hasher, b"explicit-open"),
            ConditionPolicy::Require(requirements) => {
                hash_field(&mut hasher, b"require");
                hasher.update((requirements.len() as u64).to_be_bytes());
                for requirement in requirements {
                    hash_field(&mut hasher, requirement.condition_id.as_bytes());
                    hasher.update(requirement.version.to_be_bytes());
                }
            }
        }
        hasher.update((self.required_acceptances.len() as u64).to_be_bytes());
        for requirement in &self.required_acceptances {
            hash_field(&mut hasher, requirement.requirement_id.as_bytes());
            hash_field(&mut hasher, requirement.principal_id.as_bytes());
            hash_field(&mut hasher, requirement.terms_digest.as_bytes());
        }
        format!("{:x}", hasher.finalize())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Verified,
    Rejected,
    Unknown,
}

/// An attributed reference to evidence verified by the host or named verifier.
/// The host establishes signature validity and the meaning of assessed conditions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub evidence_id: String,
    pub kind: String,
    pub schema_version: u32,
    pub subject_id: String,
    pub issuer_id: String,
    pub content_sha256: String,
    pub verifier_id: Option<String>,
    pub verification: VerificationStatus,
    pub observed_at_sequence: u64,
    pub valid_through_sequence: u64,
    /// An action-bound evidence reference fails this structural check for a
    /// different action fingerprint.
    pub action_fingerprint: Option<String>,
}

impl Evidence {
    fn valid_for(&self, action: &ActionIntent, sequence: u64) -> bool {
        !self.evidence_id.is_empty()
            && !self.kind.is_empty()
            && self.schema_version > 0
            && !self.subject_id.is_empty()
            && !self.issuer_id.is_empty()
            && is_digest(&self.content_sha256)
            && self.verification == VerificationStatus::Verified
            && self.verifier_id.as_ref().is_some_and(|id| !id.is_empty())
            && self.observed_at_sequence <= sequence
            && sequence <= self.valid_through_sequence
            && self
                .action_fingerprint
                .as_ref()
                .is_none_or(|binding| binding == &action.fingerprint())
    }
}

/// Bind only evidence that an assessed condition actually used. Sorting by
/// evidence ID makes the result independent of assessment traversal order.
/// Referenced records have already passed structural/freshness validation.
fn evaluated_evidence_fingerprint(records: &[Evidence], used_ids: &[String]) -> String {
    let mut ids = used_ids.to_vec();
    ids.sort();
    ids.dedup();
    let mut hasher = Sha256::new();
    hash_field(
        &mut hasher,
        b"constitutive-action.experimental.v1.evaluated-evidence",
    );
    hasher.update((ids.len() as u64).to_be_bytes());
    for id in ids {
        let evidence = records
            .iter()
            .find(|item| item.evidence_id == id)
            .expect("evaluated evidence ID must resolve to its validated record");
        hash_field(&mut hasher, evidence.evidence_id.as_bytes());
        hash_field(&mut hasher, evidence.kind.as_bytes());
        hasher.update(evidence.schema_version.to_be_bytes());
        hash_field(&mut hasher, evidence.subject_id.as_bytes());
        hash_field(&mut hasher, evidence.issuer_id.as_bytes());
        hash_field(&mut hasher, evidence.content_sha256.as_bytes());
        match &evidence.verifier_id {
            Some(verifier) => {
                hasher.update([1]);
                hash_field(&mut hasher, verifier.as_bytes());
            }
            None => hasher.update([0]),
        }
        hash_field(
            &mut hasher,
            match evidence.verification {
                VerificationStatus::Verified => b"verified",
                VerificationStatus::Rejected => b"rejected",
                VerificationStatus::Unknown => b"unknown",
            },
        );
        hasher.update(evidence.observed_at_sequence.to_be_bytes());
        hasher.update(evidence.valid_through_sequence.to_be_bytes());
        match &evidence.action_fingerprint {
            Some(binding) => {
                hasher.update([1]);
                hash_field(&mut hasher, binding.as_bytes());
            }
            None => hasher.update([0]),
        }
    }
    format!("{:x}", hasher.finalize())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckResult {
    Pass,
    Fail,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionAssessment {
    pub condition_id: String,
    pub version: u32,
    pub assessor_id: String,
    pub result: CheckResult,
    pub reason: String,
    pub evidence_ids: Vec<String>,
}

/// Responses are attributed to the required principal and bound to both the
/// exact action and the separately canonicalised consequential terms. A
/// matching principal ID is paired with host authentication of the response
/// and verification of the responder's authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AcceptanceState {
    Pending,
    Refused {
        by_principal_id: String,
        action_fingerprint: String,
        terms_digest: String,
        at_sequence: u64,
    },
    Accepted {
        by_principal_id: String,
        action_fingerprint: String,
        terms_digest: String,
        at_sequence: u64,
        valid_through_sequence: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceRecord {
    pub requirement_id: String,
    pub state: AcceptanceState,
}

/// A request records its routing destination; its presence has no revoking effect.
/// A host may separately impose suspension, but must express that as an
/// applicable condition rather than treating a request as a completed decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationRequest {
    pub request_id: String,
    pub target_authority_id: String,
    pub requested_by: String,
    pub routed_to: String,
    pub at_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveRevocation {
    pub decision_id: String,
    pub target_authority_id: String,
    pub effective_at_sequence: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationState {
    pub pending_requests: Vec<RevocationRequest>,
    pub effective: Option<EffectiveRevocation>,
}

impl RevocationState {
    fn structurally_valid(&self, authority_id: &str, sequence: u64) -> bool {
        let mut seen = BTreeSet::new();
        if self.pending_requests.iter().any(|request| {
            request.request_id.is_empty()
                || !seen.insert(request.request_id.as_str())
                || request.target_authority_id != authority_id
                || request.requested_by.is_empty()
                || request.routed_to.is_empty()
                || request.at_sequence > sequence
        }) {
            return false;
        }
        self.effective.as_ref().is_none_or(|decision| {
            !decision.decision_id.is_empty() && decision.target_authority_id == authority_id
        })
    }

    fn is_effective(&self, sequence: u64) -> bool {
        self.effective
            .as_ref()
            .is_some_and(|decision| decision.effective_at_sequence <= sequence)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationSnapshot {
    pub schema_version: u16,
    pub context_id: String,
    pub context_version: u64,
    pub sequence: u64,
    pub valid_through_sequence: u64,
    pub profile: GateProfile,
    pub evidence: Vec<Evidence>,
    pub assessments: Vec<ConditionAssessment>,
    pub acceptances: Vec<AcceptanceRecord>,
    pub revocation: RevocationState,
}

fn encode_assessment(assessment: &ConditionAssessment) -> Vec<u8> {
    let mut bytes = Vec::new();
    append_field(&mut bytes, assessment.condition_id.as_bytes());
    bytes.extend_from_slice(&assessment.version.to_be_bytes());
    append_field(&mut bytes, assessment.assessor_id.as_bytes());
    append_field(
        &mut bytes,
        match assessment.result {
            CheckResult::Pass => b"pass",
            CheckResult::Fail => b"fail",
            CheckResult::Unknown => b"unknown",
        },
    );
    append_field(&mut bytes, assessment.reason.as_bytes());
    let mut evidence_ids = assessment.evidence_ids.clone();
    evidence_ids.sort();
    bytes.extend_from_slice(&(evidence_ids.len() as u64).to_be_bytes());
    for id in evidence_ids {
        append_field(&mut bytes, id.as_bytes());
    }
    bytes
}

fn encode_acceptance(record: &AcceptanceRecord) -> Vec<u8> {
    let mut bytes = Vec::new();
    append_field(&mut bytes, record.requirement_id.as_bytes());
    match &record.state {
        AcceptanceState::Pending => append_field(&mut bytes, b"pending"),
        AcceptanceState::Refused {
            by_principal_id,
            action_fingerprint,
            terms_digest,
            at_sequence,
        } => {
            append_field(&mut bytes, b"refused");
            append_field(&mut bytes, by_principal_id.as_bytes());
            append_field(&mut bytes, action_fingerprint.as_bytes());
            append_field(&mut bytes, terms_digest.as_bytes());
            bytes.extend_from_slice(&at_sequence.to_be_bytes());
        }
        AcceptanceState::Accepted {
            by_principal_id,
            action_fingerprint,
            terms_digest,
            at_sequence,
            valid_through_sequence,
        } => {
            append_field(&mut bytes, b"accepted");
            append_field(&mut bytes, by_principal_id.as_bytes());
            append_field(&mut bytes, action_fingerprint.as_bytes());
            append_field(&mut bytes, terms_digest.as_bytes());
            bytes.extend_from_slice(&at_sequence.to_be_bytes());
            bytes.extend_from_slice(&valid_through_sequence.to_be_bytes());
        }
    }
    bytes
}

fn encode_revocation_request(request: &RevocationRequest) -> Vec<u8> {
    let mut bytes = Vec::new();
    append_field(&mut bytes, request.request_id.as_bytes());
    append_field(&mut bytes, request.target_authority_id.as_bytes());
    append_field(&mut bytes, request.requested_by.as_bytes());
    append_field(&mut bytes, request.routed_to.as_bytes());
    bytes.extend_from_slice(&request.at_sequence.to_be_bytes());
    bytes
}

/// Canonical binding of the assessed conditions, acceptance responses and
/// revocation state presented for this decision. Record collections are sorted
/// by their complete encodings; evidence IDs within an assessment are sorted
/// because their order has no gate meaning. This is not an authentication tag.
fn decision_basis_fingerprint(snapshot: &EvaluationSnapshot) -> String {
    let mut hasher = Sha256::new();
    hash_field(
        &mut hasher,
        b"constitutive-action.experimental.v1.decision-basis",
    );
    hasher.update(snapshot.valid_through_sequence.to_be_bytes());
    hash_sorted_records(&mut hasher, &snapshot.assessments, encode_assessment);
    hash_sorted_records(&mut hasher, &snapshot.acceptances, encode_acceptance);
    hash_sorted_records(
        &mut hasher,
        &snapshot.revocation.pending_requests,
        encode_revocation_request,
    );
    match &snapshot.revocation.effective {
        Some(decision) => {
            hasher.update([1]);
            hash_field(&mut hasher, decision.decision_id.as_bytes());
            hash_field(&mut hasher, decision.target_authority_id.as_bytes());
            hasher.update(decision.effective_at_sequence.to_be_bytes());
        }
        None => hasher.update([0]),
    }
    format!("{:x}", hasher.finalize())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    Permitted,
    Prevented,
    DecisionRequired,
    Indeterminate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateDecision {
    pub schema_version: u16,
    pub kind: DecisionKind,
    pub reasons: Vec<String>,
    pub action_fingerprint: String,
    pub context_id: String,
    pub context_version: u64,
    pub sequence: u64,
    pub profile_id: String,
    pub profile_version: u32,
    pub profile_fingerprint: String,
    pub evidence_ids: Vec<String>,
    /// Exact evaluated evidence records, not just their mutable lookup IDs.
    pub evidence_snapshot_fingerprint: String,
    /// Complete evaluated assessments, acceptance responses, revocation state
    /// and snapshot validity bound to this decision. Empty only when reading a
    /// pre-binding local record; such a decision cannot validate a new receipt.
    #[serde(default)]
    pub decision_basis_fingerprint: String,
}

/// This in-process value checks the exact admitted effect and live state. The
/// host atomically reserves one attempt against durable current state and
/// coordinates that reservation with effective revocation.
#[derive(Debug, PartialEq, Eq)]
pub struct ExecutionAuthority {
    bound_intent: ActionIntent,
    bound_decision: GateDecision,
    admitted_sequence: u64,
    valid_through_sequence: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Admission {
    pub decision: GateDecision,
    pub authority: Option<ExecutionAuthority>,
}

fn admission(
    intent: &ActionIntent,
    snapshot: &EvaluationSnapshot,
    kind: DecisionKind,
    reasons: Vec<String>,
    evidence_ids: Vec<String>,
) -> Admission {
    let mut evidence_ids = evidence_ids;
    evidence_ids.sort();
    evidence_ids.dedup();
    let decision = GateDecision {
        schema_version: SCHEMA_VERSION,
        kind,
        reasons,
        action_fingerprint: intent.fingerprint(),
        context_id: snapshot.context_id.clone(),
        context_version: snapshot.context_version,
        sequence: snapshot.sequence,
        profile_id: snapshot.profile.profile_id.clone(),
        profile_version: snapshot.profile.version,
        profile_fingerprint: snapshot.profile.fingerprint(),
        evidence_snapshot_fingerprint: evaluated_evidence_fingerprint(
            &snapshot.evidence,
            &evidence_ids,
        ),
        decision_basis_fingerprint: decision_basis_fingerprint(snapshot),
        evidence_ids,
    };
    let authority = (kind == DecisionKind::Permitted).then(|| {
        // Permission cannot outlive an input on which this decision depends.
        // Unused evidence does not constrain the resulting authority.
        let mut expires = snapshot.valid_through_sequence;
        for evidence in &snapshot.evidence {
            if decision.evidence_ids.contains(&evidence.evidence_id) {
                expires = expires.min(evidence.valid_through_sequence);
            }
        }
        for requirement in &snapshot.profile.required_acceptances {
            if let Some(AcceptanceRecord {
                state:
                    AcceptanceState::Accepted {
                        valid_through_sequence,
                        ..
                    },
                ..
            }) = snapshot
                .acceptances
                .iter()
                .find(|a| a.requirement_id == requirement.requirement_id)
            {
                expires = expires.min(*valid_through_sequence);
            }
        }
        ExecutionAuthority {
            bound_intent: intent.clone(),
            bound_decision: decision.clone(),
            admitted_sequence: snapshot.sequence,
            valid_through_sequence: expires,
        }
    });
    Admission {
        decision,
        authority,
    }
}

fn decision_with_reason(
    intent: &ActionIntent,
    snapshot: &EvaluationSnapshot,
    kind: DecisionKind,
    reason: &str,
) -> Admission {
    admission(intent, snapshot, kind, vec![reason.into()], Vec::new())
}

/// Evaluate the supplied snapshot. The host establishes its completeness,
/// authenticity and freshness under the activity's policy; a verified flag
/// records the named verifier's assessment.
pub fn evaluate(intent: &ActionIntent, snapshot: &EvaluationSnapshot) -> Admission {
    if !intent.structurally_valid()
        || snapshot.schema_version != SCHEMA_VERSION
        || intent.context_id != snapshot.context_id
        || intent.context_version != snapshot.context_version
        || snapshot.sequence > snapshot.valid_through_sequence
        || snapshot.profile.profile_id.is_empty()
        || snapshot.profile.version == 0
        || snapshot.profile.effect_profile_id != intent.effect.profile_id
        || snapshot.profile.effect_profile_version != intent.effect.profile_version
        || !snapshot
            .revocation
            .structurally_valid(&intent.authority_id, snapshot.sequence)
    {
        return decision_with_reason(
            intent,
            snapshot,
            DecisionKind::Indeterminate,
            "unsupported, stale or inconsistent action context",
        );
    }

    if snapshot.revocation.is_effective(snapshot.sequence) {
        return decision_with_reason(
            intent,
            snapshot,
            DecisionKind::Prevented,
            "authority effectively revoked",
        );
    }

    let mut used_evidence = Vec::new();
    let mut fail_reasons = Vec::new();
    let mut has_unknown = false;
    match &snapshot.profile.conditions {
        ConditionPolicy::ExplicitOpen => {
            if !snapshot.assessments.is_empty() || !snapshot.evidence.is_empty() {
                return decision_with_reason(
                    intent,
                    snapshot,
                    DecisionKind::Indeterminate,
                    "explicit-open profile cannot silently ignore supplied assessments or evidence",
                );
            }
        }
        ConditionPolicy::Require(requirements) => {
            if requirements.is_empty()
                || requirements
                    .iter()
                    .any(|r| r.condition_id.is_empty() || r.version == 0)
            {
                return decision_with_reason(
                    intent,
                    snapshot,
                    DecisionKind::Indeterminate,
                    "required-condition profile has no valid requirements",
                );
            }
            let mut required = BTreeSet::new();
            if requirements
                .iter()
                .any(|r| !required.insert((r.condition_id.as_str(), r.version)))
            {
                return decision_with_reason(
                    intent,
                    snapshot,
                    DecisionKind::Indeterminate,
                    "duplicate required condition",
                );
            }
            let mut assessments_seen = BTreeSet::new();
            let mut evidence_seen = BTreeSet::new();
            if snapshot.evidence.iter().any(|item| {
                item.evidence_id.is_empty() || !evidence_seen.insert(item.evidence_id.as_str())
            }) || snapshot.assessments.iter().any(|assessment| {
                !assessments_seen.insert((assessment.condition_id.as_str(), assessment.version))
                    || !required.contains(&(assessment.condition_id.as_str(), assessment.version))
            }) {
                return decision_with_reason(
                    intent,
                    snapshot,
                    DecisionKind::Indeterminate,
                    "duplicate or unexpected assessment/evidence",
                );
            }
            for requirement in requirements {
                let Some(assessment) = snapshot.assessments.iter().find(|item| {
                    item.condition_id == requirement.condition_id
                        && item.version == requirement.version
                }) else {
                    return decision_with_reason(
                        intent,
                        snapshot,
                        DecisionKind::Indeterminate,
                        "required condition was not assessed",
                    );
                };
                if assessment.assessor_id.is_empty() || assessment.reason.is_empty() {
                    return decision_with_reason(
                        intent,
                        snapshot,
                        DecisionKind::Indeterminate,
                        "condition lacks attributed assessment",
                    );
                }
                if assessment.result == CheckResult::Unknown {
                    has_unknown = true;
                    continue;
                }
                if assessment.evidence_ids.is_empty() {
                    return decision_with_reason(
                        intent,
                        snapshot,
                        DecisionKind::Indeterminate,
                        "condition lacks evidence",
                    );
                }
                for evidence_id in &assessment.evidence_ids {
                    let Some(evidence) = snapshot
                        .evidence
                        .iter()
                        .find(|item| &item.evidence_id == evidence_id)
                    else {
                        return decision_with_reason(
                            intent,
                            snapshot,
                            DecisionKind::Indeterminate,
                            "condition references missing evidence",
                        );
                    };
                    if !evidence.valid_for(intent, snapshot.sequence) {
                        return decision_with_reason(
                            intent,
                            snapshot,
                            DecisionKind::Indeterminate,
                            "condition evidence is unverified, stale or mismatched",
                        );
                    }
                    if !used_evidence.contains(evidence_id) {
                        used_evidence.push(evidence_id.clone());
                    }
                }
                if assessment.result == CheckResult::Fail {
                    fail_reasons.push(format!(
                        "{}: {}",
                        assessment.condition_id, assessment.reason
                    ));
                }
            }
        }
    }

    let mut required_acceptance_ids = BTreeSet::new();
    let mut response_ids = BTreeSet::new();
    if snapshot
        .profile
        .required_acceptances
        .iter()
        .any(|requirement| {
            requirement.requirement_id.is_empty()
                || requirement.principal_id.is_empty()
                || !is_digest(&requirement.terms_digest)
                || !required_acceptance_ids.insert(requirement.requirement_id.as_str())
        })
        || snapshot.acceptances.iter().any(|record| {
            !response_ids.insert(record.requirement_id.as_str())
                || !required_acceptance_ids.contains(record.requirement_id.as_str())
        })
    {
        return admission(
            intent,
            snapshot,
            DecisionKind::Indeterminate,
            vec!["invalid or duplicate acceptance requirement/response".into()],
            used_evidence,
        );
    }
    if has_unknown {
        return admission(
            intent,
            snapshot,
            DecisionKind::Indeterminate,
            vec!["one or more required conditions are unknown".into()],
            used_evidence,
        );
    }

    if !fail_reasons.is_empty() {
        return admission(
            intent,
            snapshot,
            DecisionKind::Prevented,
            fail_reasons,
            used_evidence,
        );
    }
    let mut pending = Vec::new();
    for requirement in &snapshot.profile.required_acceptances {
        let response = snapshot
            .acceptances
            .iter()
            .find(|item| item.requirement_id == requirement.requirement_id);
        let Some(response) = response else {
            pending.push(requirement.requirement_id.clone());
            continue;
        };
        let (by, action, terms, at, expires, refused) = match &response.state {
            AcceptanceState::Pending => {
                pending.push(requirement.requirement_id.clone());
                continue;
            }
            AcceptanceState::Refused {
                by_principal_id,
                action_fingerprint,
                terms_digest,
                at_sequence,
            } => (
                by_principal_id,
                action_fingerprint,
                terms_digest,
                *at_sequence,
                None,
                true,
            ),
            AcceptanceState::Accepted {
                by_principal_id,
                action_fingerprint,
                terms_digest,
                at_sequence,
                valid_through_sequence,
            } => (
                by_principal_id,
                action_fingerprint,
                terms_digest,
                *at_sequence,
                Some(*valid_through_sequence),
                false,
            ),
        };
        if by != &requirement.principal_id
            || action != &intent.fingerprint()
            || terms != &requirement.terms_digest
            || at > snapshot.sequence
            || expires.is_some_and(|end| snapshot.sequence > end)
        {
            pending.push(requirement.requirement_id.clone());
        } else if refused {
            return admission(
                intent,
                snapshot,
                DecisionKind::Prevented,
                vec![format!(
                    "acceptance refused by {}",
                    requirement.principal_id
                )],
                used_evidence,
            );
        }
    }
    if !pending.is_empty() {
        return admission(
            intent,
            snapshot,
            DecisionKind::DecisionRequired,
            vec![format!("acceptance required: {}", pending.join(", "))],
            used_evidence,
        );
    }
    admission(
        intent,
        snapshot,
        DecisionKind::Permitted,
        vec!["all required conditions and acceptances satisfied".into()],
        used_evidence,
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveAuthorityState {
    /// Absent only when reading a pre-version local record. Such a record is
    /// legacy/read-only and cannot authorize a new dispatch.
    #[serde(default)]
    pub schema_version: u16,
    pub authority_id: String,
    pub context_id: String,
    pub context_version: u64,
    pub profile_fingerprint: String,
    pub sequence: u64,
    pub revocation: RevocationState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityError {
    DifferentAction,
    StaleOrInvalidState,
    EffectivelyRevoked,
}

impl ExecutionAuthority {
    /// Check the admitted effect and live state before dispatch. The host
    /// coordinates this check with one durable dispatch reservation and
    /// effective revocation, preserving an idempotency identity for recovery.
    pub fn check_pre_dispatch(
        &self,
        attempted: &ActionIntent,
        live: &LiveAuthorityState,
    ) -> Result<(), AuthorityError> {
        if attempted != &self.bound_intent {
            return Err(AuthorityError::DifferentAction);
        }
        if self.bound_intent.schema_version != SCHEMA_VERSION
            || self.bound_decision.schema_version != SCHEMA_VERSION
            || live.schema_version != SCHEMA_VERSION
            || live.authority_id != attempted.authority_id
            || live.context_id != attempted.context_id
            || live.context_version != attempted.context_version
            || !is_digest(&self.bound_decision.decision_basis_fingerprint)
            || live.profile_fingerprint != self.bound_decision.profile_fingerprint
            || live.sequence < self.admitted_sequence
            || live.sequence > self.valid_through_sequence
            || !live
                .revocation
                .structurally_valid(&attempted.authority_id, live.sequence)
        {
            return Err(AuthorityError::StaleOrInvalidState);
        }
        if live.revocation.is_effective(live.sequence) {
            return Err(AuthorityError::EffectivelyRevoked);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutionOutcome {
    NotDispatched,
    Confirmed { occurrence_id: String },
    Rejected { reason: String },
    Uncertain { reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionReceipt {
    /// Absent only when reading a pre-version local record. Such a record is
    /// legacy/read-only and cannot validate as a current v1 receipt.
    #[serde(default)]
    pub schema_version: u16,
    pub proposal_id: String,
    pub action_fingerprint: String,
    pub decision: GateDecision,
    pub executor_id: Option<String>,
    pub attempt_id: Option<String>,
    pub outcome: ExecutionOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptError {
    UnsupportedVersion,
    InvalidAdmission,
    ActionOrDecisionMismatch,
    NonPermittedDispatch,
    InvalidAttemptShape,
}

/// Validate the structural link between the receipt, admission and action.
/// The host supplies adapter evidence of occurrence and capability mediation.
pub fn validate_receipt(
    intent: &ActionIntent,
    admission: &Admission,
    receipt: &ActionReceipt,
) -> Result<(), ReceiptError> {
    if intent.schema_version != SCHEMA_VERSION || receipt.schema_version != SCHEMA_VERSION {
        return Err(ReceiptError::UnsupportedVersion);
    }
    if admission.decision.schema_version != SCHEMA_VERSION
        || admission.decision.action_fingerprint != intent.fingerprint()
        || admission.decision.context_id != intent.context_id
        || admission.decision.context_version != intent.context_version
        || admission.decision.profile_id.is_empty()
        || admission.decision.profile_version == 0
        || !is_digest(&admission.decision.profile_fingerprint)
        || !is_digest(&admission.decision.evidence_snapshot_fingerprint)
        || !is_digest(&admission.decision.decision_basis_fingerprint)
        || (admission.decision.kind == DecisionKind::Permitted) != admission.authority.is_some()
        || admission.authority.as_ref().is_some_and(|authority| {
            authority.bound_intent != *intent
                || authority.bound_decision != admission.decision
                || authority.admitted_sequence != admission.decision.sequence
                || authority.valid_through_sequence < authority.admitted_sequence
        })
    {
        return Err(ReceiptError::InvalidAdmission);
    }
    if receipt.proposal_id != intent.proposal_id
        || receipt.action_fingerprint != intent.fingerprint()
        || receipt.decision != admission.decision
    {
        return Err(ReceiptError::ActionOrDecisionMismatch);
    }
    if admission.decision.kind != DecisionKind::Permitted
        && !matches!(receipt.outcome, ExecutionOutcome::NotDispatched)
    {
        return Err(ReceiptError::NonPermittedDispatch);
    }
    let no_attempt = receipt.executor_id.is_none() && receipt.attempt_id.is_none();
    let valid_attempt = receipt
        .executor_id
        .as_ref()
        .is_some_and(|value| !value.is_empty())
        && receipt
            .attempt_id
            .as_ref()
            .is_some_and(|value| !value.is_empty());
    let valid = match &receipt.outcome {
        ExecutionOutcome::NotDispatched => no_attempt,
        ExecutionOutcome::Confirmed { occurrence_id } => valid_attempt && !occurrence_id.is_empty(),
        ExecutionOutcome::Rejected { reason } | ExecutionOutcome::Uncertain { reason } => {
            valid_attempt && !reason.is_empty()
        }
    };
    if !valid {
        return Err(ReceiptError::InvalidAttemptShape);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;
    use serde_json::{Value, json};

    fn reject_unknown<T: Serialize + DeserializeOwned>(item: &T) {
        let mut value = serde_json::to_value(item).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unsupported_required_field".into(), json!(true));
        assert!(serde_json::from_value::<T>(value).is_err());
    }

    fn intent() -> ActionIntent {
        ActionIntent {
            schema_version: SCHEMA_VERSION,
            proposal_id: "proposal-1".into(),
            actor_id: "agent-1".into(),
            represented_principal_id: "person-1".into(),
            authority_id: "delegation-1".into(),
            context_id: "activity-1".into(),
            context_version: 2,
            effect: Effect {
                profile_id: "example.message".into(),
                profile_version: 1,
                operation: "send".into(),
                destination: "inbox-1".into(),
                canonical_payload: b"hello".to_vec(),
            },
        }
    }

    fn snapshot(policy: ConditionPolicy) -> EvaluationSnapshot {
        EvaluationSnapshot {
            schema_version: SCHEMA_VERSION,
            context_id: "activity-1".into(),
            context_version: 2,
            sequence: 4,
            valid_through_sequence: 4,
            profile: GateProfile {
                profile_id: "example-gate".into(),
                version: 1,
                effect_profile_id: "example.message".into(),
                effect_profile_version: 1,
                conditions: policy,
                required_acceptances: vec![],
            },
            evidence: vec![],
            assessments: vec![],
            acceptances: vec![],
            revocation: RevocationState::default(),
        }
    }

    fn required() -> EvaluationSnapshot {
        let mut context = snapshot(ConditionPolicy::Require(vec![ConditionRequirement {
            condition_id: "membership".into(),
            version: 1,
        }]));
        context.evidence.push(Evidence {
            evidence_id: "membership-proof".into(),
            kind: "membership".into(),
            schema_version: 1,
            subject_id: "person-1".into(),
            issuer_id: "host-1".into(),
            content_sha256: sha256_hex(b"active membership"),
            verifier_id: Some("host-verifier-1".into()),
            verification: VerificationStatus::Verified,
            observed_at_sequence: 4,
            valid_through_sequence: 4,
            action_fingerprint: None,
        });
        context.assessments.push(ConditionAssessment {
            condition_id: "membership".into(),
            version: 1,
            assessor_id: "host-1".into(),
            result: CheckResult::Pass,
            reason: "active".into(),
            evidence_ids: vec!["membership-proof".into()],
        });
        context
    }

    fn live() -> LiveAuthorityState {
        LiveAuthorityState {
            schema_version: SCHEMA_VERSION,
            authority_id: "delegation-1".into(),
            context_id: "activity-1".into(),
            context_version: 2,
            profile_fingerprint: required().profile.fingerprint(),
            sequence: 4,
            revocation: RevocationState::default(),
        }
    }

    #[test]
    fn fingerprint_binds_exact_effect_and_profile_version() {
        let original = intent();
        for changed in [
            ActionIntent {
                proposal_id: "proposal-2".into(),
                ..original.clone()
            },
            ActionIntent {
                effect: Effect {
                    destination: "inbox-2".into(),
                    ..original.effect.clone()
                },
                ..original.clone()
            },
            ActionIntent {
                effect: Effect {
                    canonical_payload: b"goodbye".to_vec(),
                    ..original.effect.clone()
                },
                ..original.clone()
            },
            ActionIntent {
                effect: Effect {
                    profile_version: 2,
                    ..original.effect.clone()
                },
                ..original.clone()
            },
        ] {
            assert_ne!(original.fingerprint(), changed.fingerprint());
        }
        assert_eq!(original.fingerprint(), original.clone().fingerprint());
    }

    #[test]
    fn open_must_be_explicit_and_required_checks_cannot_be_empty() {
        let action = intent();
        assert_eq!(
            evaluate(&action, &snapshot(ConditionPolicy::ExplicitOpen))
                .decision
                .kind,
            DecisionKind::Permitted
        );
        let mut open_with_unchecked_evidence = snapshot(ConditionPolicy::ExplicitOpen);
        open_with_unchecked_evidence.evidence = required().evidence;
        assert_eq!(
            evaluate(&action, &open_with_unchecked_evidence)
                .decision
                .kind,
            DecisionKind::Indeterminate
        );
        let empty = evaluate(&action, &snapshot(ConditionPolicy::Require(vec![])));
        assert_eq!(empty.decision.kind, DecisionKind::Indeterminate);
        assert!(empty.authority.is_none());
    }

    #[test]
    fn required_conditions_need_attributed_fresh_verified_evidence() {
        let action = intent();
        let mut context = required();
        assert_eq!(
            evaluate(&action, &context).decision.kind,
            DecisionKind::Permitted
        );
        context.evidence[0].verification = VerificationStatus::Unknown;
        assert_eq!(
            evaluate(&action, &context).decision.kind,
            DecisionKind::Indeterminate
        );
        context.evidence[0].verification = VerificationStatus::Verified;
        context.evidence[0].valid_through_sequence = 3;
        assert_eq!(
            evaluate(&action, &context).decision.kind,
            DecisionKind::Indeterminate
        );
        context.evidence[0].valid_through_sequence = 4;
        context.evidence[0].action_fingerprint = Some("wrong".into());
        assert_eq!(
            evaluate(&action, &context).decision.kind,
            DecisionKind::Indeterminate
        );
        context.evidence[0].action_fingerprint = Some(action.fingerprint());
        assert_eq!(
            evaluate(&action, &context).decision.kind,
            DecisionKind::Permitted
        );
        context.assessments[0].evidence_ids.clear();
        assert_eq!(
            evaluate(&action, &context).decision.kind,
            DecisionKind::Indeterminate
        );
        context.assessments.clear();
        assert_eq!(
            evaluate(&action, &context).decision.kind,
            DecisionKind::Indeterminate
        );
    }

    #[test]
    fn same_evidence_id_with_changed_content_or_issuer_changes_decision_basis() {
        let action = intent();
        let original = evaluate(&action, &required());
        assert_eq!(original.decision.kind, DecisionKind::Permitted);

        let mut changed_content = required();
        changed_content.evidence[0].content_sha256 = sha256_hex(b"different membership claim");
        let content_decision = evaluate(&action, &changed_content).decision;
        assert_eq!(content_decision.kind, DecisionKind::Permitted);
        assert_eq!(
            original.decision.evidence_ids,
            content_decision.evidence_ids
        );
        assert_ne!(
            original.decision.evidence_snapshot_fingerprint,
            content_decision.evidence_snapshot_fingerprint
        );

        let mut changed_issuer = required();
        changed_issuer.evidence[0].issuer_id = "host-2".into();
        let issuer_decision = evaluate(&action, &changed_issuer).decision;
        assert_eq!(issuer_decision.kind, DecisionKind::Permitted);
        assert_eq!(original.decision.evidence_ids, issuer_decision.evidence_ids);
        assert_ne!(
            original.decision.evidence_snapshot_fingerprint,
            issuer_decision.evidence_snapshot_fingerprint
        );

        let mut tampered_admission = original;
        tampered_admission.decision.evidence_snapshot_fingerprint =
            content_decision.evidence_snapshot_fingerprint;
        let receipt = ActionReceipt {
            schema_version: SCHEMA_VERSION,
            proposal_id: action.proposal_id.clone(),
            action_fingerprint: action.fingerprint(),
            decision: tampered_admission.decision.clone(),
            executor_id: None,
            attempt_id: None,
            outcome: ExecutionOutcome::NotDispatched,
        };
        assert_eq!(
            validate_receipt(&action, &tampered_admission, &receipt),
            Err(ReceiptError::InvalidAdmission)
        );
    }

    #[test]
    fn decision_basis_binds_assessor_result_and_reason_without_order_dependence() {
        let action = intent();
        let original = required();
        let original_decision = evaluate(&action, &original).decision;
        assert_eq!(original_decision.kind, DecisionKind::Permitted);

        let mut changed = original.clone();
        changed.assessments[0].assessor_id = "another-assessor".into();
        assert_ne!(
            original_decision.decision_basis_fingerprint,
            evaluate(&action, &changed)
                .decision
                .decision_basis_fingerprint
        );
        changed = original.clone();
        changed.assessments[0].reason = "same result, different explanation".into();
        assert_eq!(
            evaluate(&action, &changed).decision.kind,
            DecisionKind::Permitted
        );
        assert_ne!(
            original_decision.decision_basis_fingerprint,
            evaluate(&action, &changed)
                .decision
                .decision_basis_fingerprint
        );
        changed = original.clone();
        changed.assessments[0].result = CheckResult::Fail;
        assert_eq!(
            evaluate(&action, &changed).decision.kind,
            DecisionKind::Prevented
        );
        assert_ne!(
            original_decision.decision_basis_fingerprint,
            evaluate(&action, &changed)
                .decision
                .decision_basis_fingerprint
        );

        let mut two_conditions = original;
        if let ConditionPolicy::Require(requirements) = &mut two_conditions.profile.conditions {
            requirements.push(ConditionRequirement {
                condition_id: "bot-binding".into(),
                version: 1,
            });
        }
        let mut second = two_conditions.assessments[0].clone();
        second.condition_id = "bot-binding".into();
        two_conditions.assessments.push(second);
        let ordered = evaluate(&action, &two_conditions).decision;
        assert_eq!(ordered.kind, DecisionKind::Permitted);
        two_conditions.assessments.reverse();
        let reversed = evaluate(&action, &two_conditions).decision;
        assert_eq!(
            ordered.decision_basis_fingerprint,
            reversed.decision_basis_fingerprint
        );
    }

    #[test]
    fn decision_basis_binds_exact_acceptance_response_and_ignores_record_order() {
        let action = intent();
        let mut context = required();
        let bob_terms = sha256_hex(b"Bob's exact task terms");
        let carol_terms = sha256_hex(b"Carol's exact task terms");
        context.profile.required_acceptances.extend([
            AcceptanceRequirement {
                requirement_id: "accept-bob".into(),
                principal_id: "bob".into(),
                terms_digest: bob_terms.clone(),
            },
            AcceptanceRequirement {
                requirement_id: "accept-carol".into(),
                principal_id: "carol".into(),
                terms_digest: carol_terms.clone(),
            },
        ]);
        context.acceptances.extend([
            AcceptanceRecord {
                requirement_id: "accept-bob".into(),
                state: AcceptanceState::Accepted {
                    by_principal_id: "bob".into(),
                    action_fingerprint: action.fingerprint(),
                    terms_digest: bob_terms.clone(),
                    at_sequence: 3,
                    valid_through_sequence: 4,
                },
            },
            AcceptanceRecord {
                requirement_id: "accept-carol".into(),
                state: AcceptanceState::Accepted {
                    by_principal_id: "carol".into(),
                    action_fingerprint: action.fingerprint(),
                    terms_digest: carol_terms,
                    at_sequence: 4,
                    valid_through_sequence: 4,
                },
            },
        ]);
        let baseline = evaluate(&action, &context).decision;
        assert_eq!(baseline.kind, DecisionKind::Permitted);

        let mut changed = context.clone();
        if let AcceptanceState::Accepted {
            by_principal_id, ..
        } = &mut changed.acceptances[0].state
        {
            *by_principal_id = "mallory".into();
        }
        assert_ne!(
            baseline.decision_basis_fingerprint,
            evaluate(&action, &changed)
                .decision
                .decision_basis_fingerprint
        );
        changed = context.clone();
        if let AcceptanceState::Accepted { at_sequence, .. } = &mut changed.acceptances[0].state {
            *at_sequence = 4;
        }
        assert_eq!(
            evaluate(&action, &changed).decision.kind,
            DecisionKind::Permitted
        );
        assert_ne!(
            baseline.decision_basis_fingerprint,
            evaluate(&action, &changed)
                .decision
                .decision_basis_fingerprint
        );
        changed = context.clone();
        if let AcceptanceState::Accepted { terms_digest, .. } = &mut changed.acceptances[0].state {
            *terms_digest = sha256_hex(b"different consequential terms");
        }
        assert_ne!(
            baseline.decision_basis_fingerprint,
            evaluate(&action, &changed)
                .decision
                .decision_basis_fingerprint
        );
        context.acceptances.reverse();
        assert_eq!(
            baseline.decision_basis_fingerprint,
            evaluate(&action, &context)
                .decision
                .decision_basis_fingerprint
        );
    }

    #[test]
    fn decision_basis_binds_pending_and_effective_revocation_without_order_dependence() {
        let action = intent();
        let mut context = required();
        let baseline = evaluate(&action, &context).decision;
        context.revocation.pending_requests.push(RevocationRequest {
            request_id: "request-1".into(),
            target_authority_id: action.authority_id.clone(),
            requested_by: "person-1".into(),
            routed_to: "project-owner".into(),
            at_sequence: 3,
        });
        let pending = evaluate(&action, &context).decision;
        assert_eq!(pending.kind, DecisionKind::Permitted);
        assert_ne!(
            baseline.decision_basis_fingerprint,
            pending.decision_basis_fingerprint
        );

        let mut changed = context.clone();
        changed.revocation.pending_requests[0].routed_to = "different-reviewer".into();
        assert_ne!(
            pending.decision_basis_fingerprint,
            evaluate(&action, &changed)
                .decision
                .decision_basis_fingerprint
        );
        context.revocation.pending_requests.push(RevocationRequest {
            request_id: "request-2".into(),
            target_authority_id: action.authority_id.clone(),
            requested_by: "person-2".into(),
            routed_to: "project-owner".into(),
            at_sequence: 4,
        });
        let ordered = evaluate(&action, &context).decision;
        context.revocation.pending_requests.reverse();
        assert_eq!(
            ordered.decision_basis_fingerprint,
            evaluate(&action, &context)
                .decision
                .decision_basis_fingerprint
        );

        context.revocation.effective = Some(EffectiveRevocation {
            decision_id: "decision-1".into(),
            target_authority_id: action.authority_id.clone(),
            effective_at_sequence: 5,
        });
        let future = evaluate(&action, &context).decision;
        assert_eq!(future.kind, DecisionKind::Permitted);
        assert_ne!(
            ordered.decision_basis_fingerprint,
            future.decision_basis_fingerprint
        );
        context
            .revocation
            .effective
            .as_mut()
            .unwrap()
            .effective_at_sequence = 4;
        let effective = evaluate(&action, &context).decision;
        assert_eq!(effective.kind, DecisionKind::Prevented);
        assert_ne!(
            future.decision_basis_fingerprint,
            effective.decision_basis_fingerprint
        );
    }

    #[test]
    fn decision_basis_has_a_golden_digest_and_old_wire_is_read_only() {
        let action = intent();
        let original = evaluate(&action, &required());
        assert_eq!(
            original.decision.decision_basis_fingerprint,
            "164039790d47cd7424737f5249ae8db7d4a4413a4c98927b7a2122cb53021245"
        );
        let mut old_wire = serde_json::to_value(&original.decision).unwrap();
        old_wire
            .as_object_mut()
            .unwrap()
            .remove("decision_basis_fingerprint");
        let old_decision: GateDecision = serde_json::from_value(old_wire).unwrap();
        assert!(old_decision.decision_basis_fingerprint.is_empty());

        let old_receipt = ActionReceipt {
            schema_version: SCHEMA_VERSION,
            proposal_id: action.proposal_id.clone(),
            action_fingerprint: action.fingerprint(),
            decision: old_decision.clone(),
            executor_id: Some("earlier-local-adapter".into()),
            attempt_id: Some("earlier-attempt".into()),
            outcome: ExecutionOutcome::Confirmed {
                occurrence_id: "earlier-event".into(),
            },
        };
        let mut receipt_wire = serde_json::to_value(&old_receipt).unwrap();
        receipt_wire["decision"]
            .as_object_mut()
            .unwrap()
            .remove("decision_basis_fingerprint");
        let loaded: ActionReceipt = serde_json::from_value(receipt_wire).unwrap();
        assert!(loaded.decision.decision_basis_fingerprint.is_empty());

        let mut old_admission = original;
        old_admission.decision = old_decision.clone();
        let receipt = ActionReceipt {
            schema_version: SCHEMA_VERSION,
            proposal_id: action.proposal_id.clone(),
            action_fingerprint: action.fingerprint(),
            decision: old_decision,
            executor_id: None,
            attempt_id: None,
            outcome: ExecutionOutcome::NotDispatched,
        };
        assert_eq!(
            validate_receipt(&action, &old_admission, &receipt),
            Err(ReceiptError::InvalidAdmission)
        );
        let mut legacy_authority = evaluate(&action, &required()).authority.unwrap();
        legacy_authority
            .bound_decision
            .decision_basis_fingerprint
            .clear();
        assert_eq!(
            legacy_authority.check_pre_dispatch(&action, &live()),
            Err(AuthorityError::StaleOrInvalidState)
        );

        let mut changed_validity = required();
        changed_validity.valid_through_sequence += 1;
        assert_ne!(
            old_admission
                .authority
                .unwrap()
                .bound_decision
                .decision_basis_fingerprint,
            evaluate(&action, &changed_validity)
                .decision
                .decision_basis_fingerprint
        );
    }

    #[test]
    fn evaluated_evidence_fingerprint_is_order_independent_and_excludes_unused_records() {
        let action = intent();
        let mut context = required();
        let mut second = context.evidence[0].clone();
        second.evidence_id = "secondary-proof".into();
        second.content_sha256 = sha256_hex(b"supplemental membership proof");
        context.evidence.push(second);
        context.assessments[0]
            .evidence_ids
            .push("secondary-proof".into());

        let initial = evaluate(&action, &context).decision;
        assert_eq!(initial.kind, DecisionKind::Permitted);
        context.evidence.reverse();
        context.assessments[0].evidence_ids.reverse();
        let reordered = evaluate(&action, &context).decision;
        assert_eq!(
            initial.evidence_snapshot_fingerprint,
            reordered.evidence_snapshot_fingerprint
        );

        let mut unused = context.evidence[0].clone();
        unused.evidence_id = "unused-proof".into();
        unused.content_sha256 = sha256_hex(b"not used by an assessment");
        context.evidence.push(unused);
        let with_unused = evaluate(&action, &context).decision;
        assert_eq!(
            initial.evidence_snapshot_fingerprint,
            with_unused.evidence_snapshot_fingerprint
        );
    }

    #[test]
    fn fail_unknown_and_unsupported_versions_never_create_authority() {
        let action = intent();
        let mut context = required();
        context.assessments[0].result = CheckResult::Fail;
        assert_eq!(
            evaluate(&action, &context).decision.kind,
            DecisionKind::Prevented
        );
        context.assessments[0].result = CheckResult::Unknown;
        assert_eq!(
            evaluate(&action, &context).decision.kind,
            DecisionKind::Indeterminate
        );
        context.assessments[0].result = CheckResult::Pass;
        context.schema_version += 1;
        let result = evaluate(&action, &context);
        assert_eq!(result.decision.kind, DecisionKind::Indeterminate);
        assert!(result.authority.is_none());
    }

    #[test]
    fn gate_profile_must_match_the_typed_effect() {
        let action = intent();
        let mut context = required();
        context.profile.effect_profile_id = "another.effect".into();
        let result = evaluate(&action, &context);
        assert_eq!(result.decision.kind, DecisionKind::Indeterminate);
        assert!(result.authority.is_none());
        context.profile.effect_profile_id = action.effect.profile_id.clone();
        context.profile.effect_profile_version += 1;
        assert_eq!(
            evaluate(&action, &context).decision.kind,
            DecisionKind::Indeterminate
        );
    }

    #[test]
    fn acceptance_is_bound_to_exact_action_terms_and_responder() {
        let action = intent();
        let mut context = required();
        let terms = sha256_hex(b"assignment v1");
        context
            .profile
            .required_acceptances
            .push(AcceptanceRequirement {
                requirement_id: "accept-bob".into(),
                principal_id: "bob".into(),
                terms_digest: terms.clone(),
            });
        assert_eq!(
            evaluate(&action, &context).decision.kind,
            DecisionKind::DecisionRequired
        );
        context.acceptances.push(AcceptanceRecord {
            requirement_id: "accept-bob".into(),
            state: AcceptanceState::Pending,
        });
        assert_eq!(
            evaluate(&action, &context).decision.kind,
            DecisionKind::DecisionRequired
        );
        context.acceptances[0].state = AcceptanceState::Accepted {
            by_principal_id: "bob".into(),
            action_fingerprint: action.fingerprint(),
            terms_digest: terms.clone(),
            at_sequence: 4,
            valid_through_sequence: 4,
        };
        assert_eq!(
            evaluate(&action, &context).decision.kind,
            DecisionKind::Permitted
        );
        context.profile.required_acceptances[0].terms_digest = sha256_hex(b"assignment v2");
        assert_eq!(
            evaluate(&action, &context).decision.kind,
            DecisionKind::DecisionRequired
        );
        context.profile.required_acceptances[0].terms_digest = terms.clone();
        context.acceptances[0].state = AcceptanceState::Refused {
            by_principal_id: "bob".into(),
            action_fingerprint: action.fingerprint(),
            terms_digest: terms.clone(),
            at_sequence: 4,
        };
        assert_eq!(
            evaluate(&action, &context).decision.kind,
            DecisionKind::Prevented
        );
        context.acceptances[0].state = AcceptanceState::Accepted {
            by_principal_id: "mallory".into(),
            action_fingerprint: action.fingerprint(),
            terms_digest: terms,
            at_sequence: 4,
            valid_through_sequence: 4,
        };
        assert_eq!(
            evaluate(&action, &context).decision.kind,
            DecisionKind::DecisionRequired
        );
    }

    #[test]
    fn pending_revocation_does_not_block_but_effective_revocation_does() {
        let action = intent();
        let mut context = required();
        context.revocation.pending_requests.push(RevocationRequest {
            request_id: "request-1".into(),
            target_authority_id: "delegation-1".into(),
            requested_by: "person-1".into(),
            routed_to: "project-owner".into(),
            at_sequence: 4,
        });
        assert_eq!(
            evaluate(&action, &context).decision.kind,
            DecisionKind::Permitted
        );
        context.revocation.effective = Some(EffectiveRevocation {
            decision_id: "decision-1".into(),
            target_authority_id: "delegation-1".into(),
            effective_at_sequence: 4,
        });
        assert_eq!(
            evaluate(&action, &context).decision.kind,
            DecisionKind::Prevented
        );
        context
            .revocation
            .effective
            .as_mut()
            .unwrap()
            .effective_at_sequence = 5;
        assert_eq!(
            evaluate(&action, &context).decision.kind,
            DecisionKind::Permitted
        );
    }

    #[test]
    fn pre_dispatch_checks_exact_action_and_current_effective_state() {
        let action = intent();
        let authority = evaluate(&action, &required()).authority.unwrap();
        let mut state = live();
        state.revocation.pending_requests.push(RevocationRequest {
            request_id: "request-1".into(),
            target_authority_id: "delegation-1".into(),
            requested_by: "person-1".into(),
            routed_to: "project-owner".into(),
            at_sequence: 4,
        });
        assert_eq!(authority.check_pre_dispatch(&action, &state), Ok(()));
        let mut altered = action.clone();
        altered.effect.canonical_payload = b"altered".to_vec();
        assert_eq!(
            authority.check_pre_dispatch(&altered, &state),
            Err(AuthorityError::DifferentAction)
        );
        state.context_id = "other-activity".into();
        assert_eq!(
            authority.check_pre_dispatch(&action, &state),
            Err(AuthorityError::StaleOrInvalidState)
        );
        state.context_id = action.context_id.clone();
        state.profile_fingerprint = sha256_hex(b"another gate profile");
        assert_eq!(
            authority.check_pre_dispatch(&action, &state),
            Err(AuthorityError::StaleOrInvalidState)
        );
        state.profile_fingerprint = required().profile.fingerprint();
        state.revocation.effective = Some(EffectiveRevocation {
            decision_id: "decision-1".into(),
            target_authority_id: "delegation-1".into(),
            effective_at_sequence: 4,
        });
        assert_eq!(
            authority.check_pre_dispatch(&action, &state),
            Err(AuthorityError::EffectivelyRevoked)
        );
        state.revocation.effective = None;
        state.sequence += 1;
        assert_eq!(
            authority.check_pre_dispatch(&action, &state),
            Err(AuthorityError::StaleOrInvalidState)
        );
    }

    #[test]
    fn gate_profile_content_change_stales_prior_authority_even_at_same_version() {
        let action = intent();
        let original = required();
        let authority = evaluate(&action, &original).authority.unwrap();
        let mut changed = original.profile.clone();
        changed.conditions = ConditionPolicy::ExplicitOpen;
        assert_ne!(original.profile.fingerprint(), changed.fingerprint());
        let mut state = live();
        state.profile_fingerprint = changed.fingerprint();
        assert_eq!(
            authority.check_pre_dispatch(&action, &state),
            Err(AuthorityError::StaleOrInvalidState)
        );

        changed = original.profile.clone();
        changed.required_acceptances.push(AcceptanceRequirement {
            requirement_id: "accept-bob".into(),
            principal_id: "bob".into(),
            terms_digest: sha256_hex(b"new consequential terms"),
        });
        assert_ne!(original.profile.fingerprint(), changed.fingerprint());
        state.profile_fingerprint = changed.fingerprint();
        assert_eq!(
            authority.check_pre_dispatch(&action, &state),
            Err(AuthorityError::StaleOrInvalidState)
        );
        // A fresh evaluation under the changed profile requires the new
        // acceptance rather than inheriting an old admission.
        let mut changed_snapshot = required();
        changed_snapshot.profile = changed;
        assert_eq!(
            evaluate(&action, &changed_snapshot).decision.kind,
            DecisionKind::DecisionRequired
        );
    }

    #[test]
    fn receipt_validation_is_structural_and_fail_closed() {
        let action = intent();
        let permitted = evaluate(&action, &required());
        let mut receipt = ActionReceipt {
            schema_version: SCHEMA_VERSION,
            proposal_id: action.proposal_id.clone(),
            action_fingerprint: action.fingerprint(),
            decision: permitted.decision.clone(),
            executor_id: Some("adapter-1".into()),
            attempt_id: Some("idempotency-1".into()),
            outcome: ExecutionOutcome::Confirmed {
                occurrence_id: "event-1".into(),
            },
        };
        assert_eq!(validate_receipt(&action, &permitted, &receipt), Ok(()));
        receipt.outcome = ExecutionOutcome::Confirmed {
            occurrence_id: String::new(),
        };
        assert_eq!(
            validate_receipt(&action, &permitted, &receipt),
            Err(ReceiptError::InvalidAttemptShape)
        );
        let mut refused_context = required();
        refused_context.assessments[0].result = CheckResult::Fail;
        let refused = evaluate(&action, &refused_context);
        receipt.decision = refused.decision.clone();
        receipt.outcome = ExecutionOutcome::Confirmed {
            occurrence_id: "event-1".into(),
        };
        assert_eq!(
            validate_receipt(&action, &refused, &receipt),
            Err(ReceiptError::NonPermittedDispatch)
        );
        receipt.outcome = ExecutionOutcome::NotDispatched;
        receipt.executor_id = None;
        receipt.attempt_id = None;
        assert_eq!(validate_receipt(&action, &refused, &receipt), Ok(()));
        receipt.action_fingerprint = "wrong".into();
        assert_eq!(
            validate_receipt(&action, &refused, &receipt),
            Err(ReceiptError::ActionOrDecisionMismatch)
        );
    }

    #[test]
    fn fabricated_or_inconsistent_admission_cannot_validate_a_receipt() {
        let action = intent();
        let mut admission = evaluate(&action, &required());
        let mut receipt = ActionReceipt {
            schema_version: SCHEMA_VERSION,
            proposal_id: action.proposal_id.clone(),
            action_fingerprint: action.fingerprint(),
            decision: admission.decision.clone(),
            executor_id: Some("adapter-1".into()),
            attempt_id: Some("attempt-1".into()),
            outcome: ExecutionOutcome::Confirmed {
                occurrence_id: "event-1".into(),
            },
        };
        admission.decision.action_fingerprint = "forged".into();
        receipt.decision = admission.decision.clone();
        assert_eq!(
            validate_receipt(&action, &admission, &receipt),
            Err(ReceiptError::InvalidAdmission)
        );
        let mut admission = evaluate(&action, &required());
        admission.authority = None;
        receipt.decision = admission.decision.clone();
        assert_eq!(
            validate_receipt(&action, &admission, &receipt),
            Err(ReceiptError::InvalidAdmission)
        );
        let mut admission = evaluate(&action, &required());
        admission.decision.schema_version += 1;
        receipt.decision = admission.decision.clone();
        assert_eq!(
            validate_receipt(&action, &admission, &receipt),
            Err(ReceiptError::InvalidAdmission)
        );
    }

    #[test]
    fn receipt_rejects_decision_metadata_mutated_after_authority_issuance() {
        let action = intent();
        for field in [
            "profile_id",
            "profile_version",
            "evidence_ids",
            "evidence_snapshot_fingerprint",
            "reasons",
        ] {
            let mut admission = evaluate(&action, &required());
            match field {
                "profile_id" => admission.decision.profile_id = "forged-profile".into(),
                "profile_version" => admission.decision.profile_version += 1,
                "evidence_ids" => admission
                    .decision
                    .evidence_ids
                    .push("forged-evidence".into()),
                "evidence_snapshot_fingerprint" => {
                    admission.decision.evidence_snapshot_fingerprint = sha256_hex(b"forged basis")
                }
                "reasons" => admission.decision.reasons.push("forged reason".into()),
                _ => unreachable!(),
            }
            let receipt = ActionReceipt {
                schema_version: SCHEMA_VERSION,
                proposal_id: action.proposal_id.clone(),
                action_fingerprint: action.fingerprint(),
                decision: admission.decision.clone(),
                executor_id: Some("adapter-1".into()),
                attempt_id: Some("attempt-1".into()),
                outcome: ExecutionOutcome::Confirmed {
                    occurrence_id: "event-1".into(),
                },
            };
            assert_eq!(
                validate_receipt(&action, &admission, &receipt),
                Err(ReceiptError::InvalidAdmission),
                "mutated {field}"
            );
        }
    }

    #[test]
    fn versioned_wire_structs_reject_unknown_fields() {
        let action = intent();
        let context = required();
        let admission = evaluate(&action, &context);
        let receipt = ActionReceipt {
            schema_version: SCHEMA_VERSION,
            proposal_id: action.proposal_id.clone(),
            action_fingerprint: action.fingerprint(),
            decision: admission.decision.clone(),
            executor_id: None,
            attempt_id: None,
            outcome: ExecutionOutcome::NotDispatched,
        };
        reject_unknown(&action);
        reject_unknown(&action.effect);
        reject_unknown(&context);
        reject_unknown(&context.profile);
        reject_unknown(&context.evidence[0]);
        reject_unknown(&context.assessments[0]);
        reject_unknown(&context.profile.conditions);
        reject_unknown(&context.revocation);
        reject_unknown(&admission.decision);
        reject_unknown(&receipt);

        let mut accepted = serde_json::to_value(AcceptanceState::Accepted {
            by_principal_id: "bob".into(),
            action_fingerprint: action.fingerprint(),
            terms_digest: sha256_hex(b"terms"),
            at_sequence: 4,
            valid_through_sequence: 4,
        })
        .unwrap();
        let Value::Object(variant) = &mut accepted else {
            panic!("expected tagged acceptance object")
        };
        variant
            .get_mut("accepted")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unsupported_required_field".into(), json!(true));
        assert!(serde_json::from_value::<AcceptanceState>(accepted).is_err());
    }
}
