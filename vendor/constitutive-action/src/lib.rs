//! Admission and exact-action binding for host-governed agent effects.
//! Hosts supply activity conditions and control the capabilities that execute admitted effects.

pub mod v1;
pub use v1 as experimental_v1;
pub mod host_conformance;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionIntent {
    pub proposal_id: String,
    pub actor_id: String,
    pub represented_participant_id: String,
    pub context_id: String,
    pub context_version: u64,
    pub operation: String,
    pub destination: String,
    pub payload: String,
}

impl ActionIntent {
    /// Length-prefixing avoids delimiter ambiguity in the action binding.
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        for field in [
            self.proposal_id.as_str(),
            self.actor_id.as_str(),
            self.represented_participant_id.as_str(),
            self.context_id.as_str(),
            self.operation.as_str(),
            self.destination.as_str(),
            self.payload.as_str(),
        ] {
            hasher.update((field.len() as u64).to_be_bytes());
            hasher.update(field.as_bytes());
        }
        hasher.update(self.context_version.to_be_bytes());
        format!("{:x}", hasher.finalize())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationContext {
    pub context_id: String,
    pub version: u64,
    pub sequence: u64,
    pub valid_through_sequence: u64,
    pub evidence_refs: Vec<String>,
    pub required_acceptances: Vec<String>,
    pub checks: Vec<Check>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Check {
    pub source: String,
    pub result: CheckResult,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckResult {
    Pass,
    Fail,
    Unknown,
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
pub struct GateDecision {
    pub kind: DecisionKind,
    pub reasons: Vec<String>,
    pub context_id: String,
    pub context_version: u64,
    pub sequence: u64,
    pub evidence_refs: Vec<String>,
    pub action_fingerprint: String,
}

/// In-process authority bound to an action; the adapter also checks live state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionAuthority {
    bound_intent: ActionIntent,
    admitted_sequence: u64,
    valid_through_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admission {
    pub decision: GateDecision,
    pub authority: Option<ExecutionAuthority>,
}

pub fn evaluate(intent: &ActionIntent, context: &EvaluationContext) -> Admission {
    let mut reasons = Vec::new();
    let kind = if intent.context_id != context.context_id
        || intent.context_version != context.version
        || context.sequence > context.valid_through_sequence
    {
        reasons.push("context is stale or mismatched".into());
        DecisionKind::Indeterminate
    } else if context.checks.is_empty() {
        reasons.push("no checks supplied; admissibility cannot be determined".into());
        DecisionKind::Indeterminate
    } else if context
        .checks
        .iter()
        .any(|check| check.result == CheckResult::Fail)
    {
        reasons.extend(
            context
                .checks
                .iter()
                .filter(|check| check.result == CheckResult::Fail)
                .map(|check| format!("{}: {}", check.source, check.reason)),
        );
        DecisionKind::Prevented
    } else if context
        .checks
        .iter()
        .any(|check| check.result == CheckResult::Unknown)
    {
        reasons.extend(
            context
                .checks
                .iter()
                .filter(|check| check.result == CheckResult::Unknown)
                .map(|check| format!("{}: {}", check.source, check.reason)),
        );
        DecisionKind::Indeterminate
    } else if !context.required_acceptances.is_empty() {
        reasons.push(format!(
            "acceptance required from: {}",
            context.required_acceptances.join(", ")
        ));
        DecisionKind::DecisionRequired
    } else {
        reasons.push("all supplied checks passed".into());
        DecisionKind::Permitted
    };
    let decision = GateDecision {
        kind,
        reasons,
        context_id: context.context_id.clone(),
        context_version: context.version,
        sequence: context.sequence,
        evidence_refs: context.evidence_refs.clone(),
        action_fingerprint: intent.fingerprint(),
    };
    let authority = (kind == DecisionKind::Permitted).then(|| ExecutionAuthority {
        bound_intent: intent.clone(),
        admitted_sequence: context.sequence,
        valid_through_sequence: context.valid_through_sequence,
    });
    Admission {
        decision,
        authority,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiveState {
    pub context_version: u64,
    pub sequence: u64,
    pub revoked: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorityError {
    DifferentAction,
    StaleOrRevoked,
}

impl ExecutionAuthority {
    pub fn check(&self, attempted: &ActionIntent, live: LiveState) -> Result<(), AuthorityError> {
        if &self.bound_intent != attempted {
            return Err(AuthorityError::DifferentAction);
        }
        if live.revoked
            || live.context_version != self.bound_intent.context_version
            || live.sequence < self.admitted_sequence
            || live.sequence > self.valid_through_sequence
        {
            return Err(AuthorityError::StaleOrRevoked);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionOutcome {
    NotDispatched,
    Confirmed { external_event_id: String },
    Rejected { reason: String },
    Uncertain { reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionReceipt {
    pub proposal: ActionIntent,
    pub decision: GateDecision,
    pub executor: String,
    pub transaction_id: Option<String>,
    pub outcome: ExecutionOutcome,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent() -> ActionIntent {
        ActionIntent {
            proposal_id: "p1".into(),
            actor_id: "bot1".into(),
            represented_participant_id: "alice".into(),
            context_id: "room1".into(),
            context_version: 3,
            operation: "post".into(),
            destination: "room1".into(),
            payload: "hello".into(),
        }
    }
    fn context() -> EvaluationContext {
        EvaluationContext {
            context_id: "room1".into(),
            version: 3,
            sequence: 7,
            valid_through_sequence: 7,
            evidence_refs: vec![],
            required_acceptances: vec![],
            checks: vec![Check {
                source: "membership".into(),
                result: CheckResult::Pass,
                reason: "active".into(),
            }],
        }
    }

    #[test]
    fn authority_is_exact_and_version_bound() {
        let action = intent();
        let grant = evaluate(&action, &context()).authority.unwrap();
        let live = LiveState {
            context_version: 3,
            sequence: 7,
            revoked: false,
        };
        assert_eq!(grant.check(&action, live), Ok(()));
        let mut changed = action.clone();
        changed.payload = "different".into();
        assert_eq!(
            grant.check(&changed, live),
            Err(AuthorityError::DifferentAction)
        );
        assert_eq!(
            grant.check(
                &action,
                LiveState {
                    sequence: 8,
                    ..live
                }
            ),
            Err(AuthorityError::StaleOrRevoked)
        );
    }

    #[test]
    fn unknown_and_required_acceptance_do_not_permit() {
        let mut ctx = context();
        ctx.checks[0].result = CheckResult::Unknown;
        assert_eq!(
            evaluate(&intent(), &ctx).decision.kind,
            DecisionKind::Indeterminate
        );
        ctx.checks[0].result = CheckResult::Pass;
        ctx.required_acceptances.push("bob".into());
        assert_eq!(
            evaluate(&intent(), &ctx).decision.kind,
            DecisionKind::DecisionRequired
        );
    }

    #[test]
    fn legacy_empty_checks_do_not_silently_permit() {
        let mut ctx = context();
        ctx.checks.clear();
        let admission = evaluate(&intent(), &ctx);
        assert_eq!(admission.decision.kind, DecisionKind::Indeterminate);
        assert!(admission.authority.is_none());
    }
}
