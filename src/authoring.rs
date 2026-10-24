//! Typed authoring helpers. These construct proposals, never grant authority.
use crate::{canonical, identity::Participant, protocol::*, rules::Facts};
use constitutive_action::v1::ActionIntent;

/// Bind all instruction metadata before the participant produces its proof.
pub fn instruction(
    id: &str,
    actor: &Participant,
    path: &Commitment,
    route: Route,
    facts: Facts,
    epoch: u64,
) -> Instruction {
    let payload = Payload {
        facts,
        path_ref: path.reference(),
        interpretation_ref: path.interpretation_ref.clone(),
        rule_payload: path.rule_payload.clone(),
        route,
        upstream_ref: None,
    };
    let principal = if route == Route::Ordinary {
        path.delegation
            .as_ref()
            .map(|d| d.principal_seat.clone())
            .unwrap_or_else(|| actor.seat(id))
    } else {
        actor.seat(id)
    };
    let action = intent(
        id,
        &actor.seat(id),
        &principal,
        &format!("{}:{route:?}", path.reference()),
        &path.context,
        "apply",
        "endpoint:existing-rail",
        &payload,
    );
    let payoff = if route == Route::Exception {
        &path.payoffs.on_exceed_scope
    } else {
        &path.payoffs.on_violation
    };
    let proof = actor.prove(id, &action.fingerprint(), payoff, epoch);
    Instruction {
        intent: action,
        path_ref: payload.path_ref,
        interpretation_ref: payload.interpretation_ref,
        rule_payload: payload.rule_payload,
        route,
        proof,
        endorsements: vec![],
        delegate_kind: "participant".into(),
        upstream: None,
    }
}

/// Consent is scoped to the activity and bound to this exact proposal.
pub fn endorse(
    actor: &Participant,
    action: &ActionIntent,
    context: &str,
    payoff: &str,
    epoch: u64,
) -> Endorsement {
    Endorsement {
        scoped_seat: actor.seat(context),
        proof: actor.prove(&action.proposal_id, &action.fingerprint(), payoff, epoch),
    }
}

/// Attaching upstream evidence changes the effect. Produce a new proof and discard
/// previous endorsements; the caller must collect consent for these new terms.
pub fn attach_upstream(
    instruction: &mut Instruction,
    upstream: Instruction,
    actor: &Participant,
    epoch: u64,
) -> crate::Result<()> {
    let payload: Payload = serde_json::from_slice(&instruction.intent.effect.canonical_payload)?;
    instruction.upstream = Some(Box::new(upstream));
    instruction.intent.effect.canonical_payload = canonical(&instruction.payload(payload.facts));
    instruction.proof = actor.prove(
        &instruction.intent.proposal_id,
        &instruction.intent.fingerprint(),
        &instruction.proof.payoff_ref,
        epoch,
    );
    instruction.endorsements.clear();
    Ok(())
}
