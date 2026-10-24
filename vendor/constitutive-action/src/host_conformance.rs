//! Black-box conformance probes for a host using the versioned v1 action API.
//!
//! Implement these test-facing traits against a disposable instance of the
//! host's persistence and adapter path, then call [`check_host`] from a host
//! integration test. The probes exercise that path. `open` creates a fresh
//! handle from the same durable store to exercise restart behavior. See
//! `docs/host-conformance.md`.

use crate::v1::{ActionIntent, DecisionKind, Effect, EvaluationSnapshot, evaluate};
use std::fmt::Debug;
use std::sync::{Arc, Barrier};
use std::thread;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Prepare {
    Stored,
    Existing,
    Conflict,
}

/// The host's one committed attempt for an admitted proposal. `replay_id` is
/// the identity sent to the external system for idempotency or reconciliation;
/// it must never change when a handle is reopened or a response is uncertain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchTicket {
    pub proposal_id: String,
    pub action_fingerprint: String,
    pub attempt_id: String,
    pub replay_id: String,
    /// Authority epoch observed and committed at reservation. It is compared
    /// with `effective_revoke` to establish which transition won; distinct
    /// claims may share an epoch and this need not be a unique attempt number.
    pub reserved_at_order: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttemptState {
    InFlight,
    Uncertain { reason: String },
    Confirmed { occurrence_id: String },
    Rejected { reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reservation {
    New(DispatchTicket),
    Replay {
        ticket: DispatchTicket,
        state: AttemptState,
    },
    Denied,
}

/// Return the effective revocation's committed authority epoch, comparable
/// to `DispatchTicket::reserved_at_order` for this authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevocationCommit {
    pub order: u64,
}

/// Test-facing projection of a host's real transactional and adapter path.
/// Methods may map host-specific errors into any `Debug` type. `prepare` must
/// evaluate and persist the supplied v1 intent/snapshot once, reject reuse of
/// its proposal ID with a different intent, and establish the fixture's live
/// authority state. `reserve` must reread that state and atomically claim at
/// most one attempt. `adapter_matches` must exercise the comparison made by
/// the capability-holding adapter, without causing an external effect.
pub trait HostHandle: Send {
    type Error: Debug;

    fn prepare(
        &mut self,
        intent: &ActionIntent,
        snapshot: &EvaluationSnapshot,
    ) -> Result<Prepare, Self::Error>;
    fn reserve(&mut self, proposal_id: &str) -> Result<Reservation, Self::Error>;
    fn effective_revoke(&mut self, authority_id: &str) -> Result<RevocationCommit, Self::Error>;
    fn record_uncertain(&mut self, attempt_id: &str, reason: &str) -> Result<(), Self::Error>;
    fn adapter_matches(
        &mut self,
        ticket: &DispatchTicket,
        actual_effect: &Effect,
    ) -> Result<bool, Self::Error>;
}

/// One isolated, disposable authority/store namespace. Each `open` must use a
/// fresh handle to the *same* stored state; the factory supplied to either
/// conformance entry point must return an empty, independent namespace for
/// each scenario.
pub trait HostScenario {
    type Handle: HostHandle;

    fn open(&self) -> Self::Handle;
}

fn fixture() -> (ActionIntent, EvaluationSnapshot) {
    use crate::v1::{ConditionPolicy, GateProfile, RevocationState, SCHEMA_VERSION};

    let intent = ActionIntent {
        schema_version: SCHEMA_VERSION,
        proposal_id: "host-conformance:proposal-1".into(),
        actor_id: "host-conformance:agent".into(),
        represented_principal_id: "host-conformance:principal".into(),
        authority_id: "host-conformance:authority".into(),
        context_id: "host-conformance:context".into(),
        context_version: 1,
        effect: Effect {
            profile_id: "host-conformance.effect".into(),
            profile_version: 1,
            operation: "apply".into(),
            destination: "fixture:target".into(),
            canonical_payload: b"host-conformance/v1:payload".to_vec(),
        },
    };
    let snapshot = EvaluationSnapshot {
        schema_version: SCHEMA_VERSION,
        context_id: intent.context_id.clone(),
        context_version: intent.context_version,
        sequence: 1,
        valid_through_sequence: 100,
        profile: GateProfile {
            profile_id: "host-conformance.open".into(),
            version: 1,
            effect_profile_id: intent.effect.profile_id.clone(),
            effect_profile_version: intent.effect.profile_version,
            conditions: ConditionPolicy::ExplicitOpen,
            required_acceptances: vec![],
        },
        evidence: vec![],
        assessments: vec![],
        acceptances: vec![],
        revocation: RevocationState::default(),
    };
    (intent, snapshot)
}

fn prepared<H: HostHandle>(handle: &mut H, intent: &ActionIntent, snapshot: &EvaluationSnapshot) {
    assert_eq!(
        handle.prepare(intent, snapshot).expect("prepare failed"),
        Prepare::Stored
    );
}

fn new_ticket<H: HostHandle>(handle: &mut H, intent: &ActionIntent) -> DispatchTicket {
    let Reservation::New(ticket) = handle
        .reserve(&intent.proposal_id)
        .expect("reservation failed")
    else {
        panic!("first reservation must create one attempt");
    };
    assert_eq!(ticket.proposal_id, intent.proposal_id);
    assert_eq!(ticket.action_fingerprint, intent.fingerprint());
    assert!(!ticket.attempt_id.is_empty());
    assert!(!ticket.replay_id.is_empty());
    ticket
}

fn assert_replay<H: HostHandle>(
    handle: &mut H,
    intent: &ActionIntent,
    ticket: &DispatchTicket,
    state: AttemptState,
) {
    assert_eq!(
        handle
            .reserve(&intent.proposal_id)
            .expect("replay lookup failed"),
        Reservation::Replay {
            ticket: ticket.clone(),
            state,
        }
    );
}

/// Run independent host scenarios for reservation, replay, revocation ordering
/// and effect matching. The host separately tests process crashes, capability
/// isolation, external idempotency and occurrence evidence on its adapter path.
pub fn check_host<F, S>(fresh: F)
where
    F: Fn() -> S,
    S: HostScenario,
{
    check_host_with_fixture(|| {
        let (intent, snapshot) = fixture();
        (fresh(), intent, snapshot)
    });
}

/// Run the probes with a fresh admitted, host-native effect fixture for each
/// scenario. This lets an integrating host exercise its capability-holding adapter
/// instead of a substitute accepting the reference effect. Each call to
/// `fresh` must return an independent namespace and a unique proposal ID;
/// every `open` on its scenario must still access the same durable records.
pub fn check_host_with_fixture<F, S>(fresh: F)
where
    F: Fn() -> (S, ActionIntent, EvaluationSnapshot),
    S: HostScenario,
{
    fn checked_case<F, S>(fresh: &F) -> (S, ActionIntent, EvaluationSnapshot)
    where
        F: Fn() -> (S, ActionIntent, EvaluationSnapshot),
        S: HostScenario,
    {
        let case = fresh();
        assert_eq!(
            evaluate(&case.1, &case.2).decision.kind,
            DecisionKind::Permitted,
            "host conformance fixture must admit its effect"
        );
        case
    }
    // A proposal ID cannot be rebound. Repeated and reopened claims keep one
    // attempt and one external replay identity; the adapter checks exact effect.
    {
        let (scenario, intent, snapshot) = checked_case(&fresh);
        let mut host = scenario.open();
        prepared(&mut host, &intent, &snapshot);
        assert_eq!(
            host.prepare(&intent, &snapshot)
                .expect("repeat prepare failed"),
            Prepare::Existing
        );
        let mut changed = intent.clone();
        changed.effect.canonical_payload.push(b'!');
        assert_eq!(
            host.prepare(&changed, &snapshot)
                .expect("conflicting prepare failed"),
            Prepare::Conflict
        );
        let ticket = new_ticket(&mut host, &intent);
        assert_replay(&mut host, &intent, &ticket, AttemptState::InFlight);
        assert!(
            host.adapter_matches(&ticket, &intent.effect)
                .expect("adapter comparison failed")
        );
        let mut forged_ticket = ticket.clone();
        forged_ticket.replay_id.push_str(":other");
        assert!(
            !host
                .adapter_matches(&forged_ticket, &intent.effect)
                .expect("adapter comparison failed")
        );
        for changed_effect in [
            Effect {
                profile_id: format!("{}:other", intent.effect.profile_id),
                ..intent.effect.clone()
            },
            Effect {
                operation: format!("{}:other", intent.effect.operation),
                ..intent.effect.clone()
            },
            Effect {
                destination: format!("{}:other", intent.effect.destination),
                ..intent.effect.clone()
            },
            Effect {
                canonical_payload: [intent.effect.canonical_payload.as_slice(), b"other"].concat(),
                ..intent.effect.clone()
            },
            Effect {
                profile_version: intent.effect.profile_version.wrapping_add(1),
                ..intent.effect.clone()
            },
        ] {
            assert!(
                !host
                    .adapter_matches(&ticket, &changed_effect)
                    .expect("adapter comparison failed")
            );
        }
        drop(host);
        let mut reopened = scenario.open();
        assert_replay(&mut reopened, &intent, &ticket, AttemptState::InFlight);
    }

    // An unknown external result remains attached to the original attempt
    // and replay identity across a fresh host handle.
    {
        let (scenario, intent, snapshot) = checked_case(&fresh);
        let mut host = scenario.open();
        prepared(&mut host, &intent, &snapshot);
        let ticket = new_ticket(&mut host, &intent);
        host.record_uncertain(&ticket.attempt_id, "response lost")
            .expect("uncertain outcome was not recorded");
        drop(host);
        let mut reopened = scenario.open();
        assert_replay(
            &mut reopened,
            &intent,
            &ticket,
            AttemptState::Uncertain {
                reason: "response lost".into(),
            },
        );
    }

    // Effective revocation committed first must prevent a new claim.
    {
        let (scenario, intent, snapshot) = checked_case(&fresh);
        let mut host = scenario.open();
        prepared(&mut host, &intent, &snapshot);
        host.effective_revoke(&intent.authority_id)
            .expect("effective revocation failed");
        assert_eq!(
            host.reserve(&intent.proposal_id)
                .expect("reservation failed"),
            Reservation::Denied
        );
        drop(host);
        let mut reopened = scenario.open();
        assert_eq!(
            reopened
                .reserve(&intent.proposal_id)
                .expect("reservation failed"),
            Reservation::Denied
        );
    }

    // A later revocation does not erase an already committed attempt. Its
    // order must follow the reservation's authority-transition order.
    {
        let (scenario, intent, snapshot) = checked_case(&fresh);
        let mut host = scenario.open();
        prepared(&mut host, &intent, &snapshot);
        let ticket = new_ticket(&mut host, &intent);
        let revocation = host
            .effective_revoke(&intent.authority_id)
            .expect("effective revocation failed");
        assert!(ticket.reserved_at_order < revocation.order);
        assert_replay(&mut host, &intent, &ticket, AttemptState::InFlight);
    }

    // Two simultaneous claims must have exactly one winner.
    {
        let (scenario, intent, snapshot) = checked_case(&fresh);
        let mut setup = scenario.open();
        prepared(&mut setup, &intent, &snapshot);
        drop(setup);
        let mut first = scenario.open();
        let mut second = scenario.open();
        let barrier = Arc::new(Barrier::new(3));
        let proposal_id = intent.proposal_id.as_str();
        let (a, b) = thread::scope(|scope| {
            let start = barrier.clone();
            let first = scope.spawn(move || {
                start.wait();
                first.reserve(proposal_id).expect("reservation failed")
            });
            let start = barrier.clone();
            let second = scope.spawn(move || {
                start.wait();
                second.reserve(proposal_id).expect("reservation failed")
            });
            barrier.wait();
            (
                first.join().expect("reservation thread panicked"),
                second.join().expect("reservation thread panicked"),
            )
        });
        let (
            Reservation::New(ticket),
            Reservation::Replay {
                ticket: replay,
                state,
            },
        ) = (if matches!(a, Reservation::New(_)) {
            (a, b)
        } else {
            (b, a)
        })
        else {
            panic!("simultaneous claims must yield one new and one replay");
        };
        assert_eq!(ticket, replay);
        assert_eq!(state, AttemptState::InFlight);
    }

    // If effective revocation races a claim, a winning claim must have an
    // earlier committed order. A losing claim must not appear later as new.
    {
        let (scenario, intent, snapshot) = checked_case(&fresh);
        let mut setup = scenario.open();
        prepared(&mut setup, &intent, &snapshot);
        drop(setup);
        let mut reserver = scenario.open();
        let mut revoker = scenario.open();
        let barrier = Arc::new(Barrier::new(3));
        let proposal_id = intent.proposal_id.as_str();
        let authority_id = intent.authority_id.as_str();
        let (claim, revocation) = thread::scope(|scope| {
            let start = barrier.clone();
            let claim = scope.spawn(move || {
                start.wait();
                reserver.reserve(proposal_id).expect("reservation failed")
            });
            let start = barrier.clone();
            let revocation = scope.spawn(move || {
                start.wait();
                revoker
                    .effective_revoke(authority_id)
                    .expect("effective revocation failed")
            });
            barrier.wait();
            (
                claim.join().expect("reservation thread panicked"),
                revocation.join().expect("revocation thread panicked"),
            )
        });
        let mut reopened = scenario.open();
        match claim {
            Reservation::New(ticket) => {
                assert!(ticket.reserved_at_order < revocation.order);
                assert_replay(&mut reopened, &intent, &ticket, AttemptState::InFlight);
            }
            Reservation::Denied => assert_eq!(
                reopened
                    .reserve(&intent.proposal_id)
                    .expect("reservation failed"),
                Reservation::Denied
            ),
            Reservation::Replay { .. } => panic!("first racing claim cannot be a replay"),
        }
    }
}
