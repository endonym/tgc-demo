use constitutive_action::v1::{AcceptanceState, DecisionKind as D};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
use tgc_demo::{audit, protocol::*, rules::*, scenario::*};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "tgc-delegation-consent-{}-{}",
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
fn scene() -> Scene {
    Scene::new("test", "delegation-consent")
}
fn fixture() -> Fixture {
    let mut f = Fixture::new().unwrap();
    f.path.delegation.as_mut().unwrap().principal_seat = f.officer.seat(&f.path.context);
    assert!(!f.path.owners.contains(&f.officer.seat(&f.path.context)));
    f
}
fn consented(field: &mut Field, f: &Fixture) {
    for verb in ["propose", "accept"] {
        assert_eq!(
            govern(
                field,
                f,
                &scene(),
                &format!("path-{verb}"),
                change(
                    verb,
                    &f.path.reference(),
                    (verb == "propose").then(|| f.path.clone())
                ),
                &[&f.principal, &f.counterparty, &f.officer]
            )
            .unwrap(),
            D::Permitted
        );
    }
}

#[test]
fn both_topologies_require_the_grantor_for_constitution_and_activation() {
    for topology in [Topology::Control, Topology::Constitutive] {
        let t = Temp::new();
        let f = fixture();
        let mut field = f.field(&t.0, topology).unwrap();
        let proposed = change("propose", &f.path.reference(), Some(f.path.clone()));
        assert_eq!(
            govern(
                &mut field,
                &f,
                &scene(),
                "propose",
                proposed.clone(),
                &[&f.principal, &f.counterparty]
            )
            .unwrap(),
            D::DecisionRequired
        );
        assert!(
            !field
                .discovery()
                .commitments
                .contains_key(&f.path.reference())
        );
        assert_eq!(field.host().occurrences().unwrap(), 0);
        assert_eq!(
            govern(
                &mut field,
                &f,
                &scene(),
                "propose",
                proposed,
                &[&f.principal, &f.counterparty, &f.officer]
            )
            .unwrap(),
            D::Permitted
        );
        let accepted = change("accept", &f.path.reference(), None);
        assert_eq!(
            govern(
                &mut field,
                &f,
                &scene(),
                "accept",
                accepted.clone(),
                &[&f.principal, &f.counterparty]
            )
            .unwrap(),
            D::DecisionRequired
        );
        let blocked = instruction(
            "before-grant-activation",
            &f.agent,
            &f.path,
            Route::Ordinary,
            &facts("venue-A", 500),
            0,
        );
        assert_eq!(
            field.execute(&scene(), &f.issuers, &blocked, 20).unwrap(),
            D::Prevented
        );
        assert_eq!(field.host().occurrences().unwrap(), 1);
        assert_eq!(
            govern(
                &mut field,
                &f,
                &scene(),
                "accept",
                accepted,
                &[&f.principal, &f.counterparty, &f.officer]
            )
            .unwrap(),
            D::Permitted
        );
        let action = instruction(
            "after-grant",
            &f.agent,
            &f.path,
            Route::Ordinary,
            &facts("venue-A", 500),
            0,
        );
        assert_eq!(
            field.execute(&scene(), &f.issuers, &action, 20).unwrap(),
            D::Permitted
        );
        let state = field.host().state().unwrap();
        let grantor = f.officer.seat(&f.path.context);
        for id in ["propose", "accept"] {
            assert!(state.records[id].snapshot.acceptances.iter().any(|a| matches!(&a.state, AcceptanceState::Accepted { by_principal_id, .. } if by_principal_id == &grantor)));
        }
        // The grantor's consent establishes authority; the acting proof still
        // belongs to the agent, and self-accountable composition stays open.
        assert_eq!(action.intent.actor_id, f.agent.seat("after-grant"));
        assert_eq!(action.intent.represented_principal_id, grantor);
        let event = state
            .events
            .iter()
            .find(|e| e.kind == "decision" && e.data["intent"]["proposal_id"] == "after-grant")
            .unwrap();
        assert_eq!(
            event.data["accountable_proof"],
            tgc_demo::digest(&action.proof)
        );
        drop(field);
        let mut reopened = Field::reopen(&t.0).unwrap();
        let own = instruction(
            "self-accountable",
            &f.counterparty,
            &f.path,
            Route::Composition,
            &facts("venue-A", 500),
            0,
        );
        assert_eq!(
            reopened.execute(&scene(), &f.issuers, &own, 20).unwrap(),
            D::Permitted
        );
        assert_eq!(own.intent.actor_id, own.intent.represented_principal_id);
        audit::verify_transcript(&reopened.host().state().unwrap().events).unwrap();
    }
}

#[test]
fn grantor_consent_must_be_authentic_current_and_bound_to_exact_terms() {
    let t = Temp::new();
    let mut f = fixture();
    let mut field = f.field(&t.0, Topology::Constitutive).unwrap();
    let offered = change("propose", &f.path.reference(), Some(f.path.clone()));
    let action = governance_action("grant", &f.principal, &offered);
    let other = governance_action("other-proposal", &f.principal, &offered);
    let mut changed_path = f.path.clone();
    changed_path.window[1] = 80;
    let changed = governance_action(
        "grant",
        &f.principal,
        &change("propose", &changed_path.reference(), Some(changed_path)),
    );
    let valid = endorse(&f.officer, &action, "payoff:governance", 0);
    let mut impostor = endorse(&f.counterparty, &action, "payoff:governance", 0);
    impostor.scoped_seat = f.officer.seat(&f.path.context);
    let mut corrupted = valid.clone();
    corrupted.proof.action_binding = "changed-binding".into();
    let stale = endorse(&f.officer, &action, "payoff:governance", 1);
    for grant in [
        impostor,
        corrupted,
        stale,
        endorse(&f.officer, &other, "payoff:governance", 0),
        endorse(&f.officer, &changed, "payoff:governance", 0),
    ] {
        let proof = f
            .principal
            .prove("grant", &action.fingerprint(), "payoff:governance", 0);
        let consents = [
            endorse(&f.principal, &action, "payoff:governance", 0),
            endorse(&f.counterparty, &action, "payoff:governance", 0),
            grant,
        ];
        assert_eq!(
            field
                .govern(&scene(), &f.issuers, &action, &proof, &consents, 20)
                .unwrap(),
            D::DecisionRequired
        );
        assert_eq!(field.host().occurrences().unwrap(), 0);
    }
    assert_eq!(
        govern(
            &mut field,
            &f,
            &scene(),
            "grant",
            offered.clone(),
            &[&f.principal, &f.counterparty, &f.officer]
        )
        .unwrap(),
        D::Permitted
    );
    // Revoked Carol cannot activate even with newly minted, exactly bound
    // consent; the other participants use current, valid presentations.
    f.issuers
        .revoke(&valid.proof.moderator_urn, &valid.proof)
        .unwrap();
    assert_eq!(
        govern(
            &mut field,
            &f,
            &scene(),
            "activate-revoked",
            change("accept", &f.path.reference(), None),
            &[&f.principal, &f.counterparty, &f.officer]
        )
        .unwrap(),
        D::DecisionRequired
    );
    assert_eq!(field.host().occurrences().unwrap(), 1);
}

#[test]
fn an_authentic_but_expired_grant_does_not_authorize_constitution() {
    let t = Temp::new();
    let mut f = Fixture::new().unwrap();
    let carol = f
        .issuers
        .issue(
            &f.newcomer_moderator,
            &facts("venue-A", 500),
            "expiring-grantor",
            19,
        )
        .unwrap();
    f.path.delegation.as_mut().unwrap().principal_seat = carol.seat(&f.path.context);
    let mut field = f.field(&t.0, Topology::Constitutive).unwrap();
    let offered = change("propose", &f.path.reference(), Some(f.path.clone()));
    let action = governance_action("expired-grant", &f.principal, &offered);
    let grant = endorse(&carol, &action, "payoff:governance", 0);
    assert_eq!(
        f.issuers.verify(
            &grant.proof,
            &f.leads,
            &f.path.rulebook_ref,
            &action.proposal_id,
            &action.fingerprint(),
            "payoff:governance",
            19
        ),
        Verdict::Pass
    );
    assert_eq!(
        f.issuers.verify(
            &grant.proof,
            &f.leads,
            &f.path.rulebook_ref,
            &action.proposal_id,
            &action.fingerprint(),
            "payoff:governance",
            20
        ),
        Verdict::Fail
    );
    assert_eq!(
        govern(
            &mut field,
            &f,
            &scene(),
            "expired-grant",
            offered,
            &[&f.principal, &f.counterparty, &carol]
        )
        .unwrap(),
        D::DecisionRequired
    );
    assert_eq!(field.host().occurrences().unwrap(), 0);
    assert!(
        !field
            .discovery()
            .commitments
            .contains_key(&f.path.reference())
    );
}

#[test]
fn amendments_require_old_and_new_grantors_including_removal() {
    for topology in [Topology::Control, Topology::Constitutive] {
        for variation in [
            "scope",
            "delegate",
            "principal",
            "remove",
            "window",
            "payoff",
            "conditions",
        ] {
            let t = Temp::new();
            let f = fixture();
            let mut field = f.field(&t.0, topology).unwrap();
            consented(&mut field, &f);
            let mut candidate = f.path.clone();
            candidate.parent_ref = Some(f.path.reference());
            match variation {
                "scope" => {
                    candidate.delegation.as_mut().unwrap().scope = Predicate::AtMost {
                        field: "amount".into(),
                        value: 400,
                    }
                }
                "delegate" => {
                    candidate.delegation.as_mut().unwrap().delegate_seat =
                        f.counterparty.seat(&f.path.context)
                }
                "principal" => {
                    candidate.delegation.as_mut().unwrap().principal_seat =
                        f.agent.seat(&f.path.context)
                }
                "remove" => candidate.delegation = None,
                "window" => candidate.window[1] = 80,
                "payoff" => candidate.payoffs.on_violation = "payoff:new-accountable-terms".into(),
                "conditions" => {
                    candidate.conditions = Predicate::AtLeast {
                        field: "bond".into(),
                        value: 200,
                    }
                }
                _ => unreachable!(),
            }
            let update = change("amend", &f.path.reference(), Some(candidate.clone()));
            let before = field.host().occurrences().unwrap();
            assert_eq!(
                govern(
                    &mut field,
                    &f,
                    &scene(),
                    "amend",
                    update.clone(),
                    &[&f.principal, &f.counterparty]
                )
                .unwrap(),
                D::DecisionRequired,
                "{topology:?}/{variation}"
            );
            assert_eq!(field.host().occurrences().unwrap(), before);
            assert!(
                !field
                    .discovery()
                    .commitments
                    .contains_key(&candidate.reference())
            );
            if variation == "principal" {
                for only_one_grantor in [&f.officer, &f.agent] {
                    assert_eq!(
                        govern(
                            &mut field,
                            &f,
                            &scene(),
                            "amend",
                            update.clone(),
                            &[&f.principal, &f.counterparty, only_one_grantor]
                        )
                        .unwrap(),
                        D::DecisionRequired
                    );
                }
            }
            assert_eq!(
                govern(
                    &mut field,
                    &f,
                    &scene(),
                    "amend",
                    update,
                    &[&f.principal, &f.counterparty, &f.officer, &f.agent]
                )
                .unwrap(),
                D::Permitted
            );
            assert_eq!(field.host().occurrences().unwrap(), before + 1);
            assert_eq!(field.discovery().commitments[&f.path.reference()], f.path);
            assert_eq!(
                field.discovery().commitments[&candidate.reference()],
                candidate
            );
            audit::verify_transcript(&field.host().state().unwrap().events).unwrap();
        }
    }
}

#[test]
fn adding_a_delegation_needs_its_principal_even_when_owners_consent() {
    let t = Temp::new();
    let mut f = Fixture::new().unwrap();
    let delegation = Delegation {
        principal_seat: f.officer.seat(&f.path.context),
        delegate_seat: f.agent.seat(&f.path.context),
        scope: f.path.scope.clone(),
    };
    f.path.delegation = None;
    let mut field = f.field(&t.0, Topology::Constitutive).unwrap();
    constitute(&mut field, &f).unwrap();
    let mut candidate = f.path.clone();
    candidate.parent_ref = Some(f.path.reference());
    candidate.delegation = Some(delegation);
    let update = change("amend", &f.path.reference(), Some(candidate));
    assert_eq!(
        govern(
            &mut field,
            &f,
            &scene(),
            "add",
            update.clone(),
            &[&f.principal, &f.counterparty]
        )
        .unwrap(),
        D::DecisionRequired
    );
    assert_eq!(
        govern(
            &mut field,
            &f,
            &scene(),
            "add",
            update,
            &[&f.principal, &f.counterparty, &f.officer]
        )
        .unwrap(),
        D::Permitted
    );
}

#[test]
fn promotion_requires_fresh_grantor_consent_after_resolution() {
    for topology in [Topology::Control, Topology::Constitutive] {
        for variation in ["retain", "replace", "remove"] {
            let t = Temp::new();
            let f = fixture();
            let mut field = f.field(&t.0, topology).unwrap();
            consented(&mut field, &f);
            // A real unresolved instruction and constituted resolution establish
            // the promotion trail. Existing owner consent still cannot grant Carol's
            // authority for the replacement path.
            let mut unknown = facts("venue-A", 500);
            unknown.remove("bond");
            let pending = instruction("collision", &f.agent, &f.path, Route::Ordinary, &unknown, 0);
            assert_eq!(
                field.execute(&scene(), &f.issuers, &pending, 20).unwrap(),
                D::Indeterminate
            );
            let mut resolve = change("resolve", &f.path.reference(), None);
            resolve.queue_id = Some("collision".into());
            assert_eq!(
                govern(
                    &mut field,
                    &f,
                    &scene(),
                    "resolve",
                    resolve,
                    &[&f.principal, &f.counterparty]
                )
                .unwrap(),
                D::Permitted
            );
            let mut candidate = f.path.clone();
            candidate.parent_ref = Some(f.path.reference());
            candidate.window[1] = 80;
            if variation == "replace" {
                candidate.delegation.as_mut().unwrap().principal_seat =
                    f.agent.seat(&f.path.context);
            } else if variation == "remove" {
                candidate.delegation = None;
            }
            let mut promotion = change("promote", &f.path.reference(), Some(candidate.clone()));
            promotion.queue_id = Some("collision".into());
            assert_eq!(
                govern(
                    &mut field,
                    &f,
                    &scene(),
                    "promote",
                    promotion.clone(),
                    &[&f.principal, &f.counterparty]
                )
                .unwrap(),
                D::DecisionRequired
            );
            if variation == "replace" {
                for only_one_grantor in [&f.officer, &f.agent] {
                    assert_eq!(
                        govern(
                            &mut field,
                            &f,
                            &scene(),
                            "promote",
                            promotion.clone(),
                            &[&f.principal, &f.counterparty, only_one_grantor]
                        )
                        .unwrap(),
                        D::DecisionRequired
                    );
                }
            }
            let old_action = governance_action(
                "path-accept",
                &f.principal,
                &change("accept", &f.path.reference(), None),
            );
            let action = governance_action("promote", &f.principal, &promotion);
            let proof = f
                .principal
                .prove("promote", &action.fingerprint(), "payoff:governance", 0);
            let consents = [
                endorse(&f.principal, &action, "payoff:governance", 0),
                endorse(&f.counterparty, &action, "payoff:governance", 0),
                endorse(&f.officer, &old_action, "payoff:governance", 0),
            ];
            assert_eq!(
                field
                    .govern(&scene(), &f.issuers, &action, &proof, &consents, 20)
                    .unwrap(),
                D::DecisionRequired
            );
            assert_eq!(
                govern(
                    &mut field,
                    &f,
                    &scene(),
                    "promote",
                    promotion,
                    &[&f.principal, &f.counterparty, &f.officer, &f.agent]
                )
                .unwrap(),
                D::Permitted
            );
            assert_eq!(
                field.discovery().commitments[&candidate.reference()],
                candidate
            );
            audit::verify_transcript(&field.host().state().unwrap().events).unwrap();
        }
    }
}
