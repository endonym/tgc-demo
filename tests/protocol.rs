use constitutive_action::v1::DecisionKind as D;
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
use tgc_demo::{audit, digest, identity::Issuers, protocol::*, rules::*, scenario::*};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "tgc-protocol-{}-{}",
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
fn setup() -> (Temp, Fixture, Field) {
    let t = Temp::new();
    let f = Fixture::new().unwrap();
    let mut field = f.field(&t.0, Topology::Constitutive).unwrap();
    constitute(&mut field, &f).unwrap();
    (t, f, field)
}
fn scene() -> Scene {
    Scene::new("test", "adversarial")
}

#[test]
fn all_twelve_topology_composition_recipient_combinations() {
    let t = Temp::new();
    let mut optimization = None;
    for topology in [Topology::Control, Topology::Constitutive] {
        for composition in [Composition::Reuse, Composition::Fork] {
            for downstream in [
                RecipientPolicy::Refuse,
                RecipientPolicy::Honour,
                RecipientPolicy::Unresolved,
            ] {
                let root =
                    t.0.join(format!("{topology:?}-{composition:?}-{downstream:?}"));
                let report = run(
                    &root,
                    Config {
                        topology,
                        composition,
                        downstream,
                        ..Config::default()
                    },
                )
                .unwrap();
                assert_eq!(report.pending_queue_items, 0);
                assert_eq!(report.primary_metrics["discretionary_onboarding_events"], 0);
                assert_eq!(
                    report.primary_metrics["exception_accountability_records"],
                    1
                );
                if composition == Composition::Fork
                    || matches!(downstream, RecipientPolicy::Unresolved)
                {
                    assert!(report.all_four_outcomes);
                }
                let host = tgc_demo::store::Host::open(root.join("primary")).unwrap();
                let state = host.state().unwrap();
                let choice = &state
                    .events
                    .iter()
                    .find(|e| e.kind == "agent_optimization")
                    .unwrap()
                    .data;
                if let Some(v) = &optimization {
                    assert_eq!(v, choice);
                } else {
                    optimization = Some(choice.clone());
                }
                let accept = &state.records["path-accept"].snapshot;
                assert_eq!(
                    accept.profile.required_acceptances.len(),
                    if topology == Topology::Control { 1 } else { 2 }
                );
                assert!(state.records["temptation"].ticket.is_none());
                assert!(state.records["newcomer-first"].receipt.is_some());
                audit::verify_transcript(&state.events).unwrap();
            }
        }
    }
}

#[test]
fn repeat_runs_have_identical_semantic_transcripts() {
    let t = Temp::new();
    let a = run(&t.0.join("a"), Config::default()).unwrap();
    let b = run(&t.0.join("b"), Config::default()).unwrap();
    assert_eq!(a.semantic_hash, b.semantic_hash);
    assert_eq!(
        fs::read(t.0.join("a/semantic.json")).unwrap(),
        fs::read(t.0.join("b/semantic.json")).unwrap()
    );
}

#[test]
fn newcomer_is_not_a_fixture_membership_list() {
    let (t, mut f, mut field) = setup();
    let discovery = field.discovery();
    let path = discovery.inspect(&discovery.stubs[0]).unwrap();
    for (i, seed) in ["never-seen-omega", "independent-42", "third-987654"]
        .into_iter()
        .enumerate()
    {
        let actor = f
            .issuers
            .issue(&f.newcomer_moderator, &facts("venue-A", 600), seed, 100)
            .unwrap();
        let action = instruction(
            &format!("arrival-{i}"),
            &actor,
            path,
            Route::Composition,
            &facts("venue-A", 600),
            0,
        );
        assert_eq!(
            field.execute(&scene(), &f.issuers, &action, 20).unwrap(),
            D::Permitted
        );
    }
    assert!(
        !fs::read_to_string(t.0.join("state.json"))
            .unwrap()
            .contains("never-seen-omega")
    );
}

#[test]
fn admission_requires_the_published_predicate() {
    let mut f = Fixture::new().unwrap();
    let mut absent = facts("venue-A", 600);
    absent.remove("capital_attestation");
    assert!(
        f.issuers
            .issue(&f.newcomer_moderator, &absent, "no-attestation", 100)
            .is_err()
    );
    absent.insert("capital_attestation".into(), json!(true));
    absent.insert("bond".into(), json!(99));
    assert!(
        f.issuers
            .issue(&f.newcomer_moderator, &absent, "no-bond", 100)
            .is_err()
    );
}

#[test]
fn exception_requires_exact_officer_acceptance_and_cannot_widen_mandate() {
    let (_t, f, mut field) = setup();
    let mut ordinary = instruction(
        "ordinary-shortcut",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &facts("venue-B", 750),
        0,
    );
    ordinary.endorsements.push(endorse(
        &f.officer,
        &ordinary.intent,
        &f.path.payoffs.on_violation,
        0,
    ));
    assert_eq!(
        field.execute(&scene(), &f.issuers, &ordinary, 20).unwrap(),
        D::Prevented
    );
    let mut action = instruction(
        "exception-test",
        &f.officer,
        &f.path,
        Route::Exception,
        &facts("venue-B", 750),
        0,
    );
    assert_eq!(
        field.execute(&scene(), &f.issuers, &action, 20).unwrap(),
        D::DecisionRequired
    );
    action.endorsements.push(endorse(
        &f.counterparty,
        &action.intent,
        &f.path.payoffs.on_exceed_scope,
        0,
    ));
    assert_eq!(
        field.execute(&scene(), &f.issuers, &action, 20).unwrap(),
        D::DecisionRequired
    );
    action.endorsements = vec![endorse(
        &f.officer,
        &action.intent,
        &f.path.payoffs.on_exceed_scope,
        0,
    )];
    assert_eq!(
        field.execute(&scene(), &f.issuers, &action, 20).unwrap(),
        D::Permitted
    );
    let mut altered = instruction(
        "changed-exception",
        &f.officer,
        &f.path,
        Route::Exception,
        &facts("venue-B", 700),
        0,
    );
    altered.endorsements = action.endorsements;
    assert_eq!(
        field.execute(&scene(), &f.issuers, &altered, 20).unwrap(),
        D::DecisionRequired
    );
    let not_eligible = instruction(
        "exception-ineligible",
        &f.officer,
        &f.path,
        Route::Exception,
        &facts("venue-C", 750),
        0,
    );
    assert_eq!(
        field
            .execute(&scene(), &f.issuers, &not_eligible, 20)
            .unwrap(),
        D::Prevented
    );
}

#[test]
fn exact_effect_and_metadata_binding_reject_tampering_without_dispatch() {
    let (_t, f, mut field) = setup();
    let action = instruction(
        "binding",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &facts("venue-A", 750),
        0,
    );
    let before = field.host().occurrences().unwrap();
    let mut modified = action.clone();
    modified.route = Route::Composition;
    assert!(field.execute(&scene(), &f.issuers, &modified, 20).is_err());
    let mut modified = action.clone();
    modified.interpretation_ref = "different".into();
    assert!(field.execute(&scene(), &f.issuers, &modified, 20).is_err());
    let mut modified = action.clone();
    modified.intent.effect.destination = "uncontrolled-adapter".into();
    assert!(field.execute(&scene(), &f.issuers, &modified, 20).is_err());
    let mut modified = action.clone();
    modified.proof.payoff_ref = "no-liability".into();
    assert_eq!(
        field.execute(&scene(), &f.issuers, &modified, 20).unwrap(),
        D::Prevented
    );
    assert_eq!(field.host().occurrences().unwrap(), before);
    assert_eq!(
        field.execute(&scene(), &f.issuers, &action, 20).unwrap(),
        D::Permitted
    );
    let changed = instruction(
        "binding",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &facts("venue-A", 700),
        0,
    );
    assert!(field.execute(&scene(), &f.issuers, &changed, 20).is_err());
}

#[test]
fn revocation_invalidates_fresh_presentations_and_stale_state_is_unknown() {
    let (_t, mut f, mut field) = setup();
    let action = instruction(
        "revoked",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &facts("venue-A", 750),
        0,
    );
    assert!(
        f.issuers
            .revoke(&f.newcomer_moderator, &action.proof)
            .is_err()
    );
    f.issuers
        .revoke(&action.proof.moderator_urn, &action.proof)
        .unwrap();
    assert_eq!(
        field.execute(&scene(), &f.issuers, &action, 20).unwrap(),
        D::Indeterminate
    );
    let fresh = instruction(
        "revoked-fresh",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &facts("venue-A", 750),
        f.issuers.epoch(),
    );
    assert_eq!(
        field.execute(&scene(), &f.issuers, &fresh, 20).unwrap(),
        D::Prevented
    );
}

#[test]
fn malformed_unknown_expired_and_forged_proofs_fail_closed() {
    let (_t, f, mut field) = setup();
    for (index, expected) in [
        (0, D::Prevented),
        (1, D::Indeterminate),
        (2, D::Prevented),
        (3, D::Indeterminate),
    ] {
        let mut action = instruction(
            &format!("invalid-{index}"),
            &f.agent,
            &f.path,
            Route::Ordinary,
            &facts("venue-A", 750),
            0,
        );
        match index {
            0 => action.proof.inspection_stub = "fabricated".into(),
            1 => action.proof.moderator_urn = "urn:unknown".into(),
            2 => action.proof.valid_until = 10,
            _ => action.proof.schema_version = 99,
        }
        assert_eq!(
            field.execute(&scene(), &f.issuers, &action, 20).unwrap(),
            expected
        );
    }
}

#[test]
fn withdrawal_denies_new_effects_but_replay_keeps_original_occurrence() {
    let (_t, f, mut field) = setup();
    let action = instruction(
        "before-withdrawal",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &facts("venue-A", 750),
        0,
    );
    assert_eq!(
        field.execute(&scene(), &f.issuers, &action, 20).unwrap(),
        D::Permitted
    );
    let c = change("withdraw", &f.path.reference(), None);
    assert_eq!(
        govern(&mut field, &f, &scene(), "withdraw", c, &[&f.principal]).unwrap(),
        D::Permitted
    );
    let before = field.host().occurrences().unwrap();
    assert_eq!(
        field.execute(&scene(), &f.issuers, &action, 20).unwrap(),
        D::Permitted
    );
    assert_eq!(field.host().occurrences().unwrap(), before);
    let fresh = instruction(
        "after-withdrawal",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &facts("venue-A", 750),
        0,
    );
    assert_eq!(
        field.execute(&scene(), &f.issuers, &fresh, 20).unwrap(),
        D::Prevented
    );
}

#[test]
fn peer_rejects_unapproved_upstream_even_when_its_own_policy_honours() {
    let (_t, f, field) = setup();
    let peer_dir = Temp::new();
    let mut peer = Field::peer(
        &peer_dir.0,
        Topology::Constitutive,
        field.discovery(),
        f.leads.clone(),
        f.principal.seat("activity:demonstration"),
        RecipientPolicy::Honour,
    )
    .unwrap();
    let upstream = instruction(
        "unapproved",
        &f.officer,
        &f.path,
        Route::Exception,
        &facts("venue-B", 750),
        0,
    );
    let mut downstream = instruction(
        "downstream-unapproved",
        &f.counterparty,
        &f.path,
        Route::Composition,
        &facts("venue-A", 650),
        0,
    );
    downstream.upstream = Some(Box::new(upstream));
    rebind(&mut downstream, &f.counterparty, 0).unwrap();
    assert_eq!(
        peer.execute(&scene(), &f.issuers, &downstream, 20).unwrap(),
        D::Prevented
    );
}

#[test]
fn amendments_need_affected_parties_and_preserve_old_material() {
    let (_t, f, mut field) = setup();
    let old = f.path.reference();
    let mut revised = f.path.clone();
    revised.window = [0, 50];
    revised.parent_ref = Some(old.clone());
    let c = change("amend", &old, Some(revised.clone()));
    assert_eq!(
        govern(
            &mut field,
            &f,
            &scene(),
            "amend",
            c.clone(),
            &[&f.principal]
        )
        .unwrap(),
        D::DecisionRequired
    );
    assert_eq!(
        govern(
            &mut field,
            &f,
            &scene(),
            "amend",
            c,
            &[&f.principal, &f.counterparty]
        )
        .unwrap(),
        D::Permitted
    );
    assert_eq!(field.discovery().commitments[&old], f.path);
    let a = instruction(
        "old-after-amend",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &facts("venue-A", 750),
        0,
    );
    assert_eq!(
        field.execute(&scene(), &f.issuers, &a, 20).unwrap(),
        D::Prevented
    );
    let a = instruction(
        "new-after-amend",
        &f.agent,
        &revised,
        Route::Ordinary,
        &facts("venue-A", 750),
        0,
    );
    assert_eq!(
        field.execute(&scene(), &f.issuers, &a, 20).unwrap(),
        D::Permitted
    );
}

#[test]
fn rulebook_polymorphism_respects_rules_and_phrases_separately() {
    let book = rulebook();
    let base = Resolved::base(&book).unwrap();
    let mut patch = Interpretation {
        rulebook_ref: book.hash(),
        parent_ref: book.hash(),
        author_urn: "urn:lead:test".into(),
        level: Level::Lead,
        patches: BTreeMap::from([(
            0,
            RulePatch {
                modifier: None,
                omit: false,
                phrases: BTreeMap::from([(
                    0,
                    Phrase {
                        definition: "bounded at 500".into(),
                        modifier: Modifier::Final,
                        predicate: Predicate::AtMost {
                            field: "amount".into(),
                            value: 500,
                        },
                        omitted: false,
                    },
                )]),
            },
        )]),
    };
    let resolved = base.extend(&patch).unwrap(); // final rule still has interpretable phrase
    assert_eq!(resolved.evaluate(&facts("venue-A", 600)), Verdict::Fail);
    patch.patches.get_mut(&0).unwrap().omit = true;
    assert!(base.extend(&patch).is_err());
    patch.patches.get_mut(&0).unwrap().omit = false;
    patch.patches.get_mut(&0).unwrap().modifier = Some(Modifier::Public);
    assert!(base.extend(&patch).is_err());
    patch.patches.get_mut(&0).unwrap().modifier = None;
    patch.patches.get_mut(&0).unwrap().phrases.insert(
        1,
        Phrase {
            definition: "weaken final".into(),
            modifier: Modifier::Final,
            predicate: Predicate::AtLeast {
                field: "amount".into(),
                value: 0,
            },
            omitted: false,
        },
    );
    assert!(base.extend(&patch).is_err());
    let mut invalid = book.clone();
    invalid.rules[0].modifier = Modifier::Public;
    assert!(invalid.validate().is_err());
    assert_ne!(invalid.hash(), book.hash());
}

#[test]
fn public_phrases_can_be_omitted_but_protected_cannot() {
    let mut book = rulebook();
    book.rules[0].phrases[0].modifier = Modifier::Public;
    let mut omitted = book.rules[0].phrases[0].clone();
    omitted.omitted = true;
    let child = Interpretation {
        rulebook_ref: book.hash(),
        parent_ref: book.hash(),
        author_urn: "urn:lead:test".into(),
        level: Level::Lead,
        patches: BTreeMap::from([(
            0,
            RulePatch {
                modifier: None,
                omit: false,
                phrases: BTreeMap::from([(0, omitted)]),
            },
        )]),
    };
    assert!(Resolved::base(&book).unwrap().extend(&child).is_ok());
    book.rules[0].phrases[0].modifier = Modifier::Protected;
    let mut child = child;
    child.rulebook_ref = book.hash();
    child.parent_ref = book.hash();
    assert!(Resolved::base(&book).unwrap().extend(&child).is_err());
}

#[test]
fn stub_governance_digest_is_separate_and_discovery_detects_tampering() {
    let (_t, f, field) = setup();
    let mut d = field.discovery();
    let mut stub = d.stubs[0].clone();
    let governance = stub.governance_hash();
    stub.transaction_hash = "another-message".into();
    assert_eq!(stub.governance_hash(), governance);
    d.rulebooks.get_mut(&f.path.rulebook_ref).unwrap().rules[0]
        .description
        .push_str(" altered");
    assert!(d.inspect(&stub).is_err());
}

#[test]
fn ordinary_poh_has_no_stable_credential_identity_or_raw_handle() {
    let f = Fixture::new().unwrap();
    let a = f.agent.prove("one", "binding-one", "payoff", 0);
    let b = f.agent.prove("two", "binding-two", "payoff", 0);
    assert_ne!(a.seat_ref, b.seat_ref);
    assert_ne!(a.inspection_stub, b.inspection_stub);
    let public = serde_json::to_value(a).unwrap();
    for forbidden in [
        "pseudonym",
        "secret",
        "credential_id",
        "revocation_handle",
        "participant_id",
    ] {
        assert!(public.get(forbidden).is_none());
    }
}

#[test]
fn unknown_facts_and_unknown_interpretations_are_not_guessed() {
    let (_t, f, mut field) = setup();
    let mut data = facts("venue-A", 750);
    data.remove("bond");
    let a = instruction(
        "unknown-facts",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &data,
        0,
    );
    assert_eq!(
        field.execute(&scene(), &f.issuers, &a, 20).unwrap(),
        D::Indeterminate
    );
    assert_eq!(
        field.host().state().unwrap().queue["unknown-facts"].status,
        "pending"
    );
}

#[test]
fn evidence_log_tampering_is_detected() {
    let (_t, _f, field) = setup();
    let mut events = field.host().state().unwrap().events;
    events[0].data["agreed_amount_max"] = json!(9999);
    assert!(audit::verify_transcript(&events).is_err());
}

#[test]
fn supplied_kernel_snapshot_is_byte_identical_and_layers_stay_generic() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("vendor/kernel-source.json")).unwrap()).unwrap();
    for (path, hash) in manifest["files"].as_object().unwrap() {
        assert_eq!(
            constitutive_action::v1::sha256_hex(
                &fs::read(root.join("vendor/constitutive-action").join(path)).unwrap()
            ),
            hash.as_str().unwrap()
        );
    }
    for module in ["protocol", "rules", "identity", "store"] {
        let source = fs::read_to_string(root.join(format!("src/{module}.rs")))
            .unwrap()
            .to_lowercase();
        for forbidden in [
            "settlement",
            "custodian",
            "swift",
            "funding_cost",
            "bond-01",
            "venue-a",
            "tcplistener",
            "reqwest",
        ] {
            assert!(!source.contains(forbidden), "{module} contains {forbidden}");
        }
    }
    assert!(optimal_shortcut().expected_cost < opportunities()[0].expected_cost);
}

#[test]
fn proof_under_an_unaccepted_lead_is_prevented() {
    let (_t, mut f, mut field) = setup();
    let mut other = f.discovery.moderators[0].clone();
    other.urn = "urn:other:moderator".into();
    other.lead_urn = "urn:other:lead".into();
    let mut issuers = Issuers::new(vec![other.clone()]).unwrap();
    let actor = issuers
        .issue(&other.urn, &facts("venue-A", 600), "outsider", 100)
        .unwrap();
    let a = instruction(
        "unaccepted-lead",
        &actor,
        &f.path,
        Route::Composition,
        &facts("venue-A", 600),
        0,
    );
    assert_eq!(
        field.execute(&scene(), &issuers, &a, 20).unwrap(),
        D::Prevented
    );
    // The original issuer can still admit a never-seen actor under the selected Lead.
    assert!(
        f.issuers
            .issue(
                &f.newcomer_moderator,
                &facts("venue-A", 600),
                "another",
                100
            )
            .is_ok()
    );
    assert_ne!(digest(&a.proof), "");
}

#[test]
fn field_reopens_commitments_and_withdrawals_from_confirmed_acts() {
    let (t, f, mut field) = setup();
    let a = instruction(
        "persisted",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &facts("venue-A", 600),
        0,
    );
    assert_eq!(
        field.execute(&scene(), &f.issuers, &a, 20).unwrap(),
        D::Permitted
    );
    let before = field.host().occurrences().unwrap();
    drop(field);
    let mut reopened = Field::reopen(&t.0).unwrap();
    assert_eq!(
        reopened.execute(&scene(), &f.issuers, &a, 20).unwrap(),
        D::Permitted
    );
    assert_eq!(reopened.host().occurrences().unwrap(), before);
    assert_eq!(
        govern(
            &mut reopened,
            &f,
            &scene(),
            "withdraw-persisted",
            change("withdraw", &f.path.reference(), None),
            &[&f.principal]
        )
        .unwrap(),
        D::Permitted
    );
    drop(reopened);
    let mut reopened = Field::reopen(&t.0).unwrap();
    let a = instruction(
        "after-restart-withdrawal",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &facts("venue-A", 600),
        0,
    );
    assert_eq!(
        reopened.execute(&scene(), &f.issuers, &a, 20).unwrap(),
        D::Prevented
    );
}

#[test]
fn private_issuer_snapshot_preserves_credential_revocation() {
    let t = Temp::new();
    let mut f = Fixture::new().unwrap();
    let p = f.agent.prove("one", "binding", "payoff", 0);
    f.issuers.revoke(&p.moderator_urn, &p).unwrap();
    f.issuers.save_private(&t.0.join("issuer.json")).unwrap();
    let reopened = Issuers::load_private(&t.0.join("issuer.json")).unwrap();
    let fresh = f
        .agent
        .prove("two", "next-binding", "payoff", reopened.epoch());
    assert_eq!(
        reopened.verify(
            &fresh,
            &f.leads,
            &f.path.rulebook_ref,
            "two",
            "next-binding",
            "payoff",
            20
        ),
        Verdict::Fail
    );
    assert_eq!(reopened.revocation_ref(), f.issuers.revocation_ref());
}

#[test]
fn timing_usage_and_action_types_are_enforced_with_host_facts() {
    let t = Temp::new();
    let mut f = Fixture::new().unwrap();
    f.path.scope = Predicate::All {
        predicates: vec![
            f.path.scope.clone(),
            Predicate::AtMost {
                field: "host.count".into(),
                value: 1,
            },
        ],
    };
    let mut field = f.field(&t.0, Topology::Constitutive).unwrap();
    constitute(&mut field, &f).unwrap();
    let first = instruction(
        "usage-1",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &facts("venue-A", 600),
        0,
    );
    assert_eq!(
        field.execute(&scene(), &f.issuers, &first, 20).unwrap(),
        D::Permitted
    );
    let second = instruction(
        "usage-2",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &facts("venue-A", 600),
        0,
    );
    assert_eq!(
        field.execute(&scene(), &f.issuers, &second, 20).unwrap(),
        D::Prevented
    );
    let mut fake = facts("venue-A", 600);
    fake.insert("host.count".into(), json!(0));
    let a = instruction("spoof-usage", &f.agent, &f.path, Route::Ordinary, &fake, 0);
    assert!(field.execute(&scene(), &f.issuers, &a, 20).is_err());
    let a = instruction(
        "late",
        &f.counterparty,
        &f.path,
        Route::Composition,
        &facts("venue-A", 600),
        0,
    );
    assert_eq!(
        field.execute(&scene(), &f.issuers, &a, 31).unwrap(),
        D::Prevented
    );
    let mut fake = facts("venue-A", 600);
    fake.insert("action_type".into(), json!("unconstituted-action"));
    let a = instruction(
        "bad-action-type",
        &f.counterparty,
        &f.path,
        Route::Composition,
        &fake,
        0,
    );
    assert_eq!(
        field.execute(&scene(), &f.issuers, &a, 20).unwrap(),
        D::Prevented
    );
}

#[test]
fn forged_rules_riding_a_message_are_rejected() {
    let (_t, f, mut field) = setup();
    let mut a = instruction(
        "forged-rule-payload",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &facts("venue-A", 600),
        0,
    );
    a.rule_payload[0].phrases[0].predicate = Predicate::AtMost {
        field: "amount".into(),
        value: 999999,
    };
    rebind(&mut a, &f.agent, 0).unwrap();
    assert_eq!(
        field.execute(&scene(), &f.issuers, &a, 20).unwrap(),
        D::Prevented
    );
}

#[test]
fn promotion_cannot_skip_the_side_environment_trail() {
    let (_t, f, mut field) = setup();
    let mut candidate = f.path.clone();
    candidate.parent_ref = Some(f.path.reference());
    assert!(
        govern(
            &mut field,
            &f,
            &scene(),
            "promotion-bypass",
            change("promote", &f.path.reference(), Some(candidate)),
            &[&f.principal, &f.counterparty]
        )
        .is_err()
    );
    assert!(
        !field
            .host()
            .state()
            .unwrap()
            .records
            .contains_key("promotion-bypass")
    );
}

#[test]
fn illegal_fork_is_prevented_by_the_kernel_without_publication() {
    let (_t, f, mut field) = setup();
    let child = Interpretation {
        rulebook_ref: f.path.rulebook_ref.clone(),
        parent_ref: f.path.interpretation_ref.clone(),
        author_urn: "urn:actor:test".into(),
        level: Level::User,
        patches: BTreeMap::from([(
            0,
            RulePatch {
                modifier: Some(Modifier::Public),
                omit: false,
                phrases: BTreeMap::new(),
            },
        )]),
    };
    let reference = digest(&child);
    let mut c = change("fork", &f.path.reference(), None);
    c.interpretation = Some(child);
    assert_eq!(
        govern(&mut field, &f, &scene(), "illegal-fork", c, &[]).unwrap(),
        D::Prevented
    );
    assert!(!field.discovery().interpretations.contains_key(&reference));
}

#[test]
fn delegate_kind_is_descriptive_and_never_authorises_an_action() {
    let (_t, f, mut field) = setup();
    let mut a = instruction(
        "kind",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &facts("venue-A", 600),
        0,
    );
    a.delegate_kind = "person".into();
    assert_eq!(
        field.execute(&scene(), &f.issuers, &a, 20).unwrap(),
        D::Permitted
    );
    let mut a = instruction(
        "kind-outside",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &facts("venue-B", 600),
        0,
    );
    a.delegate_kind = "system".into();
    assert_eq!(
        field.execute(&scene(), &f.issuers, &a, 20).unwrap(),
        D::Prevented
    );
}

#[test]
fn selected_lead_accepts_another_published_moderator_without_field_registration() {
    let (_t, f, mut field) = setup();
    let mut moderators = f.discovery.moderators.clone();
    let mut third = moderators[0].clone();
    third.urn = "urn:new-moderator:under-selected-lead".into();
    moderators.push(third.clone());
    let mut issuers = Issuers::new(moderators).unwrap();
    let actor = issuers
        .issue(&third.urn, &facts("venue-A", 600), "novel-holder", 100)
        .unwrap();
    let a = instruction(
        "novel-moderator",
        &actor,
        &f.path,
        Route::Composition,
        &facts("venue-A", 600),
        0,
    );
    assert_eq!(
        field.execute(&scene(), &issuers, &a, 20).unwrap(),
        D::Permitted
    );
    let discovery = field.discovery();
    assert!(discovery.inspect(discovery.stubs.last().unwrap()).is_ok());
}
