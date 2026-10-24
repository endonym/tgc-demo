//! Executable expectations for previously observed container contract failures.
//! These remain red until implementation changes are separately reviewed.
use constitutive_action::v1::DecisionKind as D;
use serde_json::json;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
use tgc_demo::{
    audit, authoring, canonical,
    identity::{Issuers, Moderator},
    protocol::*,
    rules::{Predicate, Verdict},
    scenario::*,
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Case(PathBuf, bool);
impl Case {
    fn new(name: &str) -> Self {
        let env = std::env::var_os("TGC_COVERAGE_EVIDENCE");
        let root = env
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::temp_dir().join(format!(
                    "tgc-contract-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::SeqCst)
                ))
            })
            .join(name);
        assert!(!root.exists());
        fs::create_dir_all(&root).unwrap();
        Self(root, env.is_some())
    }
    fn save(&self, name: &str, field: &Field) {
        fs::write(
            self.0.join(format!("{name}-state.json")),
            canonical(&field.host().state().unwrap()),
        )
        .unwrap();
        fs::write(
            self.0.join(format!("{name}-discovery.json")),
            canonical(&field.discovery()),
        )
        .unwrap();
    }
}
impl Drop for Case {
    fn drop(&mut self) {
        if !self.1 {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
#[test]
fn unknown_delegation_and_composition_preserve_three_way_predicate_results() {
    let mut failures = vec![];
    for topology in [Topology::Control, Topology::Constitutive] {
        for route in [Route::Ordinary, Route::Composition] {
            for expected in [D::Permitted, D::Prevented, D::Indeterminate] {
                let c = Case::new(&format!("predicate-{topology:?}-{route:?}-{expected:?}"));
                let mut f = Fixture::new().unwrap();
                let predicate = match expected {
                    D::Permitted => Predicate::AtMost {
                        field: "amount".into(),
                        value: 600,
                    },
                    D::Prevented => Predicate::AtMost {
                        field: "amount".into(),
                        value: 400,
                    },
                    _ => Predicate::Unresolved {
                        reason: "requires resolution".into(),
                    },
                };
                if route == Route::Ordinary {
                    f.path.delegation.as_mut().unwrap().scope = predicate;
                } else {
                    f.path.composition = predicate;
                }
                let mut field = f.field(&c.0.join("field"), topology).unwrap();
                constitute(&mut field, &f).unwrap();
                let actor = if route == Route::Ordinary {
                    &f.agent
                } else {
                    &f.counterparty
                };
                let a = instruction("action", actor, &f.path, route, &facts("venue-A", 500), 0);
                assert_eq!(
                    f.issuers.verify(
                        &a.proof,
                        &f.leads,
                        &f.path.rulebook_ref,
                        "action",
                        &a.intent.fingerprint(),
                        &f.path.payoffs.on_violation,
                        20
                    ),
                    Verdict::Pass
                );
                let before = field.host().occurrences().unwrap();
                let observed = field
                    .execute(&Scene::new("coverage", "predicate"), &f.issuers, &a, 20)
                    .unwrap();
                let queued = field.host().state().unwrap().queue.contains_key("action");
                let delta = field.host().occurrences().unwrap() - before;
                let ok = observed == expected
                    && queued == (expected == D::Indeterminate)
                    && delta == usize::from(expected == D::Permitted);
                fs::write(c.0.join("result.json"),canonical(&json!({"expected":expected,"observed":observed,"queued":queued,"effect_delta":delta,"pass":ok}))).unwrap();
                c.save("final", &field);
                audit::verify_transcript(&field.host().state().unwrap().events).unwrap();
                if !ok {
                    failures.push(format!("{topology:?}/{route:?}/{expected:?}: {observed:?}, queued={queued}, effects={delta}"));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
#[test]
fn equal_predicates_in_distinct_upstream_checks_remain_valid() {
    let mut failures = vec![];
    for distinct_encoding in [false, true] {
        let c = Case::new(&format!("equal-predicates-{distinct_encoding}"));
        let mut f = Fixture::new().unwrap();
        f.path.exception = if distinct_encoding {
            Predicate::All {
                predicates: vec![f.path.conditions.clone()],
            }
        } else {
            f.path.conditions.clone()
        };
        let mut field = f
            .field(&c.0.join("primary"), Topology::Constitutive)
            .unwrap();
        constitute(&mut field, &f).unwrap();
        let scene = Scene::new("coverage", "equal-predicates");
        let mut upstream = authoring::instruction(
            "upstream",
            &f.officer,
            &f.path,
            Route::Exception,
            facts("venue-B", 600),
            0,
        );
        upstream.endorsements.push(authoring::endorse(
            &f.officer,
            &upstream.intent,
            &f.path.context,
            &f.path.payoffs.on_exceed_scope,
            0,
        ));
        assert_eq!(
            field.execute(&scene, &f.issuers, &upstream, 20).unwrap(),
            D::Permitted
        );
        let mut peer = Field::peer(
            &c.0.join("peer"),
            Topology::Constitutive,
            field.discovery(),
            f.leads.clone(),
            f.principal.seat(&f.path.context),
            RecipientPolicy::Honour,
        )
        .unwrap();
        let mut downstream = authoring::instruction(
            "downstream",
            &f.counterparty,
            &f.path,
            Route::Composition,
            facts("venue-A", 600),
            0,
        );
        authoring::attach_upstream(&mut downstream, upstream, &f.counterparty, 0).unwrap();
        let observed = peer.execute(&scene, &f.issuers, &downstream, 20).unwrap();
        let effects = peer.host().occurrences().unwrap();
        fs::write(c.0.join("result.json"),canonical(&json!({"expected":"permitted","observed":observed,"effects":effects,"distinct_encoding":distinct_encoding}))).unwrap();
        c.save("primary", &field);
        c.save("peer", &peer);
        audit::verify_transcript(&peer.host().state().unwrap().events).unwrap();
        if observed != D::Permitted || effects != 1 {
            failures.push(format!(
                "distinct_encoding={distinct_encoding}: {observed:?}, effects={effects}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
#[test]
fn confirmed_late_moderator_discovery_survives_restart() {
    let c = Case::new("late-moderator");
    let mut f = Fixture::new().unwrap();
    let mut field = f.field(&c.0.join("field"), Topology::Constitutive).unwrap();
    constitute(&mut field, &f).unwrap();
    let moderator = Moderator {
        urn: "urn:moderator:late-coverage".into(),
        lead_urn: f.leads.iter().next().unwrap().clone(),
        rulebook_ref: f.path.rulebook_ref.clone(),
        admission: f.path.conditions.clone(),
    };
    let mut moderators = f.issuers.published();
    moderators.push(moderator.clone());
    f.issuers = Issuers::new(moderators).unwrap();
    let newcomer = f
        .issuers
        .issue(
            &moderator.urn,
            &facts("venue-A", 600),
            "independent-newcomer",
            1000,
        )
        .unwrap();
    let action = authoring::instruction(
        "late-action",
        &newcomer,
        &f.path,
        Route::Composition,
        facts("venue-A", 600),
        0,
    );
    assert_eq!(
        field
            .execute(
                &Scene::new("coverage", "late-moderator"),
                &f.issuers,
                &action,
                20
            )
            .unwrap(),
        D::Permitted
    );
    let before = field.discovery();
    assert!(before.stubs.iter().all(|s| before.inspect(s).is_ok()));
    let count = field.host().occurrences().unwrap();
    c.save("before", &field);
    drop(field);
    let field = Field::reopen(&c.0.join("field")).unwrap();
    let after = field.discovery();
    assert_eq!(field.host().occurrences().unwrap(), count);
    c.save("after", &field);
    let inspect_ok = after.stubs.iter().all(|s| after.inspect(s).is_ok());
    let peer = Field::peer(
        &c.0.join("peer"),
        Topology::Constitutive,
        after.clone(),
        f.leads.clone(),
        f.principal.seat(&f.path.context),
        RecipientPolicy::Honour,
    );
    let error = peer.err().map(|e| e.to_string());
    fs::write(c.0.join("result.json"),canonical(&json!({"moderators_before":before.moderators.len(),"moderators_after":after.moderators.len(),"inspect_ok":inspect_ok,"peer_error":error}))).unwrap();
    audit::verify_transcript(&field.host().state().unwrap().events).unwrap();
    assert!(
        inspect_ok && error.is_none() && before.moderators == after.moderators,
        "confirmed discovery lost usable moderator relationship: {error:?}"
    );
}
