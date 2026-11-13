//! Commitments survive a change of utility. Terms constituted and published in
//! one container are taken up by a second, independently stored container with
//! a different controller. The first container's store is deleted before the
//! second opens, so nothing carries over except the published, content-addressed
//! terms. The same acts receive the same decisions in both.
use constitutive_action::v1::DecisionKind as D;
use serde_json::json;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
use tgc_demo::{audit, authoring, canonical, protocol::*, scenario::*};

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
                    "tgc-utility-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::SeqCst)
                ))
            })
            .join(name);
        assert!(
            !root.exists(),
            "case output must be fresh: {}",
            root.display()
        );
        fs::create_dir_all(&root).unwrap();
        Self(root, env.is_some())
    }
}
impl Drop for Case {
    fn drop(&mut self) {
        if !self.1 {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

/// Acts submitted to each utility: within the agreed terms, and outside them.
const ACTS: [(&str, &str, i64); 2] = [("within", "venue-A", 500), ("outside", "venue-A", 900)];

fn run(field: &mut Field, f: &Fixture, utility: &str) -> Vec<D> {
    let scene = Scene::new("coverage", "utility-change");
    ACTS.iter()
        .map(|(name, venue, amount)| {
            let action = authoring::instruction(
                &format!("{utility}-{name}"),
                &f.counterparty,
                &f.path,
                Route::Composition,
                facts(venue, *amount),
                0,
            );
            field.execute(&scene, &f.issuers, &action, 20).unwrap()
        })
        .collect()
}

#[test]
fn commitments_survive_a_change_of_utility() {
    let c = Case::new("utility-change");
    let f = Fixture::new().unwrap();

    // Utility A: the parties constitute and publish their terms, then act.
    let root_a = c.0.join("utility-a");
    let mut a = f.field(&root_a, Topology::Constitutive).unwrap();
    constitute(&mut a, &f).unwrap();
    let before_a = a.host().occurrences().unwrap();
    let decisions_a = run(&mut a, &f, "a");
    assert_eq!(decisions_a, vec![D::Permitted, D::Prevented]);
    let effects_a = a.host().occurrences().unwrap() - before_a;
    assert_eq!(effects_a, 1, "only the permitted act has an effect");
    audit::verify_transcript(&a.host().state().unwrap().events).unwrap();

    // Leave utility A: keep only its published terms, then delete its store.
    let published = a.discovery();
    let commitment = f.path.reference();
    assert!(published.stubs.iter().any(|s| {
        published
            .inspect(s)
            .map(|p| p.reference() == commitment)
            .unwrap_or(false)
    }));
    drop(a);
    fs::remove_dir_all(&root_a).unwrap();
    assert!(!root_a.exists());

    // Utility B: a separate store under a different controller takes up the
    // published terms. Nothing else carries over.
    let controller_b = f.counterparty.seat(&f.path.context);
    assert_ne!(controller_b, f.principal.seat(&f.path.context));
    let mut b = Field::peer(
        &c.0.join("utility-b"),
        Topology::Constitutive,
        published.clone(),
        f.leads.clone(),
        controller_b,
        RecipientPolicy::Honour,
    )
    .unwrap();

    // The terms keep their content-addressed identity in the new utility.
    let carried = b.discovery();
    assert_eq!(
        carried.rulebooks.keys().collect::<Vec<_>>(),
        published.rulebooks.keys().collect::<Vec<_>>()
    );
    assert!(carried.stubs.iter().any(|s| {
        carried
            .inspect(s)
            .map(|p| p.reference() == commitment)
            .unwrap_or(false)
    }));

    // The same acts receive the same decisions, and only permitted acts
    // produce an effect in the new utility.
    let before_b = b.host().occurrences().unwrap();
    let decisions_b = run(&mut b, &f, "b");
    assert_eq!(decisions_b, decisions_a);
    let effects_b = b.host().occurrences().unwrap() - before_b;
    assert_eq!(effects_b, effects_a);
    audit::verify_transcript(&b.host().state().unwrap().events).unwrap();

    fs::write(
        c.0.join("result.json"),
        canonical(&json!({
            "commitment": commitment,
            "acts": ACTS.iter().map(|(n, v, a)| json!({"act": n, "venue": v, "amount": a})).collect::<Vec<_>>(),
            "utility_a": {"decisions": decisions_a, "effects": effects_a, "store_deleted": true},
            "utility_b": {"decisions": decisions_b, "effects": effects_b},
        })),
    )
    .unwrap();
}
