use constitutive_action::v1::DecisionKind as D;
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};
use tgc_demo::{audit, digest, protocol::*, rules::*, scenario::*, store::Host};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "tgc-owner-{}-{}",
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
    Scene::new("test", "ownership-authorship")
}

#[test]
fn ownership_child() {
    let Some(root) = std::env::var_os("TGC_OWNERSHIP_TEST_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    if std::env::var_os("TGC_OWNERSHIP_TEST_CRASH").is_some() {
        let f = Fixture::new().unwrap();
        let _field = f.field(&root, Topology::Constitutive).unwrap();
        // No destructors: the OS must release the lifetime lock.
        std::process::exit(86);
    }
    assert!(Field::reopen(&root).is_err());
}

#[test]
fn one_owner_across_handles_and_processes_with_read_only_inspection() {
    let t = Temp::new();
    let f = Fixture::new().unwrap();
    let mut field = f.field(&t.0, Topology::Constitutive).unwrap();
    constitute(&mut field, &f).unwrap();
    assert!(f.field(&t.0, Topology::Constitutive).is_err());
    assert!(Field::reopen(&t.0).is_err());
    let observer = Host::open_existing(&t.0).unwrap();
    let before = fs::read(t.0.join("state.json")).unwrap();
    assert!(observer.state().is_ok());
    assert!(observer.recover().is_err());
    assert!(Field::recover_host(&observer).is_err());
    assert!(field.host().recover().is_err());
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "ownership_child", "--nocapture"])
        .env("TGC_OWNERSHIP_TEST_ROOT", &t.0)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(t.0.join("state.json")).unwrap(), before);
    // Amendment is visible to the sole successor; no stale owner survives.
    let mut revised = f.path.clone();
    revised.parent_ref = Some(f.path.reference());
    revised.scope = Predicate::AtMost {
        field: "amount".into(),
        value: 500,
    };
    assert_eq!(
        govern(
            &mut field,
            &f,
            &scene(),
            "amend",
            change("amend", &f.path.reference(), Some(revised)),
            &[&f.principal, &f.counterparty]
        )
        .unwrap(),
        D::Permitted
    );
    drop(field);
    let mut successor = Field::reopen(&t.0).unwrap();
    let old = instruction(
        "old-terms",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &facts("venue-A", 750),
        0,
    );
    assert_eq!(
        successor.execute(&scene(), &f.issuers, &old, 20).unwrap(),
        D::Prevented
    );
}

#[test]
fn owner_crash_releases_lock_for_reconstruction() {
    let t = Temp::new();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "ownership_child", "--nocapture"])
        .env("TGC_OWNERSHIP_TEST_ROOT", &t.0)
        .env("TGC_OWNERSHIP_TEST_CRASH", "1")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(86));
    let field = Field::reopen(&t.0).unwrap();
    assert!(field.host().state().unwrap().field_bootstrap.is_some());
}

#[test]
fn concurrent_second_owners_cannot_bypass_a_usage_limit() {
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
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let root = t.0.clone();
            std::thread::spawn(move || Field::reopen(&root).is_err())
        })
        .collect();
    for worker in workers {
        assert!(worker.join().unwrap());
    }
    let before = field.host().occurrences().unwrap();
    for (id, expected) in [("first", D::Permitted), ("second", D::Prevented)] {
        let action = instruction(
            id,
            &f.agent,
            &f.path,
            Route::Ordinary,
            &facts("venue-A", 750),
            0,
        );
        assert_eq!(
            field.execute(&scene(), &f.issuers, &action, 20).unwrap(),
            expected
        );
    }
    assert_eq!(field.host().occurrences().unwrap(), before + 1);
}

#[test]
fn fork_authorship_is_bound_to_the_publishing_credential_and_rulebook() {
    let t = Temp::new();
    let f = Fixture::new().unwrap();
    let mut field = f.field(&t.0, Topology::Constitutive).unwrap();
    constitute(&mut field, &f).unwrap();
    let authors = [
        ("forged", "urn:somebody:else".into(), D::Prevented),
        (
            "other-seat",
            f.counterparty.interpretation_author(&f.path.rulebook_ref),
            D::Prevented,
        ),
        (
            "other-book",
            f.principal.interpretation_author("different-rulebook"),
            D::Prevented,
        ),
        (
            "actual-author",
            f.principal.interpretation_author(&f.path.rulebook_ref),
            D::Permitted,
        ),
    ];
    for (id, author_urn, expected) in authors {
        let child = Interpretation {
            rulebook_ref: f.path.rulebook_ref.clone(),
            parent_ref: f.path.interpretation_ref.clone(),
            author_urn,
            level: Level::User,
            patches: BTreeMap::new(),
        };
        let reference = digest(&child);
        let mut request = change("fork", &f.path.reference(), None);
        request.interpretation = Some(child);
        assert_eq!(
            govern(&mut field, &f, &scene(), id, request, &[]).unwrap(),
            expected
        );
        assert_eq!(
            field.discovery().interpretations.contains_key(&reference),
            expected == D::Permitted
        );
    }
    audit::verify_transcript(&field.host().state().unwrap().events).unwrap();
}
