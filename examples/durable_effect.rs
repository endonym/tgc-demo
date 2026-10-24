//! A host integration laboratory using the actual durable store implementation.
//! A distinct workshop effect profile shows that the kernel is domain-neutral.
//! The store is compiled into this example as host-owned implementation code;
//! its dispatch functions remain inaccessible to participant library callers.
pub use tgc_demo::{Result, audit, canonical, digest, ensure};
#[allow(dead_code)]
#[path = "../src/store.rs"]
mod store;
use constitutive_action::v1::*;
use serde_json::{Value, json};
use std::{path::Path, time::Instant};
use store::{Host, Reservation};
fn prepare(root: &Path) -> Result<(Host, ActionIntent)> {
    let host = Host::open(root)?;
    let intent = ActionIntent {
        schema_version: 1,
        proposal_id: "workshop-reservation".into(),
        actor_id: "workshop:agent".into(),
        represented_principal_id: "workshop:owner".into(),
        authority_id: "workshop:authority".into(),
        context_id: "workshop:room".into(),
        context_version: 1,
        effect: Effect {
            profile_id: "workshop.reservation/v1".into(),
            profile_version: 1,
            operation: "reserve-room".into(),
            destination: "room:blue".into(),
            canonical_payload: canonical(&json!({"room":"blue","slot":3,"units":2})),
        },
    };
    let snapshot = EvaluationSnapshot {
        schema_version: 1,
        context_id: intent.context_id.clone(),
        context_version: 1,
        sequence: 0,
        valid_through_sequence: 100,
        profile: GateProfile {
            profile_id: "workshop.explicit-open".into(),
            version: 1,
            effect_profile_id: intent.effect.profile_id.clone(),
            effect_profile_version: 1,
            conditions: ConditionPolicy::ExplicitOpen,
            required_acceptances: vec![],
        },
        evidence: vec![],
        assessments: vec![],
        acceptances: vec![],
        revocation: RevocationState::default(),
    };
    assert_eq!(
        host.prepare(
            &intent,
            &snapshot,
            audit::Event::new("lab", "host", "explicit-open", "decision", json!({})),
            Instant::now()
        )?
        .kind,
        DecisionKind::Permitted
    );
    Ok((host, intent))
}
fn record(host: &Host, id: &str) -> Result<Value> {
    let state = host.state()?;
    Ok(
        json!({"order":state.order,"record":state.records[id],"revocations":state.revocations,"occurrences":host.occurrences()?}),
    )
}
fn main() -> Result<()> {
    let root = std::env::temp_dir().join(format!("tgc-durable-{}", std::process::id()));
    ensure(!root.exists(), "existing laboratory directory")?;
    let mut cases = vec![];
    let (h, i) = prepare(&root.join("race"))?;
    let a = h.clone();
    let b = h.clone();
    let id = i.proposal_id.clone();
    let id2 = id.clone();
    let first = std::thread::spawn(move || a.reserve(&id));
    let second = std::thread::spawn(move || b.reserve(&id2));
    let results = [first.join().unwrap()?, second.join().unwrap()?];
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Reservation::New(_)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Reservation::Replay(_)))
            .count(),
        1
    );
    let ticket = match &results[0] {
        Reservation::New(t) | Reservation::Replay(t) => t.clone(),
        _ => unreachable!(),
    };
    let before = record(&h, &i.proposal_id)?;
    let receipt = h.dispatch(&ticket, &i.effect, false)?;
    assert_eq!(h.dispatch(&ticket, &i.effect, false)?, receipt);
    assert_eq!(h.occurrences()?, 1);
    cases.push(json!({"id":"simultaneous-claims","title":"Two claims, one durable attempt","before":before,"after":record(&h,&i.proposal_id)?,"claims":results.iter().map(|r|format!("{r:?}")).collect::<Vec<_>>()}));
    let (h, i) = prepare(&root.join("changed"))?;
    let Reservation::New(t) = h.reserve(&i.proposal_id)? else {
        unreachable!()
    };
    let mut changed = i.effect.clone();
    changed.destination = "room:red".into();
    let error = h.dispatch(&t, &changed, false).unwrap_err().to_string();
    assert_eq!(h.occurrences()?, 0);
    cases.push(json!({"id":"changed-effect","title":"A changed destination cannot use the ticket","actual_effect":changed,"error":error,"after":record(&h,&i.proposal_id)?}));
    let (h, i) = prepare(&root.join("withdraw-first"))?;
    let order = h.effective_revoke(&i.authority_id)?;
    assert_eq!(h.reserve(&i.proposal_id)?, Reservation::Denied);
    cases.push(json!({"id":"withdraw-first","title":"Effective withdrawal precedes reservation","withdrawal_order":order,"reservation":"Denied","after":record(&h,&i.proposal_id)?}));
    let (h, i) = prepare(&root.join("reserve-first"))?;
    let Reservation::New(t) = h.reserve(&i.proposal_id)? else {
        unreachable!()
    };
    let order = h.effective_revoke(&i.authority_id)?;
    assert!(t.order < order);
    h.dispatch(&t, &i.effect, false)?;
    cases.push(json!({"id":"reserve-first","title":"Reservation precedes effective withdrawal","withdrawal_order":order,"after":record(&h,&i.proposal_id)?}));
    let path = root.join("uncertain");
    let (h, i) = prepare(&path)?;
    let Reservation::New(t) = h.reserve(&i.proposal_id)? else {
        unreachable!()
    };
    h.dispatch(&t, &i.effect, true)?;
    let before = record(&h, &i.proposal_id)?;
    assert!(matches!(
        h.state()?.records[&i.proposal_id]
            .receipt
            .as_ref()
            .unwrap()
            .outcome,
        ExecutionOutcome::Uncertain { .. }
    ));
    drop(h);
    let reopened = Host::open(&path)?;
    reopened.recover()?;
    reopened.recover()?;
    assert_eq!(reopened.occurrences()?, 1);
    cases.push(json!({"id":"uncertain","title":"A lost response is reconciled after reopen","before":before,"after":record(&reopened,&i.proposal_id)?}));
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"schema_version":1,"profile_note":"An explicit-open admission profile isolates durable reservation, effect binding and recovery.","cases":cases})
        )?
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}
