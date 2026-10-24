//! Each recipient validates the attached exception under its own policy.
mod support;
use constitutive_action::v1::DecisionKind as D;
use support::*;
use tgc_demo::{Result, authoring, protocol::*};
fn main() -> Result<()> {
    let mut w = Workshop::new("recipient")?;
    let mut upstream = authoring::instruction(
        "upstream",
        &w.officer,
        &w.path,
        Route::Exception,
        facts(8),
        0,
    );
    upstream.endorsements.push(authoring::endorse(
        &w.officer,
        &upstream.intent,
        &w.path.context,
        &w.path.payoffs.on_exceed_scope,
        0,
    ));
    assert_eq!(
        w.field.execute(&scene(), &w.issuers, &upstream, 1)?,
        D::Permitted
    );
    let mut results = vec![];
    for (name, policy, expected) in [
        ("refuse", RecipientPolicy::Refuse, D::Prevented),
        ("honour", RecipientPolicy::Honour, D::Permitted),
        ("unresolved", RecipientPolicy::Unresolved, D::Indeterminate),
    ] {
        let mut peer = Field::peer(
            &w.root.join(name),
            Topology::Constitutive,
            w.field.discovery(),
            w.leads.clone(),
            w.owner.seat(&w.path.context),
            policy,
        )?;
        let mut action =
            authoring::instruction(name, &w.partner, &w.path, Route::Composition, facts(3), 0);
        authoring::attach_upstream(&mut action, upstream.clone(), &w.partner, 0)?;
        let decision = peer.execute(&scene(), &w.issuers, &action, 1)?;
        assert_eq!(decision, expected);
        results.push(serde_json::json!({"policy":name,"decision":decision,"own_proof":action.proof,"upstream_proof":upstream.proof}));
    }
    output(serde_json::json!({"recipients":results}));
    Ok(())
}
