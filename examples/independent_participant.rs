//! Discover published terms; issue on criteria, without a field registration call.
mod support;
use constitutive_action::v1::DecisionKind;
use support::*;
use tgc_demo::{Result, authoring, protocol::Route};
fn main() -> Result<()> {
    let mut w = Workshop::new("arrival")?;
    let discovery = w.field.discovery();
    let stub = &discovery.stubs[0];
    let path = discovery.inspect(stub)?;
    let moderator = discovery
        .moderators
        .iter()
        .find(|m| w.leads.contains(&m.lead_urn))
        .unwrap();
    let newcomer = w
        .issuers
        .issue(&moderator.urn, &facts(3), "previously-absent-fixture", 100)?;
    let action = authoring::instruction(
        "first-action",
        &newcomer,
        path,
        Route::Composition,
        facts(3),
        0,
    );
    assert_eq!(
        w.field.execute(&scene(), &w.issuers, &action, 1)?,
        DecisionKind::Permitted
    );
    output(serde_json::json!({"discovered_stub":stub,"proof":action.proof,"host":w.summary()?}));
    Ok(())
}
