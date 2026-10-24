//! Change units from 4 to 6 and observe the bounded ordinary path.
mod support;
use constitutive_action::v1::DecisionKind;
use support::*;
use tgc_demo::{Result, authoring, protocol::Route};
fn main() -> Result<()> {
    let mut w = Workshop::new("minimal")?;
    let mut outcomes = vec![];
    for (id, units, expected) in [
        ("within", 4, DecisionKind::Permitted),
        ("outside", 6, DecisionKind::Prevented),
    ] {
        let action =
            authoring::instruction(id, &w.agent, &w.path, Route::Ordinary, facts(units), 0);
        let decision = w.field.execute(&scene(), &w.issuers, &action, 1)?;
        assert_eq!(decision, expected);
        outcomes.push(serde_json::json!({"units":units,"decision":decision}));
    }
    output(serde_json::json!({"outcomes":outcomes,"host":w.summary()?}));
    Ok(())
}
