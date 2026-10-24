//! Approval applies only to the separately constituted exception route.
mod support;
use constitutive_action::v1::DecisionKind as D;
use support::*;
use tgc_demo::{Result, authoring, protocol::Route};
fn main() -> Result<()> {
    let mut w = Workshop::new("exception")?;
    let ordinary =
        authoring::instruction("ordinary", &w.agent, &w.path, Route::Ordinary, facts(8), 0);
    assert_eq!(
        w.field.execute(&scene(), &w.issuers, &ordinary, 1)?,
        D::Prevented
    );
    let mut exception = authoring::instruction(
        "exception",
        &w.officer,
        &w.path,
        Route::Exception,
        facts(8),
        0,
    );
    assert_eq!(
        w.field.execute(&scene(), &w.issuers, &exception, 1)?,
        D::DecisionRequired
    );
    exception.endorsements.push(authoring::endorse(
        &w.officer,
        &exception.intent,
        &w.path.context,
        &w.path.payoffs.on_exceed_scope,
        0,
    ));
    assert_eq!(
        w.field.execute(&scene(), &w.issuers, &exception, 1)?,
        D::Permitted
    );
    assert_eq!(
        w.field.execute(&scene(), &w.issuers, &ordinary, 1)?,
        D::Prevented
    );
    output(w.summary()?);
    Ok(())
}
