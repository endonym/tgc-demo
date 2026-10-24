//! A final rule can contain an interpretable phrase. Its final phrase stays fixed.
mod support;
use std::collections::BTreeMap;
use support::*;
use tgc_demo::{Result, rules::*};
fn main() -> Result<()> {
    let book = book();
    let base = Resolved::base(&book)?;
    let mut phrase = book.rules[0].phrases[0].clone();
    phrase.definition = "At most 4 units".into();
    phrase.predicate = Predicate::AtMost {
        field: "units".into(),
        value: 4,
    };
    let mut child = Interpretation {
        rulebook_ref: book.hash(),
        parent_ref: book.hash(),
        author_urn: "urn:workshop:lead".into(),
        level: Level::Lead,
        patches: BTreeMap::from([(
            0,
            RulePatch {
                modifier: None,
                omit: false,
                phrases: BTreeMap::from([(0, phrase)]),
            },
        )]),
    };
    let resolved = base.extend(&child)?;
    assert_eq!(resolved.evaluate(&facts(5)), Verdict::Fail);
    let mut forbidden = book.rules[0].phrases[1].clone();
    forbidden.predicate = Predicate::AtLeast {
        field: "units".into(),
        value: 0,
    };
    child
        .patches
        .get_mut(&0)
        .unwrap()
        .phrases
        .insert(1, forbidden);
    let error = base
        .extend(&child)
        .err()
        .expect("final phrase must reject change")
        .to_string();
    output(
        serde_json::json!({"base":book,"valid_interpretation":resolved,"five_units":resolved.evaluate(&facts(5)),"invalid_interpretation_error":error}),
    );
    Ok(())
}
