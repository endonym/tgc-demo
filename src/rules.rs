//! Generic, deterministic rule interpretation. No activity-specific vocabulary.
use crate::{Result, digest, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub type Facts = BTreeMap<String, Value>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Pass,
    Fail,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
pub enum Predicate {
    Equal { field: String, value: Value },
    OneOf { field: String, values: Vec<Value> },
    AtMost { field: String, value: i64 },
    AtLeast { field: String, value: i64 },
    All { predicates: Vec<Predicate> },
    Any { predicates: Vec<Predicate> },
    Unresolved { reason: String },
}
impl Predicate {
    pub fn evaluate(&self, facts: &Facts) -> Verdict {
        use Verdict::*;
        let yes = |b| if b { Pass } else { Fail };
        match self {
            Self::Equal { field, value } => facts.get(field).map_or(Unknown, |v| yes(v == value)),
            Self::OneOf { field, values } => facts
                .get(field)
                .map_or(Unknown, |v| yes(values.contains(v))),
            Self::AtMost { field, value } => facts
                .get(field)
                .and_then(Value::as_i64)
                .map_or(Unknown, |v| yes(v <= *value)),
            Self::AtLeast { field, value } => facts
                .get(field)
                .and_then(Value::as_i64)
                .map_or(Unknown, |v| yes(v >= *value)),
            Self::All { predicates } => {
                let v: Vec<_> = predicates.iter().map(|p| p.evaluate(facts)).collect();
                if v.contains(&Fail) {
                    Fail
                } else if v.is_empty() || v.contains(&Unknown) {
                    Unknown
                } else {
                    Pass
                }
            }
            Self::Any { predicates } => {
                let v: Vec<_> = predicates.iter().map(|p| p.evaluate(facts)).collect();
                if v.contains(&Pass) {
                    Pass
                } else if v.contains(&Unknown) || v.is_empty() {
                    Unknown
                } else {
                    Fail
                }
            }
            Self::Unresolved { .. } => Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Modifier {
    Public,
    Protected,
    Final,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Phrase {
    pub definition: String,
    pub modifier: Modifier,
    pub predicate: Predicate,
    pub omitted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub description: String,
    pub modifier: Modifier,
    pub phrases: Vec<Phrase>,
    pub omitted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rulebook {
    pub uuid: String,
    pub rules: Vec<Rule>,
}
impl Rulebook {
    pub fn validate(&self) -> Result<()> {
        ensure(
            !self.uuid.is_empty() && !self.rules.is_empty(),
            "rulebook needs UUID and zeroth rule",
        )?;
        ensure(
            self.rules[0].modifier >= Modifier::Protected && !self.rules[0].omitted,
            "zeroth rule must be protected",
        )?;
        for rule in &self.rules {
            ensure(
                !rule.description.is_empty() && !rule.phrases.is_empty(),
                "rule needs description and explicit predicates",
            )?;
            ensure(
                !rule.omitted || rule.modifier == Modifier::Public,
                "mandatory rule omitted",
            )?;
            for (i, phrase) in rule.phrases.iter().enumerate() {
                ensure(
                    rule.description.contains(&format!("_[{i}]")),
                    "missing indexed phrase marker",
                )?;
                ensure(
                    !phrase.omitted || phrase.modifier == Modifier::Public,
                    "mandatory phrase omitted",
                )?;
            }
        }
        Ok(())
    }
    pub fn rule_urns(&self) -> Vec<String> {
        self.rules
            .iter()
            .enumerate()
            .map(|(i, r)| {
                format!(
                    "urn:rule:{i}:{}:{}:{}",
                    match r.modifier {
                        Modifier::Public => "public",
                        Modifier::Protected => "protected",
                        Modifier::Final => "final",
                    },
                    constitutive_action::v1::sha256_hex(r.description.as_bytes()),
                    self.uuid
                )
            })
            .collect()
    }
    pub fn urn(&self) -> String {
        format!(
            "urn:rulebook:{}",
            constitutive_action::v1::sha256_hex(self.rule_urns().concat().as_bytes())
        )
    }
    pub fn hash(&self) -> String {
        digest(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Level {
    Document,
    Lead,
    Moderator,
    User,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulePatch {
    pub modifier: Option<Modifier>,
    pub omit: bool,
    pub phrases: BTreeMap<usize, Phrase>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interpretation {
    pub rulebook_ref: String,
    pub parent_ref: String,
    pub author_urn: String,
    pub level: Level,
    pub patches: BTreeMap<usize, RulePatch>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Resolved {
    pub rulebook_ref: String,
    pub interpretation_ref: String,
    pub level: Level,
    pub rules: Vec<Rule>,
    pub trail: Vec<String>,
}
impl Resolved {
    pub fn base(book: &Rulebook) -> Result<Self> {
        book.validate()?;
        Ok(Self {
            rulebook_ref: book.hash(),
            interpretation_ref: book.hash(),
            level: Level::Document,
            rules: book.rules.clone(),
            trail: vec![book.hash()],
        })
    }
    pub fn extend(&self, child: &Interpretation) -> Result<Self> {
        ensure(
            child.rulebook_ref == self.rulebook_ref && child.parent_ref == self.interpretation_ref,
            "interpretation parent mismatch",
        )?;
        ensure(
            child.author_urn.starts_with("urn:") && child.level > self.level,
            "invalid interpretation hierarchy",
        )?;
        let mut result = self.clone();
        for (index, patch) in &child.patches {
            let rule = result.rules.get_mut(*index).ok_or("unknown rule index")?;
            ensure(!rule.omitted, "cannot revive an omitted inherited rule")?;
            if patch.omit {
                ensure(
                    rule.modifier == Modifier::Public,
                    "cannot omit protected/final rule",
                )?;
                rule.omitted = true;
            }
            if let Some(modifier) = patch.modifier {
                ensure(
                    modifier >= rule.modifier,
                    "cannot weaken inherited modifier",
                )?;
                rule.modifier = modifier;
            }
            for (i, phrase) in &patch.phrases {
                let previous = rule.phrases.get_mut(*i).ok_or("unknown phrase index")?;
                ensure(!previous.omitted, "cannot revive an omitted phrase")?;
                ensure(
                    previous.modifier != Modifier::Final || previous == phrase,
                    "cannot reinterpret final phrase",
                )?;
                ensure(
                    phrase.modifier >= previous.modifier,
                    "cannot weaken phrase modifier",
                )?;
                ensure(
                    !phrase.omitted || previous.modifier == Modifier::Public,
                    "cannot omit mandatory phrase",
                )?;
                *previous = phrase.clone();
            }
        }
        result.interpretation_ref = digest(child);
        result.level = child.level;
        result.trail.push(result.interpretation_ref.clone());
        Ok(result)
    }
    pub fn evaluate(&self, facts: &Facts) -> Verdict {
        Predicate::All {
            predicates: self
                .rules
                .iter()
                .filter(|r| !r.omitted)
                .flat_map(|r| {
                    r.phrases
                        .iter()
                        .filter(|p| !p.omitted)
                        .map(|p| p.predicate.clone())
                })
                .collect(),
        }
        .evaluate(facts)
    }
}
