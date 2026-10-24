#![allow(dead_code)]
//! Shared synthetic workshop bootstrap. No settlement scenario dependency.
use constitutive_action::v1::DecisionKind;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};
use tgc_demo::{Result, authoring, digest, identity::*, protocol::*, rules::*};

pub fn facts(units: i64) -> Facts {
    BTreeMap::from([
        ("units".into(), json!(units)),
        ("qualified".into(), json!(true)),
    ])
}
pub fn admission() -> Predicate {
    Predicate::Equal {
        field: "qualified".into(),
        value: json!(true),
    }
}
pub fn book() -> Rulebook {
    Rulebook {
        uuid: "workshop-v1".into(),
        rules: vec![Rule {
            description: "Use _[0]bounded resources_ with _[1]positive units_.".into(),
            modifier: Modifier::Final,
            omitted: false,
            phrases: vec![
                Phrase {
                    definition: "At most 10 units".into(),
                    modifier: Modifier::Protected,
                    predicate: Predicate::AtMost {
                        field: "units".into(),
                        value: 10,
                    },
                    omitted: false,
                },
                Phrase {
                    definition: "At least one unit".into(),
                    modifier: Modifier::Final,
                    predicate: Predicate::AtLeast {
                        field: "units".into(),
                        value: 1,
                    },
                    omitted: false,
                },
            ],
        }],
    }
}
pub struct Workshop {
    pub issuers: Issuers,
    pub owner: Participant,
    pub partner: Participant,
    pub agent: Participant,
    pub officer: Participant,
    pub path: Commitment,
    pub field: Field,
    pub leads: BTreeSet<String>,
    pub root: PathBuf,
}
impl Workshop {
    pub fn new(name: &str) -> Result<Self> {
        let root = std::env::temp_dir().join(format!("tgc-example-{name}-{}", std::process::id()));
        tgc_demo::ensure(!root.exists(), "example directory already exists")?;
        let book = book();
        let book_ref = book.hash();
        let moderator = Moderator {
            urn: "urn:workshop:moderator:one".into(),
            lead_urn: "urn:workshop:lead".into(),
            rulebook_ref: book_ref.clone(),
            admission: admission(),
        };
        let mut issuers = Issuers::new(vec![moderator.clone()])?;
        let owner = issuers.issue(&moderator.urn, &facts(2), "owner-fixture", 100)?;
        let partner = issuers.issue(&moderator.urn, &facts(2), "partner-fixture", 100)?;
        let agent = issuers.issue(&moderator.urn, &facts(2), "agent-fixture", 100)?;
        let officer = issuers.issue(&moderator.urn, &facts(2), "officer-fixture", 100)?;
        let lead = Interpretation {
            rulebook_ref: book_ref.clone(),
            parent_ref: book_ref.clone(),
            author_urn: moderator.lead_urn.clone(),
            level: Level::Lead,
            patches: BTreeMap::new(),
        };
        let interpretation = Interpretation {
            rulebook_ref: book_ref.clone(),
            parent_ref: digest(&lead),
            author_urn: moderator.urn.clone(),
            level: Level::Moderator,
            patches: BTreeMap::new(),
        };
        let scope = Predicate::AtMost {
            field: "units".into(),
            value: 5,
        };
        let context = "activity:workshop";
        let path = Commitment {
            context: context.into(),
            rulebook_ref: book_ref.clone(),
            interpretation_ref: digest(&interpretation),
            rule_payload: book.rules.clone(),
            owners: vec![owner.seat(context), partner.seat(context)],
            scope: scope.clone(),
            conditions: admission(),
            composition: admission(),
            exception: Predicate::AtMost {
                field: "units".into(),
                value: 10,
            },
            approver_seat: officer.seat(context),
            delegation: Some(Delegation {
                principal_seat: owner.seat(context),
                delegate_seat: agent.seat(context),
                scope,
            }),
            payoffs: Payoffs {
                on_exceed_scope: "payoff:exception-producer".into(),
                on_violation: "payoff:action-producer".into(),
            },
            window: [0, 100],
            parent_ref: None,
        };
        let discovery = Discovery {
            rulebooks: BTreeMap::from([(book_ref, book)]),
            interpretations: BTreeMap::from([
                (digest(&lead), lead),
                (digest(&interpretation), interpretation),
            ]),
            commitments: BTreeMap::new(),
            seats: BTreeMap::new(),
            moderators: vec![moderator.clone()],
            stubs: vec![],
            revocation_epoch: 0,
            revocation_ref: issuers.revocation_ref(),
        };
        let leads = BTreeSet::from([moderator.lead_urn]);
        let field = Field::new(
            &root,
            Topology::Constitutive,
            discovery,
            leads.clone(),
            owner.seat(context),
        )?;
        let mut w = Self {
            issuers,
            owner,
            partner,
            agent,
            officer,
            path,
            field,
            leads,
            root,
        };
        for verb in ["propose", "accept", "publish"] {
            let change = Change {
                verb: verb.into(),
                target: w.path.reference(),
                candidate: if verb == "propose" {
                    Some(w.path.clone())
                } else {
                    None
                },
                queue_id: None,
                recipient_policy: None,
                interpretation: None,
            };
            let id = format!("path-{verb}");
            let action = intent(
                &id,
                &w.owner.seat(&id),
                &w.owner.seat(&id),
                &format!("govern:{}", change.target),
                "activity:governance",
                verb,
                &change.target,
                &change,
            );
            let proof = w
                .owner
                .prove(&id, &action.fingerprint(), "payoff:governance", 0);
            let consents = [&w.owner, &w.partner]
                .map(|p| authoring::endorse(p, &action, context, "payoff:governance", 0));
            assert_eq!(
                w.field
                    .govern(&scene(), &w.issuers, &action, &proof, &consents, 1)?,
                DecisionKind::Permitted
            );
        }
        Ok(w)
    }
    pub fn summary(&self) -> Result<Value> {
        let s = self.field.host().state()?;
        Ok(
            json!({"decisions":s.events.iter().filter(|e|e.kind=="decision").map(|e|json!({"proposal":e.data["intent"]["proposal_id"],"decision":e.data["decision"],"protocol_outcome":e.outcome})).collect::<Vec<_>>(),"occurrences":self.field.host().occurrences()?,"records":s.records.iter().map(|(id,r)|json!({"proposal":id,"ticket":r.ticket,"receipt":r.receipt})).collect::<Vec<_>>() }),
        )
    }
}
impl Drop for Workshop {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
pub fn scene() -> Scene {
    Scene::new("workshop", "example")
}
pub fn output(value: Value) {
    println!("{}", serde_json::to_string_pretty(&value).unwrap());
}
