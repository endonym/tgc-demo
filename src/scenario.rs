//! Product narration and fixtures. Activity-specific vocabulary belongs here.
use crate::{
    Result, audit, canonical, digest, ensure,
    identity::{Issuers, Moderator, Participant},
    protocol::*,
    rules::*,
};
use constitutive_action::v1::{ActionIntent, DecisionKind};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::Path,
    time::Instant,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Composition {
    Reuse,
    Fork,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub topology: Topology,
    pub composition: Composition,
    pub downstream: RecipientPolicy,
    pub newcomer_seed: String,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            topology: Topology::Constitutive,
            composition: Composition::Fork,
            downstream: RecipientPolicy::Unresolved,
            newcomer_seed: "unfamiliar-third-party".into(),
        }
    }
}

pub fn facts(venue: &str, amount: i64) -> Facts {
    BTreeMap::from([
        ("venue".into(), json!(venue)),
        ("amount".into(), json!(amount)),
        ("instrument".into(), json!("BOND-01")),
        ("counterparty_class".into(), json!("qualified")),
        ("action_type".into(), json!("settle")),
        ("capital_attestation".into(), json!(true)),
        ("bond".into(), json!(100)),
        ("urgent".into(), json!(true)),
    ])
}
pub fn admission() -> Predicate {
    Predicate::All {
        predicates: vec![
            Predicate::Equal {
                field: "capital_attestation".into(),
                value: json!(true),
            },
            Predicate::AtLeast {
                field: "bond".into(),
                value: 100,
            },
        ],
    }
}
fn scope(maximum: i64) -> Predicate {
    Predicate::All {
        predicates: vec![
            Predicate::OneOf {
                field: "action_type".into(),
                values: vec![json!("confirm"), json!("settle")],
            },
            Predicate::Equal {
                field: "instrument".into(),
                value: json!("BOND-01"),
            },
            Predicate::Equal {
                field: "counterparty_class".into(),
                value: json!("qualified"),
            },
            Predicate::Equal {
                field: "venue".into(),
                value: json!("venue-A"),
            },
            Predicate::AtMost {
                field: "amount".into(),
                value: maximum,
            },
            Predicate::AtMost {
                field: "host.count".into(),
                value: 100,
            },
            Predicate::AtLeast {
                field: "host.tick".into(),
                value: 10,
            },
            Predicate::AtMost {
                field: "host.tick".into(),
                value: 30,
            },
        ],
    }
}

pub fn rulebook() -> Rulebook {
    Rulebook {
        uuid: "demo-activity-rules-v1".into(),
        rules: vec![Rule {
            description: "Only act with _[0]bounded exposure_ and _[1]understood conditions_."
                .into(),
            modifier: Modifier::Final,
            phrases: vec![
                Phrase {
                    definition: "Amount at most 1000 units".into(),
                    modifier: Modifier::Protected,
                    predicate: Predicate::AtMost {
                        field: "amount".into(),
                        value: 1000,
                    },
                    omitted: false,
                },
                Phrase {
                    definition: "Positive amount".into(),
                    modifier: Modifier::Final,
                    predicate: Predicate::AtLeast {
                        field: "amount".into(),
                        value: 1,
                    },
                    omitted: false,
                },
            ],
            omitted: false,
        }],
    }
}

pub struct Fixture {
    pub issuers: Issuers,
    pub principal: Participant,
    pub counterparty: Participant,
    pub agent: Participant,
    pub officer: Participant,
    pub path: Commitment,
    pub discovery: Discovery,
    pub leads: BTreeSet<String>,
    pub newcomer_moderator: String,
}
impl Fixture {
    pub fn new() -> Result<Self> {
        let book = rulebook();
        let book_ref = book.hash();
        let lead_urn = format!(
            "urn:rulebook:lead:demo:{}",
            book.urn().trim_start_matches("urn:rulebook:")
        );
        let moderators: Vec<_> = ["one", "two"]
            .into_iter()
            .map(|name| Moderator {
                urn: format!("urn:rulebook:lead:demo:moderator:{name}:{}", book_ref),
                lead_urn: lead_urn.clone(),
                rulebook_ref: book_ref.clone(),
                admission: admission(),
            })
            .collect();
        let mut issuers = Issuers::new(moderators.clone())?;
        let principal = issuers.issue(
            &moderators[0].urn,
            &facts("venue-A", 750),
            "principal",
            1000,
        )?;
        let counterparty = issuers.issue(
            &moderators[0].urn,
            &facts("venue-A", 750),
            "counterparty",
            1000,
        )?;
        let agent = issuers.issue(&moderators[0].urn, &facts("venue-A", 750), "agent", 1000)?;
        let officer = issuers.issue(&moderators[0].urn, &facts("venue-A", 750), "officer", 1000)?;
        let lead = Interpretation {
            rulebook_ref: book_ref.clone(),
            parent_ref: book_ref.clone(),
            author_urn: lead_urn.clone(),
            level: Level::Lead,
            patches: BTreeMap::new(),
        };
        let moderator = Interpretation {
            rulebook_ref: book_ref.clone(),
            parent_ref: digest(&lead),
            author_urn: moderators[0].urn.clone(),
            level: Level::Moderator,
            patches: BTreeMap::new(),
        };
        let path = Commitment {
            context: "activity:demonstration".into(),
            rulebook_ref: book_ref.clone(),
            interpretation_ref: digest(&moderator),
            rule_payload: book.rules.clone(),
            owners: vec![
                principal.seat("activity:demonstration"),
                counterparty.seat("activity:demonstration"),
            ],
            scope: scope(800),
            conditions: admission(),
            composition: admission(),
            exception: Predicate::All {
                predicates: vec![
                    Predicate::OneOf {
                        field: "action_type".into(),
                        values: vec![json!("confirm"), json!("settle")],
                    },
                    Predicate::Equal {
                        field: "urgent".into(),
                        value: json!(true),
                    },
                    Predicate::Equal {
                        field: "venue".into(),
                        value: json!("venue-B"),
                    },
                    Predicate::AtMost {
                        field: "amount".into(),
                        value: 800,
                    },
                ],
            },
            approver_seat: officer.seat("activity:demonstration"),
            delegation: Some(Delegation {
                principal_seat: principal.seat("activity:demonstration"),
                delegate_seat: agent.seat("activity:demonstration"),
                scope: scope(800),
            }),
            payoffs: Payoffs {
                on_exceed_scope: "payoff:exception-producer-accountable".into(),
                on_violation: "payoff:proof-producer-accountable".into(),
            },
            window: [0, 100],
            parent_ref: None,
        };
        let discovery = Discovery {
            rulebooks: BTreeMap::from([(book_ref, book)]),
            interpretations: BTreeMap::from([
                (digest(&lead), lead),
                (digest(&moderator), moderator),
            ]),
            commitments: BTreeMap::new(),
            seats: BTreeMap::new(),
            moderators,
            stubs: vec![],
            revocation_epoch: 0,
            revocation_ref: issuers.revocation_ref(),
        };
        let newcomer_moderator = discovery.moderators[1].urn.clone();
        Ok(Self {
            issuers,
            principal,
            counterparty,
            agent,
            officer,
            path,
            discovery,
            leads: BTreeSet::from([lead_urn]),
            newcomer_moderator,
        })
    }
    pub fn field(&self, root: &Path, topology: Topology) -> Result<Field> {
        Field::new(
            root,
            topology,
            self.discovery.clone(),
            self.leads.clone(),
            self.principal.seat("activity:demonstration"),
        )
    }
}

pub fn governance_action(id: &str, actor: &Participant, change: &Change) -> ActionIntent {
    intent(
        id,
        &actor.seat(id),
        &actor.seat(id),
        &format!("govern:{}", change.target),
        "activity:governance",
        &change.verb,
        &change.target,
        change,
    )
}
pub fn endorse(
    actor: &Participant,
    action: &ActionIntent,
    payoff: &str,
    epoch: u64,
) -> Endorsement {
    Endorsement {
        scoped_seat: actor.seat("activity:demonstration"),
        proof: actor.prove(&action.proposal_id, &action.fingerprint(), payoff, epoch),
    }
}
pub fn govern(
    field: &mut Field,
    fixture: &Fixture,
    scene: &Scene,
    id: &str,
    change: Change,
    signers: &[&Participant],
) -> Result<DecisionKind> {
    let action = governance_action(id, &fixture.principal, &change);
    let proof = fixture.principal.prove(
        id,
        &action.fingerprint(),
        "payoff:governance",
        fixture.issuers.epoch(),
    );
    let endorsements: Vec<_> = signers
        .iter()
        .map(|p| endorse(p, &action, "payoff:governance", fixture.issuers.epoch()))
        .collect();
    let result = fixture.issuers.verify(
        &proof,
        &fixture.leads,
        &fixture.path.rulebook_ref,
        &action.proposal_id,
        &action.fingerprint(),
        "payoff:governance",
        20,
    );
    field.event(scene,"participant_validation",json!({"proposal_id":action.proposal_id,"result":result,"verifier":"participant-local","governance":true}))?;
    field.govern(scene, &fixture.issuers, &action, &proof, &endorsements, 20)
}

/// Participant-side preflight uses public material before submission. An agent
/// may still submit a bad proposal; recipient verification independently gates it.
fn submit(
    field: &mut Field,
    scene: &Scene,
    issuers: &Issuers,
    instruction: &Instruction,
    tick: u64,
) -> Result<DecisionKind> {
    let d = field.discovery();
    let path = d
        .commitments
        .get(&instruction.path_ref)
        .ok_or("missing public path")?;
    let leads = d.moderators.iter().map(|m| m.lead_urn.clone()).collect();
    let payoff = if instruction.route == Route::Exception {
        &path.payoffs.on_exceed_scope
    } else {
        &path.payoffs.on_violation
    };
    let result = issuers.verify(
        &instruction.proof,
        &leads,
        &path.rulebook_ref,
        &instruction.intent.proposal_id,
        &instruction.intent.fingerprint(),
        payoff,
        tick,
    );
    field.event(scene,"participant_validation",json!({"proposal_id":instruction.intent.proposal_id,"result":result,"verifier":"participant-local","proof_ref":digest(&instruction.proof)}))?;
    field.execute(scene, issuers, instruction, tick)
}
pub fn change(verb: &str, target: &str, candidate: Option<Commitment>) -> Change {
    Change {
        verb: verb.into(),
        target: target.into(),
        candidate,
        queue_id: None,
        recipient_policy: None,
        interpretation: None,
    }
}
pub fn instruction(
    id: &str,
    actor: &Participant,
    path: &Commitment,
    route: Route,
    facts: &Facts,
    epoch: u64,
) -> Instruction {
    let principal = if route == Route::Ordinary {
        path.delegation
            .as_ref()
            .map(|d| d.principal_seat.clone())
            .unwrap_or_else(|| actor.seat(id))
    } else {
        actor.seat(id)
    };
    let payload = Payload {
        facts: facts.clone(),
        path_ref: path.reference(),
        interpretation_ref: path.interpretation_ref.clone(),
        rule_payload: path.rule_payload.clone(),
        route,
        upstream_ref: None,
    };
    let action = intent(
        id,
        &actor.seat(id),
        &principal,
        &format!("{}:{route:?}", path.reference()),
        &path.context,
        "apply",
        "endpoint:existing-rail",
        &payload,
    );
    let payoff = if route == Route::Exception {
        &path.payoffs.on_exceed_scope
    } else {
        &path.payoffs.on_violation
    };
    let proof = actor.prove(id, &action.fingerprint(), payoff, epoch);
    Instruction {
        intent: action,
        path_ref: path.reference(),
        interpretation_ref: path.interpretation_ref.clone(),
        rule_payload: path.rule_payload.clone(),
        route,
        proof,
        endorsements: vec![],
        delegate_kind: if route == Route::Ordinary {
            "agent"
        } else {
            "person"
        }
        .into(),
        upstream: None,
    }
}

pub fn rebind(instruction: &mut Instruction, actor: &Participant, epoch: u64) -> Result<()> {
    let payload: Payload = serde_json::from_slice(&instruction.intent.effect.canonical_payload)?;
    instruction.intent.effect.canonical_payload = canonical(&instruction.payload(payload.facts));
    instruction.proof = actor.prove(
        &instruction.intent.proposal_id,
        &instruction.intent.fingerprint(),
        &instruction.proof.payoff_ref,
        epoch,
    );
    instruction.endorsements.clear();
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Opportunity {
    pub venue: String,
    pub funding_cost: i64,
    pub fail_basis_points: i64,
    pub expected_cost: i64,
}
pub fn opportunities() -> Vec<Opportunity> {
    [
        ("venue-A", 80, 50),
        ("venue-B", 20, 5),
        ("venue-C", 120, 100),
    ]
    .into_iter()
    .map(|(v, c, f)| Opportunity {
        venue: v.into(),
        funding_cost: c,
        fail_basis_points: f,
        expected_cost: c * 10000 + f * 1000,
    })
    .collect()
}
pub fn optimal_shortcut() -> Opportunity {
    opportunities()
        .into_iter()
        .min_by_key(|x| (x.expected_cost, x.venue.clone()))
        .unwrap()
}

pub fn constitute(field: &mut Field, f: &Fixture) -> Result<()> {
    let scene = Scene::new("I", "constitution");
    field.event(&scene, "terms_chosen", json!({"principal_offer_amount_max":1000,"counterparty_offer_amount_max":800,"agreed_amount_max":800,"scope":f.path.scope,"exception":f.path.exception,"authority_source":field.topology,"rails":"existing messaging and ledger mocks; no new transport"}))?;
    let target = f.path.reference();
    let signers = [&f.principal, &f.counterparty];
    expect(
        govern(
            field,
            f,
            &scene,
            "path-propose",
            change("propose", &target, Some(f.path.clone())),
            &signers,
        )?,
        DecisionKind::Permitted,
    )?;
    expect(
        govern(
            field,
            f,
            &scene,
            "path-accept",
            change("accept", &target, None),
            &signers,
        )?,
        DecisionKind::Permitted,
    )?;
    expect(
        govern(
            field,
            f,
            &scene,
            "path-publish",
            change("publish", &target, None),
            &signers,
        )?,
        DecisionKind::Permitted,
    )?;
    Ok(())
}
fn expect(actual: DecisionKind, expected: DecisionKind) -> Result<()> {
    ensure(
        actual == expected,
        &format!("expected {expected:?}, got {actual:?}"),
    )
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    pub config: Config,
    pub primary_metrics: Value,
    pub peer_metrics: Value,
    pub semantic_hash: String,
    pub all_four_outcomes: bool,
    pub pending_queue_items: usize,
    pub finale: String,
}

pub fn run(root: &Path, config: Config) -> Result<Report> {
    ensure(
        !root.join("primary/state.json").exists(),
        "run directory already contains a run; use a fresh directory or inspect/recover it",
    )?;
    fs::create_dir_all(root)?;
    let mut f = Fixture::new()?;
    let mut field = f.field(&root.join("primary"), config.topology)?;
    for book in field.discovery().rulebooks.values() {
        field.host().object(book)?;
    }
    for interpretation in field.discovery().interpretations.values() {
        field.host().object(interpretation)?;
    }
    constitute(&mut field, &f)?;
    let mut confirmation_facts = facts("venue-A", 750);
    confirmation_facts.insert("action_type".into(), json!("confirm"));
    let confirmation = instruction(
        "ordinary-confirm",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &confirmation_facts,
        f.issuers.epoch(),
    );
    expect(
        submit(
            &mut field,
            &Scene::new("I", "1a"),
            &f.issuers,
            &confirmation,
            20,
        )?,
        DecisionKind::Permitted,
    )?;
    let ordinary = instruction(
        "ordinary",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &facts("venue-A", 750),
        f.issuers.epoch(),
    );
    expect(
        submit(
            &mut field,
            &Scene::new("I", "1a"),
            &f.issuers,
            &ordinary,
            20,
        )?,
        DecisionKind::Permitted,
    )?;

    let temptation = optimal_shortcut();
    field.event(&Scene::new("II", "2a"), "agent_optimization", json!({"objective":"minimize funding cost plus expected fail cost","candidates":opportunities(),"chosen":temptation,"mandate_venue":"venue-A"}))?;
    let shortcut = instruction(
        "temptation",
        &f.agent,
        &f.path,
        Route::Ordinary,
        &facts(&temptation.venue, 750),
        f.issuers.epoch(),
    );
    expect(
        submit(
            &mut field,
            &Scene::new("II", "2a"),
            &f.issuers,
            &shortcut,
            20,
        )?,
        DecisionKind::Prevented,
    )?;

    let mut exception = instruction(
        "exception",
        &f.officer,
        &f.path,
        Route::Exception,
        &facts("venue-B", 750),
        f.issuers.epoch(),
    );
    field.event(&Scene::new("II", "2b"), "override_requested", json!({"proposal_id":exception.intent.proposal_id,"prior_prevented":"temptation","distinct_authority":exception.intent.authority_id}))?;
    expect(
        submit(
            &mut field,
            &Scene::new("II", "2b"),
            &f.issuers,
            &exception,
            20,
        )?,
        DecisionKind::DecisionRequired,
    )?;
    exception.endorsements.push(endorse(
        &f.officer,
        &exception.intent,
        &f.path.payoffs.on_exceed_scope,
        f.issuers.epoch(),
    ));
    expect(
        submit(
            &mut field,
            &Scene::new("II", "2b"),
            &f.issuers,
            &exception,
            20,
        )?,
        DecisionKind::Permitted,
    )?;

    // Arrival starts before public reads and issuance. This actor is absent from
    // all founding objects; it receives only its own facts and published state.
    let arrival = Instant::now();
    let scene = Scene::new("III", "3a");
    field.event(
        &scene,
        "arrival",
        json!({"source":"public-information-space","prior_registration":false}),
    )?;
    let discovery = field.discovery();
    let stub = discovery.stubs.first().ok_or("no published stub")?;
    let discovered = discovery.inspect(stub)?.clone();
    field.event(&scene, "discovery_read", json!({"stub":stub,"governance_hash":stub.governance_hash(),"interpretation_trail":discovery.resolve(&stub.rulebook_id,&stub.rule_interpretation_hash)?.trail,"revocation_epoch":discovery.revocation_epoch}))?;
    let own_facts = facts("venue-A", 750);
    let selected = discovery
        .moderators
        .iter()
        .filter(|m| {
            m.lead_urn == stub.lead_id
                && m.rulebook_ref == stub.rulebook_id
                && m.admission.evaluate(&own_facts) == Verdict::Pass
        })
        .min_by_key(|m| (m.urn == stub.mod_id, m.urn.clone()))
        .ok_or("no compatible published moderator")?;
    let newcomer = f
        .issuers
        .issue(&selected.urn, &own_facts, &config.newcomer_seed, 1000)?;
    field.event(&scene, "credential_issued", json!({"moderator_urn":selected.urn,"criteria":selected.admission,"automatic":true,"participant_approval":false}))?;
    let arrival_action = instruction(
        "newcomer-first",
        &newcomer,
        &discovered,
        Route::Composition,
        &facts("venue-A", 750),
        f.issuers.epoch(),
    );
    expect(
        submit(&mut field, &scene, &f.issuers, &arrival_action, 20)?,
        DecisionKind::Permitted,
    )?;
    let composition_duration = field
        .last_confirmation()
        .ok_or("missing confirmation timing")?
        .duration_since(arrival);
    field.measured_event(&scene, "composition_complete", json!({"proposal_id":arrival_action.intent.proposal_id,"accountable_proof":digest(&arrival_action.proof),"registered":false}), composition_duration.as_nanos())?;
    f.issuers.save_private(&root.join("private/issuers.json"))?;

    let mut active_path = discovered;
    if config.composition == Composition::Fork {
        let scene = Scene::new("III", "3b");
        let fork = Interpretation {
            rulebook_ref: active_path.rulebook_ref.clone(),
            parent_ref: active_path.interpretation_ref.clone(),
            author_urn: newcomer.interpretation_author(&active_path.rulebook_ref),
            level: Level::User,
            patches: BTreeMap::from([(
                0,
                RulePatch {
                    modifier: None,
                    omit: false,
                    phrases: BTreeMap::from([(
                        0,
                        Phrase {
                            definition: "Amount at most 700 units".into(),
                            modifier: Modifier::Protected,
                            predicate: Predicate::AtMost {
                                field: "amount".into(),
                                value: 700,
                            },
                            omitted: false,
                        },
                    )]),
                },
            )]),
        };
        let fork_ref = digest(&fork);
        let mut fork_change = change("fork", &active_path.reference(), None);
        fork_change.interpretation = Some(fork);
        let fork_action = governance_action("newcomer-fork", &newcomer, &fork_change);
        let fork_proof = newcomer.prove(
            "newcomer-fork",
            &fork_action.fingerprint(),
            "payoff:governance",
            f.issuers.epoch(),
        );
        let preflight = f.issuers.verify(
            &fork_proof,
            &f.leads,
            &active_path.rulebook_ref,
            &fork_action.proposal_id,
            &fork_action.fingerprint(),
            "payoff:governance",
            20,
        );
        field.event(&scene,"participant_validation",json!({"proposal_id":fork_action.proposal_id,"result":preflight,"verifier":"participant-local","governance":true}))?;
        expect(
            field.govern(&scene, &f.issuers, &fork_action, &fork_proof, &[], 20)?,
            DecisionKind::Permitted,
        )?;
        let mut collision = instruction(
            "fork-collision",
            &newcomer,
            &active_path,
            Route::Composition,
            &facts("venue-A", 750),
            f.issuers.epoch(),
        );
        collision.interpretation_ref = fork_ref.clone();
        collision.rule_payload = field
            .discovery()
            .resolve(&active_path.rulebook_ref, &fork_ref)?
            .rules;
        rebind(&mut collision, &newcomer, f.issuers.epoch())?;
        expect(
            submit(&mut field, &scene, &f.issuers, &collision, 20)?,
            DecisionKind::Indeterminate,
        )?;
        for verb in ["contest", "escalate"] {
            expect(
                govern(
                    &mut field,
                    &f,
                    &scene,
                    &format!("fork-{verb}"),
                    change(verb, &active_path.reference(), None),
                    &[],
                )?,
                DecisionKind::Permitted,
            )?;
        }
        let signers = [&f.principal, &f.counterparty];
        let mut resolution = change("resolve", &active_path.reference(), None);
        resolution.queue_id = Some("fork-collision".into());
        expect(
            govern(&mut field, &f, &scene, "fork-resolve", resolution, &signers)?,
            DecisionKind::Permitted,
        )?;
        let mut promoted = active_path.clone();
        promoted.parent_ref = Some(active_path.reference());
        promoted.interpretation_ref = fork_ref;
        promoted.rule_payload = field
            .discovery()
            .resolve(&promoted.rulebook_ref, &promoted.interpretation_ref)?
            .rules;
        promoted.scope = scope(700);
        let mut promotion = change("promote", &active_path.reference(), Some(promoted.clone()));
        promotion.queue_id = Some("fork-collision".into());
        expect(
            govern(&mut field, &f, &scene, "fork-promote", promotion, &signers)?,
            DecisionKind::Permitted,
        )?;
        active_path = promoted;
        let composed = instruction(
            "fork-composed",
            &newcomer,
            &active_path,
            Route::Composition,
            &facts("venue-A", 650),
            f.issuers.epoch(),
        );
        expect(
            submit(&mut field, &scene, &f.issuers, &composed, 20)?,
            DecisionKind::Permitted,
        )?;
    } else {
        field.event(
            &Scene::new("III", "3b"),
            "path_reused",
            json!({"path_ref":active_path.reference(),"new_membership":false}),
        )?;
    }

    let mut peer = Field::peer(
        &root.join("peer"),
        config.topology,
        field.discovery(),
        f.leads.clone(),
        f.principal.seat("activity:demonstration"),
        config.downstream,
    )?;
    let scene = Scene::new("III", "3c");
    peer.event(
        &scene,
        "independent_recipient",
        json!({"origin_container_access":false,"transport":"none","policy":config.downstream}),
    )?;
    let mut forwarded = instruction(
        "downstream",
        &f.counterparty,
        &active_path,
        Route::Composition,
        &facts("venue-A", 650),
        f.issuers.epoch(),
    );
    forwarded.upstream = Some(Box::new(exception));
    rebind(&mut forwarded, &f.counterparty, f.issuers.epoch())?;
    let expected = match config.downstream {
        RecipientPolicy::Refuse => DecisionKind::Prevented,
        RecipientPolicy::Honour => DecisionKind::Permitted,
        RecipientPolicy::Unresolved => DecisionKind::Indeterminate,
    };
    expect(
        submit(&mut peer, &scene, &f.issuers, &forwarded, 20)?,
        expected,
    )?;
    if matches!(config.downstream, RecipientPolicy::Unresolved) {
        let mut resolution = change("resolve", &active_path.reference(), None);
        resolution.queue_id = Some("downstream".into());
        resolution.recipient_policy = Some(RecipientPolicy::Honour);
        expect(
            govern(
                &mut peer,
                &f,
                &scene,
                "downstream-resolution",
                resolution,
                &[&f.principal, &f.counterparty],
            )?,
            DecisionKind::Permitted,
        )?;
        expect(
            submit(&mut peer, &scene, &f.issuers, &forwarded, 20)?,
            DecisionKind::Permitted,
        )?;
    }
    let finale = "Nobody onboarded them. They read the stubs.";
    field.event(&Scene::new("III", "close"), "finale", json!({"text":finale,"meaning":"no discretionary participant-specific onboarding; automated credential issuance is logged"}))?;
    let primary = field.host().state()?;
    let downstream = peer.host().state()?;
    audit::verify_transcript(&primary.events)?;
    audit::verify_transcript(&downstream.events)?;
    export_events(&root.join("events.jsonl"), &primary.events)?;
    export_events(&root.join("peer-events.jsonl"), &downstream.events)?;
    fs::write(
        root.join("discovery.json"),
        serde_json::to_vec_pretty(&field.discovery())?,
    )?;
    let semantic: Vec<_> = primary
        .events
        .iter()
        .chain(&downstream.events)
        .map(|e| e.semantic())
        .collect();
    fs::write(
        root.join("semantic.json"),
        serde_json::to_vec_pretty(&semantic)?,
    )?;
    let kinds: BTreeSet<_> = primary
        .events
        .iter()
        .chain(&downstream.events)
        .filter_map(|e| e.outcome.clone())
        .collect();
    let report = Report {
        config,
        primary_metrics: audit::metrics(&primary.events),
        peer_metrics: audit::metrics(&downstream.events),
        semantic_hash: digest(&semantic),
        all_four_outcomes: [
            "Permitted",
            "Prevented",
            "DecisionRequired",
            "Indeterminate",
        ]
        .iter()
        .all(|k| kinds.contains(*k)),
        pending_queue_items: primary
            .queue
            .values()
            .chain(downstream.queue.values())
            .filter(|q| q.status == "pending")
            .count(),
        finale: finale.into(),
    };
    fs::write(
        root.join("report.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(report)
}

pub fn export_events(path: &Path, events: &[audit::Event]) -> Result<()> {
    let mut file = fs::File::create(path)?;
    for event in events {
        file.write_all(&canonical(event))?;
        file.write_all(b"\n")?;
    }
    Ok(())
}
