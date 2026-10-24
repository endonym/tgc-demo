//! Rederive the container's local calculations. PoH verification results and
//! authenticated seat ownership remain supplied proof-system claims.
use super::Event;
use crate::{
    Result, canonical, digest, ensure,
    protocol::{Change, Commitment, Discovery, Instruction, Payload, RecipientPolicy, Route},
    rules::{Facts, Verdict},
};
use constitutive_action::v1::{ActionIntent, CheckResult, ConditionPolicy, EvaluationSnapshot};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

struct Checks<'a> {
    snapshot: &'a EvaluationSnapshot,
    objects: &'a Value,
}
impl Checks<'_> {
    fn content(&self, name: &str) -> Result<&Value> {
        let assessments: Vec<_> = self
            .snapshot
            .assessments
            .iter()
            .filter(|a| a.condition_id == name)
            .collect();
        ensure(
            assessments.len() == 1,
            &format!("missing or duplicate local assessment: {name}"),
        )?;
        let assessment = assessments[0];
        ensure(
            assessment.version == 1 && assessment.evidence_ids.len() == 1,
            "invalid local assessment evidence binding",
        )?;
        let evidence: Vec<_> = self
            .snapshot
            .evidence
            .iter()
            .filter(|e| e.evidence_id == assessment.evidence_ids[0])
            .collect();
        ensure(
            evidence.len() == 1 && evidence[0].kind == name,
            "local assessment references unrelated evidence",
        )?;
        self.objects
            .get(&evidence[0].content_sha256)
            .ok_or_else(|| "missing local assessment evidence".into())
    }
    fn result(&self, name: &str) -> Result<CheckResult> {
        self.content(name)?;
        Ok(self
            .snapshot
            .assessments
            .iter()
            .find(|a| a.condition_id == name)
            .unwrap()
            .result)
    }
    fn exact(&self, name: &str, verdict: Verdict) -> Result<()> {
        let expected = match verdict {
            Verdict::Pass => CheckResult::Pass,
            Verdict::Fail => CheckResult::Fail,
            Verdict::Unknown => CheckResult::Unknown,
        };
        ensure(
            self.result(name)? == expected,
            &format!("local assessment contradicts recorded evidence: {name}"),
        )
    }
    // A conjunction can fail for a PoH reason we do not re-prove. It cannot
    // pass when an independently computable component fails or is unknown.
    fn conjunction(&self, name: &str, parts: &[Verdict]) -> Result<()> {
        let actual = self.result(name)?;
        ensure(
            !parts.contains(&Verdict::Fail) || actual == CheckResult::Fail,
            &format!("local assessment contradicts recorded evidence: {name}"),
        )?;
        ensure(
            actual != CheckResult::Pass || parts.iter().all(|v| *v == Verdict::Pass),
            &format!("local assessment claims an unsupported pass: {name}"),
        )
    }
    fn names(&self, expected: &[&str]) -> Result<()> {
        let ConditionPolicy::Require(required) = &self.snapshot.profile.conditions else {
            return Err("container local checks require explicit conditions".into());
        };
        let names: BTreeSet<_> = expected.iter().copied().collect();
        ensure(
            required.len() == names.len()
                && required
                    .iter()
                    .all(|c| c.version == 1 && names.contains(c.condition_id.as_str()))
                && required
                    .iter()
                    .map(|c| &c.condition_id)
                    .collect::<BTreeSet<_>>()
                    .len()
                    == names.len()
                && self.snapshot.assessments.len() == names.len()
                && self
                    .snapshot
                    .assessments
                    .iter()
                    .all(|a| names.contains(a.condition_id.as_str())),
            "container local assessment set changed",
        )?;
        for name in expected {
            self.content(name)?;
        }
        Ok(())
    }
}
fn decode<T: DeserializeOwned>(value: &Value) -> Result<T> {
    Ok(serde_json::from_value(value.clone())?)
}
fn yes(value: bool) -> Verdict {
    if value { Verdict::Pass } else { Verdict::Fail }
}
fn same<T: serde::Serialize>(value: &Value, expected: &T) -> Result<()> {
    ensure(
        *value == serde_json::to_value(expected)?,
        "local evidence differs from bound action or path",
    )
}

pub(super) fn verify(
    event: &Event,
    action: &ActionIntent,
    snapshot: &EvaluationSnapshot,
) -> Result<()> {
    if action.effect.profile_id != "generic-record/v1" {
        ensure(
            event.data.get("governance_material").is_none()
                && !matches!(event.topology.as_str(), "control" | "constitutive"),
            "container effect profile was substituted",
        )?;
        return Ok(());
    }
    ensure(
        action.effect.profile_version == 1,
        "unsupported container effect version",
    )?;
    let material = &event.data["governance_material"];
    let complete = match material.get("local_assessment_version") {
        None => false,
        Some(v) if v == 1 || v == 2 || v == 3 => true,
        Some(_) => return Err("unsupported local assessment version".into()),
    };
    let commitments: BTreeMap<String, Commitment> = if complete {
        decode(
            material
                .get("commitments")
                .ok_or("missing local commitment snapshot")?,
        )?
    } else {
        BTreeMap::new()
    };
    for (reference, path) in &commitments {
        ensure(
            path.reference() == *reference,
            "local commitment hash mismatch",
        )?;
    }
    let active: Option<BTreeSet<String>> = if complete {
        Some(decode(
            material
                .get("active_paths")
                .ok_or("missing local active-path snapshot")?,
        )?)
    } else {
        None
    };
    let discovery = Discovery {
        rulebooks: decode(&material["rulebooks"])?,
        interpretations: decode(&material["interpretations"])?,
        commitments,
        seats: BTreeMap::new(),
        moderators: vec![],
        stubs: vec![],
        revocation_epoch: 0,
        revocation_ref: String::new(),
    };
    for (reference, interpretation) in &discovery.interpretations {
        ensure(
            digest(interpretation) == *reference,
            "interpretation material hash mismatch",
        )?;
    }
    let checks = Checks {
        snapshot,
        objects: &event.data["evidence_objects"],
    };
    if action.effect.operation == "apply" {
        execution(
            &checks,
            action,
            &discovery,
            active.as_ref(),
            material["local_assessment_version"] == 2 || material["local_assessment_version"] == 3,
        )
    } else {
        governance(
            &checks,
            action,
            &discovery,
            complete,
            (material["local_assessment_version"] == 3).then_some(&event.data["proof"]),
        )
    }
}

fn execution(
    checks: &Checks<'_>,
    action: &ActionIntent,
    discovery: &Discovery,
    active: Option<&BTreeSet<String>>,
    current: bool,
) -> Result<()> {
    let payload: Payload = serde_json::from_slice(&action.effect.canonical_payload)?;
    ensure(
        canonical(&payload) == action.effect.canonical_payload,
        "noncanonical local action payload",
    )?;
    let mut names = vec![
        "standing",
        "interpretation",
        "scope",
        "conditions",
        "active",
        "delegation",
        "interpretation-agreement",
        "rules-in-message",
        "acceptance-presentations",
    ];
    if payload.upstream_ref.is_some() {
        names.extend(["upstream-accountability", "recipient-payoff-policy"]);
    }
    let needs_grant = (current
        && payload.route == Route::Ordinary
        && discovery
            .commitments
            .get(&payload.path_ref)
            .is_some_and(|p| p.delegation.is_some()))
        || checks
            .snapshot
            .assessments
            .iter()
            .any(|a| a.condition_id == "delegation-grant");
    if needs_grant {
        names.push("delegation-grant");
    }
    checks.names(&names)?;
    if needs_grant {
        let bound_path: Commitment = decode(&checks.content("scope")?["path"])?;
        let grant: Option<crate::store::Record> = decode(checks.content("delegation-grant")?)?;
        checks.exact(
            "delegation-grant",
            yes(grant
                .as_ref()
                .is_some_and(|r| crate::protocol::grants_delegation(&bound_path, r))),
        )?;
    }
    let scope = checks.content("scope")?;
    let path: Commitment = decode(&scope["path"])?;
    same(&scope["route"], &payload.route)?;
    ensure(
        path.reference() == payload.path_ref
            && action.authority_id == format!("{}:{:?}", payload.path_ref, payload.route)
            && action.context_id == path.context
            && action.effect.destination == "endpoint:existing-rail",
        "local action/path binding mismatch",
    )?;
    if active.is_some() {
        same(
            &serde_json::to_value(
                discovery
                    .commitments
                    .get(&payload.path_ref)
                    .ok_or("missing local action commitment")?,
            )?,
            &path,
        )?;
    }
    let interpretation = checks.content("interpretation")?;
    same(
        &interpretation["interpretation_ref"],
        &path.interpretation_ref,
    )?;
    let facts: Facts = decode(&interpretation["facts"])?;
    ensure(
        !payload.facts.keys().any(|k| k.starts_with("host.")),
        "participant supplied host facts",
    )?;
    let mut recorded = facts.clone();
    let tick = recorded
        .remove("host.tick")
        .and_then(|v| v.as_u64())
        .ok_or("missing local tick")?;
    ensure(
        recorded
            .remove("host.count")
            .and_then(|v| v.as_i64())
            .is_some_and(|v| v > 0),
        "missing local usage count",
    )?;
    ensure(
        recorded == payload.facts,
        "assessment facts differ from action payload",
    )?;
    checks.exact(
        "scope",
        match payload.route {
            Route::Exception => path.exception.evaluate(&facts),
            _ => path.scope.evaluate(&facts),
        },
    )?;
    same(checks.content("conditions")?, &path.conditions)?;
    checks.exact("conditions", path.conditions.evaluate(&facts))?;
    let resolved = discovery.resolve(&path.rulebook_ref, &path.interpretation_ref)?;
    ensure(
        resolved.rules == path.rule_payload,
        "local path rules differ from resolved interpretation",
    )?;
    checks.exact("interpretation", resolved.evaluate(&facts))?;
    let agreement = checks.content("interpretation-agreement")?;
    same(&agreement["offered"], &payload.interpretation_ref)?;
    same(&agreement["adopted"], &path.interpretation_ref)?;
    checks.exact(
        "interpretation-agreement",
        if payload.interpretation_ref == path.interpretation_ref {
            Verdict::Pass
        } else {
            Verdict::Unknown
        },
    )?;
    let carried = checks.content("rules-in-message")?;
    same(&carried["interpretation_ref"], &payload.interpretation_ref)?;
    same(&carried["rules"], &payload.rule_payload)?;
    checks.exact(
        "rules-in-message",
        discovery
            .resolve(&path.rulebook_ref, &payload.interpretation_ref)
            .map(|r| yes(r.rules == payload.rule_payload))
            .unwrap_or(Verdict::Unknown),
    )?;
    let timing = checks.content("active")?;
    same(&timing["window"], &path.window)?;
    same(&timing["tick"], &tick)?;
    let within_window = tick >= path.window[0] && tick <= path.window[1];
    if let Some(active) = active {
        checks.exact(
            "active",
            yes(active.contains(&payload.path_ref) && within_window),
        )?;
    } else {
        checks.conjunction("active", &[yes(within_window)])?;
    }
    same(checks.content("delegation")?, &path.delegation)?;
    match (payload.route, &path.delegation) {
        (Route::Composition, _) => checks.exact(
            "delegation",
            if current && action.represented_principal_id == action.actor_id {
                path.composition.evaluate(&facts)
            } else {
                yes(action.represented_principal_id == action.actor_id
                    && path.composition.evaluate(&facts) == Verdict::Pass)
            },
        )?,
        (Route::Ordinary, Some(d)) => checks.conjunction(
            "delegation",
            &[
                if current && action.represented_principal_id == d.principal_seat {
                    d.scope.evaluate(&facts)
                } else {
                    yes(action.represented_principal_id == d.principal_seat
                        && d.scope.evaluate(&facts) == Verdict::Pass)
                },
            ],
        )?,
        (Route::Exception, Some(_)) => {} // The remaining ownership assertion is supplied by PoH.
        (_, None) => checks.exact(
            "delegation",
            yes(action.represented_principal_id == action.actor_id),
        )?,
    }
    checks.exact("acceptance-presentations", Verdict::Pass)?;
    if let Some(reference) = &payload.upstream_ref {
        let upstream: Instruction = decode(checks.content("upstream-accountability")?)?;
        ensure(
            digest(&upstream) == *reference,
            "upstream evidence differs from bound action",
        )?;
        let policy = checks.content("recipient-payoff-policy")?;
        let disposition: Option<RecipientPolicy> = decode(&policy["policy"])?;
        checks.exact(
            "recipient-payoff-policy",
            match disposition {
                Some(RecipientPolicy::Honour) => Verdict::Pass,
                Some(RecipientPolicy::Refuse) => Verdict::Fail,
                _ => Verdict::Unknown,
            },
        )?;
        same(&policy["upstream_proof"], &digest(&upstream.proof))?;
        same(&policy["upstream_payoff"], &upstream.proof.payoff_ref)?;
        let upstream_path = discovery
            .commitments
            .get(&upstream.path_ref)
            .or_else(|| (upstream.path_ref == path.reference()).then_some(&path));
        if active.is_some() {
            ensure(upstream_path.is_some(), "missing local upstream commitment")?;
        }
        if let Some(upstream_path) = upstream_path {
            upstream_checks(checks, &upstream, upstream_path, discovery, tick)?;
        }
    }
    Ok(())
}

fn upstream_checks(
    checks: &Checks<'_>,
    instruction: &Instruction,
    path: &Commitment,
    discovery: &Discovery,
    tick: u64,
) -> Result<()> {
    let a = &instruction.intent;
    let payload: Payload = match serde_json::from_slice(&a.effect.canonical_payload) {
        Ok(p) => p,
        Err(_) => return checks.exact("upstream-accountability", Verdict::Fail),
    };
    let bound = instruction.upstream.is_none()
        && instruction.route == Route::Exception
        && instruction.path_ref == path.reference()
        && instruction.interpretation_ref == path.interpretation_ref
        && instruction.rule_payload == path.rule_payload
        && a.authority_id == format!("{}:Exception", path.reference())
        && a.context_id == path.context
        && a.effect.operation == "apply"
        && a.effect.destination == "endpoint:existing-rail"
        && canonical(&instruction.payload(payload.facts.clone())) == a.effect.canonical_payload;
    checks.conjunction(
        "upstream-accountability",
        &[
            yes(bound),
            path.exception.evaluate(&payload.facts),
            path.conditions.evaluate(&payload.facts),
            discovery
                .resolve(&path.rulebook_ref, &path.interpretation_ref)?
                .evaluate(&payload.facts),
            yes(tick >= path.window[0] && tick <= path.window[1]),
        ],
    )
}

fn governance(
    checks: &Checks<'_>,
    action: &ActionIntent,
    discovery: &Discovery,
    complete: bool,
    publisher_proof: Option<&Value>,
) -> Result<()> {
    let change: Change = serde_json::from_slice(&action.effect.canonical_payload)?;
    let mut names = vec![
        "standing",
        "inheritance",
        "lifecycle",
        "acceptance-presentations",
    ];
    if publisher_proof.is_some() && change.verb == "fork" {
        names.push("interpretation-authorship");
    }
    checks.names(&names)?;
    if let (Some(proof), Some(child)) = (publisher_proof, &change.interpretation) {
        let authorship = checks.content("interpretation-authorship")?;
        same(&authorship["author_urn"], &child.author_urn)?;
        same(&authorship["rulebook_ref"], &child.rulebook_ref)?;
        same(&authorship["publisher_proof"], &digest(proof))?;
        // The identity verifier authenticates the author/credential relationship,
        // just as it authenticates standing and scoped seat ownership.
    }
    same(checks.content("lifecycle")?, &change)?;
    ensure(
        action.effect.operation == change.verb
            && action.effect.destination == change.target
            && action.context_id == "activity:governance"
            && action.authority_id == format!("govern:{}", change.target),
        "local governance binding mismatch",
    )?;
    let inheritance = checks.content("inheritance")?;
    let path: Commitment = decode(&inheritance["path"])?;
    if let Some(candidate) = &change.candidate {
        same(&serde_json::to_value(candidate)?, &path)?;
    } else if complete {
        same(
            &serde_json::to_value(
                discovery
                    .commitments
                    .get(&change.target)
                    .ok_or("missing local governance commitment")?,
            )?,
            &path,
        )?;
    }
    let resolved = discovery
        .resolve(&path.rulebook_ref, &path.interpretation_ref)
        .and_then(|r| {
            ensure(r.rules == path.rule_payload, "path rules differ")?;
            if let Some(child) = &change.interpretation {
                r.extend(child)
            } else {
                Ok(r)
            }
        });
    checks.exact("inheritance", yes(resolved.is_ok()))?;
    let known = matches!(
        change.verb.as_str(),
        "propose"
            | "accept"
            | "publish"
            | "amend"
            | "withdraw"
            | "contest"
            | "escalate"
            | "resolve"
            | "promote"
            | "fork"
    );
    let has_authority =
        change.verb != "withdraw" || !checks.snapshot.profile.required_acceptances.is_empty();
    if complete {
        checks.exact(
            "lifecycle",
            yes(known
                && has_authority
                && (discovery.commitments.contains_key(&change.target)
                    || change.verb == "propose")),
        )?;
    } else {
        checks.conjunction("lifecycle", &[yes(known && has_authority)])?;
    }
    checks.exact("acceptance-presentations", Verdict::Pass)
}
