//! Independent contract probes. No implementation sources are changed.

#[cfg(test)]
mod tests {
    use constitutive_action::v1::*;

    pub(crate) fn fixture() -> (ActionIntent, EvaluationSnapshot) {
        let intent = ActionIntent {
            schema_version: SCHEMA_VERSION,
            proposal_id: "fresh-probe:proposal".into(),
            actor_id: "agent".into(),
            represented_principal_id: "principal".into(),
            authority_id: "delegation".into(),
            context_id: "activity".into(),
            context_version: 1,
            effect: Effect {
                profile_id: "fresh-probe.effect".into(),
                profile_version: 1,
                operation: "change".into(),
                destination: "task:1".into(),
                canonical_payload: b"recipient=bob".to_vec(),
            },
        };
        let snapshot = EvaluationSnapshot {
            schema_version: SCHEMA_VERSION,
            context_id: intent.context_id.clone(),
            context_version: intent.context_version,
            sequence: 10,
            valid_through_sequence: 20,
            profile: GateProfile {
                profile_id: "fresh-probe.gate".into(),
                version: 1,
                effect_profile_id: intent.effect.profile_id.clone(),
                effect_profile_version: intent.effect.profile_version,
                conditions: ConditionPolicy::Require(vec![ConditionRequirement {
                    condition_id: "sponsor".into(),
                    version: 1,
                }]),
                required_acceptances: vec![],
            },
            evidence: vec![Evidence {
                evidence_id: "sponsor-evidence".into(),
                kind: "host-assessment".into(),
                schema_version: 1,
                subject_id: "principal".into(),
                issuer_id: "host".into(),
                content_sha256: sha256_hex(b"sponsor assessment"),
                verifier_id: Some("verifier".into()),
                verification: VerificationStatus::Verified,
                observed_at_sequence: 10,
                valid_through_sequence: 20,
                action_fingerprint: Some(intent.fingerprint()),
            }],
            assessments: vec![ConditionAssessment {
                condition_id: "sponsor".into(),
                version: 1,
                assessor_id: "host".into(),
                result: CheckResult::Pass,
                reason: "sponsor permits exact change".into(),
                evidence_ids: vec!["sponsor-evidence".into()],
            }],
            acceptances: vec![],
            revocation: RevocationState::default(),
        };
        (intent, snapshot)
    }

    fn live(
        intent: &ActionIntent,
        snapshot: &EvaluationSnapshot,
        sequence: u64,
    ) -> LiveAuthorityState {
        LiveAuthorityState {
            schema_version: SCHEMA_VERSION,
            authority_id: intent.authority_id.clone(),
            context_id: intent.context_id.clone(),
            context_version: intent.context_version,
            profile_fingerprint: snapshot.profile.fingerprint(),
            sequence,
            revocation: snapshot.revocation.clone(),
        }
    }

    fn second_unknown(snapshot: &mut EvaluationSnapshot) {
        let ConditionPolicy::Require(required) = &mut snapshot.profile.conditions else {
            unreachable!()
        };
        required.push(ConditionRequirement {
            condition_id: "standing".into(),
            version: 1,
        });
        snapshot.assessments.push(ConditionAssessment {
            condition_id: "standing".into(),
            version: 1,
            assessor_id: "host".into(),
            result: CheckResult::Unknown,
            reason: "verification result unavailable".into(),
            evidence_ids: vec![],
        });
    }

    #[test]
    fn baseline_complete_pass_fail_and_unknown_have_expected_decisions() {
        let (intent, mut snapshot) = fixture();
        assert_eq!(
            evaluate(&intent, &snapshot).decision.kind,
            DecisionKind::Permitted
        );
        snapshot.assessments[0].result = CheckResult::Fail;
        assert_eq!(
            evaluate(&intent, &snapshot).decision.kind,
            DecisionKind::Prevented
        );
        snapshot.assessments[0].result = CheckResult::Unknown;
        assert_eq!(
            evaluate(&intent, &snapshot).decision.kind,
            DecisionKind::Indeterminate
        );
    }

    // Contract docs/contract.md:31: incomplete or inconsistent snapshots are
    // indeterminate. An unknown required standing assessment with no evidence
    // is incomplete even when another condition has a verified failure.
    #[test]
    fn failed_plus_unknown_required_condition_is_indeterminate() {
        let (intent, mut snapshot) = fixture();
        snapshot.assessments[0].result = CheckResult::Fail;
        snapshot.assessments[0].reason = "sponsor refuses exact change".into();
        second_unknown(&mut snapshot);
        let mut decisions = vec![];
        for reverse in [false, true] {
            if reverse {
                snapshot.assessments.reverse();
            }
            let result = evaluate(&intent, &snapshot);
            println!(
                "mixed failed/unknown: {:?}, authority={}",
                result.decision,
                result.authority.is_some()
            );
            decisions.push(result.decision.kind);
        }
        assert_eq!(decisions, vec![DecisionKind::Indeterminate; 2]);
    }

    // Duplicate acceptance responses are structural inconsistency. The same
    // records are rejected as Indeterminate when the condition result is Pass.
    #[test]
    fn failed_condition_does_not_hide_duplicate_acceptance_responses() {
        let (intent, mut snapshot) = fixture();
        snapshot
            .profile
            .required_acceptances
            .push(AcceptanceRequirement {
                requirement_id: "recipient".into(),
                principal_id: "bob".into(),
                terms_digest: sha256_hex(b"terms"),
            });
        snapshot.acceptances = vec![
            AcceptanceRecord {
                requirement_id: "recipient".into(),
                state: AcceptanceState::Pending,
            },
            AcceptanceRecord {
                requirement_id: "recipient".into(),
                state: AcceptanceState::Pending,
            },
        ];
        assert_eq!(
            evaluate(&intent, &snapshot).decision.kind,
            DecisionKind::Indeterminate
        );
        snapshot.assessments[0].result = CheckResult::Fail;
        snapshot.assessments[0].reason = "sponsor refuses exact change".into();
        let result = evaluate(&intent, &snapshot);
        println!(
            "failed + duplicate acceptance: {:?}, authority={}",
            result.decision,
            result.authority.is_some()
        );
        assert_eq!(result.decision.kind, DecisionKind::Indeterminate);
    }

    #[test]
    fn authority_expires_with_required_evidence() {
        let (intent, mut snapshot) = fixture();
        snapshot.evidence[0].valid_through_sequence = 10;
        let admission = evaluate(&intent, &snapshot);
        assert_eq!(admission.decision.kind, DecisionKind::Permitted);
        assert_eq!(
            admission
                .authority
                .as_ref()
                .unwrap()
                .check_pre_dispatch(&intent, &live(&intent, &snapshot, 10)),
            Ok(())
        );
        let actual = admission
            .authority
            .unwrap()
            .check_pre_dispatch(&intent, &live(&intent, &snapshot, 11));
        snapshot.sequence = 11;
        let reevaluated = evaluate(&intent, &snapshot).decision.kind;
        println!("expired evidence: reused authority={actual:?}, fresh evaluation={reevaluated:?}");
        assert_eq!(actual, Err(AuthorityError::StaleOrInvalidState));
        assert_eq!(reevaluated, DecisionKind::Indeterminate);
    }

    #[test]
    fn authority_expires_with_required_acceptance() {
        let (intent, mut snapshot) = fixture();
        let terms_digest = sha256_hex(b"terms");
        snapshot
            .profile
            .required_acceptances
            .push(AcceptanceRequirement {
                requirement_id: "recipient".into(),
                principal_id: "bob".into(),
                terms_digest: terms_digest.clone(),
            });
        snapshot.acceptances.push(AcceptanceRecord {
            requirement_id: "recipient".into(),
            state: AcceptanceState::Accepted {
                by_principal_id: "bob".into(),
                action_fingerprint: intent.fingerprint(),
                terms_digest,
                at_sequence: 10,
                valid_through_sequence: 10,
            },
        });
        let admission = evaluate(&intent, &snapshot);
        assert_eq!(
            admission
                .authority
                .as_ref()
                .unwrap()
                .check_pre_dispatch(&intent, &live(&intent, &snapshot, 10)),
            Ok(())
        );
        let actual = admission
            .authority
            .unwrap()
            .check_pre_dispatch(&intent, &live(&intent, &snapshot, 11));
        snapshot.sequence = 11;
        let reevaluated = evaluate(&intent, &snapshot).decision.kind;
        println!(
            "expired acceptance: reused authority={actual:?}, fresh evaluation={reevaluated:?}"
        );
        assert_eq!(actual, Err(AuthorityError::StaleOrInvalidState));
        assert_eq!(reevaluated, DecisionKind::DecisionRequired);
    }
}

#[cfg(test)]
#[path = "support/reference_host.rs"]
mod reference_host;
