//! Local credential issuance, verification and revocation simulation. Private issuer records substitute for
//! ZK verification and encrypted-handle inspection; they are never public PoH.
use crate::{
    Result, digest, ensure,
    rules::{Facts, Predicate, Verdict},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Moderator {
    pub urn: String,
    pub lead_urn: String,
    pub rulebook_ref: String,
    pub admission: Predicate,
}

#[derive(Clone, Serialize, Deserialize)]
struct Credential {
    secret: String,
    moderator: Moderator,
    valid_until: u64,
}

#[derive(Clone)]
pub struct Participant {
    credential: Credential,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub schema_version: u16,
    pub moderator_urn: String,
    pub lead_urn: String,
    pub rulebook_ref: String,
    pub action_binding: String,
    pub seat_ref: String,
    pub payoff_ref: String,
    pub inspection_stub: String,
    pub revocation_epoch: u64,
    pub valid_until: u64,
}

impl Participant {
    /// A rulebook-scoped author identity authenticated by the same credential
    /// as the publishing proof, without exporting its private credential handle.
    pub fn interpretation_author(&self, rulebook: &str) -> String {
        format!(
            "urn:participant:{}",
            self.seat(&format!("interpretation-author:{rulebook}"))
        )
    }
    pub fn seat(&self, proposal: &str) -> String {
        format!(
            "seat:{}",
            digest(&("seat/v1", &self.credential.secret, proposal))
        )
    }
    /// Minted by the participant, never by the field/container.
    pub fn prove(&self, proposal: &str, binding: &str, payoff_ref: &str, epoch: u64) -> Proof {
        let seat = self.seat(proposal);
        Proof {
            schema_version: 1,
            moderator_urn: self.credential.moderator.urn.clone(),
            lead_urn: self.credential.moderator.lead_urn.clone(),
            rulebook_ref: self.credential.moderator.rulebook_ref.clone(),
            action_binding: binding.into(),
            seat_ref: seat.clone(),
            payoff_ref: payoff_ref.into(),
            inspection_stub: digest(&(
                "inspection-stub/v1",
                &self.credential.secret,
                binding,
                &seat,
                payoff_ref,
                epoch,
            )),
            revocation_epoch: epoch,
            valid_until: self.credential.valid_until,
        }
    }
}

#[derive(Default, Serialize, Deserialize)]
pub struct Issuers {
    moderators: BTreeMap<String, Moderator>,
    credentials: BTreeMap<String, Credential>,
    revoked: BTreeSet<String>,
    epoch: u64,
}

impl Issuers {
    pub fn revocation_ref(&self) -> String {
        digest(&("accumulator-stub/v1", self.epoch, &self.revoked))
    }
    /// Private simulation state. This is not exported discovery or a proof.
    pub fn save_private(&self, path: &std::path::Path) -> Result<()> {
        use std::io::Write;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temp = path.with_extension("tmp");
        let mut options = std::fs::OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        file.write_all(&crate::canonical(
            &serde_json::json!({"schema_version":1,"checksum":digest(self),"value":self}),
        ))?;
        file.sync_all()?;
        std::fs::rename(temp, path)?;
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    }
    pub fn load_private(path: &std::path::Path) -> Result<Self> {
        let envelope: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
        ensure(
            envelope["schema_version"] == 1,
            "unsupported private issuer version",
        )?;
        let value: Self = serde_json::from_value(envelope["value"].clone())?;
        ensure(
            envelope["checksum"].as_str() == Some(&digest(&value)),
            "private issuer checksum mismatch",
        )?;
        Ok(value)
    }
    pub fn new(moderators: Vec<Moderator>) -> Result<Self> {
        let mut result = Self::default();
        for m in moderators {
            ensure(
                m.urn.starts_with("urn:") && m.lead_urn.starts_with("urn:"),
                "expected issuer URNs",
            )?;
            ensure(
                result.moderators.insert(m.urn.clone(), m).is_none(),
                "duplicate moderator",
            )?;
        }
        Ok(result)
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn published(&self) -> Vec<Moderator> {
        self.moderators.values().cloned().collect()
    }
    pub fn owns_seat(&self, proof: &Proof, scope: &str, seat: &str) -> bool {
        self.credentials.values().any(|c| {
            let p = Participant {
                credential: c.clone(),
            };
            p.seat(scope) == seat
                && digest(&(
                    "inspection-stub/v1",
                    &c.secret,
                    &proof.action_binding,
                    &proof.seat_ref,
                    &proof.payoff_ref,
                    proof.revocation_epoch,
                )) == proof.inspection_stub
        })
    }
    pub fn owns_interpretation_author(&self, proof: &Proof, rulebook: &str, author: &str) -> bool {
        author.strip_prefix("urn:participant:").is_some_and(|seat| {
            self.owns_seat(proof, &format!("interpretation-author:{rulebook}"), seat)
        })
    }
    /// No participant roster: admission evaluates supplied facts for every caller.
    /// `entropy` is private deterministic fixture data, not a public pseudonym.
    pub fn issue(
        &mut self,
        moderator: &str,
        facts: &Facts,
        entropy: &str,
        valid_until: u64,
    ) -> Result<Participant> {
        let m = self.moderators.get(moderator).ok_or("unknown issuer")?;
        ensure(
            m.admission.evaluate(facts) == Verdict::Pass,
            "admission predicate not satisfied",
        )?;
        let secret = digest(&("credential-stub/v1", moderator, entropy));
        ensure(
            !self.credentials.contains_key(&secret),
            "credential already issued",
        )?;
        let credential = Credential {
            secret: secret.clone(),
            moderator: m.clone(),
            valid_until,
        };
        self.credentials.insert(secret, credential.clone());
        Ok(Participant { credential })
    }
    pub fn verify(
        &self,
        proof: &Proof,
        accepted_leads: &BTreeSet<String>,
        book: &str,
        proposal: &str,
        binding: &str,
        payoff: &str,
        tick: u64,
    ) -> Verdict {
        if proof.schema_version != 1 || proof.revocation_epoch != self.epoch {
            return Verdict::Unknown;
        }
        let Some(m) = self.moderators.get(&proof.moderator_urn) else {
            return Verdict::Unknown;
        };
        if !accepted_leads.contains(&m.lead_urn)
            || proof.lead_urn != m.lead_urn
            || proof.rulebook_ref != book
            || m.rulebook_ref != book
            || proof.action_binding != binding
            || proof.payoff_ref != payoff
            || tick > proof.valid_until
        {
            return Verdict::Fail;
        }
        let credential = self.credentials.values().find(|c| {
            c.moderator.urn == proof.moderator_urn
                && c.valid_until == proof.valid_until
                && Participant {
                    credential: (*c).clone(),
                }
                .prove(proposal, binding, payoff, self.epoch)
                    == *proof
        });
        match credential {
            None => Verdict::Fail,
            Some(c) if self.revoked.contains(&c.secret) => Verdict::Fail,
            Some(_) => Verdict::Pass,
        }
    }
    /// Moderator-owned inspection/revocation, distinct from withdrawing a path.
    /// Issuer-side revocation checks the named moderator against the proof's issuer.
    pub fn revoke(&mut self, moderator_urn: &str, proof: &Proof) -> Result<()> {
        ensure(
            proof.moderator_urn == moderator_urn,
            "wrong revocation authority",
        )?;
        let secret = self
            .credentials
            .values()
            .find(|c| {
                c.moderator.urn == moderator_urn
                    && digest(&(
                        "inspection-stub/v1",
                        &c.secret,
                        &proof.action_binding,
                        &proof.seat_ref,
                        &proof.payoff_ref,
                        proof.revocation_epoch,
                    )) == proof.inspection_stub
            })
            .map(|c| c.secret.clone())
            .ok_or("inspection failed")?;
        self.revoked.insert(secret);
        self.epoch += 1;
        Ok(())
    }
}
