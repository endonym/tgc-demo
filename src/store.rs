//! Durable host and controlled mock adapter. Each transition is serialized by
//! an OS file lock, fsyncs a new complete state, then atomically renames it.
use crate::{Result, audit::Event, canonical, digest, ensure};
use constitutive_action::v1::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ticket {
    pub proposal_id: String,
    pub fingerprint: String,
    pub attempt_id: String,
    pub replay_id: String,
    pub order: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    pub intent: ActionIntent,
    pub snapshot: EvaluationSnapshot,
    pub decision: GateDecision,
    pub ticket: Option<Ticket>,
    pub receipt: Option<ActionReceipt>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueueItem {
    pub proposal_id: String,
    pub context_ref: String,
    pub reason: String,
    pub status: String,
    pub resolution_proposal: Option<String>,
}

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct State {
    pub field_bootstrap: Option<Value>,
    pub order: u64,
    pub records: BTreeMap<String, Record>,
    pub revocations: BTreeMap<String, RevocationState>,
    pub profiles: BTreeMap<String, String>,
    pub events: Vec<Event>,
    pub objects: BTreeMap<String, Value>,
    pub queue: BTreeMap<String, QueueItem>,
}

#[derive(Serialize, Deserialize)]
struct Envelope<T> {
    checksum: String,
    value: T,
}

fn read<T: serde::de::DeserializeOwned + Serialize>(path: &Path) -> Result<T> {
    ensure(
        path.is_file(),
        &format!("missing persistent store: {}", path.display()),
    )?;
    let value: Envelope<T> = serde_json::from_slice(&fs::read(path)?)?;
    ensure(
        value.checksum == digest(&value.value),
        "persistent state checksum mismatch",
    )?;
    Ok(value.value)
}
fn write<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let temp = path.with_extension("tmp");
    let mut file = File::create(&temp)?;
    file.write_all(&canonical(&Envelope {
        checksum: digest(value),
        value,
    }))?;
    file.sync_all()?;
    fs::rename(&temp, path)?;
    File::open(path.parent().ok_or("missing store parent")?)?.sync_all()?;
    Ok(())
}

#[derive(Clone)]
pub struct Host {
    root: PathBuf,
    // Only the activity owner carries this lifetime capability. Ordinary Host
    // handles can inspect activity stores but cannot mutate or recover them.
    field_owner: Option<Arc<OwnershipLock>>,
}

struct OwnershipLock(File);
impl Drop for OwnershipLock {
    fn drop(&mut self) {
        // Close-on-exec does not cover the interval between fork and exec in
        // another thread. Explicitly release ownership even if such a child
        // briefly retains a duplicate of this open file description.
        let _ = self.0.unlock();
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Reservation {
    New(Ticket),
    Replay(Ticket),
    Denied,
}

impl Host {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        fs::create_dir_all(root.as_ref())?;
        let host = Self {
            root: root.as_ref().to_path_buf(),
            field_owner: None,
        };
        Self::initialize(host)
    }
    fn initialize(host: Self) -> Result<Self> {
        let _ownership = host.mutation_guard()?;
        let lock_path = host.root.join("host.lock");
        let (lock, new_lock) = match OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&lock_path)
        {
            Ok(lock) => (lock, true),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (
                OpenOptions::new().read(true).write(true).open(&lock_path)?,
                false,
            ),
            Err(e) => return Err(e.into()),
        };
        lock.lock()?;
        let state = host.root.join("state.json");
        let adapter = host.root.join("adapter.json");
        if new_lock
            && !state.exists()
            && !adapter.exists()
            && !host.root.join("adapter.lock").exists()
        {
            // Only a new store may start empty. A partial restore or interrupted
            // initialization must never silently recreate either ledger.
            write(&adapter, &BTreeMap::<String, Effect>::new())?;
            write(&state, &State::default())?;
        }
        ensure(
            state.is_file() && adapter.is_file(),
            "incomplete persistent store: state or adapter ledger missing",
        )?;
        drop(lock);
        host.validate_confirmed_effects()?;
        Ok(host)
    }
    /// Open evidence without initializing missing state or adapter files.
    pub fn open_existing(root: impl AsRef<Path>) -> Result<Self> {
        let host = Self {
            root: root.as_ref().to_path_buf(),
            field_owner: None,
        };
        ensure(
            host.root.join("state.json").is_file() && host.root.join("adapter.json").is_file(),
            "incomplete persistent store: state or adapter ledger missing",
        )?;
        host.validate_confirmed_effects()?;
        Ok(host)
    }
    pub(crate) fn open_field(root: &Path, existing: bool) -> Result<Self> {
        if !existing {
            fs::create_dir_all(root)?;
        }
        let host = Self {
            root: root.to_path_buf(),
            field_owner: None,
        };
        let owned = host.claim_field()?;
        if existing {
            owned.validate_confirmed_effects()?;
            Ok(owned)
        } else {
            Self::initialize(owned)
        }
    }
    pub(crate) fn claim_field(&self) -> Result<Self> {
        let lock = self.ownership_lock()?;
        lock.try_lock()
            .map_err(|e| format!("activity store already owned or unavailable: {e}"))?;
        Ok(Self {
            root: self.root.clone(),
            field_owner: Some(Arc::new(OwnershipLock(lock))),
        })
    }
    fn ownership_lock(&self) -> Result<File> {
        Ok(OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.root.join("field-owner.lock"))?)
    }
    fn mutation_guard(&self) -> Result<Option<OwnershipLock>> {
        if self.field_owner.is_some() {
            return Ok(None);
        }
        let lock = self.ownership_lock()?;
        lock.try_lock_shared()
            .map_err(|e| format!("activity store already owned or unavailable: {e}"))?;
        Ok(Some(OwnershipLock(lock)))
    }
    pub(crate) fn transaction<T>(&self, f: impl FnOnce(&mut State) -> Result<T>) -> Result<T> {
        let _ownership = self.mutation_guard()?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.root.join("host.lock"))?;
        lock.lock()?;
        ensure(
            self.root.join("adapter.json").is_file(),
            "missing persistent adapter ledger",
        )?;
        let mut state: State = read(&self.root.join("state.json"))?;
        ensure(
            state.field_bootstrap.is_none() || self.field_owner.is_some(),
            "activity mutation requires its Field owner",
        )?;
        let result = f(&mut state)?;
        write(&self.root.join("state.json"), &state)?;
        Ok(result)
    }
    pub fn state(&self) -> Result<State> {
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.root.join("host.lock"))?;
        lock.lock_shared()?;
        read(&self.root.join("state.json"))
    }
    pub(crate) fn note(&self, mut event: Event) -> Result<()> {
        self.transaction(|s| {
            event.seal(s.events.last());
            s.events.push(event);
            Ok(())
        })
    }
    pub(crate) fn object<T: Serialize>(&self, value: &T) -> Result<String> {
        let key = digest(value);
        self.transaction(|s| {
            s.objects.insert(key.clone(), serde_json::to_value(value)?);
            Ok(())
        })?;
        Ok(key)
    }
    // Used by the standalone host laboratory and conformance tests. The field
    // uses prepare_with_queue so its pending work shares the decision commit.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn prepare(
        &self,
        intent: &ActionIntent,
        snapshot: &EvaluationSnapshot,
        event: Event,
        started: std::time::Instant,
    ) -> Result<GateDecision> {
        self.prepare_inner(intent, snapshot, event, started, None)
    }
    /// Commit an indeterminate decision and its pending work in one transaction.
    pub(crate) fn prepare_with_queue(
        &self,
        intent: &ActionIntent,
        snapshot: &EvaluationSnapshot,
        event: Event,
        started: std::time::Instant,
        queue_context: &str,
    ) -> Result<GateDecision> {
        self.prepare_inner(intent, snapshot, event, started, Some(queue_context))
    }
    fn prepare_inner(
        &self,
        intent: &ActionIntent,
        snapshot: &EvaluationSnapshot,
        mut event: Event,
        started: std::time::Instant,
        queue_context: Option<&str>,
    ) -> Result<GateDecision> {
        let decision = self.transaction(|s| {
            if let Some(old) = s.records.get(&intent.proposal_id) {
                ensure(
                    old.intent == *intent,
                    "proposal ID reused for different effect",
                )?;
                ensure(
                    old.ticket.is_none(),
                    "reserved proposal must be replayed, never re-evaluated",
                )?;
            }
            let admission = evaluate(intent, snapshot);
            event.latency_ns = Some(started.elapsed().as_nanos());
            event.outcome = Some(crate::audit::outcome(admission.decision.kind).into());
            event.data["intent"] = serde_json::to_value(intent)?;
            event.data["snapshot"] = serde_json::to_value(snapshot)?;
            event.data["decision"] = serde_json::to_value(&admission.decision)?;
            let mut sources = BTreeMap::new();
            for evidence in &snapshot.evidence {
                let source = s
                    .objects
                    .get(&evidence.content_sha256)
                    .ok_or("missing decision evidence material")?;
                sources.insert(evidence.content_sha256.clone(), source.clone());
            }
            event.data["evidence_objects"] = serde_json::to_value(sources)?;
            if let Some(proof) = event.data.get("proof").filter(|p| !p.is_null()) {
                s.objects.insert(digest(proof), proof.clone());
            }
            let pending = queue_context.filter(|_| admission.decision.kind == DecisionKind::Indeterminate);
            let queued = pending.map(|context| {
                s.queue.entry(intent.proposal_id.clone()).or_insert(QueueItem {
                    proposal_id: intent.proposal_id.clone(),
                    context_ref: context.into(),
                    reason: admission.decision.reasons.join("; "),
                    status: "pending".into(),
                    resolution_proposal: None,
                });
                Event::new(&event.movement, &event.beat, &event.topology, "queued",
                    serde_json::json!({"proposal_id":intent.proposal_id,"reason":admission.decision.reasons}))
            });
            event.seal(s.events.last());
            s.events.push(event);
            if let Some(mut queued) = queued {
                queued.seal(s.events.last());
                s.events.push(queued);
            }
            s.profiles
                .insert(intent.authority_id.clone(), snapshot.profile.fingerprint());
            s.records.insert(
                intent.proposal_id.clone(),
                Record {
                    intent: intent.clone(),
                    snapshot: snapshot.clone(),
                    decision: admission.decision.clone(),
                    ticket: None,
                    receipt: None,
                },
            );
            if pending.is_some() {
                crash_point("before-pending-commit", &intent.proposal_id);
            }
            Ok(admission.decision)
        })?;
        if queue_context.is_some() && decision.kind == DecisionKind::Indeterminate {
            crash_point("after-pending-commit", &intent.proposal_id);
        }
        Ok(decision)
    }
    pub(crate) fn reserve(&self, proposal: &str) -> Result<Reservation> {
        self.transaction(|s| {
            let record = s.records.get_mut(proposal).ok_or("unknown proposal")?;
            if let Some(ticket) = &record.ticket {
                return Ok(Reservation::Replay(ticket.clone()));
            }
            // Any intervening authority/effect transition requires a fresh
            // snapshot, including host-derived usage predicates.
            if s.order > record.snapshot.sequence {
                return Ok(Reservation::Denied);
            }
            let admission = evaluate(&record.intent, &record.snapshot);
            let Some(authority) = admission.authority else {
                return Ok(Reservation::Denied);
            };
            let live = LiveAuthorityState {
                schema_version: 1,
                authority_id: record.intent.authority_id.clone(),
                context_id: record.intent.context_id.clone(),
                context_version: record.intent.context_version,
                profile_fingerprint: s
                    .profiles
                    .get(&record.intent.authority_id)
                    .cloned()
                    .unwrap_or_default(),
                sequence: s.order.max(record.snapshot.sequence),
                revocation: s
                    .revocations
                    .get(&record.intent.authority_id)
                    .cloned()
                    .unwrap_or_default(),
            };
            if authority.check_pre_dispatch(&record.intent, &live).is_err() {
                return Ok(Reservation::Denied);
            }
            s.order = live.sequence + 1;
            let ticket = Ticket {
                proposal_id: proposal.into(),
                fingerprint: record.intent.fingerprint(),
                attempt_id: format!("attempt:{}", digest(&record.intent)),
                replay_id: format!("replay:{}", digest(&record.intent)),
                order: s.order,
            };
            record.ticket = Some(ticket.clone());
            Ok(Reservation::New(ticket))
        })
    }
    pub(crate) fn effective_revoke(&self, authority: &str) -> Result<u64> {
        self.transaction(|s| {
            if let Some(effective) = s
                .revocations
                .get(authority)
                .and_then(|r| r.effective.as_ref())
            {
                return Ok(effective.effective_at_sequence);
            }
            s.order += 1;
            s.revocations.entry(authority.into()).or_default().effective =
                Some(EffectiveRevocation {
                    decision_id: format!("withdrawal:{}", s.order),
                    target_authority_id: authority.into(),
                    effective_at_sequence: s.order,
                });
            Ok(s.order)
        })
    }
    pub(crate) fn adapter_matches(&self, ticket: &Ticket, actual: &Effect) -> Result<bool> {
        let state = self.state()?;
        Ok(state
            .records
            .get(&ticket.proposal_id)
            .is_some_and(|r| r.ticket.as_ref() == Some(ticket) && r.intent.effect == *actual))
    }
    /// This is the only capability that changes the mock external rail. The
    /// actual effect is reconstructed by the caller's typed profile and checked.
    pub(crate) fn dispatch(
        &self,
        ticket: &Ticket,
        actual: &Effect,
        lose_response: bool,
    ) -> Result<ActionReceipt> {
        let _ownership = self.mutation_guard()?;
        ensure(
            self.state()?.field_bootstrap.is_none() || self.field_owner.is_some(),
            "activity dispatch requires its Field owner",
        )?;
        ensure(
            self.adapter_matches(ticket, actual)?,
            "adapter refused altered or unreserved effect",
        )?;
        let state = self.state()?;
        let record = state
            .records
            .get(&ticket.proposal_id)
            .ok_or("unknown proposal")?;
        if let Some(r) = &record.receipt {
            if matches!(
                r.outcome,
                ExecutionOutcome::Confirmed { .. } | ExecutionOutcome::Rejected { .. }
            ) {
                self.validate_confirmed_effects()?;
                return Ok(r.clone());
            }
        }
        crash_point("after-reservation", &ticket.proposal_id);
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.root.join("adapter.lock"))?;
        lock.lock()?;
        let path = self.root.join("adapter.json");
        let mut rail: BTreeMap<String, Effect> = read(&path)?;
        if let Some(existing) = rail.get(&ticket.replay_id) {
            ensure(existing == actual, "external replay identity conflict")?;
        }
        rail.insert(ticket.replay_id.clone(), actual.clone());
        write(&path, &rail)?;
        drop(lock);
        crash_point("after-external", &ticket.proposal_id);
        let outcome = if lose_response {
            ExecutionOutcome::Uncertain {
                reason: "response lost after external success".into(),
            }
        } else {
            ExecutionOutcome::Confirmed {
                occurrence_id: format!("occurrence:{}", digest(&ticket.replay_id)),
            }
        };
        self.finish(ticket, outcome)
    }
    pub(crate) fn finish(
        &self,
        ticket: &Ticket,
        outcome: ExecutionOutcome,
    ) -> Result<ActionReceipt> {
        self.transaction(|s| {
            let source = s
                .events
                .iter()
                .rev()
                .find(|e| {
                    e.kind == "decision"
                        && e.data["intent"]["proposal_id"].as_str() == Some(&ticket.proposal_id)
                })
                .cloned();
            let r = s
                .records
                .get_mut(&ticket.proposal_id)
                .ok_or("missing record")?;
            ensure(r.ticket.as_ref() == Some(ticket), "ticket mismatch")?;
            if let Some(existing) = &r.receipt {
                if matches!(
                    existing.outcome,
                    ExecutionOutcome::Confirmed { .. } | ExecutionOutcome::Rejected { .. }
                ) {
                    return Ok(existing.clone());
                }
            }
            let receipt = ActionReceipt {
                schema_version: 1,
                proposal_id: ticket.proposal_id.clone(),
                action_fingerprint: ticket.fingerprint.clone(),
                decision: r.decision.clone(),
                executor_id: Some("adapter:local".into()),
                attempt_id: Some(ticket.attempt_id.clone()),
                outcome,
            };
            validate_receipt(&r.intent, &evaluate(&r.intent, &r.snapshot), &receipt)
                .map_err(|e| format!("receipt: {e:?}"))?;
            r.receipt = Some(receipt.clone());
            let source = source
                .unwrap_or_else(|| Event::new("host", "recovery", "host", "decision", Value::Null));
            let mut event = Event::new(
                &source.movement,
                &source.beat,
                &source.topology,
                "receipt",
                serde_json::json!({"receipt":receipt}),
            );
            event.seal(s.events.last());
            s.events.push(event);
            Ok(receipt)
        })
    }
    pub fn recover(&self) -> Result<Vec<ActionReceipt>> {
        ensure(
            self.state()?.field_bootstrap.is_none(),
            "activity recovery requires Field::recover_host or Field::reopen",
        )?;
        self.recover_inner()
    }
    pub(crate) fn recover_after_field_policy(&self) -> Result<Vec<ActionReceipt>> {
        ensure(
            self.field_owner.is_some(),
            "activity recovery requires exclusive ownership",
        )?;
        self.recover_inner()
    }
    fn recover_inner(&self) -> Result<Vec<ActionReceipt>> {
        let _ownership = self.mutation_guard()?;
        self.validate_confirmed_effects()?;
        let mut recovered = Vec::new();
        for r in self.state()?.records.values() {
            if let Some(ticket) = &r.ticket {
                if r.receipt
                    .as_ref()
                    .is_none_or(|r| matches!(r.outcome, ExecutionOutcome::Uncertain { .. }))
                {
                    recovered.push(self.dispatch(ticket, &r.intent.effect, false)?);
                }
            }
        }
        Ok(recovered)
    }
    pub fn occurrences(&self) -> Result<usize> {
        Ok(self.recorded_effects()?.len())
    }
    pub fn recorded_effects(&self) -> Result<BTreeMap<String, Effect>> {
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.root.join("adapter.lock"))?;
        lock.lock_shared()?;
        read(&self.root.join("adapter.json"))
    }
    fn validate_confirmed_effects(&self) -> Result<()> {
        let state = self.state()?;
        let effects = self.recorded_effects()?;
        for record in state.records.values() {
            if let Some(ActionReceipt {
                outcome: ExecutionOutcome::Confirmed { occurrence_id },
                ..
            }) = &record.receipt
            {
                let ticket = record
                    .ticket
                    .as_ref()
                    .ok_or("confirmed record missing ticket")?;
                ensure(
                    effects.get(&ticket.replay_id) == Some(&record.intent.effect),
                    "confirmed local occurrence missing or changed",
                )?;
                ensure(
                    *occurrence_id == format!("occurrence:{}", digest(&ticket.replay_id)),
                    "confirmed local occurrence identity mismatch",
                )?;
            }
        }
        Ok(())
    }
}

/// Explicit process-crash injection for durability demonstrations. It only
/// terminates execution; it cannot permit, alter or dispatch an extra effect.
fn crash_point(point: &str, proposal: &str) {
    if std::env::var("TGC_DEMO_CRASH_AT").ok().as_deref() == Some(&format!("{point}:{proposal}")) {
        std::process::exit(86);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use constitutive_action::host_conformance as c;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Scenario(PathBuf);
    impl Drop for Scenario {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    impl c::HostScenario for Scenario {
        type Handle = Host;
        fn open(&self) -> Host {
            Host::open(&self.0).unwrap()
        }
    }
    fn scenario() -> Scenario {
        Scenario(std::env::temp_dir().join(format!(
            "tgc-host-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        )))
    }
    fn project(t: &Ticket) -> c::DispatchTicket {
        c::DispatchTicket {
            proposal_id: t.proposal_id.clone(),
            action_fingerprint: t.fingerprint.clone(),
            attempt_id: t.attempt_id.clone(),
            replay_id: t.replay_id.clone(),
            reserved_at_order: t.order,
        }
    }
    impl c::HostHandle for Host {
        type Error = String;
        fn prepare(
            &mut self,
            intent: &ActionIntent,
            snapshot: &EvaluationSnapshot,
        ) -> std::result::Result<c::Prepare, String> {
            if let Some(old) = self
                .state()
                .map_err(|e| e.to_string())?
                .records
                .get(&intent.proposal_id)
            {
                return Ok(if old.intent == *intent {
                    c::Prepare::Existing
                } else {
                    c::Prepare::Conflict
                });
            }
            Host::prepare(
                self,
                intent,
                snapshot,
                Event::new("test", "host", "host", "decision", serde_json::json!({})),
                std::time::Instant::now(),
            )
            .map_err(|e| e.to_string())?;
            Ok(c::Prepare::Stored)
        }
        fn reserve(&mut self, proposal: &str) -> std::result::Result<c::Reservation, String> {
            Ok(
                match Host::reserve(self, proposal).map_err(|e| e.to_string())? {
                    Reservation::Denied => c::Reservation::Denied,
                    Reservation::New(t) => c::Reservation::New(project(&t)),
                    Reservation::Replay(t) => {
                        let state = self.state().map_err(|e| e.to_string())?;
                        let r = &state.records[proposal];
                        let outcome = match r.receipt.as_ref().map(|r| &r.outcome) {
                            None | Some(ExecutionOutcome::NotDispatched) => {
                                c::AttemptState::InFlight
                            }
                            Some(ExecutionOutcome::Uncertain { reason }) => {
                                c::AttemptState::Uncertain {
                                    reason: reason.clone(),
                                }
                            }
                            Some(ExecutionOutcome::Confirmed { occurrence_id }) => {
                                c::AttemptState::Confirmed {
                                    occurrence_id: occurrence_id.clone(),
                                }
                            }
                            Some(ExecutionOutcome::Rejected { reason }) => {
                                c::AttemptState::Rejected {
                                    reason: reason.clone(),
                                }
                            }
                        };
                        c::Reservation::Replay {
                            ticket: project(&t),
                            state: outcome,
                        }
                    }
                },
            )
        }
        fn effective_revoke(
            &mut self,
            authority: &str,
        ) -> std::result::Result<c::RevocationCommit, String> {
            Ok(c::RevocationCommit {
                order: Host::effective_revoke(self, authority).map_err(|e| e.to_string())?,
            })
        }
        fn record_uncertain(
            &mut self,
            attempt: &str,
            reason: &str,
        ) -> std::result::Result<(), String> {
            let ticket = self
                .state()
                .map_err(|e| e.to_string())?
                .records
                .values()
                .filter_map(|r| r.ticket.clone())
                .find(|t| t.attempt_id == attempt)
                .ok_or("attempt not found")?;
            self.finish(
                &ticket,
                ExecutionOutcome::Uncertain {
                    reason: reason.into(),
                },
            )
            .map_err(|e| e.to_string())?;
            Ok(())
        }
        fn adapter_matches(
            &mut self,
            ticket: &c::DispatchTicket,
            effect: &Effect,
        ) -> std::result::Result<bool, String> {
            let t = Ticket {
                proposal_id: ticket.proposal_id.clone(),
                fingerprint: ticket.action_fingerprint.clone(),
                attempt_id: ticket.attempt_id.clone(),
                replay_id: ticket.replay_id.clone(),
                order: ticket.reserved_at_order,
            };
            Host::adapter_matches(self, &t, effect).map_err(|e| e.to_string())
        }
    }
    #[test]
    fn persistent_host_passes_official_conformance_including_races() {
        c::check_host(scenario);
    }

    #[test]
    fn ownership_release_does_not_wait_for_an_inherited_descriptor_to_close() {
        let s = scenario();
        let owner = Host::open_field(&s.0, false).unwrap();
        // try_clone duplicates the open file description, as fork does.
        let inherited = owner.field_owner.as_ref().unwrap().0.try_clone().unwrap();
        let owner_clone = owner.clone();
        drop(owner);
        assert!(Host::open_field(&s.0, true).is_err());
        drop(owner_clone);
        let successor = Host::open_field(&s.0, true).unwrap();
        assert!(Host::open_field(&s.0, true).is_err());
        drop(inherited);
        assert!(Host::open_field(&s.0, true).is_err());
        drop(successor);

        let host = Host::open_existing(&s.0).unwrap();
        let guard = host.mutation_guard().unwrap().unwrap();
        let inherited = guard.0.try_clone().unwrap();
        assert!(Host::open_field(&s.0, true).is_err());
        drop(guard);
        let owner = Host::open_field(&s.0, true).unwrap();
        drop(inherited);
        assert!(Host::open_field(&s.0, true).is_err());
        drop(owner);
    }

    #[test]
    fn state_corruption_is_not_silently_reset() {
        let s = scenario();
        let h = Host::open(&s.0).unwrap();
        h.transaction(|state| {
            state.order = 42;
            Ok(())
        })
        .unwrap();
        let path = s.0.join("state.json");
        let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["value"]["order"] = 43.into();
        fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(h.state().is_err());
    }

    #[test]
    fn missing_existing_storage_is_never_reinitialized() {
        for missing in [
            vec!["state.json"],
            vec!["adapter.json"],
            vec!["state.json", "adapter.json"],
            vec!["state.json", "adapter.json", "host.lock"],
        ] {
            let s = scenario();
            let h = Host::open(&s.0).unwrap();
            assert!(h.state().unwrap().records.is_empty());
            assert_eq!(h.occurrences().unwrap(), 0);
            for name in &missing {
                fs::remove_file(s.0.join(name)).unwrap();
            }
            assert!(Host::open(&s.0).is_err());
            assert!(Host::open_existing(&s.0).is_err());
            assert!(h.recover().is_err());
            for name in missing {
                if name.ends_with(".json") {
                    assert!(!s.0.join(name).exists());
                }
            }
        }
    }
}
