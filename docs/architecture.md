# Architecture and protocol

## Action boundary

An Activity Field Container supports two authority topologies: controlled activity uses environment authority; constitutive activity uses participant commitments. For a mediated effect, the host-controlled adapter executes only the exact effect admitted under recorded authority. The host validates the supplied proofs, their bindings and required acceptances. It keeps the credentials and access needed to execute the action, orders reservations against changes of authority, and records what happened. The kernel evaluates the supplied snapshot; it does not determine an agent's internal objectives.

| Module | Responsibility |
|---|---|
| `vendor/constitutive-action` | Generic v1 gate, exact-effect authority and receipt validation |
| `rules` | Typed predicates, modification controls and content-addressed interpretation resolution |
| `identity` | Participant-created presentations and simulated issuance, verification and revocation |
| `protocol` | Commitments, lifecycle, discovery and independent recipient validation |
| `store` | Durable reservations, recovery and the sole effectful mock adapter |
| `audit`, `local_audit` | Recorded evidence, local verification and metric definitions |
| `scenario` | Settlement facts, narration, deterministic optimizer and branch orchestration |
| `main` | Run, matrix, inspection, replay, verification and recovery commands |

Only the adapter can write a mock external effect. Its mutation functions are crate-private, require a persisted ticket and compare the actual effect with the admitted effect. Participant APIs cannot dispatch directly.

Activity recovery acquires exclusive ownership and applies the activity's migration policy before reconciling reserved attempts; generic host recovery refuses activity stores.

Identity and standing can be supplied by an institution's existing systems or by Proof of Honesty (PoH), according to the activity. This implementation uses the concrete `identity::Issuers` and `Proof` types. A field receives presentations and never creates them. Participants can validate public material before submission; recipients validate again at their own boundary. Peer validation has no reference to the originating `Field`, although the simulation supplies both with the same read-only issuer verifier.

## Rulebooks and commitments

Base rules use `urn:rule:index:modifier:description_hash:rulebook_uuid` identifiers; their concatenation identifies the base Rulebook URN. A separate canonical JSON hash addresses the complete demo document, including machine predicates. Interpretation hashes cover their parent, author URN, level and edits. Publishing a new interpretation authenticates its rulebook-scoped author identity against the publishing credential.

Inheritance follows Document → Lead → Moderator → User. The zeroth rule is mandatory. Modifiers control how inherited rules and phrases may change:

| Modifier | Permitted changes |
| --- | --- |
| `Public` | Rules and phrases may be omitted or interpreted. |
| `Protected` | Material must remain present but may be interpreted. |
| `Final` | Material cannot be reinterpreted. |

A `Final` rule can contain a separately interpretable phrase. Modification controls can only tighten, and omitted inherited material cannot be silently revived.

The engine evaluates typed predicates. Prose and its explicitly supplied predicate are stored together. An `Unresolved` predicate evaluates to `Unknown`; predicate composition and the required checks determine the action’s decision. A different root rulebook receives a new identity. Amendment and promotion create new content-addressed records. Earlier records and proof references are preserved.

A commitment records the scope of permitted work, its conditions and interpreted rules, any delegation, a separately eligible exception, consequence references, affected seats and a validity window. Seats are scoped references used to attribute actions through participant proofs.

The host supplies `host.tick` from the execution call and derives `host.count` from reservations under the route’s authority, including uncertain attempts and the proposed attempt. Participant payloads cannot supply `host.*` facts.

## Authority and change

An ordinary delegated action needs a scoped grant from the principal—the participant on whose behalf the agent acts. The participant giving that grant is the grantor. In this demo, proposing and accepting that path requires the principal's PoH-backed consent to the exact governance action, even when the principal is outside the owner/controller set.

Amendments and promotions require renewed consent from the previous and resulting grantors, including removal of delegation. Changes to scope, delegate, validity or consequence terms therefore require fresh approval.

The exception route has its own eligibility predicate, authority and required officer acceptance. It does not convert a failed ordinary mandate into permission.

The proof producer remains the recorded accountable bearer for each act. Delegation provides authority to act without erasing that attribution. A downstream act has its own proof and preserves the upstream evidence. The relevant institutions determine and administer consequences; the demo preserves the applicable consequence references for those institutions.

Control topology establishes procedures under environment authority; constitutive topology establishes them under participant commitments. Both preserve grantor consent. In the fixture the controller is also the initial grantor, so initial control activation requires one acceptance and constitutive activation requires both owners. A distinct grantor adds its own acceptance.

Lifecycle verbs are `propose`, `accept`, `amend`, `withdraw`, `contest`, `escalate`, `fork`, `publish`, `resolve` and `promote`. Promotion requires a resolved queue item for the same path and offered interpretation, plus the required consents. Control promotion additionally requires environment authority. Withdrawal removes future path authority; credential revocation is separate. Neither erases an earlier occurrence.

Before new delegated work can execute, the store must contain a confirmed activation, amendment or promotion with the grantor's acceptance of that exact governance action. An existing store without that grant cannot authorize fresh delegated work; the parties can constitute replacement terms. Historical records and completed replay identities are retained.

Field recovery rejects an unexecuted reservation lacking the grant while reconciling an effect already observed under its original replay identity. Grant validity is established at constitution; later changes of the grantor's standing do not automatically cancel it.

## Discovery, composition and extension

A discovery stub points newcomers to the published terms, interpretation and commitment evidence they need to evaluate participation. It is a JSON object with six fields:

```text
rulebook_id, lead_id, mod_id, rule_interpretation_hash,
commitment_ref, transaction_hash
```

`commitment_ref` addresses a seat record containing path and proof references, an action-scoped seat and a consequence reference. The governance hash covers the first five stub fields. `transaction_hash` records the publishing action’s hash. Messages carry the interpreted rule payload and its reference, which validators check against the referenced interpretation.

A newcomer uses its own facts and public discovery. It selects a qualifying moderator under the accepted Lead, satisfies the published admission predicate and produces its own proof. Any valid moderator under that Lead can qualify, including one published later. There is no field-level participant roster or add-participant operation.

Composition lets a newcomer act under the published rules using its own proof. Its actions remain attributable to it; joining does not give it the founders' delegated authority.

A participant may publish a permitted interpretation without changing an existing commitment. A disagreement queues until resolution and the required consents adopt changed terms.

An independent recipient revalidates an attached upstream exception under its own policy and can refuse, honour or leave its decision unresolved.

The current container fixes the `generic-record/v1` effect profile and mock endpoint. Different utilities can be implemented by extending or forking the host, profiles and adapters while retaining the authority boundary. The [durable effect example](../examples/durable_effect.rs) uses another profile at the kernel/host boundary. The recipient example validates exception-authority evidence independently of its originating coordination venue.

## Identity simulation

Public Proof of Honesty contains moderator and Lead URNs, rulebook and action bindings, an action-scoped seat, consequence reference, inspection stub, revocation epoch and validity. It contains no credential secret, persistent credential ID, raw revocation handle or onboarding exonym. Activity-scoped consent references bind the required acceptance to an established seat.

Private simulation records stand in for proof verification and inspection. A stale revocation epoch yields `Indeterminate`; a current presentation of a revoked credential is prevented. Unknown issuers and unsupported proof versions fail closed. These records demonstrate the protocol shape without providing cryptographic anonymity or unforgeability. Production deployments choosing PoH must supply its real verification, issuance, inspection and revocation mechanisms.

## Durable operation

The host persists intent, complete evidence and decision before reservation. A proposal ID cannot be reused for a changed effect. An OS file lock serializes transactions; writes fsync a temporary file, atomically rename it and sync the directory. Reservations and effective withdrawals share an order. An intervening transition invalidates a new reservation's old snapshot and requires reevaluation.

The adapter has its own durable file and lock. It performs the exact effect under a stable replay ID, exposing the crash gap between external success and the host receipt. Recovery reuses that identity. A terminal receipt cannot be downgraded by a late uncertain response.

An `Indeterminate` decision, evidence and pending queue entry are committed together. Reopening reconstructs missing queue entries from recorded decisions and preserves confirmed resolutions. Existing stores with a missing journal or adapter ledger fail closed. Confirmed effects are checked against the modeled adapter record rather than inferred from a receipt alone.

`Field::reopen` rebuilds commitments, discovery, active paths and recipient policy from bootstrap and confirmed acts. One active owner holds an OS lifetime lock per activity store, covering creation, mutation and recovery. Other handles can inspect but cannot mutate that activity. Independent activities have independent owners; the generic host still supports concurrent handles for its own profiles.

## Auditing and metrics

Every decision records the original kernel outcome, complete snapshot, evidence objects, accountable proof and governance material. Receipts record persisted outcomes. Local audit rederives predicates, inheritance, payload bindings, recipient policy, grant evidence and usage counts where the stored evidence supports them. Identity, standing and seat ownership remain supplied verifier claims.

`verify RUN` reconciles event history with action records, reservations, receipts, queues, mock effects, reports, semantic exports and discovery reconstructed from confirmed acts. It verifies local evidence and does not establish the history of an external resource. Hashes support integrity within this trust boundary; an operator controlling both evidence and capabilities is outside it.

New event summaries use `DecisionRequired`; the kernel JSON value remains `decision_required`. Verification and replay also accept the historical summary spelling without rewriting recorded evidence. Wall-clock timestamps are decimal nanosecond strings for lossless JavaScript handling. Monotonic durations are numeric nanoseconds. Semantic replay excludes measured times and their dependent hashes while retaining inputs, decisions and occurrences.

New outputs use metrics schema version 2 with literal event-count names. Historical reports retain their original names and remain verifiable without rewriting them. The formulas are defined in [the metric implementation](../src/audit.rs):

| Field | What it counts or records |
|---|---|
| `event_counts`, `kernel_decisions` | Counts by event kind and recorded decision outcome |
| `path_activation_composition_and_promotion_events` | Path activations + completed compositions + promotions |
| `path_activation_exception_and_promotion_events` | Path activations + completed exception-accountability records + promotions |
| `decision_discovery_and_recipient_validation_events` | Decisions + discovery reads + recipient validations |
| `prevented_decisions` | Prevented decision events |
| `discretionary_onboarding_events` | Logged discretionary onboarding events |
| `composition_latency_ns` | Local arrival-to-first-confirmed-action durations |
| `fork_events`, `promotions` | Published forks and completed promotions, respectively |
| `indeterminate_in`, `indeterminate_out` | Queued items and completed resolutions, respectively |
| `override_requests` | Requested exceptions |
| `exception_accountability_records` | Completed exception-accountability records |
| `latency_scope`, `anonymity_scope` | Text describing the local measurement and identity-simulation scope |

These counters describe protocol activity. Composition timing measures the local flow from arrival through the first confirmed action, including verification, issuance and instrumentation. In this Proof of Honesty demonstration, published checks and automatic credential issuance require no discretionary, participant-specific onboarding. Institutional identity integrations use their own onboarding process.
