# TGC settlement demonstration

Participants authorise bounded work in advance, so agents can perform ordinary actions without asking for approval each time. The container checks each proposed action against those terms and records its authority and outcome. Exceptions and changes require the specified consent. A separate recipient can check the attached exception evidence under its own policy, without consulting the original container.

This Rust demonstration implements an Activity Field Container with two authority topologies: **controlled** activity uses environment authority; **constitutive** activity uses participant commitments.

It runs participants, a scripted optimizer, identity and standing fixtures, an independent recipient and durable infrastructure mocks in one local process. Financial settlement is the example activity and it's no coincidence that the architecture carries the same name. The kernel and action-boundary model are generic; the demo makes no LLM calls or real asset transfers.

Start here, then read [architecture and protocol](docs/architecture.md) for the boundaries and [validation](docs/validation.md) for claims linked to executable tests. The [deployment manifest](MANIFEST.md) describes the local deployment and integration responsibilities. The [interactive walkthrough](https://thegenerativecommons.org/activity-container.html) presents recorded Rust executions.

## Run and inspect

Requires Rust 1.99 or later. On a fresh machine, fetch the locked dependencies once with `cargo fetch --locked`; the supplied scripts then run offline. They also find Cargo at `~/.cargo/bin` when it is absent from PATH.

```sh
./demo run --out runs/demo
./demo inspect runs/demo --interactive
./demo verify runs/demo
./check
```

Choose a new output directory for each run; existing runs are preserved. The default is **constitutive / fork / indeterminate**: participants establish the path through commitments, a newcomer proposes a changed interpretation, and the recipient initially leaves its decision unresolved. Here `indeterminate` selects the recipient response, not the outcome of the whole run.

The run exercises all four kernel outcomes, resolves both queues and closes with “Nobody onboarded them. They read the stubs.” Here onboarding means discretionary, participant-specific intervention; automatic admission checks and credential issuance remain visible in the log.

The three movements are:

1. **Constitution.** The parties establish what the agent may do, under which conditions, and how an exception can be authorised. Proposal, acceptance and publication are governed acts. The agent confirms and settles through durable record mocks.
2. **Enforcement.** The optimizer selects a cheaper venue outside its ordinary mandate. The instruction is prevented. An officer proposes a separate exception under its own eligibility rules. It requires acceptance of that exact effect and retains the officer's accountable proof. Approval does not widen the failed ordinary mandate.
3. **Composition and change.** A newcomer discovers published terms, satisfies admission criteria and acts on its own account. Participants can propose a changed interpretation. A disputed interpretation enters a queue for resolution. Adopting changed terms requires the specified consents. An independent recipient validates the attached upstream exception and applies its own refusal, acceptance or unresolved policy.

```sh
./demo run --topology control --composition reuse --downstream refuse --out runs/control-refuse
./demo run --topology constitutive --composition fork --downstream honour --out runs/fork-honour
./demo matrix --out runs/matrix
```

The matrix covers twelve combinations: two topologies, reuse/fork and refuse/honour/indeterminate. Both topologies use the same optimizer, gate and adapters. Both require consent from the principal—the participant granting the agent authority to act on their behalf. The comparison exposes authority and approval differences.

## Read the evidence

Start with `report.json` for the selected branch, then follow decisions and receipts in `events.jsonl` and `peer-events.jsonl`. `discovery.json` contains the public rulebooks, interpretations, commitments and discovery stubs. A stub is a published record pointing to the terms and evidence needed to participate. Use proposal IDs to inspect action records and hashes to look up stored evidence.

```sh
./demo inspect runs/demo stub:0
./demo inspect runs/demo exception
./demo inspect runs/demo queue
./demo replay runs/demo 2b --out runs/replayed-exception
```

Replay executes the Rust flow in a fresh store and compares the complete semantic transcript: the execution record with timing-dependent information removed. Available beats are `constitution`, `1a`, `2a`, `2b`, `3a`, `3b`, `3c` and `close`. `semantic.json` excludes wall-clock time and measured durations so that these comparisons are stable.

| Artifact | Contents |
|---|---|
| `events.jsonl`, `peer-events.jsonl` | Hash-chained action logs with decisions, evidence and receipts |
| `discovery.json` | Public governance material, action-scoped seats and discovery stubs |
| `report.json`, `semantic.json` | Branch, counters and stable execution transcript |
| `primary/state.json`, `peer/state.json` | Host journals, evidence objects, queues and reservations |
| `primary/adapter.json`, `peer/adapter.json` | Durable mock effects under their original replay identities |
| `private/issuers.json` | Private identity simulation state; excluded from public exports |

`verify` recalculates kernel decisions and locally computable assessments, then reconciles journals, receipts, queues, mock effects and exported counters. Identity and standing remain inputs from the verifier boundary. See the [metric definitions and audit scope](docs/architecture.md#auditing-and-metrics).

## Identity, accountability and integration

The model uses authenticated identity or standing, bounded authority and evidence appropriate to the activity. The demo supplies identity and standing through simulated Proof of Honesty (PoH). `Field` checks participant presentations through an issuer verifier. Deployments can implement that integration through existing institutional systems.

The proof producer is the recorded accountable bearer for an action. The record connects that bearer to the governing terms, approvals and consequence references. Participating institutions resolve identity and administer the applicable consequences.

A deployment choosing PoH would replace its simulation with authenticated issuance, live proof verification, revocation and inspection mechanisms. Other deployments can integrate their established identity and accountability systems. The current mock adapter records instructions and confirmations; integration with a real resource supplies the corresponding effectful capability.

The demo fixes one container effect profile and endpoint. A different utility can be implemented by extending or forking the host, profiles and adapters while retaining the authority checks. The [durable effect example](examples/durable_effect.rs) uses a distinct profile at the kernel/host boundary.

## Recovery and developer examples

A deliberate crash exposes the gap between external success and a recorded receipt:

```sh
TGC_DEMO_CRASH_AT=after-external:ordinary ./demo run --out runs/crash-case
./demo recover runs/crash-case
```

The deliberate crash exits with code 86. Recovery reconciles the same replay identity and does not duplicate the mock effect. It completes the reserved attempt; use a fresh run for the complete narrative. Other recovery and authority cases are documented in [validation](docs/validation.md).

Six standalone examples cover activity construction, independent participation, rule interpretation, accountable exceptions, recipient decisions and durable execution:

```sh
cargo run --locked --offline --release --example minimal_activity
cargo run --locked --offline --release --example independent_participant
cargo run --locked --offline --release --example rule_interpretation
cargo run --locked --offline --release --example accountable_exception
cargo run --locked --offline --release --example independent_recipient
cargo run --locked --offline --release --example durable_effect
```

The `authoring` module builds bound instructions and scoped endorsements. `Field` is the implementation name for the Activity Field Container or Activity Container for short. See [Evidence capture](tools/dx/README.md) for generating and checking local recordings.

The vendored kernel's source fingerprints are recorded in [kernel provenance](vendor/kernel-source.json). The demo uses [GCL–0.x](LICENSE); the same kernel's [licence](vendor/constitutive-action/LICENSE) is retained with its source.
