# Validation

Run the locked, offline workspace suite from the demo directory:

```sh
./check --no-fail-fast
```

The recorded validation on **23 October 2026** passed 104 workspace test results and 48 standalone kernel test results, with zero failures or ignored tests. The suites overlap and are not additive counts of distinct obligations. That capture also passed all twelve narrative branches and 32 governance crash/recovery cases, executed all six example main functions and passed both formatting checks. These are dated results; running the commands below produces evidence for the current checkout.

## Claims and executable evidence

| Claim | Executable evidence |
|---|---|
| Delegation requires the principal's consent to the exact governance action in both topologies; changes require consent from the affected grantors | [Delegation-consent tests](../tests/delegation_consent.rs), including `both_topologies_require_the_grantor_for_constitution_and_activation` and `amendments_require_old_and_new_grantors_including_removal` |
| An officer's approval cannot widen a failed ordinary mandate; an exception needs its own exact acceptance | `exception_requires_exact_officer_acceptance_and_cannot_widen_mandate` in [protocol tests](../tests/protocol.rs) |
| Changing the payload, destination, interpretation, route or proof binding prevents dispatch under the earlier decision | `exact_effect_and_metadata_binding_reject_tampering_without_dispatch` in [protocol tests](../tests/protocol.rs) |
| New credential holders and a newly published moderator can participate without field registration | `newcomer_is_not_a_fixture_membership_list` and `selected_lead_accepts_another_published_moderator_without_field_registration` in [protocol tests](../tests/protocol.rs) |
| A recipient validates upstream authority under its own policy | `peer_rejects_unapproved_upstream_even_when_its_own_policy_honours` in [protocol tests](../tests/protocol.rs), plus the [independent recipient example](../examples/independent_recipient.rs) |
| A proposed interpretation must respect inherited rules and complete the required resolution process before promotion | Rulebook, illegal-fork and promotion tests in [protocol tests](../tests/protocol.rs), plus the [interpretation example](../examples/rule_interpretation.rs) |
| Unresolved required conditions cannot produce permission, even when another condition fails; evaluation order does not change that result | [Container contract tests](../tests/container_contract.rs) and [kernel contract tests](../tests/kernel_contract.rs) |
| Reservation ordering, recovery and replay preserve the admitted effect and original replay identity | [Persistent host and conformance test](../src/store.rs), [authority lifecycle tests](../tests/authority_lifecycle.rs), [CLI crash tests](../tests/cli.rs) and the [durable effect example](../examples/durable_effect.rs) |
| Pending decisions and queues survive process crashes and reopening | [Queue recovery tests](../tests/queue_recovery.rs) |
| Local verification rejects altered assessments and reconciles journals, effects and exports | [Assessment audit tests](../tests/audit_assessments.rs) and [local audit tests](../tests/local_audit.rs) |
| All twelve branches execute; repeated default runs produce identical execution records after timing-dependent information is removed | `all_twelve_topology_composition_recipient_combinations` and `repeat_runs_have_identical_semantic_transcripts` in [protocol tests](../tests/protocol.rs) |

The tests also cover proof expiry and epoch checks, simulated credential revocation, authority withdrawal, admission predicates, host-derived usage counts and time-window checks. They also cover preservation of earlier commitments, event-history checks and reopening. [Architecture](architecture.md) defines these boundaries and the literal exported metrics.

## Capture reproducible evidence

[The verification runner](../tools/verify.py) captures the workspace suite, standalone kernel suite, formatting checks and six examples into a new directory:

```sh
python3 tools/verify.py --out /tmp/tgc-verification
```

Full capture requires Python 3, Rust with cached locked dependencies and the sibling `ConstitutiveActionKernel` checkout. Choose an output path that does not already exist. The runner retains commands, logs, test stores, source/test inputs and SHA-256 fingerprints. It checks that every command passed, the two kernel source copies match and the captured inputs did not change during execution. `./check` needs only this demo checkout and its vendored kernel.

To inspect a freshly generated scenario separately:

```sh
./demo run --out runs/verification-demo
./demo verify runs/verification-demo
./demo replay runs/verification-demo 3c --out runs/verification-replay
```

## Scope

This is a runnable implementation of the container's decision-to-effect path. The tests exercise constituted authority, exact consent, proof expiry and epoch checks, simulated credential revocation, authority withdrawal, controlled local effects, recovery and the evidence they leave. Identity, standing, attestations and human responses are supplied by local fixtures, including simulated Proof of Honesty. A production integration can connect trusted sources and a real resource adapter while retaining the same action boundary.

The application runs locally. Concurrency and crash/recovery tests also exercise the host reservation and adapter boundary. They are evidence for the behaviours listed above, not a throughput benchmark. The [deployment manifest](../MANIFEST.md) sets out the operator's integration responsibilities.
