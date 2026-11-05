# Manifest

This is the Manifest the [licence](LICENSE) requires for this deployment. The architecture replaces unconstrained resource access with an explicit, accountable execution boundary. Agents act within their delegated scope without fresh acceptance for every action; changing that scope requires the applicable authority and consent. Each action is checked against its governing terms before execution, and persistent records connect it to its authority, accountable actor, required acceptances and outcome.

## Where rules and execution are fused

In this local deployment one operator runs everything: the host that supplies evidence, resolves authority and interprets rules, and the isolated adapter that is the participant API's sole route to a mock effect. The demo runs in one process with synthetic credentials, acceptances and assets, persistent stores and a mock effect adapter. No external services are contacted.

## Who exercises that control

The operator of the local checkout. Within an activity, under control one controller can change the terms; under constitutive authority every owner named in the terms must accept a change. Both require the grantor's consent to delegation, and any owner can withdraw a path alone. A receiving peer revalidates an attached upstream exception under its own policy; upstream permission does not replace the recipient's decision. Records attribute each action through its producer's proof and retain the applicable consequence references; participating institutions resolve identity and administer consequences.

## How to reproduce or contest it

Run `./demo verify` to recalculate decisions and reconcile records, `./demo replay` to re-execute a beat in a fresh store, and the [validation](docs/validation.md) suite for each claim and its tests. [Evidence capture](tools/dx/README.md) generates and checks local recordings. Contest the source through the repository's issue tracker. Resource integrations must preserve the adapter boundary: agents must not also hold an unrestricted route to the same resource.

## Identity

Identity and standing come from simulated Proof of Honesty, with published checks and automatic credential issuance and no discretionary, participant-specific onboarding. Deployments can instead integrate existing institutional systems, which use their own onboarding.
