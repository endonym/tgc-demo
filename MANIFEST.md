# Demo deployment architecture

The architecture replaces unconstrained resource access with an explicit, accountable execution boundary. Agents can act within their delegated scope without fresh approval for every action; changing that scope requires the applicable authority and consent.

Each action is checked against its governing terms before execution. Persistent records connect the action to its authority, accountable actor, required approvals and outcome.

## Authority and accountability

In **control mode**, procedure comes from environment authority; in **constitutive mode**, it comes from participant commitments. Both require the applicable grantor's consent.

A receiving peer revalidates an attached upstream exception under its own policy and governs its next action without consulting the originating container. Upstream permission does not replace the recipient's decision.

Records attribute acts to proof-producing seats and preserve consequence references. Participating institutions resolve identity and administer consequences.

## Reference implementation

The demo runs locally in one process, using synthetic credentials, approvals and assets, persistent stores and a mock effect adapter. No external services are contacted.

This implementation supplies identity and standing through simulated Proof of Honesty. Deployments can instead integrate existing institutional systems.

This Proof of Honesty demonstration uses published checks and automatic credential issuance without discretionary, participant-specific onboarding. Institutional identity integrations use their own onboarding process.

## Integration contract

The controlled adapter is the participant API’s sole route to a mock effect. Resource integrations must preserve this boundary: agents must not also hold an unrestricted route to the same resource. This local deployment trusts its operator to supply evidence, resolve authority, interpret rules and maintain the adapter boundary.

See [Validation](docs/validation.md) for reproducible tests and [Evidence capture](tools/dx/README.md) for generating and checking local evidence.
