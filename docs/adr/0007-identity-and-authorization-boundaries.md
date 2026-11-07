# ADR-0007: Verified identity and default-deny authorization

- **Status:** Accepted
- **Date:** 2026-11-07
- **Deciders:** Project maintainer (M2 design review, 2026-11-07)

## Context

The prototype trusts a launcher-set string and stdio process boundary. A public service needs identity verification, target-level grants and a mechanism for varied deployment models.

## Decision

Establish subject identity from a **trusted local launcher/OS context** for stdio or standards-based authenticated network transport for remote clients. Never treat MCP `clientInfo`, tool arguments or unverified HTTP headers as authenticated identity. Authorize subject + capability + resolved operation + target + context using a default-deny interface. Initial engine supports exact names and trusted-label selectors; advanced policy languages can be adapters after conformance testing.

## Acceptance clarifications

- The first shipped `AuthenticatedCaller` only models a **trusted local process launcher**; it is **not** an authentication mechanism for an arbitrary remote/stdin client. Future OIDC/mTLS credential verification is a separate interface and test gate, not implied by this acceptance.
- The M2 `Authorizer` contract is a default-deny exact issuer/subject/capability/operation/target check. Trusted-label selection and rich policy languages are deferred.
- The identity source must not be a tool parameter. The same authorization decision applies across both supported MCP wire eras, and legacy unaudited handlers must be removed. Offline `policy explain` is a local simulation/diagnostic with no execution authority, controlled by OS access to the configuration.

## Alternatives considered

- Authentik/Vault-specific user directory or roles: environment-coupled.
- Permit by tool name only: no resource/operation binding.
- Adopt a complex policy language immediately: delays testing and may obscure basic boundary errors.

## Consequences

The identity transport and policy interfaces must be testable independently. Caller metadata may be useful for diagnostics but is not authority. Policy explanations require trusted admin access.

## Security impact

Audience/issuer/signature/time checks on network tokens, strict subject binding, fail-closed denials, revocation semantics and non-disclosing errors. Inventory labels cannot come from client input.

## Validation

Spoofed identities, unknown issuer/audience, missing grants and unauthorized resources denied; policy behavior matches across stdio, CLI and future HTTP.

## References

[Security](../SECURITY_ARCHITECTURE.md), [Protocol](../PROTOCOL.md).
