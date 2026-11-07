# ADR-0007: Verified identity and default-deny authorization

- **Status:** Proposed
- **Date:** 2026-11-07
- **Deciders:** Maintainers (pending review)

## Context

The prototype trusts a launcher-set string and stdio process boundary. A public service needs identity verification, target-level grants and a mechanism for varied deployment models.

## Decision

Establish subject identity from a **trusted local launcher/OS context** for stdio or standards-based authenticated network transport for remote clients. Never treat MCP `clientInfo`, tool arguments or unverified HTTP headers as authenticated identity. Authorize subject + capability + resolved operation + target + context using a default-deny interface. Initial engine supports exact names and trusted-label selectors; advanced policy languages can be adapters after conformance testing.

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
