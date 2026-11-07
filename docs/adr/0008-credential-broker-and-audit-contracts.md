# ADR-0008: Credential broker and audit contracts

- **Status:** Accepted
- **Date:** 2026-11-07
- **Deciders:** Project maintainer (M2 design review, 2026-11-07)

## Context

Real integrations need credentials, and security-focused operations need trustworthy evidence. Binding the core to one vault or logging vendor limits adoption.

## Decision

Define provider-neutral credential and audit interfaces. The trusted runtime requests a credential **only after authorization** and only for the approved target/operation purpose. Providers return scoped handles or narrowly bounded secrets to adapters, not MCP clients. Audit events contain caller, decision, target, operation/config/policy digest, timing, outcome and correlation ID; never raw tokens or unbounded output. Providers and audit sinks are separately configured.

## Acceptance clarifications

- M2 ships a `CredentialBroker` interface, opaque scoped leases, and a production **deny-all** broker. Real Vault/cloud/local secret providers, renewal, and revocation are **not** implemented or approved.
- M2 commits redacted `Authorized` audit events **before** credential access and adapter execution; an audit failure blocks that operation. A failed completion audit suppresses the response but cannot reverse an already-completed action, so all mutation remains prohibited.
- Default audit goes to stderr; the optional file sink appends JSON Lines, checks restrictive file permissions, and calls `sync_data`. This is **not** tamper-evident, remote durable, or independent of the host administrator.
- No user-provided command or arbitrary plugin is accepted. Built-in static observations and test mocks are the only M2 execution paths.

## Alternatives considered

- Long-lived API tokens in YAML: simple but high exfiltration risk.
- Make Vault mandatory: strong options but vendor/deployment coupling.
- Best-effort stdout logging only: cannot support mandatory-audit operation classes.

## Consequences

Need careful error types, outages, redaction, rotation/revocation and implementation-specific least privilege. Initial M1 mock/inventory operations may use no credentials and local/test audit implementations.

## Security impact

Do not substitute broader credentials if a provider is unavailable. Define **pre-execution audit-commit/fail-closed** policy before live privileged operations; a plain application log is not necessarily tamper-evident.

## Validation

Auth failure accesses no provider; no secret appears in outputs/errors/logs; broker outage denies execution; mandatory audit sink failure blocks protected operation; credential/target scopes cannot be swapped.

## References

[Security](../SECURITY_ARCHITECTURE.md), [Adapters](../ADAPTERS.md).
