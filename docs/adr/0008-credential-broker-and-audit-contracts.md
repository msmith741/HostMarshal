# ADR-0008: Credential broker and audit contracts

- **Status:** Proposed
- **Date:** 2026-11-07
- **Deciders:** Maintainers (pending review)

## Context

Real integrations need credentials, and security-focused operations need trustworthy evidence. Binding the core to one vault or logging vendor limits adoption.

## Decision

Define provider-neutral credential and audit interfaces. The trusted runtime requests a credential **only after authorization** and only for the approved target/operation purpose. Providers return scoped handles or narrowly bounded secrets to adapters, not MCP clients. Audit events contain caller, decision, target, operation/config/policy digest, timing, outcome and correlation ID; never raw tokens or unbounded output. Providers and audit sinks are separately configured.

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
