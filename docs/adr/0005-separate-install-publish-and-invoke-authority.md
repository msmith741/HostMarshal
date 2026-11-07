# ADR-0005: Separate install, publish and invoke authority

- **Status:** Accepted
- **Date:** 2026-11-07
- **Deciders:** Project maintainer (design review, 2026-11-07)

## Context

An AI agent may legitimately inspect a host but must not be able to install its own plugin, publish a new capability, grant permissions, or swap the backend implementation.

## Decision

Treat **installation** (approved code/operation permissions), **publication** (versioned capability manifests), and **invocation** (verified caller/target grants) as distinct administrative authorities and trust boundaries. They may be assigned to one administrator in small deployments but never become the same unchecked API operation. Client invocation cannot mutate executable configuration or its own authorization.

## Acceptance clarifications

- The role separation is a security invariance **even for single-admin local deployments**. M1 has no plugin installation or runtime grant-modification API; controlling file deployment remains a trusted OS/launcher responsibility.
- Runtime callers cannot supply/modify identity, grants, configuration directories, or installation package paths through MCP. A capability's existence is never authorization.
- Administrative installation, publication approvals, revocation and policy-change audit workflows require later dedicated implementation and test evidence.

## Alternatives considered

- Single admin role used for everything: easier to implement but no separation of duties.
- Every YAML capability automatically available to every MCP client: breaks least privilege.
- Depend on AI prompt instructions to avoid unsafe changes: unenforceable.

## Consequences

Three lifecycle processes and explicit approval/revocation rules; extra UX work for small deployments. Allow a single trusted administrator to perform all three without making roles indistinguishable in the engine.

## Security impact

Policy/configuration writes must be separately authenticated; no privilege escalation through tool catalog, grants, metadata or plugin upgrades. Audit these changes.

## Validation

A capability author cannot install plugins or grant access; an invoker cannot alter published manifest or grants; removal of a grant makes invocation fail even when capability stays published.

## References

[Security](../SECURITY_ARCHITECTURE.md), [Configuration](../CONFIGURATION.md).
