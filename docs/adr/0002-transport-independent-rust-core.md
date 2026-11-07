# ADR-0002: Transport-independent Rust core

- **Status:** Proposed
- **Date:** 2026-11-07
- **Deciders:** Maintainers (pending review)

## Context

The bootstrap prototype embeds compiled MCP handlers directly in its service. This would entangle policy, execution and protocol evolution.

## Decision

Build an independent Rust domain/runtime API with separate configuration, inventory, authorization, credential, audit, and operation interfaces. MCP and CLI adapters translate requests into validated core calls; both use a single security-enforcing coordinator. Begin as one deployable process, splitting modules into crates only when justified by stable ownership boundaries.

## Alternatives considered

- MCP-first compiled handlers: small but every new capability requires recompilation and transport-specific logic.
- Distributed microservices from the start: flexibility at the cost of unnecessary network trust boundaries and operational complexity.

## Consequences

Extra interface work up front, simplified testability, and less protocol lock-in. Transport adapters cannot call execution providers directly.

## Security impact

Authorizations are enforced centrally and cannot be bypassed by a new protocol endpoint. Caller identity is established at transport entry and carried as an immutable context, not a field controlled by a tool call.

## Validation

Same mock operation and deny behavior through CLI and MCP; core unit tests compile without MCP SDK types; static analysis/review finds no direct adapter invocation in transport code.

## References

[Architecture](../ARCHITECTURE.md), [Protocol](../PROTOCOL.md).
