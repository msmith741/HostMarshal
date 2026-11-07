# ADR-0009: MCP is a first-class protocol adapter, not the core

- **Status:** Proposed
- **Date:** 2026-11-07
- **Deciders:** Maintainers (pending review)

## Context

The project targets AI automation clients but should also be useful from scripts, local operators and other future protocols. MCP evolves independently of HostMarshal's operation semantics.

## Decision

Use the official Rust MCP SDK to implement a thin protocol adapter. The core produces a validated capability catalog and accepts verified invocation requests; MCP adds version negotiation/discovery, schema publication, framed errors and transport-specific identity. Target stable **2026-07-28** behavior and test supported older **2025-11-25** clients. Use stdio first, authenticated Streamable HTTP later. Do not use protocol metadata as an authorization claim.

## Alternatives considered

- Put all policy and execution in generated MCP handlers: simple initially, impossible to reuse reliably.
- Write a custom MCP protocol stack: high maintenance and interoperability risk.
- Require MCP for all local commands: unnecessary client dependency and awkward offline validation.

## Consequences

Separate protocol test suite and compatibility matrix; dynamic catalogs and cache invalidation require care. CLI uses the same runtime rather than bypassing policy.

## Security impact

Subject-specific tool catalogs cannot be publicly cached, headers must not bypass payload validation, OAuth tokens must not be passed through to target APIs, and remote identity must be verified.

## Validation

CLI/MCP deny equivalence, dynamic tool discovery, current/legacy wire conformance, private cache behavior, and no protocol-to-adapter bypass.

## References

[Protocol](../PROTOCOL.md), [Official MCP specification](https://modelcontextprotocol.io/specification/2026-07-28).
