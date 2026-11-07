# ADR-0004: Dynamic capabilities backed by trusted operation registry

- **Status:** Proposed
- **Date:** 2026-11-07
- **Deciders:** Maintainers (pending review)

## Context

Users should create new public tools in YAML without editing Rust, but arbitrary YAML must not become unrestricted code execution.

## Decision

Distinguish a trusted **operation implementation/descriptor** from a YAML **capability publication**. The installed registry defines immutable operation identity/version/digest, type contracts, intrinsic effects, minimum privileges, target kinds and runtime maxima. YAML references an installed operation, creates a named interface, selects exposure and **narrows** input/target/budget restrictions. Runtime registration exposes capabilities dynamically to MCP. No arbitrary executable/shell or URL fields are valid.

## Alternatives considered

- Hard-coded enum and MCP handler per capability: secure-ish and simple but not extensible.
- User-defined shell command in YAML: flexible but arbitrarily powerful and hard to constrain.
- Download/execute plugin automatically on manifest load: dangerous code-loading trust violation.

## Consequences

New behavior requires vetted built-in primitives or separately installed plugins; arbitrary new schemas and bindings do not. Registry and capability lifecycle need stable identity and versioning.

## Security impact

A YAML risk label cannot downgrade operation classification. Capability definitions grant no invocation permission and cannot change installed plugin permissions.

## Validation

Two different YAML capabilities bind one mock adapter without Rust changes; an unknown operation and attempted privilege override are rejected; unauthorized grants never invoke the adapter; descriptor digest changes trigger reapproval.

## References

[Capabilities](../CAPABILITIES.md), [Architecture](../ARCHITECTURE.md).
