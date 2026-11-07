# ADR-0010: Independent contract versions and compatibility

- **Status:** Proposed
- **Date:** 2026-11-07
- **Deciders:** Maintainers (pending review)

## Context

A stable public ecosystem needs predictable updates to resource schemas, capability names, installed operation descriptors, plugin interfaces, and MCP support. These evolve on different schedules.

## Decision

Version separately: (1) HostMarshal release, (2) YAML resource `apiVersion`, (3) capability/operation identity and major version, (4) external plugin protocol, and (5) negotiated MCP protocol. Publish compatibility policy and migration fixtures before stable releases. No silent privilege widening, executable implementation substitution, or grant inheritance across changed operation digests.

## Alternatives considered

- Version every contract with the binary: forces unnecessary ecosystem lockstep.
- Unversioned YAML and rolling latest adapters: simpler but breaks clients and hides privilege changes.
- Guarantee stable APIs now: premature while contracts are proposed and not implemented.

## Consequences

More validation, docs and upgrade testing. Before v1 stability, breaking changes are allowed with explicit migration notes; after stabilization, apply semantic compatibility rules appropriate to each contract.

## Security impact

Reject unsupported versions, require approval of authority-widening changes, and provide revocation-aware cache invalidation. Adapter capability descriptions and output schemas must not silently change under a previously approved permission.

## Validation

Golden migration fixtures, version mismatch errors, changed-digest reapproval tests, backward-compatible client interoperability tests, and stable release changelogs.

## References

[Configuration](../CONFIGURATION.md), [Development workflow](../DEVELOPMENT_WORKFLOW.md), [Roadmap](../ROADMAP.md).
