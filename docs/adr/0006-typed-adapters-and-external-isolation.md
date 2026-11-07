# ADR-0006: Typed adapters and process-isolated external plugins

- **Status:** Proposed
- **Date:** 2026-11-07
- **Deciders:** Maintainers (pending review)

## Context

Integrations must support machines and APIs not envisioned by core maintainers. Running arbitrary third-party native code inside the privileged HostMarshal process would undermine the policy boundary.

## Decision

Expose typed operation adapter contracts, with trusted built-in implementations first. Defer public external plugins until a **versioned out-of-process protocol** and independently enforced OS isolation model are implemented. A privileged installer approves package provenance, immutable digest, runtime egress/filesystem/process rights and credential scopes. Plugin descriptors cannot raise permissions at invocation.

## Alternatives considered

- Require all adapters upstream: slow and vendor-coupled.
- Native dynamic libraries loaded in-process: high performance but collapse isolation and complicate ABI safety.
- Arbitrary scripts/containers selected by clients: flexible but insufficiently bounded without strict deployment trust and sandbox controls.

## Consequences

Additional supervisor/IPC, packaging and sandbox maintenance. Plugin API compatibility needs its own version separate from HostMarshal and MCP. External plugins are a **later** milestone, not an M1 promise.

## Security impact

Signatures establish provenance, not safety. The host OS and target credentials must constrain malicious plugin behavior. Limit filesystem, network, process and credential reach, and independently validate adapter output.

## Validation

Malicious test plugin denied undeclared network/secret access; process crashes are isolated; version/digest upgrades require approval; cancellation and deadlines are enforced externally.

## References

[Adapters](../ADAPTERS.md), [Roadmap](../ROADMAP.md).
