# ADR-0001: Vendor-neutral product boundary

- **Status:** Proposed
- **Date:** 2026-11-07
- **Deciders:** Maintainers (pending review)

## Context

An infrastructure operations tool can become coupled to one operator's homelab, one AI agent, or a particular secret provider. A public project must remain deployable outside those assumptions.

## Decision

Define HostMarshal as a vendor-neutral, policy-governed **infrastructure capability engine**. The core contains no hardcoded domains, hostnames, local addressing, hypervisor, cloud, AI-client, secret-provider, or Kubernetes dependencies. MCP is one transport; Rust and a small local deployment are the initial implementation constraints. First releases prioritize vetted read-only operations.

## Alternatives considered

- Build a dedicated agent-specific SSH MCP server: simplest short term but overprivileged and poorly reusable.
- Build a full infrastructure management/orchestration suite: broader but dilutes security and multiplies complexity before the execution boundary is proven.

## Consequences

Adapters must carry integrations. Documentation and CI use portable fictional fixtures. CLI and validation work without external infrastructure. Non-goals include a full CMDB, interactive shell, general-purpose scheduler and unattended remediation.

## Security impact

Narrow, explicit authority is a product requirement; no private infrastructure controls are promoted into public defaults.

## Validation

An external contributor can reproduce M1 examples with no private devices or credentials. Tests demonstrate a mock operation used via multiple client adapters and no hidden vendor assumptions.

## References

[Product](../PRODUCT.md), [Roadmap](../ROADMAP.md).
