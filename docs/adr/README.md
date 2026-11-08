# Architecture decision records

**Status:** ADR-0003–0008 and ADR-0011 are Accepted with explicit scope/security clarifications. ADR-0001, 0002, 0009 and 0010 remain Proposed. Acceptance is a design decision, not proof that future controls are implemented.

| ID | Title | Status |
| --- | --- | --- |
| [0001](0001-vendor-neutral-product-boundary.md) | Vendor-neutral product scope | Proposed |
| [0002](0002-transport-independent-rust-core.md) | Transport-independent Rust core | Proposed |
| [0003](0003-versioned-yaml-resources.md) | Versioned declarative configuration | Accepted |
| [0004](0004-dynamic-capabilities-and-operation-registry.md) | Dynamic capabilities and trusted operation registry | Accepted |
| [0005](0005-separate-install-publish-and-invoke-authority.md) | Separate installation, publication and invocation authority | Accepted |
| [0006](0006-typed-adapters-and-external-isolation.md) | Typed adapters and plugin isolation | Accepted |
| [0007](0007-identity-and-authorization-boundaries.md) | Identity and authorization interfaces | Accepted |
| [0008](0008-credential-broker-and-audit-contracts.md) | Credential broker and audit contracts | Accepted |
| [0009](0009-mcp-is-a-protocol-adapter.md) | MCP as a protocol adapter | Proposed |
| [0010](0010-versioning-and-compatibility.md) | Versioning and compatibility | Proposed |
| [0011](0011-readonly-network-observation.md) | Restricted read-only SSH/HTTPS network observation | Accepted |
| [0012](0012-m4-remote-identity-and-credential-providers.md) | Remote identity and provider security boundaries | Proposed |

## How to use ADRs

- Create a new proposal from [TEMPLATE.md](TEMPLATE.md). Include context, alternatives, consequence, security impact, and verification.
- Decisions are `Proposed`, `Accepted`, `Rejected`, `Deprecated`, or `Superseded`.
- Acceptance requires explicit maintainer review; proposal documents may evolve while proposed.
- Once accepted, decisions are historical: never rewrite them silently to justify later code. Supersede with a new ADR linking both decisions.
- ADRs do not make unimplemented capability security controls real. Implementation and negative-path tests are mandatory before release.

See [development workflow](../DEVELOPMENT_WORKFLOW.md) for approvals and change control.
