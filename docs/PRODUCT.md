# Product definition and requirements

**Status:** proposed; architectural baseline for review. **Audience:** users, contributors, maintainers, and downstream integrators.

## Mission

HostMarshal provides **typed, authorized, auditable infrastructure operations** through reusable adapters and declarative manifests. It should be useful in a laptop lab, a small fleet, a datacenter, or a cloud environment without depending on a particular deployment topology.

## Personas and use cases

- **Operator:** discover approved assets, inspect host state, run troubleshooting operations appropriate to an operator role.
- **Platform administrator:** install and configure adapters; define inventory, policies, limits, and credential providers.
- **Integration author:** publish new operations through documented interfaces without altering HostMarshal core.
- **AI/automation client:** invoke approved operations through MCP (or another transport) without obtaining root, unrestricted SSH, or shared API tokens.
- **Security reviewer:** understand and verify which subject can execute which implementation against which targets.

## Functional requirements

| ID | Requirement | Initial target |
| --- | --- | --- |
| FR-001 | Accept versioned, schema-validated YAML resources with explicit failure diagnostics | M1 |
| FR-002 | Dynamically expose typed capabilities backed by installed, trusted operations | M1 |
| FR-003 | Keep installation, capability publication, and invocation authorization separate | M1–M2 |
| FR-004 | Authenticate/bind caller identity independently of tool arguments | M2; trusted-launcher stdio M1 |
| FR-005 | Resolve resource IDs/labels from trusted inventory and enforce default-deny policies | M1 |
| FR-006 | Route all invocations through the same security-enforcing runtime | M2 |
| FR-007 | Support bounded, typed, read-only observation adapters | M3 |
| FR-008 | Use opaque credentials via provider-neutral broker; never return credentials to clients | M2–M4 |
| FR-009 | Emit audit outcomes and correlation IDs for decisions and execution | M2 |
| FR-010 | Publish CLI validation and policy explanation without live credentials | M1–M2 |
| FR-011 | Support backwards-compatible MCP clients where feasible | M1 |
| FR-012 | Define versioned, isolated external plugin interfaces | M4 |

## Non-functional requirements

- **NFR-001 Security:** default-deny at each authorization boundary; minimum operation privileges are immutable from capability YAML.
- **NFR-002 Reliability:** bounded requests, deadlines, cancellation, and failure-aware audit behavior.
- **NFR-003 Portability:** Linux-first development; a single binary should not require Kubernetes, Vault, or a particular AI client.
- **NFR-004 Testability:** mock adapters and disposable integration targets, reproducible public CI, fault injection.
- **NFR-005 Maintainability:** small stable core, documented contracts, Rust safety idioms, explicit versioning.
- **NFR-006 Observability:** structured, redacted telemetry; stable error codes and correlation IDs.
- **NFR-007 UX:** validation diagnostics identify the resource/path and violated schema or policy invariant.

## Explicit non-goals for initial releases

- General-purpose remote shell, arbitrary Bash/Python execution, automatic host remediation, remote code deployment.
- A full CMDB, scheduler, password manager, orchestration platform, or user-facing shell portal.
- Blanket authorization of an agent to install plugins, publish grants, or write policy.
- A dependency on a specific hypervisor, network controller, cloud, or home domain.
- Production certification or security guarantees before threat-model and release-gate evidence exists.

## Success criteria

A new user with no private infrastructure should be able to author an illustrative Host, Capability, and Grant, validate them offline, see an appropriate MCP catalog entry, and prove both allowed and denied mock executions. Real integrations come **after** this architecture test.

## Definitions

- **Operation:** vetted adapter action with a stable ID, typed contract, minimum risk and enforced runtime permissions.
- **Capability:** administrator-published interface binding input/output schemas and target constraints to an operation.
- **Grant:** policy assignment permitting a verified subject to invoke a capability against eligible targets.
- **Plugin:** separately installed implementation carrying its own trust/provenance and isolation requirements.
