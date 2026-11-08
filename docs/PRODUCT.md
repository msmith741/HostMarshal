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
| FR-007 | Support bounded, typed, read-only observation adapters | M2 built-in mock; M3 live |
| FR-008 | Use opaque credentials via provider-neutral broker; never return credentials to clients | M2–M4 |
| FR-009 | Emit audit outcomes and correlation IDs for decisions and execution | M2 |
| FR-010 | Publish CLI validation and policy explanation without live credentials | M1–M2 |
| FR-011 | Support backwards-compatible MCP clients where feasible | M1 |
| FR-012 | Define versioned, isolated external plugin interfaces | M5 |
| FR-013 | Publish versioned config schemas with independent conformance and drift checks | M1 |
| FR-014 | Atomically activate validated snapshots and define emergency revocation semantics | M1 |
| FR-015 | Lock application dependencies and exercise parser fuzzing and supported MCP eras | M1 |
| FR-016 | Enforce pinned SSH host identity, dedicated target-scoped key access, fixed Linux observation and bounded output | M3 |
| FR-017 | Enforce approved HTTPS-only health probes, validated TLS identity, no redirects/proxies or untrusted response-body exposure | M3 |
| FR-018 | Verify remote MCP identity independently on each HTTP request with signed access tokens, issuer/audience/scope/lifetime constraints and default-deny tool grants | M4 |
| FR-019 | Route credential acquisition by exact approved operation/target/purpose without fallback across providers | M4 |
| FR-020 | Issue verified short-lived SSH user certificates through a scoped Vault SSH signing provider, with ephemeral key lifecycle, strict principal/key/CA/TTL checks and no fallback | M4 |
| FR-021 | Audit HTTP authentication and transport/protocol rejections with sanitized reason codes and no unverified identity attribution; fail closed on rejection-audit failure | M4 |
| FR-022 | Authenticate a Vault SSH signing workload with protected AppRole credentials, exact token policy and bounded on-demand self-renewal; quarantine on renewal/token rejection without static-token fallback | M4 |
| FR-023 | Rotate remote JWT verification keys from an administrator-pinned HTTPS JWKS endpoint with pinned CA, strict key validation, bounded refresh, and no stale-on-error fallback | M4 |
| FR-024 | Publish RFC 9728 OAuth protected-resource metadata and a resource_metadata-bearing 401 challenge without treating discovery as authentication | M4 |
| FR-025 | Require authenticated local reverse-proxy attestation for ingress mode (HTTPS scheme, exact public Host, protected proof) and deny direct-backend bypass, with sanitized audit | M4 |
| FR-026 | Verify administrator-pinned OAuth/OIDC authorization-server discovery over trusted HTTPS at startup, including exact issuer, JWKS URI, endpoint origin, and supported machine-client grant; reject mismatched metadata | M4 |
| FR-027 | Test a production-shaped TLS reverse proxy and isolated MCP backend against a real OAuth issuer, covering token acquisition, issuer/audience/scope checks, TLS trust and network bypass via independent CI | M4 |
| FR-028 | Validate real K3s multi-node Flannel, K3s-managed Traefik, and an isolated local-only HostMarshal deployment in disposable CI without any private cluster access | M4 |
| FR-029 | Maintain HostMarshal loopback binding inside an unprivileged Kubernetes Pod sidecar boundary, with TLS public Host routing, protected ingress attestation and a ClusterIP-only service | M4 |
| FR-030 | Prove cross-node/namespace NetworkPolicy isolation with positive connectivity controls, a deliberately unsafe additive-policy positive control, and restored denial after rollback | M4 |
| FR-031 | Authenticate optional Vault SSH-signing workloads using an administrator-selected, externally issued JWT and Vault's role-bound JWT auth method; pin Vault TLS, require exclusive credential source and exact renewable lease policy, quarantine on failure, and do not expose or log tokens | M4 |
| FR-032 | For an active renewable Vault AppRole or JWT signing lease, proactively renew in process before expiry after first authorized use, serialize with foreground operations, validate unchanged token and exact policy, and quarantine on failed renewal without retry/fallback | M4 |
| FR-033 | Permit opt-in recovery from quarantined Vault AppRole/JWT signing lease only after a strictly increased administrator-controlled recovery epoch and fresh authenticated Vault login, preventing stale-token reuse, epoch rollback, or automatic recovery; otherwise require restart | M4 |
| FR-034 | Audit every AppRole/JWT Vault token renewal and operator-gated recovery attempt with correlated, fixed, redacted precommit and terminal records through the launch-owned audit sink; reject credential use or recovery if a required audit commitment fails | M4 |
| FR-035 | Optionally deliver all audit events through a launcher-configured, provider-neutral, finite-capacity dispatcher that requires underlying sink acknowledgment, bounds each caller wait/event size, and latches fail-closed on overload, writer errors or timeout without fallback | M4 |
| FR-036 | Use a self-tested conservative change-impact CI policy to run narrow integration suites only for relevant paths, fall back to full tests on ambiguity or shared security changes, and require scheduled/manual full release gates | M4 |

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
