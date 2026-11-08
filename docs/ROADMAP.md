# Development roadmap

**Status:** proposed; milestone criteria define completeness, not an implementation claim. No time estimates or release dates are committed.

## M0 — Architecture baseline (documentation-only)

**Deliverables:** product scope, threat model, layered design, ADRs, YAML resource contract, capability and adapter model, coding/test standards, roadmap, minimal illustrative examples.

**Exit:** contracts are coherent and reviewed; every important security privilege boundary has an owner. Existing prototype gaps are explicitly recorded. **This documentation PR targets M0.**

## M1 — Declarative core and mock integration

- Strict `v1alpha1` YAML parsing, version validation, duplicate-key checks, reference resolution, immutable registry snapshot.
- Stable domain model, inventory and policy types; exact-target default-deny.
- Dynamic MCP tool registration and typed schemas; offline CLI config validation and inspection.
- Small built-in mock/inventory operation catalog, **not** general shell execution.
- Refactor the merged hard-coded bootstrap implementation against these contracts; add checked-in `Cargo.lock`.

**Progress (partial):** versioned strict YAML parsing, one trusted static-inventory operation, local launcher identity, dynamic MCP listing/invocation, and validation CLI are being implemented in the first M1 slice. A generated machine-readable resource schema, parser security budgets, and a SHA-256 effective snapshot digest are implemented in the next M1 slice. Checked-in versioned schemas, independent schema-conformance CI and `Cargo.lock` are now added. Runtime atomic SIGHUP reload and SIGUSR1 emergency deny are now supported for trusted Unix stdio deployments. Parser fuzzing and a two-era MCP **stdio** conformance matrix are now implemented, including a bounded coverage-guided target and scheduled fuzz workflow. Legacy JSON bootstrap retirement is addressed in M2; typed built-in adapter contracts are implemented in M2. Future authenticated HTTP conformance remains open.

**Gate:** adding a YAML-only capability over an existing vetted mock operation needs no Rust change; authorized calls succeed and denied calls never reach the adapter; malformed or privilege-escalating manifests fail load. Test at least one legacy and the current supported MCP version.

## M2 — Security-enforcing execution runtime

- Immutable operation descriptors; verified caller context; one invocation pipeline.
- Typed adapter trait, target binding, limits, cancellation and structured error contracts.
- Audit sink contract, redaction, correlation IDs, denied/error audit paths and failure policy.
- Credential broker *interface* with mock secrets; scoped handles and no response leakage.
- Policy-explain CLI and formal adversarial test suite.

**M2 implementation:** `src/runtime.rs`, `src/authorization.rs`, `src/identity.rs`, `src/adapter.rs`, `src/credentials.rs`, and `src/audit.rs` now provide a central, typed, bounded and auditable execution path for the *only* built-in static-inventory operation. CI includes broker-scope, timeout, output-integrity, audit-failure and stdio JSONL integration tests. The local `policy explain` diagnostic and negative tests complete the M2 administrative-policy inspection interface. The old unaudited JSON handlers were retired rather than left as an authorization bypass.

**Gate:** mock adapters cannot escape authorization, substitute endpoints/credentials, or modify intrinsic operation risk; audit and failure-mode tests pass. This gate applies to the trusted static-inventory/M2 mock environment, **not** real Linux/Proxmox/network operations, which remain prohibited until later security gates.

## M3 — Real observation adapters

- Restricted Linux observation operations and secure SSH transport with pinned host identity.
- Constrained HTTP API observation with approved endpoints, TLS, method/redirect/response restrictions.
- Integration suites using disposable VMs/containers and mock API services.

**M3 implementation:** the vetted `builtin.linux.uname/v1` and `builtin.https.health/v1` operations are compiled into the trusted catalog, with explicit Host transport fields, strict schema equality, broker/adapter deadlines and auditable invocation. Linux observation uses OpenSSH with a verified pinned host key and protected per-target local key mapping; HTTPS uses Rustls, a fixed GET /health, strict TLS certificate validation, optional CA trust, and no proxy, redirect or response body exposure. CI runs disposable non-privileged SSH and locally signed TLS services with denial, key/cert mismatch, target substitution, injection, redirect and deadline tests. See [M3 deployment](OBSERVATION_ADAPTERS.md) and [ADR-0011](adr/0011-readonly-network-observation.md).

**Gate:** no unrestricted command tool; no credentials in output; denial, target-swap, client-controlled-URL/SSRF and timeout tests pass; real read-only targets can be inspected with least privilege. **Boundaries:** this proves the M3 approved operation subset only; neither transport grants mutation rights, guarantees remote cancellation, nor implements a remote identities/secrets service.

## M4 — Credential providers and remote transports

- Optional secret providers and leasing semantics; integration with one example provider.
- Authenticated MCP Streamable HTTP, authorization-server and audience validation, network hardening.
- Additional provider-neutral reference adapters (e.g., a hypervisor API) only after M2/M3 controls.

**M4 progress:** a fail-closed, exact operation/target/purpose credential provider router and negative-path unit tests have been added. The HTTP middleware now writes sanitized, fail-closed authentication/protocol denial records to the configured audit sink (FR-021), without claiming completeness outside the process middleware. A second vertical slice adds loopback-only stateless Streamable HTTP with per-request signed-JWT authentication via pinned local JWKS and an issuer/subject-aware caller. Production TLS ingress deployment and bypass validation, full OAuth federation/discovery and workload-token lifecycle remain open; experimental pinned-HTTPS JWKS rotation, OAuth resource metadata and local TLS-proxy attestation have separate CI suites; restricted AppRole/JWT signing leases now use bounded proactive renewal and optional operator-gated recovery. These are **pre-alpha slices** only, not full M4: authenticated HTTP and scoped Vault SSH signing are opt-in, and real Vault 2.2.1 dev-server compatibility has passed CI, while production identity provisioning and ingress release gates remain outstanding. See [M4 implementation gates](M4_IMPLEMENTATION_PLAN.md) and [proposed ADR-0012](adr/0012-m4-remote-identity-and-credential-providers.md).

**Gate:** multiple identities, policy scopes and secret backends can be configured without source code changes or assumptions about infrastructure.

**M4 Vault SSH slice:** an opt-in pinned-CA, TLS-only Vault SSH signing broker now generates ephemeral keys for the fixed Linux observation, validates short-lived signed user certificates and cleans lease-owned key files on completion/cancellation. A Vault-API-compatible local TLS fixture and real OpenSSH CA/sshd provide positive/negative integration coverage; **a real Vault 2.2.1 TLS dev-server plus restricted signing token and genuine SSH login now pass a dedicated CI job**, while production workload-identity provisioning, independently audited maintenance events, CA rotation, interactive OAuth federation and production ingress bypass testing remain unfinished; pinned JWKS refresh, RFC 9728 resource metadata and disposable TLS-ingress tests now exist. Exclusive AppRole and external JWT signing authentication (FR-022/031) now include the FR-032/033 lifecycle and operator-gated recovery increment. See [Vault SSH operations](VAULT_SSH.md).

## M5 — External extension ecosystem

- Versioned adapter SDK and process-isolated plugin protocol.
- Plugin installation/trust/permission declarations; sandbox and failure isolation.
- Optional restricted recipe language after separate threat-model review.
- Schema compatibility and conformance fixtures for third-party authors.

**Gate:** a developer ships a new protocol adapter independently; an administrator can install/approve it; unauthorized invocation or undeclared effects remain blocked.

## M6 — Public beta and stabilization

- Release artifacts for supported platforms; signed provenance, SBOM, dependency audits.
- Migration guidance, user and plugin documentation, configuration-schema stability.
- Verified public CI, end-to-end integration/security suites, operational runbooks.

**Gate:** outside contributors can install, extend, troubleshoot and upgrade using only public documentation, with independent security review of execution paths.

## Out of scope until independently designed

Writes, restarts, high-privilege changes, destructive actions, interactive shells, unattended remediation, and approvals/delegation. These require separate risk models, authorization, approvals bound to exact requests, and additional release gates.

## Dependency chain

M0 → M1 → M2 → M3. M4 depends on M2 and transport security readiness. M5 depends on M2 and sandbox design. M6 requires evidence from every supported interface and adapter.

## Release and change policy

These are **milestones**, not promised semantic versions. No stable 1.0 API or production-support claim is established. All public interfaces get explicit versioning and deprecation rules before release. See [development workflow](DEVELOPMENT_WORKFLOW.md) and [ADRs](adr/README.md).

**M4 FR-026/FR-027 extension:** Optional pinned OIDC authorization-server discovery is checked against the configured issuer/JWKS and OAuth endpoint origin at startup. A dedicated GitHub Actions job adds disposable real-Keycloak client-credentials token issuance and an isolated Traefik TLS-only ingress/backend topology, with negative network/TLS/header tests. These are CI acceptance checks for the reference design, not a production deployment or proof of the user's network configuration. Next release gates: actual ingress security review, interactive OAuth client PKCE interoperability, rotation/outage exercises, concurrency/rate limiting, and tamper-evident audit.

**M4 FR-028–FR-030 extension:** a separate three-node K3s/Flannel integration workflow uses the bundled Traefik controller and an isolated ClusterIP ingress-sidecar deployment to exercise real Kubernetes NetworkPolicy; cross-node denial, deliberately permissive additive-policy detection, restored isolation, HTTPS client trust and signed MCP authorization are independent release gates. This CI-only profile does not install or assess a real homelab workload, and the final site deployment/security acceptance remains open.

**K3s test sequencing:** FR-028/FR-029 now use an independent single-node smoke job for Kubernetes deployment correctness (non-root Pod readiness, TLS ingress, JWT authorization), while FR-030 retains a separate path-filtered multi-node CNI policy and positive/negative bypass job. Runtime Secret ownership now uses Kubernetes `fsGroup` plus non-root staging; the previous root-capability workaround is retired. The full network job remains a preproduction release requirement, regardless of smoke success.

**M4 FR-031 extension:** optional issuer-neutral workload JWT login to Vault's JWT auth method (fixed mount and role, strict source-file handling, narrow renewable service-token policy, serialized lease maintenance and sticky fail-closed quarantine). Designed for externally issued OIDC/service-account JWTs but not tied to Kubernetes or a specific issuer vendor. Real Vault JWT login and negative claim-boundary integration are a separate gate; automatic self-healing, independently audited background renewal and production issuer provisioning remain future release gates; FR-032/033 add explicit operator recovery and proactive renewal.

**M4 FR-032–FR-033 increment (PR #12):** shared proactive renewal worker for restricted Vault AppRole/JWT service-token leases, bounded by validated TTL; serialized foreground and background state; sticky quarantine on any failed renewal without fallback. Recovery is separately opt-in via an operator-owned, protected and monotonically increasing Unix epoch file: the increment permits only one fresh Vault login, not cached-token reuse, and rollback/replay does not count. No marker means process-restart recovery. Static token-file mode is unchanged. Test real Vault with idle renewal beyond the original TTL, revocation/quarantine, operator release and malicious epoch controls. Identity provisioning, background audit-event durability and trust-root rotation remain future release gates.
