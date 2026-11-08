# Requirements-to-implementation traceability

**Scope:** M1–M3 plus experimental M4 remote identity verification and provider routing; updated 2026-11-07.

Status definitions: **Implemented (tested)** means corresponding unit/integration checks passed on CI; **In progress** means source exists but milestone acceptance is incomplete; **Planned** means no implementation. This document is not a security certification and should be checked against current CI before relying on the status.

| Requirement | Design authority | Implementation artifact | Verification artifact | Current status |
| --- | --- | --- | --- | --- |
| FR-001 YAML resources | ADR-0003 | `src/declarative.rs`, `src/schema.rs`, `config/v1alpha1/` | `declarative::tests`, `tests/declarative_smoke.py` | In progress — explicit parser budgets, generated Draft 2020-12 schema export, stable effective snapshot digest; checked-in versioned schema and independent conformance implemented; atomic reload and emergency denial available in local Unix mode |
| FR-002 dynamic capabilities | ADR-0004, ADR-0011 | `src/declarative.rs`, `src/adapter.rs`, `src/dynamic_mcp.rs` | two-capabilities unit/smoke; M3 schema/transport integration | Implemented for three vetted built-in operations; arbitrary plugins still prohibited |
| FR-003 separation of authorities | ADR-0005 | fixed trusted built-in registry; capability and grant YAML separate | privilege override and denied invocation tests | In progress — deployment lifecycle RBAC not implemented |
| FR-004 caller identity | ADR-0007, ADR-0012 | `src/identity.rs`, `src/remote_auth.rs`, `src/remote_http.rs`, `src/main.rs` | identity, HTTPS issuer validation, JWT/HTTP integration tests | M4 partial — verified JWT-based loopback HTTP identity and trusted stdio; full OIDC metadata/rotation and mTLS pending |
| FR-005 target resolution/deny | ADR-0004, ADR-0005, ADR-0007 | `src/declarative.rs` | denied target, no-grant and invalid capability tests | In progress — name-only selector subset |
| FR-006 central execution | ADR-0002, ADR-0006, ADR-0007 | `src/runtime.rs`, `src/authorization.rs`, `src/adapter.rs`, `src/dynamic_mcp.rs` | runtime unit tests (including lockdown and exhausted capacity), MCP audit and legacy-mode retirement smoke | Implemented for all supported declarative MCP tools; no unaudited legacy path |
| FR-007 bounded observations | ADR-0006, ADR-0011 | `src/adapter.rs`, `src/observation.rs`, `src/runtime.rs` | integration `tests/transport_smoke.py`, runtime deadlines, negative-path tests | M3 fixed Linux uname/HTTPS health built-ins implemented; no generic commands/URLs |
| FR-008 credential brokerage | ADR-0008, ADR-0011 | `src/credentials.rs`, `src/runtime.rs` | broker unit tests, M3 protected mapping/denial integration | Scoped async broker plus M3 optional protected local target-key mapping; remote/short-lived providers deferred (M4) |
| FR-009 audit records | ADR-0008 | `src/audit.rs`, `src/runtime.rs`, `--audit-log` CLI | runtime audit failure/redaction tests, `tests/audit_smoke.py` | Implemented for static MCP invocations; persistence optional, no tamper evidence |
| FR-010 offline CLI validation/explain | ADR-0003, ADR-0007 | `src/main.rs`, `src/authorization.rs` | `tests/declarative_smoke.py`, `tests/policy_explain_smoke.py` | Implemented for offline validate/inspect/schema and trusted-local policy explain; config render pending |
| FR-011 MCP compatibility | ADR-0009, ADR-0012 | `src/dynamic_mcp.rs`, `src/remote_http.rs`, `src/main.rs` | legacy and stateless stdio suites; `tests/remote_http_smoke.py` | HTTP stateless pilot in progress; comprehensive OAuth/protocol conformance pending |
| FR-012 isolated plugins | ADR-0006 | Not implemented | Planned sandbox tests | Planned (M5) |
| FR-013 schema conformance | ADR-0003 | `src/schema.rs`, `schemas/v1alpha1/` | `tests/schema_conformance.py`, schema drift CI | Implemented (tested) |
| FR-014 atomic activation and revocation | ADR-0003, ADR-0005, ADR-0011 | `src/snapshot.rs`, `src/main.rs`, `src/runtime.rs` | snapshot unit tests, `tests/reload_smoke.py`, M3 transport deadlines | New requests revoked; in-flight network effects and remote SSH work not guaranteed cancellable |
| FR-015 lock/fuzz/MCP matrix | ADR-0003, ADR-0009 | `Cargo.lock`, `tests/parser_mutation.rs`, `fuzz/` | locked CI, deterministic mutation test, pinned nightly fuzz smoke, legacy + modern stdio tests | Implemented (M1 coverage; live HTTP and security assessment deferred) |
| FR-016 SSH target/key binding | ADR-0011, ADR-0008 | `src/observation.rs`, `src/credentials.rs`, `src/transport.rs` | real sshd integration, host-key mismatch/identity-map/command-injection tests | Implemented for fixed Linux uname only; OS/SSH hardening boundaries documented |
| FR-017 approved HTTPS health | ADR-0011 | `src/observation.rs`, `src/transport.rs`, trusted Host YAML | local TLS integration, wrong-CA, no-redirect, deadline, URL-injection and response-body tests | Implemented for fixed GET /health only; network egress policies remain operator-managed |
| FR-018 remote HTTP identity | ADR-0007, ADR-0012 | `src/remote_auth.rs`, `src/remote_http.rs`, `src/identity.rs`, `src/main.rs` | `tests/remote_http_smoke.py` disposable RSA/JWKS and negative token/HTTP tests | In progress — stateless signed-JWT loopback transport; no dynamic JWKS/metadata or TLS ingress implementation |
| FR-019 provider routing | ADR-0008, ADR-0012 | `src/provider_router.rs`, `src/main.rs` | provider-route unit tests; mixed-provider launch denial and Vault outage integration | In progress — exclusive Vault vs static-key selection, no coactive external backend registry |
| FR-020 Vault SSH signing | ADR-0008, ADR-0012 | `src/vault_ssh.rs`, `src/credentials.rs`, `src/runtime.rs`, `src/observation.rs` | lease cleanup unit test, `tests/vault_ssh_smoke.py` | In progress — disposable Vault-compatible TLS signer + real SSH CA/sshd, real Vault and workload identity unverified |

## ADR implementation matrix

| ADR | Status | Evidence | Remaining |
| --- | --- | --- | --- |
| 0003 | Accepted | typed parser, strict resource kinds, resource budgets and snapshot hashing | parser fuzzing, secure multi-file configuration deployment, and operational hardening |
| 0004 | Accepted | dynamic MCP discovery for one trusted operation | richer signed registry and robust schema subtyping |
| 0005 | Accepted | separate capability and grant resources; no write MCP tools | admin installation/publication workflows and authorization |
| 0006 | Accepted | trusted typed built-in adapter registry; no external runtime plugins | public adapter SDK and OS-isolated plugin supervisor |
| 0007 | Accepted | launcher identity and issuer-scoped grant authorization; M4 static-JWKS access-token verifier | comprehensive remote identity federation and rotation |
| 0008 | Accepted | precommit/terminal audit, async broker scope, local SSH key map | protected remote broker and tamper-evident audit |
| 0011 | Accepted | fixed OpenSSH uname/HTTPS health, validated target transports and trusted schemas | endpoint egress hardening and broader approved operations |

## Configuration hardening evidence

- `src/declarative.rs::parse_manifests` applies explicit input size, document count, depth, node, event, anchor and alias budgets and rejects merge keys/custom tags. Exhaustive fuzzing remains deferred.
- `CompiledConfig::compile` normalizes grant ordering before hashing the **effective configuration snapshot** with SHA-256. This digest is neither a signature nor independent proof of origin or executable provenance.
- `hostmarshal config schema` exports machine-readable Draft 2020-12 JSON Schema generated from Serde resource types. It captures shape, not cross-resource security validation, operation allowlists or authorization.
- `hostmarshal config inspect` returns resource counts and digest for trusted local operators without exposing inventory addresses.
- Rust unit and CLI smoke tests check parser rejection, hash stability under reordering, hash changes with grants, and parseability of the generated schema.
- Successful Unix `SIGHUP` revalidates and swaps an immutable configuration snapshot; `SIGUSR1` places new calls into deny-all lockdown. Failed validation leaves the last-known-good snapshot unchanged. Signals are OS-authorized, not MCP tools.
- External plugin digests, live-adapter cancellation and reauthorization, hardened deployment file permissions and durable audit remain **not implemented**.

## Schema publication and dependency evidence

- `schemas/v1alpha1/resources.schema.json` contains the versioned, checked-in Draft 2020-12 schema with a fixed apiVersion and stable $id.
- `src/schema.rs` generates the schema from Rust resource models; CI performs a byte-for-byte drift comparison.
- `tests/schema_conformance.py` independently checks the schema and positive/negative YAML fixtures using pinned external Python validation libraries. Passing schema validation is **not** authorization.
- The application has a committed `Cargo.lock`. CI uses `cargo --locked` for metadata, build, Clippy and tests to detect dependency-resolution drift.

## Parser fuzzing and protocol coverage (M1)

- `tests/parser_mutation.rs` executes 1,800 reproducibly seeded YAML mutations through the strict parser and compiler on stable CI; any panic fails the test.
- `fuzz/fuzz_targets/yaml_manifest.rs` adds a true libFuzzer target and seed corpus with independent dependencies. CI runs a bounded 512-case coverage-guided smoke and `.github/workflows/fuzz.yml` provides scheduled/manual 60-second campaigns using a pinned nightly compiler.
- `tests/mcp_smoke.py` tests the legacy `2025-11-25` initialize path, while `tests/mcp_modern_smoke.py` exercises `2026-07-28` stateless `server/discover` without initialization, per-request protocol metadata, restricted tool listings and denial outcomes.
- These are **implemented test coverage**, not formal certification. Fuzzing is probabilistic, and HTTP, OAuth, and server-initiated features are out of scope for the current stdio-only implementation.

## M2 runtime evidence and acceptance boundaries

- `src/identity.rs`: authenticated caller identity is created from the trusted launcher, not MCP `clientInfo`. Network identities are not verified in M2.
- `src/authorization.rs`: typed `AuthorizationRequest`, `AuthorizationDecision`, and `Authorizer`; the initial `GrantAuthorizer` enforces exact caller+operation+capability+target grants.
- `src/adapter.rs`: typed `OperationDescriptor`, `OperationAdapter`, resolved target and execution request; only the trusted static inventory adapter is installed in production.
- `src/runtime.rs`: centralized admission, policy checks, mandatory pre-execution audit, optional broker request, bounded adapter future, output validation and terminal audit. Negative tests cover no broker/adapter on denial, audit failure, mismatched credential lease, issuer-scoped discovery, broker/adapter deadlines, output tampering and error suppression.
- `src/credentials.rs`: provider-neutral scoped `CredentialBroker` and opaque `CredentialLease`; **no production credential backend** is implemented. Test doubles prove scope enforcement only.
- `src/audit.rs`: structured, redacted, reason-coded security events and file/stderr sinks. `tests/audit_smoke.py` verifies actual MCP invocations, matching correlation IDs, denial records, and a protected file.
- Local offline `hostmarshal policy explain` provides structured issuer/subject/capability/target decisions without adapter or credential access; validated by `tests/policy_explain_smoke.py`. It does **not** impersonate a caller to execute operations.
- The unaudited legacy `--config` JSON handlers were retired. The 2025 and 2026 **wire protocols** both run through this same runtime. See [Migration](MIGRATION.md).
- M2 tests apply to **pure local static observation**. No production-grade remote identities, secrets, plugin isolation, mutation approvals, or tamper-evident audit are implied.

## M3 observation security evidence and traceability

- **FR-016:** `src/observation.rs::LinuxUname` invokes an absolute OpenSSH executable with a fixed `uname -s` command, no caller-specified arguments, no inherited SSH user config, proxy jumping, password auth, tty or agent fallback. Host key trust is pinned to a trusted per-target alias and protected known_hosts file. Stdout is bounded and only the exact Linux OS classification is returned.
- **FR-016 / FR-008:** `src/credentials.rs::LocalSshKeyBroker` loads a restricted, separate launch-time per-target JSON mapping, rejects symlink or over-permissive identity/map files, and provides an opaque scoped lease after authorization and audit. If absent, the default broker denies SSH. This is **not** external secret rotation or a full SSH certificate authority.
- **FR-017:** `src/observation.rs::HttpsHealth` constructs HTTPS only from a validated trusted inventory address, fixed port and compiled-in `/health`, validates TLS identity, uses no proxies and no redirects, and returns status/health only with no untrusted body content.
- **FR-002/005/006:** `src/declarative.rs` binds only installed immutable operation IDs, exact input/output schemas, approved Host transports, and configured limits; `src/runtime.rs` rechecks descriptor/target/size/deadline/output and audits every invocation. No arbitrary shell, HTTP URL, credential grant, or target-swap mechanism is exposed.
- **NFR-001/002/004:** `tests/transport_smoke.py` uses disposable `sshd` and a locally CA-signed TLS server; tests allowed calls, denied identities/targets, wrong host key and CA, bad mappings, forbidden arguments, redirected response and timeout. `tests/schema_conformance.py` separately validates M3 YAML examples and negative fixtures. CI runs this alongside existing M1/M2 suites and fuzzing.
- **Residual risks:** privileges on the service OS account and key/trust paths, root CA/DNS compromise, filesystem replacement races, lack of network egress sandbox, remote work after local cancellation, local-only audit integrity, and external client authentication remain **outside verified M3 guarantees**. See [ADR-0011](adr/0011-readonly-network-observation.md) and [M3 operations](OBSERVATION_ADAPTERS.md).

## M4 in-progress evidence

- **Provider routing foundation:** `src/provider_router.rs` rejects duplicate or malformed operation/target/purpose routes, missing routes, cross-target and cross-operation requests, mismatched returned leases and unavailable providers. Provider failures never cause fallback to a broader credential source.
- **Implemented in M4 pilot:** signed-JWT loopback HTTP plus opt-in Vault SSH signing with ephemeral, expiry-checked user certificate leases. **Not implemented:** real Vault interoperability and dynamic workload identity/token renewal, online JWKS refresh/OAuth metadata, remote TLS ingress and independent audit. **No M4 completion claim** is made. See [M4 implementation plan](M4_IMPLEMENTATION_PLAN.md) and [ADR-0012](adr/0012-m4-remote-identity-and-credential-providers.md).

## M4 in-progress security evidence

- `src/remote_auth.rs` verifies RS256 signatures with *pinned local* JWKS, exact HTTPS issuer/resource audience, mandatory expiration/not-before/issued-at, bounded lifetime, `at+jwt` header type and `hostmarshal.observe` scope. Unknown keys or invalid tokens deny access.
- `src/remote_http.rs` implements a separate loopback-only stateless rmcp HTTP mode with per-request middleware identity verification, exact Host and Origin restrictions, no permissive CORS, 256 KiB body limit and POST-only access. The authenticated caller is passed to the existing coordinator for tool discovery and execution; HTTP metadata alone is never identity.
- `src/provider_router.rs` retains no-fallback exact operation/target/purpose broker routing and scope revalidation.
- `tests/remote_http_smoke.py` covers signature forgery, wrong issuer/audience, expired/future/oversized tokens, wrong subject permissions, forbidden Origin and Host, spoofed forwarded user, unauthorized tool arguments and unprotected config rejection.
- **Not yet verified/completed:** remote-facing TLS ingress and bypass isolation, online JWKS refresh/rotation and OAuth metadata, auth-denial durable audit, distributed rate limits, actual Vault dev-server signing with workload login/renewal and independent remote audit. **M4 remains in progress.**

## M4 signed SSH certificate test evidence

- **FR-020:** `src/vault_ssh.rs` submits only per-invocation public keys and a fixed inventory principal to a pinned HTTPS Vault SSH signing role, and cryptographically checks the returned certificate's CA, signature, public-key match, exact user, restricted options and expiry.
- **FR-008/019:** `src/main.rs::choose_broker` forbids simultaneous Vault/local SSH credentials, `src/credentials.rs` owns temporary lease material, and `src/runtime.rs` enforces lifetime beyond the remaining adapter deadline. The target adapter rechecks the configured principal.
- **NFR-001/002/004:** `tests/vault_ssh_smoke.py` tests an API-compatible TLS signing **mock**, real SSH CA and sshd, unauthorized/invalid cert responses, token rotation and ephemeral file deletion. This **does not** establish real Vault interoperability. See [Vault SSH](VAULT_SSH.md).

## CI acceptance rules

Do not change **In progress** to **Implemented (tested)** without observing successful checks for the specific source revision. Every new requirement must map to code, tests, and appropriate ADR. Tests must demonstrate **denial** as well as success.

## M1 boundary

For M1, the capability's input/output schemas must be **structurally identical to the trusted operation descriptor**. Allowing arbitrary schema narrowing requires a validated subtyping/compatibility model, not a simple YAML promise. The original M1 fixture remains fictional; M3 test fixtures operate on disposable local SSH/TLS servers. No arbitrary SSH, API request, plugin or external short-lived secret provider executes.
