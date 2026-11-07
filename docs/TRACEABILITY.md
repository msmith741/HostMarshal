# Requirements-to-implementation traceability

**Scope:** M1 configuration, M2 runtime, M3 observation and M4 OAuth resource-server/Vault SSH certificate integration; updated 2026-11-07.

Status definitions: **Implemented (tested)** means corresponding unit/integration checks passed on CI; **In progress** means source exists but milestone acceptance is incomplete; **Planned** means no implementation. This document is not a security certification and should be checked against current CI before relying on the status.

| Requirement | Design authority | Implementation artifact | Verification artifact | Current status |
| --- | --- | --- | --- | --- |
| FR-001 YAML resources | ADR-0003 | `src/declarative.rs`, `src/schema.rs`, `config/v1alpha1/` | `declarative::tests`, `tests/declarative_smoke.py` | In progress — explicit parser budgets, generated Draft 2020-12 schema export, stable effective snapshot digest; checked-in versioned schema and independent conformance implemented; atomic reload and emergency denial available in local Unix mode |
| FR-002 dynamic capabilities | ADR-0004, ADR-0011 | `src/declarative.rs`, `src/adapter.rs`, `src/dynamic_mcp.rs` | two-capabilities unit/smoke; M3 schema/transport integration | Implemented for three vetted built-in operations; arbitrary plugins still prohibited |
| FR-003 separation of authorities | ADR-0005 | fixed trusted built-in registry; capability and grant YAML separate | privilege override and denied invocation tests | In progress — deployment lifecycle RBAC not implemented |
| FR-004 caller identity | ADR-0007, ADR-0012 | `src/identity.rs`, `src/http_auth.rs`, `src/http_server.rs` | identity unit tests, `tests/http_auth_smoke.py` | Implemented for trusted stdio and strict signed-JWT remote subset; no generic OIDC/mTLS introspection |
| FR-005 target resolution/deny | ADR-0004, ADR-0005, ADR-0007 | `src/declarative.rs` | denied target, no-grant and invalid capability tests | In progress — name-only selector subset |
| FR-006 central execution | ADR-0002, ADR-0006, ADR-0007 | `src/runtime.rs`, `src/authorization.rs`, `src/adapter.rs`, `src/dynamic_mcp.rs` | runtime unit tests (including lockdown and exhausted capacity), MCP audit and legacy-mode retirement smoke | Implemented for all supported declarative MCP tools; no unaudited legacy path |
| FR-007 bounded observations | ADR-0006, ADR-0011 | `src/adapter.rs`, `src/observation.rs`, `src/runtime.rs` | integration `tests/transport_smoke.py`, runtime deadlines, negative-path tests | M3 fixed Linux uname/HTTPS health built-ins implemented; no generic commands/URLs |
| FR-008 credential brokerage | ADR-0008, ADR-0011, ADR-0013 | `src/credentials.rs`, `src/runtime.rs`, `src/vault.rs` | broker unit tests, `tests/vault_ssh_smoke.py` | Protected local mapping and opt-in Vault SSH signing with 60s certificate; no general provider SDK/auto-renewal |
| FR-009 audit records | ADR-0008 | `src/audit.rs`, `src/runtime.rs`, `--audit-log` CLI | runtime audit failure/redaction tests, `tests/audit_smoke.py` | Implemented for static MCP invocations; persistence optional, no tamper evidence |
| FR-010 offline CLI validation/explain | ADR-0003, ADR-0007 | `src/main.rs`, `src/authorization.rs` | `tests/declarative_smoke.py`, `tests/policy_explain_smoke.py` | Implemented for offline validate/inspect/schema and trusted-local policy explain; config render pending |
| FR-011 MCP compatibility | ADR-0009, ADR-0012 | `src/dynamic_mcp.rs`, `src/main.rs`, `src/http_server.rs` | stdio legacy/current protocol tests, `tests/http_auth_smoke.py` | Stateless HTTP plus existing stdio; HTTP/OAuth regression suite added; broader SDK upstream conformance deferred |
| FR-012 isolated plugins | ADR-0006 | Not implemented | Planned sandbox tests | Planned (M5) |
| FR-013 schema conformance | ADR-0003 | `src/schema.rs`, `schemas/v1alpha1/` | `tests/schema_conformance.py`, schema drift CI | Implemented (tested) |
| FR-014 atomic activation and revocation | ADR-0003, ADR-0005, ADR-0011 | `src/snapshot.rs`, `src/main.rs`, `src/runtime.rs` | snapshot unit tests, `tests/reload_smoke.py`, M3 transport deadlines | New requests revoked; in-flight network effects and remote SSH work not guaranteed cancellable |
| FR-015 lock/fuzz/MCP matrix | ADR-0003, ADR-0009 | `Cargo.lock`, `tests/parser_mutation.rs`, `fuzz/` | locked CI, deterministic mutation test, pinned nightly fuzz smoke, legacy + modern stdio tests | Implemented (M1 coverage; live HTTP and security assessment deferred) |
| FR-016 SSH target/key binding | ADR-0011, ADR-0008 | `src/observation.rs`, `src/credentials.rs`, `src/transport.rs` | real sshd integration, host-key mismatch/identity-map/command-injection tests | Implemented for fixed Linux uname only; OS/SSH hardening boundaries documented |
| FR-017 approved HTTPS health | ADR-0011 | `src/observation.rs`, `src/transport.rs`, trusted Host YAML | local TLS integration, wrong-CA, no-redirect, deadline, URL-injection and response-body tests | Implemented for fixed GET /health only; network egress policies remain operator-managed |
| FR-018 remote access-token verification | ADR-0007, ADR-0012 | `src/http_auth.rs`, `src/identity.rs` | `tests/http_auth_smoke.py` (wrong key/type/issuer/audience/scope/expiry, forged clientInfo) | Implemented for pinned RS256 JWT `at+jwt` only; introspection/revocation deferred |
| FR-019 stateless MCP HTTP resource server | ADR-0009, ADR-0012 | `src/http_server.rs`, `src/dynamic_mcp.rs`, `src/main.rs` | HTTP metadata/challenge/loopback, per-request cross-subject test | Implemented for colocated-TLS-proxy HTTP subset; no direct public listener |
| FR-020 Vault SSH scoped certificates | ADR-0008, ADR-0013 | `src/vault.rs`, `src/credentials.rs`, `src/observation.rs` | disposable CA + TLS Vault and cert-only SSH tests `tests/vault_ssh_smoke.py` | Implemented optional Vault SSH signing only; Vault ACL/agent/renewal external |

## ADR implementation matrix

| ADR | Status | Evidence | Remaining |
| --- | --- | --- | --- |
| 0003 | Accepted | typed parser, strict resource kinds, resource budgets and snapshot hashing | parser fuzzing, secure multi-file configuration deployment, and operational hardening |
| 0004 | Accepted | dynamic MCP discovery for one trusted operation | richer signed registry and robust schema subtyping |
| 0005 | Accepted | separate capability and grant resources; no write MCP tools | admin installation/publication workflows and authorization |
| 0006 | Accepted | trusted typed built-in adapter registry; no external runtime plugins | public adapter SDK and OS-isolated plugin supervisor |
| 0007 | Accepted | launcher identity and issuer-scoped grant authorization | remote cryptographic caller verification |
| 0008 | Accepted | precommit/terminal audit, async broker scope, local SSH key map | protected remote broker and tamper-evident audit |
| 0011 | Accepted | fixed OpenSSH uname/HTTPS health, validated target transports and trusted schemas | endpoint egress hardening and broader approved operations |
| 0012 | Accepted | per-request verified JWT caller and OAuth protected-resource metadata | token introspection, sender constraints, automatic JWKS reload and native TLS termination |
| 0013 | Accepted | scoped Vault SSH CA signing with transient certificate lease | short-lived Vault Agent token bootstrap, remote revocation and other secret backends |

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
- These are **implemented test coverage**, not formal certification. Fuzzing is probabilistic; M4 adds a separate HTTP/OAuth resource-server suite, while OAuth authorization-server flows, introspection, subscriptions and the full upstream MCP conformance suite remain out of scope.

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

## M4 remote MCP and credential evidence

- **FR-018:** `src/http_auth.rs` validates an operator-pinned RSA JWKS, JWT signature, explicit `at+jwt` token type, HTTPS issuer, exact resource `aud`, `exp`, `iat`, optional `nbf`, max ten-minute lifetime and `hostmarshal:observe` scope. `src/identity.rs` creates the caller identity *only* from verified token claims. `tests/http_auth_smoke.py` exercises forged JWTs, ID-token type, expired/long-duration tokens, wrong issuer/audience and principal spoofing.
- **FR-019:** `src/http_server.rs` runs rmcp stateless Streamable HTTP behind an HTTP **loopback-only** listener, advertises RFC9728 protected-resource metadata and rejects missing bearer tokens, arbitrary query tokens and invalid Origins. `src/dynamic_mcp.rs` gets the verified caller for every request; tool discovery is private and issuer-scoped. The co-located TLS proxy remains an **operator prerequisite**.
- **FR-020:** `src/vault.rs` uses a protected role/target/key mapping, HTTPS-only Vault SSH signing, exact `ssh-observe` credential scope, 60-second TTL, and bounded response. `src/credentials.rs` retains only a transient certificate file until the SSH operation ends. `tests/vault_ssh_smoke.py` signs ephemeral certificates with a disposable CA and confirms cert-only SSH admission, wrong CA/token/response denial and audit redaction.
- Existing M2 authorization, snapshot, timeout, audit, broker failure and output validation apply to both HTTP and stdio. New grants to remote issuers remain privileged local YAML configuration, never MCP inputs.
- **Residual security boundaries:** OAuth authorization-server security and public TLS gateway, secure local JWKS updates, bearer replay until expiry, Vault Agent/ACL/tokens, certificate revocation, file races, network egress control, external audit integrity, opaque tokens and full MCP feature conformance are **not** implemented in-process. See [HTTP deployment](REMOTE_MCP_HTTP.md), [Vault integration](VAULT_SSH.md), [ADR-0012](adr/0012-oauth-protected-stateless-mcp-http.md), [ADR-0013](adr/0013-vault-ssh-certificate-broker.md).

## CI acceptance rules

Do not change **In progress** to **Implemented (tested)** without observing successful checks for the specific source revision. Every new requirement must map to code, tests, and appropriate ADR. Tests must demonstrate **denial** as well as success.

## M1 boundary

For M1, the capability's input/output schemas must be **structurally identical to the trusted operation descriptor**. Allowing arbitrary schema narrowing requires a validated subtyping/compatibility model, not a simple YAML promise. The original M1 fixture remains fictional; M3 test fixtures operate on disposable local SSH/TLS servers. M4 adds a single target-scoped Vault SSH signing provider; no arbitrary SSH command, arbitrary API request, external plugin or general-purpose secrets accessor executes.
