# Requirements-to-implementation traceability

**Scope:** M1 foundation plus M2 trusted execution, authorization, broker contracts and auditing; updated 2026-11-07.

Status definitions: **Implemented (tested)** means corresponding unit/integration checks passed on CI; **In progress** means source exists but milestone acceptance is incomplete; **Planned** means no implementation. This document is not a security certification and should be checked against current CI before relying on the status.

| Requirement | Design authority | Implementation artifact | Verification artifact | Current status |
| --- | --- | --- | --- | --- |
| FR-001 YAML resources | ADR-0003 | `src/declarative.rs`, `src/schema.rs`, `config/v1alpha1/` | `declarative::tests`, `tests/declarative_smoke.py` | In progress — explicit parser budgets, generated Draft 2020-12 schema export, stable effective snapshot digest; checked-in versioned schema and independent conformance implemented; atomic reload and emergency denial available in local Unix mode |
| FR-002 dynamic capabilities | ADR-0004 | `src/declarative.rs`, `src/dynamic_mcp.rs` | two-capabilities unit and smoke tests | In progress — builtin static inventory only |
| FR-003 separation of authorities | ADR-0005 | fixed trusted built-in registry; capability and grant YAML separate | privilege override and denied invocation tests | In progress — deployment lifecycle RBAC not implemented |
| FR-004 caller identity | ADR-0007 | `src/identity.rs`, `src/main.rs` | identity unit tests, denied-caller runtime/MCP tests | Implemented for trusted local stdio; OIDC/mTLS deferred (M4) |
| FR-005 target resolution/deny | ADR-0004, ADR-0005, ADR-0007 | `src/declarative.rs` | denied target, no-grant and invalid capability tests | In progress — name-only selector subset |
| FR-006 central execution | ADR-0002, ADR-0006, ADR-0007 | `src/runtime.rs`, `src/authorization.rs`, `src/adapter.rs`, `src/dynamic_mcp.rs` | runtime unit tests, MCP audit and legacy-mode retirement smoke | Implemented for all supported declarative MCP tools; no unaudited legacy path |
| FR-007 bounded observations | ADR-0006 | `src/adapter.rs` trusted static inventory adapter | runtime output/deadline tests, MCP smoke | Built-in static observation implemented; Linux/SSH/HTTP adapters deferred (M3) |
| FR-008 credential brokerage | ADR-0008 | `src/credentials.rs`, `src/runtime.rs` | runtime broker outage/mismatched scope/denied-before-broker unit tests | Provider-neutral scoped interface implemented; production broker denies all; real backends deferred (M4) |
| FR-009 audit records | ADR-0008 | `src/audit.rs`, `src/runtime.rs`, `--audit-log` CLI | runtime audit failure/redaction tests, `tests/audit_smoke.py` | Implemented for static MCP invocations; persistence optional, no tamper evidence |
| FR-010 offline CLI validation | ADR-0003 | `hostmarshal config validate` | `tests/declarative_smoke.py` | In progress — validate, inspect and schema commands available; render/explain pending |
| FR-011 MCP compatibility | ADR-0009 | `src/dynamic_mcp.rs`, `src/main.rs` | `tests/mcp_smoke.py`, `tests/mcp_modern_smoke.py` | Legacy and stateless stdio wire conformance preserved through the single M2 runtime; HTTP deferred |
| FR-012 isolated plugins | ADR-0006 | Not implemented | Planned sandbox tests | Planned (M5) |
| FR-013 schema conformance | ADR-0003 | `src/schema.rs`, `schemas/v1alpha1/` | `tests/schema_conformance.py`, schema drift CI | Implemented (tested) |
| FR-014 atomic activation and revocation | ADR-0003, ADR-0005 | `src/snapshot.rs`, `src/main.rs`, `src/dynamic_mcp.rs` | snapshot unit tests, `tests/reload_smoke.py` | Implemented (Unix, pre-alpha static inventory); live adapter cancellation and secure deployment pending |
| FR-015 lock/fuzz/MCP matrix | ADR-0003, ADR-0009 | `Cargo.lock`, `tests/parser_mutation.rs`, `fuzz/` | locked CI, deterministic mutation test, pinned nightly fuzz smoke, legacy + modern stdio tests | Implemented (M1 coverage; live HTTP and security assessment deferred) |

## ADR implementation matrix

| ADR | Status | Evidence | Remaining |
| --- | --- | --- | --- |
| 0003 | Accepted | typed parser, strict resource kinds, resource budgets and snapshot hashing | parser fuzzing, secure multi-file configuration deployment, and operational hardening |
| 0004 | Accepted | dynamic MCP discovery for one trusted operation | richer signed registry and robust schema subtyping |
| 0005 | Accepted | separate capability and grant resources; no write MCP tools | admin installation/publication workflows and authorization |
| 0006 | Accepted | no external runtime plugins, builtin action only | typed adapter SDK and OS-isolated plugin supervisor |

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
- `src/runtime.rs`: centralized admission, policy checks, mandatory pre-execution audit, optional broker request, bounded adapter future, output validation and terminal audit. Negative tests cover no broker/adapter on denial, audit failure, mismatched credential lease, output tampering, timeout and error suppression.
- `src/credentials.rs`: provider-neutral scoped `CredentialBroker` and opaque `CredentialLease`; **no production credential backend** is implemented. Test doubles prove scope enforcement only.
- `src/audit.rs`: structured, redacted, reason-coded security events and file/stderr sinks. `tests/audit_smoke.py` verifies actual MCP invocations, matching correlation IDs, denial records, and a protected file.
- The unaudited legacy `--config` JSON handlers were retired. The 2025 and 2026 **wire protocols** both run through this same runtime. See [Migration](MIGRATION.md).
- M2 tests apply to **pure local static observation**. No production-grade remote identities, secrets, plugin isolation, mutation approvals, or tamper-evident audit are implied.

## CI acceptance rules

Do not change **In progress** to **Implemented (tested)** without observing successful checks for the specific source revision. Every new requirement must map to code, tests, and appropriate ADR. Tests must demonstrate **denial** as well as success.

## M1 boundary

For M1, the capability's input/output schemas must be **structurally identical to the trusted operation descriptor**. Allowing arbitrary schema narrowing requires a validated subtyping/compatibility model, not a simple YAML promise. All current runtime fixtures remain fictional; no SSH, arbitrary APIs, plugins, or secret providers execute.
