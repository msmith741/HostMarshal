# Requirements-to-implementation traceability

**Scope:** M1 declarative capability foundation and versioned schema release; updated 2026-11-07 (reload slice).

Status definitions: **Implemented (tested)** means corresponding unit/integration checks passed on CI; **In progress** means source exists but milestone acceptance is incomplete; **Planned** means no implementation. This document is not a security certification and should be checked against current CI before relying on the status.

| Requirement | Design authority | Implementation artifact | Verification artifact | M1 status |
| --- | --- | --- | --- | --- |
| FR-001 YAML resources | ADR-0003 | `src/declarative.rs`, `src/schema.rs`, `config/v1alpha1/` | `declarative::tests`, `tests/declarative_smoke.py` | In progress — explicit parser budgets, generated Draft 2020-12 schema export, stable effective snapshot digest; checked-in versioned schema and independent conformance implemented; atomic reload and emergency denial available in local Unix mode |
| FR-002 dynamic capabilities | ADR-0004 | `src/declarative.rs`, `src/dynamic_mcp.rs` | two-capabilities unit and smoke tests | In progress — builtin static inventory only |
| FR-003 separation of authorities | ADR-0005 | fixed trusted built-in registry; capability and grant YAML separate | privilege override and denied invocation tests | In progress — deployment lifecycle RBAC not implemented |
| FR-004 caller identity | ADR-0007 | `src/main.rs` trusted launcher principal | unauthorized subject in declarative smoke | In progress — no remote cryptographic auth |
| FR-005 target resolution/deny | ADR-0004, ADR-0005, ADR-0007 | `src/declarative.rs` | denied target, no-grant and invalid capability tests | In progress — name-only selector subset |
| FR-006 central execution | ADR-0002, ADR-0006 | `CompiledConfig::invoke` (mock inventory only) | unit/smoke test | In progress — no general execution coordinator |
| FR-007 Linux adapter | ADR-0006 | Not implemented | Planned integration suite | Planned (M3) |
| FR-008 credential brokerage | ADR-0008 | Not implemented | Planned security tests | Planned (M2–M4) |
| FR-009 audit records | ADR-0008 | Not implemented | Planned fault injection | Planned (M2) |
| FR-010 offline CLI validation | ADR-0003 | `hostmarshal config validate` | `tests/declarative_smoke.py` | In progress — validate, inspect and schema commands available; render/explain pending |
| FR-011 MCP compatibility | ADR-0009 | `src/dynamic_mcp.rs` | legacy MCP stdio smoke | In progress — current-version conformance pending |
| FR-012 isolated plugins | ADR-0006 | Not implemented | Planned sandbox tests | Planned (M5) |
| FR-013 schema conformance | ADR-0003 | `src/schema.rs`, `schemas/v1alpha1/` | `tests/schema_conformance.py`, schema drift CI | Implemented (tested) |
| FR-014 atomic activation and revocation | ADR-0003, ADR-0005 | `src/snapshot.rs`, `src/main.rs`, `src/dynamic_mcp.rs` | snapshot unit tests, `tests/reload_smoke.py` | Implemented (Unix, pre-alpha static inventory); live adapter cancellation and secure deployment pending |
| FR-015 lock/fuzz/MCP matrix | ADR-0003, ADR-0009 | `Cargo.lock`, upcoming fuzz/protocol harness | CI and conformance suite | In progress |

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

## CI acceptance rules

Do not change **In progress** to **Implemented (tested)** without observing successful checks for the specific source revision. Every new requirement must map to code, tests, and appropriate ADR. Tests must demonstrate **denial** as well as success.

## M1 boundary

For M1, the capability's input/output schemas must be **structurally identical to the trusted operation descriptor**. Allowing arbitrary schema narrowing requires a validated subtyping/compatibility model, not a simple YAML promise. All current runtime fixtures remain fictional; no SSH, arbitrary APIs, plugins, or secret providers execute.
