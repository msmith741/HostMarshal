# Requirements-to-implementation traceability

**Scope:** M1 initial declarative capability slice; updated 2026-11-07.

Status definitions: **Implemented (tested)** means corresponding unit/integration checks passed on CI; **In progress** means source exists but milestone acceptance is incomplete; **Planned** means no implementation. This document is not a security certification and should be checked against current CI before relying on the status.

| Requirement | Design authority | Implementation artifact | Verification artifact | M1 status |
| --- | --- | --- | --- | --- |
| FR-001 YAML resources | ADR-0003 | `src/declarative.rs`, `config/v1alpha1/` | `declarative::tests`, `tests/declarative_smoke.py` | In progress — typed resource parsing; full published JSON Schemas, canonical digests and reload pending |
| FR-002 dynamic capabilities | ADR-0004 | `src/declarative.rs`, `src/dynamic_mcp.rs` | two-capabilities unit and smoke tests | In progress — builtin static inventory only |
| FR-003 separation of authorities | ADR-0005 | fixed trusted built-in registry; capability and grant YAML separate | privilege override and denied invocation tests | In progress — deployment lifecycle RBAC not implemented |
| FR-004 caller identity | ADR-0007 | `src/main.rs` trusted launcher principal | unauthorized subject in declarative smoke | In progress — no remote cryptographic auth |
| FR-005 target resolution/deny | ADR-0004, ADR-0005, ADR-0007 | `src/declarative.rs` | denied target, no-grant and invalid capability tests | In progress — name-only selector subset |
| FR-006 central execution | ADR-0002, ADR-0006 | `CompiledConfig::invoke` (mock inventory only) | unit/smoke test | In progress — no general execution coordinator |
| FR-007 Linux adapter | ADR-0006 | Not implemented | Planned integration suite | Planned (M3) |
| FR-008 credential brokerage | ADR-0008 | Not implemented | Planned security tests | Planned (M2–M4) |
| FR-009 audit records | ADR-0008 | Not implemented | Planned fault injection | Planned (M2) |
| FR-010 offline CLI validation | ADR-0003 | `hostmarshal config validate` | `tests/declarative_smoke.py` | In progress — validate exists; render/explain pending |
| FR-011 MCP compatibility | ADR-0009 | `src/dynamic_mcp.rs` | legacy MCP stdio smoke | In progress — current-version conformance pending |
| FR-012 isolated plugins | ADR-0006 | Not implemented | Planned sandbox tests | Planned (M5) |

## ADR implementation matrix

| ADR | Status | Evidence | Remaining |
| --- | --- | --- | --- |
| 0003 | Accepted | typed parser, strict resource kinds and references | schema publishing, parser budgets/fuzzing, digest, atomic reload |
| 0004 | Accepted | dynamic MCP discovery for one trusted operation | richer signed registry and robust schema subtyping |
| 0005 | Accepted | separate capability and grant resources; no write MCP tools | admin installation/publication workflows and authorization |
| 0006 | Accepted | no external runtime plugins, builtin action only | typed adapter SDK and OS-isolated plugin supervisor |

## CI acceptance rules

Do not change **In progress** to **Implemented (tested)** without observing successful checks for the specific source revision. Every new requirement must map to code, tests, and appropriate ADR. Tests must demonstrate **denial** as well as success.

## M1 boundary

For M1, the capability's input/output schemas must be **structurally identical to the trusted operation descriptor**. Allowing arbitrary schema narrowing requires a validated subtyping/compatibility model, not a simple YAML promise. All current runtime fixtures remain fictional; no SSH, arbitrary APIs, plugins, or secret providers execute.
