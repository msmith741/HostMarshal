# ADR-0019: Conservative change-impact regression gates

- **Status:** Proposed — experimental CI policy; maintainer acceptance pending
- **Date:** 2026-11-08
- **Related:** FR-036, NFR-001/004/005, ADR-0014
- **Scope:** GitHub Actions regression-test selection; runtime authorization is unchanged

## Context

Previously every PR ran Rust/MCP/schema validation, real Vault TLS/SSH, real Keycloak and Traefik, fuzz smoke, and single-node K3s even for documentation edits or narrow changes. Each independent runner rebuilt the binary and booted expensive disposable services. Repeated pushes canceled in-flight jobs, wasting runner minutes.

## Decision

1. An always-running, required classify job checks its own regression-policy tests and computes changed paths using the PR base SHA and test head SHA, or push before/after SHA. Full history is checked out. Empty/failed diffs, unknown paths, workflow edits, shared security/runtime code, dependencies, and changes to the classifier itself require the **full** matrix.
2. Source edits always run Rust format, strict Clippy, unit tests, schema generation and independent schema checks. Conditional protocol/MCP/SSH/HTTP smoke steps live in the **same** Rust verify job, reusing the compiled binary.
3. Real Vault, real Keycloak/Traefik, fuzz smoke and single-node K3s run only for relevant paths on ordinary PRs/pushes. The separately path-filtered three-node CNI isolation job remains independently required when affected and before release.
4. Docs-only Markdown changes run policy validation but skip compiling and service startup. Unclassified paths must never be assumed safe.
5. Monday UTC weekly schedule and manual workflow dispatch force **full** suites, regardless of changed paths. Before a release, run both full workflows **on the candidate revision** plus manual three-node CNI isolation. A scheduled main-branch run is not a replacement for candidate-commit acceptance.
6. Branch-protection policy must require the always-running classification result and appropriate source gates. GitHub skipped jobs and missing checks are not equivalent; review queue/branch-rule configuration separately.

## Consequences

A path-based impact policy is a conservative heuristic, not a proof of independence. Indirect regressions remain possible, so periodic and pre-release full integration are non-negotiable. We will not claim particular dollar savings until runner-minute evidence is compared. Production trust, credential isolation and independent security review gates are unchanged.

## Verification

Unit tests in tests/test_ci_impact.py verify documentation-only, Vault/OAuth/K3s/parser/audit cases, shared security boundaries, unknown paths, missing diffs and manual full override. The first implementation PR changes workflow and selector files, and therefore itself triggers every suite.
