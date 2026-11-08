# GitHub Actions regression tiers and runner-cost controls

**Status:** Experimental source and CI policy (FR-036). No production acceptance claim.

## Prior testing overhead

Before this change, every PR commit ran a broad Rust+MCP verification job, real Vault SSH signer, real Keycloak TLS/Traefik, fuzz smoke and a separate single-node K3s workflow. The 3-node K3s CNI policy proof was already path-filtered. The redundant jobs build Rust and launch disposable services even when the PR only updates documentation.

## New change impact matrix

| Change class | Rust/schema | MCP/SSH/HTTP | Real Vault | OAuth/Traefik | Fuzz smoke | K3s smoke |
| --- | --- | --- | --- | --- | --- | --- |
| Markdown documentation only | — | — | — | — | — | — |
| Vault-specific source/test | Yes | Yes | Yes | — | — | — |
| Remote JWT/HTTP source | Yes | Yes | — | Yes | — | Yes |
| Audit dispatcher, MCP code | Yes | Yes | — | — | — | — |
| Parser, schema, YAML | Yes | Yes | — | — | Yes | — |
| K3s manifests | Yes | — | — | — | — | Yes |
| Shared runtime/security, dependencies, workflows, unknown path | Yes | Yes | Yes | Yes | Yes | Yes |
| Weekly schedule or manual dispatch | Yes | Yes | Yes | Yes | Yes | Yes |

An always-running classify job tests selection logic before publishing any output. Missing history, failed diff, empty diff or unknown path forces the complete matrix. Changing CI policy or workflow files is *always* a full-matrix event.

For ordinary source changes, format/Clippy/unit/schema checks always run. The protocol suite is included conditionally in that same verify runner, avoiding a second compilation. Expensive external-service tests run only for relevant changes.

## Scheduled and release gates

Both Rust CI and K3s deployment smoke run complete suites via manual workflow dispatch or Monday UTC schedule. The longer YAML parser fuzz workflow remains scheduled separately. Prior to promotion, manually dispatch a complete run of both primary workflows and the independent Disposable K3s MCP isolation workflow using the **release-candidate ref**. Check every run's exact commit SHA. A weekly run against an earlier main commit does not count for release acceptance.

Update branch protection to require the always-running classify job, and evaluate conditional skipped jobs carefully. A skipped heavy job is acceptable for narrow PRs according to the reviewed classifier; it is *not* evidence that an integration suite passed. The complete release matrix is a separate required decision gate.

## Measuring savings

Compare GitHub Actions billed runner minutes and per-job durations across representative PRs before and after this policy. Narrow or documentation-only changes should avoid expensive environment startup; workflow changes still intentionally run everything. The actual savings are not quantified here.

## References

Selection: tests/ci_impact.py; policy tests: tests/test_ci_impact.py; workflows: .github/workflows/ci.yml, .github/workflows/k3s-smoke.yml, .github/workflows/k3s-isolation.yml, .github/workflows/fuzz.yml. Architecture decision: ADR-0019. Full regression continues to be necessary for releases and security-sensitive changes.
