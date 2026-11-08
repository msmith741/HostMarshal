# Regression test selection and cost control

**Purpose:** reduce expensive disposable infrastructure setup per commit while keeping a **fail-closed, repeatable release acceptance gate**. The selection algorithm is checked into the open-source repository at `tests/ci_select.py`, with negative-path contract tests at `tests/test_ci_select.py`. No private CI runner or homelab access is required.

## Policy

On each normal pull request and push to `main`, a small `select` job uses a complete Git checkout and `git diff --name-only --no-renames BASE HEAD`. The base is the GitHub-supplied PR base SHA or push-before SHA. Missing, unavailable, ambiguous/empty or invalid comparisons, unknown paths, CI policy changes and root dependency/lockfile changes **select every suite**. There is **no** opt-out label or caller-supplied environment variable that suppresses a security suite.

A change to:

| Files | Selected suites |
| --- | --- |
| Markdown documentation only (`docs/**/*.md`, README.md, SECURITY.md) | Selector tests only; all builds safely skipped |
| Core source or normal tests | Rust formatting, Clippy, unit/MCP/schema/stdio contract lane |
| Parser, schema, YAML/fuzz code | Core + coverage-guided fuzz |
| Vault signer, credential or provider-router code | Core + disposable real Vault SSH signer |
| Remote HTTP/auth code | Core + real Keycloak/Traefik + K3s smoke |
| Runtime, launcher, or shared audit code | Core + real Vault + real Keycloak/Traefik + K3s smoke |
| K3s/Traefik manifests and related tests | K3s smoke + multi-node isolation + OAuth |
| CI workflow/selector files, `Cargo.*`, unknown paths | **All** suites |

The selector runs on the exact checked-out GitHub revision and emits only fixed boolean suite outputs. Each workflow has a **stable acceptance-gate job**, which checks that selected jobs actually succeeded and nonselected jobs were skipped. If the selector fails, the gate fails. Branch-protection rules should require the stable `Regression acceptance gate` and `K3s regression acceptance gate` instead of conditionally skipped job names. The separate `Disposable K3s MCP isolation` workflow is required for network-sensitive diffs.

## Full regression

`workflow_dispatch` always selects every suite. Weekly scheduled runs force all relevant Rust/Vault/OAuth/fuzz suites, a standalone K3s smoke, and separately scheduled three-node K3s isolation. The existing `YAML parser fuzz` weekly workflow also remains in place. Before release promotion, manually run the complete workflows on the proposed release commit and require all relevant acceptance gates to pass. A green selective PR is **not** production certification, and it does not replace a full release regression.

## Efficiency and integrity considerations

- The largest savings come from skipping Vault SSH lease/recovery delays, Keycloak/Traefik startup, K3s boot, and nightly Rust fuzz compilation when their trust boundaries were unchanged. Normal source changes still run fast compile/Clippy/unit/protocol checks.
- Path selection is a **conservative approximation**, not a proof of dependency independence. Cross-cutting changes deliberately run more suites. Any path selection flaw is treated as a security bug, tested with unknown/malformed changes and repaired with a full run.
- GitHub Actions jobs may be reported as **skipped** for unrelated changes; this is expected only when the always-running gate is green. Verify the actual selector's outputs before accepting a skipped security suite.
- No test result is reused across different source SHAs as a substitute for a required full release test. GitHub Actions concurrency may cancel superseded PR runs; only results for the final exact revision count.
- This change does not introduce untrusted third-party path-filter actions or require any repository-specific secrets. The GitHub Actions token is read-only; authenticated network fixtures remain disposable.
- The approach also works for external contributors: unexpected file additions fail safely to the full matrix.

## Suggested future improvements

Track runner minutes per job and PR; optimize dependency cache with provenance-controlled keys, split the core smoke suite into independently scoped lanes if runtime coverage remains slow, and periodically audit the classification table against the actual dependency graph. Do not remove negative-path security checks merely to shorten CI.
