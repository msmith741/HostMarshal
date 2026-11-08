# Verification and release gates

**Status:** proposed test strategy. Tests discussed here are **planned** unless present in a merged implementation.

## Test pyramid

| Level | Purpose | Typical fixtures |
| --- | --- | --- |
| Unit | Deterministic schema, policy, resolver and risk classification | Pure in-memory values |
| Property/fuzz | Parser input, canonicalization, bound handling, policy invariants | Generated malformed manifests and JSON |
| Contract | Operation descriptors, capability APIs, error and audit schemas | Golden fixtures and mock adapters |
| Integration | SSH/TLS identity checks, HTTP adapter, broker behavior | Local mock servers/disposable targets |
| End-to-end | CLI, MCP tool discovery/invocation, authorization | Local process and test configurations |
| Fault/adversarial | Timeouts, retries, host substitution, credential leaks, audit failure | Injected errors and controlled egress |

## Minimum M1 acceptance tests

1. Two YAML capabilities can reference one installed mock adapter without adding Rust handlers.
2. No grant returns an empty/filtered catalog or authorization denial as appropriate.
3. Exact grants authorize only their intended subject, operation and resource.
4. Capability metadata cannot downgrade operation risk, change adapter privileges or invent executables.
5. Unknown YAML keys, duplicate names/keys, unsupported API versions, broken references, oversized documents, aliases, custom tags, merges and excessive nesting fail validation.
6. Tool schemas and error behavior are consistent through core, CLI and supported MCP versions.
7. Atomic reload never exposes a partially validated permission set; a successful grant revocation affects new calls, invalid reload leaves old state active, and emergency deny removes the catalog without a config parse.

## Mandatory adversarial matrix

- Prompt/tool injection via descriptions and results; descriptions are data, not policy.
- Client-spoofed principal, role, metadata, header, inventory labels or target address.
- Path/hostname/URL normalization tricks, redirects, DNS rebinding, cloud metadata SSRF.
- Time-of-check/time-of-use changes of inventory, policy, plugin or credentials.
- Schema recursion/depth abuse, YAML alias expansion and duplicate keys.
- Shell metacharacters, unintended command substitution and escaping bugs.
- Oversized output, binary responses, secret-bearing errors, log injection and redaction bypass.
- Cancellation/races, stale policy snapshots, rate-limit exhaustion and audit sink outage.
- Cross-tenant data disclosure and capability discovery caching leaks.
- Unknown/malicious plugin manifests, undeclared network/filesystem effects.

## Independent schema conformance (M1)

The checked-in `schemas/v1alpha1/resources.schema.json` is compared against the Rust CLI generator. An independently maintained `jsonschema` Draft 2020-12 validator checks both valid and invalid YAML fixtures. This is an additional structural safeguard; schema validity cannot confer invocation rights. Dependency resolution uses the committed application `Cargo.lock` under `--locked`.

## Evidence and CI

- Gated: format, Clippy warnings-as-errors, tests, schema fixtures, smoke tests, dependency and license audit.
- Before live integrations: security negative-path suite, integration target verification, output redaction checks, stable error tests.
- Before releases: locked dependencies, reproducible artifacts where feasible, SBOM, vulnerability scanning, provenance/signatures and documented supported environments.
- No public CI job requires private network access, personal inventory, or production credentials.
- CI status must distinguish tests run from tests proposed; failures are not waived by documentation claims.

## Implemented parser fuzz and MCP protocol regression tests

- `tests/parser_mutation.rs`: 1,800 seeded edits of valid YAML manifests, stable CI, panic/crash regression.
- `fuzz/fuzz_targets/yaml_manifest.rs`: actual libFuzzer target for parser and compiler, with a small public seed corpus. Pull-request CI compiles and runs the target for 512 executions using a pinned nightly toolchain; separate scheduled/manual workflow runs a 60-second campaign.
- `tests/mcp_smoke.py` plus `tests/mcp_modern_smoke.py`: legacy initialize versus 2026 stateless discover and metadata, with authorized/denied calls and private catalog hints.

A green bounded fuzz run is useful regression evidence but **not** exhaustive security validation; reproduce findings and add minimized corpus cases and deterministic regression tests.

## M2 security regression suite

- Rust coordinator tests: allowed precommit/success, denied subject/target/tool/input, emergency lockdown, exhausted admission capacity, no adapter or broker on denial, failure-to-audit precommit, broker error, mismatched scope and broker timeout, timed-out adapter, malformed result suppression, terminal audit failure.
- MCP integration `tests/audit_smoke.py`: real stdio tool call, denied attempts, correlation ID pair, JSONL file mode and redaction (no input payload/token leaks).
- CLI integration `tests/policy_explain_smoke.py`: allowed/denied/unknown identities and resources, malformed subject rejection and no credential/adapter path. Legacy and stateless protocol tests still run on the same auditable handler.
- Tests should treat error messages as non-disclosing public contracts and audit records as structured privileged diagnostics, not remote telemetry.
- For future live providers/operations, expand with crash recovery, credential expiry/revocation, sandbox escape, rate-limit, TLS/SSH trust, durable audit, sensitive-output classification and side-effect cancellation tests before enabling them.

## M3 disposable real-target security suite

`tests/transport_smoke.py` provisions an ephemeral OpenSSH server with an unprivileged observer account and transient keys, and a locally CA-signed TLS health server. It verifies authorized fixed Linux identification, pinned-key replacement denial, no unmapped or unsafe SSH key use, fixed output and argument injection denial, correct TLS trust, alternate CA failure, HTTP redirect non-follow, slow response deadline, no body disclosure and audit absence of credentials. The CI workflow installs the disposable `openssh-server` prerequisite. All tests run without access to a maintainer's infrastructure.

Unit tests enforce network-hostname validation, typed operation allowlist and grant/transport matching. The schema conformance suite verifies regenerated M3 transport structure and rejects executable configuration fields.

## M4 experimental remote identity testing

`tests/remote_http_smoke.py` creates disposable RSA keys and a pinned JWKS, starts the loopback-only MCP HTTP listener and verifies signed-token success, subject-scoped tool visibility, denied target/argument calls, forged signature, wrong issuer/audience/key, expired/not-yet-valid/overlong tokens, missing observe scope, Host/Origin rejection, forwarded-header spoofing, oversized request denial, non-loopback listener rejection and protected auth file ACL. Existing stdio/M2/M3 tests still exercise the same coordinator. A pinned local JWKS does not validate online issuer key rotation; test that in a later M4 gate.

## M4 Vault SSH signer and lease test suite

`tests/vault_ssh_smoke.py` uses a disposable Vault SSH-sign API-compatible HTTPS service, real Ed25519 signing CA and disposable sshd. Cover allowed cert login, wrong signer/principal/fresh key, expired/too-short/overlong TTL, extensions, Vault outage/redirect/malformed/oversized response, token rotation, authorization before broker, mixed static/Vault sources and lease-file cleanup. `src/credentials.rs` checks expiration and tempdir ownership. A **real TLS-enabled Vault dev server with restricted policy and workload identity** is a separate unfinished release gate.

## Release-blocking failures

Block publication when authorization is bypassed; a policy-negative call reaches a live adapter; credentials leak; a client can substitute a target; an observe operation performs an unintended mutation; an audit-mandatory invocation executes without its required audit commitment; or a plugin escapes its granted isolation.
