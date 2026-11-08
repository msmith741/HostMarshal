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

`tests/remote_http_smoke.py` creates disposable RSA keys and a pinned JWKS, starts the loopback-only MCP HTTP listener and verifies signed-token success, subject-scoped tool visibility, denied target/argument calls, forged signature, wrong issuer/audience/key, expired/not-yet-valid/overlong tokens, missing observe scope, Host/Origin rejection, forwarded-header spoofing, oversized request denial, non-loopback listener rejection and protected auth file ACL. The FR-021 assertions check redacted authentication and protocol-denial audit records and unique IDs. A Rust sink-fault injection test enforces rejection-audit failure propagation; upstream proxy/early parser coverage is not claimed. Existing stdio/M2/M3 tests still exercise the same coordinator. Separate `tests/remote_hardening_smoke.py` tests administrator-pinned online HTTPS JWKS rotation using a disposable TLS issuer, old-key rejection after bounded refresh, redirect denial, TLS trust, RFC 9728 protected-resource metadata/challenge, and a disposable TLS forwarding proxy rejecting direct-backend bypass, invalid attestation, malicious forwarded headers and an independently wrong JWKS TLS CA. This is not a live production ingress security assessment or full authorization-server discovery validation.

## M4 Vault SSH signer and lease test suite

`tests/vault_ssh_smoke.py` uses a disposable Vault SSH-sign API-compatible HTTPS service, real Ed25519 signing CA and disposable sshd. Cover allowed cert login, wrong signer/principal/fresh key, expired/too-short/overlong TTL, extensions, Vault outage/redirect/malformed/oversized response, token rotation, authorization before broker, mixed static/Vault sources and lease-file cleanup. `src/credentials.rs` checks expiration and tempdir ownership. `tests/vault_real_smoke.py` now exercises a **real HashiCorp Vault 2.2.1 TLS dev server** with a restricted SSH signing role and token, role-controlled certificate key IDs, Ed25519 CA, disposable sshd, token revocation/replacement, outage and cleanup. This independent `vault-real` CI job passed on a retry after a transient GitHub runner account-creation timeout. The extended real-Vault suite also tests **AppRole** RoleID/SecretID login, expected-policy and renewable token binding, forced token renew-self, denial of renewal privilege, session quarantine and mixed tokenFile/appRole rejection. This new slice must pass on the exact branch before verification is claimed. **Kubernetes federation, continuous background renewal**, multi-CA rotation, production topology and independent security review remain unfinished release gates.

## Release-blocking failures

Block publication when authorization is bypassed; a policy-negative call reaches a live adapter; credentials leak; a client can substitute a target; an observe operation performs an unintended mutation; an audit-mandatory invocation executes without its required audit commitment; or a plugin escapes its granted isolation.

## M4 real OAuth issuer and production-shaped ingress CI (FR-026/FR-027)

`tests/ingress_oidc_ci.py` is a separate GitHub Actions job that builds the locked Rust binary and runs a disposable Keycloak 26.4.2 realm and Traefik 3.6.9 file-provider configuration. Its identity client is confidential and service-account-only with an RFC 9068 `at+jwt` access-token header, a narrowly configured resource audience, and `hostmarshal.observe` scope. The test requests a genuine client-credentials token, checks the issuer's OIDC discovery and JWKS, validates authorized MCP discovery through Traefik, and verifies wrong-client-secret, valid token for an ungranted subject, changed issuer/JWKS metadata at startup, untrusted TLS root, wrong external Host, malicious forwarded headers and cross-container backend bypass negative paths. Docker network inspection proves only TLS proxy ports are published on runner loopback. The backend binds 127.0.0.1 in the proxy's network namespace with no separately published port; Keycloak has no published direct port. Ephemeral secrets and TLS keys are generated for every job and never committed. CI must also enforce unchanged M1–M3, M4 Vault and fuzz suites.

**Scope limitation:** Docker bridge isolation and TLS on a disposable GitHub runner do not validate homelab Traefik, k3s NetworkPolicies, firewall rule placement, host-network namespace topology or production certificate lifecycle. Real client-credentials interoperability does not imply browser-based authorization-code/PKCE, refresh tokens or dynamic client registration were tested. See `docs/INGRESS_OAUTH_CI.md` for reproducible topology and transfer checklist.

## FR-028–FR-030: real K3s CNI policy and negative control

`tests/k3s_cluster_ci.py` is invoked in a distinct workflow (`.github/workflows/k3s-isolation.yml`) after installing the SHA256-verified k3d v5.9.0 CLI and starting K3s v1.34.5+k3s1 with one server and two agents. The bundled K3s Helm-managed Traefik and NetworkPolicy controller must become ready. An actual signed bearer goes over TLS to the Traefik IngressRoute and the protected local proxy/HostMarshal Pod. Unauthorized cross-agent Pod sources test both Service DNS and PodIP reachability, while a working Kubernetes API positive connectivity control prevents a false pass due to broken networking. Deliberately adding an unsafe additive ingress NetworkPolicy must make the denied path reachable, and deleting it must restore denial. Wrong OAuth issuer/audience/scope/subject, Host/Origin, forwarding headers and client TLS trust are separate negative cases.

**Scope:** real disposable K3s packet enforcement, *not* a production cluster. No leaked CI keys, no home network, no automatically merged application, no packet proof of private VLAN/MetalLB. Continue to require real Keycloak and real Vault integration in their independent jobs. See [K3s acceptance guide](K3S_INTEGRATION_CI.md), [ADR-0014](adr/0014-disposable-k3s-isolation-acceptance.md), and FR-028–FR-030 traceability.

### K3s staged CI acceptance and failure attribution

The **single-node `K3s deployment smoke`** workflow runs `tests/k3s_manifest_contract.py` without contacting Kubernetes, then builds HostMarshal, boots a one-node K3s cluster, and invokes `tests/k3s_cluster_ci.py --mode smoke`. Its PASS requires a Ready Pod, K3s-managed Traefik, TLS-client trust, OAuth resource metadata, scoped signed token success and negative bearer/issuer/audience/scope/Host/proxy cases. It does not execute cross-node NetworkPolicy probes.

The **separate three-node `Disposable K3s MCP isolation`** workflow invokes `--mode network` for related configuration changes and before release promotion. It includes the smoke authorization checks, then uses independent worker scheduling, attacker connectivity positive controls, denied Service+PodIP paths, an intentionally unsafe additive-policy positive control, and restored denial. Both modes enforce a named ephemeral k3d kube-context guard before Kubernetes mutations; no homelab context is permitted. The full network gate must be green before releasing M4.
