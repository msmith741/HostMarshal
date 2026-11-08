# HostMarshal

**Secure infrastructure operations through declarative capabilities and policy-controlled execution.**

HostMarshal is a vendor-neutral, pre-alpha Rust infrastructure capability gateway. It supports MCP over stdio, versioned YAML capabilities, and a centralized audited execution coordinator for vetted inventory, Linux SSH and HTTPS observations.

> **Pre-alpha.** M4 adds an optional loopback-only, JWT-authenticated Streamable HTTP MCP entrypoint. See [remote MCP security](docs/REMOTE_MCP.md). It is not a production-ready remote service. M3 adds fixed Linux `uname -s` over pinned-host-key SSH and a fixed HTTPS `/health` GET. There is **no** generic remote command, arbitrary URL, mutation, external plugin, complete remote OIDC federation, proactive background token renewal or tamper-evident audit. JWT HTTP and short-lived Vault-compatible SSH certificate issuance are opt-in pre-alpha slices. Use a dedicated minimally privileged OS/SSH identity and trusted configuration.

## Declarative M1 configuration + M2 execution runtime

YAML resources under `config/v1alpha1/` define a fictional Host, a published Capability and an independent Grant. The capability references the compiled-in `builtin.inventory.inspect/v1` operation. The local `policy explain` command evaluates a simulated subject against a validated snapshot without invoking an adapter or accessing credentials; it requires administrator access to the config directory. The runtime validates resources before serving MCP and denies invocations without an exact matching local-launcher subject/capability/target grant.

Requires Rust stable toolchain:

~~~sh
cargo test
cargo run -- config validate config/v1alpha1
cargo run -- config inspect config/v1alpha1
cargo run -- config schema > hostmarshal-v1alpha1.schema.json
cargo run -- policy explain config/v1alpha1 --subject example-operator \
  --capability inventory.inspect --target sample-linux
cargo run --locked -- --config-dir config/v1alpha1 --principal example-operator
~~~

To use stdio MCP, point a trusted client's MCP server configuration at the compiled binary with the same `--config-dir` and `--principal` launcher arguments. **The launcher must be trusted**: stdio does not authenticate an arbitrary MCP peer, and the principal must not be chosen by the remote tool request.

Additional capability manifests can reuse the existing inventory operation under different names. The initial validated schema subset must match the installed operation exactly; the parser uses explicit resource budgets. A SHA-256 digest identifies the effective validated configuration, but it is **not** a signature or trusted-source proof. The generated JSON Schema covers resource structure rather than semantic authorization; an unknown operation, command field or privilege escalation attempt is rejected. This is the **first vertical slice**, not a general-purpose YAML workflow executor.

## Unix reload and revocation (pre-alpha)

Only a **trusted OS administrator** should control the HostMarshal process and its config directory. While a declarative stdio server is running:

~~~sh
# Validate your full staged config separately before signaling a live process
hostmarshal config validate /protected/config
kill -HUP <hostmarshal-pid>   # validated reload; atomic in-memory publish
kill -USR1 <hostmarshal-pid>  # emergency deny new tool discovery/calls
~~~

A successful reload applies changed grants to newly starting calls; already-started static inventory requests may finish on their original immutable snapshot. An invalid reload retains the previous valid config, so an urgent revocation requires `SIGUSR1` or stopping the process. A valid SIGHUP is required to recover from lockdown. File ownership and OS signal permissions are the current control plane; **MCP clients cannot change configuration or trigger reload**. Unix signals are unavailable on Windows; restart is required there.

This does not provide cryptographic caller authentication, durable audit, atomic on-disk configuration deployment, or cancellation/revocation guarantees for future live adapters. See [Security Architecture](docs/SECURITY_ARCHITECTURE.md).

## M2 security runtime and M3 observation transports

Every published MCP `tools/call` goes through the central [execution runtime](docs/EXECUTION_RUNTIME.md): trusted-launcher identity, exact operation/target grant, mandatory pre-execution audit, scoped credential request where required, bounded built-in adapter, output verification and terminal audit. M3 adds two vetted live observations: `builtin.linux.uname/v1` using pinned-host-key OpenSSH with a protected target-specific key mapping, and `builtin.https.health/v1` using certificate-validating HTTPS with a fixed health URL. Without a trusted `--ssh-credential-map`, SSH requests fail closed.

Structured audit events go to stderr by default; for a local synchronized JSONL file, run from a trusted launcher with `--audit-log /protected/audit/events.jsonl` (outside the YAML directory). See [Audit](docs/AUDIT.md) for permissions, log retention and limitations. For transport setup and restrictions see [M3 observation adapters](docs/OBSERVATION_ADAPTERS.md) and [portable example](examples/m3-observations/README.md).

## M4 experimental authenticated HTTP MCP

A new, separate loopback-only `http` CLI mode authenticates each request with an administrator-pinned RS256 JWKS and exact issuer/audience, validates JWT lifetime/scope and binds the verified subject to the existing authorization coordinator. Middleware-visible HTTP authentication and protocol denials are now audited without trusting unverified identity claims; rejection-audit failure produces HTTP 503. The public-facing HTTPS/TLS reverse proxy must be separately configured and protected. An opt-in pinned-HTTPS online JWKS refresh and RFC 9728 protected-resource metadata mode now exists, with a shared-secret-attested trusted TLS proxy test fixture. This is **not** full OAuth login/OIDC federation or production TLS ingress; M4 remains unfinished.

See [Remote MCP deployment and threat model](docs/REMOTE_MCP.md) and [M4 acceptance gates](docs/M4_IMPLEMENTATION_PLAN.md).

## M4 Vault SSH signer (experimental)

An optional Vault SSH certificate broker generates a fresh Ed25519 keypair **after** authorization and mandatory audit, verifies the returned short-lived user certificate against a pinned CA and exact target account, and deletes ephemeral material after each call. The provider never falls back to static keys. A real Vault 2.2.1 TLS dev-server with restricted signing token and actual SSH login now passes CI; an experimental protected-file AppRole login/on-demand token renewal mode has disposable test coverage; Kubernetes-native workload identity, continuous renewal and full M4 release gates remain outstanding. See [Vault SSH deployment and security](docs/VAULT_SSH.md).

## Parser fuzzing and MCP compatibility

The regular Rust CI suite includes a deterministic mutation test for the YAML loader. The separate [fuzz workspace](fuzz/README.md) supports `cargo-fuzz` coverage-guided campaigns, with a bounded CI smoke and a weekly/manual workflow.

MCP tests cover two stdio protocol eras: `2025-11-25` uses `initialize`; `2026-07-28` uses `server/discover` and stateless request metadata. Neither client-provided `clientInfo` value establishes authorization identity.

## Pre-alpha migration

The old unaudited `--config` JSON mode and its hard-coded `list_hosts`/`get_host` tools were removed in M2. Legacy MCP **2025-11-25 framing** is still supported over the new declarative runtime. See [Migration](docs/MIGRATION.md).

## Documentation

- [Product requirements](docs/PRODUCT.md), [Architecture](docs/ARCHITECTURE.md), [Roadmap](docs/ROADMAP.md)
- [Configuration](docs/CONFIGURATION.md), [Capabilities](docs/CAPABILITIES.md), [Adapters](docs/ADAPTERS.md)
- [Security architecture](docs/SECURITY_ARCHITECTURE.md), [Execution runtime](docs/EXECUTION_RUNTIME.md), [M3 observations](docs/OBSERVATION_ADAPTERS.md), [Audit](docs/AUDIT.md), [Coding standards](docs/CODING_STANDARDS.md)
- [Vault SSH certificate provider](docs/VAULT_SSH.md), [Remote MCP security and setup](docs/REMOTE_MCP.md), [Traceability matrix](docs/TRACEABILITY.md), [Machine-readable schemas](docs/SCHEMA_EXPORT.md), [ADRs](docs/adr/README.md)
- [Test strategy](docs/TEST_STRATEGY.md), [Contributing](CONTRIBUTING.md), [Security policy](SECURITY.md)

## Development

~~~sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo build --locked --bin hostmarshal
python3 tests/mcp_smoke.py
python3 tests/declarative_smoke.py
python3 tests/reload_smoke.py  # Unix only
python3 tests/mcp_modern_smoke.py  # MCP 2026-07-28 stateless
python3 tests/audit_smoke.py  # audited stdio execution and denial
python3 tests/transport_smoke.py  # disposable sshd and TLS target (requires CI prerequisites)
python3 tests/vault_ssh_smoke.py  # disposable Vault-compatible TLS signer, SSH CA and sshd
# Pinned Python JWT dependencies: see .github/workflows/ci.yml
python3 tests/remote_http_smoke.py  # disposable RSA/JWKS and HTTP client
python3 tests/remote_hardening_smoke.py  # disposable pinned-TLS JWKS, OAuth metadata and proxy bypass
# Additional schema drift and independent validation run in CI
~~~

Licensed under [Apache 2.0](LICENSE).

### Production-shaped ingress and real OAuth CI

M4 now has an additional **disposable** CI topology with real Keycloak machine-to-machine client-credentials access tokens, pinned OIDC discovery and a Traefik TLS-only proxy sharing its network namespace with a loopback-only HostMarshal backend. See [the ingress/OAuth test guide](docs/INGRESS_OAUTH_CI.md). It is not a deployed production service; do not merge M4 without the remaining release review and actual site isolation checks.

### Disposable K3s integration and network-isolation CI

M4 additionally includes an **isolated three-node K3s** integration workflow that runs bundled Traefik, Flannel and actual NetworkPolicy enforcement. It creates a CI-only, loopback-bound HostMarshal Pod with a private NGINX ingress sidecar, authenticates TLS MCP requests, blocks unauthorized Service/PodIP traffic from another worker, and verifies a deliberately permissive policy opens the path and that removing it closes the path again. All material is ephemeral; no homelab kubeconfig, Service, Argo sync, Vault or firewall is accessed. See [K3s integration guide](docs/K3S_INTEGRATION_CI.md) and [ADR-0014](docs/adr/0014-disposable-k3s-isolation-acceptance.md). Production k3s/Traefik configuration and actual network isolation still require independent review.

**Staged K3s CI gates:** `K3s deployment smoke` is the single-node, non-root Pod + HTTPS/JWT acceptance path; `Disposable K3s MCP isolation` is the separately triggered two-worker CNI/additive-NetworkPolicy bypass test. Both reject unexpected Kubernetes contexts and never use private homelab credentials. Init and runtime containers are non-root with no added Linux capabilities. Run the extended gate before release; smoke alone is not proof of network isolation.

### Optional issuer-neutral Vault workload JWT

The scoped Vault SSH signer also supports an **opt-in JWT workload identity source**, alongside the existing mutually exclusive operator-token and AppRole modes. It accepts an administrator-fixed Vault JWT login role and protected externally issued assertion, then verifies the resulting short-lived Vault lease's exact signing-only policy. The JWT is authenticated by Vault with configured issuer keys and bound claims; HostMarshal neither supplies an identity provider nor interprets a workload JWT as MCP caller authority. It works outside Kubernetes. See the [workload JWT integration guide](docs/WORKLOAD_JWT_AUTH.md) and [ADR-0015](docs/adr/0015-issuer-neutral-jwt-workload-auth.md). M4 remains experimental; FR-032/033 add proactive idle renewal and explicit operator recovery, while production identity provisioning and security review remain open.

### Proactive Vault signing-lease renewal (experimental)

Renewable Vault AppRole and external JWT signing tokens can now be proactively maintained after an authorized operation, without needing regular MCP traffic. This is a provider-level, process-owned worker that renews the same restricted Vault service token and quarantines on failure—no fallback or silent re-login. An **optional operator-controlled Unix recovery epoch** authorizes only a fresh validated Vault login when an administrator increments a root-owned protected marker; by default, recovery still requires a trusted restart. See [lease lifecycle guide](docs/VAULT_LEASE_LIFECYCLE.md), [ADR-0016](docs/adr/0016-vault-proactive-renewal-recovery.md), and FR-032/FR-033 traceability. No Kubernetes or identity-provider-specific control is required.
