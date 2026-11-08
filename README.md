# HostMarshal

**Secure infrastructure operations through declarative capabilities and policy-controlled execution.**

HostMarshal is a vendor-neutral, pre-alpha Rust infrastructure capability gateway. It supports MCP over stdio, versioned YAML capabilities, and a centralized audited execution coordinator for vetted inventory, Linux SSH and HTTPS observations.

> **Pre-alpha.** M4 adds an optional loopback-only, JWT-authenticated Streamable HTTP MCP entrypoint. See [remote MCP security](docs/REMOTE_MCP.md). It is not a production-ready remote service. M3 adds fixed Linux `uname -s` over pinned-host-key SSH and a fixed HTTPS `/health` GET. There is **no** generic remote command, arbitrary URL, mutation, external plugin, remote MCP authentication, short-lived secret issuance or tamper-evident audit. Use a dedicated minimally privileged OS/SSH identity and trusted configuration.

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

A new, separate loopback-only `http` CLI mode authenticates each request with an administrator-pinned RS256 JWKS and exact issuer/audience, validates JWT lifetime/scope and binds the verified subject to the existing authorization coordinator. The public-facing HTTPS/TLS reverse proxy must be separately configured and protected. This is **not** a full OIDC discovery, key-rotation or Vault credential integration; M4 remains unfinished.

See [Remote MCP deployment and threat model](docs/REMOTE_MCP.md) and [M4 acceptance gates](docs/M4_IMPLEMENTATION_PLAN.md).

## M4 Vault SSH signer (experimental)

An optional Vault SSH certificate broker generates a fresh Ed25519 keypair **after** authorization and mandatory audit, verifies the returned short-lived user certificate against a pinned CA and exact target account, and deletes ephemeral material after each call. The provider never falls back to static keys. A real Vault interoperability gate and workload token lifecycle remain outstanding. See [Vault SSH deployment and security](docs/VAULT_SSH.md).

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
# Additional schema drift and independent validation run in CI
~~~

Licensed under [Apache 2.0](LICENSE).
