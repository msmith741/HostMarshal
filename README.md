# HostMarshal

**Secure infrastructure operations through declarative capabilities and policy-controlled execution.**

HostMarshal is a vendor-neutral, pre-alpha Rust infrastructure capability gateway. It supports MCP over stdio and is being extended from an initial hard-coded inventory proof of concept into an independently configurable, security-governed execution engine.

> **Pre-alpha.** The declarative mode is limited to approved **static inventory observation**. It does **not** connect to hosts, invoke remote commands, load plugins, authenticate remote clients, broker secrets or provide durable auditing. Do not treat it as a production security boundary.

## Declarative M1 slice

YAML resources under `config/v1alpha1/` define a fictional Host, a published Capability and an independent Grant. The capability references the compiled-in `builtin.inventory.inspect/v1` operation. The runtime validates resources before serving MCP and denies invocations without an exact matching local-launcher subject/capability/target grant.

Requires Rust stable toolchain:

~~~sh
cargo test
cargo run -- config validate config/v1alpha1
cargo run -- config inspect config/v1alpha1
cargo run -- config schema > hostmarshal-v1alpha1.schema.json
cargo run -- --config-dir config/v1alpha1 --principal example-operator
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

## Parser fuzzing and MCP compatibility

The regular Rust CI suite includes a deterministic mutation test for the YAML loader. The separate [fuzz workspace](fuzz/README.md) supports `cargo-fuzz` coverage-guided campaigns, with a bounded CI smoke and a weekly/manual workflow.

MCP tests cover two stdio protocol eras: `2025-11-25` uses `initialize`; `2026-07-28` uses `server/discover` and stateless request metadata. Neither client-provided `clientInfo` value establishes authorization identity.

## Legacy bootstrap compatibility

The initial two static tools can still be exercised temporarily through:

~~~sh
cargo run -- --config config/example.json
~~~

Legacy JSON and new YAML are intentionally distinct; legacy configuration must not be interpreted as modern grants. A later migration will remove the bootstrap route.

## Documentation

- [Product requirements](docs/PRODUCT.md), [Architecture](docs/ARCHITECTURE.md), [Roadmap](docs/ROADMAP.md)
- [Configuration](docs/CONFIGURATION.md), [Capabilities](docs/CAPABILITIES.md), [Adapters](docs/ADAPTERS.md)
- [Security architecture](docs/SECURITY_ARCHITECTURE.md), [Coding standards](docs/CODING_STANDARDS.md)
- [Traceability matrix](docs/TRACEABILITY.md), [Machine-readable schemas](docs/SCHEMA_EXPORT.md), [ADRs](docs/adr/README.md)
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
# Additional schema drift and independent validation run in CI
~~~

Licensed under [Apache 2.0](LICENSE).
