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
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo build --bin hostmarshal
python3 tests/mcp_smoke.py
python3 tests/declarative_smoke.py
~~~

Licensed under [Apache 2.0](LICENSE).
