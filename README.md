# HostMarshal

**Secure infrastructure operations through declarative capabilities and policy-controlled execution.**

HostMarshal is a proposed open-source, vendor-neutral infrastructure operations platform. It is intended to let automation clients, AI agents, and administrators invoke **typed, scoped, auditable** actions against managed systems without handing them general-purpose shell, network, or credential access.

> **Project status: architecture/design phase; no production release.** The configuration examples and contracts under `docs/` and `examples/` are **proposals, not implemented interfaces**. The initial Rust proof of concept from [PR #1](https://github.com/msmith741/HostMarshal/pull/1) is now merged into main, but it is **not** the approved long-term architecture. Do not deploy the proof of concept as an infrastructure security boundary.

## Principles

1. **Vendor-neutral**: no built-in dependence on any single hypervisor, cloud, secret manager, network vendor, cluster, AI client, or private environment.
2. **Declarative extensibility**: versioned YAML defines capabilities over **installed trusted operations**; configuration cannot manufacture privileges.
3. **Separate trust authorities**: installing implementation code, publishing capabilities, and granting invocation rights are distinct actions.
4. **Default deny**: identity, target, operation, and runtime restrictions are enforced in trusted code on every call.
5. **Transport-independent core**: MCP is the initial integration, not the domain model.
6. **Predictable execution**: typed inputs/results, hard limits, credential isolation, audit trails, negative-path tests.
7. **Small, approachable deployments**: local CLI/stdio first; Kubernetes, Vault, and remote hosting remain optional.

## Documentation index

- [Product requirements and non-goals](docs/PRODUCT.md)
- [Architecture and execution flow](docs/ARCHITECTURE.md)
- [Roadmap and milestone exit criteria](docs/ROADMAP.md)
- [Configuration resources and validation](docs/CONFIGURATION.md)
- [Capabilities, recipes, and extension model](docs/CAPABILITIES.md)
- [Adapter and plugin contracts](docs/ADAPTERS.md)
- [Security architecture and threat model](docs/SECURITY_ARCHITECTURE.md)
- [Testing and release gates](docs/TEST_STRATEGY.md)
- [Rust coding standards](docs/CODING_STANDARDS.md)
- [Development workflow and ADR policy](docs/DEVELOPMENT_WORKFLOW.md)
- [Architecture decision records](docs/adr/README.md)
- [Proposed YAML examples](examples/proposed-v1alpha1/README.md)
- [Contributor guide](CONTRIBUTING.md) · [Security reporting](SECURITY.md)

## Extension philosophy

**Capability definition** (YAML) describes a typed tool and references an immutable operation descriptor. **Implementation** (a built-in adapter or separately trusted plugin) determines what actually executes and its minimum privileges. **Authorization** determines whether a verified caller may invoke that operation against an eligible target. Changing one does not grant the others.

Initial support targets read-only inventory, mocks, and constrained observations. Mutation, approvals, rich recipe composition, and third-party plugin execution require additional security work before release.

## License

[Apache License 2.0](LICENSE).
