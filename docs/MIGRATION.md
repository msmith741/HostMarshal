# Migration from the pre-alpha JSON bootstrap

**Status:** The old `--config <legacy-json>` interface and hard-coded `list_hosts`/`get_host` handlers were **retired in M2** so no application tool path bypasses the security-enforcing runtime.

This is a **breaking pre-alpha interface change**. The old JSON representation has no implicit secure translation to versioned YAML policies. Do not transform a client-selected `principal` into a verified identity.

## Supported replacement

Create an administrator-owned YAML resource directory with the three resource kinds:

1. **Host** — a stable inventory name with its trusted, vetted address.
2. **Capability** — an approved `operationRef` such as `builtin.inventory.inspect/v1`; keep schemas identical to the installed descriptor.
3. **Grant** — an explicit verified issuer/subject, capability name, and authorized target.

Review [config/v1alpha1](../config/v1alpha1), then validate before serving:

```sh
cargo run --locked -- config validate ./config/v1alpha1
cargo run --locked -- --config-dir ./config/v1alpha1 \
  --principal example-operator
```

Do not copy JSON's `principal` blindly; the trusted launcher now binds the identity and runtime authorizes against grants. The legacy MCP **2025-11-25 protocol framing** still works against the new declarative server, but its tool names and schemas differ from the old bootstrap. Clients using `list_hosts` or `get_host` must migrate to `inventory.inspect` or other published YAML capabilities.

For security-relevant deployments, configure `--audit-log` with a protected path. Tool output, permissions and errors should be revalidated after migration. See [Execution Runtime](EXECUTION_RUNTIME.md) and [Audit](AUDIT.md).
