# HostMarshal

**Give AI agents capabilities, not unrestricted access.**

HostMarshal is a security-first, policy-governed infrastructure operations gateway built in Rust. It exposes narrowly scoped capabilities to MCP clients while keeping host credentials, policy, and execution in a separate trust boundary.

> **Status: bootstrap / v0.1.0-prealpha.** This first increment deliberately supports **only static inventory lookup**. It does **not** connect to SSH, Proxmox, or Vault; authenticate remote callers; or execute commands.

## Why

General-purpose shells give an agent more authority than it needs. HostMarshal is intended to replace that pattern with named, typed, audited operations backed by policy checks and short-lived credentials.

## Current capabilities

| MCP tool | Capability granted per host | Behavior |
| --- | --- | --- |
| `list_hosts` | `hosts_list` | Returns only inventory records explicitly enumeratable by the configured principal |
| `get_host` | `hosts_get` | Returns one exact authorized inventory record, otherwise a nondisclosing error |

No permissions are implicit. Every grant is scoped to an exact principal, capability, and host ID. The example grants access only to `sample-linux`, not `sample-proxmox`.

## Getting started

Requires the Rust toolchain (stable) and Cargo.

```sh
git clone https://github.com/msmith741/HostMarshal.git
cd HostMarshal
cargo test
cargo run -- --config config/example.json
```

The binary serves MCP over **stdio**. Run it from an MCP-compatible client's stdio configuration; keep standard output reserved for protocol messages.

Example MCP client configuration (adjust executable path):

```json
{
  "mcpServers": {
    "hostmarshal": {
      "command": "/absolute/path/to/hostmarshal",
      "args": ["--config", "/absolute/path/to/hostmarshal.json"]
    }
  }
}
```

**Trust model:** The local process launcher chooses the configuration file and thereby asserts the principal. The stdio transport does **not authenticate the caller**. Do not expose this process as a network service or let an untrusted client control its launch arguments or config. The example file contains no secrets and hosts under `.invalid`.

Configuration is strict JSON. Unknown fields, invalid identifiers, duplicate host IDs, and grants referring to unknown hosts fail startup. A missing grants array means **deny all**.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

Read [Architecture](docs/ARCHITECTURE.md), [Threat Model](docs/THREAT_MODEL.md), and [Roadmap](docs/ROADMAP.md). Security bugs should be disclosed according to [SECURITY.md](SECURITY.md).

Licensed under the [Apache License, Version 2.0](LICENSE).
