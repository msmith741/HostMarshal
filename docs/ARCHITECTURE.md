# Architecture

## Boundary

```text
Trusted process launcher
   |-- chooses executable and trusted configuration
   v
MCP client --stdio--> HostMarshal MCP transport
                           |
                           v
                     capability router
                           |
                           v
                     default-deny policy
                           |
                           v
                     read-only inventory (v0.1)
                     [future: audited host adapters]
```

HostMarshal is designed to remain independent of Hermes. Hermes is an initial prospective MCP client, not part of the authorization engine.

## Layering

1. **Transport:** official Rust MCP SDK (rmcp), stdio-only in this increment.
2. **Capability contracts:** explicitly named tools with JSON Schema inputs, no free-form shell tool.
3. **Policy:** exact principal + capability + host-id grants; checks happen server-side on each tool invocation.
4. **Inventory:** trusted configuration, not data supplied by MCP calls.
5. **Adapters (future):** Linux read-only probes, Proxmox API, Vault credential leasing.
6. **Audit (future):** durable, tamper-evident records tied to authenticated caller, authorization decision, target, outcome and correlation ID.

## Non-goals in v0.1

- Remote transport, network listeners, OAuth, or caller attestation
- SSH connections, Proxmox operations, or command execution
- Vault or long-lived secret storage
- Claims of production readiness or a strong security boundary against local processes that can replace the executable or configuration

## Planned adapter contract

Every adapter should accept a **typed operation** and a resolved **inventory host**, never an arbitrary host string, shell script, or user-supplied credential. Adapters must return bounded, structured results with deadlines, output limits, explicit errors, and audit events. Permissions must be checked *before* credential access or network activity.

A future trusted identity provider must bind principal to a verifiable client/session identity. Do not treat client-supplied MCP fields as authenticating information.
