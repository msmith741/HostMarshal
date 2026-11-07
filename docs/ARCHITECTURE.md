# Proposed architecture

**Status:** accepted ADR-0003–0008 and ADR-0011 design principles; M3 adds two audited, bounded real observation adapters. Arbitrary remote execution, writes, remote MCP authentication and external plugins remain unavailable. **Design goal:** transport independence, declarative capabilities, and security boundaries that apply to every adapter.

## Logical diagram

~~~text
MCP stdio / future authenticated MCP HTTP / native CLI
                           |
                 Transport + identity binding
                           |
       request {subject, capability, target, args}
                           |
                Capability registry (compiled)
                           |
        Input validation + trusted target resolver
                           |
               Policy decision (deny by default)
                           |
             Limits / approvals / audit intent
                           |
            Credential broker (if required)
                           |
                Typed execution coordinator
                           |
       Installed adapter / isolated external plugin
                           |
                 Managed host / external API
                           |
        Bounded typed result -> redact -> audit
~~~

**All paths converge on the same core invocation API.** Neither the MCP handler nor the plugin can grant itself additional rights.

## Layer boundaries

| Layer | Owns | Must not own |
| --- | --- | --- |
| Transports | MCP/CLI framing, verified principal binding, protocol negotiation | Policy grants, direct adapter calls |
| Configuration | Strict parsing, schema/version checks, reference resolution, immutable snapshots | Executable arbitrary scripts |
| Capability registry | Stable names, schemas, resolved operation references, discovery | Secret values, caller impersonation |
| Inventory | Trusted targets, labels, immutable IDs, connection reference resolution | User-supplied arbitrary destinations |
| Policy | Principal/operation/capability/target authorization | Implementation code or privileged credentials |
| Runtime | Sequence, timeouts, cancellation, output bounds, audit commitments | Unchecked raw shell/network facilities |
| Credential broker | Scoped credential handles, rotation/revocation behavior | Secret presentation to client |
| Adapters | Vetted, typed operation execution | Defining invocation grants or bypassing runtime |
| Audit/telemetry | Structured security events and sink behavior | Secret/raw sensitive payload dumps |

## Command path

1. Transport authenticates/binds the caller; stdio is tied to a **trusted launcher**, not a client-provided `principal`.
2. Registry resolves a stable capability name to a trusted, versioned operation descriptor.
3. Validation enforces JSON Schema and rejects unsupported external schema references.
4. Inventory resolves the submitted opaque target ID; labels/endpoints are *not* client assertions.
5. Policy evaluates verified subject, operation, resource, and context. Minimum operation risk can **never** be weakened by YAML.
6. Runtime checks admission, concurrency, budgets, and any required approval; records the attempted decision.
7. Broker issues only the scoped credential handle needed by the operation, if any.
8. The adapter executes within its permitted effects, targets, and deadlines.
9. Output undergoes size/type validation and redaction; audit includes result, policy/config digests, duration and correlation ID. Fail closed where required by audit policy.

For any operation crossing additional trust boundaries, re-evaluate authorization and resolve identities again rather than relying on mutable client state. Deny ambiguous or inconsistent configuration and target resolution.

## Suggested Rust module boundaries

~~~text
crates/
  hostmarshal-core/      # domain types and traits, no MCP types
  hostmarshal-config/    # versioned YAML and immutable validated snapshots
  hostmarshal-policy/    # authorization, explanation and grants
  hostmarshal-runtime/   # invocation orchestration, admission and auditing
  hostmarshal-mcp/       # protocol adapter, catalog and tool invocation
  hostmarshal-adapters/  # approved built-in adapter operations
apps/
  hostmarshal/           # executable and CLI
~~~

This is a **target layout**, not a demand to create all crates immediately. Favor one process and clear module contracts before splitting into deployable services.

## Implemented M2 coordinator

`src/runtime.rs` receives a verified local `AuthenticatedCaller`, acquires one immutable config snapshot, validates the operation/target/arguments, calls the `Authorizer`, commits pre-execution audit, requests an optional scoped credential, executes a typed trusted adapter under deadline/concurrency limits, validates its result and commits a terminal audit outcome. MCP has no direct adapter call. Stderr or optional protected file-backed JSON Lines records support audit of invocations; this is not tamper-evident. See [Execution Runtime](EXECUTION_RUNTIME.md) and [Audit](AUDIT.md).

The old JSON-mode MCP handlers were **removed in M2** because they bypassed the coordinator. M3's fixed SSH Linux identification and HTTPS health operations use the same authorization, broker, output validation and audit pipeline. Endpoint selection is from trusted inventory only; see [M3 deployment and threat boundaries](OBSERVATION_ADAPTERS.md). Both supported MCP wire eras now use the declarative pipeline. See [Migration](MIGRATION.md).

## Extension tiers

1. A YAML capability binds an **already trusted** operation.
2. A restricted recipe composes a small set of vetted primitives under cumulative limits (deferred).
3. An external adapter introduces new implementation logic but requires **separate privileged installation**, provenance review and OS-enforced isolation.

See [Capabilities](CAPABILITIES.md), [Adapters](ADAPTERS.md), [Configuration](CONFIGURATION.md), and [Security](SECURITY_ARCHITECTURE.md).

## Deployment profiles

- **Local:** single binary, stdio, local trusted process launcher, static/packaged inventory, explicit grants.
- **Remote (later):** authenticated MCP HTTP, listener hardening, workload identity, strict egress, secret provider, durable audit.
- **Containers (later):** optional distribution only; do not require Kubernetes or service meshes.

## Current bootstrap comparison

Merged [PR #1](https://github.com/msmith741/HostMarshal/pull/1) was an early Rust MCP bootstrap. Its hard-coded tools and JSON mode were retired during M2, leaving only the validated declarative invocation path. External authentication, live adapters and plugin isolation remain separate future requirements.
