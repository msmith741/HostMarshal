# Adapter and plugin architecture

**Status:** ADR-0006 Accepted. The M2 Rust `OperationAdapter` trait and `OperationDescriptor` are implemented for **trusted in-process built-ins and test doubles only**. A public external plugin SDK and sandbox protocol do not yet exist.

## Purpose

An adapter is a reusable implementation of a **bounded, typed operation**, not a delegation of unrestricted command execution. Keep vendor-specific APIs outside the core; Linux, Proxmox, Kubernetes, networking and secrets are optional integrations.

## Implemented Rust adapter contract (M2)

```rust
pub trait OperationAdapter: Send + Sync {
    fn descriptor(&self) -> &'static OperationDescriptor;

    fn execute(
        &self,
        request: AdapterInvocation,
    ) -> Pin<Box<dyn Future<Output = Result<Value, AdapterFailure>> + Send + '_>>;
}
```

A trusted `OperationDescriptor` fixes operation ID, effect class, supported resource kind, maximum timeout and bytes, and any required credential purpose. The runtime creates `AdapterInvocation` with a resolved target from trusted inventory, validated input, and optionally an opaque scoped lease. The adapter cannot create the caller identity, policy permit, or audit event; those belong to the coordinator.

A builtin adapter may return only the vetted static inventory output in M2. The coordinator double-checks that the returned content exactly matches the authorized target and fits the output budget. The only real installed implementation is `builtin.inventory.inspect/v1`, with **no network or shell execution**. Test-only adapters exercise failures and deadlines. Future external plugins require a separate OS-enforced sandbox and versioned protocol (M5).

## Required operation invariants

- Operation ID, major version, implementation package/digest, input/output schema.
- Supported target class, side-effect class, and minimum permissions that cannot be weakened by capability manifests.
- Address/endpoint selection controlled by trusted inventory; no arbitrary caller URLs.
- Hard timeouts, cancellation, bounded output, concurrency/rate limits and typed errors.
- No raw secret returns; credentials acquired through broker using a narrowly scoped purpose.
- No direct policy writes, grant installation, plugin loading, caller-identity claims or audit suppression.

## Adapter families

| Family | Initial safety model |
| --- | --- |
| Built-in inventory/mock | Pure functions, no network or secret requirements |
| Linux observation | Vetted, fixed operations; restricted SSH identity and remote privileges |
| HTTP API | Fixed approved destinations, methods, redirects, TLS trust, bounded decoding |
| Hypervisor API | Narrowly scoped integration packages, capability-specific permission mapping |
| External plugin | Separate OS process, explicit permission manifest, constrained IPC |

No generic `shell.execute`, raw `ssh(command)`, `http.request(any_url)`, or `plugin.load(path)` capability should be exposed as an initial public primitive.

## Plugin trust lifecycle (M5)

1. **Distribution:** signed/traceable artifact with publisher identity, immutable digest and versioned operation descriptors.
2. **Installation:** privileged administrator verifies package provenance and approves **maximum allowed** filesystem, network, process, credential and target permissions.
3. **Registration:** schema/config validation binds capability references to exact installed operation versions; publication alone is not a grant.
4. **Invocation:** trusted runtime authenticates caller, authorizes action and target, allocates restricted execution context and audits outcome.
5. **Upgrade/revoke:** digest changes or privilege widening require reapproval; revocation disables invocations and stops active operations under defined policy.

Publisher signature verifies origin/integrity **not runtime safety**. An untrusted plugin written in Rust is still untrusted code. The architecture must enforce sandbox constraints using OS primitives or an equivalent independent isolation boundary; a plugin voluntarily restricting itself is insufficient.

## External protocol

Choose a versioned, explicitly documented IPC schema (e.g. protobuf/JSON over a protected local channel) only after threat modeling. Include authenticated launcher/peer identity, operation binding, timeout/cancellation, sanitized errors, resource budgets and compatibility negotiation. Avoid unstable native ABI/dlopen as the default extension mechanism.

## Credential handling

An adapter requests a specific credential purpose through the broker; it must never choose arbitrary secret paths or request unrelated tokens. Configure short-lived, scoped identities on the target system. Credential backends are optional: local protected files for development, Vault/cloud/native stores later. No provider-specific type belongs in core domain models.

## Testing obligations

Every adapter must supply contract tests for permitted operations, forbidden host substitution, invalid input, credential denials, output/redaction handling, cancellation, network/TLS failures and side-effect guarantees. Public CI uses disposable targets/mocks, never a maintainer's environment.
