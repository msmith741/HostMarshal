# Adapter and plugin architecture

**Status:** ADR-0006 Accepted. No public adapter SDK or sandbox protocol currently exists; the implemented M1 operation is trusted static inventory only.

## Purpose

An adapter is a reusable implementation of a **bounded, typed operation**, not a delegation of unrestricted command execution. Keep vendor-specific APIs outside the core; Linux, Proxmox, Kubernetes, networking and secrets are optional integrations.

## Core interface (conceptual, not compiled Rust)

~~~rust
trait OperationAdapter {
    fn describe(&self) -> OperationDescriptor;
    async fn invoke(
        &self,
        operation: ValidatedOperation,
        target: ResolvedTarget,
        context: RestrictedExecutionContext,
        input: ValidatedInput,
    ) -> Result<ValidatedOutput, OperationError>;
}
~~~

The runtime, not the adapter, produces `ValidatedOperation`, `ResolvedTarget` and the authorization decision. `RestrictedExecutionContext` exposes only explicitly granted services (e.g., a scoped outbound client and credential handle). Adapter descriptors declare minimum required effects; they are not themselves proof that unsafe code is harmless.

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
