# Capability and operation model

**Status:** M3 pre-alpha exposes a dynamic catalog backed by three trusted built-in operations (inventory.inspect, Linux uname, HTTPS health). The old unaudited JSON handler was retired in M2. Public plugin registry lifecycle remains proposed.

## Three separate objects

1. **Operation implementation** — installed trusted code exposing a stable `operationRef` with typed inputs/outputs, minimum risk/effects and externally enforced resource permissions.
2. **Published capability** — YAML describing tool name, schemas, operation binding, target restrictions, exposure and stricter limits. Publication is an administrative act.
3. **Invocation grant** — policy granting a **verified subject** a capability against selected target resources. A valid capability without a grant is non-executable.

A manifest may choose parameters and **narrow** allowed targets/effects and limits, but never change executable path, user/group privileges, credential scope, trust root, network egress or operation risk classification.

## Why new capabilities can be YAML-only

A known trusted operation `builtin.inventory.inspect/v1` can back several independently named capabilities with distinct output contracts, target selectors or policy grants. A new YAML capability does not require a Rust tool handler because the registry generates the MCP catalog and dispatches to the same operation.

Examples:
- `inventory.inspect`: metadata for an authorized host.
- `inventory.inspect-staging`: the same operation further restricted to staging hosts.
- `linux.os-release`: needs a **separately installed** Linux observation implementation; authoring YAML alone cannot invent it.

## Proposed operation descriptor

~~~text
OperationDescriptor {
  id, version, provider, digest, supported_target_kinds,
  accepted_input_schema, output_schema,
  intrinsic_effect_class, minimum_permissions,
  endpoint_policy, credential_scope,
  max_timeout, max_output_bytes, concurrency_budget
}
~~~

The descriptor is supplied by a trusted built-in adapter or approved plugin package, independently of capability YAML. Installed operation identity is bound to publisher/provenance plus digest. Replacing a descriptor without reapproval must not silently retain invocation authority.

## Classification

- **Observe:** vetted no-side-effect implementation; treats HTTP GET and read-only labels as claims needing verification.
- **Diagnose:** retrieval of potentially sensitive diagnostic data; output classification and retention matter.
- **Mutate:** scoped state changes, with a distinct permission and later approval model.
- **Privileged:** administrative changes; elevated controls and auditing.
- **Destructive:** high-impact state removal; strict additional approval and blast-radius checks.

Only **Observe** on vetted inventory, fixed Linux uname and HTTPS health operations is supported. M4 changes authenticated transport and scoped SSH credential issuance only; it adds no arbitrary shell, HTTP or secret-reading operation. Treat unverified operations as higher risk rather than trusting manifest metadata.

## Initial interface and validation

Tool input must identify a trusted inventory resource by opaque `target` ID. Dynamic tool registration uses the resolved schema from a validated, complete snapshot; fail if schema is invalid, recursive beyond budgets, or references unknown files/URLs. Tools discoverable to one subject must not leak another subject's inventory or capability metadata.

An invocation is bound to **capability name + immutable operation identity/digest + policy/config snapshot + verified subject + resolved target**. Cache only if these dependencies and revocation semantics remain valid.

## Extensibility tiers

### Tier 1 — declarative binding (M1)

YAML binds installed operation descriptors and constrains target selections and budgets. **In the initial subset, schemas must exactly equal the trusted descriptor's schemas**; validated schema narrowing is later work. No arbitrary interpreter and no custom executable paths.

### Tier 2 — restricted recipes (M5, optional)

Later, YAML may compose a **closed set of vetted, typed primitives**: e.g. fixed-endpoint read, bounded JSON extraction and typed mapping. Each primitive must have declared side effects and network permissions. The recipe compiler checks cumulative effects, maximum fan-out/depth, deadlines and available credentials. Reject arbitrary expressions, shell, dynamic URLs, filesystem traversal, unbounded loops, runtime package loading and recursive workflows.

### Tier 3 — custom implementation (M5)

Authors implement a new adapter under an SDK/protocol, publish a versioned package, and request installation-specific sandbox capabilities. Only a privileged administrator can install or approve it; capability manifests and grants remain separate.

## Anti-escalation scenarios

| Attempt | Enforcement |
| --- | --- |
| YAML says `mode: observe` for a restart operation | Registry intrinsic risk prevails; cannot downgrade |
| YAML specifies `runAs: root` or a shell pipeline | Schema rejection; no generic shell primitive |
| Caller supplies a new target IP or URL | Inventory resolver rejects substitution |
| Capability references nonexistent/unsigned plugin | Reject registration |
| Caller modifies capability or grant at invocation time | Request cannot reach privileged configuration interface |
| Previously approved plugin digest changes | Disable/reapprove rather than silently inherit authority |
| GET URL redirects to metadata endpoint | Adapter destination and redirect checks; restrictive egress |
| Adapter claims low risk but is malicious | Installation review, runtime OS isolation and least-privilege credentials; risk label alone never sufficient |

See [security architecture](SECURITY_ARCHITECTURE.md), [adapters](ADAPTERS.md), and [configuration](CONFIGURATION.md).
