# Declarative configuration specification

**Status:** limited M1 YAML loader, CLI validation/inspection, generated JSON Schema export, and deterministic effective snapshot digest exist in pre-alpha. Full specification remains a target design; schema narrowing, checked-in schema releases, secure reload, and lifecycle authorization are not implemented.

## Goals and resources

HostMarshal configuration should be **machine readable, offline-validatable, versioned, extensible and auditable**. Resources use a consistent envelope:

~~~yaml
apiVersion: hostmarshal.io/v1alpha1
kind: Capability
metadata:
  name: inventory.inspect
spec: {}
~~~

The proposed `apiVersion` names a **HostMarshal resource schema**, not the MCP protocol revision or adapter version. Supported kinds at M1: `Host`, `Capability`, `Grant`. Later: `InventorySource`, `Connection`, `Role`, `Adapter`, `SecretProvider`, `AuditSink`, `PolicyBundle`. Optional future resources must not be silently accepted as executable by older versions.

## Trust domains

| Configuration | Who may change it | Consequence |
| --- | --- | --- |
| Installed operation descriptor | Trusted binary/plugin publisher + installer | Defines behavior and minimum privilege profile |
| Capability manifest | Trusted capability publisher/administrator | Defines public interface, target narrowing and limits |
| Inventory and connections | Trusted inventory administrator | Defines selectable target identities and endpoints |
| Grants/policy | Trusted security administrator | Grants invocation rights but cannot install executable operations |
| Caller input | Authenticated caller only | Selects **within** authorized capabilities and trusted inventory |

Configurations are **privileged deployment inputs**. Loading files from a Git working tree, tenant upload, user prompt, or MCP tool without an independent deployment authorization would break the model.

## Parsing and validation pipeline

1. Read from explicitly configured, permission-protected paths; enforce file size and resource count limits. Reject symlink/traversal surprises as appropriate to the deployment trust model.
2. Parse YAML with explicit restrictions: reject duplicate mapping keys, unexpected tags, dangerous aliases/anchor expansion, malformed encodings and overlong nesting. No ambient YAML environment evaluation.
3. Validate each versioned resource against a **published machine-readable JSON Schema**. Unknown fields are errors for security-sensitive resources; reject unsupported versions.
4. Validate cross-references: unique resource IDs; immutable operationRef exists in trusted registry; grants reference known capabilities; target selectors reference trusted inventory; no cycles or invalid dependency chains.
5. Check safety constraints: capability YAML can only **narrow**, never expand, operation-defined effects, credential requirements, target class, egress and limits.
6. Compile to an immutable complete registry/policy snapshot. Record a canonical digest and source provenance.
7. Activate atomically only after full validation. Failed reload retains the previous valid snapshot **except** urgent revocations, which need a separate deny-first control plane.

M1 accepts schemas only when structurally identical to the trusted builtin operation descriptor; runtime-defined `$ref`/arbitrary schemas are not supported. Never honor dynamic schema references to untrusted external URLs. Limit schema depth and validation cost; be explicit about JSON Schema Draft 2020-12 support and backward compatibility.

## Resource design (proposed)

### Host

- `metadata.name`: stable opaque ID; changes are identity changes.
- `metadata.labels`: asserted by trusted inventory, never supplied by invocation clients.
- `spec.address`: vetted endpoint, not a tool argument.
- `spec.connectionRef`: optional reference to a trusted connection resource; not used by static inventory operations.

### Capability

- `spec.operationRef`: immutable trusted operation ID and major version.
- `spec.targetKind`: supported inventory resource type.
- `spec.inputSchema`, `spec.outputSchema`: JSON Schema 2020-12 documents, with bounded `$ref` handling.
- `spec.limits`: **more restrictive** time/output/concurrency limits than operation maxima.
- `spec.exposure`: which transports may advertise the capability; **not** an authorization grant.
- Execution semantics come from the installed operation descriptor, not YAML labels such as `mode: observe`.

### Grant

- `spec.subjects`: verified issuer/subject identities or policy-defined roles.
- `spec.capabilities`: exact name or explicitly defined pattern rules; initial release requires exact names.
- `spec.targets`: explicit resource names or trusted label filters.
- Absence of grants means default deny. Listing is not implicit permission to invoke another capability.

## CLI and failure behavior

CLI design (`config validate`, `config inspect` and `config schema` implemented):

~~~sh
hostmarshal config validate ./config
hostmarshal config inspect ./config
hostmarshal config schema > hostmarshal-v1alpha1.schema.json
hostmarshal config render ./config
hostmarshal capabilities list
hostmarshal policy explain --subject example-operator --capability inventory.inspect --target sample-linux
~~~

The schema export is derived from the Rust resource types and is structural. Semantic validation of trusted operation IDs, cross-references, schema equality, and authorization still happens in trusted code. The SHA-256 digest is computed over the normalized **effective** snapshot and is not a signature or proof of source/binary integrity. The parser rejects anchors, aliases, merges and custom tags and applies explicit resource budgets. TOCTOU file-replacement risks remain for later secure deployment hardening.

`policy explain` is an administrative diagnostic, not an identity-spoofing invocation interface; authorization and caller identity for that command must follow a separate trusted local context. Validation errors must identify file, resource, field, constraint and remediation without printing secrets.

## Backward compatibility and rollout

- Never treat old JSON bootstrap configuration as if it were automatically the new security model.
- Provide explicit migration tooling and fixture tests if bootstrap users need migration.
- Version schema and operation descriptors independently.
- Configuration publication should use dry-run validation, immutable digest and atomic promotion, with rollback.
- A revoked grant takes precedence over a cached registry snapshot; cached authorization must not live past revocation guarantees.
- An authority-widening manifest or operation update requires administrator reapproval.

See [Capabilities](CAPABILITIES.md) and [examples](../examples/proposed-v1alpha1/README.md).
