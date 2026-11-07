# Security architecture and threat model

**Status: PROPOSED.** Security controls in this document are requirements, **not claims of implemented protections**. For disclosure see [SECURITY.md](../SECURITY.md).

## Assets and adversaries

**Assets:** managed infrastructure, privileged API tokens, SSH credentials/trust roots, identity context, policy grants, inventory identity, configuration bundles, plugins, logs and audit evidence.

**Threats:** compromised AI clients and prompt injection, authenticated but over-privileged users, malicious capability authors, untrusted plugin publishers, compromised inventory or config sources, hostile managed endpoints and network attackers. A local administrator or attacker with root-level control of the HostMarshal process/host is outside the in-process threat boundary; OS/platform isolation is required.

## Trust boundaries

| Boundary | Trust source | Must be enforced by |
| --- | --- | --- |
| Client → transport | Verified OIDC/mTLS authorization or trusted OS launcher | Identity layer; **never** client-supplied `clientInfo` |
| Transport → runtime | Authenticated subject and fixed request context | Core |
| Manifest → operation | Installed trusted descriptor and immutable digest | Config compiler/registry |
| Request → host | Trusted inventory identity and vetted endpoint | Resolver/adapter |
| Runtime → external plugin | Installer approval, IPC auth, sandbox/egress controls | Host OS + supervisor |
| Runtime → credential provider | Narrowly scoped service identity and operation purpose | Broker and provider ACLs |
| Adapter → managed target | SSH host keys/cert trust or TLS identity, least-privilege target credential | Network/protocol adapter + target |

**Never assume a YAML file is safe because it is declarative.** Capability publishing is a privileged action. Installation, publication, and invocation rights must be independently controlled.

## Authorization and risk

Effective authorization requires **all** of:

~~~text
authenticated caller
AND installed/approved operation digest
AND validated capability/config snapshot
AND authorization for subject + capability + operation + target
AND vetted endpoint and permitted effects
AND budgets/required approvals satisfied
~~~

A denial fails before broker access and adapter invocation. Missing policies deny. Capabilities cannot downgrade intrinsic operation risk or request additional credentials beyond the trusted descriptor. Authorization decisions should include stable reason codes; errors to ordinary clients must not leak sensitive inventory.

Authorization must be rechecked at relevant state transitions (e.g., target or credential identity changes) and revocation must invalidate caches in a bounded, specified way. For mutable inventories, define a snapshot/reconciliation model that avoids TOCTOU errors.

## Input, execution, network and output controls

- **Input:** strict typed JSON Schema, bounded depth/size/cost; reject unknown security-sensitive YAML fields and unsupported external schema references.
- **Execution:** no generic unrestricted shell or interpreter; fixed operations with bounded arguments, deadlines, output and concurrency.
- **Network:** approved endpoints only; pinned host identity, TLS validation, no arbitrary redirects, DNS rebinding/SSRF protection, restrictive egress.
- **Credentials:** opaque secret references; broker issues scoped short-lived handles where supported; never include raw secrets in errors, logs or MCP responses.
- **Plugins:** privileged install and explicit permission manifest; OS-enforced sandbox; runtime cannot rely on self-reported plugin read-only classification.
- **Output:** declared schema, size limit, redact/classify sensitive data, do not blindly trust tool output or expose secrets.
- **Audit:** all decisions and attempted live execution emit structured correlation/policy/config/operation digests and outcome; decide fail-closed audit policy per risk class before enabling live operations.

HTTP GET can mutate state; arbitrary read-only declarations are **not** a safety proof. SSH commands can have side effects even when intended as diagnostics.

## Baseline threat scenarios and controls

| Scenario | Required mitigation |
| --- | --- |
| Prompt injection tries to enable a new operation | Configuration and grants not exposed as invocation tools; trusted deployment path |
| Client asserts principal or role in tool arguments | Ignore client claims; bind identity from authenticated channel |
| Adversary edits `operationRef` or risk label | Trusted descriptors immutable; reapproval for digest/permission change |
| SSRF to loopback or metadata service | Fixed inventory destinations, protocol-aware redirect validation, OS egress policy |
| Malicious plugin requests filesystem or network access | Independent sandbox and explicit installer-approved permissions |
| Agent queries another tenant's host | Per-principal target grants and tenant-aware catalog filtering |
| Host key or TLS identity changes | Reject connection until trusted identity reestablished |
| Credential backend unavailable | Do not fall back to long-lived broad secrets |
| Output/log contains secret | Redact/classify; never log raw auth headers or tokens |
| Audit sink fails during privileged operation | Defined fail-closed pre-execution commitment for mandatory-audit classes |
| Config reload partially fails | Atomic snapshot; separate emergency-deny path for revocation |

## Operation classes

Observe → Diagnose → Mutate → Privileged → Destructive. These are design classifications; the initial implementation is limited to vetted static inventory and mock observation. State-changing support requires its own ADR and per-invocation approval bound to exact actor, target, operation and arguments; neither a generic authorization nor a model confirmation message is an adequate privileged approval mechanism.

## Residual risks

Signatures prove origin, not safety. A compromised broker/OS or overly powerful target credential can circumvent application-level intent. Misclassified adapter operations remain dangerous unless runtime and target permissions enforce least privilege. Security review and adversarial tests must assess these risks, not merely run Clippy.

## Release security gates

No live target adapter until identity, authorization, target validation, time/output bounds, and auditable outcomes are demonstrated. No third-party plugin execution without independent isolation verification. No privileged mutation or production claims without audited policy, approvals, failure testing, and documented response procedures.
