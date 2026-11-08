# Security architecture and threat model

**Status:** security architecture covers M1/M2 enforcement, M3 restricted SSH/HTTPS observations and M4 JWT-authenticated loopback HTTP plus experimental Vault SSH certificate issuance; production remote transport hardening remains **unimplemented**. Do not infer production assurance from this document. For disclosure see [SECURITY.md](../SECURITY.md).

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
| Audit sink fails during privileged operation | Defined fail-closed pre-execution commitment for mandatory-audit classes; the M4 HTTP middleware also returns 503 when a rejected-request denial cannot be committed |
| Config reload partially fails | Atomic in-memory activation after full validation; SIGUSR1 emergency-deny on Unix or stop the process |

## Operation classes

Observe → Diagnose → Mutate → Privileged → Destructive. These are design classifications; the initial implementation is limited to vetted static inventory and mock observation. State-changing support requires its own ADR and per-invocation approval bound to exact actor, target, operation and arguments; neither a generic authorization nor a model confirmation message is an adequate privileged approval mechanism.

## Implemented local reload and revocation boundary (M1)

The Unix stdio service can handle OS-protected signals: **SIGHUP** compiles the complete trusted configuration directory and atomically replaces the active in-memory snapshot on success; **SIGUSR1** disables all tool enumeration and invocation for new requests. Only a subsequent valid SIGHUP or trusted process restart can re-enable operations.

A rejected SIGHUP retains the previous validated snapshot. If that snapshot includes permissions that urgently require revocation, the operator **must issue SIGUSR1 or stop the process**; a malformed staged config is not a revocation mechanism. Signal permission is governed by the host OS, and all processes running as the same OS user may generally signal each other, so the deployment identity must not be shared with untrusted workloads.

M1 requests use one immutable snapshot acquired at request start. Already-started static inventory reads may complete using that snapshot; a successful revocation applies to requests that **start after** the replacement is activated. Side-effecting adapters are still prohibited until interruption and reauthorization at effect boundaries are implemented. No persistent audit of signal provenance exists.

The directory loader currently reads several files in sequence. It does **not** prove filesystem-level transactionality or prevent privileged same-user file replacement races. Stage a complete validated config in a separate protected directory, use an OS-controlled atomic rename or symlink promotion as appropriate, and then signal reload. No client may submit an arbitrary directory or grant change through MCP.

## Implemented M2 execution boundary

The declarative stdio MCP handler now delegates all tool invocations to `ExecutionCoordinator`. The old unaudited JSON handlers were removed. A typed trusted-launcher caller, issuer/subject-aware authorizer and vetted operation descriptor are checked before the broker or adapter. The static-inventory operation is restricted to Observe, Host targets, a deadline, bounded concurrency and an output limit. Tests prove unauthorized requests do not reach adapters or the broker, issuer-sensitive tool discovery, unexpected output is rejected, and slow broker/adapter futures exceeding their shared deadline are dropped.

For each invocation, the audit sink must accept `Authorized` *before* credential access/operation execution; failures deny execution. The sink records denied and terminal outcomes with correlation IDs, operation and snapshot digests. Default stderr and optional protected local JSONL/sync-data backends are available, but the latter is **not tamper-evident** and has OS file-replacement risks. Terminal audit failure can only suppress the response, not undo an effect, which is why no mutation is permitted. See [Audit](AUDIT.md).

A `CredentialBroker` interface accepts exact operation/target/purpose scopes. Without an explicit protected local SSH identity mapping, the broker denies credential requests. M3's minimal local key-path broker allows only `builtin.linux.uname/v1` for mapped targets with purpose `ssh-observe`. Real external/short-lived secret provider integration remains M4. See [M3 security design](OBSERVATION_ADAPTERS.md). External plugins, complete remote identity federation, approvals and cancellation guarantees for privileged work are explicitly absent. M4 only provides a pinned-JWKS loopback HTTP pilot.

## M4 experimental remote MCP trust boundary

The loopback-only HTTP MCP mode authenticates every request with an offline pinned or fixed-HTTPS/pinned-CA RS256 JWKS, exact issuer/resource audience, subject, lifetime and observe-only scope. Only a validated `AuthenticatedCaller` enters the authorization-aware tool discovery and execution pipeline; forwarded identity headers are ignored. The handler denies requests without a trusted request context and exposes no unauthenticated tool catalog. Host/Origin checking and bounded request bodies constrain common browser/proxy abuse.

**This is not an independently authenticated public listener.** A separately managed TLS reverse proxy must secure the external endpoint and prevent direct backend access. Optional pinned-HTTPS JWKS renewal, OAuth protected-resource metadata and fixed proof-attested ingress checks now exist, but token revocation, interactive OAuth authorization-code/PKCE interoperability, production proxy isolation, external audit of pre-MCP auth errors and a **production-validated Vault SSH certificate issuer** remain unavailable. The pinned JWKS and OS file permissions are deployment trust assumptions. Do not mark M4 complete or claim production-grade remote security on this basis alone. See [Remote MCP](REMOTE_MCP.md).

## M4 Vault certificate and temporary-key trust boundary

The opt-in Vault broker uses a protected OS-owned signer config, fixed role/mount, verified TLS and SSH signing CAs, per-call Ed25519 keypairs, cryptographic certificate/principal/expiry validation, and lease-owned temporary files. The coordinator checks grants/audit before the broker and validity beyond the pending operation deadline. The static-key provider and Vault signer are **mutually exclusive**; a Vault outage never triggers static fallback. The SSH adapter retains host-key pinning and the fixed Linux observation.

Vault authentication may use an owner-only operator token file (reread for every request) or a separate protected-file AppRole identity. AppRole tokens are checked against a single expected policy and renewable TTL; renewal occurs on demand before use, while failed renewal/auth rejection places the session in a fail-closed quarantine. This does not implement Kubernetes federation, a background renewal agent or automatic recovery after expiration. A disposable real Vault 2.2.1 TLS signer and restricted token/SSH role are covered by CI. Trusted workload login/renewal, production CA rotation, tamper-evident audit, ingress TLS, and OS egress isolation are incomplete. See [Vault SSH](VAULT_SSH.md).

## Residual risks

Signatures prove origin, not safety. A compromised broker/OS or overly powerful target credential can circumvent application-level intent. Misclassified adapter operations remain dangerous unless runtime and target permissions enforce least privilege. Security review and adversarial tests must assess these risks, not merely run Clippy.

## Release security gates

No live target adapter until identity, authorization, target validation, time/output bounds, and auditable outcomes are demonstrated. No third-party plugin execution without independent isolation verification. No privileged mutation or production claims without audited policy, approvals, failure testing, and documented response procedures.

## FR-023–FR-025: remote issuer trust and reverse-proxy attestations

The optional online verifier has a distinct administrator-fixed URL and CA, refreshes under a single async mutex on request after its bounded interval, discards previous keys on successful rotation and **does not use stale keys after refresh failure**. RFC 9728 resource metadata is public through the trusted ingress but does not create a caller. In `trustedProxy` mode, all backend calls require a protected shared ingress proof and validated forwarded HTTPS/public Host. The loopback listener cannot be reached from another host, but malicious colocated processes, a compromised proxy/proof, improper external network namespace or forged client headers passed through the ingress remain deployment risks. The CI TLS proxy fixture validates the logical protocol boundary only; it does not establish production TLS or OS isolation. See [REMOTE_MCP.md](REMOTE_MCP.md).

## M4 FR-026/FR-027 — real OAuth and isolated ingress acceptance

For an administrator-configured `authorizationServerMetadataUrl`, HostMarshal requires online JWKS and retrieves OIDC discovery over the *same independently pinned TLS root* used by the JWKS client. Startup fails if metadata redirects, exceeds size/time budgets, identifies a different issuer/JWKS, changes origin for OAuth endpoints or does not advertise client-credentials. Discovery is **not** a trust-on-first-use step: all issuer, CA and JWKS URL expectations are already administrator-fixed. JWTs remain independently signed/validated and are never forwarded to adapters. The `nbf` claim, optional for RFC 9068 access tokens, is validated when present; `iat` and `exp` remain mandatory and bounded.

The production-shaped reference topology puts the backend on the proxy's **loopback interface inside its private network namespace**, with no separately published TCP port. Only TLS Traefik entry points are published (on loopback in CI). Keycloak is another isolated container reachable through its own TLS virtual host; its internal HTTP port is never directly published. Traefik must overwrite untrusted forwarded/proof fields, enforce exact external virtual hosts and preserve the bearer header. Docker isolation cannot guarantee Kubernetes pod network policy, host firewalling, real-world certificate maintenance, protection from compromised colocated workloads or a secret leaked by a proxy. Verify all of those during site deployment. Evidence: `tests/ingress_oidc_ci.py` and `docs/INGRESS_OAUTH_CI.md`.
