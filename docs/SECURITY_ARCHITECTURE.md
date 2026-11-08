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

Vault authentication supports a protected operator-token file or mutually exclusive AppRole/external-JWT workload credentials. Renewable Vault service tokens are checked for an exact policy and bounded TTL; AppRole/JWT tokens are maintained by an in-process worker after first approved use, while failed renewal/signing places the source in fail-closed quarantine. Default recovery remains restart-only; an optional **administrator-root-owned** Unix recovery epoch permits a fresh login after a strictly increased counter. This is neither automatic self-healing nor a Kubernetes-specific authenticator. A disposable real Vault 2.2.1 TLS signer and restricted token/SSH role are covered by CI. Production identity provisioning, CA rotation, tamper-evident background audit, live ingress and OS egress isolation remain incomplete. See [Vault SSH](VAULT_SSH.md) and [ADR-0016](adr/0016-vault-proactive-renewal-recovery.md).

## Residual risks

Signatures prove origin, not safety. A compromised broker/OS or overly powerful target credential can circumvent application-level intent. Misclassified adapter operations remain dangerous unless runtime and target permissions enforce least privilege. Security review and adversarial tests must assess these risks, not merely run Clippy.

## Release security gates

No live target adapter until identity, authorization, target validation, time/output bounds, and auditable outcomes are demonstrated. No third-party plugin execution without independent isolation verification. No privileged mutation or production claims without audited policy, approvals, failure testing, and documented response procedures.

## FR-023–FR-025: remote issuer trust and reverse-proxy attestations

The optional online verifier has a distinct administrator-fixed URL and CA, refreshes under a single async mutex on request after its bounded interval, discards previous keys on successful rotation and **does not use stale keys after refresh failure**. RFC 9728 resource metadata is public through the trusted ingress but does not create a caller. In `trustedProxy` mode, all backend calls require a protected shared ingress proof and validated forwarded HTTPS/public Host. The loopback listener cannot be reached from another host, but malicious colocated processes, a compromised proxy/proof, improper external network namespace or forged client headers passed through the ingress remain deployment risks. The CI TLS proxy fixture validates the logical protocol boundary only; it does not establish production TLS or OS isolation. See [REMOTE_MCP.md](REMOTE_MCP.md).

## M4 FR-026/FR-027 — real OAuth and isolated ingress acceptance

For an administrator-configured `authorizationServerMetadataUrl`, HostMarshal requires online JWKS and retrieves OIDC discovery over the *same independently pinned TLS root* used by the JWKS client. Startup fails if metadata redirects, exceeds size/time budgets, identifies a different issuer/JWKS, changes origin for OAuth endpoints or does not advertise client-credentials. Discovery is **not** a trust-on-first-use step: all issuer, CA and JWKS URL expectations are already administrator-fixed. JWTs remain independently signed/validated and are never forwarded to adapters. The `nbf` claim, optional for RFC 9068 access tokens, is validated when present; `iat` and `exp` remain mandatory and bounded.

The production-shaped reference topology puts the backend on the proxy's **loopback interface inside its private network namespace**, with no separately published TCP port. Only TLS Traefik entry points are published (on loopback in CI). Keycloak is another isolated container reachable through its own TLS virtual host; its internal HTTP port is never directly published. Traefik must overwrite untrusted forwarded/proof fields, enforce exact external virtual hosts and preserve the bearer header. Docker isolation cannot guarantee Kubernetes pod network policy, host firewalling, real-world certificate maintenance, protection from compromised colocated workloads or a secret leaked by a proxy. Verify all of those during site deployment. Evidence: `tests/ingress_oidc_ci.py` and `docs/INGRESS_OAUTH_CI.md`.

## M4 FR-028–FR-030 — Kubernetes sidecar trust boundary

The K3s CI profile retains HostMarshal's non-negotiable **loopback-only** listener. An unprivileged local NGINX sidecar shares the Pod network namespace and forwards fixed MCP/resource-metadata paths to `127.0.0.1:8338`. It overwrites proxy-owned Host/HTTPS/ingress-proof headers and never forwards caller-provided identity as an authenticated principal. Only a ClusterIP service exposes the sidecar TCP port 8080, with ingress restricted by a K3s NetworkPolicy whose same peer element ANDs the kube-system namespace label with the Traefik Pod label. The Pod has no service-account token, uses owner-only staged auth files in a memory volume, and drops application privileges; the RSA signing private key never enters the cluster. The NGINX sidecar itself remains within the trusted computing base.

Kubernetes NetworkPolicy is **additive**, and ingress restrictions are only effective if all matching policies are sufficiently narrow and the CNI actually enforces them. Accordingly the CI suite proves negative PodIP/Service paths, verifies its attacker has working network connectivity, deliberately installs an overbroad policy to **reopen** that path, and removes it to re-establish denial. It also verifies authorized TLS MCP access and denial of malformed/foreign identity, Host, Origin and TLS trust. That is stronger evidence than YAML lint or synthetic Docker bridge tests, but does not prove any production network/security property (MetalLB/host routing, compromised sidecar, CNI versions, IPv6, router VLANs, proof/cert renewal or site RBAC). See ADR-0014.

**Non-root staging and verified CI scope:** The disposable K3s profile uses Pod `fsGroup: 10001` so a GID 10001 non-root init can read 0440 Secret projections and write a memory-backed runtime directory. Copied auth/proof files are owner-readable mode 0600 and independently checked by HostMarshal. Init and both runtime containers drop all Linux capabilities; no CHOWN/FOWNER escalation or root init is permitted. A manifest preflight tests these invariants before single-node authenticated-ingress smoke, and a separate multi-node job tests CNI isolation with an unsafe-policy positive control. Neither proves site-level Secret rotation or router/CNI security.

**Projected configuration:** Kubernetes ConfigMap keys are symlinks by design. The unprivileged init reads only known versioned `host.yaml`, `capability.yaml` and `grant.yaml` names from a read-only projected ConfigMap, creates new ordinary files in a memory-backed volume, and mounts that materialized directory read-only at HostMarshal's `/config`. The strict HostMarshal loader continues to reject symlinks or nonregular entries, including unexpected additions.

## M4 FR-031: optional external workload JWT -> Vault security boundary

HostMarshal accepts `jwtAuth` only from the protected launch-time Vault SSH signer config, with a fixed, validated JWT auth mount, fixed role, constrained local JWT file path, and exact expected Vault lease policy. A projected-token symlink is acceptable **only** in the standard atomic `token -> ..data/token` form and only if it resolves inside the trusted mount directory; arbitrary symlink targets, directory escapes, group/other-writable inputs, oversized or malformed JWT strings are denied. The source JWT is never used as an MCP caller principal, signing target or Vault URL. It is forwarded once to the pinned-TLS Vault auth endpoint, whose server-side role must cryptographically bind signature, issuer, audience and subject.

The resulting Vault token is **not** the MCP access token. It is an in-memory, short-lived restricted signing credential for an already-authorized SSH operation; reuse and renewal are serialized, expiry/policy/privilege failures quarantine the session, and source JWT rotation alone cannot silently bypass a quarantined lease. HostMarshal does not validate the issuer JWT signature independently; Vault must do so using configured trusted public keys/JWKS and role-bound claims. If the process/issuer/Vault role is compromised, or a co-UID attacker can mutate protected mounts, the trust boundary can fail. Proactive renewal and operator-gated recovery are implemented experimentally in FR-032/FR-033; production recovery procedures, Vault role bootstrap and independent audit evidence remain open. See ADR-0015 and `WORKLOAD_JWT_AUTH.md`.

## FR-032/FR-033: proactive renewable lease and operator recovery boundary

The trusted provider may renew only an already acquired, exactly scoped **Vault AppRole or external-JWT signing lease**. No external login occurs until the existing caller authorization has permitted a credential request. A background task holding only a weak lifecycle reference is started after first use, renews the same token via the fixed pinned-TLS Vault renew-self endpoint, and is aborted when its lifecycle drops. The issued Vault token remains in zeroizing process memory, is never a caller identity and never appears in MCP results. A single async lock serializes foreground and background renewals. Renewed token ID, policy, renewable status and TTL are reverified every time. Any denial, error, expiry or revoked sign permission causes sticky quarantine; the worker has **no retry or login fallback**.

An optional recovery epoch file is considered an **operator authorization channel** and is never present in user-controllable YAML, MCP arguments or provider responses. A mode-0400 file owned by the same process user is not sufficient: that user can change its mode. Accordingly, on Unix the implementation insists the marker and **every path ancestor** are root-owned and not group/other writable; the marker itself has no write bits, is a canonical regular path and is bounded to an unsigned integer. A strictly increased epoch compared with the quarantine baseline permits one fresh role-bound Vault login. Invalid/old/rolled-back values cannot lower that baseline, and an unsuccessful login consumes an epoch. Without this configured file, an authorized process restart is required. Operators should run HostMarshal unprivileged and publish marker changes atomically from a separate administrative principal, not mount a writable operator directory into the process.

**FR-034 maintenance audit boundary:** After first authorized credential use, the launcher-selected audit sink is shared by the execution coordinator and Vault AppRole/JWT lifecycle. Each renewal and operator-epoch recovery login emits redacted `authorized` and terminal audit commitments with the literal `<system>` identity; an event cannot be attributed to an MCP caller. Failure of a precommit prevents renewal or recovery login; failure to commit a terminal record discards the prospective usable token and quarantines the lease. Audit I/O occurs under the existing serialized lease lock. No credentials, Vault URLs, policy strings or remote error bodies are included. This closes the in-process background audit gap but does not isolate the sink from process compromise or guarantee delivery/retention at the site.

**Explicit limitations:** This optional Unix control is not a substitute for OS identity separation, secure filesystem/mount setup, or root-compromise resistance. The background renewal itself is not yet committed as an independently durable audit event; the next requested operation still yields an audited denial if the provider is quarantined. Production issuer enrollment, trust-root and SSH CA rotation, Vault/Kubernetes auth configuration, tenant-specific recovery procedure, failover, and independent threat review remain out of scope.
