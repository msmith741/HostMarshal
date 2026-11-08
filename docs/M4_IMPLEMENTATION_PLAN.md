# M4 implementation plan and security acceptance gates

**Status: in progress.** M4 is not complete until every security gate below passes in public CI. This document is vendor-neutral and uses no private environment assumptions.

## Phase A — Broker composition and lease contracts

- Keep the existing M2 `CredentialBroker` authorization boundary and M3 `LocalSshKeyBroker` unchanged.
- Add a **strict provider-selection registry** that binds an exact approved operation/target/purpose tuple to one vetted broker; no fallback on denial/outage. Duplicate mappings and unknown targets fail at startup.
- Extend the lease contract with expiry and revocation/cancellation semantics before enabling remote provider secrets.
- Add unit tests for no matching provider, duplicate mapping, cross-target/cross-operation attempts, provider denial, outage, deadline and cancellation.
- Keep the default deny broker. Local key files remain an explicit opt-in compatibility path, not a secret-service implementation.

## Phase B — Remote identity and Streamable HTTP

- Separate `--listen` remote mode from stdio, with no remote `--principal` flag.
- Implement a vetted per-request OIDC/JWT verifier with configured HTTPS JWKS origin and exact resource audience. Reject token-based key discovery or trust-on-first-use.
- Ensure request-specific `AuthenticatedCaller` is used for both tool discovery and execution, never a shared global identity.
- Enforce TLS or protected ingress boundary, explicit Host/Origin controls, 401 challenge, body limits, timeouts, concurrency quotas and no permissive CORS.
- Test using disposable issuer and remote clients for all invalid-token, cross-identity, reload, concurrency and bypass cases.
- Do not ship a listener accepting unverified bearer tokens or headers.

### Phase B vertical-slice progress

The project now includes a loopback-only HTTP MCP listener with signed access-token validation using a pinned, local JWKS. Verification is per request; the SDK passes a trusted identity extension into the existing execution coordinator. Test coverage includes forged/expired/wrong-audience tokens, subject isolation and common HTTP header bypasses. The middleware also writes redacted, reason-coded denial events to the same configured sink, preserves verified/unverified identity boundaries and returns HTTP 503 if it cannot record a rejection. The HTTP parser and upstream proxy remain outside that audit boundary.

**Still blocking phase-B completion:** online JWKS renewal/rotation, external TLS ingress proof and bypass isolation, authorization-server/protected-resource metadata, full lifecycle/request audit coverage beyond middleware-visible denials, and more extensive concurrency/availability tests. No internet-facing listener is enabled.

## Phase C — Vault SSH certificate provider

- Introduce an optional provider that authenticates to Vault with a narrow workload identity, verifies TLS and approved role/path, and obtains **short-lived SSH user certificates**.
- Generate ephemeral private/public key pairs with protected lifecycle; sign only via approved Vault SSH CA role. Validate signed certificate principals, key, lifetime and target restrictions.
- Integrate certificate and private key as a bounded credential lease with cleanup on cancellation/timeout and no material in logs or MCP output.
- Use disposable Vault and sshd integration fixtures, negative tests for wrong target, expired cert, issuer mismatch, outage, renewal and cleanup.
- Retain fail-closed behavior when Vault is unavailable. Do not silently substitute a static SSH key.

### Phase C in-progress implementation

The optional `--vault-ssh-config` provider now generates per-call Ed25519 keys, calls a fixed Vault SSH signing role over CA-verified TLS, validates certificates against an independently pinned SSH CA with exact inventory principal, key binding, restricted extensions and TTL, and retains key/cert files only for the lease lifetime. Launcher configuration refuses concurrent local-static and Vault providers; the M2 deadline bounds issuance and execution. The disposable Vault-API-compatible signer and real SSH CA/sshd test positive and negative paths.

**Completed phase-C integration gate (CI):** `tests/vault_real_smoke.py` provisions a disposable TLS-enabled HashiCorp Vault 2.2.1 dev server, an Ed25519 SSH CA, a policy-restricted signing token and a real OpenSSH server. It verifies authorized SSH login, token replacement/revocation, provider outage, denied operations and temporary-key cleanup. **Next implemented experimental slice (FR-022, verification in progress):** exclusive AppRole RoleID/SecretID authentication and serialized on-demand renew-self with exact token-policy/lease validation, sticky quarantine on renewal/auth denial and no static-token fallback. **Still open:** Kubernetes-native workload identity, proactive renewal across idle periods, administrative reactivation/recovery, full CA rotation and recovery fault injection, independent security review and production deployment proof. A local operator-rotated token file is not a complete credential lifecycle service. See [Vault SSH deployment](VAULT_SSH.md).

## Phase D — Optional provider-neutral API adapter

- Add only vetted fixed read-only operations with typed target inventory and scoped credentials.
- No generic HTTP request, arbitrary API method, or direct client token forwarding.
- Test a disposable API server, malformed responses, TLS failure, unauthorized resources and output redaction.

## Release gate

M4 is complete only when A–C have independently green positive/negative CI, existing M1–M3 regression suites pass, versioned schema/ADR/product requirements and traceability are updated, deployment instructions cover credential rotation and outage response, and a security review confirms no transport bypass. D is optional and separately gated.

**Important:** A provider registry alone is not remote MCP authentication. A secure HTTP transport alone is not an external secret provider. Do not mark M4 complete on either partial result.
