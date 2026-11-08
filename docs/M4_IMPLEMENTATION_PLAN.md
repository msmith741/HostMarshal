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

## Phase C — Vault SSH certificate provider

- Introduce an optional provider that authenticates to Vault with a narrow workload identity, verifies TLS and approved role/path, and obtains **short-lived SSH user certificates**.
- Generate ephemeral private/public key pairs with protected lifecycle; sign only via approved Vault SSH CA role. Validate signed certificate principals, key, lifetime and target restrictions.
- Integrate certificate and private key as a bounded credential lease with cleanup on cancellation/timeout and no material in logs or MCP output.
- Use disposable Vault and sshd integration fixtures, negative tests for wrong target, expired cert, issuer mismatch, outage, renewal and cleanup.
- Retain fail-closed behavior when Vault is unavailable. Do not silently substitute a static SSH key.

## Phase D — Optional provider-neutral API adapter

- Add only vetted fixed read-only operations with typed target inventory and scoped credentials.
- No generic HTTP request, arbitrary API method, or direct client token forwarding.
- Test a disposable API server, malformed responses, TLS failure, unauthorized resources and output redaction.

## Release gate

M4 is complete only when A–C have independently green positive/negative CI, existing M1–M3 regression suites pass, versioned schema/ADR/product requirements and traceability are updated, deployment instructions cover credential rotation and outage response, and a security review confirms no transport bypass. D is optional and separately gated.

**Important:** A provider registry alone is not remote MCP authentication. A secure HTTP transport alone is not an external secret provider. Do not mark M4 complete on either partial result.
