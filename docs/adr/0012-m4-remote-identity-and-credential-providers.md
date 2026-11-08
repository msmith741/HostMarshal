# ADR-0012: M4 remote identity and credential-provider boundaries

- **Status:** Proposed; JWT/HTTP and restricted Vault-compatible signer slices implemented, full M4 gate pending
- **Date:** 2026-11-07
- **Scope:** Authenticated remote MCP transport, provider-neutral credentials, and optional Vault SSH CA

## Context

M3 is a trusted-local-launcher stdio service. Its credential lease is a protected local SSH private-key path; it is not a short-lived secret. Remote access must not reuse the local principal flag, a forwarded `X-User` header, an unverified JWT claim, or an HTTP proxy's mere assertion of authentication.

## Decision: distinct listener and principal construction

Maintain stdio with its existing launcher-bound issuer. Introduce remote Streamable HTTP **only behind a new independent authentication boundary**. The remote transport must verify each request before MCP parsing or tool discovery. Each request obtains a newly constructed `AuthenticatedCaller` with issuer, subject, authentication method and verified audience; never retain a global caller across connections.

### OIDC/JWT validation contract

- TLS is mandatory on the externally exposed endpoint, terminated by HostMarshal or by an explicitly trusted, access-controlled ingress. The latter must not be reachable by bypassing that ingress.
- Verify the JWT signature with an issuer-specific pinned JWKS origin, accepted algorithm allowlist, exact `iss`, expected resource `aud`, `exp`, `nbf` and `iat` with bounded clock skew, nonempty `sub`, and token type/scope policy. Reject `alg=none`, unsigned tokens, missing `kid`, algorithm confusion, stale keys, and mismatched issuer or audience.
- JWKS refresh is bounded and pinned to configured HTTPS hosts. Fail closed when keys are unavailable; never derive discovery URLs from untrusted token contents.
- MCP authorization metadata is **not** identity. HTTP auth failures return 401 with appropriate challenge; authorization failures remain default-deny. Middleware-observed transport/authentication rejections require sanitized, identity-safe audit commitment; if the configured sink rejects the record, return 503. Do not attribute unverified JWT claims to a caller or promise audit for HTTP parser/proxy refusals before the middleware.
- Require a resource-specific audience and prevent access-token forwarding to downstream adapters. Protect against CSRF and cross-origin abuse: validate `Origin` for browser-originated requests, configure no permissive CORS, reject unexpected Host headers and enforce request body/time/concurrency limits.
- Stateless HTTP is the preferred first implementation; if MCP session IDs are later enabled, bind session to verified subject and prevent session fixation or cross-principal reuse.
- Do not permit anonymous fallback, local launcher identity fallback, or query-string access tokens. Use a per-request caller to filter tool discovery and execute grants.

### Credential provider contract

- The broker is called only after grant authorization and pre-execution audit, with exact operation, inventory target and purpose. Configuration for provider selection is administrator-owned and validated at startup; no client can choose a provider.
- An optional Vault provider must authenticate with a dedicated restricted Vault workload identity, use only approved paths/roles, verify Vault server TLS, and prohibit redirects/proxies. Never expose Vault token, SSH private key, certificate, lease ID or provider errors to MCP.
- Prefer **Vault SSH certificate signing**: the operator provisions an approved SSH CA and restricted Vault SSH role, and HostMarshal submits a generated short-lived user public key. The returned signed SSH certificate is bound to the exact target account and expiry. A local temporary private key and signed cert are protected, cleaned up on cancellation/drop, and never appear in logs. This requires a separate approved adapter contract; do not repurpose a permanent-key path as if it were a renewable lease.
- Provider leases have expiration, cancellation and revocation semantics. If expiration cannot be proven to exceed the execution deadline plus safety margin, deny. Broker outage or lease renewal failure must fail closed. Never automatically fall back from Vault to a broader local key.
- Multiple provider backends may be configured without code changes **only for installed, vetted provider types**; no YAML-controlled arbitrary HTTP secret request or plugin execution.

### Provider-neutral reference adapter

An optional hypervisor API observation adapter can be added after the identity/provider tests pass, but it must use a fixed allowlisted endpoint and action, narrowly scoped API token, strict TLS and output filtering. It is not a prerequisite for secure remote MCP. A generic API request tool is prohibited.

## Required integration and negative-path evidence

1. Disposable OIDC issuer/JWKS and HTTP MCP client: two issuers/subjects, per-subject tool visibility and target grants, valid tokens, expired/not-yet-valid tokens, forged signatures, wrong audience, wrong issuer, unsupported algorithm, JWKS outage/rotation, no auth, malicious Origin and header spoofing.
2. TLS and HTTP transport: bypassed proxy, missing TLS, body-size and deadline enforcement, malformed JSON-RPC, concurrent sessions, reconnect, protocol-version conformance and denial audit.
3. Disposable Vault dev server with restricted policies and an isolated SSH CA: successful scoped issuance, wrong role/target, wrong Vault token, Vault outage, malformed certificate, expiry, rotation, cancellation cleanup and no secret disclosure.
4. M2/M3 regression: authorization before broker, no target substitution, audit failure prevents credential acquisition, strict pinned SSH trust, and no generic shell/API.
5. Release gates: documented operational trust roots, key rotation, outage and break-glass runbooks, pinned dependencies, vulnerability scan, complete traceability and independent security review.

## Implemented first remote-transport slice

A loopback-only stateless Streamable HTTP handler now verifies each request against a **locally pinned, administrator-owned JWKS** using asymmetric RS256 keys and exact issuer/audience/expiry/not-before/issued-at/scope constraints, creates a verified caller, and delegates to the existing coordinator. The provider router enforces exact operation/target/purpose without fallback. These are **partial implementations only**: there is no external TLS ingress, online JWKS rotation/authorization-server metadata, protected-resource metadata, cross-issuer registry or real-Vault-validated SSH certificate provider. The opt-in signer now exists behind a protected local token file, with ephemeral key lifecycle, pinned CAs and strict certificate validation, but lacks real Vault/workload identity CI. See [M4 remote MCP deployment](../REMOTE_MCP.md) and [implementation gates](../M4_IMPLEMENTATION_PLAN.md).

## Security non-goals

M4 does not grant write/mutation privileges, unattended remediation, interactive shells, arbitrary URLs or commands, externally loaded plugins, or production certification.

## Status and migration

This ADR is **Proposed** until a complete implementation and its tests exist. Existing local stdio deployments remain supported; the presence of this ADR or provider-neutral interfaces does not imply that remote HTTP or Vault is active.
