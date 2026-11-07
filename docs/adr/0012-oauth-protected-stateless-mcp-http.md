# ADR-0012: OAuth-protected stateless MCP over loopback HTTP

- **Status:** Accepted (M4 architectural review)
- **Date:** 2026-11-07
- **Deciders:** HostMarshal maintainer

## Context

HostMarshal's M2 authorization and M3 observation adapters must be reachable by remote MCP clients without treating HTTP connection metadata, MCP `clientInfo`, a claimed username or a previous client's session as authentication. The MCP 2026-07-28 authorization specification requires protected-resource discovery and resource-specific bearer access tokens.

## Decision

HostMarshal acts only as an **OAuth 2.1 protected resource server**, not an authorization server. An independently operated OIDC/OAuth provider handles authorization-code + PKCE, client registration, consent, authorization-server discovery and access-token issuance.

The **implemented M4 subset** validates short-lived, signed RFC9068-style JWT **access tokens** from a pinned administrator-installed JWKS file. It requires exactly RS256, an `at+jwt` header, known `kid`, an explicitly configured HTTPS issuer, exact resource audience, `iat`, `exp`, valid `nbf` if present, lifetime no greater than ten minutes, and the `hostmarshal:observe` scope. Missing/invalid tokens fail before the MCP service. Subjects and issuers become a private `AuthenticatedCaller` that cannot be assembled from caller-supplied tool parameters. The existing YAML Grant must *separately* authorize the issuer/subject/capability/target.

The MCP endpoint uses the official Rust SDK **stateless** Streamable HTTP transport. Each HTTP request is individually authenticated; no session retains a caller's identity. ClientInfo and header claims are never substituted for verified token claims. Unauthenticated calls receive an RFC6750 Bearer challenge with RFC9728 `resource_metadata`; public `/.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/mcp` provide the resource and authorization-server URLs.

The Rust backend binds **loopback only**. Operators MUST provide a **co-located, TLS-terminating reverse proxy** with correct Host/Origin handling, an authenticated TLS certificate and ingress/network controls. The loopback backend is not an independently HTTPS-capable network listener. TLS termination, public DNS and issuer metadata must be configured by the deployment administrator.

## Alternatives

- Trusting proxy `X-Forwarded-User`, `X-Remote-User` or MCP identity metadata: **rejected**, because an unauthenticated client can forge those headers without separate strict proxy identity contracts.
- A shared API token or all-clients-as-one principal: **rejected**, because tool listing and policy decisions become cross-client.
- In-process OAuth authorization server: **rejected** for M4; this would duplicate security-critical flows, consent and client registration.
- Automatic JWKS retrieval from a user-controlled URL: **rejected** for M4 to avoid SSRF, unpredictable key/issuer changes and implicit external trust. The operator installs an approved JWKS file and deliberately rotates it on process restart.
- Any-address cleartext HTTP: **rejected**. Direct non-loopback binding is refused.
- Long-lived server-side MCP sessions for pre-2026 clients: **rejected** in favor of stateless legacy request handling and per-request auth.

## Security consequences and limitations

This is a **JWT-only** OAuth protected-resource subset. Opaque tokens, token introspection, online revocation, mTLS/DPoP sender-constrained tokens, per-request external authorization-server callbacks, automatic JWKS rotation, multi-AS federation, and a built-in OAuth authorization server are **not** implemented. A stolen bearer token can be replayed until expiration (max ten minutes by local policy). Resource-server signature validation does not replace administrative enforcement of minimum issuer/client security.

A colocated HTTPS proxy must block unauthorized direct access to the backend, verify certificate trust, avoid forwarding credentials over insecure upstream paths, and never rewrite a client's bearer identity. Invalid HTTP authentication is rejected before the execution runtime and therefore does not generate a tool execution audit event; proxy/HTTP access logging and rate controls are separate requirements. Audit excludes raw tokens and tool arguments.

## Acceptance evidence

`src/http_auth.rs`, `src/http_server.rs`, `src/dynamic_mcp.rs`, `src/identity.rs`, `tests/http_auth_smoke.py`. CI verifies protected-resource metadata, Bearer challenge, verified issuer/subject mapping, allow/deny isolation, incorrect signature/key/algorithm/type, invalid expiry/issuer/audience/scope, forged client info, origin/URL rejection, loopback binding and audit redaction. See [remote deployment](../REMOTE_MCP_HTTP.md) and [traceability](../TRACEABILITY.md).
