# M4 — Authenticated remote MCP over Streamable HTTP

**Status:** Pre-alpha OAuth **resource server**. Requires a colocated HTTPS reverse proxy and an external standards-compliant OAuth/OIDC authorization server. HostMarshal itself serves **loopback cleartext HTTP only** and refuses a non-loopback bind. Do not publish the backend port directly.

## Supported architecture

```text
Remote MCP client ──HTTPS──> colocated TLS gateway ──loopback──>
  HostMarshal Streamable HTTP [Bearer token validation on EVERY request]
    -> authenticated issuer+subject
    -> immutable snapshot + default-deny Grant + scope
    -> M2 execution/audit/broker -> M3 vetted observation adapter
```

The auth issuer signs **access tokens**. HostMarshal validates a pinned JWKS (no automatic fetch) and responds to unauthenticated requests with OAuth 2.0 Protected Resource Metadata per RFC9728. The client discovers the external auth server via that metadata, obtains a token for **this exact resource URI** using an appropriate OAuth 2.1 flow and Resource Indicator (RFC8707), then sends `Authorization: Bearer ...` on each request.

Supported access-token subset: **RS256 JWT**, `typ: at+jwt`, known `kid`, configured issuer, exact resource audience, issued-at, valid expiration and optional not-before, lifetime no more than **600 seconds**, and scope `hostmarshal:observe`. Opaque tokens, other algorithms, access-token introspection, online revocation, DPoP, mTLS-bound tokens and JWKS auto-refresh are not implemented. Invalid/expired token responses are **401**; a token with insufficient scope is refused. A scope-bearing token does not itself grant an operation: YAML Grants still explicitly bind issuer, subject, capability and target.

## Secure deployment

1. Operate an independent OAuth/OIDC issuer with HTTPS authorization-server discovery. Configure it to mint appropriate **access** JWTs for the exact HostMarshal resource (not identity tokens).
2. Install the issuer's current approved JWKS public keys in a regular, administrator-managed file (not group/world-writable). Restrict its parent directories and replace it only through a trusted deployment process. Restart HostMarshal to rotate trusted signing keys.
3. Author a YAML Grant with `issuer: https://identity.example.invalid` and a verified `subject`; do **not** use the `local://trusted-launcher` issuer for remote tokens.
4. Configure a colocated TLS reverse proxy with a certificate valid for the canonical resource URL, strict Host/Origin enforcement, request size and rate limits, request header hygiene, no public exposure of the HostMarshal loopback backend, and **no caching** of tool responses or access tokens. For multi-instance deployments, configure each independently; M4 has no distributed sessions.
5. Start HostMarshal as a dedicated OS service account with protected manifest/audit paths:

```sh
hostmarshal http serve /etc/hostmarshal/config \
  --bind 127.0.0.1:8090 \
  --issuer https://identity.example.invalid \
  --resource https://marshal.example.invalid/mcp \
  --jwks-file /etc/hostmarshal/trust/issuer-jwks.json \
  --audit-log /var/lib/hostmarshal/audit/events.jsonl
```

The backend is *HTTP on loopback*, not an alternative TLS endpoint. Place the TLS proxy in the **same host or network namespace**. A remote proxy connecting to an arbitrary backend address is explicitly refused. Misconfiguration must not be fixed by binding HostMarshal on `0.0.0.0`. The public resource URI must match the auth token `aud` and the proxy's external HTTPS route exactly.

The two public protected-resource metadata endpoints are `/.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/mcp`; the MCP endpoint is `/mcp` and requires a Bearer token even for discovery. Missing or malformed access tokens receive `401` and `WWW-Authenticate: Bearer ... resource_metadata="..."`. A token is **never** passed to another resource or used to authenticate to Vault or managed hosts. Invalid `Origin` requests are rejected. The API accepts no token in the query string.

## Stateless caller isolation

The SDK handles MCP protocol framing. M4 explicitly disables old HTTP sessions and binds caller identity from verified HTTP authorization on each request. The older `2025-11-25` and modern `2026-07-28` MCP wire semantics are supported where the SDK allows; stdio remains independent. A client cannot choose its subject by setting `clientInfo`, `X-Forwarded-User`, or MCP tool arguments. A signed caller who lacks a HostMarshal Grant discovers no tools and cannot invoke a capability, regardless of its OAuth scope.

## Known limitations

No in-process OAuth authorization server, consent, account lifecycle, certificate management, dynamic JWKS download, online token revocation, token introspection, host-level ingress firewall configuration, external audit integrity, network QoS or per-subject network request quotas. An unexpired stolen bearer is replayable; minimize token lifetime and protect clients and TLS termination. New permission removals take effect for new requests after the validated snapshot swap, while in-flight pure observations can finish. See [ADR-0012](adr/0012-oauth-protected-stateless-mcp-http.md), [security architecture](SECURITY_ARCHITECTURE.md), and [M4 tests](TEST_STRATEGY.md).
