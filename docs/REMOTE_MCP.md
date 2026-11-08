# M4 remote MCP — pinned-key JWT authentication (experimental)

**Status:** M4 phase-B vertical slice, pre-alpha and **loopback-only**. The remote MCP entrypoint accepts **no anonymous access**, does not trust HTTP user headers, and authenticates each request before the rmcp Streamable HTTP service processes it. This is not a complete OIDC authorization-server integration or production deployment guide.

## Security boundaries

1. Only the `http --listen 127.0.0.1:<port>` command enables this transport. Binding `0.0.0.0` or a public/private non-loopback address is refused.
2. Exposing the listener to remote clients **requires a separately configured TLS reverse proxy**, with network access to the loopback backend limited to that proxy. The proxy must preserve the authorized public `Host` header and must not strip the Authorization bearer header. The MCP service ignores `X-Forwarded-User` and similar identity claims.
3. Each HTTP POST must carry exactly one `Authorization: Bearer <access-token>` header. The token signature is verified with an **administrator-pinned offline JWKS file**, not a key discovered from untrusted token contents. Only RSA/RS256 keys with a unique trusted `kid`, `kty=RSA`, `use=sig` and `alg=RS256` are admitted.
4. The token header must identify an **access token** (`typ=at+jwt`). Validation requires exact `iss` and `aud`, nonempty `sub`, `exp`, `nbf`, `iat`, `hostmarshal.observe` scope, at most 30 seconds clock skew and one-hour issuance lifetime.
5. The verified issuer and subject form the `AuthenticatedCaller` used for **both discovery and execution**. A JWT with a valid signature but no matching HostMarshal Grant sees no authorized capabilities. Stdio `--principal` never establishes a remote caller's identity.
6. HTTP uses stateless MCP mode and no server-side session principal cache. `Origin` requests are denied; there is no permissive CORS. Incorrect `Host` is denied. The server limits request bodies to 256 KiB, uses runtime concurrency limits and requires POST; GET/DELETE return 405.
7. The same central ExecutionCoordinator enforces operation, inventory target, credential broker, timeout, output validation and audit. The HTTP middleware also records sanitized denial events for requests it rejects and downstream HTTP error responses; failed denial audit responds 503. Unverified tokens cannot name an audit subject. **No new command execution, write or arbitrary URL capabilities** are introduced.

## Administrator-owned authentication configuration

Create an OS-protected local JSON file (owner-only mode `0600`, no symlink) at an **absolute** path, separate from YAML capability manifests:

```json
{
  "apiVersion": "hostmarshal.io/remote-auth/v1alpha1",
  "issuer": "https://issuer.example.invalid/",
  "audience": "https://mcp.example.invalid/mcp",
  "allowedHost": "mcp.example.invalid",
  "jwksFile": "/etc/hostmarshal/trust/issuer-jwks.json"
}
```

The pinned JWKS file is a locally provisioned bounded JSON document containing `keys`, each with `kid`, `kty`, `alg`, `use`, `n`, and `e` (RSA public modulus/exponent). The file must be regular, not a symlink and not group/world writable. **Never paste private RSA keys or bearer tokens into the repository.**

An administrator must independently verify and install the issuer public keys; do **not** bootstrap from a URL in a JWT header. The offline `jwksFile` mode requires an operator-owned file replacement and restart for rotation. The optional pinned-HTTPS online mode below supports bounded request-driven refresh with no stale-on-error fallback.

Grant resource entries must refer to the exact issuer and verified token subject, for example:

```yaml
apiVersion: hostmarshal.io/v1alpha1
kind: Grant
metadata:
  name: remote-observer
spec:
  subjects:
    - issuer: https://issuer.example.invalid/
      subject: operator-a
  capabilities: [inventory.inspect]
  targets:
    kind: Host
    names: [sample-linux]
```

Deploy using a dedicated low-privilege service identity:

```sh
hostmarshal config validate /etc/hostmarshal/config
hostmarshal http --listen 127.0.0.1:8338 \
  --config-dir /etc/hostmarshal/config \
  --auth-config /etc/hostmarshal/remote-auth.json \
  --audit-log /var/lib/hostmarshal/audit/events.jsonl
```

The protected proxy must expose `https://mcp.example.invalid/mcp` and forward that same public Host header; if the proxy rewrites Host, configure `allowedHost` for the exact value the backend actually sees and enforce the expected external authority at the proxy. The proxy must not permit bypass and must not accept unauthenticated access. The JWT's audience remains the **external resource identifier**, never the loopback backend URL.

The 2026-07-28 Streamable HTTP wire format additionally requires `MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name` for named tool calls; values must match JSON-RPC body fields. Clients must supply per-request `_meta` containing the protocol version and capabilities. The SDK rejects missing or mismatched routing headers before tool invocation.

## Fault handling, testing and limitations

`tests/remote_http_smoke.py` generates an ephemeral RSA issuer/JWKS and tests valid and invalid access tokens, cross-subject isolation, authorization denial, wrong Host/Origin, spoofed forwarded identity, invalid input, non-loopback binding, oversized bodies and key-file permissions. The test uses only local loopback connections and fictional hosts.

The design is intentionally conservative but **not production hardened**: the offline pinned file does not implement dynamic JWKS renewal, and neither mode implements a complete OAuth login, token revocation or dynamic authorization-server discovery; a local TLS reverse proxy is not created or managed by HostMarshal. Middleware-observed HTTP rejections now use the configured audit sink with fixed reason codes, but errors rejected by the HTTP parser before middleware, by an external proxy, or during disconnection are not covered; local JSONL files provide no tamper evidence. Transport-level distributed rate limiting and remote request tracing remain open. Test certificate rotation, reverse-proxy Host preservation, exposed listener isolation and outage recovery before real deployment.

M4 now includes an optional **experimental** Vault-compatible SSH certificate signer and ephemeral lease cleanup; see [Vault SSH](VAULT_SSH.md). Disposable real Vault 2.2.1 TLS signing/SSH tests are now in CI, while trusted workload identity, token renewal and production ingress assurance remain required. The M3 local SSH key-path broker remains separate and cannot be configured as a fallback. See [ADR-0012](adr/0012-m4-remote-identity-and-credential-providers.md), [M4 plan](M4_IMPLEMENTATION_PLAN.md), [Security](SECURITY_ARCHITECTURE.md), and [Traceability](TRACEABILITY.md).


## M4 phase-B hardening slice: online JWKS, protected-resource metadata and ingress proof

**Experimental / CI-gated.** The existing `jwksFile` mode is retained. A deployment may instead configure **exactly one** trusted online source with `jwksUrl`, `jwksCaCertificateFile` and `jwksRefreshSeconds` (30–3600). The URL is chosen by the administrator, must be HTTPS, and can have no query, fragment or redirect. The client trusts only the administrator-supplied CA, disables platform roots and ambient proxies, and applies short network deadlines and a 32 KiB JWKS cap. RSA/RS256 key validation and exact issuer/audience checks are unchanged. **The JWT cannot select a JWKS endpoint or override trust.**

```json
{
  "apiVersion": "hostmarshal.io/remote-auth/v1alpha1",
  "issuer": "https://issuer.example.invalid/",
  "audience": "https://mcp.example.invalid/mcp",
  "allowedHost": "127.0.0.1:8338",
  "jwksUrl": "https://issuer.example.invalid/.well-known/jwks.json",
  "jwksCaCertificateFile": "/etc/hostmarshal/trust/issuer-tls-ca.pem",
  "jwksRefreshSeconds": 60,
  "ingress": {
    "mode": "trustedProxy",
    "publicHost": "mcp.example.invalid",
    "proofFile": "/run/hostmarshal/ingress-proof"
  }
}
```

On the first bearer-verification attempt the verifier retrieves the JWKS over trusted HTTPS. Once its bounded freshness interval expires, the next verification serializes an online refresh and **replaces** the trusted key set. Refresh failure, malformed JSON, wrong CA, HTTP redirect, duplicate key IDs, or unavailable service means **no stale-key fallback**. Repeating a valid but rotated-out JWT fails after the refresh boundary; newly signed tokens may work without restarting the service. This is **request-driven** rather than proactive refresh: the operator must independently assess the key-revocation latency of the configured interval and availability impact of failing closed. Initial fetch and refresh can add up to the configured network deadline to request latency. This does not verify real-world issuer discovery, revocation endpoints, OIDC configuration, or entitlement changes.

The protected resource metadata for the configured `/mcp` audience is published at **`GET /.well-known/oauth-protected-resource/mcp`** with `resource` equal to the exact configured audience, `authorization_servers` set to the trusted configured issuer, and only the `hostmarshal.observe` scope and bearer-header delivery advertised. A `401` bearer challenge includes `resource_metadata=` pointing to the public HTTPS metadata URL, per [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html) and the [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization). This **does not host** authorization-server metadata, perform OAuth login, client registration, or issue access tokens; the issuer must provide those services separately.

**Ingress validation:** The listener still binds **only loopback**. With `ingress.mode=trustedProxy`, *every* request, including the public metadata GET, additionally requires exactly one `X-Forwarded-Proto: https`, one matching `X-Forwarded-Host`, and one `X-HostMarshal-Ingress-Proof` equal to a randomly provisioned, high-entropy OS-protected shared secret. `publicHost` must equal the configured resource audience authority. Proof comparison uses a fixed-length SHA-256 digest. Missing, duplicate, wrong, or HTTP-scheme attestations deny before bearer parsing, with sanitized `http_ingress_rejected` audit. A client cannot select a caller using `X-Forwarded-User`.

The **external reverse proxy must** terminate trusted HTTPS, verify the external Host, **remove any client-supplied** `X-Forwarded-Proto`, `X-Forwarded-Host` and `X-HostMarshal-Ingress-Proof`, then inject its own validated values and proof; never expose the backend TCP port beyond the proxy's trust boundary. Use a private network namespace or equivalent OS isolation so arbitrary colocated workloads cannot read the proof file, inject local TCP requests, or impersonate the proxy. Rotate the proof with a controlled restart. A shared secret is not mTLS, does not cryptographically bind an individual request, and cannot defend against a compromised same-UID process or a proxy leaking its proof; production ingress topology and bypass isolation require separate deployment validation. **This configuration is pre-alpha, not a turnkey HTTPS ingress.**

The CI-only `tests/remote_hardening_smoke.py` runs disposable localhost TLS issuers and TLS forwarding proxy, rotates two RSA keys under the same `kid`, verifies old-key removal after the refresh bound, tests an untrusted proxy certificate, wrong proof/direct-backend bypass, restricted metadata discovery and challenge behavior, and rejects unexpected JWKS redirects. See FR-023–FR-025, [Traceability](TRACEABILITY.md), and [M4 acceptance plan](M4_IMPLEMENTATION_PLAN.md).
