# M4 remote MCP — pinned-key JWT authentication (experimental)

**Status:** M4 phase-B vertical slice, pre-alpha and **loopback-only**. The remote MCP entrypoint accepts **no anonymous access**, does not trust HTTP user headers, and authenticates each request before the rmcp Streamable HTTP service processes it. This is not a complete OIDC authorization-server integration or production deployment guide.

## Security boundaries

1. Only the `http --listen 127.0.0.1:<port>` command enables this transport. Binding `0.0.0.0` or a public/private non-loopback address is refused.
2. Exposing the listener to remote clients **requires a separately configured TLS reverse proxy**, with network access to the loopback backend limited to that proxy. The proxy must preserve the authorized public `Host` header and must not strip the Authorization bearer header. The MCP service ignores `X-Forwarded-User` and similar identity claims.
3. Each HTTP POST must carry exactly one `Authorization: Bearer <access-token>` header. The token signature is verified with an **administrator-pinned offline JWKS file**, not a key discovered from untrusted token contents. Only RSA/RS256 keys with a unique trusted `kid`, `kty=RSA`, `use=sig` and `alg=RS256` are admitted.
4. The token header must identify an **access token** (`typ=at+jwt`). Validation requires exact `iss` and `aud`, nonempty `sub`, `exp`, `nbf`, `iat`, `hostmarshal.observe` scope, at most 30 seconds clock skew and one-hour issuance lifetime.
5. The verified issuer and subject form the `AuthenticatedCaller` used for **both discovery and execution**. A JWT with a valid signature but no matching HostMarshal Grant sees no authorized capabilities. Stdio `--principal` never establishes a remote caller's identity.
6. HTTP uses stateless MCP mode and no server-side session principal cache. `Origin` requests are denied; there is no permissive CORS. Incorrect `Host` is denied. The server limits request bodies to 256 KiB, uses runtime concurrency limits and requires POST; GET/DELETE return 405.
7. The same central ExecutionCoordinator enforces operation, inventory target, credential broker, timeout, output validation and audit. **No new command execution, write or arbitrary URL capabilities** are introduced.

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

An administrator must independently verify and install the issuer public keys; do **not** bootstrap from a URL in a JWT header. Key rotation requires a trusted replacement of the file and a process restart in this first slice; there is no automatic online JWKS refresh or authorization-server metadata discovery.

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

## Fault handling, testing and limitations

`tests/remote_http_smoke.py` generates an ephemeral RSA issuer/JWKS and tests valid and invalid access tokens, cross-subject isolation, authorization denial, wrong Host/Origin, spoofed forwarded identity, invalid input, non-loopback binding, oversized bodies and key-file permissions. The test uses only local loopback connections and fictional hosts.

The design is intentionally conservative but **not production hardened**: a pinned file does not implement dynamic JWKS renewal, revocation, live issuer discovery or OAuth protected-resource metadata; a local TLS reverse proxy is not created or managed by HostMarshal; request-origin authentication failures are not yet committed to the same durable audit sink as authorized MCP invocations; transport-level distributed rate limiting and remote request tracing remain open. Test certificate rotation, reverse-proxy Host preservation, exposed listener isolation and outage recovery before real deployment.

M4 also requires a properly scoped Vault SSH certificate provider and lease lifecycle tests; the M3 local SSH key-path broker is **not** that integration. See [ADR-0012](adr/0012-m4-remote-identity-and-credential-providers.md), [M4 plan](M4_IMPLEMENTATION_PLAN.md), [Security](SECURITY_ARCHITECTURE.md), and [Traceability](TRACEABILITY.md).
