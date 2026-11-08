# M4 Traefik ingress and real OAuth interoperability — reproducible CI reference

**Scope:** FR-026 and FR-027. This is a GitHub-hosted disposable integration test, not a production deployment template with real private certificates or firewall automation.

## Design and trust boundaries

```text
GitHub runner, loopback only
   https://mcp.example.invalid:8443   https://auth.example.invalid:8444
                  |                               |
                  v                               v
          Traefik v3.6.9 (static entry points, file provider)
          TLS certificates independently issued by test CAs
             |                             |
        proxy-owned proof                 Keycloak container
             |                             on isolated Docker bridge
          http://127.0.0.1:8338
             |
       HostMarshal container
       shares Traefik NETNS; no published port, read-only rootfs, dropped caps

Attacker container on Docker bridge --> Traefik eth0:8338 MUST FAIL
Host runner loopback 127.0.0.1:8338 MUST FAIL
```

The reference Traefik configuration is versioned in `deploy/traefik/ingress-static.yml` and `deploy/traefik/ingress-dynamic.yml.tmpl`. The test runner injects freshly generated TLS paths and a secret ingress proof. **Never commit the rendered dynamic configuration, proof, bearer tokens or TLS private keys.** Traefik uses its file provider, **no Docker socket mount**, no insecure dashboard and only two TLS entry points. Its private HostMarshal upstream is `127.0.0.1:8338`, with `passHostHeader=false`. It overwrites forwarded scheme, public Host and protected ingress proof; HostMarshal rechecks every value and validates each bearer token independently. The Keycloak HTTP port is not published; Traefik alone forwards to it.

## Verified OAuth resource-server protocol

Keycloak 26.4.2 is started with a disposable realm, a confidential service-account client, a `hostmarshal.observe` client scope, an audience mapper for the exact `https://mcp.example.invalid/mcp` resource and `access.token.header.type.rfc9068=true`. The test performs a genuine `client_credentials` token exchange over the TLS-protected issuer virtual host. It rejects incorrect client secrets and exercises signed access tokens through the authorized HostMarshal MCP endpoint. The authorized subject must also match an explicit HostMarshal Grant; valid OAuth tokens alone grant no tool access.

When `authorizationServerMetadataUrl` is configured, HostMarshal independently fetches discovery over its existing pinned JWKS TLS trust channel before binding HTTP. The metadata `issuer` must exactly equal `issuer`; its `jwks_uri` must exactly equal `jwksUrl`; `authorization_endpoint` and `token_endpoint` must be HTTPS at the same origin; advertised grant types must include `client_credentials`. No metadata-driven redirect, trust-on-first-use JWKS substitution or external URL from token claims is allowed. A failed discovery prevents startup.

RFC 9068 `at+jwt` tokens still require RS256 signature, correct `iss`, `aud`, bounded `iat`/`exp`, approved scope, valid `sub` and explicit grants. Since `nbf` is optional in RFC 9068, it is verified whenever provided but is not mandatory. Real OIDC issuers may serve mixed JWKS and standard `x5c` metadata; these do not enable unapproved algorithms, encryption keys, bad key operations or duplicate `kid` values.

## GitHub Actions commands

The `ingress-oauth` job of `.github/workflows/ci.yml` compiles `hostmarshal` with `cargo build --locked`, installs pinned disposable Python test helpers, and runs:

```sh
.oauth-ci-venv/bin/python tests/ingress_oidc_ci.py
```

The script creates independent CAs, a Keycloak client secret and ingress proof at runtime; creates/disposes an isolated Docker network and containers; obtains a real OAuth access token; checks discovery, authorized versus ungranted service-account tool discovery, mismatched issuer/JWKS startup rejection, TLS trust, malicious forwarding, and inability to access the loopback-only backend from the runner or a Docker bridge attacker. This job is **additional to**, never a replacement for, Rust format/Clippy/tests, real-Vault SSH, schema conformance, legacy MCP and parser fuzz CI.

## Translating the pattern to a production deployment

The following controls **are not proven by GitHub Actions**: your actual public ingress and DNS, valid/renewed production certificates, authorization-server and token signing-key rollover, k3s NetworkPolicies and service ports, UniFi/firewall segmentation, file permissions under a privileged workload, and independent audit retention. Review the actual Traefik routing/Host/header sanitization and backend no-bypass network path; never expose the HostMarshal loopback listener as a Kubernetes Service or hostNetwork port without a reviewed binding strategy. Protect/rotate proof secrets using Vault or comparable provisioning, pin OIDC issuer/JWKS TLS trust roots, and monitor issuer availability. A compromised proxy or shared netns process can impersonate the ingress proof: this reference uses symmetric proof attestation, **not mTLS**.

The real-Keycloak test verifies one standards-conforming machine-client OAuth grant. It does **not** establish interactive authorization-code + PKCE client login, refresh-token handling, dynamic registration, user session management, or enterprise identity governance. Those are separate client/authorization-server acceptance tests and are not silently delegated to HostMarshal. PR #11 stays draft until release and operational reviews are complete.
