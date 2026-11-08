# ADR-0013: Pinned OIDC metadata and isolated TLS ingress interoperability

- **Status:** Proposed — CI acceptance slice, not production deployment approval
- **Date:** 2026-11-07
- **Related:** ADR-0012, FR-018, FR-023–FR-027

## Context

The M4 pilot authenticates a loopback MCP listener with pinned RSA access-token verification and enforces an ingress proof, but a local synthetic issuer and mock TLS proxy are insufficient to establish real OAuth issuer interoperability or validate a deployed proxy topology.

## Decision

1. Keep HostMarshal a **resource server**, never an OAuth issuer or bearer-token forwarding service.
2. Add an optional administrator-pinned OIDC metadata URL validated with the existing pinned-JWKS HTTPS CA. Metadata must match the administrator-fixed issuer and JWKS URI; auth and token endpoints must remain on the issuer HTTPS origin. Failure denies listener startup, without dynamic trust expansion.
3. Maintain the RFC 9068 `at+jwt` access-token profile. Treat `nbf` as optional but validate it when present; enforce all other bound claims, signature, scope and explicit grants. Accept standard OIDC JWK public metadata while rejecting duplicate key IDs and unsupported RSA signing contexts.
4. Version a **TLS-only Traefik file-provider** example that has no Docker socket mount or unsecured dashboard, and configure the backend to bind only `127.0.0.1` within Traefik's own network namespace. No port or host interface publishes the backend. Treat the ingress proof as privileged data, not client identity.
5. Require a GitHub Actions job with real Keycloak 26.4.2 machine-client OAuth issuance, issuer discovery and JWT validation, negative client/TLS/Host/header checks, and active Docker-bridge/runner-backend bypass tests. Use only CI-generated keys and credentials; do not contact production.

## Alternatives and exclusions

Using a reverse proxy with public access to HostMarshal's backend port is rejected: a JWT alone does not verify that ingress TLS/header constraints were enforced. Accepting arbitrary issuer-discovered JWKS hosts or changing trusted roots from token data is rejected. Docker auto-discovery by exposing `/var/run/docker.sock` to Traefik is avoided. Dynamic authorization-code/PKCE UX is a client/issuer task, not a HostMarshal API.

## Remaining risks and release gates

This GitHub Actions topology cannot prove real k3s/Traefik/UniFi or Kubernetes network isolation. A compromised proxy or colocated process with the ingress proof can spoof the upstream attestation; mTLS/network namespace policy and production certificate/credential rotation are separate gates. Keycloak client-credentials validation does not prove browser PKCE interoperability. An independent production configuration/security review remains required. ADR-0013 remains Proposed pending those gates.
