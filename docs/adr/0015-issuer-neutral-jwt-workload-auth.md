# ADR-0015: Issuer-neutral workload JWT authentication for restricted Vault SSH signing

- **Status:** Proposed — experimental M4 implementation, production review pending
- **Date:** 2026-11-08
- **Scope:** FR-031, existing FR-008/019/020/022, ADR-0008/0012

## Context

A reusable open-source infrastructure tool cannot rely on a named cloud, a private K3s cluster, a specific hostname, or one user's identity platform. Vault's existing local token and AppRole modes are opt-in, but workload deployments increasingly receive signed JWTs from Kubernetes, workload identity exchanges, OIDC issuers or another operator-controlled provider. Binding HostMarshal to a Kubernetes TokenReview API would exclude other deployments and introduce extra control-plane and token-reviewer privileges. HostMarshal must not authenticate arbitrary client-controlled JWTs to a privileged Vault endpoint.

## Decision

Introduce optional **`jwtAuth`** as exactly one of three launch-time authentication sources: `tokenFile`, `appRole` or `jwtAuth`. The administrator pins the Vault HTTPS origin, independently trusted CA, JWT authentication mount/role, JWT file path and expected restricted Vault token policy. All names are validated path segments. Reject mixed sources at startup; there is no fallback, automatic provider selection or MCP-controlled role.

Read the JWT from either a protected regular file or a Kubernetes-style atomic projected-volume symlink `token -> ..data/token`, and only when its canonical destination remains within the trusted mount. Enforce bounded size and restrictive file permissions. Do not decode unverified JWT claims to make authorization decisions, derive a new URL, or use it as the MCP caller identity. Pass the signed assertion to Vault's fixed `/v1/auth/<mount>/login` endpoint with the fixed role. **Vault** is responsible for verifying the signature, exact issuer, bound audience, allowed subject and lifecycle of the JWT assertion using operator-configured public keys or trusted JWKS.

For issued Vault tokens require exact one-policy scope with no identity-policy additions, renewable true and TTL 30–3600 seconds. Renew-self only through the fixed Vault URL and serialized with client operations; ADR-0016 adds optional proactive renewal after first use. Denial/outage, policy expansion, failed renewal and expired token quarantine the session until an authorized restart. A rotated external JWT does not lift quarantine automatically. Continue to enforce existing target-bound SSH cert signing, trusted Ed25519 CA, audited denials and temporary key cleanup.

## Rejected alternatives

- Kubernetes-only login as HostMarshal's mandatory workload API: not vendor-neutral and requires TokenReview trust and cluster-specific privileges.
- Parsing arbitrary JWT claims as proof of caller authorization: unacceptable without signature verification and separate identity boundary.
- Trusting token-provided `iss`/JWKS URLs or Vault paths: implicit trust expansion.
- JWT fallback to AppRole or a static token on rejection: privilege confusion and hidden downgrade.
- Vault batch tokens for the current stateful renew-self lifecycle: incompatible with this renewal contract.
- Automatically re-login with new JWT after revoked active token: could bypass explicit session quarantine.

## Verification and remaining risk

Rust unit tests verify ordinary-file permission and projected-symlink escape rejection. A disposable real HashiCorp Vault JWT auth mount validates actual signed correct/incorrect issuer, audience and subject, renewable service-token issuance, SSH signing, revoked renew-self and sticky quarantine with no token leakage. No real third-party identity provider, cluster trust policy, production JWT rotation/idle refresh, automatic recovery, mTLS, standalone Vault TLS/SSH CA rotation or independent security audit is claimed. All examples use reserved fictional domains, illustrative role names and private ephemeral CI keys. See `docs/WORKLOAD_JWT_AUTH.md` and `docs/TRACEABILITY.md`.
