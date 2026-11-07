# Threat model

The full proposed threat model and trust-boundary analysis are maintained in [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md).

This path is retained for compatibility with the initial Rust bootstrap documentation. The old bootstrap-era threat model is available in Git history; its implementation limitations should not be confused with the **planned** architecture. All security controls in the architecture document remain requirements until implemented and verified.

## M4 external identity and credential threats

Stolen OAuth Bearer tokens may be replayed until their enforced expiration; a compromised issuer, stale administrator-pinned JWKS, incorrectly configured TLS gateway, forged proxy-identity headers or failure to bind audience could expose tools. HostMarshal validates tokens and ignores identity claims from MCP/tool headers, but neither manages authorization-server consent nor implements online token revocation.

An overbroad Vault SSH signing role, compromised Vault service token/CA, malicious trusted role mapping, TLS MITM or OS-level file replacement race can authorize unwanted SSH certificates. HostMarshal restricts signing role per target, checks HTTPS CA, requires audited grants and issues only a short-lived user certificate for the fixed read-only Linux operation. Vault/OS policy and remote certificate revocation remain outside its boundary. See [ADR-0012](adr/0012-oauth-protected-stateless-mcp-http.md) and [ADR-0013](adr/0013-vault-ssh-certificate-broker.md).
