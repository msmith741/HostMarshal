# ADR-0013: Optional scoped Vault SSH certificate provider

- **Status:** Accepted (M4 architectural review)
- **Date:** 2026-11-07
- **Deciders:** HostMarshal maintainer

## Context

M3 accepts a protected local SSH private-key file mapped to a target. For scalable credentials, HostMarshal needs short-lived, policy-scoped credentials without exposing private keys to MCP clients or permitting YAML-defined secret paths and signing roles.

## Decision

Implement one provider-neutral extension of the M2 `CredentialBroker` contract: `VaultSshCertBroker`, which calls the official Vault SSH secrets engine **sign** endpoint `POST /v1/<approved-mount>/sign/<approved-role>`. A protected, launcher-provided M4 JSON map specifies the trusted Vault HTTPS origin, CA PEM, Vault token file, mount, and **per-target** identity/public-key path, signing role and requested principal. No tool argument or Capability YAML can choose the Vault host, secret path, SSH role, key file or user.

For an authorized SSH observe request, the runtime binds its verified issuer/subject to `CredentialScope` and commits pre-execution audit. Only then does the broker read an owner-only token file, fetch the corresponding public key, and request a **60-second** SSH user certificate. TLS verification, no redirects/proxy inheritance, bounded response size, fixed operation/purpose/target and exact lease scope are enforced. The certificate is stored temporarily in a mode-0600 file and passed to the M3 vetted SSH client using `CertificateFile`. It is unlinked when the lease drops. The protected private key itself is not returned by Vault, parsed into an MCP result, or disclosed over the protocol.

M3's static local broker remains available as an alternative; configuration forbids enabling both providers in one process, and omission selects a deny-all broker.

## Alternatives

- Vault SSH OTP/password authentication: **rejected**, because password management and one-time command handling are outside the read-only SSH contract.
- Vault KV private-key retrieval: **rejected** for M4; issuing a public-key certificate preserves a local protected private key and avoids repeatedly exposing key material.
- Generic Vault `read(secret/path)` MCP operation: **rejected**, as it defeats operation-scoped credentials.
- Open-ended role or Vault URL from YAML/tool parameters: **rejected**, must be administrator-approved and target-bound.
- Full Vault Agent auto-auth and token renewal inside HostMarshal: **deferred**; supported deployments may mount an externally managed Vault Agent token file.

## Operational constraints and residual risks

The Vault role must constrain allowed principals, TTL, extensions and target-side SSH account privileges. The signing service token must be bound by Vault ACL to only the approved `ssh/sign/<role>` endpoint and be renewed/rotated by the operator or an external Vault Agent. The client uses an independently approved TLS trust root. Certificate temp files and token files depend on OS filesystem security; same-user/root compromise and path-replacement races are not eliminated. Issued certificates cannot be immediately revoked by deleting the temporary local file—remote SSH CA and revocation policy is essential. Local timeout/cancellation of the SSH client is not a remote kill guarantee.

A successful HTTP POST is not enough to trust a certificate: the broker checks response shape, certificate type and size, then the M3 OpenSSH client/server enforces certificate authentication. Service token lifetime/revocation and token-audience constraints depend on Vault configuration. No generic renewable lease handler, dynamic secrets provider SDK or Vault administration interface is implemented.

## Evidence

`src/vault.rs`, `src/credentials.rs`, `src/observation.rs`, `tests/vault_ssh_smoke.py` and existing M2 denial and audit tests. The integration test provisions disposable TLS, SSH, ephemeral keys and a Vault-compatible signing service; it verifies issuance, no raw-key SSH fallback, invalid certificates, rejected Vault token, bad CA and audit redaction. See [Vault integration](../VAULT_SSH.md) and [traceability](../TRACEABILITY.md).
