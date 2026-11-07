# M4 — Vault-signed, short-lived SSH user certificates

**Status:** Opt-in provider for the *single vetted* `builtin.linux.uname/v1` observation operation. It is not a generic Vault secrets browser or SSH CA administrator.

## Data flow

```text
Verified caller + authorized target
    -> mandatory M2 audit precommit
    -> CredentialScope(operation=linux.uname, target, purpose=ssh-observe, issuer, subject)
    -> approved per-target Vault role and local public key
    -> POST /v1/<mount>/sign/<role> (TLS verified; no proxy/redirect)
    -> issued 60s SSH user certificate in owner-only tempfile
    -> pinned-host-key OpenSSH -i <local-protected-private-key> -o CertificateFile=<temp-cert>
    -> fixed uname -s; exact Linux result; terminal audit
    -> certificate tempfile unlinked on lease drop
```

No MCP argument specifies the private key, Vault token, target role, SSH principal, network URL or certificate. Authenticated callers only invoke YAML-defined capabilities with exact target grants. The existing static mapping remains an alternative; do not enable both provider flags simultaneously.

## Vault setup (generic)

1. Enable the Vault SSH secrets engine at an administrator-selected mount such as `ssh`. Configure a CA signing key; distribute its **public** CA key securely to authorized SSH servers and configure `TrustedUserCAKeys` (or your SSH certificate trust mechanism). Verify the CA fingerprint out of band.
2. Create a restrictive signing role (e.g. `observe-only`): `allowed_users` includes only the chosen low-privilege observer, `default_user` is that observer, `ttl` and `max_ttl` bound issuance, user certificate type only, no unconstrained principal and no privileged extensions. Review host-side OpenSSH permissions and target login restrictions.
3. Configure the HostMarshal service identity with a Vault policy allowing only this role's **sign** endpoint (e.g. `path "ssh/sign/observe-only" { capabilities = ["create","update"] }` as appropriate for Vault). Never grant `ssh/issue/*`, `ssh/roles/*`, `sys/*` or arbitrary secret reads to HostMarshal.
4. Provide a protected token file, ideally maintained by an external Vault Agent with short renewal intervals. No Vault root token should be deployed. Restrict token and map files to the HostMarshal OS identity (mode 0600), and protect parent directories.
5. Keep the matching local private/public keypair in OS-protected files. HostMarshal only reads the **public** key; the SSH client opens the protected private key. Rotate local keypairs through your administrative credential lifecycle.
6. Configure a trusted Vault TLS CA file. Invalid TLS, redirects, non-HTTPS origins, malformed signatures or unexpected responses fail closed.

## Example protected provider map

Create a file outside the YAML manifest directory, e.g. `/etc/hostmarshal/vault-ssh.json` (mode **0600**, not in a public repository):

```json
{
  "apiVersion": "hostmarshal.io/vault-ssh/v1alpha1",
  "vaultUrl": "https://vault.example.invalid:8200",
  "sshMount": "ssh",
  "tokenFile": "/run/hostmarshal/vault-token",
  "caCertificateFile": "/etc/hostmarshal/trust/vault-ca.pem",
  "identities": [
    {
      "target": "demo-linux",
      "identityFile": "/var/lib/hostmarshal/keys/demo-linux",
      "publicKeyFile": "/var/lib/hostmarshal/keys/demo-linux.pub",
      "role": "observe-only",
      "principal": "observer"
    }
  ]
}
```

Grant the caller `linux.uname` against the same trusted Host target, and configure `Host.spec.ssh.user: observer`, a verified `knownHostsFile` and destination. The role's principal and inventory login user must align. When a Vault-issued certificate is used, the SSH client restricts accepted public-key algorithms to certificate variants, preventing silent fallback to raw authorized_keys. The target SSH server should also avoid authorizing this identity's raw key.

Start either local stdio or authenticated HTTP with the **one** optional `--vault-ssh-config /etc/hostmarshal/vault-ssh.json` flag. Never provide it alongside `--ssh-credential-map`. Without a configured provider, requests requiring SSH credentials are denied.

## Rotation and failure modes

- The Vault service-token file is re-read for **each authorized issuance**, allowing an external agent to rotate it. A missing/expired/mispermissioned token fails closed. The provider map and its signing-role allowlist are loaded at process launch; restart after updating these trusted mappings or Vault CA.
- Each issuance requests a 60-second certificate, checks the returned shape and lease duration and stores it only for the operation. A successful local unlink is not remote revocation: use Vault role TTL and SSH CA/CRL mechanisms to address issued certificates.
- Vault HTTP requests have a bounded timeout (four seconds) and share the M2 operation deadline. Remote signing failure, wrong TLS CA, denied grants, wrong roles, mismatched lease scope or malformed data never fall back to password or unrestricted SSH.
- Local files, named temp paths and the co-located service process depend on OS protection. Root/same-user compromise and filesystem races are outside the in-process threat boundary. A compromised Vault service token can issue whatever the Vault role allows; limit its ACL and monitor Vault audit logs separately.

See [ADR-0013](adr/0013-vault-ssh-certificate-broker.md), [M3 SSH operations](OBSERVATION_ADAPTERS.md), [traceability](TRACEABILITY.md).
