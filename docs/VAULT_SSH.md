# M4 Vault SSH user certificate provider (experimental)

**Status:** pre-alpha, opt-in short-lived SSH *user certificates* only for the trusted `builtin.linux.uname/v1` **Observe** operation. This is not a general Vault client, arbitrary remote shell, or production-hardened credential service.

## Security architecture

The M2 ExecutionCoordinator authenticates the caller, validates the capability and exact target grant, commits pre-execution audit, and enforces a shared broker/adapter deadline **before** a broker may issue a credential. The Vault provider generates a fresh Ed25519 private/public keypair in a 0700 temporary directory for each allowed invocation, sends only its public key to a fixed approved Vault SSH signing role, and returns a strictly scoped ephemeral lease.

The Vault connection uses **HTTPS certificate verification** against an administrator-pinned TLS CA, disables environment proxy inheritance, rejects redirects, uses a 2-second connect/3-second request timeout, and caps response bodies at 16 KiB. The signed SSH certificate is verified cryptographically against a separately pinned **Ed25519** SSH signing CA fingerprint and checked for user type, exactly one inventory SSH principal, matching just-generated public key, no critical options or granted extensions, and bounded validity. RSA/ECDSA SSH signing CA files are rejected at startup in this pre-alpha implementation; the RSA signature verifier is not enabled in the compiled `ssh-key` dependency. Generate/import an Ed25519 SSH signing CA in Vault, independently verify its public key, and use only that verified key here. The runtime requires the certificate to remain valid beyond the entire pending adapter deadline. The SSH adapter rechecks the current inventory principal and uses the existing pinned SSH host-key configuration and fixed `uname -s` command.

The lease owns both files. Dropping it on completion, failure, cancellation or deadline removes the temporary private key and certificate; the keygen/SSH subprocesses are configured for termination on drop. This is local resource cleanup, **not a guarantee that a remote command has been cancelled**. The Vault token, keys, signed certificate and API response never belong in MCP output or audit.

## Administrator-owned configuration

The protected signer configuration is a separate **0600** JSON file outside the YAML capability directory and outside version control:

```json
{
  "apiVersion": "hostmarshal.io/vault-ssh/v1alpha1",
  "vaultAddress": "https://vault.example.invalid:8200",
  "tokenFile": "/run/hostmarshal/vault-token",
  "caCertificateFile": "/etc/hostmarshal/trust/vault-tls-ca.pem",
  "sshCaPublicKeyFile": "/etc/hostmarshal/trust/vault-ssh-ca.pub",
  "mount": "ssh",
  "role": "observer",
  "ttlSeconds": 90,
  "targets": [
    {"target": "example-linux", "principal": "observer"}
  ]
}
```

The target must exist in the administrator-controlled Host inventory and its `spec.ssh.user` must equal the configured principal. The signed role/path and CA are **not** supplied by MCP. Role and mount are validated as individual path segments; client-controlled Vault URLs or commands are not exposed.

To generate an Ed25519 CA in Vault (administrator setup, illustrative only), use `vault write ssh/config/ca generate_signing_key=true key_type=ed25519` after mounting the SSH secrets engine. Retrieve the public key over a trusted administrative channel and independently verify its fingerprint before installing it in the HostMarshal trust path. Do not store CA private keys in HostMarshal or the repository. RSA is Vault's default generated SSH CA key type and is intentionally unsupported by this pre-alpha verifier.

The Vault role should permit *user certificate signing* only, allow only the minimum-privilege remote account, cap TTL, and deny privileged extensions/critical options. Keep `allow_user_key_ids=false`: HostMarshal deliberately omits the `key_id` request field so the role retains control of certificate audit identity. A server-owned `key_id_format` may include `{{public_key_hash}}` and role/token fields; do not permit MCP callers or issued tokens to choose arbitrary certificate audit identifiers. Configure sshd with the verified trusted user CA via `TrustedUserCAKeys` **and** keep its SSH host-key pin separate in `Host.spec.ssh.knownHostsFile`. Grant only the required `POST /v1/ssh/sign/observer` capability to the Vault token's policy. The process owner, token file, trust files, parent directories and network egress must be protected independently.

```sh
hostmarshal config validate /etc/hostmarshal/config
hostmarshal --config-dir /etc/hostmarshal/config \
  --principal example-operator \
  --vault-ssh-config /etc/hostmarshal/vault-ssh.json \
  --audit-log /var/lib/hostmarshal/audit/events.jsonl
```

The experimental JWT-authenticated loopback HTTP mode also permits this launcher-owned `--vault-ssh-config`. It **cannot** be used together with `--ssh-credential-map`; a Vault outage or denial never falls back to a static key.

## Lifecycle, failures and outstanding gates

- **Token rotation:** the protected token file is rechecked and read per signing request, allowing an operator-controlled rotation. The current pre-alpha provider does **not** implement Vault AppRole/Kubernetes workload login, token renewal or automated token revocation.
- **Signing CA/TLS CA rotation:** stage verified CA files with trusted parents and restart HostMarshal; coordinate the SSH CA rotation with target `TrustedUserCAKeys`. Never learn new CAs from untrusted responses or disable TLS.
- **Failure:** wrong certificate signature, CA, key, principal, type, options or TTL; HTTP redirect, outage or malformed response; or insufficient remaining validity all fail closed with non-disclosing errors. The real Vault role defaults to rejecting user-supplied `key_id`; issuance uses the role-controlled key ID and does not widen this permission. There is no broad fallback.
- **Revocation:** emergency lockdown prevents new observations, but cannot revoke an already-accepted certificate or cancel work already accepted by sshd. Restrict TTL and manage target CA revocation separately.
- **Threat boundaries:** same-service-user file replacement, compromised process/Vault token, malicious DNS, unprotected egress and lack of tamper-evident remote audit remain outside the current enforcement guarantees.

`tests/vault_ssh_smoke.py` uses a **disposable Vault-API-compatible TLS signing fixture**, an actual Ed25519 OpenSSH user CA, and a real disposable SSH daemon. It checks authorized cert login, wrong signer/key/principals/expiry/options, provider errors, redirects, oversized/malformed responses, token changes, denied target input, mixed-provider rejection and temporary-file cleanup.

**Real Vault dev-server interoperability has now been verified in CI**, using HashiCorp Vault 2.2.1 under TLS, an Ed25519 signing CA, a narrowly scoped Vault token, a genuine SSH daemon, token revocation/replacement, Vault outage, and ephemeral-key cleanup (`tests/vault_real_smoke.py`). The real-Vault job passed on retry after a transient CI SSH-account provisioning timeout. **This does not verify production Vault deployments, Kubernetes/AppRole workload authentication/renewal, CA rotation or independent security assurance**. ADR-0012 remains Proposed and M4 is incomplete. See [M4 plan](M4_IMPLEMENTATION_PLAN.md), [Traceability](TRACEABILITY.md), [Remote MCP](REMOTE_MCP.md), and [Security Architecture](SECURITY_ARCHITECTURE.md).
