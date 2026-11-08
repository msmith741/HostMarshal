# M4 Vault SSH user certificate provider (experimental)

**Status:** pre-alpha, opt-in short-lived SSH *user certificates* only for the trusted `builtin.linux.uname/v1` **Observe** operation. This is not a general Vault client, arbitrary remote shell, or production-hardened credential service.

## Security architecture

The M2 ExecutionCoordinator authenticates the caller, validates the capability and exact target grant, commits pre-execution audit, and enforces a shared broker/adapter deadline **before** a broker may issue a credential. The Vault provider generates a fresh Ed25519 private/public keypair in a 0700 temporary directory for each allowed invocation, sends only its public key to a fixed approved Vault SSH signing role, and returns a strictly scoped ephemeral lease.

The Vault connection uses **HTTPS certificate verification** against an administrator-pinned TLS CA, disables environment proxy inheritance, rejects redirects, uses a 2-second connect/3-second request timeout, and caps response bodies at 16 KiB. The signed SSH certificate is verified cryptographically against a separately pinned SSH signing CA fingerprint and checked for user type, exactly one inventory SSH principal, matching just-generated public key, no critical options or granted extensions, and bounded validity. The runtime requires the certificate to remain valid beyond the entire pending adapter deadline. The SSH adapter rechecks the current inventory principal and uses the existing pinned SSH host-key configuration and fixed `uname -s` command.

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

The Vault role should permit *user certificate signing* only, allow only the minimum-privilege remote account, cap TTL, and deny privileged extensions/critical options. Configure sshd with the verified trusted user CA via `TrustedUserCAKeys` **and** keep its SSH host-key pin separate in `Host.spec.ssh.knownHostsFile`. Grant only the required `POST /v1/ssh/sign/observer` capability to the Vault token's policy. The process owner, token file, trust files, parent directories and network egress must be protected independently.

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
- **Failure:** wrong certificate signature, CA, key, principal, type, options or TTL; HTTP redirect, outage or malformed response; or insufficient remaining validity all fail closed with non-disclosing errors. There is no broad fallback.
- **Revocation:** emergency lockdown prevents new observations, but cannot revoke an already-accepted certificate or cancel work already accepted by sshd. Restrict TTL and manage target CA revocation separately.
- **Threat boundaries:** same-service-user file replacement, compromised process/Vault token, malicious DNS, unprotected egress and lack of tamper-evident remote audit remain outside the current enforcement guarantees.

`tests/vault_ssh_smoke.py` uses a **disposable Vault-API-compatible TLS signing fixture**, an actual Ed25519 OpenSSH user CA, and a real disposable SSH daemon. It checks authorized cert login, wrong signer/key/principals/expiry/options, provider errors, redirects, oversized/malformed responses, token changes, denied target input, mixed-provider rejection and temporary-file cleanup.

**This does not verify real HashiCorp Vault interoperability.** A restricted-role, TLS-enabled disposable **real Vault server** and workload-identity integration test remain separate release gates. ADR-0012 remains Proposed and M4 is incomplete. See [M4 plan](M4_IMPLEMENTATION_PLAN.md), [Traceability](TRACEABILITY.md), [Remote MCP](REMOTE_MCP.md), and [Security Architecture](SECURITY_ARCHITECTURE.md).
