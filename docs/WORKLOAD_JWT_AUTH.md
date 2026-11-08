# Externally issued workload JWT authentication for Vault SSH signer

**Status:** Experimental M4 feature (FR-031), real Vault JWT login and negative-path checks passed in disposable CI; independent production review remains required. This is an **optional**, issuer-neutral source for Vault signer credentials. It does not authenticate MCP clients or make HostMarshal a Kubernetes operator.

## Scope and architecture

```text
Administrator-controlled external JWT issuer
    -> mounted/protected signed JWT file (regular or kubelet atomic projection)
    -> HostMarshal trusted credential broker only after MCP caller grant check
    -> pinned-TLS Vault auth/<mount>/login with a fixed role
    -> Vault cryptographic JWT issuer/audience/subject role verification
    -> restricted renewable Vault signing-only service token in memory
    -> fixed Vault SSH sign/<role> request -> validated short-lived SSH certificate
    -> bounded read-only target operation and redacted audit
```

Unlike the *remote MCP access token*, the workload JWT is never considered a caller subject or a capability. It is used only to request a narrower Vault signing credential from a trusted issuer. A successful Vault login does **not** bypass HostMarshal's own per-caller Grant, exact operation/target scope, audit, pinned SSH host key, principal or CA checks.

## Generic administrator-owned configuration

Store outside the public YAML capability/resource directory as protected mode 0600 JSON, with an independently pinned Vault HTTPS CA and trusted Ed25519 SSH signing CA. All following values are fictional examples and must be replaced with an operator's independently verified configuration.

```json
{
  "apiVersion": "hostmarshal.io/vault-ssh/v1alpha1",
  "vaultAddress": "https://vault.example.invalid:8200",
  "jwtAuth": {
    "authMount": "jwt",
    "role": "read-only-workload",
    "jwtFile": "/run/hostmarshal/workload-token",
    "expectedPolicy": "sign-only",
    "renewBeforeSeconds": 120
  },
  "caCertificateFile": "/etc/hostmarshal/trust/vault-ca.pem",
  "sshCaPublicKeyFile": "/etc/hostmarshal/trust/ssh-user-ca.pub",
  "mount": "ssh",
  "role": "read-only",
  "ttlSeconds": 90,
  "targets": [
    {"target": "example-linux", "principal": "observer"}
  ]
}
```

Configure **exactly one** of `tokenFile`, `appRole` or `jwtAuth`; multiple or missing sources abort startup. `authMount`, `role` and `expectedPolicy` are validated segments and never taken from MCP arguments or token claims. The JWT path must be absolute and readable by the HostMarshal workload identity. A direct file must be regular and protected. A Kubernetes projected `token -> ..data/token` symlink is supported only when it resolves inside its mounted directory, has restricted permissions and does not permit group/other writes. Kubernetes' default 0644 projection is **too permissive** for this mode: use an explicit 0400 or 0440 file mode appropriate to the chosen non-root UID/GID.

For JWT authentication, configure Vault's JWT/OIDC auth method with **role_type=jwt**, restricted accepted signing algorithms (e.g. RS256), independently trusted issuer verification keys/JWKS, `bound_issuer`, `bound_audiences`, `bound_subject` or appropriately specific `bound_claims`, and the exact `user_claim`. The role issues **renewable service tokens** (not Vault batch tokens), sets `token_no_default_policy=true`, and attaches only the fixed signing policy that permits the intended `ssh/sign/<role>` and `auth/token/renew-self` paths. Vault must reject a JWT with the wrong signature/issuer/audience/identity. Vault's JWT validation and lease role configuration are deployment-owned; HostMarshal does not bootstrap those permissions.

### Vault role illustration (operator review required)

The commands below illustrate resource shape only; they are not executed by CI against production and are not a turnkey secure Vault configuration. All addresses and role names are placeholders.

```sh
vault auth enable -path=jwt jwt

# Pin issuer public signing keys or a trusted JWKS endpoint in Vault first.
# Example: vault write auth/jwt/config jwt_validation_pubkeys=@issuer-pubkeys.pem bound_issuer=https://issuer.example.invalid/ jwt_supported_algs=RS256

vault write auth/jwt/role/read-only-workload \
  role_type=jwt user_claim=sub \
  bound_subject=workload-observer \
  bound_audiences=https://vault.example.invalid/workload \
  token_type=service token_no_default_policy=true \
  token_policies=sign-only token_ttl=90s token_max_ttl=6m
```

Never copy a signing **private** key into Vault's JWT verification config or HostMarshal. Do not use a Vault root token or broad default policy as the signer. Restrict the SSH role to a non-privileged principal and pin the returned SSH CA. Protect the workload token source from co-UID writers and broad volume mounts.

## Lifecycle and failure modes

At the **first authorized** observation HostMarshal reads the signed JWT, submits it only to the fixed Vault JWT login endpoint, validates Vault's returned bounded renewable token and stores only the Vault token in memory. The provider then runs bounded proactive renew-self in process, serialized with foreground requests. The source JWT is re-read only for a **fresh** login following trusted restart or a separately authorized new recovery epoch. It is never read for every signing operation or used as a backup for an already-invalidated token. A failed login, invalid response, unexpected policy, revoked renewal privilege, expired session or signing HTTP 401/403 **quarantines** the source; without an administrator-controlled recovery marker, restart remains necessary.

**Still not implemented:** silent self-healing, automatic CA rotation, real production issuer enrollment or provider-independent audit of background renewals. If a token expires or Vault becomes unavailable, access denies without static fallback. Secret values must never enter MCP results or audit logs.

## Verification and release gate

The CI test `tests/vault_real_smoke.py` exercises an actual disposable TLS Vault JWT auth backend with ephemeral RSA signing keys and fixed issuer/audience/subject. It performs short-lived SSH certificate operations against an ephemeral local SSH server, wrong-claim denials, time-bounded renew-self, revoked renewal and sticky quarantine, without any production secrets. Rust unit tests verify protected direct file and projected symlink boundaries. Real Vault tests are necessary but insufficient for production deployment or independent third-party identity federation. This feature remains experimental pending full lifecycle and security review. See [ADR-0015](adr/0015-issuer-neutral-jwt-workload-auth.md).

## Proactive renewal and operator recovery

JWT workload auth uses the same background-renewal lease manager as AppRole. It starts only after first authorized SSH observation; subsequent renewal uses the **already issued Vault token**, never an unverified newly fetched JWT. Invalid lease response, Vault outage, revoked renewal privilege or expired token quarantines the source and stops the worker. This is **not** automatic JWT login retry.

An optional administrator-controlled `recoveryEpochFile` under `jwtAuth` enables a **single fresh JWT login** after sticky quarantine when its unsigned integer increases. The file must be Unix root-owned, read-only, regular and canonical, with root-owned protected ancestry. It is not a secret but is a privileged administrative signal; the runtime UID must not control its directory. A changed JWT file alone or a replayed/rolled-back epoch cannot authorize re-login. Without the file, a trusted restart remains necessary. See [lease lifecycle guide](VAULT_LEASE_LIFECYCLE.md) and [ADR-0016](adr/0016-vault-proactive-renewal-recovery.md). Background renewal event auditing, external issuer provisioning and trust CA rotation remain future release gates.
