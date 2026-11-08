# Proactive Vault signer lease lifecycle and recovery

**Status:** Experimental M4 FR-032/FR-033, draft PR #12; deployment-neutral and not a production security sign-off.

## Architecture and behavior

The opt-in Vault SSH signer supports three mutually exclusive sources:
- `tokenFile`: operator-managed static Vault token file; read on each request; **no** background renewal and unchanged recovery semantics.
- `appRole`: restricted Vault AppRole role/SecretID login yielding renewable signing-only service token.
- `jwtAuth`: externally issued JWT passed to an operator-configured Vault JWT auth role; Vault verifies issuer/audience/subject and mints restricted signing-only service token.

AppRole and JWT share one **provider-owned lifecycle**. On the **first authorized** use (after HostMarshal's ordinary caller Grant and exact operation/target checks), it obtains a token from the fixed, TLS-pinned Vault endpoint. It validates the exact signing-only policy, renewable status and bounded TTL, then schedules a weak-owner renewal task. On continued idle, the task renews the same Vault service token through the fixed `auth/token/renew-self` endpoint before expiry. The task and foreground requests serialize state under the same async lock. On any denial, wrong policy, changed token, expired lease, renewal outage or failed signer authorization, the provider enters sticky quarantine and the task stops. **There is never an automatic retry login or fallback to another provider.**

Background renewal runs only in-process, and the task is cancelled on lifecycle drop. The token is held in zeroizing memory. A process shutdown loses the lease and does not keep renewing. This is **not** Vault Agent, token creation of arbitrary secrets, issuer enrollment, or a general-purpose Vault client.

## Optional administrator recovery

AppRole and JWT configurations may include an **optional** `recoveryEpochFile`, absent by default:

```json
{
  "appRole": {
    "authMount": "approle",
    "roleIdFile": "/etc/hostmarshal/role-id",
    "secretIdFile": "/etc/hostmarshal/secret-id",
    "expectedPolicy": "sign-only",
    "renewBeforeSeconds": 15,
    "recoveryEpochFile": "/run/hostmarshal-admin/recovery-epoch"
  }
}
```

These are generic example paths/values, not a live system. For `jwtAuth`, the same field belongs inside that object. The path must be an **absolute, canonical, regular Unix file**, owner UID 0, no write bits, holding a decimal `u64` with at most 20 bytes (trailing CR/LF permitted). Every ancestor directory must be root-owned, non-symlinked and not group/other-writable. A process-UID-owned `0400` file is **not sufficient**, because that principal could change its permissions. Protect the directory against service-UID mutation; deploy HostMarshal itself unprivileged.

**Operator procedure (illustrative, root administrative channel only):** Provision `/run/hostmarshal-admin` root-owned mode 0755; stage `100\n` as a root-owned mode 0444 regular file; atomically rename it to `/run/hostmarshal-admin/recovery-epoch`. Increase the counter to `101`, `102`, etc. **only after an operator verifies** the Vault signer role/policies, issuer, token validity, incident cause and desired resumption. An unchanged counter, decrease, replay or unreadable marker never authorizes a login. A failed recovery login consumes that increment, requiring another explicit operator change. The file is a **control signal**, not a bearer secret; operators must audit who published it and why.

No marker means **restart-only recovery**, which is often preferable for sensitive environments. A changed SecretID or rotated workload JWT by itself does **not** clear quarantine. The new login after an epoch increase must still pass all existing Vault TLS, credential source, role, policy and target checks. There is no MCP tool to read, set, or approve recovery epochs, and no long-lived admin endpoint.

## Evidence, testing and security boundaries

`tests/vault_real_smoke.py` creates a disposable Vault 2.2.1 server and SSH signer, then uses `sudo` on the ephemeral CI runner **only** to provision/update a root-owned `/run` epoch fixture; the HostMarshal process runs as the ordinary unprivileged user. The test verifies idle proactive renewal (30-second initial lease, 36 seconds no MCP traffic), denied renewal after policy revocation, continued denial after restoring policy, epoch rollback/baseline replay failure, AppRole/JWT fresh login only after increment, and no token/audit leaks. Rust unit tests verify scheduling bounds and reject runtime-owned marker files.

The test is **not** proof of production Vault token durability, externally configured root/file ownership, independent audit or per-tenant workload identity isolation. No CA, SSH signer, OIDC/JWKS, VLAN, ingress, Kubernetes service or cloud provider is configured by this PR. Production integration requires separately reviewed deployment instructions, credential rotation, operator incident-response workflow, durable audit evidence for background failures and independent security acceptance.

See [ADR-0016](adr/0016-vault-proactive-renewal-recovery.md), [FR-032/FR-033 traceability](TRACEABILITY.md), [Vault signer](VAULT_SSH.md), and [workload JWT auth](WORKLOAD_JWT_AUTH.md).
