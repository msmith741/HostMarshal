# M2 — Security-enforcing execution runtime

**Status:** M2 central runtime implemented, now used by the M3 built-in SSH/HTTPS observations as well as static inventory. This is an architectural security foundation, not authorization to execute infrastructure-changing commands.

## Architecture and trust boundary

```text
trusted OS launcher -> AuthenticatedCaller
MCP call -> ExecutionCoordinator
  -> immutable ConfigStore snapshot
  -> validate capability and arguments
  -> resolve target from trusted inventory
  -> Authorizer (default deny)
  -> trusted OperationDescriptor (intrinsic Observe-only constraint)
  -> admission semaphore
  -> AuditSink pre-execution commitment [failure => no adapter]
  -> asynchronous, deadline-bound scoped CredentialBroker [only if required]
  -> bounded async OperationAdapter execution
  -> exact output shape, target binding, byte-limit validation
  -> AuditSink terminal outcome [failure => no client output]
  -> structured MCP response
```

The MCP layer **does not call adapters, read credential providers, or evaluate policies itself**. It invokes `ExecutionCoordinator::invoke` and formats the result or a stable, non-disclosing failure message. The legacy JSON handlers were retired with this milestone so there is no separate unaudited tool path. The older MCP protocol remains supported *over this same coordinator*.

## Typed interfaces

| Interface | Source | Authority |
| --- | --- | --- |
| `AuthenticatedCaller` | `src/identity.rs` | Trusted launcher constructs subject; MCP metadata is not authentication |
| `AuthorizationRequest`, `Authorizer` | `src/authorization.rs` | Trusted runtime supplies verified subject, operation, capability, target and snapshot |
| `OperationDescriptor`, `OperationAdapter` | `src/adapter.rs` | Only compiled-in trusted operations are registered in M2; no plugin loader |
| `CredentialScope`, `CredentialBroker`, `CredentialLease` | `src/credentials.rs` | Trusted runtime requests a purpose/operation/target scope *after* permit and audit |
| `AuditEvent`, `AuditSink` | `src/audit.rs` | Redacted, reason-coded audit of accepted, denied, succeeded and failed requests |
| `ExecutionCoordinator` | `src/runtime.rs` | Centralizes order, limits, broker, adapter, output and audit |

Trusted built-ins include `builtin.inventory.inspect/v1` (2-second max) plus `builtin.linux.uname/v1` and `builtin.https.health/v1` (5-second maximum each). All are Observe-only with a 4096-byte descriptor ceiling. The user's validated YAML capability may further reduce these limits. The runtime validates each operation's schema and output separately. Capability YAML may only further narrow permitted limits. A global admission semaphore bounds concurrency (16 in M2); per-operation quotas, rate limiting and administrative approvals remain later work.

## Security invariants

1. Missing/invalid caller, missing capability grant or unauthorized target => **deny before broker and adapter access**.
2. Unrecognized adapter or operation descriptor risk, schema or target mismatch => deny, regardless of a YAML description.
3. Failure to commit `Authorized` audit event => **no credential acquisition and no execution**.
4. Credentialless operations never call the broker; credentialed operation scopes are checked for **exact match** (operation/target/purpose), with no fallback. The asynchronous broker and adapter share one absolute operation deadline.
5. Broker and adapter futures share a `tokio::time::timeout_at` deadline; a timeout drops/cancels the future. This is cooperative cancellation, **not** an OS kill/sandbox guarantee.
6. Static inventory output must exactly match trusted resolved inventory and fit the configured byte ceiling. Invalid or secret-bearing results are suppressed.
7. Completion audit failure suppresses the response. This **cannot roll back a previously completed operation**; therefore mutation remains explicitly prohibited.
8. Reload/revocation applies to requests beginning after an atomic snapshot swap; already-started static observations may complete on their previous immutable snapshot.

## Offline policy diagnostics

The CLI supports `hostmarshal policy explain <config-dir> --subject <local-subject> --capability <name> --target <host-id>`. This evaluates a simulated **trusted-launcher issuer** against a validated snapshot, returns a structured permit/deny and snapshot digest, and never calls the broker, adapter or network. File permissions must restrict who can inspect the configuration. This is **not** an authenticated session or a tool for acting as another user.

## Error model

The coordinator exposes stable `RuntimeFailure` variants: `Unauthorized`, `InvalidInput`, `Unavailable`, `Busy`, `AuditUnavailable`, `BrokerUnavailable`, `AdapterFailed`, `TimedOut`, and `InvalidOutput`. MCP responses do not disclose exception messages, raw target endpoints, tokens or adapter stdout.

## M2 verification

Rust tests cover authorized success, denied caller/target/tool/arguments, emergency lockdown, exhausted admission capacity, broker-not-called on denial, broker outages, mismatched scope and a slow broker, audit-start failure before execution, adapter failure, output tampering, timeouts, and terminal-audit failure. `tests/audit_smoke.py` drives the real MCP process using a protected JSONL file and checks request correlation, authorization, denial, secret redaction and file mode. All earlier schema, reload and dual-MCP-era suites remain required CI checks.

## M4 ephemeral SSH certificate leases

The optional `VaultSshCertificateBroker` is a trusted, launcher-selected credential provider for the fixed Linux observation. It generates a unique private/public key pair after grant authorization and mandatory pre-execution audit, obtains a short-lived **user certificate** from an approved Vault SSH sign role, and checks its pinned signing CA, public-key match, inventory principal, restricted options and validity. `CredentialLease` owns the temporary private key/certificate files and drops them on completion or cancellation. The coordinator requires expiration beyond the remaining absolute adapter deadline plus a safety margin; the SSH adapter checks principal equality and uses the already-pinned SSH host identity. A Vault outage or invalid certificate cannot fall back to the M3 local static-key broker.

This is an experimental token-file-based Vault client, not general Vault secret brokering, workload login/renewal or tamper-evident audit. A disposable Vault-API-compatible TLS signer with a **real OpenSSH CA and sshd** is covered by `tests/vault_ssh_smoke.py`; a separate disposable real HashiCorp Vault 2.2.1 TLS dev-server and real sshd test now pass in CI. Workload identity/token renewal, CA rotation and production security acceptance remain M4 release gates. See [Vault SSH](VAULT_SSH.md) and [M4 plan](M4_IMPLEMENTATION_PLAN.md).

## Deliberate limitations

M3 provides two fixed **live read-only** transports: Linux uname over pinned-key SSH and TLS-validated HTTPS health. The default `DenyCredentialBroker` still denies all SSH requests unless the trusted launcher selects exactly one scoped SSH provider: M3's protected local-key map or M4's experimental Vault SSH certificate signer. No complete remote workload-authentication or credential-renewal service is implemented. The project does **not** yet implement complete remote identity federation (the loopback signed-JWT pilot exists), plugin process sandboxing, approval workflows, reauthorization at side-effect boundaries, durable remote audit, tamper evidence, or multiple independent tenants. The local launcher and protected configuration directory remain deployment trust assumptions. Do not advertise this M2 runtime as a production remote-admin gateway.

See [Audit](AUDIT.md), [Security](SECURITY_ARCHITECTURE.md), [Adapters](ADAPTERS.md), and [Traceability](TRACEABILITY.md).
