# ADR-0017: Fail-closed Vault lease maintenance auditing

- **Status:** Proposed — experimental source implementation; independent security review and production release gates remain open
- **Date:** 2026-11-08
- **Related:** FR-009, FR-021, FR-032, FR-033, FR-034; ADR-0007, ADR-0016
- **Scope:** optional Vault SSH signing through AppRole or external JWT, independent of deployment platform

## Context

FR-032 renews a restricted Vault service token in the background after an already-authorized operation. The ordinary invocation auditor already records the initiating MCP request, but an idle renewal can succeed or enter quarantine without a corresponding maintenance record. A failure in renewal or an operator-approved post-quarantine login is a security-relevant transition and must not be silently omitted when an audit sink is configured.

## Decision

1. Pass the **same launcher-controlled `AuditSink`** used by the execution coordinator into the Vault signer broker and lease lifecycle. MCP callers, credential sources and YAML configuration cannot change the sink or its destination. The existing `tokenFile` source has no provider-managed renewal and is unchanged.
2. Every foreground or background `renew-self` attempt emits an **authorized** precommit event before network use and a **succeeded** or **failed** terminal event. Both share one generated correlation ID. The operation is fixed to `vault.signing-lease.renew/v1`. An audit precommit failure prevents the Vault request; a terminal audit failure rejects the returned token and leaves the lease quarantined.
3. When an operator increments a trusted `recoveryEpochFile` and a quarantined AppRole/JWT lease is eligible for one new login, emit the same precommit/outcome pair under `vault.signing-lease.recovery/v1`. If either audit commitment fails, the epoch is consumed, the fresh login cannot yield a credential, and quarantine persists. An invalid, replayed or absent marker remains denied without an operator recovery event; the invocation itself remains audited by the normal runtime.
4. Maintenance audit identity is the **literal system sentinel** `<system>`, with capability `<credential-provider>`, target `<provider>`, digest `<maintenance>` and fixed reason codes. No caller identity is attributed to background maintenance. Never log token/SecretID/JWT contents, Vault policy, TLS endpoint, environment details or unsanitized Vault error messages.
5. Maintain one serialized lease state machine. Failed renewals and audit errors have no retries, alternative provider or auto-login. The maintenance worker remains weak-owned and cannot outlive the credential lifecycle.

## Tradeoffs and limitations

The sink currently writes synchronous JSONL to stderr or an operator-selected local file. The local file sink calls `sync_data()`; **stderr is not independently durable**, and a local file is not tamper-evident, WORM, remotely replicated or isolated from the HostMarshal process. The blocking sink call also has no bounded latency if a destination stalls. Reusing the process sink improves completeness and fail-closed behavior but **does not satisfy independent audit durability**. A separately isolated audit provider, authenticated delivery/receipt, rotation/retention, timing budgets and deployment acceptance remain distinct future requirements.

For fixed renewal and recovery operations, source faults are mapped to static reason codes. Audit status cannot be inferred from Vault response bodies, and maintenance identity is never a verified human operator. Root-owned Unix recovery-file provisioning and actual incident approval remain the administrator's responsibility.

## Verification

- Rust unit tests inject a failing audit sink before a renewal to prove no network attempt is made and assert that audit records are redacted and correlated.
- Disposable Vault TLS and SSH integration checks assert authorized, successful and failed renewal records and authorized recovery results for AppRole and JWT, without exposing credentials.
- The existing Rust/MCP, OAuth/Traefik, fuzz and K3s checks remain separate CI gates. Do not mark implementation tested on a revision until all relevant jobs pass on that exact source head.
