# ADR-0016: Proactive Vault signing lease renewal and operator-controlled recovery

- **Status:** Accepted — experimental implementation; independent production security review and release gates remain pending
- **Date:** 2026-11-08
- **Related:** FR-032, FR-033, FR-022, FR-031; ADR-0008, ADR-0012, ADR-0015
- **Scope:** Opt-in Vault SSH signing via AppRole or externally issued JWT; deployment-neutral provider lifecycle

## Context

AppRole and JWT providers currently obtain restricted renewable Vault service tokens and renew them only when a new authorized SSH observation arrives. Idle periods beyond the token TTL therefore quarantine a session despite an otherwise healthy Vault provider. A generic, OSS infrastructure gateway needs a bounded lifecycle that is not tied to Kubernetes, Vault Agent, a specific issuer or a user's network. It must preserve sticky quarantine for actual revocation, outage or unexpected policy expansion rather than silently re-login after a broken authentication boundary.

## Decision

1. Share one `LeaseLifecycle` across Vault AppRole and JWT signing sources. A first approved request triggers a validated Vault login. Only **after** that use, spawn an in-process weak-owner worker; no token or background network activity is obtained at startup without caller authorization.
2. Schedule proactive and foreground renew-self before expiry, no earlier than one-third of the issued TTL (to avoid a tight renewal loop when the configured threshold exceeds TTL), and renew via the fixed pinned-TLS Vault URL. A single async mutex serializes renewal, foreground use and quarantine. Every response must return the **same** Vault token, renewable true, TTL 30–3600s, exactly the configured token policy and no additional identity policies. Any failure permanently quarantines the existing epoch; the worker never performs automatic login or fallback.
3. Keep the static token-file source unchanged; it remains explicitly operator-rotated and has no background token lifecycle.
4. Recovery is **optional and default-off**. When configured, the administrator provisions a canonical Unix regular file containing an unsigned monotonically increasing counter. The marker is root-owned and has no write permission, and **all ancestor directories** are root-owned and not group/other-writable or symlinked. HostMarshal reads but cannot mutate that marker when running as an unprivileged process. An epoch strictly greater than the value captured at quarantine allows exactly one **new login** through the same locked-down role/issuer and Vault server; failed login consumes the epoch. Counter rollbacks, unreadable/invalid files, in-flight request failures or unchanged values never lower the quarantine baseline; a sleeping renewal task cannot overwrite a prior quarantine. No marker means restart-only recovery.
5. Do not create MCP tools, YAML capabilities, automatic control-plane APIs or provider fallback that expose or modify the marker. An operator must publish it atomically from a distinct principal. No arbitrary Vault role, token identity, signing target or cert issuer is inferred from the counter.
6. The task is cancelled when the provider lifecycle drops; tokens remain only in process memory. Errors are sanitized; credentials are never emitted into MCP outputs or audit messages.

## Alternatives and security tradeoffs

- **Renew only on request:** leaves idle sessions nonfunctional after TTL and breaks long-lived service operation.
- **Unbounded retry/re-login after renewal error:** could defeat revocation or widen signer privileges during provider outage.
- **Treat a service-UID-owned 0400 file as operator authorization:** rejected; the same UID could chmod/replace it.
- **Permit generic symlink or writable ancestor in marker path:** rejected; a compromised process could replace the file while retaining a superficially read-only marker.
- **Kubernetes-native restart/Secret watcher, Vault Agent or a specific cloud KMS:** optional deployment choices, not a mandatory OSS dependency.
- **Self-healing after any external JWT rotation:** rejected; external identity evidence alone does not authorize recovery from already-revoked Vault signing access.

## Verification and remaining work

Real Vault 2.2.1 TLS + disposable sshd CI must prove a 30-second Vault lease survives at least 36 seconds of inactivity through background renewal; revoked renew-self causes sticky quarantine; rights restoration without an operator increment remains denied; a strictly increased trusted counter permits one fresh AppRole/JWT login; rollback/replay is denied; background work cannot bypass grants or leak secrets. Rust tests verify schedule bounds and unsafe same-UID marker rejection.

The actual production identity/role bootstrap, local filesystem trust configuration, durable independent audit for background maintenance failures, cross-platform operator control, signer/issuer CA rotation, Vault HA failover, multi-tenant stress/fairness and independent security review remain out of scope. Acceptance of this ADR is not production certification.
