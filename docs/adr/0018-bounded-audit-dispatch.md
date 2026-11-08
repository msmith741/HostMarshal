# ADR-0018: Bounded acknowledged audit dispatch boundary

- **Status:** Proposed — experimental M4 implementation, production security approval pending
- **Date:** 2026-11-08
- **Related:** FR-009, FR-021, FR-034, FR-035; ADR-0008, ADR-0017
- **Scope:** provider-neutral in-process audit delivery for all trusted `AuditSink` implementations

## Context

The current audit sink contract is synchronous and fail-closed, but file sync or stderr I/O can block indefinitely if a local destination hangs. Concurrent MCP invocations and background Vault lease tasks all depend on those audit commits. A configurable bound on caller waiting and queue growth improves fault containment without allowing the audit requirement to be bypassed or inventing unsupported durable-receipt claims.

## Decision

1. Provide an **opt-in** `BoundedAuditSink` wrapper over any launch-selected `AuditSink`. The trusted launcher reads a protected, versioned JSON `audit-delivery` spec. No YAML capability, policy grant, MCP caller, JWT or Vault provider can configure the audit destination or delivery policy. The default sink remains unchanged when this option is omitted.
2. Spawn one in-process writer thread with a **fixed-capacity synchronous channel**, a bounded serialized event size, and per-event acknowledgment of the **underlying sink's completed `record()` call**. Enqueue acceptance alone never counts as audit success.
3. Use nonblocking queue admission and a finite `ackTimeoutMs` wait for the receipt. Queue saturation, oversized events, worker disconnection, sink error or acknowledgment timeout **permanently latch fail closed** for this process lifetime. Never silently drop, resend, fallback, enqueue indefinitely or reopen without operator restart.
4. Retain M2/M4 precommit and terminal semantics: failing a precommit denies execution before its adapter/credential operation; failing a completion suppresses the result but cannot roll back an already completed side effect. The existing restricted observation-only surface remains unchanged.
5. Restrict configuration to fixed `hostmarshal.io/audit-delivery/v1alpha1` with `queueCapacity` 1–256 and `ackTimeoutMs` 100–5000, strict fields, protected file path and a 4096-byte input budget. The payload event budget is 8 KiB; record bodies must already satisfy ordinary audit redaction rules.

## Alternatives considered

- **Unbounded async fire-and-forget queue:** rejected because enqueuing does not establish a committed audit event and memory can grow without limit.
- **Drop-on-overflow or fallback to stderr:** rejected; either creates an unaudited authorization bypass or splits the trusted event stream silently.
- **Retry/reopen on writer timeout:** rejected; a prior event might still commit after its acknowledgment deadline, and duplicate/reordered records would weaken audit semantics.
- **Network collector or separate process with signed receipts:** deferred to a distinct threat model and deployable protocol. This in-process increment does not imply WORM/durable remote auditing.

## Consequences and remaining limits

An acknowledgment can be delayed or absent when a filesystem stalls. The caller has a finite wait and can fail closed, but the **writer thread itself may remain blocked** until the underlying OS I/O completes; a late write may be visible even after denial. The dispatcher does not enforce external worker isolation, crash consistency beyond the underlying sink, immutability, trusted-clock correlation, independent receipt verification or retention. It can also briefly block a Tokio worker because the existing audit interface is synchronous. Proper persistent collector and bounded admission fairness/latency under high contention require additional work.

## Verification

Unit tests cover event ordering/acknowledgment, permanent writer-failure and timeout latches, per-event size limits, and strict configuration. Stdio integration runs authorized/denied MCP calls under the opt-in dispatcher and rejects unsafe configs. Existing real Vault, Keycloak/Traefik, fuzz, schema/MCP and disposable K3s checks remain non-negotiable on the exact PR head. The independent multi-node K3s policy suite remains a separate release gate.
