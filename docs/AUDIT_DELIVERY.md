# Bounded audit delivery (FR-035)

**Status:** opt-in experimental M4 implementation; source-level process fault containment only, **not** an independently durable or tamper-evident audit service.

## What it does

The default HostMarshal `AuditSink` interface remains unchanged. For stdio and remote HTTP, a trusted launcher can opt into a `BoundedAuditSink` which dispatches to the **same configured sink** (synchronized local JSONL file or stderr) using a dedicated in-process writer thread. The wrapper is provider-neutral; runtime authorization, HTTP denial and Vault renewal/recovery events all share it. No YAML Capability/Grant, MCP argument, external identity issuer, plugin or Vault config can select the audit destination or queue policy.

Each event is checked for an **8 KiB maximum serialized size**; delivery uses a bounded event-count queue, nonblocking admission and one dedicated acknowledgment channel per event. The caller waits for the underlying sink to finish `record()` and acknowledge success, up to the configured acknowledgment deadline. An event is **never** regarded as committed merely because it was enqueued.

If the queue is full, writer exits/fails, an event is oversized, or its receipt does not arrive before the deadline, the wrapper **latches closed** for the lifetime of the process. Subsequent writes fail without retry, queuing, or fallback to stderr or an alternate provider. The existing coordinator refuses to invoke an adapter when its precommit audit fails, and withholds a result when terminal audit fails; Vault lease maintenance and recovery use the same sink and quarantine on audit failure. With multiple simultaneous callers, some already-acknowledged events can precede a later latch failure; the promise is per-event acknowledgment, not a distributed transaction.

## Operator configuration

The optional launch-time JSON file must be a protected, absolute, nonsymlink regular file (mode 0600 or stricter on Unix), under a directory controlled by a trusted OS administrator. It is not a credential or dynamically reloadable YAML resource.

```json
{
  "apiVersion": "hostmarshal.io/audit-delivery/v1alpha1",
  "queueCapacity": 32,
  "ackTimeoutMs": 2000
}
```

`queueCapacity` must be between **1 and 256** inclusive; `ackTimeoutMs` must be between **100 and 5000** milliseconds. Unknown fields and unsupported versions fail startup. The file size must not exceed 4096 bytes.

Use `--audit-delivery-config /etc/hostmarshal/audit-delivery.json` with an existing stdio or HTTP invocation, optionally also specifying `--audit-log /var/lib/hostmarshal/audit/events.jsonl` to select the underlying synchronized file sink. The default behavior **without the flag** is unchanged. There is no queue configuration in MCP requests, remote JWTs, Vault roles or manifests.

An example trusted stdio launch (illustrative paths only):

```sh
hostmarshal --config-dir /etc/hostmarshal/config \
  --principal example-operator \
  --audit-log /var/lib/hostmarshal/audit/events.jsonl \
  --audit-delivery-config /etc/hostmarshal/audit-delivery.json
```

For HTTP, supply the same optional `--audit-delivery-config` after the usual `http --listen ... --config-dir ... --auth-config ...` arguments; the listener remains loopback-only and must still be protected by a separately validated HTTPS proxy.

## Security and failure semantics

- **Acknowledgment, not queueing, is commitment.** The writer calls the existing trusted `AuditSink::record` before signaling success. The JSONL sink still uses `sync_data()`, subject to OS/filesystem guarantees.
- **Finite caller wait, not finite writer lifetime.** When a sink blocks indefinitely, the caller stops waiting after its deadline and the audit wrapper latches closed. The OS thread might still be blocked; Rust cannot safely terminate an arbitrary blocked write. A late writer success **never reopens** the dispatcher. A late audit record may appear after the caller has already been denied.
- **Bounded queue, fail-closed overload.** No dropping oldest events, bypass mode, disk spool, fallback, retry, or in-memory unbounded growth is permitted. A full queue is a security-relevant stop condition, not a success indication.
- **One trusted sink.** The wrapper does not introduce network egress, receipt verification from an external collector, a separate security principal, detached persistence, or a generic extensible plugin.
- **Process failure and cancellation.** A crash may leave authorized/precommit events without terminal records, and even an acknowledged local write might be lost after catastrophic storage failure. No exactly-once or global transaction semantics are claimed.
- **Timing and scheduling.** `AuditSink::record` remains a synchronous trait method. Its bounded wait may block a Tokio worker thread; configure capacity/deadline for your workload and test service-level latency/availability. One writer thread serializes underlying sink events. No hot reload of the queue, thread restart or automatic recovery is provided.
- **Latched failure recovery.** Restore the underlying audit destination, investigate the incident and restart HostMarshal under a trusted operator workflow. Do not programmatically clear the latch or retry unsafe operations.

This reduces an unbounded in-process audit wait to a configurable caller-side deadline; it **does not** provide process isolation, WORM storage, tamper evidence, out-of-band receipts, authenticated remote delivery, durable spooling, retention management, or protection from compromise of the HostMarshal OS identity. Those remain separate design and production acceptance gates.

## Tests and release gates

- `src/audit_delivery.rs` unit tests exercise acknowledged in-order commits, writer failure, permanently latched timeout, oversized events and strict configuration validation.
- `tests/audit_delivery_smoke.py` runs a disposable stdio MCP process using an operator-protected delivery config, verifies authorized/denied event commitments and rejects unsafe launch-time inputs.
- All ordinary Rust, real Vault/SSH signer, OAuth/Traefik, fuzz and disposable K3s checks still apply. The multi-node K3s CNI isolation gate remains separate and is not implied by the smoke job.

See [ADR-0018](adr/0018-bounded-audit-dispatch.md), [FR-035 traceability](TRACEABILITY.md), [audit guidance](AUDIT.md) and [security architecture](SECURITY_ARCHITECTURE.md).
