# Audit events and operational guidance

**Status:** M2 implements structured audit events for the declarative stdio execution runtime. An audit event is evidence of what the process attempted and recorded; local files are **not** tamper-evident.

## Event lifecycle

- **denied** — rejected due to input, missing authorization, missing approved operation or capacity. These requests do not reach the adapter.
- **authorized** — pre-execution audit commitment completed *before* any broker access or adapter call.
- **succeeded** — output validated and execution completed.
- **failed** — broker, adapter, timeout or output-validation failure; reason codes are stable and do not include exception details.

Each event carries `timestampMs`, `requestId`, `issuer`, `subject`, `capability`, `operation`, `target`, `snapshotDigest`, `phase`, and `reason`. Denied unresolved input identifiers are sanitized. Events do **not** include arbitrary tool arguments, outputs, authentication headers, credential handles, adapter errors or secret values.

The pre-execution and terminal events share a request ID. Current stderr/file sinks use synchronous I/O (including file synchronization), which can block on a stalled destination; use protected local storage, and do not claim bounded audit latency or support for untrusted network filesystems. Async/isolated audit providers require a separate release gate. A protected operation never runs if the **authorized** record cannot be committed. If a completion record cannot be committed, the runtime returns `audit unavailable` rather than the output; this cannot reverse any side effect, which is why M2 allows only static observation.

## Deployment

The default stdio service writes structured audit JSON lines to **stderr**, so stdout remains MCP protocol-only. Logging/retention depends on the launching service manager; stderr is not independently durable.

For local file-backed audit, use a protected directory and a separate path *outside* the YAML manifest directory:

```sh
install -d -m 0700 /var/lib/hostmarshal/audit
hostmarshal --config-dir /etc/hostmarshal/config \
  --principal operator-01 \
  --audit-log /var/lib/hostmarshal/audit/events.jsonl
```

On Unix the file is created mode **0600**, existing group/world-readable files and non-regular paths are rejected, and each event is written as one JSON line with `sync_data()`. A failed append or sync is treated as audit failure. Protect the parent directory and process identity. Local file rotation, storage exhaustion, backups, retention, integrity monitoring and export are administrator responsibilities.

**Threat boundaries:** An attacker controlling the HostMarshal process, its OS user, parent directory or log storage can still alter/delete local records. Checking a path before opening it is not an atomic anti-symlink guarantee. Do not claim WORM retention, cloud durability, immutability, signing, causality across distributed systems or external correlation from this implementation. Those require future providers, an isolated audit service, and a dedicated threat model.

## Verification

`tests/audit_smoke.py` checks the actual MCP wire + synchronized file, correlation between precommit/terminal records, denied calls, redaction, and file permissions. In-memory audit sink fault-injection tests enforce deny-on-precommit-failure and no-output-on-terminal-failure. Audit sink implementations should be subjected to additional fault injection before supporting any privileged operation.
