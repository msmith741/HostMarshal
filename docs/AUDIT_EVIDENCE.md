# Hash-linked audit evidence and offline verification (FR-036)

**Status:** experimental integrity-detection component. This is neither a standalone audit service nor tamper-evident retention without an **externally protected checkpoint**.

## Design

HostMarshal supports an optional launch-time `--audit-evidence-log /absolute/path/evidence.jsonl` in place of `--audit-log`. The existing default stderr/file sink is unchanged. The new `EvidenceFileAudit` implements the same `AuditSink` trait and is compatible with optional `--audit-delivery-config` bounded dispatch from FR-035.

Each appended canonical JSONL record includes:

- `apiVersion=hostmarshal.io/audit-evidence/v1alpha1`
- Monotonically increasing `sequence`, starting at 1
- `previous`, the preceding 32-byte digest as 64 lowercase hex digits (all zeroes for the first record)
- `event`, the already-redacted standard HostMarshal audit event
- `digest`, SHA-256 of a domain-separated encoding of previous digest, 8-byte big-endian sequence, 4-byte big-endian event length, and serialized event bytes

The underlying file is created 0600 on Unix (or existing 0600-or-stricter regular file). Each record is appended under one mutex and `sync_data()` completes before `AuditSink::record` reports success. On any write or synchronization failure, the writer latches unavailable. Restart validates the **entire existing journal** before appending; a broken line, unknown format, noncanonical record, sequence discontinuity, wrong link or digest prevents startup. An 8-KiB event budget and 16-KiB line bound apply. Full-file verification requires time proportional to journal length; external archival/rotation is deliberately not automated.

## Verify and anchor

```sh
hostmarshal audit verify /var/lib/hostmarshal/audit/evidence.jsonl
hostmarshal audit verify /var/lib/hostmarshal/audit/evidence.jsonl \
  --expected-head <64-lowercase-hex-digest>
```

The CLI outputs a JSON object containing `sequence` and `head`. Compare `head` to a checkpoint **published and retained outside the HostMarshal process/OS identity and log storage**. Protect the checkpoint's authenticity and integrity with an independent trust channel (for example, a security-owned signed record or separately access-controlled store). A matching externally trusted head establishes that the log still contains the same ordered prefix up to that checkpoint. A later valid suffix can be verified but is not independently anchored until the next exported checkpoint.

**Important limitation:** A local adversary who can modify all log records can rewrite the entire chain; they can also delete a valid suffix or replace the journal with a new valid chain. Local `audit verify` without an external head does **not** detect such replacement or truncation. A forged checkpoint held by the same compromised identity is not an external anchor. A file with a valid hash chain is not proof of true event completeness, honest event generation, correct timestamps, crash-consistent receipt semantics, or immutability. External authenticated receipt delivery, independent process credentials/storage, key-managed signing, retention and anti-rollback are separate designs.

This is a generic Linux-first source capability; it does not depend on Kubernetes, Vault, a cloud service or private DNS. The illustrative paths above are not installed or provisioned automatically.

## Security and failure boundaries

- The log path must be an absolute path and not a symlink; nonregular files or broadly readable existing files fail closed. Parent-directory ownership/ACLs and race-free path resolution must still be enforced by a trusted operator. The implementation does not claim atomic anti-replacement controls against an attacker with its OS UID.
- `--audit-log` and `--audit-evidence-log` cannot be supplied simultaneously; there is no automatic fallback or copy to an unaudited sink.
- The verifier rejects an incomplete final line; if a process crashes after partial write, an operator must examine evidence rather than silently repairing or truncating the log.
- An acknowledged local `sync_data()` is not a guarantee against power loss, storage firmware faults, rollback, or process compromise. Default stderr, ordinary JSONL and the hash-linked sink are distinct operator choices.
- Internal records contain only sanitized audit fields. Raw tool arguments, secrets, HTTP authorization headers, SSH private keys and Vault tokens are never introduced into records.
- File rotation and a trusted externally retained anchor are not automated. A future process-isolated collector with authenticated receipts and bounded network delivery requires another security design/acceptance gate.

## Tests

`src/audit_evidence.rs` covers append, reopen, strict record checking, per-file ownership/perms, tampering, reordering, malformed/truncated lines, and external-head detection of a missing suffix. `tests/audit_evidence_smoke.py` runs actual stdio MCP traffic with a bounded audit worker and checks redaction, CLI verification and startup denial after tampering. Source CI remains release-limited and may use conservative change-based regression selection; see [CI policy](CI_REGRESSION_SELECTION.md).

See [ADR-0019](adr/0019-hash-linked-audit-evidence.md) and [FR-036 traceability](TRACEABILITY.md).
