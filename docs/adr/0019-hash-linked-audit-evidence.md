# ADR-0019: Optional hash-linked audit evidence and external-head verification

- **Status:** Proposed — source implementation experimental, release security review pending
- **Date:** 2026-11-08
- **Related:** FR-009/034/035/036, ADR-0008/0017/0018
- **Scope:** provider-neutral local journal integrity detection; never independent retention by itself

## Context

HostMarshal's synchronous file sink and bounded dispatch worker can ensure that an operation is not treated as audit-committed until the underlying local write succeeds. They cannot detect alteration of old records, reordered records, missing lines, or operator/attacker rollback. Before designing a separate collector with authenticated receipts, introduce a bounded and versioned integrity record format that can be audited offline.

## Decision

1. Make a **separate opt-in file sink** selectable by the trusted launcher, not manifests/MCP/issuer data; existing stderr/ordinary JSONL behavior is unchanged. Require exclusive choice of `--audit-log` and `--audit-evidence-log`. Continue supporting the FR-035 bounded dispatcher as a wrapper.
2. Each standard redacted event becomes a canonical JSONL evidence record containing a version, incrementing 64-bit sequence, previous digest, full sanitized event and new SHA-256 digest. Include explicit domain separation and unambiguous binary encoding of the sequence and length before hashing.
3. Commit one row at a time under a lock and `sync_data()` before acknowledging an audit operation. On append/sync failure, permanently latch the file sink unavailable. Reject oversized records or invalid history rather than auto-recovering/truncating.
4. At startup, verify the complete existing history and refuse append if any record is malformed, noncanonical, out of sequence or hash-inconsistent. Provide `hostmarshal audit verify <path> [--expected-head <hex>]` for offline checks; reject a supplied head that differs from the local history.
5. Treat externally published and separately protected checkpoints as **future operator infrastructure**, not as an implied feature of this local sink. Without an external trust boundary, a sufficiently privileged attacker can regenerate the whole chain or delete a valid suffix. Any claim of immutable, WORM, independently durable or cryptographically authenticated audit requires a separately approved collector/attestation protocol.

## Alternatives

- Replace legacy JSONL silently: rejected because downstream consumers depend on its event format and retention semantics.
- Sign records with an unprotected private key inside the process: rejected because a process compromise would allow forging and would create a false sense of independent integrity.
- Automatically truncate damaged trailing records: rejected as evidence destruction and an unauthorized recovery mechanism.
- Deploy an external collector in this slice: deferred pending separate privilege isolation, authentication, receipt replay, key management, outage and operator recovery threat analysis.

## Verification and release gates

Unit and real stdio MCP/CLI smoke tests must prove positive append/verify, preserved event redaction, corrupt record and incomplete-line denial, and the inability to identify missing valid suffix records without a separately supplied trusted head. The CI selector itself is fail-safe: unknown changes trigger all suites; full weekly, dispatch and relevant integration runs remain mandatory. Production storage ownership, verified out-of-process checkpoints, collector isolation, performance/rotation, retention and independent security assessment remain outstanding.
