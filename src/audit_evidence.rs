//! Optional independently *verifiable* local audit record chaining (FR-036).
//! Integrity evidence is NOT proof of independent retention, WORM, authenticity
//! or unbroken history without an external trusted checkpoint.
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    path::Path,
    sync::Mutex,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::audit::{AuditEvent, AuditSink};

const FORMAT: &str = "hostmarshal.io/audit-evidence/v1alpha1";
const DOMAIN: &[u8] = b"hostmarshal.audit-evidence/v1\0";
const MAX_EVENT_BYTES: usize = 8192;
const MAX_LINE_BYTES: usize = 16384;
const ZERO: [u8; 32] = [0; 32];

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EvidenceRecord {
    api_version: String,
    sequence: u64,
    previous: String,
    event: AuditEvent,
    digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceCheckpoint {
    pub sequence: u64,
    pub head: String,
}

fn bad(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("in-memory hex formatting");
    }
    out
}

fn digest(previous: &[u8; 32], sequence: u64, encoded_event: &[u8]) -> io::Result<[u8; 32]> {
    let event_len = u32::try_from(encoded_event.len()).map_err(|_| bad("oversized event"))?;
    let mut sha = Sha256::new();
    sha.update(DOMAIN);
    sha.update(previous);
    sha.update(sequence.to_be_bytes());
    sha.update(event_len.to_be_bytes());
    sha.update(encoded_event);
    Ok(sha.finalize().into())
}

fn check_existing(path: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_file() {
        return Err(bad("audit evidence path must be a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(bad("audit evidence file must be mode 0600 or stricter"));
        }
    }
    Ok(())
}

fn verify_reader<R: BufRead>(mut reader: R) -> io::Result<EvidenceCheckpoint> {
    let mut previous = ZERO;
    let mut sequence: u64 = 0;
    loop {
        let mut line = Vec::new();
        let read = (&mut reader)
            .take(MAX_LINE_BYTES as u64 + 1)
            .read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        if read > MAX_LINE_BYTES || line.last() != Some(&b'\n') {
            return Err(bad("audit evidence line exceeds limit or is incomplete"));
        }
        line.pop();
        let record: EvidenceRecord =
            serde_json::from_slice(&line).map_err(|_| bad("malformed audit evidence record"))?;
        if record.api_version != FORMAT {
            return Err(bad("unsupported audit evidence record version"));
        }
        let expected_seq = sequence.checked_add(1).ok_or_else(|| bad("sequence overflow"))?;
        if record.sequence != expected_seq || record.previous != hex(&previous) {
            return Err(bad("audit evidence sequence or predecessor mismatch"));
        }
        let event_bytes = serde_json::to_vec(&record.event).map_err(io::Error::other)?;
        if event_bytes.len() > MAX_EVENT_BYTES {
            return Err(bad("audit evidence event exceeds limit"));
        }
        let candidate = digest(&previous, record.sequence, &event_bytes)?;
        if record.digest != hex(&candidate) {
            return Err(bad("audit evidence digest mismatch"));
        }
        if serde_json::to_vec(&record).map_err(io::Error::other)? != line {
            return Err(bad("noncanonical audit evidence record"));
        }
        sequence = record.sequence;
        previous = candidate;
    }
    Ok(EvidenceCheckpoint {
        sequence,
        head: hex(&previous),
    })
}

/// Check the local chain, and optionally compare its head to a checkpoint
/// obtained from a separately controlled trust domain.
pub fn verify(path: &Path, expected_head: Option<&str>) -> io::Result<EvidenceCheckpoint> {
    check_existing(path)?;
    let file = File::open(path)?;
    let checkpoint = verify_reader(BufReader::new(file))?;
    if let Some(expected) = expected_head {
        if expected.len() != 64
            || !expected.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || checkpoint.head != expected
        {
            return Err(bad("audit evidence does not match trusted external checkpoint"));
        }
    }
    Ok(checkpoint)
}

struct Writer {
    file: File,
    sequence: u64,
    previous: [u8; 32],
    healthy: bool,
}

pub struct EvidenceFileAudit {
    writer: Mutex<Writer>,
}

impl EvidenceFileAudit {
    /// A new file is created mode 0600; an existing file must validate fully
    /// before append. File ancestry, races and external anchoring are outside
    /// this pre-alpha process-local contract and must be protected by operators.
    pub fn open(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(bad("audit evidence path must be absolute"));
        }
        let file = match check_existing(path) {
            Ok(()) => OpenOptions::new().append(true).open(path)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let mut opts = OpenOptions::new();
                opts.create_new(true).append(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.mode(0o600);
                }
                opts.open(path)?
            }
            Err(error) => return Err(error),
        };
        let checkpoint = verify(path, None)?;
        let mut decoded = [0_u8; 32];
        for (index, byte) in decoded.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&checkpoint.head[index * 2..index * 2 + 2], 16)
                .map_err(|_| bad("invalid internal checkpoint"))?;
        }
        Ok(Self {
            writer: Mutex::new(Writer {
                file,
                sequence: checkpoint.sequence,
                previous: decoded,
                healthy: true,
            }),
        })
    }
}

impl AuditSink for EvidenceFileAudit {
    fn record(&self, event: &AuditEvent) -> io::Result<()> {
        let payload = serde_json::to_vec(event).map_err(io::Error::other)?;
        if payload.len() > MAX_EVENT_BYTES {
            return Err(bad("audit event too large"));
        }
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| io::Error::other("audit evidence lock poisoned"))?;
        if !writer.healthy {
            return Err(io::Error::other("audit evidence writer unavailable"));
        }
        let sequence = writer.sequence.checked_add(1).ok_or_else(|| {
            writer.healthy = false;
            bad("audit evidence sequence exhausted")
        })?;
        let next = digest(&writer.previous, sequence, &payload)?;
        let row = EvidenceRecord {
            api_version: FORMAT.to_owned(),
            sequence,
            previous: hex(&writer.previous),
            event: event.clone(),
            digest: hex(&next),
        };
        let mut data = serde_json::to_vec(&row).map_err(io::Error::other)?;
        if data.len() + 1 > MAX_LINE_BYTES {
            writer.healthy = false;
            return Err(bad("audit evidence record exceeds line size"));
        }
        data.push(b'\n');
        // A failed write or sync may leave a partial line. Never continue on
        // the current handle; require operator investigation and fresh verify.
        if let Err(error) = writer.file.write_all(&data).and_then(|_| writer.file.sync_data()) {
            writer.healthy = false;
            return Err(error);
        }
        writer.sequence = sequence;
        writer.previous = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditContext, AuditPhase};
    use std::io::Cursor;

    fn event(id: &str) -> AuditEvent {
        AuditEvent::new(
            AuditContext {
                request_id: id,
                issuer: "local://trusted-launcher",
                subject: "operator",
                capability: "inventory.inspect",
                operation: "builtin.inventory.inspect/v1",
                target: "host-a",
                snapshot_digest: "sha256:123",
            },
            AuditPhase::Authorized,
            "explicit_grant",
        )
    }

    #[test]
    fn chained_append_reopen_and_external_checkpoint() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("audit.evidence.jsonl");
        let a = EvidenceFileAudit::open(&file).unwrap();
        a.record(&event("first")).unwrap();
        a.record(&event("second")).unwrap();
        let checkpoint = verify(&file, None).unwrap();
        assert_eq!(checkpoint.sequence, 2);
        assert_eq!(checkpoint.head.len(), 64);
        drop(a);
        let b = EvidenceFileAudit::open(&file).unwrap();
        b.record(&event("third")).unwrap();
        assert_eq!(verify(&file, None).unwrap().sequence, 3);
        assert!(verify(&file, Some(&checkpoint.head)).is_err());
    }

    #[test]
    fn altered_record_and_missing_line_are_detectable_with_checkpoint() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("audit.evidence.jsonl");
        let a = EvidenceFileAudit::open(&file).unwrap();
        a.record(&event("one")).unwrap();
        a.record(&event("two")).unwrap();
        drop(a);
        let original = fs::read(&file).unwrap();
        let checkpoint = verify(&file, None).unwrap();
        let modified = String::from_utf8(original.clone()).unwrap().replace("one", "two");
        fs::write(&file, modified).unwrap();
        assert!(verify(&file, None).is_err());
        fs::write(&file, &original).unwrap();
        let first_line = original.split(|byte| *byte == b'\n').next().unwrap();
        fs::write(&file, [first_line, b"\n"].concat()).unwrap();
        // A well-formed prefix is NOT independently detectable without a
        // trusted external commitment to the expected final head.
        assert_eq!(verify(&file, None).unwrap().sequence, 1);
        assert!(verify(&file, Some(&checkpoint.head)).is_err());
        fs::write(&file, &original[..original.len() - 1]).unwrap();
        assert!(verify(&file, None).is_err());
        assert!(EvidenceFileAudit::open(&file).is_err());
    }

    #[test]
    fn rejects_reordering_noncanonical_and_bad_permissions() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("evidence.jsonl");
        assert!(verify_reader(Cursor::new(b"invalid\n")).is_err());
        let audit = EvidenceFileAudit::open(&path).unwrap();
        audit.record(&event("a")).unwrap();
        audit.record(&event("b")).unwrap();
        drop(audit);
        let original = fs::read_to_string(&path).unwrap();
        let reversed = original.lines().rev().collect::<Vec<_>>().join("\n") + "\n";
        fs::write(&path, reversed).unwrap();
        assert!(verify(&path, None).is_err());
        fs::write(&path, original).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(EvidenceFileAudit::open(&path).is_err());
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let alias = root.path().join("alias");
            symlink(&path, &alias).unwrap();
            assert!(EvidenceFileAudit::open(&alias).is_err());
        }
    }
}
