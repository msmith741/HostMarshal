//! Audit commitments and outcomes for every invocation (FR-009).
//! Events intentionally exclude input, output, handles, secrets and error details.
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditPhase {
    Denied,
    Authorized,
    Succeeded,
    Failed,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub timestamp_ms: u128,
    pub request_id: String,
    pub issuer: String,
    pub subject: String,
    pub capability: String,
    pub operation: String,
    pub target: String,
    pub snapshot_digest: String,
    pub phase: AuditPhase,
    pub reason: String,
}

impl AuditEvent {
    pub fn new(
        request_id: &str,
        issuer: &str,
        subject: &str,
        capability: &str,
        operation: &str,
        target: &str,
        snapshot_digest: &str,
        phase: AuditPhase,
        reason: &str,
    ) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        Self {
            timestamp_ms,
            request_id: request_id.to_owned(),
            issuer: issuer.to_owned(),
            subject: subject.to_owned(),
            capability: capability.to_owned(),
            operation: operation.to_owned(),
            target: target.to_owned(),
            snapshot_digest: snapshot_digest.to_owned(),
            phase,
            reason: reason.to_owned(),
        }
    }
}

pub trait AuditSink: Send + Sync {
    /// An error blocks execution *before* the adapter is called.
    /// Completion-record failure suppresses the result, but cannot undo completed work.
    fn record(&self, event: &AuditEvent) -> io::Result<()>;
}

/// Default stdio deployment sink; no persistent retention guarantee.
pub struct StderrAudit;

impl AuditSink for StderrAudit {
    fn record(&self, event: &AuditEvent) -> io::Result<()> {
        let mut stderr = io::stderr().lock();
        let encoded = serde_json::to_vec(event).map_err(io::Error::other)?;
        stderr.write_all(&encoded)?;
        stderr.write_all(b"\n")?;
        stderr.flush()
    }
}

/// Append-only JSON Lines with sync_data() for each event, where supported.
/// A file alone is NOT tamper-evident, remotely durable or a secure audit service.
pub struct JsonlFileAudit {
    file: Mutex<fs::File>,
}

impl JsonlFileAudit {
    pub fn open(path: &Path) -> io::Result<Self> {
        // Reject an already-present symlink. Protected directory ownership and
        // concurrent file replacement remain operator responsibilities.
        if let Ok(metadata) = fs::symlink_metadata(path) {
            if !metadata.file_type().is_file() {
                return Err(io::Error::other("audit path is not a regular file"));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(io::Error::other(
                        "audit file permissions must be 0600 or stricter",
                    ));
                }
            }
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }
}

impl AuditSink for JsonlFileAudit {
    fn record(&self, event: &AuditEvent) -> io::Result<()> {
        let bytes = serde_json::to_vec(event).map_err(io::Error::other)?;
        let mut file = self
            .file
            .lock()
            .map_err(|_| io::Error::other("audit lock poisoned"))?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_data()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_do_not_encode_payloads_or_tokens() {
        let event = AuditEvent::new(
            "request-1",
            "local://trusted-launcher",
            "operator",
            "inventory.inspect",
            "builtin.inventory.inspect/v1",
            "sample-linux",
            "sha256:abc",
            AuditPhase::Denied,
            "unauthorized",
        );
        let serialized = serde_json::to_string(&event).unwrap();
        assert!(!serialized.contains("password"));
        assert!(!serialized.contains("arguments"));
        assert!(serialized.contains("\"phase\":\"denied\""));
    }
}
