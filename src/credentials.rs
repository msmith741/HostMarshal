//! Explicitly scoped, optional local SSH private-key references (FR-008, FR-016).
//! No key bytes or passwords are loaded into HostMarshal memory.
use std::{
    collections::BTreeMap,
    fmt,
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialScope {
    operation: String,
    target: String,
    purpose: String,
}

impl CredentialScope {
    pub(crate) fn new(operation: &str, target: &str, purpose: &str) -> Self {
        Self {
            operation: operation.to_owned(),
            target: target.to_owned(),
            purpose: purpose.to_owned(),
        }
    }

    pub fn operation(&self) -> &str {
        &self.operation
    }
    pub fn target(&self) -> &str {
        &self.target
    }
    pub fn purpose(&self) -> &str {
        &self.purpose
    }
}

/// Opaque reference visible to a trusted in-process adapter, never MCP callers.
pub struct CredentialLease {
    scope: CredentialScope,
    opaque_handle: String,
    certificate_path: Option<PathBuf>,
    certificate_principal: Option<String>,
    expires_at: Option<SystemTime>,
    // Owns generated private-key/certificate files. Drop removes them on
    // success, error, cancellation and adapter timeout.
    _ephemeral_dir: Option<tempfile::TempDir>,
}

impl CredentialLease {
    pub(crate) fn new_scoped(scope: CredentialScope, handle: String) -> Self {
        Self {
            scope,
            opaque_handle: handle,
            certificate_path: None,
            certificate_principal: None,
            expires_at: None,
            _ephemeral_dir: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(scope: CredentialScope, handle: &str) -> Self {
        Self::new_scoped(scope, handle.to_owned())
    }

    pub(crate) fn new_ephemeral_ssh_certificate(
        scope: CredentialScope,
        directory: tempfile::TempDir,
        identity_path: PathBuf,
        certificate_path: PathBuf,
        principal: String,
        expires_at: SystemTime,
    ) -> Self {
        Self {
            scope,
            opaque_handle: identity_path.to_string_lossy().into_owned(),
            certificate_path: Some(certificate_path),
            certificate_principal: Some(principal),
            expires_at: Some(expires_at),
            _ephemeral_dir: Some(directory),
        }
    }

    pub fn certificate_path(&self) -> Option<&Path> {
        self.certificate_path.as_deref()
    }

    pub fn certificate_principal(&self) -> Option<&str> {
        self.certificate_principal.as_deref()
    }

    pub fn expires_at(&self) -> Option<SystemTime> {
        self.expires_at
    }

    /// A temporary SSH cert must remain valid through the full remaining
    /// adapter deadline and skew margin; static keys have no expiry metadata.
    pub fn valid_for(&self, duration: Duration) -> bool {
        self.expires_at.is_none_or(|expiry| {
            SystemTime::now()
                .checked_add(duration)
                .is_some_and(|until| expiry > until)
        })
    }

    pub fn scope(&self) -> &CredentialScope {
        &self.scope
    }
    pub fn opaque_handle(&self) -> &str {
        &self.opaque_handle
    }
}

impl fmt::Debug for CredentialLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialLease")
            .field("scope", &self.scope)
            .field("opaque_handle", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerFailure {
    Unavailable,
    Denied,
}

pub trait CredentialBroker: Send + Sync {
    /// Called only after authorization and pre-execution audit. Runtime binds
    /// this async future to the operation deadline and verifies the lease scope.
    fn acquire(
        &self,
        scope: CredentialScope,
    ) -> Pin<Box<dyn Future<Output = Result<CredentialLease, BrokerFailure>> + Send + '_>>;
}

pub struct DenyCredentialBroker;

impl CredentialBroker for DenyCredentialBroker {
    fn acquire(
        &self,
        _scope: CredentialScope,
    ) -> Pin<Box<dyn Future<Output = Result<CredentialLease, BrokerFailure>> + Send + '_>> {
        Box::pin(async { Err(BrokerFailure::Denied) })
    }
}

/// This protected launch-time mapping is NOT a YAML Capability, Grant or remote
/// request. It is controlled by the OS process owner and checked fail-closed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LocalKeyMap {
    api_version: String,
    identities: Vec<LocalIdentity>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LocalIdentity {
    target: String,
    identity_file: PathBuf,
}

/// A minimal local deployment provider. Future secret services belong to M4.
pub struct LocalSshKeyBroker {
    keys: BTreeMap<String, PathBuf>,
}

impl LocalSshKeyBroker {
    pub fn load(path: &Path) -> Result<Self> {
        check_private_key_file(path).context("untrusted SSH identity map permissions")?;
        let raw = std::fs::read(path)?;
        ensure!(raw.len() <= 32 * 1024, "SSH identity map exceeds limit");
        let mapping: LocalKeyMap = serde_json::from_slice(&raw)?;
        ensure!(
            mapping.api_version == "hostmarshal.io/ssh-credentials/v1alpha1",
            "unsupported SSH credential mapping version"
        );
        let mut keys = BTreeMap::new();
        ensure!(mapping.identities.len() <= 128, "too many SSH identities");
        for entry in mapping.identities {
            ensure!(
                !entry.target.is_empty() && entry.target.len() <= 128,
                "invalid identity target"
            );
            ensure!(
                entry
                    .target
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')),
                "invalid identity target"
            );
            ensure!(
                entry.identity_file.is_absolute(),
                "identity file must use an absolute path"
            );
            check_private_key_file(&entry.identity_file)
                .context("invalid SSH identity file permissions")?;
            ensure!(
                keys.insert(entry.target, entry.identity_file).is_none(),
                "duplicate SSH identity target"
            );
        }
        Ok(Self { keys })
    }
}

impl CredentialBroker for LocalSshKeyBroker {
    fn acquire(
        &self,
        scope: CredentialScope,
    ) -> Pin<Box<dyn Future<Output = Result<CredentialLease, BrokerFailure>> + Send + '_>> {
        Box::pin(async move {
            if scope.operation() != "builtin.linux.uname/v1" || scope.purpose() != "ssh-observe" {
                return Err(BrokerFailure::Denied);
            }
            let Some(path) = self.keys.get(scope.target()) else {
                return Err(BrokerFailure::Denied);
            };
            // Recheck each request. A compromised OS owner can still race a
            // path swap; such principals are outside this process trust model.
            check_private_key_file(path).map_err(|_| BrokerFailure::Unavailable)?;
            Ok(CredentialLease::new_scoped(
                scope,
                path.to_string_lossy().to_string(),
            ))
        })
    }
}

/// Fail closed on symlinks, directory paths and key/map files with any group
/// or world permissions. Additional parent-directory ACLs are the deployer's duty.
pub fn check_private_key_file(path: &Path) -> std::io::Result<()> {
    if !path.is_absolute() {
        return Err(std::io::Error::other(
            "expected absolute private credential path",
        ));
    }
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.file_type().is_file() || meta.len() > 64 * 1024 {
        return Err(std::io::Error::other("invalid private credential path"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(std::io::Error::other(
                "private credential file permissions too broad",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ephemeral_lease_cleans_up_material_and_enforces_expiry() {
        let tmp = tempfile::Builder::new()
            .prefix("hm-lease-test")
            .tempdir()
            .unwrap();
        let identity = tmp.path().join("identity");
        let cert = tmp.path().join("identity-cert.pub");
        std::fs::write(&identity, b"test-private-key").unwrap();
        std::fs::write(&cert, b"test-certificate").unwrap();
        let expires = SystemTime::now() + Duration::from_secs(30);
        let lease = CredentialLease::new_ephemeral_ssh_certificate(
            CredentialScope::new("builtin.linux.uname/v1", "host-a", "ssh-observe"),
            tmp,
            identity.clone(),
            cert.clone(),
            "observer".into(),
            expires,
        );
        assert_eq!(lease.certificate_principal(), Some("observer"));
        assert_eq!(lease.certificate_path(), Some(cert.as_path()));
        assert!(lease.valid_for(Duration::from_secs(5)));
        assert!(!lease.valid_for(Duration::from_secs(40)));
        assert!(!format!("{lease:?}").contains("hm-lease-test"));
        drop(lease);
        assert!(!identity.exists());
        assert!(!cert.exists());
    }

    #[test]
    fn credential_lease_debug_never_exposes_handle() {
        let lease = CredentialLease::new_scoped(
            CredentialScope::new("builtin.linux.uname/v1", "host", "ssh-observe"),
            "VERY-SENSITIVE-SSH-PATH".into(),
        );
        assert!(!format!("{lease:?}").contains("VERY-SENSITIVE"));
    }
}
