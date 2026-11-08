//! Authenticated caller context bound by a trusted transport (FR-004 / ADR-0007).
//! In pre-alpha, only the local OS/process launcher may assert a principal.
use anyhow::{Result, ensure};

/// How a caller identity was established. Client-provided MCP metadata is never proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationMethod {
    TrustedLocalLauncher,
    VerifiedJwtAccessToken,
}

/// Private fields prevent MCP tool arguments from constructing or modifying identity.
#[derive(Clone, Debug)]
pub struct AuthenticatedCaller {
    issuer: String,
    subject: String,
    method: AuthenticationMethod,
}

impl AuthenticatedCaller {
    /// The program launcher, not the MCP peer, is responsible for binding this value.
    pub fn from_trusted_launcher(subject: &str) -> Result<Self> {
        ensure!(
            !subject.is_empty()
                && subject.len() <= 128
                && subject
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_')),
            "invalid launcher identity"
        );
        Ok(Self {
            issuer: "local://trusted-launcher".to_owned(),
            subject: subject.to_owned(),
            method: AuthenticationMethod::TrustedLocalLauncher,
        })
    }

    /// This constructor may be called only after cryptographic token verification
    /// in the trusted remote authentication module, never from an MCP field.
    pub(crate) fn from_verified_jwt(issuer: &str, subject: &str) -> Result<Self> {
        ensure!(
            issuer.starts_with("https://") && !subject.is_empty(),
            "invalid verified identity"
        );
        Ok(Self {
            issuer: issuer.to_owned(),
            subject: subject.to_owned(),
            method: AuthenticationMethod::VerifiedJwtAccessToken,
        })
    }

    pub fn issuer(&self) -> &str {
        self.issuer
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }

    pub fn method(&self) -> AuthenticationMethod {
        self.method
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_untrusted_identity_syntax() {
        for principal in ["", "someone\nadmin", "../../root", "a b", "🌍"] {
            assert!(AuthenticatedCaller::from_trusted_launcher(principal).is_err());
        }
        let principal = AuthenticatedCaller::from_trusted_launcher("example-operator").unwrap();
        assert_eq!(principal.issuer(), "local://trusted-launcher");
        assert_eq!(
            principal.method(),
            AuthenticationMethod::TrustedLocalLauncher
        );
    }
}
