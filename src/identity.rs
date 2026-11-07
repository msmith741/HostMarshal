//! Transport-authenticated caller identity (FR-004 / ADR-0007 / ADR-0012).
//! Only a trusted local launcher or verified JWT access-token validator may bind it.
use anyhow::{Result, ensure};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationMethod {
    TrustedLocalLauncher,
    VerifiedJwtAccessToken,
}

#[derive(Clone, Debug)]
pub struct AuthenticatedCaller {
    issuer: String,
    subject: String,
    method: AuthenticationMethod,
}

fn valid_subject(subject: &str) -> bool {
    !subject.is_empty()
        && subject.len() <= 128
        && subject
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_'))
}

/// Remote issuers must be stable https identities, not arbitrary client strings.
pub fn valid_remote_issuer(issuer: &str) -> bool {
    if issuer.len() > 512 || issuer.is_empty() {
        return false;
    }
    let Ok(url) = url::Url::parse(issuer) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && !issuer.ends_with('/')
}

impl AuthenticatedCaller {
    /// Identity is asserted by the trusted OS launcher, never MCP parameters.
    pub fn from_trusted_launcher(subject: &str) -> Result<Self> {
        ensure!(valid_subject(subject), "invalid launcher identity");
        Ok(Self {
            issuer: "local://trusted-launcher".to_owned(),
            subject: subject.to_owned(),
            method: AuthenticationMethod::TrustedLocalLauncher,
        })
    }

    /// Only the JWT signature/claim verifier can invoke this internal constructor.
    pub(crate) fn from_verified_access_token(issuer: &str, subject: &str) -> Result<Self> {
        ensure!(valid_remote_issuer(issuer), "invalid verified issuer");
        ensure!(valid_subject(subject), "invalid verified subject");
        Ok(Self {
            issuer: issuer.to_owned(),
            subject: subject.to_owned(),
            method: AuthenticationMethod::VerifiedJwtAccessToken,
        })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
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
    fn rejects_invalid_identities() {
        for principal in ["", "someone\nadmin", "../../root", "a b", "🌍"] {
            assert!(AuthenticatedCaller::from_trusted_launcher(principal).is_err());
        }
        for issuer in [
            "http://issuer.example.invalid",
            "https://user:pass@example.invalid",
            "https://example.invalid?ignored=1",
            "https://example.invalid/",
        ] {
            assert!(!valid_remote_issuer(issuer));
        }
        let principal = AuthenticatedCaller::from_trusted_launcher("example-operator").unwrap();
        assert_eq!(principal.issuer(), "local://trusted-launcher");
        assert_eq!(
            principal.method(),
            AuthenticationMethod::TrustedLocalLauncher
        );
    }
}
