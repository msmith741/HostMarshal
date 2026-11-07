//! M4 optional Vault SSH CA signing provider (FR-020, ADR-0013).
//! Vault never gives HostMarshal a private key. The local key belongs to the
//! dedicated service identity; its public half is signed per authorized call.
use std::{
    collections::BTreeMap,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use reqwest::{Client, header::HeaderValue};
use serde::Deserialize;
use serde_json::json;
use zeroize::Zeroizing;

use crate::{
    credentials::{
        BrokerFailure, CredentialBroker, CredentialLease, CredentialScope, check_private_key_file,
    },
    transport::check_public_trust_file,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProviderConfig {
    api_version: String,
    vault_url: String,
    ssh_mount: String,
    token_file: PathBuf,
    #[serde(default)]
    ca_certificate_file: Option<PathBuf>,
    identities: Vec<SshIdentity>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SshIdentity {
    target: String,
    identity_file: PathBuf,
    public_key_file: PathBuf,
    role: String,
    principal: String,
}

pub struct VaultSshCertBroker {
    client: Client,
    base_url: url::Url,
    mount: String,
    token_file: PathBuf,
    identities: BTreeMap<String, SshIdentity>,
}

fn valid_path_segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

impl VaultSshCertBroker {
    pub fn load(path: &Path) -> Result<Self> {
        check_private_key_file(path).context("invalid Vault provider map")?;
        let bytes = std::fs::read(path)?;
        ensure!(bytes.len() <= 32 * 1024, "Vault provider map exceeds limit");
        let cfg: ProviderConfig = serde_json::from_slice(&bytes)?;
        ensure!(
            cfg.api_version == "hostmarshal.io/vault-ssh/v1alpha1",
            "unsupported Vault SSH map version"
        );
        let base_url = url::Url::parse(&cfg.vault_url)?;
        ensure!(
            base_url.scheme() == "https"
                && base_url.host_str().is_some()
                && base_url.username().is_empty()
                && base_url.password().is_none()
                && base_url.query().is_none()
                && base_url.fragment().is_none()
                && base_url.path() == "/",
            "Vault server must be an HTTPS origin with no embedded path or credentials"
        );
        ensure!(
            cfg.ssh_mount.split('/').all(valid_path_segment),
            "invalid trusted Vault SSH mount"
        );
        check_private_key_file(&cfg.token_file).context("invalid Vault token path")?;
        let mut client = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(2))
            .timeout(std::time::Duration::from_secs(4))
            .user_agent("HostMarshal/0.1");
        if let Some(ca) = &cfg.ca_certificate_file {
            check_public_trust_file(ca)?;
            let cert = reqwest::Certificate::from_pem(&std::fs::read(ca)?)?;
            client = client.add_root_certificate(cert);
        }
        let client = client.build()?;
        ensure!(
            !cfg.identities.is_empty() && cfg.identities.len() <= 128,
            "invalid number of Vault identities"
        );
        let mut identities = BTreeMap::new();
        for id in cfg.identities {
            ensure!(
                valid_path_segment(&id.target) || crate::transport::valid_host_address(&id.target),
                "invalid identity target"
            );
            ensure!(valid_path_segment(&id.role), "invalid Vault signing role");
            ensure!(
                valid_path_segment(&id.principal),
                "invalid Vault SSH principal"
            );
            check_private_key_file(&id.identity_file)?;
            check_public_trust_file(&id.public_key_file)?;
            ensure!(
                identities.insert(id.target.clone(), id).is_none(),
                "duplicate Vault SSH target"
            );
        }
        Ok(Self {
            client,
            base_url,
            mount: cfg.ssh_mount,
            token_file: cfg.token_file,
            identities,
        })
    }

    async fn issue(&self, scope: CredentialScope) -> Result<CredentialLease, BrokerFailure> {
        if scope.operation() != "builtin.linux.uname/v1" || scope.purpose() != "ssh-observe" {
            return Err(BrokerFailure::Denied);
        }
        // Caller identity is supplied by the trusted runtime, never by YAML
        // input or a caller-provided Vault role.
        let Some(subject) = scope.subject() else {
            return Err(BrokerFailure::Denied);
        };
        let Some(_issuer) = scope.issuer() else {
            return Err(BrokerFailure::Denied);
        };
        let Some(entry) = self.identities.get(scope.target()) else {
            return Err(BrokerFailure::Denied);
        };
        check_private_key_file(&entry.identity_file).map_err(|_| BrokerFailure::Unavailable)?;
        check_public_trust_file(&entry.public_key_file).map_err(|_| BrokerFailure::Unavailable)?;
        check_private_key_file(&self.token_file).map_err(|_| BrokerFailure::Unavailable)?;

        let token_raw = std::fs::read(&self.token_file).map_err(|_| BrokerFailure::Unavailable)?;
        if token_raw.len() > 4096 {
            return Err(BrokerFailure::Denied);
        }
        let token =
            Zeroizing::new(String::from_utf8(token_raw).map_err(|_| BrokerFailure::Denied)?);
        let token = token.trim();
        let header = HeaderValue::from_str(token).map_err(|_| BrokerFailure::Denied)?;
        if token.is_empty() {
            return Err(BrokerFailure::Denied);
        }
        let public_key = std::fs::read_to_string(&entry.public_key_file)
            .map_err(|_| BrokerFailure::Unavailable)?;
        if public_key.len() > 4096 || public_key.split_whitespace().count() < 2 {
            return Err(BrokerFailure::Denied);
        }
        let url = self
            .base_url
            .join(&format!("/v1/{}/sign/{}", self.mount, entry.role))
            .map_err(|_| BrokerFailure::Unavailable)?;
        let result = self
            .client
            .post(url)
            .header("X-Vault-Token", header)
            .json(&json!({
                "public_key": public_key,
                "valid_principals": entry.principal,
                "cert_type": "user",
                "ttl": "60s",
                "key_id": format!("hostmarshal:{}:{}", subject, scope.target())
            }))
            .send()
            .await
            .map_err(|_| BrokerFailure::Unavailable)?;
        if !result.status().is_success() {
            return Err(BrokerFailure::Denied);
        }
        let mut content = Vec::new();
        let mut response = result;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| BrokerFailure::Unavailable)?
        {
            if content.len().saturating_add(chunk.len()) > 16 * 1024 {
                return Err(BrokerFailure::Denied);
            }
            content.extend_from_slice(&chunk);
        }
        let body: serde_json::Value =
            serde_json::from_slice(&content).map_err(|_| BrokerFailure::Unavailable)?;
        let cert = body
            .pointer("/data/signed_key")
            .and_then(|v| v.as_str())
            .ok_or(BrokerFailure::Unavailable)?;
        let mut fields = cert.split_whitespace();
        let kind = fields.next().ok_or(BrokerFailure::Denied)?;
        let encoded = fields.next().ok_or(BrokerFailure::Denied)?;
        if !kind.ends_with("-cert-v01@openssh.com")
            || kind.len() > 96
            || encoded.len() > 8192
            || encoded.len() < 64
            || !encoded
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        {
            return Err(BrokerFailure::Denied);
        }
        let lease_duration = body["lease_duration"].as_u64().unwrap_or(60);
        if !(1..=120).contains(&lease_duration) {
            return Err(BrokerFailure::Denied);
        }
        // NamedTempFile creates a mode-0600 path and unlinks it on drop.
        // No signed certificate or private-key material is returned over MCP.
        let mut file = tempfile::Builder::new()
            .prefix("hostmarshal-ssh-cert-")
            .tempfile()
            .map_err(|_| BrokerFailure::Unavailable)?;
        writeln!(file, "{kind} {encoded}").map_err(|_| BrokerFailure::Unavailable)?;
        file.flush().map_err(|_| BrokerFailure::Unavailable)?;
        Ok(CredentialLease::with_signed_certificate(
            scope,
            entry.identity_file.to_string_lossy().to_string(),
            file,
        ))
    }
}

impl CredentialBroker for VaultSshCertBroker {
    fn acquire(
        &self,
        scope: CredentialScope,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<CredentialLease, BrokerFailure>> + Send + '_>,
    > {
        Box::pin(self.issue(scope))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mount_path_segments_are_strictly_authorized() {
        assert!(valid_path_segment("ssh-prod"));
        for s in ["", "..", "ssh/sign", "ssh?token=x", "ssh/../../admin", "-"] {
            assert!(!valid_path_segment(s) || s == "-");
        }
    }
}
