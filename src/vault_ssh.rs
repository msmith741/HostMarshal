//! M4 opt-in Vault SSH CA signing broker, never an arbitrary secret fetcher.
//! Private keys are generated per invocation; the trusted CA signature,
//! principal, fresh public-key binding and expiry are checked before use.
use std::{
    collections::BTreeMap,
    fs,
    future::Future,
    io::Write,
    path::{Path, PathBuf},
    pin::Pin,
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use reqwest::{Client, Url, header::HeaderValue};
use serde::Deserialize;
use serde_json::json;
use ssh_key::{Certificate, HashAlg, PublicKey, certificate::CertType};
use tokio::process::Command;

use crate::{
    credentials::{
        BrokerFailure, CredentialBroker, CredentialLease, CredentialScope, check_private_key_file,
    },
    declarative::CompiledConfig,
    transport::check_public_trust_file,
};

const OPERATION: &str = "builtin.linux.uname/v1";
const PURPOSE: &str = "ssh-observe";
const API_VERSION: &str = "hostmarshal.io/vault-ssh/v1alpha1";
const CERT_MARGIN_SECONDS: u64 = 15;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct VaultSshConfig {
    api_version: String,
    vault_address: String,
    token_file: PathBuf,
    ca_certificate_file: PathBuf,
    ssh_ca_public_key_file: PathBuf,
    mount: String,
    role: String,
    ttl_seconds: u64,
    targets: Vec<VaultTarget>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct VaultTarget {
    target: String,
    principal: String,
}

#[derive(Clone)]
struct TargetBinding {
    principal: String,
}

/// Configured by an OS-authorized launcher, not by YAML Grants or MCP calls.
pub struct VaultSshCertificateBroker {
    client: Client,
    signing_url: Url,
    token_file: PathBuf,
    signing_ca: ssh_key::Fingerprint,
    ttl_seconds: u64,
    bindings: BTreeMap<String, TargetBinding>,
}

#[derive(Deserialize)]
struct SignEnvelope {
    data: Option<SignData>,
}

#[derive(Deserialize)]
struct SignData {
    signed_key: String,
}

fn safe_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

impl VaultSshCertificateBroker {
    pub fn load(path: &Path, config: &CompiledConfig) -> Result<Self> {
        check_private_key_file(path).context("Vault signer config must be protected")?;
        let content = fs::read(path)?;
        ensure!(
            content.len() <= 32 * 1024,
            "Vault signer config exceeds limit"
        );
        let spec: VaultSshConfig = serde_json::from_slice(&content)?;
        ensure!(
            spec.api_version == API_VERSION,
            "unsupported Vault signer configuration"
        );
        ensure!(
            safe_segment(&spec.mount) && safe_segment(&spec.role),
            "invalid Vault SSH mount or role"
        );
        ensure!(
            (30..=300).contains(&spec.ttl_seconds),
            "Vault SSH TTL outside allowed range"
        );
        ensure!(
            !spec.targets.is_empty() && spec.targets.len() <= 128,
            "invalid number of Vault SSH target bindings"
        );

        let url = Url::parse(&spec.vault_address)?;
        ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && (url.path() == "/" || url.path().is_empty()),
            "Vault address must be an HTTPS origin"
        );
        let signing_url = url.join(&format!("v1/{}/sign/{}", spec.mount, spec.role))?;

        check_private_key_file(&spec.token_file).context("Vault token file not protected")?;
        ensure!(
            spec.ca_certificate_file.is_absolute(),
            "Vault TLS CA path must be absolute"
        );
        check_public_trust_file(&spec.ca_certificate_file)
            .context("untrusted Vault TLS CA file")?;
        let tls_pem = fs::read(&spec.ca_certificate_file)?;
        let tls_ca = reqwest::Certificate::from_pem(&tls_pem)?;
        ensure!(
            spec.ssh_ca_public_key_file.is_absolute(),
            "SSH CA path must be absolute"
        );
        check_public_trust_file(&spec.ssh_ca_public_key_file)
            .context("untrusted SSH signing CA file")?;
        let public_ca = PublicKey::read_openssh_file(&spec.ssh_ca_public_key_file)?;
        let signing_ca = public_ca.fingerprint(HashAlg::Sha256);

        let mut bindings = BTreeMap::new();
        for target in spec.targets {
            ensure!(
                safe_segment(&target.target) && safe_segment(&target.principal),
                "invalid Vault SSH target or principal"
            );
            let host = config
                .hosts
                .get(&target.target)
                .context("Vault SSH binding target not in inventory")?;
            ensure!(
                host.spec
                    .ssh
                    .as_ref()
                    .is_some_and(|ssh| ssh.user == target.principal),
                "Vault SSH principal must exactly match trusted inventory SSH user"
            );
            ensure!(
                bindings
                    .insert(
                        target.target,
                        TargetBinding {
                            principal: target.principal
                        }
                    )
                    .is_none(),
                "duplicate Vault SSH target binding"
            );
        }
        let client = Client::builder()
            .https_only(true)
            // Use ONLY the approved Vault TLS CA; platform/public roots are
            // broader than the administrator's pinned signing endpoint.
            .tls_built_in_root_certs(false)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(3))
            .add_root_certificate(tls_ca)
            .user_agent("HostMarshal/0.1")
            .build()?;
        Ok(Self {
            client,
            signing_url,
            token_file: spec.token_file,
            signing_ca,
            ttl_seconds: spec.ttl_seconds,
            bindings,
        })
    }

    async fn sign(
        &self,
        scope: CredentialScope,
        binding: &TargetBinding,
    ) -> Result<CredentialLease, BrokerFailure> {
        // A private 0700 directory and unique short-lived keypair are owned by
        // this future until the lease is returned. Cancellation cleans them up.
        let directory = tempfile::Builder::new()
            .prefix("hostmarshal-vault-")
            .tempdir()
            .map_err(|_| BrokerFailure::Unavailable)?;
        let identity = directory.path().join("id_ed25519");
        let mut keygen = Command::new("/usr/bin/ssh-keygen");
        let status = keygen
            .arg("-q")
            .arg("-t")
            .arg("ed25519")
            .arg("-N")
            .arg("")
            .arg("-f")
            .arg(&identity)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .status()
            .await
            .map_err(|_| BrokerFailure::Unavailable)?;
        if !status.success() {
            return Err(BrokerFailure::Unavailable);
        }
        check_private_key_file(&identity).map_err(|_| BrokerFailure::Unavailable)?;
        let public_path = directory.path().join("id_ed25519.pub");
        let public_string =
            fs::read_to_string(&public_path).map_err(|_| BrokerFailure::Unavailable)?;
        if public_string.len() > 4096 {
            return Err(BrokerFailure::Denied);
        }
        let public_key =
            PublicKey::from_openssh(&public_string).map_err(|_| BrokerFailure::Denied)?;

        // No environment-variable Vault token or forwarded MCP credential:
        // read the protected OS-controlled token file at each issuance for
        // operator-driven rotation; never log token or raw response.
        check_private_key_file(&self.token_file).map_err(|_| BrokerFailure::Unavailable)?;
        let raw_token =
            fs::read_to_string(&self.token_file).map_err(|_| BrokerFailure::Unavailable)?;
        let token = raw_token.trim_end_matches(['\r', '\n']);
        if token.is_empty()
            || token.len() > 4096
            || !token.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(BrokerFailure::Denied);
        }
        let mut token_header = HeaderValue::from_str(token).map_err(|_| BrokerFailure::Denied)?;
        token_header.set_sensitive(true);
        let response = self
            .client
            .post(self.signing_url.clone())
            .header("X-Vault-Token", token_header)
            .json(&json!({
                "public_key": public_string,
                "valid_principals": binding.principal,
                "cert_type": "user",
                "ttl": format!("{}s", self.ttl_seconds),
                "key_id": format!("hostmarshal-{}", scope.target()),
                "extensions": {}
            }))
            .send()
            .await
            .map_err(|_| BrokerFailure::Unavailable)?;
        if !response.status().is_success() {
            return Err(BrokerFailure::Denied);
        }

        let mut response = response;
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| BrokerFailure::Unavailable)?
        {
            if bytes.len().saturating_add(chunk.len()) > 16 * 1024 {
                return Err(BrokerFailure::Denied);
            }
            bytes.extend_from_slice(&chunk);
        }
        let envelope: SignEnvelope =
            serde_json::from_slice(&bytes).map_err(|_| BrokerFailure::Denied)?;
        let signed = envelope.data.ok_or(BrokerFailure::Denied)?.signed_key;
        if signed.len() > 8192 {
            return Err(BrokerFailure::Denied);
        }
        let cert = Certificate::from_openssh(&signed).map_err(|_| BrokerFailure::Denied)?;
        validate_signed_cert(
            &cert,
            &public_key,
            &self.signing_ca,
            &binding.principal,
            self.ttl_seconds,
        )?;
        let expiration = UNIX_EPOCH + Duration::from_secs(cert.valid_before());
        let cert_path = directory.path().join("id_ed25519-cert.pub");
        {
            let mut out = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&cert_path)
                .map_err(|_| BrokerFailure::Unavailable)?;
            out.write_all(signed.as_bytes())
                .map_err(|_| BrokerFailure::Unavailable)?;
            out.write_all(b"\n")
                .map_err(|_| BrokerFailure::Unavailable)?;
        }
        Ok(CredentialLease::new_ephemeral_ssh_certificate(
            scope,
            directory,
            identity,
            cert_path,
            binding.principal.clone(),
            expiration,
        ))
    }
}

fn validate_signed_cert(
    cert: &Certificate,
    public: &PublicKey,
    signing_ca: &ssh_key::Fingerprint,
    principal: &str,
    ttl: u64,
) -> Result<(), BrokerFailure> {
    cert.validate(&[*signing_ca])
        .map_err(|_| BrokerFailure::Denied)?;
    if cert.cert_type() != CertType::User
        || cert.public_key() != public.key_data()
        || cert.valid_principals().len() != 1
        || cert.valid_principals()[0] != principal
        || !cert.critical_options().is_empty()
        || !cert.extensions().is_empty()
    {
        return Err(BrokerFailure::Denied);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BrokerFailure::Denied)?
        .as_secs();
    if cert.valid_before() < now.saturating_add(CERT_MARGIN_SECONDS)
        || cert.valid_before() > now.saturating_add(ttl + 10)
    {
        return Err(BrokerFailure::Denied);
    }
    Ok(())
}

impl CredentialBroker for VaultSshCertificateBroker {
    fn acquire(
        &self,
        scope: CredentialScope,
    ) -> Pin<Box<dyn Future<Output = Result<CredentialLease, BrokerFailure>> + Send + '_>> {
        Box::pin(async move {
            if scope.operation() != OPERATION || scope.purpose() != PURPOSE {
                return Err(BrokerFailure::Denied);
            }
            let Some(binding) = self.bindings.get(scope.target()) else {
                return Err(BrokerFailure::Denied);
            };
            self.sign(scope, binding).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_segments_cannot_select_another_vault_role() {
        for value in [
            "",
            "../ssh",
            "a/b",
            "-role",
            "role%2fother",
            "role?x=1",
            "x\n",
        ] {
            assert!(!safe_segment(value), "{value}");
        }
        for value in ["ssh", "role_01", "host-1"] {
            assert!(safe_segment(value), "{value}");
        }
    }
}
