//! AppRole credentials for the restricted M4 Vault SSH signer.
//! Never infer a Vault endpoint or principal from an MCP request.
use crate::credentials::{BrokerFailure, check_private_key_file};
use anyhow::{Context, Result, ensure};
use reqwest::{Client, Url, header::HeaderValue};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct AppRoleSpec {
    pub auth_mount: String,
    pub role_id_file: PathBuf,
    pub secret_id_file: PathBuf,
    pub expected_policy: String,
    pub renew_before_seconds: u64,
}

fn segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
struct Active {
    token: Zeroizing<String>,
    expires: Instant,
}
enum State {
    Cold,
    Active(Active),
    Quarantined,
}
pub(crate) struct AppRole {
    login_url: Url,
    renew_url: Url,
    role_id: PathBuf,
    secret_id: PathBuf,
    policy: String,
    renew_before: Duration,
    state: Mutex<State>,
}
pub(crate) enum VaultAuth {
    File(PathBuf),
    AppRole(AppRole),
}

#[derive(Deserialize)]
struct Envelope {
    auth: Option<Lease>,
}
#[derive(Deserialize)]
struct Lease {
    client_token: String,
    renewable: bool,
    lease_duration: u64,
    #[serde(default)]
    policies: Vec<String>,
    #[serde(default)]
    token_policies: Vec<String>,
    #[serde(default)]
    identity_policies: Vec<String>,
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.client_token.zeroize();
    }
}
#[derive(Serialize)]
struct Login<'a> {
    role_id: &'a str,
    secret_id: &'a str,
}

fn secret(path: &PathBuf) -> Result<Zeroizing<String>, BrokerFailure> {
    check_private_key_file(path).map_err(|_| BrokerFailure::Unavailable)?;
    let raw = fs::read_to_string(path).map_err(|_| BrokerFailure::Unavailable)?;
    let value = raw.trim_end_matches(['\r', '\n']);
    if value.is_empty() || value.len() > 4096 || !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(BrokerFailure::Denied);
    }
    Ok(Zeroizing::new(value.to_owned()))
}
fn header(token: &str) -> Result<HeaderValue, BrokerFailure> {
    if token.is_empty() || token.len() > 4096 || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(BrokerFailure::Denied);
    }
    let mut result = HeaderValue::from_str(token).map_err(|_| BrokerFailure::Denied)?;
    result.set_sensitive(true);
    Ok(result)
}
async fn read(response: reqwest::Response, policy: &str) -> Result<Lease, BrokerFailure> {
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
        if bytes.len().saturating_add(chunk.len()) > 8192 {
            return Err(BrokerFailure::Denied);
        }
        bytes.extend_from_slice(&chunk);
    }
    let lease = serde_json::from_slice::<Envelope>(&bytes)
        .map_err(|_| BrokerFailure::Denied)?
        .auth
        .ok_or(BrokerFailure::Denied)?;
    let policies = if lease.token_policies.is_empty() {
        &lease.policies
    } else {
        &lease.token_policies
    };
    if !lease.renewable
        || !(30..=3600).contains(&lease.lease_duration)
        || policies.len() != 1
        || policies[0] != policy
        || (!lease.policies.is_empty() && lease.policies != *policies)
        || !lease.identity_policies.is_empty()
    {
        return Err(BrokerFailure::Denied);
    }
    header(&lease.client_token)?;
    Ok(lease)
}
impl AppRole {
    async fn login(&self, client: &Client) -> Result<Active, BrokerFailure> {
        let role_id = secret(&self.role_id)?;
        let secret_id = secret(&self.secret_id)?;
        let response = client
            .post(self.login_url.clone())
            .json(&Login {
                role_id: &role_id,
                secret_id: &secret_id,
            })
            .send()
            .await
            .map_err(|_| BrokerFailure::Unavailable)?;
        let lease = read(response, &self.policy).await?;
        Ok(Active {
            token: Zeroizing::new(lease.client_token.clone()),
            expires: Instant::now() + Duration::from_secs(lease.lease_duration),
        })
    }
    async fn renew(&self, client: &Client, active: Active) -> Result<Active, BrokerFailure> {
        if active.expires <= Instant::now() {
            return Err(BrokerFailure::Denied);
        }
        let response = client
            .post(self.renew_url.clone())
            .header("X-Vault-Token", header(&active.token)?)
            .json(&serde_json::json!({}))
            .send()
            .await
            .map_err(|_| BrokerFailure::Unavailable)?;
        let lease = read(response, &self.policy).await?;
        if lease.client_token != *active.token {
            return Err(BrokerFailure::Denied);
        }
        Ok(Active {
            token: active.token,
            expires: Instant::now() + Duration::from_secs(lease.lease_duration),
        })
    }
    async fn token(&self, client: &Client) -> Result<HeaderValue, BrokerFailure> {
        // Serialize token state transitions; denial/outage leaves Quarantined.
        // Never automatically re-login after an invalidated active token.
        let mut state = self.state.lock().await;
        let old = std::mem::replace(&mut *state, State::Quarantined);
        let active = match old {
            State::Cold => self.login(client).await?,
            State::Quarantined => return Err(BrokerFailure::Denied),
            State::Active(active) => {
                if active.expires <= Instant::now() {
                    return Err(BrokerFailure::Denied);
                }
                if active.expires.saturating_duration_since(Instant::now()) <= self.renew_before {
                    self.renew(client, active).await?
                } else {
                    active
                }
            }
        };
        let token = header(&active.token)?;
        *state = State::Active(active);
        Ok(token)
    }
}
impl VaultAuth {
    pub(crate) fn load(
        origin: &Url,
        token_file: Option<PathBuf>,
        app_role: Option<AppRoleSpec>,
    ) -> Result<Self> {
        ensure!(
            token_file.is_some() != app_role.is_some(),
            "choose exactly one Vault tokenFile or appRole authentication source"
        );
        if let Some(path) = token_file {
            check_private_key_file(&path).context("Vault token file not protected")?;
            return Ok(Self::File(path));
        }
        let cfg = app_role.expect("validated exclusive auth source");
        ensure!(
            segment(&cfg.auth_mount) && segment(&cfg.expected_policy),
            "invalid Vault AppRole mount or policy"
        );
        ensure!(
            (15..=3600).contains(&cfg.renew_before_seconds),
            "invalid renewal threshold"
        );
        ensure!(
            cfg.role_id_file != cfg.secret_id_file,
            "AppRole credentials must be separate"
        );
        check_private_key_file(&cfg.role_id_file).context("AppRole RoleID not protected")?;
        check_private_key_file(&cfg.secret_id_file).context("AppRole SecretID not protected")?;
        Ok(Self::AppRole(AppRole {
            login_url: origin.join(&format!("v1/auth/{}/login", cfg.auth_mount))?,
            renew_url: origin.join("v1/auth/token/renew-self")?,
            role_id: cfg.role_id_file,
            secret_id: cfg.secret_id_file,
            policy: cfg.expected_policy,
            renew_before: Duration::from_secs(cfg.renew_before_seconds),
            state: Mutex::new(State::Cold),
        }))
    }
    pub(crate) async fn token(&self, client: &Client) -> Result<HeaderValue, BrokerFailure> {
        match self {
            Self::File(path) => header(&secret(path)?),
            Self::AppRole(a) => a.token(client).await,
        }
    }
    pub(crate) async fn quarantine(&self) {
        if let Self::AppRole(role) = self {
            *role.state.lock().await = State::Quarantined;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unsafe_mounts() {
        for s in ["", "../bad", "a/b", "a%2fb", "-a", "a?x=1"] {
            assert!(!segment(s));
        }
    }
}
