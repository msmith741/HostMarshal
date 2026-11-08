//! Optional AppRole and externally issued workload JWT authentication for
//! the restricted M4 Vault SSH signer. Vault validates JWT signatures,
//! issuer/audience and bound role; HostMarshal validates the leased token.
//! Never infer a Vault endpoint, JWT source or role from an MCP request.
use crate::credentials::{BrokerFailure, check_private_key_file};
use anyhow::{Context, Result, ensure};
use reqwest::{Client, Url, header::HeaderValue};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex as StdMutex, Weak},
    time::{Duration, Instant},
};
use tokio::{sync::Mutex, task::JoinHandle, time::sleep_until};
use zeroize::{Zeroize, Zeroizing};

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct AppRoleSpec {
    pub auth_mount: String,
    pub role_id_file: PathBuf,
    pub secret_id_file: PathBuf,
    pub expected_policy: String,
    pub renew_before_seconds: u64,
    /// Optional operator-only, read-only epoch marker. New counter enables
    /// ONE fresh login after quarantine; never an automatic retry.
    pub recovery_epoch_file: Option<PathBuf>,
}

/// Issued by an administrator-approved external workload identity provider.
/// Vault's JWT auth method must independently verify signed token identity,
/// exact issuer, bound audience and subject before minting a Vault lease.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct JwtAuthSpec {
    pub auth_mount: String,
    pub role: String,
    pub jwt_file: PathBuf,
    pub expected_policy: String,
    pub renew_before_seconds: u64,
    pub recovery_epoch_file: Option<PathBuf>,
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
    /// Proactive renewal is scheduled at the configured threshold but never
    /// earlier than one third of the issued TTL (prevents tight renew loops
    /// for legacy renewBeforeSeconds > the Vault TTL).
    maintain_at: Instant,
}
impl Active {
    fn from_lease(lease: &Lease, before: Duration) -> Self {
        let now = Instant::now();
        let ttl = Duration::from_secs(lease.lease_duration);
        let delay = ttl.saturating_sub(before).max(ttl / 3);
        Self {
            token: Zeroizing::new(lease.client_token.clone()),
            expires: now + ttl,
            maintain_at: now + delay,
        }
    }
}
enum State {
    Cold,
    Active(Active),
    /// The recovery epoch is observed at the moment of quarantine.
    /// No marker or unreadable marker means restart-only recovery.
    Quarantined(Option<u64>),
}
struct LeaseLifecycle {
    state: Arc<Mutex<State>>,
    policy: String,
    renew_url: Url,
    renew_before: Duration,
    recovery_epoch_file: Option<PathBuf>,
    worker: StdMutex<Option<JoinHandle<()>>>,
}
impl Drop for LeaseLifecycle {
    fn drop(&mut self) {
        if let Ok(mut handle) = self.worker.lock() {
            if let Some(task) = handle.take() {
                task.abort();
            }
        }
    }
}
pub(crate) struct AppRole {
    login_url: Url,
    role_id: PathBuf,
    secret_id: PathBuf,
    lifecycle: Arc<LeaseLifecycle>,
}
pub(crate) struct JwtWorkload {
    login_url: Url,
    role: String,
    jwt_file: PathBuf,
    lifecycle: Arc<LeaseLifecycle>,
}
pub(crate) enum VaultAuth {
    File(PathBuf),
    AppRole(Box<AppRole>),
    Jwt(Box<JwtWorkload>),
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
#[derive(Serialize)]
struct JwtLogin<'a> {
    role: &'a str,
    jwt: &'a str,
}

/// A JWT source is an explicit protected file or a Kubernetes-style projected
/// "token -> ..data/token" symlink. The latter MUST resolve within the same
/// trusted mount, which supports atomic kubelet rotation without accepting an
/// arbitrary symlink or outside-the-mount secret.
fn check_workload_jwt(path: &Path) -> std::io::Result<()> {
    use std::io::Error;
    if !path.is_absolute() {
        return Err(Error::other("workload JWT path must be absolute"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| Error::other("workload JWT has no parent directory"))?;
    let root = fs::canonicalize(parent)?;
    let parent_meta = fs::metadata(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if parent_meta.permissions().mode() & 0o022 != 0 {
            return Err(Error::other(
                "workload JWT parent is writable by other principals",
            ));
        }
    }
    let link = fs::symlink_metadata(path)?;
    if link.file_type().is_symlink() {
        let filename = path
            .file_name()
            .ok_or_else(|| Error::other("invalid projected JWT filename"))?;
        // The Kubernetes atomic projected-volume convention is intentionally
        // narrow; a direct regular file is allowed for non-Kubernetes runtimes.
        if fs::read_link(path)? != Path::new("..data").join(filename) {
            return Err(Error::other("untrusted JWT symlink target"));
        }
    } else if !link.file_type().is_file() {
        return Err(Error::other("workload JWT is not a regular file"));
    }
    let resolved = fs::canonicalize(path)?;
    if !resolved.starts_with(root) {
        return Err(Error::other("workload JWT escapes its mounted directory"));
    }
    let meta = fs::metadata(path)?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > 8192 {
        return Err(Error::other("invalid workload JWT file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o027 != 0 {
            return Err(Error::other("workload JWT permissions too broad"));
        }
    }
    Ok(())
}

fn workload_jwt(path: &Path) -> Result<Zeroizing<String>, BrokerFailure> {
    check_workload_jwt(path).map_err(|_| BrokerFailure::Unavailable)?;
    let raw = Zeroizing::new(fs::read_to_string(path).map_err(|_| BrokerFailure::Unavailable)?);
    let jwt = raw.trim_end_matches(['\r', '\n']);
    if jwt.is_empty()
        || jwt.len() > 8192
        || jwt.split('.').count() != 3
        || !jwt
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(BrokerFailure::Denied);
    }
    Ok(Zeroizing::new(jwt.to_owned()))
}

fn secret(path: &PathBuf) -> Result<Zeroizing<String>, BrokerFailure> {
    check_private_key_file(path).map_err(|_| BrokerFailure::Unavailable)?;
    let raw = Zeroizing::new(fs::read_to_string(path).map_err(|_| BrokerFailure::Unavailable)?);
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
    // Avoid retaining bearer-token JSON in freed heap memory after parsing.
    let mut bytes = Zeroizing::new(Vec::new());
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
/// Operator-owned counter used ONLY for release from sticky quarantine.
/// This is not an authentication credential, and a changed epoch never bypasses
/// Vault policy, issuer or SSH certificate verification.
fn recovery_epoch(path: &Path) -> Result<u64> {
    use anyhow::{Context, bail};
    let metadata = fs::symlink_metadata(path).context("recovery epoch cannot be inspected")?;
    ensure!(
        path.is_absolute() && metadata.file_type().is_file() && metadata.len() <= 20,
        "recovery epoch must be an absolute, small regular file"
    );
    let parent = fs::metadata(path.parent().context("invalid recovery marker parent")?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o222 == 0 && parent.permissions().mode() & 0o022 == 0,
            "recovery epoch must be read-only with a protected parent"
        );
    }
    let content = fs::read_to_string(path).context("recovery epoch unreadable")?;
    let value = content.trim_end_matches(['\n', '\r']);
    if value.is_empty()
        || value.len() > 20
        || (value.starts_with('0') && value != "0")
        || !value.bytes().all(|c| c.is_ascii_digit())
    {
        bail!("invalid recovery epoch format");
    }
    value.parse::<u64>().context("invalid recovery epoch value")
}

fn observed_epoch(path: Option<&PathBuf>) -> Option<u64> {
    path.and_then(|file| recovery_epoch(file).ok())
}

async fn renew_active(
    client: &Client,
    url: &Url,
    policy: &str,
    before: Duration,
    active: Active,
) -> Result<Active, BrokerFailure> {
    if active.expires <= Instant::now() {
        return Err(BrokerFailure::Denied);
    }
    let response = client
        .post(url.clone())
        .header("X-Vault-Token", header(&active.token)?)
        .json(&serde_json::json!({}))
        .send()
        .await
        .map_err(|_| BrokerFailure::Unavailable)?;
    let lease = read(response, policy).await?;
    if lease.client_token != *active.token {
        return Err(BrokerFailure::Denied);
    }
    Ok(Active::from_lease(&lease, before))
}

impl LeaseLifecycle {
    fn load(
        renew_url: Url,
        policy: String,
        renew_before: Duration,
        recovery_epoch_file: Option<PathBuf>,
    ) -> Result<Arc<Self>> {
        if let Some(path) = &recovery_epoch_file {
            recovery_epoch(path).context("invalid administrator recovery epoch")?;
        }
        Ok(Arc::new(Self {
            state: Arc::new(Mutex::new(State::Cold)),
            policy,
            renew_url,
            renew_before,
            recovery_epoch_file,
            worker: StdMutex::new(None),
        }))
    }

    fn quarantined(&self) -> State {
        State::Quarantined(observed_epoch(self.recovery_epoch_file.as_ref()))
    }

    async fn acquire<F>(
        self: &Arc<Self>,
        client: &Client,
        login: F,
    ) -> Result<HeaderValue, BrokerFailure>
    where
        F: std::future::Future<Output = Result<Active, BrokerFailure>>,
    {
        let mut state = self.state.lock().await;
        let old = std::mem::replace(&mut *state, self.quarantined());
        let active = match old {
            State::Cold => login.await?,
            State::Quarantined(previous) => {
                let current = observed_epoch(self.recovery_epoch_file.as_ref());
                if !matches!((previous, current), (Some(old), Some(new)) if new > old) {
                    return Err(BrokerFailure::Denied);
                }
                // The marker was already consumed by the replacement state.
                // Failure of the new login requires ANOTHER operator increment.
                login.await?
            }
            State::Active(active) => {
                if active.expires <= Instant::now() {
                    return Err(BrokerFailure::Denied);
                }
                if active.expires.saturating_duration_since(Instant::now()) <= self.renew_before {
                    renew_active(
                        client,
                        &self.renew_url,
                        &self.policy,
                        self.renew_before,
                        active,
                    )
                    .await?
                } else {
                    active
                }
            }
        };
        let value = header(&active.token)?;
        *state = State::Active(active);
        self.start_worker(client.clone())?;
        Ok(value)
    }

    fn start_worker(self: &Arc<Self>, client: Client) -> Result<(), BrokerFailure> {
        let mut slot = self.worker.lock().map_err(|_| BrokerFailure::Unavailable)?;
        if slot.as_ref().is_some_and(|worker| !worker.is_finished()) {
            return Ok(());
        }
        let weak: Weak<Self> = Arc::downgrade(self);
        *slot = Some(tokio::spawn(async move {
            loop {
                let Some(owner) = weak.upgrade() else {
                    return;
                };
                let next = {
                    let state = owner.state.lock().await;
                    match &*state {
                        State::Active(active) => active.maintain_at,
                        _ => return,
                    }
                };
                drop(owner);
                sleep_until(next.into()).await;

                let Some(owner) = weak.upgrade() else {
                    return;
                };
                let mut state = owner.state.lock().await;
                let old = std::mem::replace(&mut *state, owner.quarantined());
                let active = match old {
                    State::Active(active) if active.expires <= Instant::now() => return,
                    State::Active(active) if active.maintain_at <= Instant::now() => {
                        match renew_active(
                            &client,
                            &owner.renew_url,
                            &owner.policy,
                            owner.renew_before,
                            active,
                        )
                        .await
                        {
                            Ok(renewed) => renewed,
                            Err(_) => return, // sticky quarantine, no retry
                        }
                    }
                    State::Active(active) => active, // foreground renewed already
                    _ => return,
                };
                *state = State::Active(active);
            }
        }));
        Ok(())
    }

    async fn quarantine(&self) {
        *self.state.lock().await = self.quarantined();
    }
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
        let lease = read(response, &self.lifecycle.policy).await?;
        Ok(Active::from_lease(&lease, self.lifecycle.renew_before))
    }
}

impl JwtWorkload {
    async fn login(&self, client: &Client) -> Result<Active, BrokerFailure> {
        let jwt = workload_jwt(&self.jwt_file)?;
        let response = client
            .post(self.login_url.clone())
            .json(&JwtLogin {
                role: &self.role,
                jwt: &jwt,
            })
            .send()
            .await
            .map_err(|_| BrokerFailure::Unavailable)?;
        let lease = read(response, &self.lifecycle.policy).await?;
        Ok(Active::from_lease(&lease, self.lifecycle.renew_before))
    }
}

impl VaultAuth {
    pub(crate) fn load(
        origin: &Url,
        token_file: Option<PathBuf>,
        app_role: Option<AppRoleSpec>,
        jwt_auth: Option<JwtAuthSpec>,
    ) -> Result<Self> {
        ensure!(
            usize::from(token_file.is_some())
                + usize::from(app_role.is_some())
                + usize::from(jwt_auth.is_some())
                == 1,
            "choose exactly one Vault tokenFile, appRole or jwtAuth authentication source"
        );
        if let Some(path) = token_file {
            check_private_key_file(&path).context("Vault token file not protected")?;
            return Ok(Self::File(path));
        }
        if let Some(cfg) = jwt_auth {
            ensure!(
                segment(&cfg.auth_mount) && segment(&cfg.role) && segment(&cfg.expected_policy),
                "invalid Vault JWT auth mount, role or policy"
            );
            ensure!(
                (15..=3600).contains(&cfg.renew_before_seconds),
                "invalid JWT renewal threshold"
            );
            check_workload_jwt(&cfg.jwt_file).context("workload JWT source not protected")?;
            return Ok(Self::Jwt(Box::new(JwtWorkload {
                login_url: origin.join(&format!("v1/auth/{}/login", cfg.auth_mount))?,
                role: cfg.role,
                jwt_file: cfg.jwt_file,
                lifecycle: LeaseLifecycle::load(
                    origin.join("v1/auth/token/renew-self")?,
                    cfg.expected_policy,
                    Duration::from_secs(cfg.renew_before_seconds),
                    cfg.recovery_epoch_file,
                )?,
            })));
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
        Ok(Self::AppRole(Box::new(AppRole {
            login_url: origin.join(&format!("v1/auth/{}/login", cfg.auth_mount))?,
            role_id: cfg.role_id_file,
            secret_id: cfg.secret_id_file,
            lifecycle: LeaseLifecycle::load(
                origin.join("v1/auth/token/renew-self")?,
                cfg.expected_policy,
                Duration::from_secs(cfg.renew_before_seconds),
                cfg.recovery_epoch_file,
            )?,
        })))
    }
    pub(crate) async fn token(&self, client: &Client) -> Result<HeaderValue, BrokerFailure> {
        match self {
            Self::File(path) => header(&secret(path)?),
            Self::AppRole(a) => a.lifecycle.acquire(client, a.login(client)).await,
            Self::Jwt(jwt) => jwt.lifecycle.acquire(client, jwt.login(client)).await,
        }
    }
    pub(crate) async fn quarantine(&self) {
        match self {
            Self::File(_) => (),
            Self::AppRole(role) => role.lifecycle.quarantine().await,
            Self::Jwt(jwt) => jwt.lifecycle.quarantine().await,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn jwt_source_requires_regular_protected_file_or_bounded_projection() {
        use std::fs;
        let tmp = tempfile::tempdir().unwrap();
        let plain = tmp.path().join("token");
        fs::write(&plain, "test.jwt.payload").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt, symlink};
            fs::set_permissions(&plain, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(check_workload_jwt(&plain).is_ok());
            let outside = tmp.path().join("untrusted");
            symlink("token", &outside).unwrap();
            assert!(check_workload_jwt(&outside).is_err());
            fs::set_permissions(&plain, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(check_workload_jwt(&plain).is_err());
            fs::set_permissions(&plain, fs::Permissions::from_mode(0o600)).unwrap();
            let projection = tmp.path().join("projected");
            fs::create_dir(&projection).unwrap();
            fs::create_dir(projection.join("..2026_11_08")).unwrap();
            let secret = projection.join("..2026_11_08/token");
            fs::write(&secret, "test.jwt.payload").unwrap();
            fs::set_permissions(&secret, fs::Permissions::from_mode(0o440)).unwrap();
            symlink("..2026_11_08", projection.join("..data")).unwrap();
            symlink("..data/token", projection.join("token")).unwrap();
            assert!(check_workload_jwt(&projection.join("token")).is_ok());
            fs::remove_file(projection.join("..data")).unwrap();
            symlink(tmp.path(), projection.join("..data")).unwrap();
            assert!(check_workload_jwt(&projection.join("token")).is_err());
        }
    }
    #[test]
    fn recovery_epoch_requires_protected_regular_monotonic_counter() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("epoch");
        fs::write(&path, "4\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt, symlink};
            fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
            assert_eq!(recovery_epoch(&path).unwrap(), 4);
            let link = dir.path().join("alias");
            symlink("epoch", &link).unwrap();
            assert!(recovery_epoch(&link).is_err());
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(recovery_epoch(&path).is_err());
            fs::write(&path, "04\n").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
            assert!(recovery_epoch(&path).is_err());
        }
    }

    #[test]
    fn proactive_schedule_has_minimum_ttl_fraction() {
        let lease = Lease {
            client_token: "opaque".into(),
            renewable: true,
            lease_duration: 30,
            policies: vec![],
            token_policies: vec![],
            identity_policies: vec![],
        };
        let active = Active::from_lease(&lease, Duration::from_secs(300));
        let delay = active.maintain_at.saturating_duration_since(Instant::now());
        assert!(delay >= Duration::from_secs(9));
        assert!(delay <= Duration::from_secs(11));
        assert!(active.maintain_at < active.expires);
    }

    #[test]
    fn rejects_unsafe_mounts() {
        for s in ["", "../bad", "a/b", "a%2fb", "-a", "a?x=1"] {
            assert!(!segment(s));
        }
    }
}
