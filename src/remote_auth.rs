//! Pinned-key JWT access-token verification for the loopback HTTP MCP transport.
//! No token-supplied JWKS URLs, insecure algorithms, header-trust or anonymous fallback.
use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use reqwest::{Client, Url, header::HeaderMap};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::{
    credentials::check_private_key_file, identity::AuthenticatedCaller,
    transport::check_public_trust_file,
};

const MAX_TOKEN_BYTES: usize = 8192;
const MAX_TOKEN_LIFETIME_SECONDS: u64 = 3600;
const CLOCK_SKEW_SECONDS: u64 = 30;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AuthConfigFile {
    api_version: String,
    issuer: String,
    audience: String,
    allowed_host: String,
    jwks_file: Option<String>,
    jwks_url: Option<String>,
    jwks_ca_certificate_file: Option<String>,
    jwks_refresh_seconds: Option<u64>,
    ingress: Option<IngressConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct IngressConfig {
    mode: String,
    public_host: String,
    proof_file: String,
}

struct IngressProof {
    public_host: String,
    digest: [u8; 32],
}

struct OnlineKeys {
    client: Client,
    url: Url,
    refresh: Duration,
    state: Mutex<OnlineState>,
}
struct OnlineState {
    keys: BTreeMap<String, DecodingKey>,
    valid_until: Option<Instant>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JwkFile {
    keys: Vec<RsaPublicKey>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RsaPublicKey {
    kid: String,
    kty: String,
    alg: String,
    #[serde(rename = "use")]
    key_use: String,
    #[serde(default)]
    key_ops: Option<Vec<String>>,
    n: String,
    e: String,
}

#[derive(Debug, Deserialize)]
struct AccessClaims {
    iss: String,
    sub: String,
    exp: u64,
    nbf: u64,
    iat: u64,
    scope: String,
}

pub struct RemoteJwtVerifier {
    issuer: String,
    audience: String,
    allowed_host: String,
    keys: BTreeMap<String, DecodingKey>,
    online: Option<OnlineKeys>,
    ingress: Option<IngressProof>,
    metadata_url: String,
}

impl RemoteJwtVerifier {
    /// The auth file is a protected local administrator configuration; the JWKS
    /// file is an offline pinned public trust bundle, not a remote discovery URL.
    pub fn load(path: &Path) -> Result<Self> {
        check_private_key_file(path)
            .context("remote auth config must be a protected regular file")?;
        let data = fs::read(path)?;
        ensure!(data.len() <= 32 * 1024, "auth configuration too large");
        let config: AuthConfigFile = serde_json::from_slice(&data)?;
        ensure!(
            config.api_version == "hostmarshal.io/remote-auth/v1alpha1",
            "unsupported auth version"
        );
        for (name, uri) in [("issuer", &config.issuer), ("audience", &config.audience)] {
            let parsed = reqwest::Url::parse(uri).with_context(|| format!("invalid {name} URI"))?;
            ensure!(
                parsed.scheme() == "https"
                    && parsed.host_str().is_some()
                    && parsed.username().is_empty()
                    && parsed.password().is_none()
                    && parsed.fragment().is_none(),
                "{name} must be an HTTPS URI without userinfo/fragment"
            );
        }
        ensure!(
            !config.allowed_host.is_empty()
                && config.allowed_host.len() <= 253
                && config
                    .allowed_host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric()
                        || matches!(b, b'.' | b'-' | b':' | b'[' | b']')),
            "invalid allowedHost"
        );
        let (keys, online) = match (config.jwks_file, config.jwks_url) {
            (Some(path), None) => {
                ensure!(
                    config.jwks_ca_certificate_file.is_none()
                        && config.jwks_refresh_seconds.is_none(),
                    "offline JWKS cannot specify online trust fields"
                );
                let file = Path::new(&path);
                ensure!(file.is_absolute(), "jwksFile must be absolute");
                check_public_trust_file(file).context("invalid pinned JWKS file")?;
                let bytes = fs::read(file)?;
                ensure!(bytes.len() <= 32 * 1024, "JWKS exceeds size limit");
                (parse_jwks(&bytes)?, None)
            }
            (None, Some(address)) => {
                let url = Url::parse(&address).context("invalid administrator-pinned jwksUrl")?;
                ensure!(
                    url.scheme() == "https"
                        && url.host_str().is_some()
                        && url.username().is_empty()
                        && url.password().is_none()
                        && url.fragment().is_none()
                        && url.query().is_none()
                        && !url.path().contains(".."),
                    "jwksUrl must be a fixed HTTPS endpoint"
                );
                let refresh = config
                    .jwks_refresh_seconds
                    .context("online JWKS requires jwksRefreshSeconds")?;
                ensure!(
                    (30..=3600).contains(&refresh),
                    "JWKS refresh bounds must be 30–3600 seconds"
                );
                let ca_path = config
                    .jwks_ca_certificate_file
                    .context("online JWKS requires jwksCaCertificateFile")?;
                let ca = Path::new(&ca_path);
                ensure!(ca.is_absolute(), "JWKS CA must use an absolute path");
                check_public_trust_file(ca).context("invalid JWKS pinned TLS CA")?;
                let pem = fs::read(ca)?;
                let root = reqwest::Certificate::from_pem(&pem)?;
                let client = Client::builder()
                    .https_only(true)
                    .tls_built_in_root_certs(false)
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .connect_timeout(Duration::from_secs(2))
                    .timeout(Duration::from_secs(3))
                    .add_root_certificate(root)
                    .user_agent("HostMarshal/0.1")
                    .build()?;
                (
                    BTreeMap::new(),
                    Some(OnlineKeys {
                        client,
                        url,
                        refresh: Duration::from_secs(refresh),
                        state: Mutex::new(OnlineState {
                            keys: BTreeMap::new(),
                            valid_until: None,
                        }),
                    }),
                )
            }
            _ => anyhow::bail!("configure exactly one jwksFile or jwksUrl"),
        };
        let public_url = Url::parse(&config.audience)?;
        ensure!(
            public_url.path() == "/mcp" && public_url.query().is_none(),
            "remote MCP audience must identify the public /mcp resource"
        );
        let metadata_url = public_url
            .join("/.well-known/oauth-protected-resource/mcp")?
            .to_string();
        let ingress = match config.ingress {
            Some(ingress) => {
                ensure!(ingress.mode == "trustedProxy", "unsupported ingress mode");
                let expected_host = public_url.host_str().context("invalid public host")?;
                let expected_host = match public_url.port() {
                    Some(port) => format!("{expected_host}:{port}"),
                    None => expected_host.to_owned(),
                };
                ensure!(
                    ingress.public_host == expected_host,
                    "ingress publicHost must match audience authority"
                );
                let proof_file = Path::new(&ingress.proof_file);
                check_private_key_file(proof_file).context("ingress proof file not protected")?;
                let proof = fs::read(proof_file)?;
                let proof = proof.strip_suffix(b"\n").unwrap_or(&proof);
                ensure!(
                    proof.len() >= 32
                        && proof.len() <= 256
                        && proof.iter().all(u8::is_ascii_graphic),
                    "invalid ingress proof length/characters"
                );
                let digest: [u8; 32] = Sha256::digest(proof).into();
                Some(IngressProof {
                    public_host: ingress.public_host,
                    digest,
                })
            }
            None => None,
        };
        Ok(Self {
            issuer: config.issuer,
            audience: config.audience,
            allowed_host: config.allowed_host,
            keys,
            online,
            ingress,
            metadata_url,
        })
    }

    pub fn allowed_host(&self) -> &str {
        &self.allowed_host
    }

    pub fn resource_metadata_url(&self) -> &str {
        &self.metadata_url
    }

    pub fn resource_metadata(&self) -> serde_json::Value {
        serde_json::json!({
            "resource": self.audience,
            "authorization_servers": [self.issuer],
            "scopes_supported": ["hostmarshal.observe"],
            "bearer_methods_supported": ["header"],
        })
    }

    /// The bearer token NEVER selects a key URL, proxy, issuer, or trust root.
    /// A direct request to loopback cannot satisfy the protected proxy contract.
    pub fn verify_ingress(&self, headers: &HeaderMap) -> bool {
        let Some(ingress) = &self.ingress else {
            return true;
        };
        fn sole<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
            let mut values = headers.get_all(name).iter();
            let first = values.next()?.to_str().ok()?;
            if values.next().is_some() {
                return None;
            }
            Some(first)
        }
        if sole(headers, "x-forwarded-proto") != Some("https")
            || sole(headers, "x-forwarded-host") != Some(&ingress.public_host)
        {
            return false;
        }
        let Some(proof) = sole(headers, "x-hostmarshal-ingress-proof") else {
            return false;
        };
        let actual: [u8; 32] = Sha256::digest(proof.as_bytes()).into();
        let mut diff = 0_u8;
        for (a, b) in actual.iter().zip(&ingress.digest) {
            diff |= a ^ b;
        }
        diff == 0
    }

    pub async fn authenticate_header(&self, authorization: &str) -> Result<AuthenticatedCaller> {
        let token = authorization
            .strip_prefix("Bearer ")
            .ok_or_else(|| anyhow::anyhow!("expected Bearer authorization"))?;
        ensure!(
            !token.is_empty()
                && token.len() <= MAX_TOKEN_BYTES
                && token
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')),
            "invalid bearer token format"
        );
        let header = decode_header(token).context("invalid access token header")?;
        ensure!(header.alg == Algorithm::RS256, "unsupported JWT algorithm");
        ensure!(
            header.typ.as_deref() == Some("at+jwt"),
            "expected an access token"
        );
        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing key ID"))?;
        let key = if let Some(online) = &self.online {
            online.key(kid).await?
        } else {
            self.keys.get(kid).cloned().context("untrusted key ID")?
        };

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.set_required_spec_claims(&["exp", "nbf", "aud", "iss", "sub"]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = CLOCK_SKEW_SECONDS;
        let decoded =
            decode::<AccessClaims>(token, &key, &validation).context("JWT validation failed")?;
        let claims = decoded.claims;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        ensure!(claims.iss == self.issuer, "wrong issuer");
        ensure!(
            !claims.sub.is_empty()
                && claims.sub.len() <= 128
                && claims
                    .sub
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'@')),
            "invalid access token subject"
        );
        ensure!(
            claims.iat <= now.saturating_add(CLOCK_SKEW_SECONDS)
                && claims.nbf <= claims.exp
                && claims.iat <= claims.exp
                && claims.exp.saturating_sub(claims.iat) <= MAX_TOKEN_LIFETIME_SECONDS,
            "invalid access token lifetime"
        );
        ensure!(
            claims
                .scope
                .split_ascii_whitespace()
                .any(|scope| scope == "hostmarshal.observe"),
            "missing required observe scope"
        );
        AuthenticatedCaller::from_verified_jwt(&claims.iss, &claims.sub)
    }
}

fn parse_jwks(bytes: &[u8]) -> Result<BTreeMap<String, DecodingKey>> {
    let jwks: JwkFile = serde_json::from_slice(bytes)?;
    ensure!(
        !jwks.keys.is_empty() && jwks.keys.len() <= 16,
        "invalid JWKS key count"
    );
    let mut keys = BTreeMap::new();
    for jwk in jwks.keys {
        ensure!(
            jwk.kty == "RSA" && jwk.alg == "RS256" && jwk.key_use == "sig",
            "only RSA RS256 signing keys accepted"
        );
        ensure!(
            jwk.key_ops
                .as_ref()
                .is_none_or(|ops| ops.len() == 1 && ops[0] == "verify"),
            "JWKS key operations must be verify-only"
        );
        ensure!(
            !jwk.kid.is_empty()
                && jwk.kid.len() <= 128
                && jwk
                    .kid
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')),
            "invalid JWT key ID"
        );
        let key =
            DecodingKey::from_rsa_components(&jwk.n, &jwk.e).context("invalid pinned RSA key")?;
        ensure!(keys.insert(jwk.kid, key).is_none(), "duplicate JWT key ID");
    }
    Ok(keys)
}

impl OnlineKeys {
    async fn key(&self, kid: &str) -> Result<DecodingKey> {
        let mut state = self.state.lock().await;
        if !state
            .valid_until
            .is_some_and(|until| Instant::now() < until)
        {
            // Refresh is serialized: a failed fetch never extends trust in
            // removed/stale keys, and no stale-on-error fallback is enabled.
            state.valid_until = None;
            let response = self.client.get(self.url.clone()).send().await?;
            ensure!(
                response.status().is_success() && response.url() == &self.url,
                "untrusted JWKS response or redirect"
            );
            let mut response = response;
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                ensure!(
                    bytes.len().saturating_add(chunk.len()) <= 32 * 1024,
                    "online JWKS exceeds limit"
                );
                bytes.extend_from_slice(&chunk);
            }
            let next = parse_jwks(&bytes)?;
            state.keys = next;
            state.valid_until = Some(Instant::now() + self.refresh);
        }
        state
            .keys
            .get(kid)
            .cloned()
            .context("untrusted or rotated JWT key ID")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn empty_or_non_bearer_header_is_rejected_without_key_access() {
        let verifier = RemoteJwtVerifier {
            issuer: "https://issuer.example.invalid/".to_owned(),
            audience: "https://mcp.example.invalid/mcp".to_owned(),
            allowed_host: "127.0.0.1:7878".to_owned(),
            keys: BTreeMap::new(),
            online: None,
            ingress: None,
            metadata_url: "https://mcp.example.invalid/.well-known/oauth-protected-resource/mcp"
                .to_owned(),
        };
        for header in ["", "Basic anything", "Bearer ", "Bearer a/b", "bearer abc"] {
            assert!(verifier.authenticate_header(header).await.is_err());
        }
    }
}
