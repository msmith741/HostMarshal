//! Pinned-key JWT access-token verification for the loopback HTTP MCP transport.
//! No token-supplied JWKS URLs, insecure algorithms, header-trust or anonymous fallback.
use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;

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
    jwks_file: String,
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
        let jwks_path = Path::new(&config.jwks_file);
        ensure!(jwks_path.is_absolute(), "jwksFile must be an absolute path");
        check_public_trust_file(jwks_path).context("invalid pinned JWKS file")?;
        let bytes = fs::read(jwks_path)?;
        let jwks: JwkFile = serde_json::from_slice(&bytes)?;
        ensure!(
            !jwks.keys.is_empty() && jwks.keys.len() <= 16,
            "invalid pinned JWKS key count"
        );
        let mut keys = BTreeMap::new();
        for jwk in jwks.keys {
            ensure!(
                jwk.kty == "RSA" && jwk.alg == "RS256" && jwk.key_use == "sig",
                "only RSA RS256 signing keys are accepted"
            );
            ensure!(
                jwk.key_ops.as_ref().is_none_or(|operations| {
                    operations.len() == 1 && operations[0] == "verify"
                }),
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
            let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
                .context("invalid pinned RSA key")?;
            ensure!(keys.insert(jwk.kid, key).is_none(), "duplicate JWT key ID");
        }
        Ok(Self {
            issuer: config.issuer,
            audience: config.audience,
            allowed_host: config.allowed_host,
            keys,
        })
    }

    pub fn allowed_host(&self) -> &str {
        &self.allowed_host
    }

    pub fn authenticate_header(&self, authorization: &str) -> Result<AuthenticatedCaller> {
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
        let key = self
            .keys
            .get(kid)
            .ok_or_else(|| anyhow::anyhow!("untrusted key ID"))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.set_required_spec_claims(&["exp", "nbf", "aud", "iss", "sub"]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = CLOCK_SKEW_SECONDS;
        let decoded =
            decode::<AccessClaims>(token, key, &validation).context("JWT validation failed")?;
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_or_non_bearer_header_is_rejected_without_key_access() {
        let verifier = RemoteJwtVerifier {
            issuer: "https://issuer.example.invalid/".to_owned(),
            audience: "https://mcp.example.invalid/mcp".to_owned(),
            allowed_host: "127.0.0.1:7878".to_owned(),
            keys: BTreeMap::new(),
        };
        for header in ["", "Basic anything", "Bearer ", "Bearer a/b", "bearer abc"] {
            assert!(verifier.authenticate_header(header).is_err());
        }
    }
}
