//! M4 verified OAuth JWT access-token resource-server subset (FR-018).
//! External authorization servers issue tokens; HostMarshal never issues tokens.
use std::{
    collections::{BTreeMap, HashSet},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, ensure};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use url::Url;

use crate::{identity::AuthenticatedCaller, transport::check_public_trust_file};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JwkSet {
    keys: Vec<PublicRsaKey>,
}

#[derive(Debug, Deserialize)]
struct PublicRsaKey {
    kid: String,
    kty: String,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default, rename = "use")]
    key_use: Option<String>,
    n: String,
    e: String,
}

#[derive(Debug, Deserialize)]
struct AccessClaims {
    iss: String,
    sub: String,
    exp: u64,
    iat: u64,
    #[serde(default)]
    nbf: Option<u64>,
    scope: String,
}

pub struct JwtVerifier {
    issuer: String,
    resource: String,
    metadata_uri: String,
    keys: BTreeMap<String, DecodingKey>,
}

impl JwtVerifier {
    pub fn load(issuer: &str, resource: &str, jwks_path: &Path) -> Result<Self> {
        ensure!(
            crate::identity::valid_remote_issuer(issuer),
            "issuer must be a fixed HTTPS URL"
        );
        let url = Url::parse(resource)?;
        ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.path().ends_with("/mcp"),
            "resource URL must be an HTTPS MCP endpoint"
        );
        ensure!(resource.len() <= 512, "resource URL too long");
        check_public_trust_file(jwks_path)?;
        let bytes = std::fs::read(jwks_path)?;
        let jwks: JwkSet = serde_json::from_slice(&bytes)?;
        ensure!(
            !jwks.keys.is_empty() && jwks.keys.len() <= 16,
            "invalid JWKS key count"
        );
        let mut keys = BTreeMap::new();
        for jwk in jwks.keys {
            ensure!(
                jwk.kid.len() <= 128
                    && !jwk.kid.is_empty()
                    && jwk
                        .kid
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')),
                "invalid JWT key id"
            );
            ensure!(jwk.kty == "RSA", "JWT key must use RSA");
            ensure!(
                jwk.alg.as_deref().is_none_or(|alg| alg == "RS256"),
                "unsupported JWT key algorithm"
            );
            ensure!(
                jwk.key_use
                    .as_deref()
                    .is_none_or(|purpose| purpose == "sig"),
                "JWT key not valid for signature use"
            );
            let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)?;
            ensure!(keys.insert(jwk.kid, key).is_none(), "duplicate JWT key id");
        }
        let authority = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("missing resource host"))?;
        let metadata_uri = format!(
            "https://{authority}{}{}",
            url.port()
                .map_or_else(String::new, |port| format!(":{port}")),
            "/.well-known/oauth-protected-resource"
        );
        Ok(Self {
            issuer: issuer.to_owned(),
            resource: resource.to_owned(),
            metadata_uri,
            keys,
        })
    }

    pub fn metadata_uri(&self) -> &str {
        &self.metadata_uri
    }
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn resource(&self) -> &str {
        &self.resource
    }

    pub fn authenticate(&self, token: &str) -> Result<AuthenticatedCaller> {
        ensure!(
            token.len() <= 8192 && token.matches('.').count() == 2,
            "invalid access token"
        );
        let header = decode_header(token)?;
        ensure!(
            header.alg == Algorithm::RS256,
            "unsupported signature algorithm"
        );
        ensure!(
            header.typ.as_deref() == Some("at+jwt"),
            "access token type required"
        );
        let kid = header
            .kid
            .ok_or_else(|| anyhow::anyhow!("missing key id"))?;
        let key = self
            .keys
            .get(&kid)
            .ok_or_else(|| anyhow::anyhow!("unknown key"))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.resource.as_str()]);
        validation.leeway = 0;
        validation.required_spec_claims = HashSet::from([
            "exp".into(),
            "iat".into(),
            "iss".into(),
            "sub".into(),
            "aud".into(),
        ]);
        let claims = decode::<AccessClaims>(token, key, &validation)?.claims;
        ensure!(claims.iss == self.issuer, "issuer mismatch");
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        ensure!(
            claims.iat <= now && claims.exp > now,
            "invalid token lifetime"
        );
        ensure!(
            claims.exp.saturating_sub(claims.iat) <= 600,
            "access token lifetime exceeds 10 minutes"
        );
        ensure!(
            claims.nbf.is_none_or(|not_before| not_before <= now),
            "token not active"
        );
        ensure!(
            claims
                .scope
                .split_ascii_whitespace()
                .any(|scope| scope == "hostmarshal:observe"),
            "missing resource scope"
        );
        AuthenticatedCaller::from_verified_access_token(&claims.iss, &claims.sub)
    }

    pub fn metadata(&self) -> serde_json::Value {
        serde_json::json!({
            "resource": self.resource,
            "authorization_servers": [self.issuer],
            "scopes_supported": ["hostmarshal:observe"]
        })
    }

    pub fn challenge(&self) -> String {
        format!(
            "Bearer realm=\"hostmarshal\", resource_metadata=\"{}\", scope=\"hostmarshal:observe\"",
            self.metadata_uri
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_resource_configuration_is_rejected_before_listener_starts() {
        let temp = std::env::temp_dir().join("no-such-hostmarshal-jwks");
        assert!(
            JwtVerifier::load("https://issuer.example.invalid", "http://host/mcp", &temp).is_err()
        );
        assert!(
            JwtVerifier::load("http://issuer.example.invalid", "https://host/mcp", &temp).is_err()
        );
    }
}
