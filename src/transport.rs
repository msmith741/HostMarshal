//! Fixed, typed transport settings from trusted inventory.
//! Strings from MCP arguments NEVER become network destinations or commands.
use std::{net::IpAddr, path::Path};

use anyhow::{Result, ensure};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SshEndpoint {
    pub user: String,
    pub port: u16,
    pub known_hosts_file: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HttpsEndpoint {
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_certificate_file: Option<String>,
}

pub fn valid_host_address(address: &str) -> bool {
    if address.parse::<IpAddr>().is_ok() {
        return true;
    }
    if address.is_empty() || address.len() > 253 || address.starts_with('-') {
        return false;
    }
    address.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

fn valid_username(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 32
        && user
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
        && !user.starts_with('-')
}

pub fn validate_transport(
    address: &str,
    ssh: Option<&SshEndpoint>,
    https: Option<&HttpsEndpoint>,
) -> Result<()> {
    if ssh.is_none() && https.is_none() {
        return Ok(());
    }
    ensure!(
        valid_host_address(address),
        "invalid network target address"
    );
    if let Some(ssh) = ssh {
        ensure!(ssh.port != 0, "SSH port must be nonzero");
        ensure!(valid_username(&ssh.user), "invalid SSH username");
        ensure!(
            Path::new(&ssh.known_hosts_file).is_absolute(),
            "SSH knownHostsFile must be an absolute path"
        );
    }
    if let Some(https) = https {
        ensure!(https.port != 0, "HTTPS port must be nonzero");
        if let Some(path) = &https.ca_certificate_file {
            ensure!(
                Path::new(path).is_absolute(),
                "HTTPS CA file must use an absolute path"
            );
        }
    }
    Ok(())
}

/// Used before passing public key or CA files to an external transport.
/// The operator must additionally protect parent directories against replacement.
pub fn check_public_trust_file(path: &Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.file_type().is_file() || meta.len() > 128 * 1024 {
        return Err(std::io::Error::other("invalid transport trust file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o022 != 0 {
            return Err(std::io::Error::other(
                "trust file is writable by group/other",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_validated_addresses_can_be_transport_endpoints() {
        for invalid in [
            "-oProxyCommand=whoami",
            "host:22",
            "https://example.com",
            "example.com/path",
            "x@host",
            "localhost\n-o",
            "a..b",
            "0.0.0.0#fragment",
            "[::1]",
        ] {
            assert!(!valid_host_address(invalid), "{invalid}");
        }
        for valid in ["localhost", "127.0.0.1", "::1", "node-01.example.invalid"] {
            assert!(valid_host_address(valid), "{valid}");
        }
    }
}
