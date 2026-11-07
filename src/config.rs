//! Trusted, local process configuration. Never accept this document over MCP.
use std::{collections::{BTreeMap, HashSet}, fs, path::Path};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    HostsList,
    HostsGet,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Host {
    pub id: String,
    pub hostname: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub principal: String,
    pub capability: Capability,
    pub host_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Identity asserted by a trusted process launcher, NOT authenticated by stdio.
    pub principal: String,
    #[serde(default)]
    pub hosts: Vec<Host>,
    #[serde(default)]
    pub grants: Vec<Grant>,
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("unable to read configuration: {}", path.display()))?;
        let config: Self = serde_json::from_str(&contents).context("invalid configuration JSON")?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(valid_id(&self.principal), "invalid principal identifier");
        let mut ids = HashSet::new();
        for host in &self.hosts {
            ensure!(valid_id(&host.id), "invalid host identifier");
            ensure!(!host.hostname.trim().is_empty(), "empty hostname");
            ensure!(ids.insert(host.id.as_str()), "duplicate host identifier");
        }
        for grant in &self.grants {
            ensure!(valid_id(&grant.principal), "invalid grant principal");
            ensure!(ids.contains(grant.host_id.as_str()), "grant references unknown host");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_and_duplicate_hosts_are_rejected() {
        let mut config = Config {
            principal: "local".into(),
            hosts: vec![Host {
                id: "node".into(),
                hostname: "node.invalid".into(),
                labels: BTreeMap::new(),
            }],
            grants: vec![],
        };
        assert!(config.validate().is_ok());
        config.hosts.push(config.hosts[0].clone());
        assert!(config.validate().is_err());
    }

    #[test]
    fn unknown_config_fields_are_rejected() {
        let input = r#"{"principal":"local","grants":[],"hosts":[],"allow_all":true}"#;
        assert!(serde_json::from_str::<Config>(input).is_err());
    }

    #[test]
    fn missing_grants_are_default_deny() {
        let config: Config = serde_json::from_str(r#"{"principal":"local"}"#).unwrap();
        assert!(config.grants.is_empty());
        assert!(config.validate().is_ok());
    }
}
