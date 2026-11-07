//! Fail-closed authorization on the fixed launcher principal and exact host ID.
use crate::config::{Capability, Config, Host};

#[derive(Clone)]
pub struct Policy {
    config: Config,
}

impl Policy {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    fn permits(&self, capability: Capability, host_id: &str) -> bool {
        self.config.grants.iter().any(|grant| {
            grant.principal == self.config.principal
                && grant.capability == capability
                && grant.host_id == host_id
        })
    }

    /// Return only inventory entries the current principal may enumerate.
    pub fn visible_hosts(&self) -> Vec<Host> {
        self.config
            .hosts
            .iter()
            .filter(|host| self.permits(Capability::HostsList, &host.id))
            .cloned()
            .collect()
    }

    /// Intentionally collapse "not found" and "unauthorized" to avoid disclosure.
    pub fn get_host(&self, id: &str) -> Option<Host> {
        if !self.permits(Capability::HostsGet, id) {
            return None;
        }
        self.config.hosts.iter().find(|host| host.id == id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Grant;
    use std::collections::BTreeMap;

    fn config() -> Config {
        Config {
            principal: "hermes".into(),
            hosts: ["alpha", "bravo"]
                .into_iter()
                .map(|id| Host {
                    id: id.into(),
                    hostname: format!("{id}.invalid"),
                    labels: BTreeMap::new(),
                })
                .collect(),
            grants: vec![],
        }
    }

    #[test]
    fn denies_everything_without_grants() {
        let policy = Policy::new(config());
        assert!(policy.visible_hosts().is_empty());
        assert!(policy.get_host("alpha").is_none());
    }

    #[test]
    fn scopes_by_principal_capability_and_host() {
        let mut config = config();
        config.grants = vec![
            Grant {
                principal: "hermes".into(),
                capability: Capability::HostsList,
                host_id: "alpha".into(),
            },
            Grant {
                principal: "untrusted".into(),
                capability: Capability::HostsGet,
                host_id: "alpha".into(),
            },
            Grant {
                principal: "hermes".into(),
                capability: Capability::HostsGet,
                host_id: "bravo".into(),
            },
        ];
        let policy = Policy::new(config);
        let visible = policy.visible_hosts();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].id, "alpha");
        assert!(policy.get_host("alpha").is_none());
        assert_eq!(policy.get_host("bravo").unwrap().id, "bravo");
        assert!(policy.get_host("nonexistent").is_none());
    }
}
