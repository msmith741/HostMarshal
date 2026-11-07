//! Atomically activated, immutable configuration snapshots (FR-014).
//! The store itself has no MCP or administrative configuration-write surface.
use std::{
    path::Path,
    sync::{Arc, RwLock},
};

use anyhow::{Result, anyhow};

use crate::declarative::CompiledConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadOutcome {
    Applied { previous: Option<String>, current: String },
    Unchanged { current: String },
}

/// An active snapshot or emergency-deny state. Each request reads one consistent
/// Arc<CompiledConfig> and holds it for that request, never a partially built set.
pub struct ConfigStore {
    active: RwLock<Option<Arc<CompiledConfig>>>,
}

impl ConfigStore {
    pub fn new(initial: CompiledConfig) -> Self {
        Self {
            active: RwLock::new(Some(Arc::new(initial))),
        }
    }

    /// Return the active snapshot. Lock poisoning fails closed (no capabilities).
    pub fn snapshot(&self) -> Option<Arc<CompiledConfig>> {
        self.active.read().ok().and_then(|current| current.clone())
    }

    /// Validate the full configuration *before* taking the write lock.
    /// Failed validation leaves the last-known-good snapshot unchanged.
    pub fn reload(&self, directory: &Path) -> Result<ReloadOutcome> {
        let next = CompiledConfig::load(directory)?;
        self.activate(next)
    }

    fn activate(&self, next: CompiledConfig) -> Result<ReloadOutcome> {
        let digest = next.snapshot_digest.clone();
        let mut guard = self
            .active
            .write()
            .map_err(|_| anyhow!("configuration lock poisoned; denying requests"))?;
        let previous = guard.as_ref().map(|snapshot| snapshot.snapshot_digest.clone());
        if previous.as_deref() == Some(digest.as_str()) {
            return Ok(ReloadOutcome::Unchanged { current: digest });
        }
        *guard = Some(Arc::new(next));
        Ok(ReloadOutcome::Applied { previous, current: digest })
    }

    /// Emergency lockout, applied atomically for all subsequent request starts.
    /// A valid administrative reload is required to reactivate the service.
    pub fn lockdown(&self) -> Result<()> {
        let mut guard = self
            .active
            .write()
            .map_err(|_| anyhow!("configuration lock poisoned; already fail-closed"))?;
        *guard = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> CompiledConfig {
        CompiledConfig::load(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config/v1alpha1"))
            .expect("known valid fixture")
    }

    #[test]
    fn snapshot_replacement_and_lockdown_never_expose_partial_state() {
        let store = ConfigStore::new(fixture());
        let original = store.snapshot().unwrap();
        let digest = original.snapshot_digest.clone();
        assert!(original.authorized("example-operator", "inventory.inspect", "sample-linux"));

        let unchanged = store.activate(fixture()).unwrap();
        assert_eq!(unchanged, ReloadOutcome::Unchanged { current: digest });

        let deny_all = CompiledConfig::compile(Vec::new()).unwrap();
        let result = store.activate(deny_all).unwrap();
        assert!(matches!(result, ReloadOutcome::Applied { .. }));
        assert!(!store.snapshot().unwrap().authorized("example-operator", "inventory.inspect", "sample-linux"));
        // A reader that already acquired its Arc holds an immutable old snapshot.
        assert!(original.authorized("example-operator", "inventory.inspect", "sample-linux"));

        store.lockdown().unwrap();
        assert!(store.snapshot().is_none());
        store.activate(fixture()).unwrap();
        assert!(store.snapshot().unwrap().authorized("example-operator", "inventory.inspect", "sample-linux"));
    }

    #[test]
    fn rejected_reload_keeps_valid_configuration() {
        let store = ConfigStore::new(fixture());
        let prior = store.snapshot().unwrap().snapshot_digest.clone();
        let impossible = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config/not-a-directory");
        assert!(store.reload(&impossible).is_err());
        assert_eq!(store.snapshot().unwrap().snapshot_digest, prior);
    }
}
