//! Typed adapter contracts and the only production M2 operation (FR-006/FR-007).
//! Only trusted built-in code is registered; no native or external plugin loader.
use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc, time::Duration};

use serde_json::{Value, json};

use crate::credentials::CredentialLease;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectClass {
    Observe,
    Diagnose,
    Mutate,
    Privileged,
    Destructive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialRequirement {
    None,
    Scoped { purpose: &'static str },
}

/// The trusted adapter descriptor cannot be overridden through capability YAML.
#[derive(Clone, Copy, Debug)]
pub struct OperationDescriptor {
    pub id: &'static str,
    pub effects: EffectClass,
    pub supported_target_kind: &'static str,
    pub max_timeout: Duration,
    pub max_output_bytes: usize,
    pub credential: CredentialRequirement,
}

pub const INVENTORY_INSPECT: OperationDescriptor = OperationDescriptor {
    id: "builtin.inventory.inspect/v1",
    effects: EffectClass::Observe,
    supported_target_kind: "Host",
    max_timeout: Duration::from_secs(2),
    max_output_bytes: 4096,
    credential: CredentialRequirement::None,
};

/// An inventory-resolved, trusted target. These fields are never taken from tool
/// arguments except by looking up a stable ID in a validated snapshot.
#[derive(Debug)]
pub struct ResolvedTarget {
    pub id: String,
    pub address: String,
}

pub struct AdapterInvocation {
    pub target: ResolvedTarget,
    pub input: Value,
    pub lease: Option<CredentialLease>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterFailure {
    Unavailable,
    Rejected,
    Failed,
}

pub trait OperationAdapter: Send + Sync {
    fn descriptor(&self) -> &'static OperationDescriptor;

    fn execute(
        &self,
        invocation: AdapterInvocation,
    ) -> Pin<Box<dyn Future<Output = Result<Value, AdapterFailure>> + Send + '_>>;
}

/// Registration is a privileged, compile-time trusted composition action.
/// It is deliberately not exposed to MCP clients or configuration YAML.
pub struct TrustedAdapterCatalog {
    adapters: BTreeMap<&'static str, Arc<dyn OperationAdapter>>,
}

impl TrustedAdapterCatalog {
    pub fn builtin() -> Self {
        let mut adapters: BTreeMap<&'static str, Arc<dyn OperationAdapter>> = BTreeMap::new();
        adapters.insert(INVENTORY_INSPECT.id, Arc::new(InventoryInspect));
        Self { adapters }
    }

    pub fn resolve(&self, operation_id: &str) -> Option<Arc<dyn OperationAdapter>> {
        self.adapters.get(operation_id).cloned()
    }

    #[cfg(test)]
    pub(crate) fn with_test_adapter(adapter: Arc<dyn OperationAdapter>) -> Self {
        let mut catalog = Self::builtin();
        catalog.adapters.insert(adapter.descriptor().id, adapter);
        catalog
    }
}

/// Built-in observation only. No network, child process, secret or host execution.
struct InventoryInspect;

impl OperationAdapter for InventoryInspect {
    fn descriptor(&self) -> &'static OperationDescriptor {
        &INVENTORY_INSPECT
    }

    fn execute(
        &self,
        request: AdapterInvocation,
    ) -> Pin<Box<dyn Future<Output = Result<Value, AdapterFailure>> + Send + '_>> {
        Box::pin(async move {
            if request.lease.is_some() {
                return Err(AdapterFailure::Rejected);
            }
            Ok(json!({
                "id": request.target.id,
                "hostname": request.target.address,
            }))
        })
    }
}
