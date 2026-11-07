//! Trusted built-in observation operation registry (FR-006/FR-007, ADR-0006).
//! No runtime-loaded plugins, arbitrary commands or arbitrary HTTP URLs.
use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc, time::Duration};

use serde_json::{Value, json};

use crate::{
    credentials::CredentialLease,
    transport::{HttpsEndpoint, SshEndpoint},
};

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
pub const LINUX_UNAME: OperationDescriptor = OperationDescriptor {
    id: "builtin.linux.uname/v1",
    effects: EffectClass::Observe,
    supported_target_kind: "Host",
    max_timeout: Duration::from_secs(5),
    max_output_bytes: 4096,
    credential: CredentialRequirement::Scoped {
        purpose: "ssh-observe",
    },
};
pub const HTTPS_HEALTH: OperationDescriptor = OperationDescriptor {
    id: "builtin.https.health/v1",
    effects: EffectClass::Observe,
    supported_target_kind: "Host",
    max_timeout: Duration::from_secs(5),
    max_output_bytes: 4096,
    credential: CredentialRequirement::None,
};

/// Only operations compiled and audited into HostMarshal can be bound by YAML.
pub fn descriptor(id: &str) -> Option<&'static OperationDescriptor> {
    match id {
        "builtin.inventory.inspect/v1" => Some(&INVENTORY_INSPECT),
        "builtin.linux.uname/v1" => Some(&LINUX_UNAME),
        "builtin.https.health/v1" => Some(&HTTPS_HEALTH),
        _ => None,
    }
}

/// Common input: one opaque inventory ID. No command, path, method, URL, or shell.
pub fn trusted_input_schema() -> Value {
    json!({
        "type":"object",
        "properties":{"target":{"type":"string"}},
        "required":["target"],
        "additionalProperties":false
    })
}

pub fn trusted_output_schema(id: &str) -> Option<Value> {
    match id {
        "builtin.inventory.inspect/v1" => Some(json!({
            "type":"object",
            "properties":{"id":{"type":"string"},"hostname":{"type":"string"}},
            "required":["id","hostname"],"additionalProperties":false
        })),
        "builtin.linux.uname/v1" => Some(json!({
            "type":"object",
            "properties":{"id":{"type":"string"},"os":{"type":"string","const":"Linux"}},
            "required":["id","os"],"additionalProperties":false
        })),
        "builtin.https.health/v1" => Some(json!({
            "type":"object",
            "properties":{"id":{"type":"string"},"statusCode":{"type":"integer"},"healthy":{"type":"boolean"}},
            "required":["id","statusCode","healthy"],"additionalProperties":false
        })),
        _ => None,
    }
}

#[derive(Debug)]
pub struct ResolvedTarget {
    pub id: String,
    pub address: String,
    pub ssh: Option<SshEndpoint>,
    pub https: Option<HttpsEndpoint>,
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
        request: AdapterInvocation,
    ) -> Pin<Box<dyn Future<Output = Result<Value, AdapterFailure>> + Send + '_>>;
}

pub struct TrustedAdapterCatalog {
    adapters: BTreeMap<&'static str, Arc<dyn OperationAdapter>>,
}

impl TrustedAdapterCatalog {
    pub fn builtin() -> Self {
        let mut adapters: BTreeMap<&'static str, Arc<dyn OperationAdapter>> = BTreeMap::new();
        adapters.insert(INVENTORY_INSPECT.id, Arc::new(InventoryInspect));
        adapters.insert(LINUX_UNAME.id, Arc::new(crate::observation::LinuxUname));
        adapters.insert(HTTPS_HEALTH.id, Arc::new(crate::observation::HttpsHealth));
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
            Ok(json!({"id":request.target.id,"hostname":request.target.address}))
        })
    }
}
