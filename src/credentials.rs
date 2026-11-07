//! Provider-neutral credential request and *opaque* lease contracts (FR-008).
//! M2 supports only a denying production broker; no real secrets are handled.
use std::{fmt, future::Future, pin::Pin};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialScope {
    operation: String,
    target: String,
    purpose: String,
}

impl CredentialScope {
    /// Created by the trusted runtime from validated operation/target identifiers.
    pub(crate) fn new(operation: &str, target: &str, purpose: &str) -> Self {
        Self {
            operation: operation.to_owned(),
            target: target.to_owned(),
            purpose: purpose.to_owned(),
        }
    }

    pub fn operation(&self) -> &str {
        &self.operation
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn purpose(&self) -> &str {
        &self.purpose
    }
}

/// An opaque provider-side reference: not a token, password, or serialized secret.
/// A future trusted provider must resolve this through a separate restricted channel.
pub struct CredentialLease {
    scope: CredentialScope,
    opaque_handle: String,
}

impl CredentialLease {
    #[cfg(test)]
    pub(crate) fn for_test(scope: CredentialScope, handle: &str) -> Self {
        Self {
            scope,
            opaque_handle: handle.to_owned(),
        }
    }

    pub fn scope(&self) -> &CredentialScope {
        &self.scope
    }

    /// Only a trusted adapter may consume the handle. It is never serialized to MCP.
    pub fn opaque_handle(&self) -> &str {
        &self.opaque_handle
    }
}

impl fmt::Debug for CredentialLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialLease")
            .field("scope", &self.scope)
            .field("opaque_handle", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerFailure {
    Unavailable,
    Denied,
}

pub trait CredentialBroker: Send + Sync {
    /// May be called only *after* authorization and pre-execution audit commitment.
    /// The broker must enforce the operation+target+purpose scope independently.
    /// Futures are bounded by the coordinator's operation-wide deadline.
    fn acquire(
        &self,
        scope: CredentialScope,
    ) -> Pin<Box<dyn Future<Output = Result<CredentialLease, BrokerFailure>> + Send + '_>>;
}

/// Conservative production default: there are no secrets or credential backends.
pub struct DenyCredentialBroker;

impl CredentialBroker for DenyCredentialBroker {
    fn acquire(
        &self,
        _scope: CredentialScope,
    ) -> Pin<Box<dyn Future<Output = Result<CredentialLease, BrokerFailure>> + Send + '_>> {
        Box::pin(async { Err(BrokerFailure::Denied) })
    }
}
