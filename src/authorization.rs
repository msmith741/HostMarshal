//! Authorization decision interface (FR-004/005/006, ADR-0007).
//! Policies run in the trusted execution coordinator, not inside MCP handlers.
use crate::{declarative::CompiledConfig, identity::AuthenticatedCaller};

/// Immutable, vetted authorization context for a specific operation and host.
/// This is constructed after capability and inventory resolution.
pub struct AuthorizationRequest<'a> {
    pub snapshot: &'a CompiledConfig,
    pub caller: &'a AuthenticatedCaller,
    pub capability: &'a str,
    pub operation: &'a str,
    pub target: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDecision {
    Permit,
    Deny,
}

impl AuthorizationDecision {
    pub fn permitted(self) -> bool {
        self == Self::Permit
    }
}

/// Implementations must fail closed and have no direct adapter/credential access.
pub trait Authorizer: Send + Sync {
    fn authorize(&self, request: AuthorizationRequest<'_>) -> AuthorizationDecision;
}

pub struct GrantAuthorizer;

impl Authorizer for GrantAuthorizer {
    fn authorize(&self, request: AuthorizationRequest<'_>) -> AuthorizationDecision {
        let Some(capability) = request.snapshot.capabilities.get(request.capability) else {
            return AuthorizationDecision::Deny;
        };
        if capability.operation_ref != request.operation {
            return AuthorizationDecision::Deny;
        }
        if request.snapshot.authorized_identity(
            request.caller.issuer(),
            request.caller.subject(),
            request.capability,
            request.target,
        ) {
            AuthorizationDecision::Permit
        } else {
            AuthorizationDecision::Deny
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn denies_without_capability_even_when_identity_is_verified() {
        let snapshot = CompiledConfig::compile(Vec::new()).unwrap();
        let caller = AuthenticatedCaller::from_trusted_launcher("operator").unwrap();
        assert_eq!(
            GrantAuthorizer.authorize(AuthorizationRequest {
                snapshot: &snapshot,
                caller: &caller,
                capability: "inventory.inspect",
                operation: "builtin.inventory.inspect/v1",
                target: "host-1",
            }),
            AuthorizationDecision::Deny
        );
    }
}
