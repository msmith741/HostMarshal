//! M4 provider-neutral, fail-closed broker routing.
//! The registry is administrator-supplied, not an MCP capability or request.
use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc};

use anyhow::{Result, ensure};

use crate::credentials::{BrokerFailure, CredentialBroker, CredentialLease, CredentialScope};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProviderRoute {
    operation: String,
    target: String,
    purpose: String,
}

impl ProviderRoute {
    pub fn new(operation: &str, target: &str, purpose: &str) -> Result<Self> {
        ensure!(
            !operation.is_empty() && !target.is_empty() && !purpose.is_empty(),
            "credential provider route fields cannot be empty"
        );
        for field in [operation, target, purpose] {
            let allowed_slash = field == operation;
            ensure!(
                field.len() <= 128
                    && field.bytes().all(|b| {
                        b.is_ascii_alphanumeric()
                            || matches!(b, b'-' | b'_' | b'.')
                            || (allowed_slash && b == b'/')
                    }),
                "invalid credential provider route"
            );
        }
        Ok(Self {
            operation: operation.to_owned(),
            target: target.to_owned(),
            purpose: purpose.to_owned(),
        })
    }

    fn from_scope(scope: &CredentialScope) -> Self {
        Self {
            operation: scope.operation().to_owned(),
            target: scope.target().to_owned(),
            purpose: scope.purpose().to_owned(),
        }
    }
}

/// No implicit fallback. If the selected provider is unavailable or denies,
/// the request fails without consulting another provider.
pub struct RoutedCredentialBroker {
    providers: BTreeMap<ProviderRoute, Arc<dyn CredentialBroker>>,
}

impl RoutedCredentialBroker {
    pub fn new() -> Self {
        Self {
            providers: BTreeMap::new(),
        }
    }

    /// Only the trusted startup configuration may call this method.
    pub fn register(
        &mut self,
        route: ProviderRoute,
        provider: Arc<dyn CredentialBroker>,
    ) -> Result<()> {
        ensure!(
            !self.providers.contains_key(&route),
            "duplicate credential provider route: {route:?}"
        );
        self.providers.insert(route, provider);
        Ok(())
    }
}

impl Default for RoutedCredentialBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialBroker for RoutedCredentialBroker {
    fn acquire(
        &self,
        scope: CredentialScope,
    ) -> Pin<Box<dyn Future<Output = Result<CredentialLease, BrokerFailure>> + Send + '_>> {
        Box::pin(async move {
            let route = ProviderRoute::from_scope(&scope);
            let provider = self.providers.get(&route).ok_or(BrokerFailure::Denied)?;
            let lease = provider.acquire(scope).await?;
            if ProviderRoute::from_scope(lease.scope()) != route {
                return Err(BrokerFailure::Denied);
            }
            Ok(lease)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::CredentialLease;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestProvider {
        calls: Arc<AtomicUsize>,
        failure: Option<BrokerFailure>,
        wrong_target: bool,
    }

    impl CredentialBroker for TestProvider {
        fn acquire(
            &self,
            scope: CredentialScope,
        ) -> Pin<Box<dyn Future<Output = Result<CredentialLease, BrokerFailure>> + Send + '_>>
        {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if let Some(failure) = self.failure {
                    return Err(failure);
                }
                let actual = if self.wrong_target {
                    CredentialScope::new(scope.operation(), "other-target", scope.purpose())
                } else {
                    scope
                };
                Ok(CredentialLease::for_test(actual, "opaque-test-handle"))
            })
        }
    }

    fn scope(target: &str) -> CredentialScope {
        CredentialScope::new("builtin.linux.uname/v1", target, "ssh-observe")
    }

    fn route(target: &str) -> ProviderRoute {
        ProviderRoute::new("builtin.linux.uname/v1", target, "ssh-observe").unwrap()
    }

    #[tokio::test]
    async fn exact_route_required_and_no_cross_target_access() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut router = RoutedCredentialBroker::new();
        router
            .register(
                route("host-a"),
                Arc::new(TestProvider {
                    calls: Arc::clone(&calls),
                    failure: None,
                    wrong_target: false,
                }),
            )
            .unwrap();
        assert!(router.acquire(scope("host-a")).await.is_ok());
        assert!(matches!(
            router.acquire(scope("host-b")).await,
            Err(BrokerFailure::Denied)
        ));
        assert!(matches!(
            router
                .acquire(CredentialScope::new(
                    "builtin.https.health/v1",
                    "host-a",
                    "ssh-observe"
                ))
                .await,
            Err(BrokerFailure::Denied)
        ));
        assert!(matches!(
            router
                .acquire(CredentialScope::new(
                    "builtin.linux.uname/v1",
                    "host-a",
                    "other-purpose"
                ))
                .await,
            Err(BrokerFailure::Denied)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn duplicate_routes_rejected_and_provider_outage_does_not_fallback() {
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = Arc::new(TestProvider {
            calls: Arc::clone(&calls),
            failure: Some(BrokerFailure::Unavailable),
            wrong_target: false,
        });
        let mut router = RoutedCredentialBroker::new();
        router.register(route("host-a"), provider.clone()).unwrap();
        assert!(router.register(route("host-a"), provider).is_err());
        assert!(matches!(
            router.acquire(scope("host-a")).await,
            Err(BrokerFailure::Unavailable)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn mismatched_provider_lease_is_rejected() {
        let mut router = RoutedCredentialBroker::new();
        router
            .register(
                route("host-a"),
                Arc::new(TestProvider {
                    calls: Arc::new(AtomicUsize::new(0)),
                    failure: None,
                    wrong_target: true,
                }),
            )
            .unwrap();
        assert!(matches!(
            router.acquire(scope("host-a")).await,
            Err(BrokerFailure::Denied)
        ));
    }

    #[test]
    fn route_validation_rejects_injection_and_empty_fields() {
        for target in ["", "../secret", "host a", "host\nother", "🌍"] {
            assert!(ProviderRoute::new("builtin.linux.uname/v1", target, "ssh-observe").is_err());
        }
    }
}
