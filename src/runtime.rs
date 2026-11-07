//! Security-enforcing execution coordinator (FR-004/006/008/009, ADR-0007/0008).
//! Only the trusted static-inventory operation is registered in production.
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use tokio::{
    sync::Semaphore,
    time::{Instant, timeout_at},
};

use crate::{
    adapter::{
        AdapterInvocation, CredentialRequirement, EffectClass, ResolvedTarget,
        TrustedAdapterCatalog,
    },
    audit::{AuditContext, AuditEvent, AuditPhase, AuditSink},
    authorization::{AuthorizationRequest, Authorizer, GrantAuthorizer},
    credentials::{CredentialBroker, CredentialScope},
    declarative::{input_schema, output_schema},
    identity::AuthenticatedCaller,
    snapshot::ConfigStore,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeFailure {
    Unauthorized,
    InvalidInput,
    Unavailable,
    Busy,
    AuditUnavailable,
    BrokerUnavailable,
    AdapterFailed,
    TimedOut,
    InvalidOutput,
}

impl RuntimeFailure {
    /// Stable, intentionally non-disclosing error messages for MCP callers.
    pub fn public_message(self) -> &'static str {
        match self {
            Self::Unauthorized => "capability not found or not authorized",
            Self::InvalidInput => "invalid capability input",
            Self::Unavailable => "operation unavailable",
            Self::Busy => "execution capacity unavailable",
            Self::AuditUnavailable => "audit unavailable",
            Self::BrokerUnavailable => "credential unavailable",
            Self::AdapterFailed => "operation failed",
            Self::TimedOut => "operation deadline exceeded",
            Self::InvalidOutput => "operation result rejected",
        }
    }

    pub fn reason_code(self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::InvalidInput => "invalid_input",
            Self::Unavailable => "unavailable",
            Self::Busy => "busy",
            Self::AuditUnavailable => "audit_unavailable",
            Self::BrokerUnavailable => "broker_unavailable",
            Self::AdapterFailed => "adapter_failed",
            Self::TimedOut => "timeout",
            Self::InvalidOutput => "invalid_output",
        }
    }
}

pub struct ExecutionCoordinator {
    store: Arc<ConfigStore>,
    adapters: TrustedAdapterCatalog,
    broker: Arc<dyn CredentialBroker>,
    authorizer: Arc<dyn Authorizer>,
    audit: Arc<dyn AuditSink>,
    capacity: Arc<Semaphore>,
    sequence: AtomicU64,
}

impl ExecutionCoordinator {
    pub fn new(
        store: Arc<ConfigStore>,
        broker: Arc<dyn CredentialBroker>,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            store,
            adapters: TrustedAdapterCatalog::builtin(),
            broker,
            authorizer: Arc::new(GrantAuthorizer),
            audit,
            capacity: Arc::new(Semaphore::new(16)),
            sequence: AtomicU64::new(0),
        }
    }

    #[cfg(test)]
    fn with_test_catalog(
        store: Arc<ConfigStore>,
        broker: Arc<dyn CredentialBroker>,
        audit: Arc<dyn AuditSink>,
        adapters: TrustedAdapterCatalog,
    ) -> Self {
        Self {
            store,
            adapters,
            broker,
            authorizer: Arc::new(GrantAuthorizer),
            audit,
            capacity: Arc::new(Semaphore::new(16)),
            sequence: AtomicU64::new(0),
        }
    }

    pub fn store(&self) -> &Arc<ConfigStore> {
        &self.store
    }

    fn next_id(&self) -> String {
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let n = self.sequence.fetch_add(1, Ordering::Relaxed);
        format!("{:x}-{epoch:x}-{n:016x}", std::process::id())
    }

    /// Every invocation emits a denial or an authorized+terminal audit event.
    /// A failed pre-execution audit commitment prevents adapter execution.
    pub async fn invoke(
        &self,
        caller: &AuthenticatedCaller,
        capability: &str,
        input: Value,
    ) -> Result<Value, RuntimeFailure> {
        let request_id = self.next_id();
        let snapshot = self.store.snapshot();
        let digest = snapshot
            .as_ref()
            .map(|s| s.snapshot_digest.clone())
            .unwrap_or_else(|| "<locked>".to_owned());
        let target_input = input
            .as_object()
            .and_then(|obj| obj.get("target"))
            .and_then(Value::as_str);
        let target_for_log = "<unresolved>";
        // Never echo an arbitrary client-provided tool name into security logs.
        let log_capability = if snapshot
            .as_ref()
            .is_some_and(|s| s.capabilities.contains_key(capability))
        {
            capability
        } else {
            "<unresolved>"
        };
        let operation_for_log = "<unresolved>";
        let deny = |operation: &str, target: &str, failure| {
            self.denied(
                AuditContext {
                    request_id: &request_id,
                    issuer: caller.issuer(),
                    subject: caller.subject(),
                    capability: log_capability,
                    operation,
                    target,
                    snapshot_digest: &digest,
                },
                failure,
            )
        };

        let Some(snapshot) = snapshot else {
            deny(
                operation_for_log,
                target_for_log,
                RuntimeFailure::Unauthorized,
            )?;
            return Err(RuntimeFailure::Unauthorized);
        };
        let Some(cap) = snapshot.capabilities.get(capability) else {
            deny(
                operation_for_log,
                target_for_log,
                RuntimeFailure::Unauthorized,
            )?;
            return Err(RuntimeFailure::Unauthorized);
        };
        let Some(target) = target_input else {
            deny(
                &cap.operation_ref,
                target_for_log,
                RuntimeFailure::InvalidInput,
            )?;
            return Err(RuntimeFailure::InvalidInput);
        };
        let target = target.to_owned();
        let valid_input = input.as_object().is_some_and(|obj| obj.len() == 1);
        if !valid_input || target.is_empty() || target.len() > 128 {
            deny(
                &cap.operation_ref,
                target_for_log,
                RuntimeFailure::InvalidInput,
            )?;
            return Err(RuntimeFailure::InvalidInput);
        }
        if !self
            .authorizer
            .authorize(AuthorizationRequest {
                snapshot: &snapshot,
                caller,
                capability,
                operation: &cap.operation_ref,
                target: &target,
            })
            .permitted()
        {
            deny(
                &cap.operation_ref,
                target_for_log,
                RuntimeFailure::Unauthorized,
            )?;
            return Err(RuntimeFailure::Unauthorized);
        }

        // Trust-boundary checks are repeated in the coordinator; a manifest is
        // never permitted to redefine risk, targets, schemas or maximum limits.
        let Some(adapter) = self.adapters.resolve(&cap.operation_ref) else {
            deny(&cap.operation_ref, &target, RuntimeFailure::Unavailable)?;
            return Err(RuntimeFailure::Unavailable);
        };
        let desc = adapter.descriptor();
        if desc.id != cap.operation_ref
            || desc.effects != EffectClass::Observe
            || desc.supported_target_kind != "Host"
            || cap.input_schema != input_schema()
            || cap.output_schema != output_schema()
            || cap.max_output_bytes == 0
            || cap.max_output_bytes > desc.max_output_bytes
        {
            deny(&cap.operation_ref, &target, RuntimeFailure::Unavailable)?;
            return Err(RuntimeFailure::Unavailable);
        }
        let Some(host) = snapshot.hosts.get(&target) else {
            deny(
                &cap.operation_ref,
                target_for_log,
                RuntimeFailure::Unauthorized,
            )?;
            return Err(RuntimeFailure::Unauthorized);
        };

        let permit = match self.capacity.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                deny(desc.id, &target, RuntimeFailure::Busy)?;
                return Err(RuntimeFailure::Busy);
            }
        };

        let event_context = AuditContext {
            request_id: &request_id,
            issuer: caller.issuer(),
            subject: caller.subject(),
            capability,
            operation: desc.id,
            target: &target,
            snapshot_digest: &digest,
        };
        let event = |phase, reason: &str| AuditEvent::new(event_context, phase, reason);

        // This is a mandatory *pre-execution* commitment even for observation.
        // A missing/broken audit sink blocks the broker and adapter.
        self.audit
            .record(&event(AuditPhase::Authorized, "authorized"))
            .map_err(|_| RuntimeFailure::AuditUnavailable)?;

        // A single absolute deadline covers any broker request and the adapter.
        // A slow/failed provider cannot extend execution beyond the descriptor.
        let deadline = Instant::now() + desc.max_timeout;
        let lease = match desc.credential {
            CredentialRequirement::None => None,
            CredentialRequirement::Scoped { purpose } => {
                let expected = CredentialScope::new(desc.id, &target, purpose);
                match timeout_at(deadline, self.broker.acquire(expected.clone())).await {
                    Ok(Ok(received)) if received.scope() == &expected => Some(received),
                    Err(_) => return self.fail(&event, RuntimeFailure::TimedOut),
                    _ => return self.fail(&event, RuntimeFailure::BrokerUnavailable),
                }
            }
        };

        let req = AdapterInvocation {
            target: ResolvedTarget {
                id: host.metadata.name.clone(),
                address: host.spec.address.clone(),
            },
            input,
            lease,
        };

        let output = match timeout_at(deadline, adapter.execute(req)).await {
            Ok(Ok(value)) => value,
            Ok(Err(_)) => return self.fail(&event, RuntimeFailure::AdapterFailed),
            Err(_) => return self.fail(&event, RuntimeFailure::TimedOut),
        };

        // Only the vetted inventory result shape is supported in M2.
        // It must match the resolved inventory, not just an arbitrary JSON shape.
        if output != json!({"id": host.metadata.name, "hostname": host.spec.address})
            || serde_json::to_vec(&output)
                .map_or(true, |encoded| encoded.len() > cap.max_output_bytes)
        {
            return self.fail(&event, RuntimeFailure::InvalidOutput);
        }
        // The permit is deliberately held through the terminal audit commitment.
        self.audit
            .record(&event(AuditPhase::Succeeded, "ok"))
            .map_err(|_| RuntimeFailure::AuditUnavailable)?;
        drop(permit);
        Ok(output)
    }

    fn denied(
        &self,
        context: AuditContext<'_>,
        failure: RuntimeFailure,
    ) -> Result<(), RuntimeFailure> {
        self.audit
            .record(&AuditEvent::new(
                context,
                AuditPhase::Denied,
                failure.reason_code(),
            ))
            .map_err(|_| RuntimeFailure::AuditUnavailable)
    }

    fn fail(
        &self,
        make_event: &impl Fn(AuditPhase, &str) -> AuditEvent,
        failure: RuntimeFailure,
    ) -> Result<Value, RuntimeFailure> {
        self.audit
            .record(&make_event(AuditPhase::Failed, failure.reason_code()))
            .map_err(|_| RuntimeFailure::AuditUnavailable)?;
        Err(failure)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        pin::Pin,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use super::*;
    use crate::{
        adapter::{
            AdapterFailure, AdapterInvocation, CredentialRequirement, EffectClass,
            OperationAdapter, OperationDescriptor, TrustedAdapterCatalog,
        },
        audit::{AuditEvent, AuditPhase, AuditSink},
        credentials::{BrokerFailure, CredentialLease, CredentialScope},
        declarative::CompiledConfig,
    };

    struct MemoryAudit {
        events: Mutex<Vec<AuditEvent>>,
        reject_phase: Option<AuditPhase>,
    }

    impl MemoryAudit {
        fn new(reject_phase: Option<AuditPhase>) -> Self {
            Self {
                events: Mutex::new(Vec::new()),
                reject_phase,
            }
        }
        fn phases(&self) -> Vec<AuditPhase> {
            self.events
                .lock()
                .unwrap()
                .iter()
                .map(|e| e.phase)
                .collect()
        }
    }

    impl AuditSink for MemoryAudit {
        fn record(&self, event: &AuditEvent) -> std::io::Result<()> {
            if self.reject_phase == Some(event.phase) {
                return Err(std::io::Error::other(
                    "injected audit failure: SECRET-NEVER-LOG",
                ));
            }
            self.events.lock().unwrap().push(event.clone());
            Ok(())
        }
    }

    struct BrokerSpy {
        count: AtomicUsize,
        mode: &'static str,
    }

    impl BrokerSpy {
        fn new(mode: &'static str) -> Self {
            Self {
                count: AtomicUsize::new(0),
                mode,
            }
        }
    }

    impl CredentialBroker for BrokerSpy {
        fn acquire(
            &self,
            scope: CredentialScope,
        ) -> Pin<Box<dyn Future<Output = Result<CredentialLease, BrokerFailure>> + Send + '_>>
        {
            self.count.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                match self.mode {
                    "correct" => Ok(CredentialLease::for_test(scope, "SECRET-CANARY")),
                    "wrong" => Ok(CredentialLease::for_test(
                        CredentialScope::new(scope.operation(), "wrong-target", scope.purpose()),
                        "SECRET-CANARY",
                    )),
                    "delay" => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        Ok(CredentialLease::for_test(scope, "SECRET-CANARY"))
                    }
                    _ => Err(BrokerFailure::Unavailable),
                }
            })
        }
    }

    const SCOPED_DESCRIPTOR: OperationDescriptor = OperationDescriptor {
        id: "builtin.inventory.inspect/v1",
        effects: EffectClass::Observe,
        supported_target_kind: "Host",
        max_timeout: Duration::from_millis(20),
        max_output_bytes: 4096,
        credential: CredentialRequirement::Scoped {
            purpose: "inspect-only",
        },
    };
    const OBSERVE_DESCRIPTOR: OperationDescriptor = OperationDescriptor {
        credential: CredentialRequirement::None,
        ..SCOPED_DESCRIPTOR
    };

    struct TestAdapter {
        calls: AtomicUsize,
        kind: &'static str,
        descriptor: &'static OperationDescriptor,
    }

    impl TestAdapter {
        fn new(kind: &'static str, descriptor: &'static OperationDescriptor) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                kind,
                descriptor,
            }
        }
    }

    impl OperationAdapter for TestAdapter {
        fn descriptor(&self) -> &'static OperationDescriptor {
            self.descriptor
        }

        fn execute(
            &self,
            request: AdapterInvocation,
        ) -> Pin<Box<dyn Future<Output = Result<Value, AdapterFailure>> + Send + '_>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if self.kind == "delay" {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                if self.kind == "reject" {
                    return Err(AdapterFailure::Rejected);
                }
                if self.kind == "bad-output" {
                    return Ok(json!({"token": "SECRET-CANARY"}));
                }
                Ok(json!({
                    "id": request.target.id,
                    "hostname": request.target.address,
                }))
            })
        }
    }

    fn fixture() -> Arc<ConfigStore> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config/v1alpha1");
        Arc::new(ConfigStore::new(CompiledConfig::load(&dir).unwrap()))
    }

    fn caller(subject: &str) -> AuthenticatedCaller {
        AuthenticatedCaller::from_trusted_launcher(subject).unwrap()
    }

    fn coordinator(
        adapter: Arc<TestAdapter>,
        broker: Arc<BrokerSpy>,
        audit: Arc<MemoryAudit>,
    ) -> ExecutionCoordinator {
        let catalog = TrustedAdapterCatalog::with_test_adapter(adapter);
        ExecutionCoordinator::with_test_catalog(fixture(), broker, audit, catalog)
    }

    #[tokio::test]
    async fn allowed_request_produces_precommit_and_terminal_audit() {
        let adapter = Arc::new(TestAdapter::new("ok", &OBSERVE_DESCRIPTOR));
        let broker = Arc::new(BrokerSpy::new("error"));
        let audit = Arc::new(MemoryAudit::new(None));
        let runtime = coordinator(adapter.clone(), broker.clone(), audit.clone());
        let result = runtime
            .invoke(
                &caller("example-operator"),
                "inventory.inspect",
                json!({"target":"sample-linux"}),
            )
            .await
            .unwrap();
        assert_eq!(result["id"], "sample-linux");
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 1);
        assert_eq!(broker.count.load(Ordering::SeqCst), 0);
        assert_eq!(
            audit.phases(),
            vec![AuditPhase::Authorized, AuditPhase::Succeeded]
        );
        let events = audit.events.lock().unwrap();
        assert_eq!(events[0].request_id, events[1].request_id);
        assert_eq!(events[0].subject, "example-operator");
        assert_eq!(events[0].operation, "builtin.inventory.inspect/v1");
        assert!(events[0].snapshot_digest.starts_with("sha256:"));
    }

    #[tokio::test]
    async fn denied_inputs_never_reach_broker_or_adapter() {
        let adapter = Arc::new(TestAdapter::new("ok", &SCOPED_DESCRIPTOR));
        let broker = Arc::new(BrokerSpy::new("correct"));
        let audit = Arc::new(MemoryAudit::new(None));
        let runtime = coordinator(adapter.clone(), broker.clone(), audit.clone());
        let cases = [
            (
                caller("unauthorized"),
                "inventory.inspect",
                json!({"target":"sample-linux"}),
            ),
            (
                caller("example-operator"),
                "inventory.inspect",
                json!({"target":"unknown"}),
            ),
            (
                caller("example-operator"),
                "inventory.inspect",
                json!({"target":"sample-linux","command":"id"}),
            ),
            (
                caller("example-operator"),
                "inventory.unpublished",
                json!({"target":"sample-linux"}),
            ),
        ];
        for (subject, tool, args) in cases {
            assert!(runtime.invoke(&subject, tool, args).await.is_err());
        }
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 0);
        assert_eq!(broker.count.load(Ordering::SeqCst), 0);
        assert_eq!(audit.phases(), vec![AuditPhase::Denied; 4]);
    }

    #[tokio::test]
    async fn audit_sink_failure_fails_closed_before_execution() {
        let adapter = Arc::new(TestAdapter::new("ok", &SCOPED_DESCRIPTOR));
        let broker = Arc::new(BrokerSpy::new("correct"));
        let audit = Arc::new(MemoryAudit::new(Some(AuditPhase::Authorized)));
        let runtime = coordinator(adapter.clone(), broker.clone(), audit);
        let failure = runtime
            .invoke(
                &caller("example-operator"),
                "inventory.inspect",
                json!({"target":"sample-linux"}),
            )
            .await
            .unwrap_err();
        assert_eq!(failure, RuntimeFailure::AuditUnavailable);
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 0);
        assert_eq!(broker.count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn broker_must_honor_exact_authorized_scope() {
        for mode in ["error", "wrong", "correct"] {
            let adapter = Arc::new(TestAdapter::new("ok", &SCOPED_DESCRIPTOR));
            let broker = Arc::new(BrokerSpy::new(mode));
            let audit = Arc::new(MemoryAudit::new(None));
            let runtime = coordinator(adapter.clone(), broker.clone(), audit.clone());
            let result = runtime
                .invoke(
                    &caller("example-operator"),
                    "inventory.inspect",
                    json!({"target":"sample-linux"}),
                )
                .await;
            assert_eq!(broker.count.load(Ordering::SeqCst), 1);
            if mode == "correct" {
                assert!(result.is_ok());
                assert_eq!(adapter.calls.load(Ordering::SeqCst), 1);
                assert_eq!(
                    audit.phases(),
                    vec![AuditPhase::Authorized, AuditPhase::Succeeded]
                );
            } else {
                assert_eq!(result.unwrap_err(), RuntimeFailure::BrokerUnavailable);
                assert_eq!(adapter.calls.load(Ordering::SeqCst), 0);
                assert_eq!(
                    audit.phases(),
                    vec![AuditPhase::Authorized, AuditPhase::Failed]
                );
            }
            assert!(!format!("{:?}", audit.events.lock().unwrap()).contains("SECRET-CANARY"));
        }
    }

    #[tokio::test]
    async fn broker_deadline_prevents_late_adapter_execution() {
        let adapter = Arc::new(TestAdapter::new("ok", &SCOPED_DESCRIPTOR));
        let broker = Arc::new(BrokerSpy::new("delay"));
        let audit = Arc::new(MemoryAudit::new(None));
        let runtime = coordinator(adapter.clone(), broker.clone(), audit.clone());
        let result = runtime
            .invoke(
                &caller("example-operator"),
                "inventory.inspect",
                json!({"target":"sample-linux"}),
            )
            .await;
        assert_eq!(result.unwrap_err(), RuntimeFailure::TimedOut);
        assert_eq!(broker.count.load(Ordering::SeqCst), 1);
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            audit.phases(),
            vec![AuditPhase::Authorized, AuditPhase::Failed]
        );
    }

    #[tokio::test]
    async fn timeout_and_invalid_output_have_terminal_failure_events() {
        for kind in ["delay", "bad-output", "reject"] {
            let adapter = Arc::new(TestAdapter::new(kind, &OBSERVE_DESCRIPTOR));
            let broker = Arc::new(BrokerSpy::new("error"));
            let audit = Arc::new(MemoryAudit::new(None));
            let runtime = coordinator(adapter, broker, audit.clone());
            let result = runtime
                .invoke(
                    &caller("example-operator"),
                    "inventory.inspect",
                    json!({"target":"sample-linux"}),
                )
                .await;
            let expected = match kind {
                "delay" => RuntimeFailure::TimedOut,
                "bad-output" => RuntimeFailure::InvalidOutput,
                _ => RuntimeFailure::AdapterFailed,
            };
            assert_eq!(result.unwrap_err(), expected);
            assert_eq!(
                audit.phases(),
                vec![AuditPhase::Authorized, AuditPhase::Failed]
            );
        }
    }

    #[tokio::test]
    async fn terminal_audit_failure_never_returns_output() {
        let adapter = Arc::new(TestAdapter::new("ok", &OBSERVE_DESCRIPTOR));
        let broker = Arc::new(BrokerSpy::new("error"));
        let audit = Arc::new(MemoryAudit::new(Some(AuditPhase::Succeeded)));
        let runtime = coordinator(adapter.clone(), broker, audit.clone());
        assert_eq!(
            runtime
                .invoke(
                    &caller("example-operator"),
                    "inventory.inspect",
                    json!({"target":"sample-linux"})
                )
                .await
                .unwrap_err(),
            RuntimeFailure::AuditUnavailable
        );
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 1);
        assert_eq!(audit.phases(), vec![AuditPhase::Authorized]);
    }
}
