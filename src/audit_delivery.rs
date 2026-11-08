//! Opt-in, provider-neutral, bounded audit dispatch (FR-035).
//! A dedicated in-process writer thread isolates a stalled sink from an
//! unbounded caller wait, but does NOT provide independent durable storage.
use std::{
    io,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender, TrySendError},
    },
    thread,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;

use crate::{
    audit::{AuditEvent, AuditSink},
    credentials::check_private_key_file,
};

const MAX_CONFIG_BYTES: u64 = 4096;
const MAX_EVENT_BYTES: usize = 8192;
const API_VERSION: &str = "hostmarshal.io/audit-delivery/v1alpha1";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditDeliverySpec {
    api_version: String,
    queue_capacity: usize,
    ack_timeout_ms: u64,
}

impl AuditDeliverySpec {
    /// Load only a trusted launch-time configuration, never a YAML Grant or
    /// an MCP caller-supplied path.
    pub fn load(path: &Path) -> Result<Self> {
        check_private_key_file(path).context("audit delivery config must be protected")?;
        let metadata = std::fs::metadata(path)?;
        ensure!(
            metadata.len() <= MAX_CONFIG_BYTES,
            "audit delivery config exceeds size budget"
        );
        let bytes = std::fs::read(path)?;
        let spec: Self = serde_json::from_slice(&bytes)?;
        spec.validate()?;
        Ok(spec)
    }

    fn validate(&self) -> Result<()> {
        ensure!(self.api_version == API_VERSION, "unsupported audit delivery version");
        ensure!(
            (1..=256).contains(&self.queue_capacity),
            "audit queue capacity must be 1..=256"
        );
        ensure!(
            (100..=5000).contains(&self.ack_timeout_ms),
            "audit acknowledgment timeout must be 100..=5000 ms"
        );
        Ok(())
    }
}

struct Delivery {
    event: AuditEvent,
    committed: SyncSender<bool>,
}

/// All calls require a positive acknowledgment from the same trusted sink.
/// Saturation, sink failure, worker loss, and delivery timeout permanently
/// latch the dispatcher closed; no queued retry or fallback is attempted.
pub struct BoundedAuditSink {
    sender: SyncSender<Delivery>,
    healthy: Arc<AtomicBool>,
    ack_timeout: Duration,
}

impl BoundedAuditSink {
    pub fn from_spec(sink: Arc<dyn AuditSink>, spec: &AuditDeliverySpec) -> io::Result<Self> {
        spec.validate()
            .map_err(|_| io::Error::other("invalid audit delivery configuration"))?;
        Self::new(
            sink,
            spec.queue_capacity,
            Duration::from_millis(spec.ack_timeout_ms),
        )
    }

    /// An in-process worker is not an independently isolated audit service.
    /// The dispatcher accepts at most `queue_capacity` pending events; the
    /// caller cannot continue until the underlying sink acknowledges success.
    pub fn new(
        sink: Arc<dyn AuditSink>,
        queue_capacity: usize,
        ack_timeout: Duration,
    ) -> io::Result<Self> {
        if !(1..=256).contains(&queue_capacity)
            || ack_timeout.is_zero()
            || ack_timeout > Duration::from_secs(5)
        {
            return Err(io::Error::other("invalid bounded audit configuration"));
        }
        let (sender, receiver) = mpsc::sync_channel::<Delivery>(queue_capacity);
        let healthy = Arc::new(AtomicBool::new(true));
        let worker_health = Arc::clone(&healthy);
        thread::Builder::new()
            .name("hostmarshal-audit-writer".to_owned())
            .spawn(move || {
                while let Ok(delivery) = receiver.recv() {
                    if !worker_health.load(Ordering::SeqCst) {
                        let _ = delivery.committed.send(false);
                        break;
                    }
                    // This call may stall. It cannot block a caller beyond
                    // its configured acknowledgment deadline, but the OS
                    // thread itself cannot be forcibly cancelled safely.
                    let committed = sink.record(&delivery.event).is_ok();
                    if !committed {
                        worker_health.store(false, Ordering::SeqCst);
                    }
                    let _ = delivery.committed.send(committed);
                    if !committed {
                        break;
                    }
                }
            })?;
        Ok(Self {
            sender,
            healthy,
            ack_timeout,
        })
    }

    fn fail(&self) -> io::Error {
        self.healthy.store(false, Ordering::SeqCst);
        io::Error::other("audit delivery unavailable")
    }
}

impl AuditSink for BoundedAuditSink {
    fn record(&self, event: &AuditEvent) -> io::Result<()> {
        if !self.healthy.load(Ordering::SeqCst) {
            return Err(io::Error::other("audit delivery unavailable"));
        }
        // A bound on pending event *count* alone is not enough if upstream
        // identity fields are oversized.
        let encoded = serde_json::to_vec(event).map_err(|_| self.fail())?;
        if encoded.len() > MAX_EVENT_BYTES {
            return Err(self.fail());
        }
        let (committed, receipt) = mpsc::sync_channel(1);
        match self.sender.try_send(Delivery {
            event: event.clone(),
            committed,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                return Err(self.fail());
            }
        }
        match receipt.recv_timeout(self.ack_timeout) {
            Ok(true) if self.healthy.load(Ordering::SeqCst) => Ok(()),
            _ => Err(self.fail()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditContext, AuditPhase};
    use std::sync::{Mutex, mpsc::Receiver};

    fn sample() -> AuditEvent {
        AuditEvent::new(
            AuditContext {
                request_id: "bounded-1",
                issuer: "local://trusted-launcher",
                subject: "operator",
                capability: "inventory.inspect",
                operation: "builtin.inventory.inspect/v1",
                target: "host-a",
                snapshot_digest: "sha256:abc",
            },
            AuditPhase::Authorized,
            "explicit_grant",
        )
    }

    #[derive(Default)]
    struct Capture(Mutex<Vec<AuditEvent>>);

    impl AuditSink for Capture {
        fn record(&self, event: &AuditEvent) -> io::Result<()> {
            self.0.lock().unwrap().push(event.clone());
            Ok(())
        }
    }

    #[test]
    fn acknowledged_events_reach_the_underlying_sink_in_order() {
        let capture = Arc::new(Capture::default());
        let dispatcher =
            BoundedAuditSink::new(capture.clone(), 2, Duration::from_secs(2)).unwrap();
        let mut first = sample();
        let mut second = sample();
        first.request_id = "one".to_owned();
        second.request_id = "two".to_owned();
        dispatcher.record(&first).unwrap();
        dispatcher.record(&second).unwrap();
        let events = capture.0.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].request_id, "one");
        assert_eq!(events[1].request_id, "two");
    }

    struct Rejecting;
    impl AuditSink for Rejecting {
        fn record(&self, _event: &AuditEvent) -> io::Result<()> {
            Err(io::Error::other("injected writer failure"))
        }
    }

    #[test]
    fn worker_failure_latches_all_subsequent_commits_closed() {
        let dispatcher =
            BoundedAuditSink::new(Arc::new(Rejecting), 2, Duration::from_secs(2)).unwrap();
        assert!(dispatcher.record(&sample()).is_err());
        assert!(dispatcher.record(&sample()).is_err());
        assert!(!dispatcher.healthy.load(Ordering::SeqCst));
    }

    struct Blocked {
        started: SyncSender<()>,
        release: Mutex<Receiver<()>>,
    }
    impl AuditSink for Blocked {
        fn record(&self, _event: &AuditEvent) -> io::Result<()> {
            self.started.send(()).unwrap();
            self.release.lock().unwrap().recv().unwrap();
            Ok(())
        }
    }

    #[test]
    fn writer_stall_times_out_and_cannot_release_late_success() {
        let (started, entered) = mpsc::sync_channel(1);
        let (release, unblock) = mpsc::channel();
        let dispatcher = BoundedAuditSink::new(
            Arc::new(Blocked {
                started,
                release: Mutex::new(unblock),
            }),
            1,
            Duration::from_millis(40),
        )
        .unwrap();
        let caller = thread::spawn(move || {
            let first = dispatcher.record(&sample());
            // A delayed successful writer must not reopen the latch.
            assert!(first.is_err());
            assert!(dispatcher.record(&sample()).is_err());
            assert!(!dispatcher.healthy.load(Ordering::SeqCst));
        });
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        caller.join().unwrap();
        release.send(()).unwrap();
    }

    #[test]
    fn full_queue_fails_closed_instead_of_dropping_or_acknowledging() {
        let (started, entered) = mpsc::sync_channel(1);
        let (release, unblock) = mpsc::channel();
        let dispatcher = Arc::new(
            BoundedAuditSink::new(
                Arc::new(Blocked {
                    started,
                    release: Mutex::new(unblock),
                }),
                1,
                Duration::from_secs(2),
            )
            .unwrap(),
        );
        let caller_dispatcher = Arc::clone(&dispatcher);
        let caller = thread::spawn(move || caller_dispatcher.record(&sample()));
        // The worker has accepted the first event and is stalled inside the
        // sink; filling the one-slot queue is now deterministic.
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        let (committed, _receipt) = mpsc::sync_channel(1);
        assert!(dispatcher
            .sender
            .try_send(Delivery {
                event: sample(),
                committed,
            })
            .is_ok());
        assert!(dispatcher.record(&sample()).is_err());
        assert!(!dispatcher.healthy.load(Ordering::SeqCst));
        release.send(()).unwrap();
        assert!(caller.join().unwrap().is_err());
    }

    #[test]
    fn oversize_event_fails_closed_without_writer_use() {
        let capture = Arc::new(Capture::default());
        let dispatcher =
            BoundedAuditSink::new(capture.clone(), 1, Duration::from_secs(1)).unwrap();
        let mut event = sample();
        event.subject = "a".repeat(MAX_EVENT_BYTES);
        assert!(dispatcher.record(&event).is_err());
        assert!(dispatcher.record(&sample()).is_err());
        assert!(capture.0.lock().unwrap().is_empty());
    }

    #[test]
    fn strict_operator_configuration_rejects_unknown_and_unsafe_bounds() {
        let good = r#"{"apiVersion":"hostmarshal.io/audit-delivery/v1alpha1","queueCapacity":8,"ackTimeoutMs":1000}"#;
        let parsed: AuditDeliverySpec = serde_json::from_str(good).unwrap();
        assert!(parsed.validate().is_ok());
        for invalid in [
            r#"{"apiVersion":"hostmarshal.io/audit-delivery/v1alpha1","queueCapacity":0,"ackTimeoutMs":1000}"#,
            r#"{"apiVersion":"hostmarshal.io/audit-delivery/v1alpha1","queueCapacity":8,"ackTimeoutMs":0}"#,
            r#"{"apiVersion":"hostmarshal.io/audit-delivery/v1alpha1","queueCapacity":8,"ackTimeoutMs":1000,"unsafeFallback":true}"#,
        ] {
            match serde_json::from_str::<AuditDeliverySpec>(invalid) {
                Ok(config) => assert!(config.validate().is_err()),
                Err(_) => {}
            }
        }
    }
}
