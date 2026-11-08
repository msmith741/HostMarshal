#[cfg(unix)]
use std::path::PathBuf;
use std::{env, path::Path, sync::Arc};

use anyhow::{Result, bail};
use hostmarshal::{
    audit::{AuditSink, JsonlFileAudit, StderrAudit},
    audit_delivery::{AuditDeliverySpec, BoundedAuditSink},
    audit_evidence::{self, EvidenceFileAudit},
    authorization::{AuthorizationRequest, Authorizer, GrantAuthorizer},
    credentials::{CredentialBroker, DenyCredentialBroker, LocalSshKeyBroker},
    declarative::CompiledConfig,
    dynamic_mcp::DeclarativeMcp,
    identity::AuthenticatedCaller,
    remote_auth::RemoteJwtVerifier,
    remote_http,
    runtime::ExecutionCoordinator,
    snapshot::ConfigStore,
    vault_ssh::VaultSshCertificateBroker,
};
use rmcp::{ServiceExt, transport::stdio};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [command, validate, directory] if command == "config" && validate == "validate" => {
            let config = CompiledConfig::load(Path::new(directory))?;
            eprintln!(
                "valid configuration: {} hosts, {} capabilities, {} grants; digest {}",
                config.hosts.len(),
                config.capabilities.len(),
                config.grants.len(),
                config.snapshot_digest
            );
            Ok(())
        }
        [command, inspect, directory] if command == "config" && inspect == "inspect" => {
            let config = CompiledConfig::load(Path::new(directory))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "apiVersion": "hostmarshal.io/v1alpha1",
                    "snapshotDigest": config.snapshot_digest,
                    "hosts": config.hosts.len(),
                    "capabilities": config.capabilities.len(),
                    "grants": config.grants.len(),
                }))?
            );
            Ok(())
        }
        [audit, verify, path, opts @ ..] if audit == "audit" && verify == "verify" => {
            let expected = match opts {
                [] => None,
                [flag, head] if flag == "--expected-head" => Some(head.as_str()),
                _ => bail!("usage: hostmarshal audit verify <path> [--expected-head <hex>]"),
            };
            let head = audit_evidence::verify(Path::new(path), expected)?;
            println!("{}", serde_json::to_string_pretty(&head)?);
            Ok(())
        }
        [command, schema] if command == "config" && schema == "schema" => {
            println!("{}", hostmarshal::schema::resource_schema_json()?);
            Ok(())
        }
        [
            policy,
            explain,
            directory,
            subject_flag,
            subject,
            capability_flag,
            capability,
            target_flag,
            target,
        ] if policy == "policy"
            && explain == "explain"
            && subject_flag == "--subject"
            && capability_flag == "--capability"
            && target_flag == "--target" =>
        {
            // Offline local diagnostic. The caller does NOT gain execution authority.
            // Only operators allowed to read the configuration should run this.
            let snapshot = CompiledConfig::load(Path::new(directory))?;
            let caller = AuthenticatedCaller::from_trusted_launcher(subject)?;
            let operation = snapshot
                .capabilities
                .get(capability.as_str())
                .map(|cap| cap.operation_ref.as_str())
                .unwrap_or("<unresolved>");
            let allowed = GrantAuthorizer
                .authorize(AuthorizationRequest {
                    snapshot: &snapshot,
                    caller: &caller,
                    capability,
                    operation,
                    target,
                })
                .permitted();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "apiVersion": "hostmarshal.io/v1alpha1",
                    "subject": caller.subject(),
                    "issuer": caller.issuer(),
                    "capability": capability,
                    "operation": operation,
                    "target": target,
                    "allowed": allowed,
                    "reason": if allowed { "explicit_grant" } else { "not_authorized" },
                    "snapshotDigest": snapshot.snapshot_digest,
                    "diagnosticOnly": true,
                }))?
            );
            Ok(())
        }
        [
            http,
            listen_flag,
            address,
            config_flag,
            directory,
            auth_flag,
            auth_file,
            options @ ..,
        ] if http == "http"
            && listen_flag == "--listen"
            && config_flag == "--config-dir"
            && auth_flag == "--auth-config" =>
        {
            let mut audit_file = None;
            let mut audit_evidence = None;
            let mut audit_delivery = None;
            let mut ssh_map = None;
            let mut vault_ssh = None;
            let mut remaining = options;
            while !remaining.is_empty() {
                let [flag, value, rest @ ..] = remaining else {
                    bail!("missing HTTP server option value");
                };
                match flag.as_str() {
                    "--audit-log" if audit_file.is_none() => audit_file = Some(value.as_str()),
                    "--audit-evidence-log" if audit_evidence.is_none() => {
                        audit_evidence = Some(value.as_str());
                    }
                    "--audit-delivery-config" if audit_delivery.is_none() => {
                        audit_delivery = Some(value.as_str());
                    }
                    "--ssh-credential-map" if ssh_map.is_none() => ssh_map = Some(value.as_str()),
                    "--vault-ssh-config" if vault_ssh.is_none() => vault_ssh = Some(value.as_str()),
                    _ => bail!("unknown or repeated HTTP server option"),
                };
                remaining = rest;
            }
            serve_remote_http(
                address,
                directory,
                auth_file,
                audit_file,
                audit_evidence,
                audit_delivery,
                ssh_map,
                vault_ssh,
            )
            .await
        }
        [flag, directory, principal_flag, principal, rest @ ..]
            if flag == "--config-dir" && principal_flag == "--principal" =>
        {
            let mut audit_path = None;
            let mut audit_evidence = None;
            let mut audit_delivery = None;
            let mut ssh_map = None;
            let mut vault_ssh = None;
            let mut remaining = rest;
            while !remaining.is_empty() {
                let [option, value, tail @ ..] = remaining else {
                    bail!("expected a value after a server option");
                };
                match option.as_str() {
                    "--audit-log" if audit_path.is_none() => audit_path = Some(value.as_str()),
                    "--audit-evidence-log" if audit_evidence.is_none() => {
                        audit_evidence = Some(value.as_str());
                    }
                    "--audit-delivery-config" if audit_delivery.is_none() => {
                        audit_delivery = Some(value.as_str());
                    }
                    "--ssh-credential-map" if ssh_map.is_none() => ssh_map = Some(value.as_str()),
                    "--vault-ssh-config" if vault_ssh.is_none() => vault_ssh = Some(value.as_str()),
                    _ => bail!("unknown or duplicate server option"),
                };
                remaining = tail;
            }
            serve_declarative(
                directory,
                principal,
                audit_path,
                audit_evidence,
                audit_delivery,
                ssh_map,
                vault_ssh,
            )
            .await
        }
        _ => bail!(
            "usage: hostmarshal config validate <directory> | \
             hostmarshal config inspect <directory> | \
             hostmarshal config schema | \
             hostmarshal audit verify <path> [--expected-head <hex>] | \
             hostmarshal policy explain <directory> --subject <launcher-subject> \
                 --capability <name> --target <host-id> | \
             hostmarshal http --listen <127.0.0.1:port> --config-dir <directory> \
                 --auth-config <protected-json-file> [--audit-log <file> | --audit-evidence-log <file>] \
                 [--audit-delivery-config <protected-json-file>] \
                 [--ssh-credential-map <file> | --vault-ssh-config <file>] | \
             hostmarshal --config-dir <directory> --principal <trusted-launcher-subject> \
             [--audit-log <protected-file-path> | --audit-evidence-log <file>] \
             [--audit-delivery-config <protected-json-file>] \
             [--ssh-credential-map <protected-json-file> | --vault-ssh-config <file>] | \
             Use YAML resources; legacy --config JSON mode has been retired"
        ),
    }
}

async fn serve_declarative(
    directory: &str,
    principal: &str,
    audit_path: Option<&str>,
    evidence_path: Option<&str>,
    audit_delivery: Option<&str>,
    ssh_map: Option<&str>,
    vault_ssh: Option<&str>,
) -> Result<()> {
    // Caller identity and audit destination are bound by the trusted launcher.
    // No MCP message can choose or modify either value.
    let caller = AuthenticatedCaller::from_trusted_launcher(principal)?;
    let config = CompiledConfig::load(Path::new(directory))?;
    let audit = open_audit(audit_path, evidence_path, audit_delivery)?;
    let broker = choose_broker(&config, ssh_map, vault_ssh, Arc::clone(&audit))?;
    let store = Arc::new(ConfigStore::new(config));
    let runtime = Arc::new(ExecutionCoordinator::new(Arc::clone(&store), broker, audit));
    #[cfg(unix)]
    register_reload_signals(Arc::clone(&store), PathBuf::from(directory))?;
    #[cfg(not(unix))]
    eprintln!("hostmarshal: signal reload unavailable; restart required");
    let server = DeclarativeMcp::new(runtime, caller).serve(stdio()).await?;
    server.waiting().await?;
    Ok(())
}

#[cfg(unix)]
fn register_reload_signals(store: Arc<ConfigStore>, directory: PathBuf) -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    // Only the host OS can authorize signals in this stdio deployment mode.
    // A client cannot select a config directory, signal or new principal.
    let mut hangup = signal(SignalKind::hangup())?;
    let mut emergency = signal(SignalKind::user_defined1())?;
    tokio::spawn(async move {
        loop {
            tokio::select! {
                received = hangup.recv() => {
                    if received.is_none() {
                        break;
                    }
                    match store.reload(&directory) {
                        Ok(outcome) => eprintln!("hostmarshal: reload {outcome:?}"),
                        Err(error) => eprintln!(
                            "hostmarshal: reload rejected; last valid snapshot retained: {error:#}"
                        ),
                    }
                }
                received = emergency.recv() => {
                    if received.is_none() {
                        break;
                    }
                    match store.lockdown() {
                        Ok(()) => eprintln!("hostmarshal: emergency lockdown active"),
                        Err(error) => eprintln!("hostmarshal: lockdown error: {error:#}"),
                    }
                }
            }
        }
    });
    Ok(())
}

async fn serve_remote_http(
    listen: &str,
    directory: &str,
    auth_file: &str,
    audit_path: Option<&str>,
    evidence_path: Option<&str>,
    audit_delivery: Option<&str>,
    ssh_map: Option<&str>,
    vault_ssh: Option<&str>,
) -> Result<()> {
    use std::net::SocketAddr;

    let address: SocketAddr = listen.parse()?;
    // Bind loopback only. External clients must come through a separately
    // secured TLS reverse proxy; no X-Forwarded-User authentication shortcut.
    anyhow::ensure!(
        address.ip().is_loopback(),
        "HTTP MCP must listen on loopback"
    );
    let verifier = Arc::new(RemoteJwtVerifier::load(Path::new(auth_file))?);
    verifier.validate_authorization_server().await?;
    let config = CompiledConfig::load(Path::new(directory))?;
    let audit = open_audit(audit_path, evidence_path, audit_delivery)?;
    let broker = choose_broker(&config, ssh_map, vault_ssh, Arc::clone(&audit))?;
    let store = Arc::new(ConfigStore::new(config));
    let runtime = Arc::new(ExecutionCoordinator::new(Arc::clone(&store), broker, audit));
    #[cfg(unix)]
    register_reload_signals(store, PathBuf::from(directory))?;
    remote_http::serve_loopback(address, runtime, verifier).await
}

/// Only the trusted launcher can choose the delivery policy and sink.
/// Neither MCP requests nor YAML grants can supply delivery destinations.
fn open_audit(
    audit_path: Option<&str>,
    evidence_path: Option<&str>,
    delivery_config: Option<&str>,
) -> Result<Arc<dyn AuditSink>> {
    anyhow::ensure!(
        audit_path.is_none() || evidence_path.is_none(),
        "audit destinations are mutually exclusive"
    );
    let sink: Arc<dyn AuditSink> = match (audit_path, evidence_path) {
        (Some(path), None) => Arc::new(JsonlFileAudit::open(Path::new(path))?),
        (None, Some(path)) => Arc::new(EvidenceFileAudit::open(Path::new(path))?),
        (None, None) => Arc::new(StderrAudit),
        (Some(_), Some(_)) => unreachable!("exclusive audit destinations enforced"),
    };
    match delivery_config {
        Some(path) => {
            let spec = AuditDeliverySpec::load(Path::new(path))?;
            Ok(Arc::new(BoundedAuditSink::from_spec(sink, &spec)?))
        }
        None => Ok(sink),
    }
}

fn choose_broker(
    config: &CompiledConfig,
    ssh_map: Option<&str>,
    vault_ssh: Option<&str>,
    audit: Arc<dyn AuditSink>,
) -> Result<Arc<dyn CredentialBroker>> {
    anyhow::ensure!(
        ssh_map.is_none() || vault_ssh.is_none(),
        "choose exactly one SSH credential source; no fallback is permitted"
    );
    match (ssh_map, vault_ssh) {
        (Some(path), None) => Ok(Arc::new(LocalSshKeyBroker::load(Path::new(path))?)),
        (None, Some(path)) => Ok(Arc::new(VaultSshCertificateBroker::load(
            Path::new(path),
            config,
            audit,
        )?)),
        (None, None) => Ok(Arc::new(DenyCredentialBroker)),
        (Some(_), Some(_)) => unreachable!("conflicting sources rejected"),
    }
}
