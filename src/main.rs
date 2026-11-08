#[cfg(unix)]
use std::path::PathBuf;
use std::{env, path::Path, sync::Arc};

use anyhow::{Result, bail};
use hostmarshal::{
    audit::{AuditSink, JsonlFileAudit, StderrAudit},
    authorization::{AuthorizationRequest, Authorizer, GrantAuthorizer},
    credentials::{CredentialBroker, DenyCredentialBroker, LocalSshKeyBroker},
    declarative::CompiledConfig,
    dynamic_mcp::DeclarativeMcp,
    identity::AuthenticatedCaller,
    remote_auth::RemoteJwtVerifier,
    remote_http,
    runtime::ExecutionCoordinator,
    snapshot::ConfigStore,
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
            let mut ssh_map = None;
            let mut remaining = options;
            while !remaining.is_empty() {
                let [flag, value, rest @ ..] = remaining else {
                    bail!("missing HTTP server option value");
                };
                match flag.as_str() {
                    "--audit-log" if audit_file.is_none() => audit_file = Some(value.as_str()),
                    "--ssh-credential-map" if ssh_map.is_none() => ssh_map = Some(value.as_str()),
                    _ => bail!("unknown or repeated HTTP server option"),
                };
                remaining = rest;
            }
            serve_remote_http(address, directory, auth_file, audit_file, ssh_map).await
        }
        [flag, directory, principal_flag, principal, rest @ ..]
            if flag == "--config-dir" && principal_flag == "--principal" =>
        {
            let mut audit_path = None;
            let mut ssh_map = None;
            let mut remaining = rest;
            while !remaining.is_empty() {
                let [option, value, tail @ ..] = remaining else {
                    bail!("expected a value after a server option");
                };
                match option.as_str() {
                    "--audit-log" if audit_path.is_none() => audit_path = Some(value.as_str()),
                    "--ssh-credential-map" if ssh_map.is_none() => ssh_map = Some(value.as_str()),
                    _ => bail!("unknown or duplicate server option"),
                };
                remaining = tail;
            }
            serve_declarative(directory, principal, audit_path, ssh_map).await
        }
        _ => bail!(
            "usage: hostmarshal config validate <directory> | \
             hostmarshal config inspect <directory> | \
             hostmarshal config schema | \
             hostmarshal policy explain <directory> --subject <launcher-subject> \
                 --capability <name> --target <host-id> | \
             hostmarshal http --listen <127.0.0.1:port> --config-dir <directory> \
                 --auth-config <protected-json-file> [--audit-log <file>] \
                 [--ssh-credential-map <file>] | \
             hostmarshal --config-dir <directory> --principal <trusted-launcher-subject> \
             [--audit-log <protected-file-path>] \
             [--ssh-credential-map <protected-json-file>] | \
             Use YAML resources; legacy --config JSON mode has been retired"
        ),
    }
}

async fn serve_declarative(
    directory: &str,
    principal: &str,
    audit_path: Option<&str>,
    ssh_map: Option<&str>,
) -> Result<()> {
    // Caller identity and audit destination are bound by the trusted launcher.
    // No MCP message can choose or modify either value.
    let caller = AuthenticatedCaller::from_trusted_launcher(principal)?;
    let config = CompiledConfig::load(Path::new(directory))?;
    let store = Arc::new(ConfigStore::new(config));
    let audit: Arc<dyn AuditSink> = match audit_path {
        Some(path) => Arc::new(JsonlFileAudit::open(Path::new(path))?),
        None => Arc::new(StderrAudit),
    };
    let broker: Arc<dyn CredentialBroker> = match ssh_map {
        Some(path) => Arc::new(LocalSshKeyBroker::load(Path::new(path))?),
        None => Arc::new(DenyCredentialBroker),
    };
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
    ssh_map: Option<&str>,
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
    let config = CompiledConfig::load(Path::new(directory))?;
    let store = Arc::new(ConfigStore::new(config));
    let audit: Arc<dyn AuditSink> = match audit_path {
        Some(path) => Arc::new(JsonlFileAudit::open(Path::new(path))?),
        None => Arc::new(StderrAudit),
    };
    let broker: Arc<dyn CredentialBroker> = match ssh_map {
        Some(path) => Arc::new(LocalSshKeyBroker::load(Path::new(path))?),
        None => Arc::new(DenyCredentialBroker),
    };
    let runtime = Arc::new(ExecutionCoordinator::new(Arc::clone(&store), broker, audit));
    #[cfg(unix)]
    register_reload_signals(store, PathBuf::from(directory))?;
    remote_http::serve_loopback(address, runtime, verifier).await
}
