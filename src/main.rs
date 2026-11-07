#[cfg(unix)]
use std::path::PathBuf;
use std::{env, path::Path, sync::Arc};

use anyhow::{Result, bail};
use hostmarshal::{
    audit::{AuditSink, JsonlFileAudit, StderrAudit},
    authorization::{AuthorizationRequest, Authorizer, GrantAuthorizer},
    credentials::DenyCredentialBroker,
    declarative::CompiledConfig,
    dynamic_mcp::DeclarativeMcp,
    identity::AuthenticatedCaller,
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
        [flag, directory, principal_flag, principal]
            if flag == "--config-dir" && principal_flag == "--principal" =>
        {
            serve_declarative(directory, principal, None).await
        }
        [
            flag,
            directory,
            principal_flag,
            principal,
            audit_flag,
            audit_path,
        ] if flag == "--config-dir"
            && principal_flag == "--principal"
            && audit_flag == "--audit-log" =>
        {
            serve_declarative(directory, principal, Some(audit_path)).await
        }
        _ => bail!(
            "usage: hostmarshal config validate <directory> | \
             hostmarshal config inspect <directory> | \
             hostmarshal config schema | \
             hostmarshal policy explain <directory> --subject <launcher-subject> \
                 --capability <name> --target <host-id> | \
             hostmarshal --config-dir <directory> --principal <trusted-launcher-subject> \
             [--audit-log <protected-file-path>] | \
             Use YAML resources; legacy --config JSON mode has been retired"
        ),
    }
}

async fn serve_declarative(
    directory: &str,
    principal: &str,
    audit_path: Option<&str>,
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
    let runtime = Arc::new(ExecutionCoordinator::new(
        Arc::clone(&store),
        Arc::new(DenyCredentialBroker),
        audit,
    ));
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
