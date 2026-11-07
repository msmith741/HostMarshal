#[cfg(unix)]
use std::path::PathBuf;
use std::{env, path::Path, sync::Arc};

use anyhow::{Result, bail, ensure};
use hostmarshal::{
    HostMarshal, config::Config, declarative::CompiledConfig, dynamic_mcp::DeclarativeMcp,
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
            // This is an administrative local CLI operation, not an MCP tool.
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
        [flag, directory, principal_flag, principal]
            if flag == "--config-dir" && principal_flag == "--principal" =>
        {
            ensure!(
                !principal.is_empty()
                    && principal.len() <= 128
                    && principal
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_')),
                "invalid launcher principal"
            );
            // A trusted launcher must choose both directory and principal. MCP cannot change them.
            let config = CompiledConfig::load(Path::new(directory))?;
            let store = Arc::new(ConfigStore::new(config));
            #[cfg(unix)]
            register_reload_signals(Arc::clone(&store), PathBuf::from(directory))?;
            #[cfg(not(unix))]
            eprintln!("hostmarshal: signal reload unavailable; restart required");
            let server = DeclarativeMcp::new(store, principal.clone())
                .serve(stdio())
                .await?;
            server.waiting().await?;
            Ok(())
        }
        [flag, path] if flag == "--config" => {
            // Legacy pre-alpha JSON mode retained temporarily for migration.
            let config = Config::load(Path::new(path))?;
            let server = HostMarshal::new(config).serve(stdio()).await?;
            server.waiting().await?;
            Ok(())
        }
        _ => bail!(
            "usage: hostmarshal config validate <directory> | \
             hostmarshal config inspect <directory> | \
             hostmarshal config schema | \
             hostmarshal --config-dir <directory> --principal <trusted-launcher-subject> | \
             hostmarshal --config <legacy-config.json>"
        ),
    }
}

#[cfg(unix)]
fn register_reload_signals(store: Arc<ConfigStore>, directory: PathBuf) -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    // OS-level process signaling is the *only* reload control for stdio mode.
    // A client cannot select a configuration path, signal, or new principal.
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
                        Ok(outcome) => {
                            eprintln!("hostmarshal: reload {outcome:?}");
                        }
                        Err(error) => {
                            eprintln!("hostmarshal: reload rejected; last valid snapshot retained: {error:#}");
                        }
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
