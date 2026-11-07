use std::{env, path::Path};

use anyhow::{Result, bail};
use hostmarshal::{HostMarshal, config::Config};
use rmcp::{ServiceExt, transport::stdio};

#[tokio::main]
async fn main() -> Result<()> {
    // Process arguments and configuration must come from a trusted launcher.
    // Never allow a remote MCP client to choose a principal or configuration.
    let mut args = env::args().skip(1);
    let (Some(flag), Some(path), None) = (args.next(), args.next(), args.next()) else {
        bail!("usage: hostmarshal --config <trusted-config.json>");
    };
    if flag != "--config" {
        bail!("usage: hostmarshal --config <trusted-config.json>");
    }

    let config = Config::load(Path::new(&path))?;
    let server = HostMarshal::new(config).serve(stdio()).await?;
    server.waiting().await?;
    Ok(())
}
