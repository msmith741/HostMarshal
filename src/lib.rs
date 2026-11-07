//! HostMarshal capability core and MCP interfaces.
//! Live host access is deliberately not implemented in pre-alpha.
pub mod config;
pub mod declarative;
pub mod dynamic_mcp;
pub mod policy;
pub mod schema;
pub mod snapshot;

use std::sync::Arc;

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, ContentBlock},
    schemars, tool, tool_router,
};
use serde::Deserialize;

use crate::{config::Config, policy::Policy};

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct GetHostArgs {
    /// Exact inventory identifier for the host to read.
    host_id: String,
}

/// Legacy pre-alpha JSON mode, available temporarily for migration.
#[derive(Clone)]
pub struct HostMarshal {
    policy: Arc<Policy>,
}

impl HostMarshal {
    pub fn new(config: Config) -> Self {
        Self {
            policy: Arc::new(Policy::new(config)),
        }
    }
}

#[tool_router(server_handler)]
impl HostMarshal {
    #[tool(
        description = "List only hosts the configured principal can enumerate. Static inventory only; does not contact hosts."
    )]
    fn list_hosts(&self) -> String {
        serde_json::to_string(&self.policy.visible_hosts()).unwrap_or_else(|_| "[]".into())
    }

    #[tool(
        description = "Read static inventory metadata for one authorized host. Does not execute commands or contact the host."
    )]
    fn get_host(&self, Parameters(args): Parameters<GetHostArgs>) -> CallToolResult {
        match self.policy.get_host(&args.host_id) {
            Some(host) => match serde_json::to_string(&host) {
                Ok(data) => CallToolResult::success(vec![ContentBlock::text(data)]),
                Err(_) => {
                    CallToolResult::error(vec![ContentBlock::text("unable to encode result")])
                }
            },
            None => {
                CallToolResult::error(vec![ContentBlock::text("host not found or not authorized")])
            }
        }
    }
}
