//! Declarative MCP transport adapter. Security decisions remain in CompiledConfig.
//! M1: builtin inventory only, trusted local launcher identity only.
use std::sync::Arc;

use rmcp::{
    ErrorData as McpError, ServerHandler,
    model::{
        CacheScope, CallToolRequestParams, CallToolResponse, CallToolResult, ListToolsResult,
        PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
    },
    service::{RequestContext, RoleServer},
};
use serde_json::Value;

use crate::{declarative::{CompiledConfig, PublishedCapability}, snapshot::ConfigStore};

#[derive(Clone)]
pub struct DeclarativeMcp {
    store: Arc<ConfigStore>,
    principal: String,
}

impl DeclarativeMcp {
    pub fn new(store: Arc<ConfigStore>, principal: String) -> Self {
        Self {
            store,
            principal,
        }
    }

    fn definition(&self, cap: &PublishedCapability) -> Tool {
        let input = cap.input_schema.as_object().cloned().unwrap_or_default();
        let output = cap.output_schema.as_object().cloned().unwrap_or_default();
        Tool::new(
            cap.name.clone(),
            "Read authorized static inventory metadata (no network or process execution)",
            Arc::new(input),
        )
        .with_raw_output_schema(Arc::new(output))
    }

    fn authorized_tool(&self, snapshot: &CompiledConfig, name: &str) -> Option<Tool> {
        let cap = snapshot.capabilities.get(name)?;
        snapshot
            .visible_capabilities(&self.principal)
            .iter()
            .any(|visible| visible.name == name)
            .then(|| self.definition(cap))
    }
}

impl ServerHandler for DeclarativeMcp {
    fn get_info(&self) -> ServerConfig {
        let mut info = ServerConfig::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        let snapshot = self.store.snapshot()?;
        self.authorized_tool(&snapshot, name)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let tools = self
            .store
            .snapshot()
            .map(|snapshot| {
                snapshot
                    .visible_capabilities(&self.principal)
                    .into_iter()
                    .map(|cap| self.definition(cap))
                    .collect()
            })
            .unwrap_or_default();
        Ok(ListToolsResult::with_all_items(tools)
            .with_ttl_ms(0)
            .with_cache_scope(CacheScope::Private))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        // Do not disclose whether a hidden/unapproved capability exists.
        let name = request.name.as_ref();
        // Evaluate visibility and invoke against the *same* snapshot to prevent
        // mixing policy from one generation with inventory from another.
        let Some(snapshot) = self.store.snapshot() else {
            return Ok(CallToolResult::error(vec![rmcp::model::ContentBlock::text(
                "capability not found or not authorized",
            )]).into());
        };
        if self.authorized_tool(&snapshot, name).is_none() {
            return Ok(CallToolResult::error(vec![rmcp::model::ContentBlock::text(
                "capability not found or not authorized",
            )])
            .into());
        }
        let args = Value::Object(request.arguments.unwrap_or_default());
        let result = match snapshot.invoke(&self.principal, name, args) {
            Ok(data) => CallToolResult::structured(data),
            Err(_) => CallToolResult::error(vec![rmcp::model::ContentBlock::text(
                "input invalid or target not authorized",
            )]),
        };
        Ok(result.into())
    }
}
