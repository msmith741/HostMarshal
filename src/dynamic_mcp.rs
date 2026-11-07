//! Declarative MCP transport adapter. Security decisions remain in CompiledConfig.
//! M1: builtin inventory only, trusted local launcher identity only.
use std::sync::Arc;

use rmcp::{
    ErrorData as McpError, ServerHandler,
    model::{
        CacheScope, CallToolRequestParams, CallToolResponse, CallToolResult,
        ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool,
    },
    service::{RequestContext, RoleServer},
};
use serde_json::Value;

use crate::declarative::{CompiledConfig, PublishedCapability};

#[derive(Clone)]
pub struct DeclarativeMcp {
    config: Arc<CompiledConfig>,
    principal: String,
}

impl DeclarativeMcp {
    pub fn new(config: CompiledConfig, principal: String) -> Self {
        Self { config: Arc::new(config), principal }
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

    fn authorized_tool(&self, name: &str) -> Option<Tool> {
        let cap = self.config.capabilities.get(name)?;
        self.config
            .visible_capabilities(&self.principal)
            .iter()
            .any(|visible| visible.name == name)
            .then(|| self.definition(cap))
    }
}

impl ServerHandler for DeclarativeMcp {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.authorized_tool(name)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let tools = self.config
            .visible_capabilities(&self.principal)
            .into_iter()
            .map(|cap| self.definition(cap))
            .collect();
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
        if self.authorized_tool(name).is_none() {
            return Ok(CallToolResult::error(vec![rmcp::model::ContentBlock::text(
                "capability not found or not authorized",
            )]).into());
        }
        let args = Value::Object(request.arguments.unwrap_or_default());
        let result = match self.config.invoke(&self.principal, name, args) {
            Ok(data) => CallToolResult::structured(data),
            Err(_) => CallToolResult::error(vec![rmcp::model::ContentBlock::text(
                "input invalid or target not authorized",
            )]),
        };
        Ok(result.into())
    }
}
