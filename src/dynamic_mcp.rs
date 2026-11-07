//! Declarative MCP transport. Invocation is always delegated to the audit-enforcing runtime.
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

use crate::{
    declarative::{CompiledConfig, PublishedCapability},
    identity::AuthenticatedCaller,
    runtime::ExecutionCoordinator,
};

#[derive(Clone)]
pub struct DeclarativeMcp {
    runtime: Arc<ExecutionCoordinator>,
    caller: AuthenticatedCaller,
}

impl DeclarativeMcp {
    pub fn new(runtime: Arc<ExecutionCoordinator>, caller: AuthenticatedCaller) -> Self {
        Self { runtime, caller }
    }

    fn definition(&self, cap: &PublishedCapability) -> Tool {
        let input = cap.input_schema.as_object().cloned().unwrap_or_default();
        let output = cap.output_schema.as_object().cloned().unwrap_or_default();
        Tool::new(
            cap.name.clone(),
            "Execute a bounded, authorized observation of a trusted inventory target",
            Arc::new(input),
        )
        .with_raw_output_schema(Arc::new(output))
    }

    fn authorized_tool(&self, snapshot: &CompiledConfig, name: &str) -> Option<Tool> {
        let cap = snapshot.capabilities.get(name)?;
        snapshot
            .visible_capabilities(self.caller.subject())
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
        let snapshot = self.runtime.store().snapshot()?;
        self.authorized_tool(&snapshot, name)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let tools = self
            .runtime
            .store()
            .snapshot()
            .map(|snapshot| {
                snapshot
                    .visible_capabilities_for(self.caller.issuer(), self.caller.subject())
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
        // Intentionally do not short-circuit hidden tool names: the coordinator
        // must record denied invocations as well as successful ones.
        let input = Value::Object(request.arguments.unwrap_or_default());
        let result = match self
            .runtime
            .invoke(&self.caller, request.name.as_ref(), input)
            .await
        {
            Ok(data) => CallToolResult::structured(data),
            Err(failure) => CallToolResult::error(vec![rmcp::model::ContentBlock::text(
                failure.public_message(),
            )]),
        };
        Ok(result.into())
    }
}
