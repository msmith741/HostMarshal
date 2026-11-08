//! Loopback-only authenticated MCP Streamable HTTP transport.
//! Middleware cryptographically validates every request before the SDK sees it.
use std::{net::SocketAddr, sync::Arc};

use anyhow::{Result, ensure};
use axum::{
    Router,
    extract::{Request, State},
    http::{Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use rmcp::{
    ErrorData as McpError, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResponse, ListToolsResult, PaginatedRequestParams,
        RoleServer, ServerCapabilities, ServerConfig, Tool,
    },
    service::RequestContext,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
        session::local::LocalSessionManager,
    },
};
use tower_http::limit::RequestBodyLimitLayer;

use crate::{
    dynamic_mcp::DeclarativeMcp,
    identity::AuthenticatedCaller,
    remote_auth::RemoteJwtVerifier,
    runtime::ExecutionCoordinator,
};

#[derive(Clone)]
pub struct AuthenticatedRemoteMcp {
    runtime: Arc<ExecutionCoordinator>,
}

impl AuthenticatedRemoteMcp {
    /// The SDK receives request Parts with the trusted middleware-created
    /// caller in extensions. An absent caller always denies.
    fn caller(context: &RequestContext<RoleServer>) -> Result<AuthenticatedCaller, McpError> {
        context
            .extensions
            .get::<axum::http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<AuthenticatedCaller>())
            .cloned()
            .ok_or_else(|| McpError::invalid_params("authenticated request context required", None))
    }
}

impl ServerHandler for AuthenticatedRemoteMcp {
    fn get_info(&self) -> ServerConfig {
        let mut info = ServerConfig::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info
    }

    // Without authenticated RequestContext, this must not reveal any tools.
    fn get_tool(&self, _name: &str) -> Option<Tool> {
        None
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let caller = Self::caller(&context)?;
        DeclarativeMcp::new(Arc::clone(&self.runtime), caller)
            .list_tools(request, context)
            .await
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let caller = Self::caller(&context)?;
        DeclarativeMcp::new(Arc::clone(&self.runtime), caller)
            .call_tool(request, context)
            .await
    }
}

async fn require_bearer(
    State(verifier): State<Arc<RemoteJwtVerifier>>,
    mut request: Request,
    next: Next,
) -> Response {
    // HTTP is intentionally loopback-only; TLS must be enforced by a locally
    // controlled reverse proxy. Never accept X-Forwarded-* as identity.
    if request.method() != Method::POST {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let host = request.headers().get(header::HOST).and_then(|v| v.to_str().ok());
    if host != Some(verifier.allowed_host()) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if request.headers().contains_key(header::ORIGIN) {
        // Browser access is not supported; avoid cross-origin bearer misuse.
        return StatusCode::FORBIDDEN.into_response();
    }
    let mut bearer_values = request.headers().get_all(header::AUTHORIZATION).iter();
    let authorization = bearer_values.next().and_then(|value| value.to_str().ok());
    if bearer_values.next().is_some() {
        return unauthorized();
    }
    let Some(authorization) = authorization else {
        return unauthorized();
    };
    let caller = match verifier.authenticate_header(authorization) {
        Ok(identity) => identity,
        Err(_) => return unauthorized(),
    };
    // Insert an authenticated identity into HTTP request extensions. rmcp's
    // HTTP transport carries it into each JSON-RPC request's RequestContext.
    request.extensions_mut().insert(caller);
    next.run(request).await
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer realm=\"hostmarshal\", error=\"invalid_token\"")],
        "authentication required",
    ).into_response()
}

pub async fn serve_loopback(
    address: SocketAddr,
    runtime: Arc<ExecutionCoordinator>,
    verifier: Arc<RemoteJwtVerifier>,
) -> Result<()> {
    ensure!(address.ip().is_loopback(), "remote HTTP listener must bind loopback only");
    let service = StreamableHttpService::new(
        move || Ok(AuthenticatedRemoteMcp { runtime: Arc::clone(&runtime) }),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default()
            .with_legacy_session_mode(false)
            .with_json_response(true),
    );
    let router = Router::new()
        .nest_service("/mcp", service)
        .layer(RequestBodyLimitLayer::new(256 * 1024))
        .layer(middleware::from_fn_with_state(verifier, require_bearer));

    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, router).await?;
    Ok(())
}
