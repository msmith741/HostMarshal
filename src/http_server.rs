//! Authenticated, stateless Streamable HTTP MCP resource server (FR-018/019).
//! Binds ONLY to loopback; an independent co-located TLS reverse proxy is REQUIRED.
use std::{net::SocketAddr, sync::Arc};

use anyhow::{Result, ensure};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderValue, Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};

use crate::{dynamic_mcp::DeclarativeMcp, http_auth::JwtVerifier, runtime::ExecutionCoordinator};

async fn authenticate_request(
    State(verifier): State<Arc<JwtVerifier>>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    // A proxy must not forward HTTP Authorization, Origin or query material
    // from an untrusted source without the mandatory TLS boundary.
    let headers = request.headers();
    let count = headers.get_all(header::AUTHORIZATION).iter().count();
    let auth = (count == 1)
        .then(|| headers.get(header::AUTHORIZATION))
        .flatten()
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let origin_valid = match headers.get(header::ORIGIN) {
        None => true,
        Some(v) => v
            .to_str()
            .ok()
            .and_then(|origin| url::Url::parse(origin).ok())
            .is_some_and(|origin| {
                let Ok(resource) = url::Url::parse(verifier.resource()) else {
                    return false;
                };
                origin.scheme() == resource.scheme()
                    && origin.host_str() == resource.host_str()
                    && origin.port_or_known_default() == resource.port_or_known_default()
            }),
    };
    let caller = if origin_valid && request.uri().query().is_none() {
        auth.and_then(|bearer| verifier.authenticate(bearer).ok())
    } else {
        None
    };
    let Some(caller) = caller else {
        return unauthorized(&verifier);
    };
    request.extensions_mut().insert(caller);
    let mut result = next.run(request).await;
    result
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    result
}

fn unauthorized(verifier: &JwtVerifier) -> Response {
    let mut response = (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    if let Ok(value) = HeaderValue::from_str(&verifier.challenge()) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn protected_resource_metadata(State(verifier): State<Arc<JwtVerifier>>) -> Response {
    let mut response = Json(verifier.metadata()).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub async fn serve(
    bind: SocketAddr,
    runtime: Arc<ExecutionCoordinator>,
    verifier: Arc<JwtVerifier>,
) -> Result<()> {
    ensure!(
        bind.ip().is_loopback(),
        "HTTP backend must bind to loopback; use a co-located HTTPS proxy"
    );
    // Both modern and legacy clients are stateless: no authenticated session
    // survives across HTTP requests or between bearer token principals.
    let mcp = StreamableHttpService::new(
        move || Ok(DeclarativeMcp::for_authenticated_http(Arc::clone(&runtime))),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default()
            .with_legacy_session_mode(false)
            .with_json_response(true),
    );
    let protected = Router::new()
        .nest_service("/mcp", mcp)
        .layer(middleware::from_fn_with_state(
            Arc::clone(&verifier),
            authenticate_request,
        ));
    let router = Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(protected_resource_metadata),
        )
        .with_state(Arc::clone(&verifier))
        .merge(protected);
    let tcp = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(tcp, router).await?;
    Ok(())
}
