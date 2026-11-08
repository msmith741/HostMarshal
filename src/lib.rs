//! HostMarshal capability core and MCP interfaces.
//! Only vetted read-only host observations are available in pre-alpha.
pub mod adapter;
pub mod audit;
pub mod audit_delivery;
pub mod audit_evidence;
pub mod authorization;
pub mod credentials;
pub mod declarative;
pub mod dynamic_mcp;
pub mod identity;
pub mod observation;
pub mod runtime;
pub mod schema;
pub mod snapshot;
pub mod transport;

pub mod provider_router;
pub mod remote_auth;
pub mod remote_http;
mod vault_auth;
pub mod vault_ssh;
