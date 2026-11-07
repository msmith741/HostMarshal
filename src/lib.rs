//! HostMarshal capability core and MCP interfaces.
//! All live operations use the audited, authorized M2 runtime.
pub mod adapter;
pub mod audit;
pub mod authorization;
pub mod credentials;
pub mod declarative;
pub mod dynamic_mcp;
pub mod identity;
pub mod http_auth;
pub mod http_server;
pub mod observation;
pub mod runtime;
pub mod schema;
pub mod snapshot;
pub mod transport;
pub mod vault;
