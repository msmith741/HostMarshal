# Client protocols and identity

**Status:** stdio and M4 authenticated stateless MCP Streamable HTTP are implemented for approved read-only observations. A full OAuth authorization server, distributed multi-client sessions and full remote production hardening remain outside this pre-alpha scope.

## MCP posture

Target the stable [MCP 2026-07-28 specification](https://modelcontextprotocol.io/specification/2026-07-28) and retain tested compatibility with legacy `2025-11-25` clients where supported by the official [Rust SDK](https://github.com/modelcontextprotocol/rust-sdk). Different protocol versions have different initialization, session, discovery and caching semantics; **never assume the old initialize/initialized handshake is universal**.

- Dynamically generate tool definitions and JSON Schema 2020-12 contracts from a validated registry.
- Keep tool discovery deterministic and principal-filtered. Responses carrying policy-dependent information need subject-specific/private caching; invalidate when inventory/policy/capability changes.
- For Streamable HTTP, do not infer authorization solely from standardized routing headers; authenticate the bearer/channel and verify that headers match the parsed request.
- Treat `clientInfo`, descriptions, prompts, and client metadata as untrusted context, **not proof of identity**.
- Do not proxy OAuth/bearer tokens to targets. Use scoped credential broker identities for target API calls.
- Treat server discovery, request context, subscription/task semantics and legacy compatibility as protocol-adapter concerns. Core execution does not depend on sessions.

## Transports

- **stdio first:** fixed trusted launcher, process/OS identity binding, stdout reserved for protocol, stderr for redacted diagnostics. This is not cryptographic caller authentication.
- **authenticated MCP HTTP (M4):** strict pinned RSA JWT issuer/audience/signature/lifetime/scope verification, per-request identity and stateless protocol semantics, RFC9728 protected-resource metadata, enforced loopback binding. A colocated HTTPS proxy, rate limiting, egress controls and sender-constrained tokens remain external/future hardening requirements.
- **CLI:** direct invocations share the same validated security context, registry and runtime; a policy-explanation command may not impersonate a runtime caller.

## Policy changes during a stdio connection

M1 uses immutable per-request snapshots. On a successful Unix SIGHUP, a new tool discovery request returns the updated, authorization-filtered catalog. The SDK's catalog advertises private caching with `ttlMs: 0`; clients must not retain previously discovered capabilities as authorization. `tools/call` always checks the current snapshot even if a client submits a tool name it discovered earlier.

## Protocol conformance testing

HostMarshal tests **two distinct protocol eras** over actual stdio sessions in CI. Since M2, both eras use the **single audited declarative runtime**; the legacy JSON-mode handlers have been removed:

| Era | Wire sequence | Test |
| --- | --- | --- |
| `2025-11-25` legacy | `initialize` → `notifications/initialized` → `tools/list` and `tools/call` | `tests/mcp_smoke.py`, `tests/declarative_smoke.py` |
| `2026-07-28` stateless | `server/discover` → request-scoped `_meta` with protocol version and client capabilities → `tools/list`, `tools/call` | `tests/mcp_modern_smoke.py` |

Both paths verify authorization boundaries; the modern test also checks no-cache private tool-catalog hints and schema presence. A successful SDK build alone is **not** counted as protocol conformance. M4 independently tests JWT bearer-protected stateless Streamable HTTP through actual HTTP requests; the earlier tests cover stdio. Neither suite certifies a full OAuth authorization server, token introspection, all subscriptions/MRTR, or the complete upstream MCP conformance matrix.

M4 HTTP uses the same immutable-snapshot policy and invocation coordinator as stdio. Each request's trusted middleware injects `AuthenticatedCaller` derived from a verified access token; no HTTP session or user-provided MCP metadata establishes authority. See [Remote MCP](REMOTE_MCP_HTTP.md) and [ADR-0012](adr/0012-oauth-protected-stateless-mcp-http.md).
