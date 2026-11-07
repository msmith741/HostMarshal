# Client protocols and identity

**Status: PROPOSED.** MCP is a first-class transport **adapter**, not the authorization engine.

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
- **authenticated MCP HTTP later:** strict audience/issuer verification, TLS, origin/CSRF/DNS rebinding protections where applicable, network restrictions, timeouts and per-identity rates.
- **CLI:** direct invocations share the same validated security context, registry and runtime; a policy-explanation command may not impersonate a runtime caller.

## Policy changes during a stdio connection

M1 uses immutable per-request snapshots. On a successful Unix SIGHUP, a new tool discovery request returns the updated, authorization-filtered catalog. The SDK's catalog advertises private caching with `ttlMs: 0`; clients must not retain previously discovered capabilities as authorization. `tools/call` always checks the current snapshot even if a client submits a tool name it discovered earlier.

## Protocol conformance testing

Maintain fixtures for supported versions, tool discovery and invocation, JSON Schema validation, denial behavior, cache invalidation and error mapping. Legacy compatibility claims must be backed by CI evidence, not documentation or dependency version strings.
