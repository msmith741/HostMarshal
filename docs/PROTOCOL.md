# Client protocols and identity

**Status:** stdio MCP protocol adapter is implemented for a limited static inventory capability. The broader authenticated HTTP and multi-client architecture remains proposed.

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

HostMarshal tests **two distinct protocol eras** over actual stdio sessions in CI:

| Era | Wire sequence | Test |
| --- | --- | --- |
| `2025-11-25` legacy | `initialize` → `notifications/initialized` → `tools/list` and `tools/call` | `tests/mcp_smoke.py`, `tests/declarative_smoke.py` |
| `2026-07-28` stateless | `server/discover` → request-scoped `_meta` with protocol version and client capabilities → `tools/list`, `tools/call` | `tests/mcp_modern_smoke.py` |

Both paths verify authorization boundaries; the modern test also checks no-cache private tool-catalog hints and schema presence. A successful SDK build alone is **not** counted as protocol conformance. The tests do not validate HTTP transports, OAuth, subscriptions, MRTR, or the complete upstream MCP conformance suite; those remain explicit future work.

New transport implementations must reuse the same snapshot-aware policy and invocation coordinator, without accepting unverified caller metadata as identity.
