# Initial threat model

Status: living design document, not a certification or completed security assessment.

## Assets and boundaries

Protected assets include managed hosts, control-plane APIs, credentials, inventory, and audit logs. The primary threat is an untrusted or compromised AI client trying to exceed an allowed operation.

The **current** process-level trust boundary is the OS user/launcher. The server trusts the on-disk configuration selected by its launcher. MCP request fields are untrusted. The static inventory is not a network connector.

## Invariants

1. **Default deny:** absence of a matching grant returns no data.
2. **Exact target:** grant matches a host's inventory ID, not prefixes/globs.
3. **No client-chosen principal:** the MCP tool surface cannot set caller identity.
4. **No target enumeration:** unauthorized and nonexistent lookups share an error.
5. **No arbitrary execution:** no SSH, shell, subprocess or HTTP adapter is wired.
6. **Strict configuration:** reject malformed or unknown fields at startup.
7. **No stdout logs:** stdio stdout is reserved exclusively for MCP transport.

## Known limitations

- The stdio process has no cryptographic caller authentication. OS protections and a trusted launcher are prerequisites.
- Anyone who can modify the trusted configuration, executable or launch command can change the effective grants.
- Current tool responses are static inventory metadata; no live infrastructure state is verified.
- Audit persistence, rate limiting, transport authentication, secret rotation, sandboxing, and host-key verification are not implemented.

## Mandatory controls before live adapters

- Authenticated caller identity and authorization independent of tool arguments
- Per-host, per-operation grants; never expose a raw shell API
- Host identity pinning (SSH host keys, TLS CA/identity) and strict timeouts
- Vault short-lived credentials, least-privilege API roles, no secrets in outputs
- Execution logging and sensitive-data redaction; bounded output
- Adversarial tests for injection, traversal, privilege escalation, misbinding, concurrency and outages
- Secure deployment guide including process permissions, network policy and failure modes
