# Security policy

**Status:** no supported production release. Design documents and examples are not security guarantees. The M4 runtime supports audited inventory plus fixed SSH/HTTPS observations, externally verified JWT access tokens on stateless HTTP and an optional short-lived Vault SSH certificate-signing provider. It still lacks an in-process OAuth authorization server, token introspection/revocation, native public TLS termination, independent audit integrity, arbitrary command execution, mutation and OS-isolated plugins. The old unaudited JSON handlers were retired.

## Reporting vulnerabilities

Use GitHub's **private vulnerability reporting** for this repository if it is enabled. Otherwise contact the maintainer privately through a suitable existing channel. Do **not** publish exploits, sensitive endpoints, credentials, or reproductions involving other people's infrastructure in public issues.

A useful report includes the affected revision, reproducible steps against a disposable target, actual versus expected result, impact, and any known mitigations. We cannot guarantee a disclosure SLA until a formal maintenance and response policy is adopted.

## Assumptions and safe use

- Treat configuration directories, plugins, executable files, trust roots, and policy grants as privileged deployment material.
- MCP clients are untrusted unless the **transport authenticates** them; client-supplied names are never evidence of identity.
- No adapter may be considered safe merely because its capability is labeled `observe` or uses HTTP GET.
- No arbitrary shell, target URL, command, or secret is a valid client-supplied execution primitive in the initial design.
- Do not test privileged operations on systems you do not administer.

See [Security Architecture](docs/SECURITY_ARCHITECTURE.md) and [Testing](docs/TEST_STRATEGY.md) for proposed controls and release gates.
