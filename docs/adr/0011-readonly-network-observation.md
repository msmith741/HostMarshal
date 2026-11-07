# ADR-0011: Bounded SSH and HTTPS observation operations

- **Status:** Accepted (Milestone 3 implementation review)
- **Date:** 2026-11-07
- **Deciders:** Project maintainer

## Context

HostMarshal needs real read-only observation without becoming an unrestricted remote execution, network request or credential-exfiltration gateway. Hosts may reside on private networks; therefore blanket rejection of RFC1918 addresses is incompatible with the product. Client-controlled targets and URLs are prohibited.

## Decision

**Only two new trusted, versioned built-in operations** are enabled in M3:

1. `builtin.linux.uname/v1` runs the fixed remote command `uname -s` through the system OpenSSH client, validates the exact `Linux\n` response, and returns only a typed OS classification and inventory ID. A protected local per-target identity mapping is mandatory. Strict host-key verification uses a dedicated known_hosts file and stable inventory-ID HostKeyAlias; no user ssh config, password, agent identity forwarding, ProxyCommand/Jump, PTY or arbitrary command arguments. Child stdout is capped, stderr hidden, and timeout drops/kills the child.
2. `builtin.https.health/v1` issues HTTPS GET to a **compiled-in** `/health` path at a trusted inventory host and port. TLS identity validation is mandatory; optional trusted CA PEM supports local infrastructure. No automatic proxies, redirects, user headers, method selection, response bodies or arbitrary URL input. Return only target ID, numeric status and derived health boolean.

Both are `Observe` operations. Their schemas, output contracts, credential purpose, 5-second maximum descriptor timeout and output ceiling are trusted Rust definitions. YAML can bind/grant them but cannot change their behavior. The runtime continues to authorize/audit before any broker or transport call.

## Alternatives considered

- Generic SSH or HTTP request YAML templates — rejected because the caller could smuggle commands, URLs, proxy routes or sensitive payloads into an ostensibly read-only permission.
- Embed SSH implementation/host-key checks directly into HostMarshal — rejected in M3 in favor of audited, widely deployed OpenSSH tooling with explicitly fixed argv.
- Hard-code public-address-only HTTPS — rejected because approved infrastructure frequently uses private/loopback addressing; approval is anchored to trusted administrator-owned inventory, mandatory TLS identity and grants.
- Require a full external secrets manager — deferred until M4, while a minimal OS-protected per-target local mapping is sufficient for M3.

## Consequences

- Linux/Unix-first implementation with operational OpenSSH, a trusted pinned-key file and a protected local identity mapping. No generic command exposure.
- The local SSH key mapping is **not** a Vault replacement: parent directory ACLs, key rotations, revocation, local file race protection and service identities remain administrator responsibilities.
- API designers must expose a real `/health` endpoint. HTTPS probe does not inspect any response bodies and does not follow redirects, even to the same origin.
- Unsupported protocols and future hypervisor integrations require their own typed descriptors and tests.

## Security impact and residual risks

- Target inventory and key/CA files are an **administrator trust boundary**. A compromised config author can select destinations; the MCP caller cannot. A malicious hostname can still use a compromised CA or DNS if the administrator trusts it.
- SSRF prevention is enforced against **client-supplied URLs** through opaque target binding and a fixed HTTPS path, not by blocking all private addresses. DNS pinning and network-layer egress enforcement are future hardening requirements.
- OpenSSH runs a fixed command on a remote shell; no writable or interactive execution is made available. A remote host or key can still be compromised, or a server can implement a forced command. Treat output as untrusted and return only a validated result.
- Credential paths are opaque to MCP but available to trusted built-in code; symlink and ACL checks do not eliminate OS-level TOCTOU races. Run with a dedicated service identity.
- Pre-execution audit is mandatory; local file auditing is not tamper-evident. Side effects of arbitrary third-party endpoints cannot be proven from HTTP method semantics alone; operators must approve endpoints.

## Validation

- Disposable Linux sshd with ephemeral user/client/host keys: authorized fixed observation, wrong pinned key denial, missing/mispermissioned credential mapping, client argument injection, wrong-target and no-grant denials.
- Disposable TLS health server with locally created CA: valid certificate, wrong CA denial, redirect non-follow, slow-response deadline, extra-argument/target substitution denial, audit redaction.
- `cargo test` checks hostile inventory addresses, schema/operation limits and output contracts. CI independently verifies regenerated schema artifacts and Cargo.lock.

## References

[Observation adapters](../OBSERVATION_ADAPTERS.md), [Security](../SECURITY_ARCHITECTURE.md), [Roadmap](../ROADMAP.md), [Traceability](../TRACEABILITY.md).
