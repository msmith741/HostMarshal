# Roadmap

## v0.1 — Foundation (this PR)

- [x] Independent Rust crate and official MCP stdio server
- [x] Typed, read-only inventory tools
- [x] Default-deny exact principal/capability/host policy
- [x] Configuration validation and unit tests
- [x] CI: formatting, Clippy, tests
- [x] Architecture and initial threat model
- [ ] Verified builds, test results and a checked-in Cargo.lock
- [ ] MCP client interoperability smoke test

## v0.2 — Authenticated observation

- [ ] Trusted identity binding rather than launcher-asserted identity
- [ ] Formal typed adapter trait and strict time/output budgets
- [ ] Restricted Linux SSH observation adapter with host-key pinning
- [ ] Immutable operation registry and policy matrix
- [ ] Durable audit sink, redaction and correlation IDs

## v0.3 — Credential broker and Proxmox

- [ ] Vault-backed credential leasing and renewal/revocation
- [ ] Proxmox adapter with least-privilege scoped API tokens
- [ ] TLS trust validation, retry policy and quota limits
- [ ] Integration test environments, negative-path security tests

## v0.4+ — Operations platform

- [ ] Containerized deployment on Kubernetes with workload identity
- [ ] Optional authenticated network MCP transport
- [ ] Inventory reconciliation and operator-approved changes
- [ ] Multi-client support, metrics and audit dashboards

**Design rule:** read-only operations first. Any future mutation requires a separate authorization and approval model.
