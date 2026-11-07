# Contributing to HostMarshal

Thanks for helping build a secure and general-purpose infrastructure operations platform.

**Present status:** design specifications and ADRs are proposed. Please do not treat examples as implemented configuration or introduce production execution adapters until their security prerequisites have landed.

## Contribution process

1. Read [product requirements](docs/PRODUCT.md), [architecture](docs/ARCHITECTURE.md), [security model](docs/SECURITY_ARCHITECTURE.md), and [coding standards](docs/CODING_STANDARDS.md).
2. Open an issue or draft ADR for public API, security boundary, plugin protocol, or configuration schema changes.
3. Use a short-lived branch and a focused pull request with a problem statement, alternatives, operational/security consequences, and tests.
4. For security-sensitive behavior, provide **negative-path tests** (denial, injection, target substitution, failures), not merely happy-path tests.
5. Keep examples fictional and self-contained: `example.invalid` hostnames, no organization-specific domains, IP ranges, credentials, or internal network descriptions.
6. Do not add broad shell execution, generic user-supplied URLs, untrusted module loading, or permission bypasses.

## Review expectations

- All externally visible contracts need documented compatibility/versioning impact.
- Capability manifests must never weaken an installed operation's intrinsic restrictions.
- Trust boundaries must be explicit and verifiable with tests.
- New dependencies need a purpose, maintenance/security review, license compatibility, and bounded permissions.
- Documents and ADRs must say **proposed**, **accepted**, or **superseded**; do not claim unimplemented behavior works.

Development commands (for the current Rust crate and eventual workspace):

~~~sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
~~~

For security issues, use [SECURITY.md](SECURITY.md), **not** public issue discussion. All contributions are subject to Apache-2.0; contributors are responsible for having rights to submit their code.
