# Contributing

HostMarshal is in early development. Small, focused PRs with tests and clear security implications are preferred.

1. Open an issue for new capabilities, especially privileged or network-facing features.
2. Avoid arbitrary shell primitives, client-selected principals, wildcard policy grants and implicit permissions.
3. Add tests for **denial** as well as success. Keep examples free of real domains, addresses and secrets.
4. Run `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
5. Document trust boundaries, resource limits, credential handling and any new side effects.

By contributing, you agree that your contribution is licensed under Apache-2.0. Do not submit third-party or employer-owned code without the required authorization.
