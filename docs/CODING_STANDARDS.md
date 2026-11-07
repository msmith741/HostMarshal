# Rust coding standards

**Status:** proposed for implementation PRs. Apply to every workspace crate, adapter, and test.

## Baseline

- Rust **2024 edition**; stable toolchain; document a minimum supported Rust version (MSRV) once dependency compatibility is measured. Do not claim an MSRV without CI evidence.
- Use `cargo fmt` and `cargo clippy --workspace --all-targets --all-features -- -D warnings`. CI must run `cargo test --workspace --all-targets --all-features`.
- Commit `Cargo.lock` for deployable applications; review dependency updates; do not add dependencies just to shorten trivial code.
- `unsafe` is prohibited in core code by default; exceptions require a narrowly scoped ADR, safety comments, and review.

## Design and APIs

- Use explicit, narrow public interfaces. Keep the domain model free of MCP SDK types and vendor SDK types.
- Separate identity context, authorization decision, resolved target, typed operation, and output as distinct structs; do not pass unvalidated JSON deep into adapters.
- Prefer strongly typed enums/newtypes to magic strings; stable identifiers use a documented canonical form.
- Follow standard Rust naming: `snake_case` functions/modules, `PascalCase` types, `SCREAMING_SNAKE_CASE` constants.
- Minimize public API surface; document assumptions and security invariants in rustdoc.
- No ambient or mutable global credential/policy state; inject interfaces for testability.

## Errors and observability

- Prefer domain error enums for cross-crate contracts; preserve causal chains internally while returning stable, non-disclosing error codes externally.
- Never use `unwrap()`/`expect()` on runtime inputs, I/O, network or credential paths. They may be used in small tests with clear assumptions.
- Avoid `panic!` for expected failures; use `Result` and explicit fail-closed behavior.
- Structured `tracing` should carry a request/correlation ID, not raw secrets, auth headers, command outputs, or private payloads.
- Reserve stdout for stdio MCP protocol messages; diagnostics go to stderr or a configured log sink.

## Async and operational safety

- Enforce deadlines, cancellation, bounded queues/concurrency and response size ceilings.
- Do not hold blocking locks across `.await`; use asynchronous I/O and cancellation-safe patterns.
- Redaction/response validation must be done in the trusted runtime, never left to plugins alone.
- Avoid unsafe command composition; do not run shell interpreters with untrusted arguments.
- Centralize target resolution; do not allow user-provided IPs, hostnames or URLs to bypass inventory.

## Configuration and compatibility

- Strictly reject unknown security-sensitive fields, invalid references, duplicate keys and unsupported resource versions.
- Validate schemas before operation resolution, authorization, and adapter invocation.
- Schema/resource changes require examples, migration notes, and compatibility tests. Prefer additive fields with explicit defaults, never silent privilege widening.
- Snapshot the full validated registry atomically and record its digest in audit events.

## Test standards

- Every capability path requires authorized, denied, malformed-input, nonexistent-target, timeout/failure and redaction tests.
- Test structural boundaries independently: policy, resolver, adapter, transport.
- Use mocks and disposable fixtures in public CI. No private homelab assumptions, live credentials, or external infrastructure needed.
- Fuzz untrusted YAML, JSON Schema, tool arguments and plugin protocol boundaries before exposing them widely.

## Documentation and PR standards

A feature PR must state the trust boundary, negative cases, API/schema compatibility, configuration example, and test evidence. Security-impacting deviations require an ADR. See [Testing](TEST_STRATEGY.md) and [Contributing](../CONTRIBUTING.md).
