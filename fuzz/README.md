# HostMarshal YAML parser fuzzing

This independent fuzz crate uses `libfuzzer-sys` with `cargo-fuzz`, operating on both the strict YAML parser and the configuration compiler. It is **not** a runtime extension.

To run a coverage-guided campaign on a disposable development machine:

~~~sh
rustup toolchain install nightly --profile minimal
cargo +nightly install cargo-fuzz --locked --version 0.13.2
cargo +nightly fuzz run yaml_manifest -- -max_total_time=120 -timeout=5 -max_len=8192
~~~

The CI pipeline runs a separate deterministic 1,800-case mutation test using stable Rust. A bounded nightly fuzzing workflow runs weekly and can also be dispatched manually. Coverage-guided fuzzing is probabilistic and cannot prove absence of parser vulnerabilities; inspect crashes and convert minimized inputs into regression tests before triage.

The fuzz crate is a separate workspace. `fuzz/Cargo.lock` is intentionally not part of the deployable application; the root `Cargo.lock` is committed and CI builds the application with `--locked`.

Inputs are limited to 128 KiB, matching the public parser's file budget. All seeds use fictional or malicious-example metadata only.
