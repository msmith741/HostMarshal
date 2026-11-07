# Machine-readable HostMarshal configuration schema

**Status:** Versioned, checked-in **v1alpha1** resource schema and independent schema-conformance CI are implemented. This validates structural configuration, **not** authorization, identity, plugin safety, or the source of config.

## Published artifact

- [schemas/v1alpha1/resources.schema.json](../schemas/v1alpha1/resources.schema.json) — JSON Schema Draft 2020-12, with stable `$id` `urn:hostmarshal:schemas:v1alpha1:resource`.
- The schema covers the three resource kinds implemented now: `Host`, `Capability`, and `Grant`; each has a fixed `apiVersion: hostmarshal.io/v1alpha1`.
- The schema is **derived from Rust Serde models**, version constrained, and committed to source control.

Regenerate and verify the committed artifact:

~~~sh
cargo run --locked --quiet -- config schema > /tmp/resources.schema.json
diff -u schemas/v1alpha1/resources.schema.json /tmp/resources.schema.json
~~~

CI automatically fails on drift between the generated schema and checked-in artifact.

## Independent conformance

CI validates the schema through the separate Python `jsonschema` Draft 2020-12 implementation, not Rust Serde. It checks the three real YAML examples, malformed resource types, extra executable fields, unsupported versions, and incorrect value types:

~~~sh
python3 -m venv .schema-venv
.schema-venv/bin/pip install 'jsonschema==4.25.1' 'PyYAML==6.0.3'
.schema-venv/bin/python tests/schema_conformance.py
~~~

The Python test rejects external schema references, keeping schema validation self-contained. This is separate from Rust's security-sensitive semantic validation.

**Important:** Being schema-valid does not confer execution permission. Cross-document grants, installed operation references, schema identity and target authorization are enforced by HostMarshal's trusted compiler and runtime. In the current M1 subset, capability input/output schemas must still exactly equal the vetted operation descriptor.

## Versioning and compatibility

Resource schemas are versioned by their directory and `apiVersion`; future versions should be published alongside existing ones, not silently replace them. The `Cargo.lock` file is committed for repeatable dependency resolution, and CI uses `--locked`. This is not a bit-for-bit reproducible build guarantee.

## Deployment example

~~~sh
cargo run --locked -- config validate config/v1alpha1
cargo run --locked -- config inspect config/v1alpha1
~~~

Refer to [Configuration](CONFIGURATION.md), [Traceability](TRACEABILITY.md), [ADR-0003](adr/0003-versioned-yaml-resources.md), and [Security](SECURITY_ARCHITECTURE.md).
