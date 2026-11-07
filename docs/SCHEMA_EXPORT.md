# Machine-readable YAML resource schemas

**Status:** pre-alpha schema export available through the local CLI. Standalone checked-in schema bundles and external-validator conformance tests remain future milestones.

Export a **JSON Schema Draft 2020-12** document from the currently compiled Rust Serde resource definitions:

~~~sh
cargo run -- config schema > hostmarshal-v1alpha1.schema.json
~~~

Editors and external tooling may use the generated schema for structural validation and completion. The schema models \`Host\`, \`Capability\`, and \`Grant\` document variants.

**A document valid against the JSON Schema is not automatically trusted, executable or authorized.** Rust validation additionally checks installed operation IDs, exact input/output contracts, cross-resource references, issuer restrictions, limits, and grants. Capability declarations never grant themselves execution permissions.

For trusted local configurations:

~~~sh
cargo run -- config validate config/v1alpha1
cargo run -- config inspect config/v1alpha1
~~~

\`config inspect\` returns resource counts and a SHA-256 digest of the normalized effective snapshot. Reordering manifests should not change the digest, while altering an effective grant should. This digest is not a cryptographic signature, attestation of source authorship, or verification of installed code provenance.

The parser rejects YAML aliases, anchors, merge keys and unsupported custom tags, and imposes limits on depth, input bytes, documents, nodes and events. Configuration file permissions and trusted launchers remain necessary; cross-platform TOCTOU file protection is still pending.

See [Configuration](CONFIGURATION.md), [Traceability](TRACEABILITY.md), and [ADR-0003](adr/0003-versioned-yaml-resources.md).
