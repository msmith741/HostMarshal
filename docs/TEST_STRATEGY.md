# Verification and release gates

**Status:** proposed test strategy. Tests discussed here are **planned** unless present in a merged implementation.

## Test pyramid

| Level | Purpose | Typical fixtures |
| --- | --- | --- |
| Unit | Deterministic schema, policy, resolver and risk classification | Pure in-memory values |
| Property/fuzz | Parser input, canonicalization, bound handling, policy invariants | Generated malformed manifests and JSON |
| Contract | Operation descriptors, capability APIs, error and audit schemas | Golden fixtures and mock adapters |
| Integration | SSH/TLS identity checks, HTTP adapter, broker behavior | Local mock servers/disposable targets |
| End-to-end | CLI, MCP tool discovery/invocation, authorization | Local process and test configurations |
| Fault/adversarial | Timeouts, retries, host substitution, credential leaks, audit failure | Injected errors and controlled egress |

## Minimum M1 acceptance tests

1. Two YAML capabilities can reference one installed mock adapter without adding Rust handlers.
2. No grant returns an empty/filtered catalog or authorization denial as appropriate.
3. Exact grants authorize only their intended subject, operation and resource.
4. Capability metadata cannot downgrade operation risk, change adapter privileges or invent executables.
5. Unknown YAML keys, duplicate names/keys, unsupported API versions, broken references, oversized documents, aliases, custom tags, merges and excessive nesting fail validation.
6. Tool schemas and error behavior are consistent through core, CLI and supported MCP versions.
7. Atomic reload never exposes a partially validated permission set.

## Mandatory adversarial matrix

- Prompt/tool injection via descriptions and results; descriptions are data, not policy.
- Client-spoofed principal, role, metadata, header, inventory labels or target address.
- Path/hostname/URL normalization tricks, redirects, DNS rebinding, cloud metadata SSRF.
- Time-of-check/time-of-use changes of inventory, policy, plugin or credentials.
- Schema recursion/depth abuse, YAML alias expansion and duplicate keys.
- Shell metacharacters, unintended command substitution and escaping bugs.
- Oversized output, binary responses, secret-bearing errors, log injection and redaction bypass.
- Cancellation/races, stale policy snapshots, rate-limit exhaustion and audit sink outage.
- Cross-tenant data disclosure and capability discovery caching leaks.
- Unknown/malicious plugin manifests, undeclared network/filesystem effects.

## Independent schema conformance (M1)

The checked-in `schemas/v1alpha1/resources.schema.json` is compared against the Rust CLI generator. An independently maintained `jsonschema` Draft 2020-12 validator checks both valid and invalid YAML fixtures. This is an additional structural safeguard; schema validity cannot confer invocation rights. Dependency resolution uses the committed application `Cargo.lock` under `--locked`.

## Evidence and CI

- Gated: format, Clippy warnings-as-errors, tests, schema fixtures, smoke tests, dependency and license audit.
- Before live integrations: security negative-path suite, integration target verification, output redaction checks, stable error tests.
- Before releases: locked dependencies, reproducible artifacts where feasible, SBOM, vulnerability scanning, provenance/signatures and documented supported environments.
- No public CI job requires private network access, personal inventory, or production credentials.
- CI status must distinguish tests run from tests proposed; failures are not waived by documentation claims.

## Release-blocking failures

Block publication when authorization is bypassed; a policy-negative call reaches a live adapter; credentials leak; a client can substitute a target; an observe operation performs an unintended mutation; an audit-mandatory invocation executes without its required audit commitment; or a plugin escapes its granted isolation.
