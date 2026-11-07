# ADR-0003: Versioned declarative configuration resources

- **Status:** Proposed
- **Date:** 2026-11-07
- **Deciders:** Maintainers (pending review)

## Context

JSON-only bootstrap configuration cannot easily express independent inventory, capabilities, policy, adapters and providers. Human-friendly YAML is desirable but may become a code-execution or privilege-escalation channel.

## Decision

Use versioned, strictly validated YAML resources with `apiVersion`, `kind`, `metadata` and `spec`. Publish machine-readable schemas. Parse under resource budgets; reject duplicate keys, unsupported tags/versions, invalid references, unknown security-sensitive fields, unsafe schemas and privilege-widening manifest settings. Compile a **complete immutable snapshot**, then activate atomically. Configuration paths are privileged deployment material.

## Alternatives considered

- One free-form JSON/TOML file: simpler parsing but weaker multi-resource composition and portability.
- Full Kubernetes CRDs/controller: familiar but creates an unnecessary Kubernetes dependency.
- Arbitrary templating/scripting during load: expressive but undermines sandbox and provenance boundaries.

## Consequences

Schema lifecycle and migration discipline are required. External YAML must never be treated as a trusted grant just because it parses. Configuration loader is independent of the input transport.

## Security impact

Parser limits, reference validation, role separation, digest tracking and deny-first emergency revocation are required. Hot reload may not partially apply a newly parsed configuration.

## Validation

Golden valid/invalid YAML fixtures, parser fuzzing, unknown-key/duplicate-key tests, privilege-widening rejection, cross-resource reference tests and atomic-reload fault tests.

## References

[Configuration](../CONFIGURATION.md), [Examples](../../examples/proposed-v1alpha1/README.md).
