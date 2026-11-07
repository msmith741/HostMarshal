# ADR-0003: Versioned declarative configuration resources

- **Status:** Accepted
- **Date:** 2026-11-07
- **Deciders:** Project maintainer (design review, 2026-11-07)

## Context

JSON-only bootstrap configuration cannot easily express independent inventory, capabilities, policy, adapters and providers. Human-friendly YAML is desirable but may become a code-execution or privilege-escalation channel.

## Decision

Use versioned, strictly validated YAML resources with `apiVersion`, `kind`, `metadata` and `spec`. Publish machine-readable schemas. Parse under resource budgets; reject duplicate keys, unsupported tags/versions, invalid references, unknown security-sensitive fields, unsafe schemas and privilege-widening manifest settings. Compile a **complete immutable snapshot**, then activate atomically. Configuration paths are privileged deployment material.

## Acceptance clarifications

- M1 is an intentionally restricted implementation subset. Only explicitly supported `Host`, `Capability`, and `Grant` resources are accepted; schema publication, canonical digests, secure hot reload, and privileged deployment workflows remain separately gated work.
- A trusted process launcher owns configuration inputs. A successful parse does not authenticate the author of the files. Process/OS permissions are part of the trusted deployment boundary.
- A parser must never partially activate resources on error. Parser budgets, duplicate-key rejection, and adversarial YAML fuzzing are release requirements; merely choosing a YAML library does not prove all these controls.

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
