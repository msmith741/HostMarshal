# Development and architectural governance

**Status:** proposed project workflow. HostMarshal is early-stage and has not established release commitments or a multi-maintainer governance body.

## Design before implementation

1. Write or update requirement(s) in [PRODUCT.md](PRODUCT.md).
2. For a cross-cutting change, open an ADR in [docs/adr](adr/README.md): context, decision, alternatives, security effects and consequences.
3. Add protocol/schema fixtures and failure cases before wiring an execution path.
4. Implement the smallest adapter/core change consistent with the approved boundaries.
5. Review the threat model, documentation, migration consequences and security tests.
6. Merge only after required CI and review gates pass.

## ADR states

`Proposed` → `Accepted` → optionally `Superseded`. `Rejected` and `Deprecated` may also be used with rationale. A proposed ADR is **not yet an implementation directive**. Accepted ADRs are authoritative over older prose; never silently rewrite historical decisions. Supersede with a new ADR referencing the original.

Use zero-padded numbers and descriptive filenames. Each ADR includes `Status`, `Date`, `Context`, `Decision`, `Alternatives`, `Consequences`, `Security impact`, and `Validation`.

## Definition of done for code

- Traceable requirement/ADR and updated docs.
- Tested allow/deny cases, errors, deadlines and sensitive-data handling.
- Dependency and license review; schema/version handling if applicable.
- CI checks pass, including protocol interoperability if transport changes.
- No real environment names, embedded secrets, copied internal runbooks or production endpoints.

## Compatibility and deprecation

- Resource API versions, operation IDs, adapter ABI/protocol versions and MCP compatibility are separate versioned contracts.
- No stable contract is promised before beta; nevertheless, any breaking change needs migration notes and test fixtures.
- Stable-capability identity must not silently change implementations or security classifications under an existing grant.
- A changed operation digest or permission profile must trigger revalidation and, for authority-widening changes, renewed administrative approval.
- Fail closed if a client or plugin needs an unsupported protocol/schema version.

## Review roles

For early development, the maintainer reviews the proposal and its tests. For higher-risk changes, independent review is strongly recommended; it becomes a release requirement before production mutation support. Code contributors must not self-approve changes to authorization and plugin trust controls in deployments that require separation of duties.

## Integration and PR #1

The open [bootstrap PR #1](https://github.com/msmith741/HostMarshal/pull/1) contains a hard-coded tool prototype. Do not merge it unchanged into a declarative architecture. Reconcile/rework that PR (or replace it) after M0 design acceptance; preserve useful test fixtures and MCP initialization coverage, update references, and keep this documentation authoritative.
