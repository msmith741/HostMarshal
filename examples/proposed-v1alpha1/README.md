# Proposed HostMarshal configuration examples

**These remain illustrative design fixtures**, potentially broader than the deliberately strict M1 subset. For a presently supported pre-alpha YAML configuration, use [config/v1alpha1](../../config/v1alpha1) and `hostmarshal config validate config/v1alpha1`. The legacy bootstrap JSON mode remains separate.

Files:

- [host.yaml](host.yaml): a fictional managed host with stable ID and trusted inventory label.
- [capability.yaml](capability.yaml): a manifest that publishes a known **built-in inventory operation** under a tool name.
- [grant.yaml](grant.yaml): an independent invocation authorization for one fictional subject and target.
- [deny-all.yaml](deny-all.yaml): no grants; validates fail-closed behavior conceptually.

All addresses use reserved `.invalid` names. The fixtures intentionally include no secrets, SSH commands, environment-specific domains or vendor dependencies.

## Expected design behavior

With the vetted `builtin.inventory.inspect/v1` operation installed and the trusted launcher establishing the example identity, the subject `example-operator` can inspect only `sample-linux`. Without the grant, the tool may be absent from an identity-filtered catalog or every invocation must be denied; the adapter must never execute a denied call. An unknown operation, unknown field, privilege-widening override or changed operation digest is a validation/deployment error, not an implicit permission.

Canonical JSON Schemas for these resource kinds and real offline validation tooling are Milestone 1 deliverables. Do not infer security semantics from these unimplemented examples alone.
