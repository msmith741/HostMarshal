# M3 observation example

This portable, fictional example demonstrates how two independently published YAML capabilities refer to trusted compiled-in observation operations. The `knownHostsFile`, `caCertificateFile` and SSH identity paths are illustrative and must be replaced by administrator-controlled paths before **live use**.

- `hosts.yaml`: trusted Linux and HTTPS inventory targets.
- `capabilities.yaml`: strict operation references and fixed I/O schemas.
- `grants.yaml`: separate explicit authorization to individual targets.
- `ssh-identities.example.json`: **example only**; copy outside version control, set owner-only permissions, and provide `--ssh-credential-map`.

The example YAML can be validated offline with `hostmarshal config validate examples/m3-observations` if the JSON example credential file is kept outside that directory before validation (the loader only accepts YAML files). It never contacts the fictional endpoints during validation.

Read [M3 operations](../../docs/OBSERVATION_ADAPTERS.md).
