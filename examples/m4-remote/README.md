# M4 authenticated remote MCP — fictional example

`remote-grant.yaml` is a versioned resource to add to an administrator-owned YAML configuration directory *alongside* existing M3/M1 host and capability resources. Replace the fictional HTTPS issuer and subject with independently verified values.

`vault-ssh.example.json` is a **non-secret structural example only** and must be stored outside the YAML manifest directory if used. Do **not** check in real tokens, signing keys, SSH keys, CA private keys, or JWKS material. Use the protected `--vault-ssh-config` option and the official [Vault integration guide](../../docs/VAULT_SSH.md).

The supported HTTP access token is a short-lived RS256, `at+jwt` access JWT with audience equal to the externally advertised MCP HTTPS resource and `hostmarshal:observe` scope. HostMarshal requires a dedicated local HTTPS proxy; see [remote MCP deployment](../../docs/REMOTE_MCP_HTTP.md).
