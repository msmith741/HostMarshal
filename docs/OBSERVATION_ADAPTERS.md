# Milestone 3 — Restricted SSH and HTTPS observations

**Status:** Two compiled-in read-only observation operations. These are **pre-alpha** capabilities, not a general-purpose remote admin shell, arbitrary HTTP client or production-approved secrets integration.

## Installed operations

| Operation ID | Trusted target configuration | Result | Credential |
| --- | --- | --- | --- |
| `builtin.linux.uname/v1` | Host `ssh` settings | `{"id":"host-id","os":"Linux"}` | Protected per-target local SSH private-key path |
| `builtin.https.health/v1` | Host `https` settings | `{"id":"host-id","statusCode":200,"healthy":true}` | None; system or configured CA trust |
| `builtin.inventory.inspect/v1` | Host address | `{"id":"host-id","hostname":"..."}` | None |

All three accept exactly `{"target":"inventory-id"}`. The descriptor fixes risk=Observe, result schema, protocol, credential purpose, maximum execution time (5 seconds for network observations), and output limit (4096 bytes). A published YAML Capability must match the trusted input/output schemas exactly and may specify a shorter timeout and a smaller output limit. A Grant must separately authorize the caller and that exact target.

## Host configuration (versioned YAML)

Example with **fictional** network names and paths; administrators must supply their own approved infrastructure and protected trust files:

```yaml
apiVersion: hostmarshal.io/v1alpha1
kind: Host
metadata:
  name: demo-linux
spec:
  address: demo-linux.example.invalid
  ssh:
    user: observer
    port: 22
    knownHostsFile: /etc/hostmarshal/trust/known_hosts
---
apiVersion: hostmarshal.io/v1alpha1
kind: Host
metadata:
  name: demo-https
spec:
  address: status.example.invalid
  https:
    port: 443
    caCertificateFile: /etc/hostmarshal/trust/ca.pem
```

The inventory address is validated as an IP address or simple DNS name: it cannot include scheme, path, port, username, whitespace, `@`, or command options. A `Host` without a matching typed transport cannot be granted an operation requiring it. CA file paths must be absolute; the trust file must be regular, not a symlink, and not group/world-writable. Identity files must be regular, not symlinks, and mode 0600 or stricter.

## SSH credential map

For Linux observations, the **trusted local launcher**, not an AI client, supplies a separate protected JSON mapping:

```json
{
  "apiVersion": "hostmarshal.io/ssh-credentials/v1alpha1",
  "identities": [
    {
      "target": "demo-linux",
      "identityFile": "/var/lib/hostmarshal/keys/demo-linux"
    }
  ]
}
```

Use a dedicated, minimally privileged remote user with **only key-based SSH access** and read-only permissions appropriate to its role. Ensure local identity and map files are mode 0600; keep their parent directories inaccessible to untrusted users. Password authentication is disabled and no ssh-agent key fallback is allowed. This provider references protected local files; it does not read private-key bytes into HostMarshal, fetch secrets from a remote provider, or issue short-lived credentials. That is future M4 work.

Prepare the pinned SSH host-key file using a **verified** host key obtained out of band. Do not blindly trust an unauthenticated `ssh-keyscan` result. Store the host's verified key under the stable inventory ID, e.g. `demo-linux ssh-ed25519 AAAA...`. HostMarshal uses `HostKeyAlias=demo-linux` and `StrictHostKeyChecking=yes`, does not update host keys automatically, and refuses mismatches. Rotation is an administrator-controlled trust update.

Run HostMarshal through a dedicated OS service account:

```sh
hostmarshal config validate /etc/hostmarshal/config
hostmarshal --config-dir /etc/hostmarshal/config \
  --principal operator-01 \
  --ssh-credential-map /etc/hostmarshal/ssh-identities.json \
  --audit-log /var/lib/hostmarshal/audit/events.jsonl
```

Do not publish private keys, the identity mapping, or real host trust files to this public repository. Existing M1-only setups can omit `--ssh-credential-map`; then SSH operations fail closed at broker acquisition.

## HTTPS health checks

HostMarshal constructs only `https://<inventory-address>:<port>/health`. TLS hostname validation is mandatory. `caCertificateFile` adds a trusted PEM root/intermediate for private PKI; without it, system roots apply. The HTTP client never adopts environment proxies or follows redirects; the body is not read, parsed, logged, or returned. A 3xx response is reported as unhealthy, not followed.

The target is **administratively approved** and may reside on a private network. Network-layer egress ACLs remain recommended to constrain access even if manifests or DNS are compromised. A `GET` is not a mathematical guarantee of zero side effects on every server; only approved health endpoints should be configured.

## Operational and security limitations

- Fixed SSH `uname -s` may still execute through the remote login shell. The command and all argv are compiled in, not derived from MCP input.
- Unix process permissions and trusted config deployment are prerequisites. Protected file paths are checked, but a privileged same-user attacker might race their replacement.
- The SSH binary is `/usr/bin/ssh`; no execution occurs when it is absent. SSH host-key pinning and endpoint identities are verified at each connection, but target-side authorization still depends on remote account configuration.
- SSH stdout is capped at 64 bytes and accepted only when exactly `Linux\n`. HTTP output contains status only; no server-provided body or headers are disclosed.
- Deadlines include broker acquisition and adapter execution; killing a local SSH client does not prove remote work was interrupted. Do not authorize mutations using this mechanism.
- The host OS identity/configuration, DNS, trusted CA/key material and a correctly scoped local key are essential security assumptions. Neither operation provides remote MCP authentication or a protected external audit service.

See [ADR-0011](adr/0011-readonly-network-observation.md), [Architecture](ARCHITECTURE.md), [Audit](AUDIT.md) and [Traceability](TRACEABILITY.md).
