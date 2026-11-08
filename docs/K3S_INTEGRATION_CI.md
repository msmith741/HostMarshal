# Disposable three-node K3s/Traefik security acceptance

**Status:** two independent CI test levels, **not a production deployment**. Both run on disposable GitHub-hosted Linux runners without private homelab Kubernetes credentials.

**Fast deployment smoke:** `.github/workflows/k3s-smoke.yml` creates one K3s server node, checks the manifest security contract, installs bundled Traefik and HostMarshal, then checks Pod readiness and authenticated/denied HTTPS MCP end to end. **Extended security acceptance:** `.github/workflows/k3s-isolation.yml` additionally creates two agents and tests Kubernetes NetworkPolicy and cross-node paths, including a deliberately unsafe additive-policy positive control and its rollback. The extended workflow is path-filtered for related changes on PR/push and independently dispatchable; it remains required before any production release.

The init container uses Kubernetes `fsGroup: 10001` and a group-readable read-only Secret projection (0440) to copy protected auth/ingress files into a memory-backed volume as UID/GID 10001. Copies are mode 0600, owned by the non-root runtime identity. **No init/runtime container runs as root or adds capabilities.** The previous root + CHOWN/FOWNER workaround is retired.

## What runs

`.github/workflows/k3s-isolation.yml` uses a full SHA-pinned GitHub checkout, a SHA256-verified k3d v5.9.0 binary, a pinned `rancher/k3s:v1.34.5-k3s1` image with **one server and two agents**, the bundled K3s Traefik and kube-router network-policy controller, and an unprivileged HostMarshal + NGINX local proxy Pod. Docker image `hostmarshal-k3s-ci:ci` is built locally using `deploy/k3s/ci/Dockerfile` and imported into ephemeral k3d nodes; it is never pushed to a registry. The job tears down its cluster even on failure.

All test-only public CA, leaf TLS certificate, RSA signing key, JWKS file, protected ingress proof and OAuth access tokens are freshly generated in the job. The RSA signing private key never enters Kubernetes. CI uses an offline public JWKS fixture; the real **Keycloak authorization-server interoperability** and Vault credential-provider tests continue to run in the existing `Rust CI` workflow. Do not confuse synthetic JWT signing in this K3s test with actual external issuer federation; both gates are required.

### Traffic and trust boundaries

```text
GitHub runner: HTTPS client verifies generated CA / SNI mcp.hmci.example.test
               |
 kubectl port-forward, selected K3s kube-system/Traefik Pod HTTPS:443
               |
 K3s Traefik IngressRoute, exact Host + /mcp / metadata, tls.secretName
               |
 TCP 8080, ClusterIP Service, NetworkPolicy only kube-system/traefik
               |
 HostMarshal Pod (worker agent-0):
   nginx-unprivileged :8080 (proxy-owned Host/forwarded/proof headers)
            |
        loopback :8338
            |
   HostMarshal signed JWT, subject grants, audit
               ^
    NOT accessible at podIP:8338

Probes on worker agent-1:
  external namespace, forged Traefik Pod label -> denied Service/Pod IP
  kube-system namespace, wrong Pod label -> denied Service/Pod IP
  temporary intentionally unsafe ingress NetworkPolicy -> Service path opens
  delete unsafe policy -> Service path must close again
```

`deploy/k3s/ci/resources.yaml` is **not** a production Kubernetes installation and is deliberately not an Argo CD source. Its Pod uses a runtime-only tmpfs for protected files and audit, an init container to set file ownership, an unprivileged local proxy that overwrites forwarding attestations, non-root HostMarshal, a dedicated ServiceAccount with token automount disabled and a strictly selected ingress NetworkPolicy. The app backend binds loopback so a separate PodIP cannot directly reach the MCP TCP port.

## Running safely

GitHub Actions invokes:

```sh
cargo build --locked --bin hostmarshal
docker build -f deploy/k3s/ci/Dockerfile -t hostmarshal-k3s-ci:ci .
k3d cluster create hostmarshal-m4-ci --image rancher/k3s:v1.34.5-k3s1 --servers 1 --agents 2 --wait --timeout 300s
k3d image import hostmarshal-k3s-ci:ci --cluster hostmarshal-m4-ci
python tests/k3s_cluster_ci.py --mode network
k3d cluster delete hostmarshal-m4-ci
```

In CI, Python runs inside an isolated venv with pinned PyJWT/cryptography versions. Locally these commands require Docker, k3d, kubectl, OpenSSL, Python, and permission to create/delete a **disposable cluster**. The test script uses the active kubectl context and performs real Kubernetes mutations; **never invoke it against the homelab context**. The workflow creates a new cluster and sets its context first. No homelab domain or credentials are used.

## Requirements and acceptance criteria

| Requirement | Control | Required evidence |
| --- | --- | --- |
| FR-028 | Multi-node, versioned K3s/Flannel + bundled Traefik | Three Ready nodes; Traefik rollout; Pod placed on agent-0, attacker on agent-1 |
| FR-029 | Loopback-only MCP and unprivileged local ingress proxy | HTTPS metadata succeeds with validated CA; backend PodIP port 8338 cannot be reached; no HostMarshal external Service type |
| FR-030 | NetworkPolicy trust and active negative control | Wrong-namespace/wrong-Pod-label sources denied Service+Pod IP; deliberately permissive additive policy reopens path; deletion restores denial |
| FR-018/FR-025 | Signed bearer and ingress proof | Authorized tool, empty catalog for ungranted signed subject, correct 401/403/405 and Host/TLS/proxy forgery denial |
| NFR-001/002 | Security/regression | Existing Rust tests, schema, fuzz, Vault and Keycloak remain independent CI requirements |

The *positive-control policy test* is essential: simply observing timeouts could otherwise be explained by DNS failure, unscheduled workloads, blocked egress, or an unrelated broken Service. Each attacker also has a positive Kubernetes API reachability check before denial is credited.

### Residual release gates

CI validates actual Flannel/kube-router policy enforcement in a disposable Linux/Docker environment, not a homelab CNI dataplane. It does not prove real k3s Traefik chart configuration, MetalLB routes, UniFi security rules, node/VLAN interfaces, local-cluster RBAC, production Secret permissions and rotation, site-specific cross-namespace relays or IPv6. It does not exercise independent real Keycloak and Vault *inside* this particular K3s cluster; those are separate CI jobs. Cluster installation and active probes are authorized only within disposable CI; PRs in `homelab-gitops` remain draft/unmerged pending site review.

### Fast single-node smoke procedure

The source-manifest security contract is independently tested by `tests/k3s_manifest_contract.py` using pinned PyYAML. The first PR gate starts `hostmarshal-smoke` with only one K3s server (no agents), then runs:

```sh
HOSTMARSHAL_K3D_CLUSTER=hostmarshal-smoke \
HOSTMARSHAL_K3D_BACKEND_NODE=k3d-hostmarshal-smoke-server-0 \
python tests/k3s_cluster_ci.py --mode smoke
```

The second, separate, path-filtered two-agent job runs `--mode network` in `hostmarshal-m4-ci`. Both runners verify the **exact expected disposable k3d kube context** before any Kubernetes mutations; they refuse to run against an arbitrary context, including a homelab cluster. The smoke result is a deployment/authenticated-ingress result only, and never proves CNI isolation.

### Strict loader and Kubernetes ConfigMaps

Kubernetes ConfigMap volumes present projected keys through symlink paths (for atomic updates). HostMarshal's compiled-config loader intentionally accepts only **regular files**, not symlinks. The non-root init reads the three approved YAML filenames from a read-only `config-projected` volume and writes new regular files into the memory-backed `config-regular` volume. HostMarshal mounts only that latter volume, read-only, at `/config`. Never weaken the compiled-config file-type verification or pass the projection directly to HostMarshal. The independent manifest preflight asserts this staging contract.
