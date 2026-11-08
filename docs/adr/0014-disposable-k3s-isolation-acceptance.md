# ADR-0014: Multi-node K3s ingress isolation in disposable CI

- **Status:** Proposed — integration-test acceptance, not production deployment
- **Date:** 2026-11-08
- **Related:** ADR-0012, ADR-0013, FR-025–FR-030

## Context

The M4 real-Keycloak CI topology runs Traefik and HostMarshal in the same Docker network namespace, not in Kubernetes. Source review of a private homelab repository found no HostMarshal Argo CD deployment. A useful release gate must exercise the actual Kubernetes NetworkPolicy controller, K3s-bundled Traefik, cross-node pod communications, and TLS routing **before any private cluster deployment**.

## Decision

Provide an intentionally isolated, disposable GitHub Actions job running k3d v5.9.0 with one K3s server and two K3s agents pinned to v1.34.5+k3s1. Keep Flannel, the K3s network-policy controller, and K3s-managed Traefik enabled. Build a local-only HostMarshal test image with the locked Rust dependency graph and import it into the ephemeral nodes.

Deploy a test-only Pod with two containers sharing one network namespace:

1. HostMarshal runs unprivileged, read-only root filesystem, capability drops, without a Kubernetes service-account token, listening **only on `127.0.0.1:8338`**. A disposable init container stages protected owner-only auth and ingress-proof files into an in-memory volume. ConfigMap contains only public signing keys and fictional capability definitions; signing private keys are not placed in the cluster.
2. An unprivileged NGINX proxy on TCP 8080 forwards fixed `/mcp` and OAuth protected-resource metadata paths to localhost. It removes user control of `Host`, forwarded scheme/Host and ingress-proof fields. The proof is injected from a fresh CI Secret and never committed. This proxy is not a claim that ingress proof itself is mTLS.
3. A **ClusterIP-only** Service selects the shared Pod's ingress-sidecar port. A default-isolating ingress NetworkPolicy admits TCP 8080 only from Pods labeled `app.kubernetes.io/name=traefik` **in** `kube-system`; the namespace and Pod selectors are in the **same** NetworkPolicy peer item (logical AND). No HostMarshal port 8338 or NodePort/LoadBalancer is exposed.
4. K3s-bundled Traefik handles exact public Host routing at `websecure`, terminating TLS using a CI-generated certificate. The client verifies the CI root CA, not `-k`, for externally presented HTTPS MCP requests.
5. Run probes on a *different K3s agent* against HostMarshal Service DNS and Pod IP, including a spoofed Traefik Pod label in another namespace and a mismatched Pod label in `kube-system`. Each denial must have a working positive connectivity control. Explicitly add an overbroad ingress NetworkPolicy **in CI only** and assert that it re-opens a previously denied Service path; then delete it and assert that denial returns. This positive/negative control validates that the network-policy tests are genuinely able to detect authorization mistakes.
6. Exercise real signed JWT acceptance and missing-bearer, wrong issuer/audience/scope, not-before, cross-subject grants, unexpected Origin/method, proxy-header forgery, wrong Host and untrusted external CA denials. Existing independent Keycloak and Vault jobs remain required; the K3s job uses ephemeral signed offline JWKS rather than deploying a second heavyweight identity provider.

## Explicit exclusions and risk

The tested container images are CI-only, not a published hardened runtime image or production manifest. Neither the CI runner nor the Pod has access to a homelab cluster, Vault tenant, UniFi firewall or private credentials. K3s Flannel with kube-router NetworkPolicy is the integration environment, not a substitute for real host firewall, MetalLB load balancer, Traefik scheduling/failover, production CA and proof rotation, IPv6 or CNI differences. Kubernetes NetworkPolicies are additive: compromised workload labels or another permissive policy can defeat namespace-to-Pod isolation. The sidecar holds a protected ingress proof and must itself be treated as part of the trusted computing base. Site-specific live bypass probes and an independent security review remain release gates.

No generic shell/tool authorization is added to HostMarshal. This ADR does not approve merging M4 as a production-ready release.

## CI test staging refinement — 2026-11-08

The test is divided into **two independent workflows**: a single-server preflight/Pod/TLS/JWT smoke gate (`k3s-smoke.yml`) and a path-filtered three-node CNI/bypass acceptance gate (`k3s-isolation.yml`). Distinguish readiness/configuration failures from actual network-policy enforcement failures. The extended workflow remains a production release prerequisite even when unrelated PRs only run the smoke gate.

The original init-container approach requiring root `CHOWN`/`FOWNER` was retired after disposable K3s startup failures. Kubernetes `fsGroup: 10001` grants GID 10001 access to its Secret projection (0440) and memory-backed shared directories. Init runs as **UID 10001**, uses `umask 077`, copies protected auth/proof files as owner-readable **0600** for HostMarshal, and adds no capabilities. HostMarshal itself independently rejects broader credential file modes. All containers retain `allowPrivilegeEscalation: false`, read-only root filesystem and `drop: ALL`. This is a CI deployment profile, not a production Secret lifecycle solution.
