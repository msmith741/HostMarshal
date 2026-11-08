"""Independent pre-cluster deployment contract; no kubeconfig required."""
import pathlib
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
objects = list(yaml.safe_load_all((ROOT / "deploy/k3s/ci/resources.yaml").read_text()))
by_kind = {x["kind"]: x for x in objects if x is not None and x["kind"] in ("Deployment", "Service", "NetworkPolicy", "IngressRoute")}
pod = by_kind["Deployment"]["spec"]["template"]["spec"]
security = pod["securityContext"]
assert security["fsGroup"] == 10001
assert security["seccompProfile"]["type"] == "RuntimeDefault"
assert pod["automountServiceAccountToken"] is False
assert pod.get("hostNetwork", False) is False
assert pod["nodeSelector"] == {"hostmarshal.ci/role": "backend"}
init = pod["initContainers"][0]
assert init["securityContext"]["runAsUser"] == 10001
assert init["securityContext"]["runAsNonRoot"] is True
for container in [init, *pod["containers"]]:
    ctx = container["securityContext"]
    assert ctx["allowPrivilegeEscalation"] is False
    assert ctx["capabilities"]["drop"] == ["ALL"]
    assert not ctx["capabilities"].get("add")
    assert ctx["readOnlyRootFilesystem"] is True
assert pod["volumes"][0]["secret"]["defaultMode"] == 0o440
assert by_kind["Service"]["spec"]["type"] == "ClusterIP"
assert [p["port"] for p in by_kind["Service"]["spec"]["ports"]] == [8080]
policy = by_kind["NetworkPolicy"]["spec"]
assert policy["policyTypes"] == ["Ingress"]
assert policy["ingress"] == [{
    "from": [{
        "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
        "podSelector": {"matchLabels": {"app.kubernetes.io/name": "traefik"}},
    }],
    "ports": [{"port": 8080, "protocol": "TCP"}],
}]
route = by_kind["IngressRoute"]["spec"]
assert route["entryPoints"] == ["websecure"]
assert route["tls"]["secretName"] == "hostmarshal-ci-tls"
print("PASS: non-root init/runtime, fsGroup Secret staging, private ClusterIP, exact NetworkPolicy and TLS ingress")
