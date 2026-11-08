"""M4 K3s multi-node disposable ingress and actual CNI NetworkPolicy acceptance.

Runs ONLY against a k3d cluster already created by the GitHub-hosted CI job.
All config, TLS, JWKS, signing keys and ingress proofs are ephemeral. No
homelab credentials or Kubernetes contexts are used.
"""
import argparse
import http.client
import json
import os
import secrets
import socket
import ssl
import subprocess
import tempfile
import time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from ingress_oidc_ci import generate_ca_and_leaf

RESOURCE = "https://mcp.hmci.example.test/mcp"
MCP_HOST = "mcp.hmci.example.test"
ISSUER = "https://issuer.example.invalid/"
NS = "hostmarshal-ci"
ATTACKER_NS = "hostmarshal-ci-attacker"
NODE_LABEL = "hostmarshal.ci/role"
CLUSTER = os.getenv("HOSTMARSHAL_K3D_CLUSTER", "hostmarshal-m4-ci")
BACKEND_NODE = os.getenv("HOSTMARSHAL_K3D_BACKEND_NODE", f"k3d-{CLUSTER}-agent-0")
ATTACKER_NODE = os.getenv("HOSTMARSHAL_K3D_ATTACKER_NODE", f"k3d-{CLUSTER}-agent-1")
LOCAL_PORT = 18443
IMAGE = "curlimages/curl:8.13.0"


def cmd(*args, timeout=35, check=True, input=None):
    return subprocess.run(
        args, input=input, capture_output=True, text=True,
        check=check, timeout=timeout,
    )


def kube(*args, **kwargs):
    return cmd("kubectl", "--request-timeout=15s", *args, **kwargs)


def read_json(*args):
    return json.loads(kube(*args, "-o", "json").stdout)


def wait_pod(namespace, name, *, seconds=220):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        r = kube("get", "pod", name, "-n", namespace, "-o", "json", check=False)
        if r.returncode == 0:
            p = json.loads(r.stdout)
            if p.get("status", {}).get("phase") == "Running" and all(
                x.get("ready") for x in p.get("status", {}).get("containerStatuses", [])
            ) and len(p.get("status", {}).get("containerStatuses", [])) == len(
                p.get("spec", {}).get("containers", [])
            ):
                return p
            if p.get("status", {}).get("phase") in ("Failed", "Succeeded"):
                raise AssertionError(f"Probe pod {namespace}/{name} not Running")
        time.sleep(2)
    raise AssertionError(f"Pod {namespace}/{name} not Ready within bound")


def kube_apply_yaml(doc):
    kube("apply", "-f", "-", input=json.dumps(doc))


def prepare_fixtures(root):
    ingress_ca, tls_cert, tls_key = generate_ca_and_leaf(
        root / "ingress", MCP_HOST,
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": "k3s-test-rs256", "kty": "RSA", "alg": "RS256", "use": "sig"})
    jwks = root / "keys.json"
    jwks.write_text(json.dumps({"keys": [jwk]}))
    proof = root / "ingress.proof"
    proof.write_text(secrets.token_urlsafe(48))
    proof.chmod(0o600)
    auth = root / "auth.json"
    auth.write_text(json.dumps({
        "apiVersion": "hostmarshal.io/remote-auth/v1alpha1",
        "issuer": ISSUER,
        "audience": RESOURCE,
        "allowedHost": "127.0.0.1:8338",
        "jwksFile": "/runtime/keys.json",
        "ingress": {
            "mode": "trustedProxy",
            "publicHost": MCP_HOST,
            "proofFile": "/runtime/ingress.proof",
        },
    }))
    auth.chmod(0o600)
    return key, ingress_ca, tls_cert, tls_key, auth, proof, jwks


def token(key, *, subject="operator-a", **overrides):
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": RESOURCE,
        "sub": subject,
        "iat": now,
        "nbf": now - 2,
        "exp": now + 300,
        "scope": "hostmarshal.observe",
    }
    claims.update(overrides)
    return jwt.encode(claims, key, algorithm="RS256", headers={
        "typ": "at+jwt", "kid": "k3s-test-rs256",
    })


class PinnedHttps(http.client.HTTPSConnection):
    def connect(self):
        raw = socket.create_connection(("127.0.0.1", self.port), timeout=self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def external(ca, method, path, bearer=None, headers=None):
    context = ssl.create_default_context(cafile=str(ca))
    conn = PinnedHttps(MCP_HOST, LOCAL_PORT, timeout=9, context=context)
    h = {
        "Host": MCP_HOST,
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/list",
    }
    if bearer:
        h["Authorization"] = "Bearer " + bearer
    h.update(headers or {})
    message = {
        "jsonrpc": "2.0",
        "id": 33,
        "method": "tools/list",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {
                    "name": "k3s-ci", "version": "1.0",
                },
            },
        },
    }
    try:
        conn.request(method, path, body=json.dumps(message) if method == "POST" else None, headers=h)
        result = conn.getresponse()
        data = result.read(100000)
        return result.status, {k.lower(): v for k, v in result.getheaders()}, data
    finally:
        conn.close()


def wait_ingress(ca, port_forward, seconds=100):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if port_forward.poll() is not None:
            raise AssertionError("Traefik port forward terminated")
        try:
            code, _, payload = external(
                ca, "GET", "/.well-known/oauth-protected-resource/mcp",
            )
            if code == 200:
                return json.loads(payload)
        except (ConnectionError, TimeoutError, ssl.SSLError, OSError,
                http.client.HTTPException):
            pass
        time.sleep(2)
    raise AssertionError("HostMarshal TLS ingress or backend not ready")


def install(root, tls_cert, tls_key, auth, proof, jwks, *, network=False):
    kube("create", "namespace", NS)
    kube("create", "namespace", ATTACKER_NS)
    kube("label", "node", BACKEND_NODE, NODE_LABEL + "=backend", "--overwrite")
    if network:
        kube("label", "node", ATTACKER_NODE, NODE_LABEL + "=attacker", "--overwrite")
    nginx_template = Path("deploy/k3s/ci/nginx-default.conf.tmpl").resolve()
    fixture_config = root / "config"
    fixture_config.mkdir()
    for source in Path("config/v1alpha1").glob("*.yaml"):
        payload = source.read_text().replace(
            "local://trusted-launcher", ISSUER,
        ).replace("example-operator", "operator-a")
        (fixture_config / source.name).write_text(payload)
    kube("create", "configmap", "hostmarshal-ci-config", "-n", NS,
         "--from-file=" + str(fixture_config))
    kube("create", "configmap", "hostmarshal-ci-nginx", "-n", NS,
         "--from-file=default.conf=" + str(nginx_template))
    kube("create", "configmap", "hostmarshal-ci-jwks", "-n", NS,
         "--from-file=keys.json=" + str(jwks))
    kube("create", "secret", "generic", "hostmarshal-ci-identity", "-n", NS,
         "--from-file=auth.json=" + str(auth),
         "--from-file=ingress.proof=" + str(proof))
    kube("create", "secret", "tls", "hostmarshal-ci-tls", "-n", NS,
         "--cert=" + str(tls_cert), "--key=" + str(tls_key))
    kube("apply", "-f", "deploy/k3s/ci/resources.yaml")
    result = kube("rollout", "status", "deploy/hostmarshal", "-n", NS,
                  "--timeout=75s", timeout=85, check=False)
    if result.returncode != 0:
        # Inspect only the disposable namespace. Never dump Secrets/Pod specs,
        # file content or configured ingress proof into CI logs.
        pod_list = read_json("get", "pods", "-n", NS,
                             "-l", "app.kubernetes.io/name=hostmarshal")
        statuses = []
        for pod in pod_list.get("items", []):
            for c in pod.get("status", {}).get("containerStatuses", []):
                state = c.get("state", {})
                previous = c.get("lastState", {}).get("terminated", {})
                statuses.append({
                    "container": c["name"],
                    "ready": c.get("ready"),
                    "reason": (state.get("waiting") or state.get("terminated") or {}).get("reason"),
                    "exitCode": previous.get("exitCode"),
                })
        # Startup logs are ephemeral and redacted against the generated proof.
        # Only collect bounded output from the two test containers on failure.
        sections = []
        for name in ("hostmarshal", "ingress-sidecar"):
            output = kube("logs", "deployment/hostmarshal", "-n", NS,
                          "-c", name, "--tail=18", check=False)
            lines = (output.stdout + output.stderr).replace(
                proof.read_text().strip(), "<redacted-ci-proof>"
            )
            sections.append(name + ": " + lines[-1500:])
        raise AssertionError(
            "HostMarshal rollout failed; container statuses: "
            + json.dumps(statuses) + "; " + "; ".join(sections)
        )


def attacker_pod(name, namespace, label):
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {
            "name": name, "namespace": namespace,
            "labels": {"app.kubernetes.io/name": label},
        },
        "spec": {
            "restartPolicy": "Never",
            "nodeSelector": {NODE_LABEL: "attacker"},
            "automountServiceAccountToken": False,
            "containers": [{
                "name": "curl", "image": IMAGE,
                "command": ["sh", "-c", "sleep 800"],
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "capabilities": {"drop": ["ALL"]},
                },
            }],
        },
    }


def probe(ns, pod, address):
    result = kube(
        "exec", "-n", ns, pod, "--",
        "curl", "--noproxy", "*", "-k",
        "--connect-timeout", "2", "--max-time", "5",
        "-s", "-o", "/dev/null",
        "-w", "%{http_code}",
        address, check=False, timeout=16,
    )
    # 000 with curl's nonzero exit = no established HTTP connection.
    return result.returncode == 0 and result.stdout.strip() != "000", (
        result.returncode, result.stdout.strip(),
    )


def test_network_isolation(key, ca):
    pod = read_json("get", "pods", "-n", NS, "-l", "app.kubernetes.io/name=hostmarshal")
    assert len(pod["items"]) == 1, "requires exactly one backend"
    backend = pod["items"][0]
    backend_ip = backend["status"]["podIP"]
    assert backend["spec"]["nodeName"] == BACKEND_NODE
    assert all(not c["securityContext"].get("allowPrivilegeEscalation", True)
               for c in backend["spec"]["containers"])
    svc = read_json("get", "service", "hostmarshal", "-n", NS)
    assert svc["spec"]["type"] == "ClusterIP"
    assert not svc["spec"].get("externalIPs")
    assert not any("nodePort" in p for p in svc["spec"]["ports"])
    assert not backend["spec"].get("hostNetwork")
    assert not backend["spec"].get("automountServiceAccountToken", True)
    assert all(c.get("imagePullPolicy") != "Always" for c in backend["spec"]["containers"])

    for name, ns, label in [
        ("remote-attacker", ATTACKER_NS, "traefik"),  # spoof label, wrong namespace
        ("kube-system-attacker", "kube-system", "untrusted-probe"),  # namespace only
    ]:
        kube_apply_yaml(attacker_pod(name, ns, label))
        attacker = wait_pod(ns, name)
        assert attacker["spec"]["nodeName"] == ATTACKER_NODE, "cross-node test not scheduled"
        # Positive: pod has valid DNS and can reach the in-cluster Kubernetes API.
        connected, proof = probe(ns, name, "https://kubernetes.default.svc")
        if not connected:
            raise AssertionError(f"{ns}: positive API connectivity failed: {proof}")
        for target in [
            f"http://hostmarshal.{NS}.svc.cluster.local:8080/mcp",
            f"http://{backend_ip}:8080/mcp",
            f"http://{backend_ip}:8338/mcp",
        ]:
            reachable, details = probe(ns, name, target)
            assert not reachable, (ns, target, details)

    # The attacker must become able to access a deliberately overbroad policy,
    # proving that the denial checks actually exercise the CNI policy plane.
    bad = {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"namespace": NS, "name": "unsafe-bypass-control-ci"},
        "spec": {
            "podSelector": {"matchLabels": {"app.kubernetes.io/name": "hostmarshal"}},
            "policyTypes": ["Ingress"],
            "ingress": [{"from": [{"namespaceSelector": {
                "matchLabels": {"kubernetes.io/metadata.name": ATTACKER_NS},
            }}], "ports": [{"protocol": "TCP", "port": 8080}]}],
        },
    }
    kube_apply_yaml(bad)
    try:
        deadline = time.monotonic() + 45
        while True:
            accessible, _ = probe(
                ATTACKER_NS, "remote-attacker",
                f"http://hostmarshal.{NS}.svc.cluster.local:8080/mcp",
            )
            if accessible:
                break
            if time.monotonic() >= deadline:
                raise AssertionError("positive network policy bypass control never opened")
            time.sleep(2)
    finally:
        kube("delete", "networkpolicy", bad["metadata"]["name"], "-n", NS,
             "--wait=true", timeout=30)
    deadline = time.monotonic() + 45
    while True:
        accessible, _ = probe(
            ATTACKER_NS, "remote-attacker",
            f"http://hostmarshal.{NS}.svc.cluster.local:8080/mcp",
        )
        if not accessible:
            break
        if time.monotonic() >= deadline:
            raise AssertionError("network isolation NOT restored after deleting additive bypass")
        time.sleep(2)


def test_authorization(key, ca):
    metadata = wait_ingress(ca, FORWARD)
    assert metadata["resource"] == RESOURCE, metadata
    assert metadata["authorization_servers"] == [ISSUER]
    allowed = token(key)
    denied = token(key, subject="operator-b")
    status, headers, _ = external(ca, "POST", "/mcp", bearer=None)
    assert status == 401 and "resource_metadata=" in headers.get("www-authenticate", "")
    code, _, body = external(ca, "POST", "/mcp", bearer=allowed)
    assert code == 200 and b"inventory.inspect" in body, (code, body)
    code, _, body = external(ca, "POST", "/mcp", bearer=denied)
    assert code == 200 and json.loads(body)["result"]["tools"] == [], (code, body)
    for bad in [
        token(key, iss="https://rogue.example.invalid/"),
        token(key, aud="https://rogue.example.invalid/mcp"),
        token(key, scope="different.scope"),
        token(key, nbf=int(time.time()) + 3600),
        token(key, exp=int(time.time()) - 100),
    ]:
        assert external(ca, "POST", "/mcp", bearer=bad)[0] == 401
    # Host, Origin and non-POST method restrictions are enforced.
    assert external(ca, "POST", "/mcp", bearer=allowed,
                    headers={"Host": "rogue.invalid"})[0] in (404, 421)
    assert external(ca, "POST", "/mcp", bearer=allowed,
                    headers={"Origin": "https://rogue.invalid"})[0] == 403
    assert external(ca, "GET", "/mcp", bearer=allowed)[0] == 405

    # Untrusted client-supplied proxy headers cannot change authenticated
    # identity, public hostname or internal trust proof.
    forged = {
        "X-Forwarded-Proto": "http",
        "X-Forwarded-Host": "rogue.invalid",
        "X-HostMarshal-Ingress-Proof": "untrusted",
        "X-Forwarded-User": "operator-b",
    }
    code, _, body = external(ca, "POST", "/mcp", bearer=allowed, headers=forged)
    assert code == 200 and b"inventory.inspect" in body, (code, body)
    # Exercise a genuine, syntactically valid *untrusted* CA (not /dev/null,
    # which would only prove that SSL rejects a malformed trust file).
    with tempfile.TemporaryDirectory(prefix="hm-k3s-wrong-ca-") as temp:
        wrong_ca, _, _ = generate_ca_and_leaf(
            Path(temp) / "untrusted-root", MCP_HOST
        )
        try:
            external(wrong_ca, "GET",
                     "/.well-known/oauth-protected-resource/mcp")
        except ssl.SSLError:
            pass
        else:
            raise AssertionError("untrusted CA unexpectedly verified ingress TLS")


def main():
    global FORWARD
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["smoke", "network"], required=True)
    options = parser.parse_args()
    # The test performs kubectl mutations. Reject any context other than the
    # specifically provisioned ephemeral k3d cluster.
    context = kube("config", "current-context").stdout.strip()
    if context != f"k3d-{CLUSTER}":
        raise RuntimeError("refusing Kubernetes mutations outside the named disposable k3d context")
    with tempfile.TemporaryDirectory(prefix="hm-k3s-m4-") as dirname:
        root = Path(dirname)
        signer, ca, tls_cert, tls_key, auth, proof, jwks = prepare_fixtures(root)
        install(root, tls_cert, tls_key, auth, proof, jwks,
                network=options.mode == "network")
        pod = read_json("get", "pods", "-n", NS, "-l", "app.kubernetes.io/name=hostmarshal")
        assert len(pod["items"]) == 1
        runtime = pod["items"][0]
        assert len(runtime["spec"]["containers"]) == 2
        assert runtime["spec"]["containers"][0]["name"] == "hostmarshal"
        assert runtime["spec"]["containers"][1]["name"] == "ingress-sidecar"
        FORWARD = subprocess.Popen([
            "kubectl", "-n", "kube-system", "port-forward", "svc/traefik",
            f"{LOCAL_PORT}:443", "--address", "127.0.0.1",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            test_authorization(signer, ca)
            if options.mode == "network":
                test_network_isolation(signer, ca)
                # Recheck the authorized path after policy mutation/recovery.
                code, _, body = external(ca, "POST", "/mcp", bearer=token(signer))
                assert code == 200 and b"inventory.inspect" in body, code
                print("PASS: multi-node CNI policy isolation, unsafe-policy "
                      "causality and restored denial, authenticated MCP TLS")
            else:
                print("PASS: single-node K3s Pod startup, TLS ingress, "
                      "JWT authorization/denial, proxy-header protection")
        finally:
            FORWARD.terminate()
            FORWARD.wait(timeout=10)


if __name__ == "__main__":
    main()
