"""M4 real Keycloak OAuth2 + file-provider Traefik / network isolation CI.

GitHub-hosted runner only. Generates all keys/secrets at runtime, starts real
Keycloak and Traefik containers, puts HostMarshal in Traefik's network namespace
with a loopback-only backend and no published service port. No homelab access.
"""
import http.client
import json
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.parse
from pathlib import Path

import jwt

from mcp_smoke import BIN

ISSUER_HOST = "auth.example.invalid"
MCP_HOST = "mcp.example.invalid"
RESOURCE = f"https://{MCP_HOST}/mcp"
REALM = "hostmarshal-ci"
KC_IMAGE = "quay.io/keycloak/keycloak:26.4.2"
TRAEFIK_IMAGE = "traefik:v3.6.9"
OS_IMAGE = "ubuntu:24.04"
ATTACK_IMAGE = "alpine:3.22"


def run(*args, timeout=50, check=True):
    return subprocess.run(
        args, check=check, capture_output=True, text=True, timeout=timeout,
    )


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def generate_ca_and_leaf(folder, dns_name):
    folder.mkdir()
    ca_key, ca_cert = folder / "ca.key", folder / "ca.pem"
    leaf_key, leaf_csr, leaf_cert = (
        folder / "server.key", folder / "server.csr", folder / "server.pem"
    )
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-noenc",
        "-days", "1", "-subj", f"/CN={dns_name} test CA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-keyout", str(ca_key), "-out", str(ca_cert), timeout=20)
    run("openssl", "req", "-newkey", "rsa:2048", "-noenc",
        "-subj", f"/CN={dns_name}", "-keyout", str(leaf_key),
        "-out", str(leaf_csr), timeout=20)
    extensions = folder / "server.ext"
    extensions.write_text(
        f"subjectAltName=DNS:{dns_name}\n"
        "basicConstraints=CA:FALSE\n"
        "keyUsage=digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
    )
    run("openssl", "x509", "-req", "-in", str(leaf_csr),
        "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial",
        "-days", "1", "-out", str(leaf_cert),
        "-extfile", str(extensions), timeout=20)
    return ca_cert, leaf_cert, leaf_key


class PinnedConnection(http.client.HTTPSConnection):
    """Verify TLS against the test CA, while routing to host-mapped loopback."""
    def connect(self):
        raw = socket.create_connection(("127.0.0.1", self.port), timeout=self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def https_request(host, port, ca, method, path, headers=None, body=None):
    context = ssl.create_default_context(cafile=str(ca))
    connection = PinnedConnection(host, port, timeout=7, context=context)
    h = dict(headers or {})
    h.setdefault("Host", f"{host}:8444" if host == ISSUER_HOST else MCP_HOST)
    try:
        connection.request(method, path, body=body, headers=h)
        response = connection.getresponse()
        payload = response.read(128 * 1024)
        return response.status, {
            k.lower(): v for k, v in response.getheaders()
        }, payload
    finally:
        connection.close()


def mcp_rpc(port, ca, token, headers=None):
    metadata = {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {"name": "ci", "version": "1.0"},
    }
    message = {
        "jsonrpc": "2.0", "id": 7, "method": "tools/list",
        "params": {"_meta": metadata},
    }
    h = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/list",
    }
    if token:
        h["Authorization"] = f"Bearer {token}"
    h.update(headers or {})
    return https_request(
        MCP_HOST, port, ca, "POST", "/mcp",
        headers=h, body=json.dumps(message),
    )


def token_request(port, ca, secret, *, client_id="hostmarshal-client",
                  scope="hostmarshal.observe"):
    payload = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": secret,
        "scope": scope,
    }).encode()
    return https_request(
        ISSUER_HOST, port, ca, "POST",
        f"/realms/{REALM}/protocol/openid-connect/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=payload,
    )


def wait_http(host, port, ca, path, deadline=160):
    finish = time.monotonic() + deadline
    last = None
    while time.monotonic() < finish:
        try:
            status, _, payload = https_request(host, port, ca, "GET", path)
            if status == 200:
                return json.loads(payload)
            last = f"HTTP {status}"
        except (OSError, ssl.SSLError, ValueError, http.client.HTTPException) as exc:
            last = type(exc).__name__
        time.sleep(1.5)
    raise AssertionError(f"TLS service {host} did not become healthy: {last}")


def network_inspection(proxy_name, backend_name, kc_name, network):
    inspect = json.loads(run(
        "docker", "inspect", proxy_name, backend_name, kc_name,
    ).stdout)
    proxy, backend, keycloak = inspect
    assert backend["HostConfig"]["NetworkMode"].startswith("container:"), "backend must share proxy netns"
    assert not backend["HostConfig"]["PortBindings"], "backend publishes its HTTP port"
    assert not keycloak["HostConfig"]["PortBindings"], "issuer must not expose HTTP backend"
    assert set(proxy["HostConfig"]["PortBindings"]) == {"8443/tcp", "8444/tcp"}
    assert all(
        all(x["HostIp"] == "127.0.0.1" for x in host_ports)
        for host_ports in proxy["HostConfig"]["PortBindings"].values()
    ), "CI proxy ports must be loopback-published"
    address = proxy["NetworkSettings"]["Networks"][network]["IPAddress"]
    assert address
    # No other container can connect to HostMarshal's 127.0.0.1 port,
    # even when attached to the same bridge as Traefik and Keycloak.
    failed = run(
        "docker", "run", "--rm", "--network", network, ATTACK_IMAGE,
        "sh", "-c", f"wget -q -T 3 -O - http://{address}:8338/mcp",
        check=False, timeout=30,
    )
    assert failed.returncode != 0, "isolated backend was reachable on Docker bridge"
    with socket.socket() as sock:
        sock.settimeout(1)
        assert sock.connect_ex(("127.0.0.1", 8338)) != 0, "HostMarshal port exposed on runner"


def write_realm(path, client_secret, denied_secret):
    # The only real credential is generated per CI job; never committed.
    realm = {
        "realm": REALM, "enabled": True, "sslRequired": "none",
        "accessTokenLifespan": 300,
        "clientScopes": [{
            "name": "hostmarshal.observe",
            "protocol": "openid-connect",
            "attributes": {
                "include.in.token.scope": "true",
                "display.on.consent.screen": "false",
            },
        }],
        "clients": [{
            "clientId": "hostmarshal-client",
            "enabled": True,
            "protocol": "openid-connect",
            "clientAuthenticatorType": "client-secret",
            "publicClient": False,
            "serviceAccountsEnabled": True,
            "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "secret": client_secret,
            "attributes": {
                "access.token.header.type.rfc9068": "true",
            },
            "defaultClientScopes": ["hostmarshal.observe"],
            "protocolMappers": [{
                "name": "hostmarshal-resource-audience",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "consentRequired": False,
                "config": {
                    "included.custom.audience": RESOURCE,
                    "access.token.claim": "true",
                    "id.token.claim": "false",
                },
            }],
        }],
    }
    # Second real service account has valid JWT issuer/audience/scope but no
    # HostMarshal Grant. Cryptographic identity does not grant a capability.
    denied = json.loads(json.dumps(realm["clients"][0]))
    denied["clientId"] = "hostmarshal-ungranted"
    denied["secret"] = denied_secret
    realm["clients"].append(denied)
    path.write_text(json.dumps(realm))
    # This fixture is read-only mounted into non-root Keycloak; all secrets
    # are disposable and never committed or logged.
    path.chmod(0o644)


def main():
    prefix = "hmci-" + secrets.token_hex(4)
    network = prefix + "-auth"
    proxy, keycloak, backend = (
        prefix + "-traefik", prefix + "-keycloak", prefix + "-backend"
    )
    published_mcp, published_auth = free_port(), free_port()
    secret = secrets.token_urlsafe(32)
    denied_secret = secrets.token_urlsafe(32)
    proof = secrets.token_urlsafe(48)
    root = Path(tempfile.mkdtemp(prefix="hmci-ingress-"))
    created = []
    try:
        oauth_ca, oauth_cert, oauth_key = generate_ca_and_leaf(
            root / "oauth-tls", ISSUER_HOST,
        )
        ingress_ca, ingress_cert, ingress_key = generate_ca_and_leaf(
            root / "ingress-tls", MCP_HOST,
        )
        realm = root / "realm.json"
        write_realm(realm, secret, denied_secret)
        run("docker", "network", "create", network)
        created.append(("network", network))
        kc_args = [
            "docker", "run", "-d", "--name", keycloak,
            "--network", network, "--network-alias", "hostmarshal-keycloak",
            "--restart", "no",
            "-e", "KC_HTTP_ENABLED=true",
            "-e", "KC_PROXY_HEADERS=xforwarded",
            "-e", f"KC_HOSTNAME=https://{ISSUER_HOST}:8444",
            "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=test-admin",
            "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD=" + secrets.token_urlsafe(24),
            "-v", f"{realm}:/opt/keycloak/data/import/realm.json:ro",
            KC_IMAGE, "start-dev", "--import-realm",
        ]
        run(*kc_args, timeout=70)
        created.append(("container", keycloak))

        proxy_dir = root / "traefik"
        proxy_dir.mkdir()
        (proxy_dir / "static.yml").write_text(
            Path("deploy/traefik/ingress-static.yml").read_text()
        )
        dynamic = Path("deploy/traefik/ingress-dynamic.yml.tmpl").read_text()
        for a, b in {
            "@@INGRESS_PROOF@@": proof,
            "@@MCP_TLS_CERT@@": "/etc/traefik/mcp-server.pem",
            "@@MCP_TLS_KEY@@": "/etc/traefik/mcp-server.key",
            "@@OAUTH_TLS_CERT@@": "/etc/traefik/oauth-server.pem",
            "@@OAUTH_TLS_KEY@@": "/etc/traefik/oauth-server.key",
        }.items():
            dynamic = dynamic.replace(a, b)
        assert "@@" not in dynamic
        (proxy_dir / "dynamic.yml").write_text(dynamic)
        (proxy_dir / "dynamic.yml").chmod(0o600)
        for name, source in [
            ("mcp-server.pem", ingress_cert),
            ("mcp-server.key", ingress_key),
            ("oauth-server.pem", oauth_cert),
            ("oauth-server.key", oauth_key),
        ]:
            shutil.copyfile(source, proxy_dir / name)
        run(
            "docker", "run", "-d", "--name", proxy,
            "--network", network, "--network-alias", ISSUER_HOST,
            "--restart", "no",
            "-p", f"127.0.0.1:{published_mcp}:8443",
            "-p", f"127.0.0.1:{published_auth}:8444",
            "-v", f"{proxy_dir}:/etc/traefik:ro",
            TRAEFIK_IMAGE, "--configFile=/etc/traefik/static.yml",
            timeout=70,
        )
        created.append(("container", proxy))
        issuer = f"https://{ISSUER_HOST}:8444/realms/{REALM}"
        discovery = wait_http(
            ISSUER_HOST, published_auth, oauth_ca,
            f"/realms/{REALM}/.well-known/openid-configuration",
        )
        assert discovery["issuer"] == issuer
        assert discovery["jwks_uri"] == (
            issuer + "/protocol/openid-connect/certs"
        ), discovery
        assert "client_credentials" in discovery.get("grant_types_supported", [])

        denied, _, payload = token_request(
            published_auth, oauth_ca, "incorrect-" + secret,
        )
        assert denied == 401, (denied, payload)
        status, _, data = token_request(published_auth, oauth_ca, secret)
        assert status == 200, (status, data)
        access_token = json.loads(data)["access_token"]
        assert jwt.get_unverified_header(access_token)["typ"] == "at+jwt"
        claims = jwt.decode(access_token, options={"verify_signature": False})
        assert claims["iss"] == issuer
        assert RESOURCE in (
            [claims["aud"]] if isinstance(claims["aud"], str) else claims["aud"]
        )
        assert "hostmarshal.observe" in claims.get("scope", "").split()
        assert len(claims["sub"]) <= 128

        fixture = root / "hostmarshal"
        fixture.mkdir()
        config = fixture / "config"
        config.mkdir()
        for source in Path("config/v1alpha1").glob("*.yaml"):
            contents = source.read_text().replace("local://trusted-launcher", issuer)
            contents = contents.replace("example-operator", claims["sub"])
            (config / source.name).write_text(contents)
        ingress_proof = fixture / "ingress.proof"
        ingress_proof.write_text(proof + "\n")
        ingress_proof.chmod(0o600)
        auth_config = fixture / "auth.json"
        auth_config.write_text(json.dumps({
            "apiVersion": "hostmarshal.io/remote-auth/v1alpha1",
            "issuer": issuer,
            "audience": RESOURCE,
            "allowedHost": "127.0.0.1:8338",
            "jwksUrl": issuer + "/protocol/openid-connect/certs",
            "jwksCaCertificateFile": "/fixtures/oauth-ca.pem",
            "jwksRefreshSeconds": 60,
            "authorizationServerMetadataUrl":
                issuer + "/.well-known/openid-configuration",
            "ingress": {
                "mode": "trustedProxy",
                "publicHost": MCP_HOST,
                "proofFile": "/fixtures/ingress.proof",
            },
        }))
        auth_config.chmod(0o600)
        shutil.copyfile(oauth_ca, fixture / "oauth-ca.pem")
        run(
            "docker", "run", "-d", "--name", backend,
            "--network", "container:" + proxy,
            "--restart", "no",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--tmpfs", "/tmp:rw,nosuid,noexec,size=16m",
            "-v", f"{BIN.resolve()}:/usr/local/bin/hostmarshal:ro",
            "-v", f"{fixture}:/fixtures:ro",
            OS_IMAGE, "/usr/local/bin/hostmarshal",
            "http", "--listen", "127.0.0.1:8338",
            "--config-dir", "/fixtures/config",
            "--auth-config", "/fixtures/auth.json",
            "--audit-log", "/tmp/audit.jsonl",
            timeout=70,
        )
        created.append(("container", backend))

        metadata = wait_http(
            MCP_HOST, published_mcp, ingress_ca,
            "/.well-known/oauth-protected-resource/mcp", deadline=30,
        )
        assert metadata["resource"] == RESOURCE
        assert metadata["authorization_servers"] == [issuer]
        network_inspection(proxy, backend, keycloak, network)
        status, headers, _ = mcp_rpc(published_mcp, ingress_ca, None)
        assert status == 401 and "resource_metadata=" in headers.get("www-authenticate", "")
        status, _, body = mcp_rpc(published_mcp, ingress_ca, access_token)
        assert status == 200 and b"inventory.inspect" in body, (status, body)
        assert b"sample-linux" not in body
        # Same real issuer and signed audience/scope, distinct service account:
        # the verification succeeds but HostMarshal's Grant must deny tools.
        denied_status, _, denied_reply = token_request(
            published_auth, oauth_ca, denied_secret,
            client_id="hostmarshal-ungranted",
        )
        assert denied_status == 200, (denied_status, denied_reply)
        denied_token = json.loads(denied_reply)["access_token"]
        assert jwt.decode(
            denied_token, options={"verify_signature": False},
        )["sub"] != claims["sub"]
        denied_status, _, denied_tools = mcp_rpc(
            published_mcp, ingress_ca, denied_token,
        )
        assert denied_status == 200 and json.loads(denied_tools)["result"]["tools"] == [], (
            denied_status, denied_tools,
        )  # scope gates discovery, not inventory contents

        status, _, body = mcp_rpc(
            published_mcp, ingress_ca, access_token,
            headers={
                "X-Forwarded-Proto": "http",
                "X-Forwarded-Host": "attacker.invalid",
                "X-HostMarshal-Ingress-Proof": "forged",
            },
        )
        assert status == 200 and b"inventory.inspect" in body, (status, body)

        # Discovery is pinned to administrator expectations. A wrong issuer
        # or a changed JWKS URI must PREVENT the server from binding, not
        # silently use keys from the discovery response.
        for failure, changed, message in [
            ("issuer", {"issuer": issuer + "-attacker"}, "issuer mismatch"),
            ("jwks", {"jwksUrl": issuer + "/protocol/openid-connect/other-certs"},
             "administrator-pinned URL"),
        ]:
            bad = json.loads(auth_config.read_text())
            bad.update(changed)
            bad_path = fixture / f"auth-bad-{failure}.json"
            bad_path.write_text(json.dumps(bad))
            bad_path.chmod(0o600)
            denied = run(
                "docker", "run", "--rm",
                "--network", "container:" + proxy,
                "--user", f"{os.getuid()}:{os.getgid()}",
                "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                "-v", f"{BIN.resolve()}:/usr/local/bin/hostmarshal:ro",
                "-v", f"{fixture}:/fixtures:ro",
                OS_IMAGE, "/usr/local/bin/hostmarshal",
                "http", "--listen", "127.0.0.1:8339",
                "--config-dir", "/fixtures/config",
                "--auth-config", "/fixtures/" + bad_path.name,
                check=False, timeout=18,
            )
            assert denied.returncode != 0 and message in denied.stderr, (
                failure, denied.returncode, denied.stderr[-500:],
            )

        # A Keycloak access token with audience/scope requirements missing is
        # rejected regardless of the real issuer signature.
        status, _, token_data = token_request(
            published_auth, oauth_ca, secret, scope="openid",
        )
        if status == 200:
            token_without_scope = json.loads(token_data)["access_token"]
            if "hostmarshal.observe" not in jwt.decode(
                token_without_scope, options={"verify_signature": False},
            ).get("scope", "").split():
                assert mcp_rpc(
                    published_mcp, ingress_ca, token_without_scope,
                )[0] == 401

        other_ca = oauth_ca
        try:
            https_request(MCP_HOST, published_mcp, other_ca,
                "GET", "/.well-known/oauth-protected-resource/mcp")
        except ssl.SSLCertVerificationError:
            pass
        else:
            raise AssertionError("untrusted ingress TLS certificate accepted")

        wrong_host = https_request(
            MCP_HOST, published_mcp, ingress_ca, "GET",
            "/.well-known/oauth-protected-resource/mcp",
            headers={"Host": "attacker.invalid"},
        )
        assert wrong_host[0] in (404, 421), wrong_host[0]
        print("CI: real Keycloak token/discovery, Traefik ingress, bypass isolation PASS")
    finally:
        for kind, value in reversed(created):
            if kind == "container":
                run("docker", "rm", "-f", value, check=False, timeout=35)
            else:
                run("docker", "network", "rm", value, check=False, timeout=35)
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
