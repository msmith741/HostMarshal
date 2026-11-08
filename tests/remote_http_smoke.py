"""M4 signed JWT + stateless MCP HTTP negative-path integration.

Uses a disposable RSA signing key and JWKS generated in-memory. The server
must bind only to loopback and every RPC must re-authenticate independently.
"""
import http.client
import json
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp_smoke import BIN

ISSUER = "https://issuer.example.invalid/"
AUDIENCE = "https://mcp.example.invalid/mcp"


def port_available():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def rpc(port, token, method, params=None, extra_headers=None, body=None):
    content = body if body is not None else json.dumps({
        "jsonrpc": "2.0", "id": 19, "method": method,
        "params": params if params is not None else {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {
                    "name": "untrusted-client", "version": "1.0",
                },
            }
        },
    })
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
    }
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if extra_headers:
        headers.update(extra_headers)
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
    try:
        connection.request("POST", "/mcp", body=content, headers=headers)
        response = connection.getresponse()
        payload = response.read()
        result = json.loads(payload) if payload.startswith(b"{") else payload.decode(errors="replace")
        return response.status, result
    finally:
        connection.close()


def claims(subject="operator-a", **overrides):
    now = int(time.time())
    result = {
        "iss": ISSUER, "aud": AUDIENCE, "sub": subject,
        "iat": now, "nbf": now - 1, "exp": now + 300,
        "scope": "hostmarshal.observe",
    }
    result.update(overrides)
    return result


def run():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": "trusted-1", "alg": "RS256", "use": "sig"})

    def token(subject="operator-a", key_override=None, headers=None, **overrides):
        return jwt.encode(
            claims(subject, **overrides),
            key_override if key_override is not None else key,
            algorithm="RS256",
            headers={"kid": "trusted-1", "typ": "at+jwt", **(headers or {})},
        )

    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        config = root / "config"
        config.mkdir()
        for src in Path("config/v1alpha1").glob("*.yaml"):
            contents = src.read_text()
            contents = contents.replace("local://trusted-launcher", ISSUER)
            contents = contents.replace("example-operator", "operator-a")
            (config / src.name).write_text(contents)
        jwks = root / "trusted-jwks.json"
        jwks.write_text(json.dumps({"keys": [jwk]}))
        jwks.chmod(0o644)

        port = port_available()
        auth = root / "remote-auth.json"
        auth.write_text(json.dumps({
            "apiVersion": "hostmarshal.io/remote-auth/v1alpha1",
            "issuer": ISSUER, "audience": AUDIENCE,
            "allowedHost": f"127.0.0.1:{port}",
            "jwksFile": str(jwks),
        }))
        auth.chmod(0o600)
        audit = root / "audit.jsonl"

        command = [
            str(BIN), "http", "--listen", f"127.0.0.1:{port}",
            "--config-dir", str(config), "--auth-config", str(auth),
            "--audit-log", str(audit),
        ]
        server = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        try:
            for _ in range(90):
                if server.poll() is not None:
                    raise AssertionError(f"HTTP server terminated early: {server.stderr.read()}")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise AssertionError("M4 HTTP listener did not start")

            valid = token()
            status, data = rpc(port, valid, "server/discover")
            assert status == 200 and "result" in data, (status, data)
            status, data = rpc(port, valid, "tools/list")
            assert status == 200, (status, data)
            assert {tool["name"] for tool in data["result"]["tools"]} == {"inventory.inspect"}

            status, data = rpc(port, valid, "tools/call", {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "untrusted-client", "version": "1.0",
                    },
                },
                "name": "inventory.inspect",
                "arguments": {"target": "sample-linux"},
            })
            assert status == 200 and data["result"]["structuredContent"]["id"] == "sample-linux", data

            # Every separate request MUST use its own cryptographically verified identity.
            status, data = rpc(port, token("operator-b"), "tools/list")
            assert status == 200, (status, data)
            assert data["result"]["tools"] == [], data
            status, data = rpc(port, token("operator-b"), "tools/call", {
                "name": "inventory.inspect", "arguments": {"target": "sample-linux"},
                "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"},
            })
            assert status == 200 and data["result"].get("isError") is True, (status, data)

            invalid_tokens = [
                None, "",
                token(key_override=attacker),  # forged signature, same kid
                token(aud="https://wrong.example.invalid/mcp"),
                token(iss="https://other-issuer.example.invalid/"),
                token(exp=int(time.time()) - 500),
                token(nbf=int(time.time()) + 1000),
                token(iat=int(time.time()) + 1000),
                token(scope="other.read"),
                token(headers={"kid": "unknown"}),
                token(headers={"typ": "JWT"}),
                token(exp=int(time.time()) + 7200),
            ]
            for bad in invalid_tokens:
                status, _ = rpc(port, bad, "tools/list")
                assert status == 401, (bad is None, status)

            for headers, expected in [
                ({"Origin": "https://evil.example.invalid"}, 403),
                ({"Host": "attacker.example.invalid"}, 400),
            ]:
                status, _ = rpc(port, valid, "tools/list", extra_headers=headers)
                assert status == expected, (headers, status)
            status, data = rpc(
                port, valid, "tools/list",
                extra_headers={"X-Forwarded-User": "operator-a"},
            )
            assert status == 200, (status, data)

            # The caller cannot select an arbitrary URL, command, or target.
            status, data = rpc(port, valid, "tools/call", {
                "name": "inventory.inspect",
                "arguments": {"target": "sample-linux", "command": "id"},
                "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"},
            })
            assert status == 200 and data["result"].get("isError") is True

            status, _ = rpc(port, valid, "tools/list", body="x" * 300000)
            assert status in (413, 400), status

            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/mcp", headers={"Authorization": f"Bearer {valid}"})
            assert conn.getresponse().status == 405
            conn.close()

        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)

        audit_text = audit.read_text()
        assert "operator-a" in audit_text
        assert "operator-b" in audit_text
        assert valid not in audit_text
        assert "Authorization" not in audit_text
        print("M4 JWT-authenticated stateless MCP HTTP integration tests passed")

        # Prevent remote binding even with a valid protected auth configuration.
        blocked = subprocess.run(
            [str(BIN), "http", "--listen", "0.0.0.0:9876",
             "--config-dir", str(config), "--auth-config", str(auth)],
            capture_output=True, text=True, timeout=5,
        )
        assert blocked.returncode != 0
        assert "loopback" in blocked.stderr

        auth.chmod(0o644)
        bad_acl = subprocess.run(
            command, capture_output=True, text=True, timeout=5,
        )
        assert bad_acl.returncode != 0
        assert "protected" in bad_acl.stderr


if __name__ == "__main__":
    run()
