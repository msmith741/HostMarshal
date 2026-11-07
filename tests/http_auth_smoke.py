"""M4 external OAuth resource-server integration over real stateless MCP HTTP.

Local JWT signing keys and OIDC-like issuer are disposable CI fixtures.
The Rust listener is intentionally loopback-only (TLS is required at the proxy).
"""
import base64
import json
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from mcp_smoke import BIN

ISSUER = "https://issuer.example.invalid"
RESOURCE = "https://mcp.example.invalid/mcp"


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def run(*command, data=None):
    return subprocess.run(command, input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=True, timeout=25)


def make_keys(root):
    key = root / "signing.pem"
    run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
        "rsa_keygen_bits:2048", "-out", str(key))
    modulus = run("openssl", "rsa", "-in", str(key),
                  "-noout", "-modulus").stdout.decode().split("=")[1].strip()
    jwks = root / "jwks.json"
    jwks.write_text(json.dumps({"keys": [{
        "kid": "test-key-1", "kty": "RSA", "alg": "RS256", "use": "sig",
        "n": b64url(bytes.fromhex(modulus).lstrip(b"\x00")),
        "e": "AQAB",
    }]}))
    jwks.chmod(0o644)
    return key, jwks


def token(key, subject, **overrides):
    now = int(time.time())
    headers = {"alg": "RS256", "typ": "at+jwt", "kid": "test-key-1"}
    headers.update(overrides.pop("headers", {}))
    claims = {
        "iss": ISSUER, "aud": RESOURCE, "sub": subject,
        "iat": now, "nbf": now - 1, "exp": now + 120,
        "scope": "hostmarshal:observe", "client_id": "test-client",
    }
    claims.update(overrides)
    header = b64url(json.dumps(headers, separators=(",", ":")).encode())
    payload = b64url(json.dumps(claims, separators=(",", ":")).encode())
    body = f"{header}.{payload}".encode()
    sig = run("openssl", "dgst", "-sha256", "-sign", str(key), data=body).stdout
    return f"{header}.{payload}.{b64url(sig)}"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def request(port, method="GET", path="/mcp", payload=None, bearer=None, origin=None):
    headers = {"Accept": "application/json, text/event-stream"}
    if bearer is not None:
        headers["Authorization"] = "Bearer " + bearer
    if origin is not None:
        headers["Origin"] = origin
    if payload is not None:
        headers["Content-Type"] = "application/json"
        headers["MCP-Protocol-Version"] = "2026-07-28"
        headers["Mcp-Method"] = payload["method"]
        if payload["method"] == "tools/call":
            headers["Mcp-Name"] = payload["params"]["name"]
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        headers=headers, method=method, data=data,
    )
    try:
        with urllib.request.urlopen(req, timeout=6) as resp:
            raw = resp.read(64 * 1024)
            return resp.status, dict(resp.headers), json.loads(raw) if raw else None
    except urllib.error.HTTPError as ex:
        return ex.code, dict(ex.headers), ex.read(4096).decode()


META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
    "io.modelcontextprotocol/clientInfo": {
        "name": "spoofed-untrusted-client", "version": "1.0",
    },
}


def rpc(port, bearer, number, method, args=None):
    params = {"_meta": dict(META)}
    if args:
        params.update(args)
    payload = {"jsonrpc": "2.0", "id": number, "method": method,
               "params": params}
    return request(port, "POST", payload=payload, bearer=bearer)


def main():
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        key, jwks = make_keys(root)
        config = root / "config"
        config.mkdir()
        for source in Path("config/v1alpha1").glob("*.yaml"):
            shutil.copy2(source, config / source.name)
        grant = config / "grant.yaml"
        grant.write_text(grant.read_text().replace(
            "issuer: local://trusted-launcher", f"issuer: {ISSUER}"
        ).replace("subject: example-operator", "subject: alice"))
        audit = root / "audit.jsonl"
        port = free_port()
        args = [
            str(BIN), "http", "serve", str(config),
            "--bind", f"127.0.0.1:{port}",
            "--issuer", ISSUER,
            "--resource", RESOURCE,
            "--jwks-file", str(jwks),
            "--audit-log", str(audit),
        ]
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        try:
            for _ in range(100):
                try:
                    status, _, meta = request(
                        port, path="/.well-known/oauth-protected-resource")
                    if status == 200:
                        break
                except (ConnectionError, OSError):
                    time.sleep(0.1)
            else:
                raise AssertionError(
                    f"HTTP server failed to start: {process.poll()}, "
                    f"{process.stderr.read() if process.poll() is not None else 'running'}")

            assert meta["resource"] == RESOURCE
            assert meta["authorization_servers"] == [ISSUER]
            assert meta["scopes_supported"] == ["hostmarshal:observe"]
            assert request(
                port, path="/.well-known/oauth-protected-resource/mcp"
            )[0] == 200

            alice = token(key, "alice")
            bob = token(key, "bob")
            denied, challenge, _ = request(port, "POST", payload={
                "jsonrpc": "2.0", "id": 1, "method": "server/discover",
                "params": {"_meta": META},
            })
            assert denied == 401
            challenge_headers = {key.lower(): value for key, value in challenge.items()}
            assert "/.well-known/oauth-protected-resource" in challenge_headers.get("www-authenticate", ""), challenge_headers

            assert rpc(port, alice, 1, "server/discover")[0] == 200
            ok, _, listing = rpc(port, alice, 2, "tools/list")
            assert ok == 200, listing
            assert {x["name"] for x in listing["result"]["tools"]} == {"inventory.inspect"}
            assert listing["result"].get("cacheScope", "").lower() == "private"
            ok, _, response = rpc(port, alice, 3, "tools/call", {
                "name":"inventory.inspect", "arguments":{"target":"sample-linux"}
            })
            assert ok == 200 and response["result"]["structuredContent"]["id"] == "sample-linux", response

            ok, _, listing_bob = rpc(port, bob, 4, "tools/list")
            assert ok == 200 and listing_bob["result"]["tools"] == [], listing_bob
            ok, _, bad = rpc(port, bob, 5, "tools/call", {
                "name":"inventory.inspect", "arguments":{"target":"sample-linux"}
            })
            assert ok == 200 and bad["result"]["isError"] is True, bad
            assert rpc(port, alice, 6, "tools/list")[2]["result"]["tools"]

            # A claim signed by the wrong key, wrong audience/issuer/expiry,
            # long TTL, missing scopes, ID-token typ or future nbf all fail.
            alt_key = root / "other.pem"
            run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                "rsa_keygen_bits:2048", "-out", str(alt_key))
            invalid_tokens = [
                token(alt_key, "alice"),
                token(key, "alice", aud="https://another.example.invalid/mcp"),
                token(key, "alice", iss="https://other.example.invalid"),
                token(key, "alice", exp=int(time.time()) - 1),
                token(key, "alice", exp=int(time.time()) + 3600),
                token(key, "alice", scope="read:other"),
                token(key, "alice", nbf=int(time.time()) + 3600),
                token(key, "alice", headers={"typ":"JWT"}),
                token(key, "alice", headers={"kid":"unknown"}),
            ]
            for invalid in invalid_tokens:
                status, _, _ = rpc(port, invalid, 7, "tools/list")
                assert status == 401, status

            # Origin and token-in-query are forbidden.
            assert request(port, "POST", payload={
                "jsonrpc": "2.0", "id": 8, "method": "tools/list",
                "params": {"_meta": META},
            }, bearer=alice, origin="https://attacker.example.invalid")[0] in (401,403)
            for invalid_origin in [
                "https://mcp.example.invalid/extra-path",
                "https://mcp.example.invalid/?invalid=1",
                "https://mcp.example.invalid/#fragment",
            ]:
                assert request(port, "POST", payload={
                    "jsonrpc": "2.0", "id": 8, "method": "tools/list",
                    "params": {"_meta": META},
                }, bearer=alice, origin=invalid_origin)[0] in (401,403)
            assert request(port, "POST", path="/mcp?access_token=fake",
                           payload={"jsonrpc":"2.0","id":9,"method":"tools/list",
                                    "params":{"_meta":META}}, bearer=alice)[0] == 401

            # No spoofed MCP client identity is authorized in place of alice.
            assert rpc(port, alice, 10, "tools/call", {
                "name":"inventory.inspect",
                "arguments":{"target":"sample-linux","subject":"bob"}
            })[2]["result"]["isError"] is True
            # The localhost service must refuse non-loopback listener requests.
            cannot_start = subprocess.run([
                str(BIN), "http", "serve", str(config),
                "--bind", f"0.0.0.0:{free_port()}",
                "--issuer", ISSUER, "--resource", RESOURCE,
                "--jwks-file", str(jwks),
            ], capture_output=True, text=True, timeout=5)
            assert cannot_start.returncode != 0
            assert "loopback" in cannot_start.stderr

        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

        records = [json.loads(line) for line in audit.read_text().splitlines()]
        assert any(x["subject"] == "alice" and x["phase"] == "succeeded" for x in records)
        assert any(x["subject"] == "bob" and x["phase"] == "denied" for x in records)
        assert all(x["issuer"] == ISSUER for x in records)
        raw = audit.read_text()
        assert alice not in raw and bob not in raw and "Bearer" not in raw
        print("M4 OAuth JWT, per-request MCP identity and negative-path tests passed")


if __name__ == "__main__":
    main()
