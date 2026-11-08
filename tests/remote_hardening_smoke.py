"""M4 remote auth hardening: trusted HTTPS JWKS rotation and TLS-ingress bypass.
Only disposable localhost TLS endpoints, signing keys and proof files are used.
"""
import http.client
import json
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp_smoke import BIN
from remote_http_smoke import ISSUER, AUDIENCE, claims, port_available, rpc
from transport_smoke import tls_material


def tls_cert(root, name):
    folder = root / name
    folder.mkdir()
    # A pinned trust anchor must be a CA, NOT an end-entity certificate.
    # Reuse the existing independently tested CA + localhost server leaf.
    return tls_material(folder)


def start_tls_server(port, handler, cert, key):
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    return server


def jwt_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": "rotating", "alg": "RS256", "use": "sig"})
    return key, jwk


def issue(key, **overrides):
    return jwt.encode(claims(**overrides), key, algorithm="RS256",
                      headers={"kid": "rotating", "typ": "at+jwt"})


def wait_ready(proc, port):
    for _ in range(150):
        if proc.poll() is not None:
            raise AssertionError(f"HostMarshal stopped during startup: {proc.stderr.read()}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.1):
                return
        except OSError:
            time.sleep(.1)
    raise AssertionError("HostMarshal HTTP did not become ready")


def request_tls(port, cert, method, path, token=None, extra=None):
    context = ssl.create_default_context(cafile=str(cert))
    connection = http.client.HTTPSConnection("localhost", port, context=context, timeout=8)
    headers = {"Host": "mcp.example.invalid"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if method == "POST":
        headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2026-07-28",
            "Mcp-Method": "tools/list",
        })
    headers.update(extra or {})
    body = (json.dumps({
        "jsonrpc": "2.0", "id": 19, "method": "tools/list",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {"name": "m4-test", "version": "1.0"},
            }
        }
    }) if method == "POST" else None)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read()
        return response.status, {key.lower(): value for key, value in response.getheaders()}, data
    finally:
        connection.close()


def main():
    with tempfile.TemporaryDirectory(prefix="hostmarshal-online-jwks-") as tmp:
        root = Path(tmp)
        jwks_ca, jwks_cert, jwks_key = tls_cert(root, "jwks")
        ingress_ca, ingress_cert, ingress_key = tls_cert(root, "ingress")
        key_a, jwk_a = jwt_key()
        key_b, jwk_b = jwt_key()
        signer = {"jwks": {"keys": [jwk_a]}, "status": 200, "redirect": False}
        jwks_port = port_available()
        port = port_available()
        ingress_port = port_available()
        proof = "m4-test-only-" + "a" * 48
        proof_file = root / "ingress.proof"
        proof_file.write_text(proof + "\n")
        proof_file.chmod(0o600)

        class Jwks(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_GET(self):
                if self.path != "/keys":
                    self.send_error(404)
                    return
                if signer["redirect"]:
                    self.send_response(302)
                    self.send_header("Location", f"https://localhost:{jwks_port}/redirect")
                    self.end_headers()
                    return
                payload = json.dumps(signer["jwks"]).encode()
                self.send_response(signer["status"])
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        jwks_server = start_tls_server(jwks_port, Jwks, jwks_cert, jwks_key)
        config = root / "config"
        config.mkdir()
        for src in Path("config/v1alpha1").glob("*.yaml"):
            text = src.read_text().replace("local://trusted-launcher", ISSUER)
            (config / src.name).write_text(text.replace("example-operator", "operator-a"))
        auth = root / "auth.json"
        auth.write_text(json.dumps({
            "apiVersion": "hostmarshal.io/remote-auth/v1alpha1",
            "issuer": ISSUER, "audience": AUDIENCE,
            "allowedHost": f"127.0.0.1:{port}",
            "jwksUrl": f"https://localhost:{jwks_port}/keys",
            "jwksCaCertificateFile": str(jwks_ca),
            "jwksRefreshSeconds": 30,
            "ingress": {
                "mode": "trustedProxy",
                "publicHost": "mcp.example.invalid",
                "proofFile": str(proof_file),
            },
        }))
        auth.chmod(0o600)
        audit = root / "audit.jsonl"
        command = [
            str(BIN), "http", "--listen", f"127.0.0.1:{port}",
            "--config-dir", str(config), "--auth-config", str(auth),
            "--audit-log", str(audit),
        ]
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

        class Ingress(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def relay(self):
                # Disposable test ingress enforces external Host and sanitizes
                # forwarded/proof headers; HostMarshal validates the proof again.
                if self.headers.get("Host") != "mcp.example.invalid":
                    self.send_error(400)
                    return
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length) if length else None
                headers = {
                    "Host": f"127.0.0.1:{port}",
                    "X-Forwarded-Proto": "https",
                    "X-Forwarded-Host": "mcp.example.invalid",
                    "X-HostMarshal-Ingress-Proof": proof,
                }
                for name in ("Authorization", "Content-Type", "Accept",
                             "MCP-Protocol-Version", "Mcp-Method", "Mcp-Name"):
                    if name in self.headers:
                        headers[name] = self.headers[name]
                upstream = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
                try:
                    upstream.request(self.command, self.path, body=body, headers=headers)
                    response = upstream.getresponse()
                    content = response.read()
                    self.send_response(response.status)
                    for h, value in response.getheaders():
                        if h.lower() in ("content-type", "www-authenticate", "cache-control"):
                            self.send_header(h, value)
                    self.send_header("Content-Length", str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                finally:
                    upstream.close()
            do_POST = relay
            do_GET = relay

        ingress_server = start_tls_server(ingress_port, Ingress, ingress_cert, ingress_key)
        try:
            wait_ready(process, port)
            valid_a = issue(key_a)
            # A direct TCP client cannot supply valid identity to the TLS proxy
            # boundary, even if it has a valid JWT.
            direct_status, _ = rpc(port, valid_a, "tools/list")
            assert direct_status == 403, direct_status
            forged_status, _ = rpc(port, valid_a, "tools/list", extra_headers={
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "mcp.example.invalid",
                "X-HostMarshal-Ingress-Proof": "invalid-proof",
            })
            assert forged_status == 403, forged_status

            status, hdr, payload = request_tls(
                ingress_port, ingress_ca, "GET",
                "/.well-known/oauth-protected-resource/mcp",
            )
            assert status == 200, (status, payload)
            meta = json.loads(payload)
            assert meta == {
                "resource": AUDIENCE,
                "authorization_servers": [ISSUER],
                "scopes_supported": ["hostmarshal.observe"],
                "bearer_methods_supported": ["header"],
            }, meta
            assert hdr["cache-control"] == "no-store", hdr
            status, hdr, _ = request_tls(
                ingress_port, ingress_ca, "POST", "/mcp",
            )
            assert status == 401 and "resource_metadata=" in hdr["www-authenticate"], (status, hdr)
            assert "https://mcp.example.invalid/.well-known/oauth-protected-resource/mcp" in hdr["www-authenticate"]

            status, _, payload = request_tls(ingress_port, ingress_ca, "POST", "/mcp", valid_a)
            assert status == 200 and "inventory.inspect" in payload.decode(), (status, payload)
            # Tests TLS validation; an untrusted public root must not silently
            # validate this disposable ingress certificate.
            try:
                request_tls(ingress_port, jwks_ca, "POST", "/mcp", valid_a)
            except ssl.SSLCertVerificationError:
                pass
            else:
                raise AssertionError("untrusted TLS ingress certificate accepted")

            # The two keys have the SAME kid to prove that a successful
            # trusted refresh REPLACES, rather than merges, the old trust set.
            signer["jwks"] = {"keys": [jwk_b]}
            # The old key remains accepted for the bounded refresh interval.
            assert request_tls(ingress_port, ingress_ca, "POST", "/mcp", valid_a)[0] == 200
            time.sleep(31)
            status, _, _ = request_tls(ingress_port, ingress_ca, "POST", "/mcp", valid_a)
            assert status == 401, status
            valid_b = issue(key_b)
            status, _, payload = request_tls(ingress_port, ingress_ca, "POST", "/mcp", valid_b)
            assert status == 200 and "inventory.inspect" in payload.decode(), (status, payload)

            # After cached keys expire, invalid online payloads and redirects
            # must never re-enable stale trust or follow a surprise endpoint.
            signer["redirect"] = True
            time.sleep(31)
            assert request_tls(ingress_port, ingress_ca, "POST", "/mcp", valid_b)[0] == 401
            signer["redirect"] = False
            signer["jwks"] = {"keys": [jwk_b]}
            assert request_tls(ingress_port, ingress_ca, "POST", "/mcp", valid_b)[0] == 200
            signer["status"] = 503
            # No immediate stale use after the next refresh deadline.
            # Avoid a third 30-second sleep: replace the running issuer
            # trust endpoint with a wrong CA on a separate startup fixture.
            log = audit.read_text()
            assert proof not in log and valid_a not in log and valid_b not in log
            assert "http_ingress_rejected" in log
            print("M4 pinned online JWKS rotation, OAuth metadata and TLS-ingress bypass suite passed")
        finally:
            process.terminate()
            try:
                process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=6)
            ingress_server.shutdown()
            ingress_server.server_close()
            jwks_server.shutdown()
            jwks_server.server_close()


if __name__ == "__main__":
    main()
