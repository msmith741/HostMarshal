"""M4 Vault SSH certificate integration against disposable Vault-compatible TLS API.

The issuer is a local test server signing ephemeral OpenSSH user certificates.
No real Vault, personal credentials or infrastructure is accessed.
"""
import http.server
import json
import os
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from mcp_smoke import BIN
from transport_smoke import (
    MCP, USER, command, free_port, start_ssh, tls_material, write_manifests
)


class VaultHandler(http.server.BaseHTTPRequestHandler):
    role = "observe-only"
    token = "test-vault-token"
    ca_key = None
    key_file = None
    calls = 0
    broken_certificate = False
    reject_token = False
    observed_principal = None

    def do_POST(self):
        VaultHandler.calls += 1
        if self.path != "/v1/ssh/sign/observe-only":
            self.send_error(404)
            return
        if self.headers.get("X-Vault-Token") != self.token or self.reject_token:
            self.send_error(403)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 8192:
            self.send_error(400)
            return
        body = json.loads(self.rfile.read(length))
        VaultHandler.observed_principal = body.get("valid_principals")
        if (body.get("cert_type") != "user" or body.get("ttl") != "60s"
                or body.get("valid_principals") != USER
                or not body.get("key_id", "").startswith("hostmarshal:example-operator:")
                or body.get("public_key", "").split()[:2] !=
                VaultHandler.key_file.read_text().split()[:2]):
            self.send_error(400)
            return

        if self.broken_certificate:
            signed = "untrusted DATA-WILL-BE-REJECTED"
        else:
            request_pub = self.server.test_folder / "issued.pub"
            request_pub.write_text(body["public_key"])
            command("ssh-keygen", "-q", "-s", str(self.ca_key),
                    "-I", "m4-ci-credential", "-n", USER,
                    "-V", "-5s:+65s", "-z", str(VaultHandler.calls),
                    str(request_pub))
            signed = (self.server.test_folder / "issued-cert.pub").read_text()

        data = json.dumps({"data":{"signed_key":signed}, "lease_duration":60}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_args):
        pass


def start_vault(root):
    ca, cert, key = tls_material(root)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), VaultHandler)
    server.test_folder = root
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(certfile=str(cert), keyfile=str(key))
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    return server, ca


def start_cert_only_ssh(root):
    sshd, port, known, other_key = start_ssh(root)
    sshd.terminate()
    sshd.wait(timeout=5)
    command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(root / "vault-ca"))
    config = root / "sshd_config"
    config.write_text(config.read_text() + f"\nTrustedUserCAKeys {root / 'vault-ca.pub'}\n")
    # The user must NOT be able to log in with the raw M3 public key.
    # The account's test-only authorized-keys file is confined to this temp dir.
    (root / "authorized_keys").write_text("")
    sshd = subprocess.Popen(
        ["sudo", "/usr/sbin/sshd", "-D", "-e", "-f", str(config)],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    for _ in range(60):
        if sshd.poll() is not None:
            raise AssertionError(f"cert-only sshd exited: {sshd.stderr.read()}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return sshd, port, known
        except OSError:
            time.sleep(0.1)
    raise AssertionError("cert-only sshd unavailable")


def vault_mapping(root, port, ca):
    token_file = root / "vault-token"
    token_file.write_text(VaultHandler.token + "\n")
    token_file.chmod(0o600)
    mapping = root / "vault-ssh.json"
    mapping.write_text(json.dumps({
        "apiVersion":"hostmarshal.io/vault-ssh/v1alpha1",
        "vaultUrl":f"https://localhost:{port}",
        "sshMount":"ssh",
        "tokenFile":str(token_file),
        "caCertificateFile":str(ca),
        "identities":[{
            "target":"sample-linux",
            "identityFile":str(root / "client_key"),
            "publicKeyFile":str(root / "client_key.pub"),
            "role":VaultHandler.role,
            "principal":USER,
        }],
    }))
    mapping.chmod(0o600)
    return mapping, token_file


def run_mcp(root, config, mapping):
    process = subprocess.Popen([
        str(BIN), "--config-dir", str(config),
        "--principal", "example-operator",
        "--audit-log", str(root / "audit.jsonl"),
        "--vault-ssh-config", str(mapping),
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, bufsize=1)
    return process, MCP(process)


def close_mcp(process):
    process.stdin.close()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main():
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        VaultHandler.calls = 0
        VaultHandler.broken_certificate = False
        VaultHandler.reject_token = False
        sshd, ssh_port, known = start_cert_only_ssh(root)
        VaultHandler.ca_key = root / "vault-ca"
        VaultHandler.key_file = root / "client_key.pub"
        vault, ca = start_vault(root)
        mapping, token = vault_mapping(root, vault.server_port, ca)
        config = root / "manifests"
        config.mkdir()
        write_manifests(config, ssh_port, known, vault.server_port, ca)

        try:
            process, mcp = run_mcp(root, config, mapping)
            try:
                good = mcp.tool("linux.uname", "sample-linux")
                assert good.get("isError") is not True, good
                assert good["structuredContent"] == {
                    "id":"sample-linux", "os":"Linux"
                }, good
                assert VaultHandler.calls == 1
                assert VaultHandler.observed_principal == USER

                # Authorization failure must not contact Vault.
                denied = mcp.tool("linux.uname", "sample-https")
                assert denied.get("isError") is True
                assert VaultHandler.calls == 1

                # A corrupted Vault response cannot be used as a certificate.
                VaultHandler.broken_certificate = True
                bad_cert = mcp.tool("linux.uname", "sample-linux")
                assert bad_cert.get("isError") is True
                VaultHandler.broken_certificate = False

                # Vault token rotation/revocation is enforced per acquisition.
                token.write_text("invalid-rotated-token\n")
                revoked = mcp.tool("linux.uname", "sample-linux")
                assert revoked.get("isError") is True
                token.write_text(VaultHandler.token + "\n")
                restored = mcp.tool("linux.uname", "sample-linux")
                assert restored.get("isError") is not True, restored

                # Unrelated secret-broker request fields cannot enter MCP.
                assert mcp.tool(
                    "linux.uname", "sample-linux", role="administrator"
                ).get("isError") is True
            finally:
                close_mcp(process)

            # A grant cannot make a protected provider file world-readable.
            mapping.chmod(0o644)
            broken = subprocess.run([
                str(BIN), "--config-dir", str(config),
                "--principal", "example-operator",
                "--vault-ssh-config", str(mapping),
            ], capture_output=True, text=True, timeout=6)
            assert broken.returncode != 0
            mapping.chmod(0o600)

            # A forged CA must not allow Vault impersonation.
            alternate = root / "other-ca.pem"
            command("openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-noenc", "-days", "1", "-subj", "/CN=Unrelated CA",
                    "-keyout", str(root / "other-ca.key"), "-out", str(alternate))
            original = ca.read_bytes()
            ca.write_bytes(alternate.read_bytes())
            process, mcp = run_mcp(root, config, mapping)
            try:
                failed_tls = mcp.tool("linux.uname", "sample-linux")
                assert failed_tls.get("isError") is True, failed_tls
            finally:
                close_mcp(process)
            ca.write_bytes(original)

            events = [
                json.loads(line)
                for line in (root / "audit.jsonl").read_text().splitlines()
            ]
            assert any(x["phase"] == "succeeded" for x in events)
            assert any(x["phase"] == "denied" for x in events)
            assert any(x["phase"] == "failed" for x in events)
            encoded = json.dumps(events)
            assert VaultHandler.token not in encoded
            assert "signed_key" not in encoded
            assert "vault-token" not in encoded
            assert "client_key" not in encoded
            print("M4 Vault SSH certificate issuance, denial, rotation and TLS tests passed")
        finally:
            vault.shutdown()
            sshd.terminate()
            try:
                sshd.wait(timeout=5)
            except subprocess.TimeoutExpired:
                sshd.kill()
                sshd.wait(timeout=5)


if __name__ == "__main__":
    main()
