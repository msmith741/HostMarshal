"""M4 Vault-compatible SSH signer over TLS, with real disposable OpenSSH CA and sshd.

This fixture deliberately does not claim to be a real Vault server. It exercises
the public Vault SSH sign API contract, certificate cryptography, pinning,
principal/key/expiry checking, cancellation and lease-file deletion. The real
Vault dev-server interoperability gate remains independent and outstanding.
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

from transport_smoke import BIN, MCP, command, free_port, tls_material

USER = "hmvault"
TARGET = "vault-linux"
TOKEN = "vault-disposable-test-token"


class VaultSigner(http.server.BaseHTTPRequestHandler):
    key_dir = None
    ca_key = None
    untrusted_ca_key = None
    unrelated_public_key = None
    mode = "ok"
    calls = 0

    def log_message(self, *_args):
        pass

    def do_POST(self):
        VaultSigner.calls += 1
        if self.path != "/v1/ssh/sign/read-only":
            self.send_reply(404, b"{}")
            return
        if self.headers.get("X-Vault-Token") != TOKEN:
            self.send_reply(403, b'{"errors":["permission denied"]}')
            return
        if VaultSigner.mode == "slow":
            time.sleep(4)
        if VaultSigner.mode == "http-error":
            self.send_reply(503, b'{"errors":["Vault unavailable"]}')
            return
        if VaultSigner.mode == "redirect":
            self.send_response(302)
            self.send_header("Location", "https://127.0.0.1:1/other")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if VaultSigner.mode == "oversize":
            self.send_reply(200, b"z" * 20000)
            return
        if VaultSigner.mode == "bad-json":
            self.send_reply(200, b'{"data": {"signed_key": "not an SSH certificate"}}')
            return

        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size <= 8192:
            self.send_reply(400, b"{}")
            return
        payload = json.loads(self.rfile.read(size))
        assert payload["cert_type"] == "user"
        assert payload["valid_principals"] == USER
        assert payload["ttl"] == "90s"
        assert payload["extensions"] == {}
        assert payload["public_key"].startswith("ssh-ed25519 ")
        public = VaultSigner.key_dir / f"requested-{VaultSigner.calls}.pub"
        public.write_text(payload["public_key"])
        signer = VaultSigner.ca_key
        principal = USER
        validity = "-5s:+90s"
        options = ["-O", "clear"]
        if VaultSigner.mode == "wrong-ca":
            signer = VaultSigner.untrusted_ca_key
        elif VaultSigner.mode == "wrong-principal":
            principal = "different-user"
        elif VaultSigner.mode == "wide-principals":
            principal = f"{USER},root"
        elif VaultSigner.mode == "wrong-key":
            public.write_text(VaultSigner.unrelated_public_key.read_text())
        elif VaultSigner.mode == "expired":
            validity = "20000101:20000102"
        elif VaultSigner.mode == "short-lived":
            validity = "-5s:+10s"
        elif VaultSigner.mode == "long-lived":
            validity = "-5s:+2h"
        elif VaultSigner.mode == "extensions":
            options = []

        command(
            "ssh-keygen", "-q", "-s", str(signer),
            "-I", "hostmarshal-disposable-test",
            "-n", principal, "-V", validity,
            *options, str(public),
        )
        signed_path = public.with_name(public.stem + "-cert.pub")
        signed = signed_path.read_text()
        self.send_reply(200, json.dumps({"data": {"signed_key": signed}}).encode())

    def send_reply(self, status, body):
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


def start_vault_signer(root):
    cert_ca, server_cert, server_key = tls_material(root)
    for name in ["ssh_ca", "untrusted_ca", "other_client"]:
        command("ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                "-f", str(root / name))
    VaultSigner.key_dir = root
    VaultSigner.ca_key = root / "ssh_ca"
    VaultSigner.untrusted_ca_key = root / "untrusted_ca"
    VaultSigner.unrelated_public_key = root / "other_client.pub"
    VaultSigner.mode = "ok"
    VaultSigner.calls = 0
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), VaultSigner)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=server_cert, keyfile=server_key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, cert_ca


def start_certificate_sshd(root):
    command("ssh-keygen", "-q", "-t", "ed25519", "-N", "",
            "-f", str(root / "host_key"))
    command("sudo", "useradd", "-m", "-s", "/bin/sh", USER)
    # Password login is disabled; random test password only unlocks account.
    command("sudo", "chpasswd", input_text=f"{USER}:{os.urandom(24).hex()}\n")
    command("sudo", "install", "-d", "-m", "0755", "/run/sshd")
    port = free_port()
    pub = (root / "host_key.pub").read_text().split()
    known = root / "known_hosts"
    known.write_text(f"{TARGET} {pub[0]} {pub[1]}\n")
    config = root / "sshd_config"
    config.write_text(
        f"Port {port}\nListenAddress 127.0.0.1\n"
        f"HostKey {root / 'host_key'}\n"
        f"TrustedUserCAKeys {root / 'ssh_ca.pub'}\n"
        "AuthorizedKeysFile none\n"
        "PubkeyAuthentication yes\nPasswordAuthentication no\n"
        "KbdInteractiveAuthentication no\nStrictModes no\nUsePAM no\n"
        "PermitRootLogin no\n"
        f"AllowUsers {USER}\n"
        f"PidFile {root / 'sshd.pid'}\nLogLevel ERROR\n"
    )
    process = subprocess.Popen(
        ["sudo", "/usr/sbin/sshd", "-D", "-e", "-f", str(config)],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    for _ in range(60):
        if process.poll() is not None:
            raise AssertionError(f"disposable cert SSHD exited: {process.stderr.read()}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                break
        except OSError:
            time.sleep(0.1)
    else:
        raise AssertionError("disposable certificate SSHD did not start")
    return process, port, known


def write_inventory(config, port, known):
    host = {
        "apiVersion":"hostmarshal.io/v1alpha1", "kind":"Host",
        "metadata":{"name":TARGET},
        "spec":{"address":"127.0.0.1", "ssh":{
            "user":USER, "port":port, "knownHostsFile":str(known)
        }},
    }
    capability = {
        "apiVersion":"hostmarshal.io/v1alpha1", "kind":"Capability",
        "metadata":{"name":"linux.uname"},
        "spec":{
            "operationRef":"builtin.linux.uname/v1", "targetKind":"Host",
            "exposure":{"mcp":True},
            "inputSchema":{
                "type":"object", "properties":{"target":{"type":"string"}},
                "required":["target"], "additionalProperties":False,
            },
            "outputSchema":{
                "type":"object", "properties":{
                    "id":{"type":"string"},
                    "os":{"type":"string","const":"Linux"},
                },
                "required":["id","os"], "additionalProperties":False,
            },
            "limits":{"timeout":"5s","maxOutputBytes":4096},
        },
    }
    grant = {
        "apiVersion":"hostmarshal.io/v1alpha1", "kind":"Grant",
        "metadata":{"name":"vault-observer"},
        "spec":{
            "subjects":[{
                "issuer":"local://trusted-launcher", "subject":"example-operator"
            }],
            "capabilities":["linux.uname"],
            "targets":{"kind":"Host","names":[TARGET]},
        },
    }
    (config / "resources.yaml").write_text(
        "\n---\n".join(json.dumps(x) for x in [host, capability, grant]) + "\n"
    )


def run():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        ephemeral = root / "ephemeral"
        ephemeral.mkdir(mode=0o700)
        signer, tls_ca = start_vault_signer(root)
        sshd, port, known = start_certificate_sshd(root)
        config = root / "config"
        config.mkdir()
        write_inventory(config, port, known)
        token = root / "vault.token"
        token.write_text(TOKEN)
        token.chmod(0o600)
        signer_config = root / "vault-ssh.json"
        signer_config.write_text(json.dumps({
            "apiVersion":"hostmarshal.io/vault-ssh/v1alpha1",
            "vaultAddress":f"https://localhost:{signer.server_port}",
            "tokenFile":str(token),
            "caCertificateFile":str(tls_ca),
            "sshCaPublicKeyFile":str(root / "ssh_ca.pub"),
            "mount":"ssh", "role":"read-only",
            "ttlSeconds":90,
            "targets":[{"target":TARGET,"principal":USER}],
        }))
        signer_config.chmod(0o600)
        audit = root / "audit.jsonl"
        environment = dict(os.environ)
        environment["TMPDIR"] = str(ephemeral)
        # Reqwest is configured not to inherit proxies; a malicious proxy
        # variable must not divert this trusted Vault endpoint.
        environment["HTTPS_PROXY"] = "http://127.0.0.1:1"
        argv = [
            str(BIN), "--config-dir", str(config),
            "--principal", "example-operator",
            "--vault-ssh-config", str(signer_config),
            "--audit-log", str(audit),
        ]
        try:
            command(str(BIN), "config", "validate", str(config))
            process = subprocess.Popen(
                argv, env=environment,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, bufsize=1,
            )
            try:
                client = MCP(process)
                discovered = {x["name"] for x in client.call("tools/list")["tools"]}
                assert discovered == {"linux.uname"}
                good = client.tool("linux.uname", TARGET)
                assert good.get("isError") is not True, good
                assert good["structuredContent"] == {"id":TARGET, "os":"Linux"}, good
                assert not list(ephemeral.glob("hostmarshal-vault-*")), "lease files leaked"

                for mode in [
                    "wrong-ca", "wrong-principal", "wide-principals", "wrong-key",
                    "expired", "short-lived", "long-lived", "extensions",
                    "http-error", "redirect", "bad-json", "oversize", "slow",
                ]:
                    VaultSigner.mode = mode
                    result = client.tool("linux.uname", TARGET)
                    assert result.get("isError") is True, (mode, result)
                    assert not list(ephemeral.glob("hostmarshal-vault-*")), (
                        f"temporary private key leaked after {mode}"
                    )

                VaultSigner.mode = "ok"
                before = VaultSigner.calls
                # Grant/input denial must happen before invoking the signer.
                assert client.tool("linux.uname", "unknown").get("isError") is True
                assert client.tool("linux.uname", TARGET, command="id").get("isError") is True
                assert VaultSigner.calls == before

                token.write_text("invalid-rotated-token")
                denied = client.tool("linux.uname", TARGET)
                assert denied.get("isError") is True, denied
                token.write_text(TOKEN)
                restored = client.tool("linux.uname", TARGET)
                assert restored.get("isError") is not True, restored
                assert not list(ephemeral.glob("hostmarshal-vault-*"))

            finally:
                process.stdin.close()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

            audit_text = audit.read_text()
            assert TOKEN not in audit_text
            assert "BEGIN OPENSSH PRIVATE KEY" not in audit_text
            assert "ssh-ed25519-cert-v01@" not in audit_text
            assert "succeeded" in audit_text and "failed" in audit_text
            assert not list(ephemeral.iterdir()), "ephemeral material remained"

            # Startup rejects mixed static + Vault credentials with NO fallback.
            extra = root / "legacy-map.json"
            extra.write_text("{}")
            extra.chmod(0o600)
            rejected = subprocess.run(
                argv + ["--ssh-credential-map", str(extra)],
                capture_output=True, text=True, timeout=7, env=environment
            )
            assert rejected.returncode != 0
            assert "no fallback" in rejected.stderr

            # A changed inventory principal cannot be reinterpreted as an
            # already-authorized Vault target binding.
            cfg = json.loads(signer_config.read_text())
            cfg["targets"][0]["principal"] = "root"
            signer_config.write_text(json.dumps(cfg))
            invalid = subprocess.run(argv, capture_output=True,
                                     text=True, timeout=7, env=environment)
            assert invalid.returncode != 0
            assert "principal must exactly match" in invalid.stderr
            print("M4 Vault-compatible TLS signer, SSH certificate, revocation, denial and cleanup tests passed")
        finally:
            signer.shutdown()
            sshd.terminate()
            try:
                sshd.wait(timeout=5)
            except subprocess.TimeoutExpired:
                sshd.kill()
                sshd.wait(timeout=5)


if __name__ == "__main__":
    run()
