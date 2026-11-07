"""End-to-end M3 read-only SSH and TLS observation tests using disposable targets.

Requires openssh-server (Ubuntu CI), openssl, Python stdlib and the project binary.
Does not access the user's network, SSH keys or real services.
"""
import http.server
import json
import pwd
import os
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from mcp_smoke import BIN, response, send

USER = pwd.getpwuid(os.getuid()).pw_name


def command(*args, input_text=None):
    return subprocess.run(
        args, input=input_text, text=True, check=True,
        capture_output=True, timeout=40,
    )


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def tls_material(root):
    ca_key, ca_pem = root / "ca.key", root / "ca.pem"
    srv_key, srv_csr, srv_pem = root / "server.key", root / "server.csr", root / "server.pem"
    command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-noenc",
            "-days", "1", "-subj", "/CN=HostMarshal Local Test CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout", str(ca_key), "-out", str(ca_pem))
    command("openssl", "req", "-newkey", "rsa:2048", "-noenc", "-subj",
            "/CN=localhost", "-keyout", str(srv_key), "-out", str(srv_csr))
    ext = root / "server.ext"
    ext.write_text(
        "subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\n"
        "keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
    )
    command("openssl", "x509", "-req", "-in", str(srv_csr),
            "-CA", str(ca_pem), "-CAkey", str(ca_key), "-CAcreateserial",
            "-days", "1", "-out", str(srv_pem), "-extfile", str(ext))
    return ca_pem, srv_pem, srv_key


class Handler(http.server.BaseHTTPRequestHandler):
    hits = []
    mode = "ok"

    def do_GET(self):
        Handler.hits.append(self.path)
        if Handler.mode == "slow":
            time.sleep(4)
        if Handler.mode == "redirect":
            self.send_response(302)
            self.send_header("Location", "https://127.0.0.1:1/metadata")
        elif self.path == "/health":
            self.send_response(200)
        else:
            self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_args):
        pass


def start_tls(root):
    ca, cert, key = tls_material(root)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(certfile=str(cert), keyfile=str(key))
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, ca


def start_ssh(root):
    if not Path("/usr/sbin/sshd").exists():
        raise AssertionError("Install openssh-server for the disposable SSH test")
    command("ssh-keygen", "-q", "-t", "ed25519", "-N", "",
            "-f", str(root / "client_key"))
    command("ssh-keygen", "-q", "-t", "ed25519", "-N", "",
            "-f", str(root / "host_key"))
    command("ssh-keygen", "-q", "-t", "ed25519", "-N", "",
            "-f", str(root / "other_host_key"))
    # Reuse the disposable CI runner's own local account; do not modify or
    # create system users. The key file is private to this temporary directory.
    command("sudo", "install", "-d", "-m", "0755", "/run/sshd")
    authorized = root / "authorized_keys"
    authorized.write_text((root / "client_key.pub").read_text())
    authorized.chmod(0o600)
    known = root / "known_hosts"
    alias = "sample-linux"
    host_key_pub = (root / "host_key.pub").read_text().split()
    other_key_pub = (root / "other_host_key.pub").read_text().split()
    known.write_text(f"{alias} {host_key_pub[0]} {host_key_pub[1]}\n")
    config = root / "sshd_config"
    port = free_port()
    config.write_text(
        f"Port {port}\nListenAddress 127.0.0.1\n"
        f"HostKey {root / 'host_key'}\n"
        f"AuthorizedKeysFile {authorized}\n"
        "PubkeyAuthentication yes\nPasswordAuthentication no\n"
        "KbdInteractiveAuthentication no\nStrictModes no\nUsePAM yes\n"
        "PermitRootLogin no\n"
        f"AllowUsers {USER}\n"
        f"PidFile {root / 'sshd.pid'}\nLogLevel ERROR\n"
    )
    proc = subprocess.Popen(
        ["sudo", "/usr/sbin/sshd", "-D", "-e", "-f", str(config)],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    for _ in range(60):
        if proc.poll() is not None:
            raise AssertionError(f"test sshd exited: {proc.stderr.read()}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                break
        except OSError:
            time.sleep(0.1)
    else:
        raise AssertionError("disposable sshd did not listen")
    return proc, port, known, other_key_pub


def write_manifests(directory, ssh_port, known, tls_port, ca):
    (directory / "host.yaml").write_text(f"""apiVersion: hostmarshal.io/v1alpha1
kind: Host
metadata:
  name: sample-linux
spec:
  address: 127.0.0.1
  ssh:
    user: {USER}
    port: {ssh_port}
    knownHostsFile: {known}
---
apiVersion: hostmarshal.io/v1alpha1
kind: Host
metadata:
  name: sample-https
spec:
  address: localhost
  https:
    port: {tls_port}
    caCertificateFile: {ca}
""")
    input_schema = {
        "type":"object", "properties":{"target":{"type":"string"}},
        "required":["target"], "additionalProperties":False,
    }
    outputs = {
        "linux.uname": {
            "type":"object", "properties":{
                "id":{"type":"string"}, "os":{"type":"string","const":"Linux"}},
            "required":["id","os"],"additionalProperties":False,
        },
        "https.health": {
            "type":"object", "properties":{
                "id":{"type":"string"}, "statusCode":{"type":"integer"},
                "healthy":{"type":"boolean"}},
            "required":["id","statusCode","healthy"],"additionalProperties":False,
        },
    }
    resources = []
    for name, op in [
        ("linux.uname", "builtin.linux.uname/v1"),
        ("https.health", "builtin.https.health/v1"),
    ]:
        resources.append(
            {
                "apiVersion":"hostmarshal.io/v1alpha1", "kind":"Capability",
                "metadata":{"name":name},
                "spec":{
                    "operationRef":op,"targetKind":"Host",
                    "exposure":{"mcp":True},
                    "inputSchema":input_schema,
                    "outputSchema":outputs[name],
                    "limits":{"timeout":"3s","maxOutputBytes":4096},
                },
            }
        )
        resources.append(
            {
                "apiVersion":"hostmarshal.io/v1alpha1","kind":"Grant",
                "metadata":{"name":name},
                "spec":{
                    "subjects":[
                        {"issuer":"local://trusted-launcher","subject":"example-operator"}
                    ],
                    "capabilities":[name],
                    "targets":{"kind":"Host","names":[
                        "sample-linux" if name == "linux.uname" else "sample-https"
                    ]},
                },
            }
        )
    # JSON documents are also valid YAML, so this avoids an extra test dependency.
    (directory / "capabilities.yaml").write_text(
        "\n---\n".join(json.dumps(x) for x in resources) + "\n"
    )


def run_mcp(config, identity_map, audit_file):
    proc = subprocess.Popen([
        str(BIN), "--config-dir", str(config), "--principal", "example-operator",
        "--audit-log", str(audit_file),
        "--ssh-credential-map", str(identity_map),
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, bufsize=1)
    return proc


class MCP:
    def __init__(self, process):
        self.process = process
        self.number = 0
        data = self.call("initialize", {
            "protocolVersion":"2025-11-25", "capabilities":{},
            "clientInfo":{"name":"m3-observation-test","version":"1.0"},
        })
        assert "tools" in data["capabilities"]
        send(self.process, {"jsonrpc":"2.0","method":"notifications/initialized"})

    def call(self, method, params=None):
        self.number += 1
        packet = {"jsonrpc":"2.0","method":method,"id":self.number}
        if params is not None:
            packet["params"] = params
        send(self.process, packet)
        return response(self.process, self.number)

    def tool(self, name, target, **overrides):
        return self.call("tools/call", {
            "name": name,
            "arguments":{"target": target, **overrides},
        })


def main():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        tls, ca = start_tls(root)
        sshd, port, known, other = start_ssh(root)
        config = root / "manifests"
        config.mkdir()
        write_manifests(config, port, known, tls.server_port, ca)

        ssh_map = root / "ssh-identities.json"
        ssh_map.write_text(json.dumps({
            "apiVersion":"hostmarshal.io/ssh-credentials/v1alpha1",
            "identities":[{
                "target":"sample-linux",
                "identityFile":str(root / "client_key"),
            }],
        }))
        ssh_map.chmod(0o600)
        audit = root / "audit.jsonl"
        try:
            command(str(BIN), "config", "validate", str(config))
            proc = run_mcp(config, ssh_map, audit)
            try:
                mcp = MCP(proc)
                discovered = {x["name"] for x in mcp.call("tools/list")["tools"]}
                assert discovered == {"linux.uname","https.health"}, discovered

                good_ssh = mcp.tool("linux.uname", "sample-linux")
                if good_ssh.get("isError") is True:
                    diagnostics = subprocess.run(
                        [
                            "/usr/bin/ssh", "-F", "/dev/null",
                            "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
                            "-o", "KbdInteractiveAuthentication=no",
                            "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
                            "-o", "StrictHostKeyChecking=yes",
                            "-o", "GlobalKnownHostsFile=/dev/null",
                            "-o", f"UserKnownHostsFile={known}",
                            "-o", "HostKeyAlias=sample-linux",
                            "-T", "-i", str(root / "client_key"),
                            "-l", USER, "-p", str(port), "127.0.0.1", "uname -s",
                        ], capture_output=True, text=True, timeout=7
                    )
                    raise AssertionError(
                        f"SSH failure: {good_ssh}; direct ssh rc={diagnostics.returncode}, "
                        f"stdout={diagnostics.stdout!r}, stderr={diagnostics.stderr[-600:]!r}"
                    )
                assert good_ssh["structuredContent"] == {
                    "id":"sample-linux", "os":"Linux"
                }, good_ssh

                good_https = mcp.tool("https.health", "sample-https")
                assert good_https.get("isError") is not True, good_https
                assert good_https["structuredContent"] == {
                    "id":"sample-https", "statusCode":200, "healthy":True
                }, good_https
                assert Handler.hits == ["/health"]

                # No arbitrary command, URL, host or transport substitution.
                assert mcp.tool("linux.uname","sample-linux",command="id").get("isError") is True
                assert mcp.tool("https.health","sample-https",url="https://example.com").get("isError") is True
                assert mcp.tool("linux.uname","sample-https").get("isError") is True
                assert mcp.tool("https.health","sample-linux").get("isError") is True
                assert mcp.tool("linux.uname","unknown-target").get("isError") is True
                assert Handler.hits == ["/health"], Handler.hits

                # Host-key substitution must fail (StrictHostKeyChecking + pinned alias).
                original = known.read_text()
                known.write_text(f"sample-linux {other[0]} {other[1]}\n")
                mismatch = mcp.tool("linux.uname","sample-linux")
                assert mismatch.get("isError") is True, mismatch
                known.write_text(original)

                # Must never follow a redirect or emit a response body.
                Handler.mode = "redirect"
                redirect = mcp.tool("https.health","sample-https")
                assert redirect.get("isError") is not True, redirect
                assert redirect["structuredContent"] == {
                    "id":"sample-https","statusCode":302,"healthy":False
                }
                assert Handler.hits == ["/health","/health"]

                # Shared operation deadline bounds a slow HTTPS endpoint.
                Handler.mode = "slow"
                slow = mcp.tool("https.health","sample-https")
                assert slow.get("isError") is True, slow

                # Trusted CA must match server's cert; never ignore TLS failure.
                Handler.mode = "ok"
                alternate_ca = root / "other-ca.pem"
                command("openssl", "req", "-x509", "-newkey", "rsa:2048",
                        "-noenc", "-days","1","-subj","/CN=Unrelated CA",
                        "-keyout",str(root/"other-ca.key"),"-out",str(alternate_ca))
                original_ca = ca.read_bytes()
                ca.write_bytes(alternate_ca.read_bytes())
                invalid_tls = mcp.tool("https.health","sample-https")
                assert invalid_tls.get("isError") is True, invalid_tls
                ca.write_bytes(original_ca)

            finally:
                proc.stdin.close()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)

            # Identity map is required for SSH, even with valid Host/Grant YAML.
            proc = subprocess.Popen([
                str(BIN), "--config-dir", str(config),
                "--principal", "example-operator",
            ], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, bufsize=1)
            try:
                mcp = MCP(proc)
                assert mcp.tool("linux.uname", "sample-linux").get("isError") is True
            finally:
                proc.stdin.close()
                proc.wait(timeout=5)

            # Credential-map ACLs are a launch-time security gate.
            ssh_map.chmod(0o644)
            denied = subprocess.run([
                str(BIN), "--config-dir", str(config),
                "--principal", "example-operator",
                "--ssh-credential-map", str(ssh_map),
            ], capture_output=True, text=True, timeout=5)
            assert denied.returncode != 0
            assert "SSH identity map" in denied.stderr
            ssh_map.chmod(0o600)

            audit_events = [
                json.loads(line)
                for line in audit.read_text().splitlines()
            ]
            phases = [event["phase"] for event in audit_events]
            assert "authorized" in phases and "succeeded" in phases
            assert "denied" in phases and "failed" in phases
            encoded = audit.read_text()
            assert "client_key" not in encoded
            assert "other-ca" not in encoded
            assert "openssl" not in encoded
            assert '"url"' not in encoded
            print("M3 real SSH and TLS observation/denial smoke tests passed")
        finally:
            tls.shutdown()
            sshd.terminate()
            try:
                sshd.wait(timeout=5)
            except subprocess.TimeoutExpired:
                sshd.kill()
                sshd.wait(timeout=5)


if __name__ == "__main__":
    main()
