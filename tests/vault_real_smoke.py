"""Real HashiCorp Vault HTTPS SSH signer interoperability gate for M4.

Runs only against a disposable locally published Vault dev container and sshd.
No production infrastructure, static private keys, or external credentials.
The root token is test-only and used strictly for fixture provisioning; the
HostMarshal subprocess receives only a separate restricted signing token.
"""
import json
import os
import secrets
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from transport_smoke import BIN, MCP, free_port
from vault_ssh_smoke import TARGET, USER, start_certificate_sshd, write_inventory


def main():
    with tempfile.TemporaryDirectory(prefix="hostmarshal-real-vault-") as temp:
        root = Path(temp)
        tls = root / "vault-tls"
        tls.mkdir(mode=0o777)
        tls.chmod(0o777)  # container's unprivileged Vault UID must create test TLS
        vault_port = free_port()
        root_token = "hm-ci-" + secrets.token_urlsafe(24)
        container = "hostmarshal-vault-" + secrets.token_hex(8)
        address = f"https://localhost:{vault_port}"
        ca = tls / "vault-ca.pem"

        def api(method, path, value=None, token=None, statuses=(200, 204)):
            data = json.dumps(value).encode() if value is not None else None
            headers = {"Content-Type": "application/json"}
            if token is not None:
                headers["X-Vault-Token"] = token
            request = urllib.request.Request(
                address + "/v1/" + path, data=data, headers=headers,
                method=method,
            )
            context = ssl.create_default_context(cafile=str(ca))
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=context),
            )
            try:
                with opener.open(request, timeout=6) as response:
                    status, payload = response.status, response.read()
            except urllib.error.HTTPError as error:
                status, payload = error.code, error.read()
            assert status in statuses, (path, status, statuses)
            return json.loads(payload) if payload else {}

        def limited_token():
            issued = api("POST", "auth/token/create", {
                "policies": ["hostmarshal-sign-only"],
                "no_default_policy": True,
                "ttl": "10m",
                "renewable": False,
            }, root_token)
            return issued["auth"]["client_token"]

        run = subprocess.run([
            "docker", "run", "--rm", "--detach", "--name", container,
            "--publish", f"127.0.0.1:{vault_port}:8200",
            "--volume", f"{tls}:/vault/tls:rw",
            "hashicorp/vault:2.2.1",
            "server", "-dev", "-dev-tls",
            "-dev-tls-cert-dir=/vault/tls",
            "-dev-listen-address=0.0.0.0:8200",
            "-dev-root-token-id=" + root_token,
            "-dev-no-store-token",
        ], capture_output=True, text=True, timeout=120)
        assert run.returncode == 0, "disposable Vault dev server failed to start"
        sshd = None
        process = None
        try:
            for _ in range(150):
                if ca.is_file():
                    # Only the generated public CA is made readable by the
                    # host runner; Vault's TLS private key stays private.
                    subprocess.run(
                        ["sudo", "chmod", "0644", str(ca)],
                        check=True, capture_output=True,
                    )
                    try:
                        api("GET", "sys/health", statuses=(200,))
                        break
                    except (OSError, ValueError, AssertionError):
                        pass
                time.sleep(0.2)
            else:
                raise AssertionError("disposable TLS Vault did not become healthy")

            api("POST", "sys/mounts/ssh", {"type": "ssh"}, root_token)
            ca_result = api(
                "POST", "ssh/config/ca",
                {"generate_signing_key": True, "key_type": "ed25519"},
                root_token,
            )
            ssh_ca = root / "ssh_ca.pub"
            ssh_ca.write_text(ca_result["data"]["public_key"].strip() + "\n")
            assert ssh_ca.read_text().startswith("ssh-ed25519 "), (
                "real Vault fixture must use independently pinned Ed25519 CA"
            )

            api("POST", "ssh/roles/read-only", {
                "key_type": "ca",
                "allow_user_certificates": True,
                "allow_host_certificates": False,
                "allowed_users": USER,
                "default_user": USER,
                "allow_empty_principals": False,
                "default_extensions": {},
                "allowed_extensions": "never-requested",
                "allowed_critical_options": "never-requested",
                "ttl": "90s",
                "max_ttl": "90s",
                "not_before_duration": "10s",
                "allow_user_key_ids": False,
                "key_id_format": "hostmarshal-{{public_key_hash}}",
            }, root_token)
            policy = 'path "ssh/sign/read-only" { capabilities = ["create", "update"] }'
            api("PUT", "sys/policies/acl/hostmarshal-sign-only",
                {"policy": policy}, root_token)

            restricted = limited_token()
            # Rootless signing token cannot reconfigure Vault/SSH/roles.
            api("GET", "sys/mounts", token=restricted, statuses=(403,))
            api("GET", "ssh/roles/read-only", token=restricted, statuses=(403,))

            # Verify *actual* Vault sign API/role independently before testing
            # HostMarshal. The signing key is disposable and its private half
            # is never passed to Vault. Never print tokens, keys, or responses.
            probe_key = root / "probe_key"
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                 "-f", str(probe_key)],
                capture_output=True, check=True, timeout=10,
            )
            signed = api("POST", "ssh/sign/read-only", {
                "public_key": (root / "probe_key.pub").read_text(),
                "valid_principals": USER,
                "cert_type": "user",
                "ttl": "90s",
                "extensions": {},
            }, restricted)["data"]["signed_key"]
            probe_cert = root / "probe_key-cert.pub"
            probe_cert.write_text(signed + "\n")
            properties = subprocess.run(
                ["ssh-keygen", "-Lf", str(probe_cert)],
                capture_output=True, text=True, check=True, timeout=10,
            ).stdout
            assert "Type:" in properties and "user certificate" in properties, properties
            # The exact authorized principal is not an SSH certificate option.
            assert USER in properties and "Principals:" in properties, properties
            print(
                "Real Vault signing preflight: ",
                " | ".join(line.strip() for line in properties.splitlines()
                           if any(field in line for field in
                                  ["Type:", "Valid:", "Principals:",
                                   "Critical Options:", "Extensions:"])),
                flush=True,
            )

            sshd, ssh_port, known_hosts = start_certificate_sshd(root)
            config = root / "config"
            config.mkdir()
            write_inventory(config, ssh_port, known_hosts)

            token_file = root / "vault.token"
            token_file.write_text(restricted)
            token_file.chmod(0o600)
            signer_config = root / "vault-config.json"
            signer_config.write_text(json.dumps({
                "apiVersion": "hostmarshal.io/vault-ssh/v1alpha1",
                "vaultAddress": address,
                "tokenFile": str(token_file),
                "caCertificateFile": str(ca),
                "sshCaPublicKeyFile": str(ssh_ca),
                "mount": "ssh",
                "role": "read-only",
                "ttlSeconds": 90,
                "targets": [{"target": TARGET, "principal": USER}],
            }))
            signer_config.chmod(0o600)
            ephemeral = root / "ephemeral"
            ephemeral.mkdir(mode=0o700)
            audit = root / "audit.jsonl"
            environment = dict(os.environ)
            environment["TMPDIR"] = str(ephemeral)
            environment["HTTPS_PROXY"] = "http://127.0.0.1:1"
            process = subprocess.Popen([
                str(BIN), "--config-dir", str(config),
                "--principal", "example-operator",
                "--vault-ssh-config", str(signer_config),
                "--audit-log", str(audit),
            ], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, bufsize=1, env=environment)
            client = MCP(process)

            def observe(should_succeed):
                result = client.tool("linux.uname", TARGET)
                assert (result.get("isError") is not True) == should_succeed, result
                if should_succeed:
                    assert result["structuredContent"] == {
                        "id": TARGET, "os": "Linux"
                    }, result
                assert not list(ephemeral.iterdir()), "short-lived key material leaked"

            observe(True)
            # Both malformed credentials and actual Vault token revocation
            # must stop issuance; there is no static-key fallback.
            token_file.write_text("revoked-or-untrusted-token")
            observe(False)
            token_file.write_text(restricted)
            observe(True)
            api("POST", "auth/token/revoke",
                {"token": restricted}, root_token)
            observe(False)
            replacement = limited_token()
            token_file.write_text(replacement)
            observe(True)

            # Policy and argument denials are enforced before signing.
            denied = client.tool("linux.uname", TARGET, command="id")
            assert denied.get("isError") is True, denied
            denied = client.tool("linux.uname", "not-in-inventory")
            assert denied.get("isError") is True, denied
            assert not list(ephemeral.iterdir())

            subprocess.run(
                ["docker", "stop", container],
                check=True, capture_output=True, timeout=20,
            )
            observe(False)  # Vault outage must not re-enable a cached key.
            audit_text = audit.read_text()
            for secret in (root_token, restricted, replacement, "BEGIN OPENSSH PRIVATE KEY"):
                assert secret not in audit_text
            assert "succeeded" in audit_text and "failed" in audit_text
            print("Real Vault 2.2.1 TLS, restricted SSH role/token, sshd, revocation, outage and cleanup passed")
        finally:
            if process is not None:
                process.stdin.close()
                try:
                    process.wait(timeout=6)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=6)
            if sshd is not None:
                sshd.terminate()
                try:
                    sshd.wait(timeout=6)
                except subprocess.TimeoutExpired:
                    sshd.kill()
                    sshd.wait(timeout=6)
            subprocess.run(
                ["docker", "rm", "--force", container],
                capture_output=True, text=True, timeout=15,
            )


if __name__ == "__main__":
    main()
