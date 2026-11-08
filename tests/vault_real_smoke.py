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

            sshd, ssh_port, known_hosts = start_certificate_sshd(root, create_user=False)
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

            # AppRole is a separate, explicit authentication mode. Its
            # restricted service token can sign and renew itself, not list
            # mounts or manage other tokens/roles.
            api("POST", "sys/auth/approle", {"type": "approle"}, root_token)
            api("POST", "auth/approle/role/hostmarshal", {
                "bind_secret_id": True,
                "secret_id_num_uses": 0,
                "token_no_default_policy": True,
                "token_policies": ["hostmarshal-sign-only"],
                "token_type": "service",
                "token_ttl": "90s",
                "token_max_ttl": "6m",
            }, root_token)
            role_id = api("GET", "auth/approle/role/hostmarshal/role-id",
                          token=root_token)["data"]["role_id"]
            secret_id = api("POST", "auth/approle/role/hostmarshal/secret-id",
                            {}, root_token)["data"]["secret_id"]
            role_file = root / "approle-role-id"
            secret_file = root / "approle-secret-id"
            role_file.write_text(role_id)
            secret_file.write_text(secret_id)
            role_file.chmod(0o600)
            secret_file.chmod(0o600)

            # No change in grants/adapter or ability to use arbitrary API paths.
            # Revocation of renewal rights must be sticky even after restore.
            renewable_policy = (
                'path "ssh/sign/read-only" { capabilities = ["create", "update"] }\n'
                'path "auth/token/renew-self" { capabilities = ["create", "update"] }'
            )
            api("PUT", "sys/policies/acl/hostmarshal-sign-only",
                {"policy": renewable_policy}, root_token)
            # An epoch marker is operator-owned state, never an access token.
            # Tests simulate an atomic administrator update; production
            # deployments must keep the file and its parent outside the
            # HostMarshal runtime user's write authority.
            # The external operator runs as a different OS principal.
            # /run, its dedicated child, and marker are all root-owned,
            # non-writable by HostMarshal's unprivileged test process.
            # CI uses sudo solely to set up/advance/clean up the fixture.
            operator_directory = Path("/run") / ("hm-ci-epoch-" + secrets.token_hex(8))
            subprocess.run(
                ["sudo", "install", "-d", "-o", "root", "-g", "root", "-m", "0755",
                 str(operator_directory)],
                check=True, capture_output=True, timeout=10,
            )
            recovery_file = operator_directory / "epoch"

            def advance_recovery_epoch(value):
                source = root / "staged-recovery-epoch"
                source.write_text(f"{value}\n")
                subprocess.run(
                    ["sudo", "install", "-o", "root", "-g", "root", "-m", "0444",
                     str(source), str(operator_directory / "next")],
                    check=True, capture_output=True, timeout=10,
                )
                subprocess.run(
                    ["sudo", "mv", "-f", "--", str(operator_directory / "next"),
                     str(recovery_file)],
                    check=True, capture_output=True, timeout=10,
                )

            advance_recovery_epoch(100)

            app_cfg = json.loads(signer_config.read_text())
            app_cfg.pop("tokenFile")
            app_cfg["appRole"] = {
                "authMount": "approle",
                "roleIdFile": str(role_file),
                "secretIdFile": str(secret_file),
                "expectedPolicy": "hostmarshal-sign-only",
                # Exceeds 90-second TTL intentionally: every subsequent call
                # must exercise renew-self, rather than silently using a cache.
                "renewBeforeSeconds": 120,
                "recoveryEpochFile": str(recovery_file),
            }
            app_config = root / "vault-approle.json"
            app_config.write_text(json.dumps(app_cfg))
            app_config.chmod(0o600)

            # Fail at configuration load on ambiguous/static fallback sources.
            both = dict(app_cfg)
            both["tokenFile"] = str(token_file)
            bad_config = root / "vault-invalid-auth.json"
            bad_config.write_text(json.dumps(both))
            bad_config.chmod(0o600)
            invalid = subprocess.run([
                str(BIN), "--config-dir", str(config),
                "--principal", "example-operator",
                "--vault-ssh-config", str(bad_config),
            ], capture_output=True, text=True, timeout=8)
            assert invalid.returncode != 0 and "exactly one" in invalid.stderr
            # Shutdown the separate token-file session before testing AppRole.
            process.stdin.close()
            process.wait(timeout=6)
            process = None
            app_audit = root / "approle-audit.jsonl"
            process = subprocess.Popen([
                str(BIN), "--config-dir", str(config),
                "--principal", "example-operator",
                "--vault-ssh-config", str(app_config),
                "--audit-log", str(app_audit),
            ], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, bufsize=1, env=environment)
            app_client = MCP(process)
            def observe_app(expected):
                result = app_client.tool("linux.uname", TARGET)
                assert (result.get("isError") is not True) == expected, result
                if expected:
                    assert result["structuredContent"] == {"id": TARGET, "os": "Linux"}
                assert not list(ephemeral.iterdir())
            observe_app(True)   # AppRole login obtains first restricted token
            observe_app(True)   # renew-self must work for a reusable session
            api("PUT", "sys/policies/acl/hostmarshal-sign-only",
                {"policy": policy}, root_token)
            observe_app(False)  # failed renew-self quarantines token
            api("PUT", "sys/policies/acl/hostmarshal-sign-only",
                {"policy": renewable_policy}, root_token)
            observe_app(False)  # must NOT silently re-login with SecretID
            advance_recovery_epoch(99)
            observe_app(False)  # rollbacks are never authorization
            advance_recovery_epoch(100)
            observe_app(False)  # restoring the baseline still does not recover
            advance_recovery_epoch(101)   # explicit operator-authorized retry
            observe_app(True)             # fresh bounded Vault AppRole login
            app_text = app_audit.read_text()
            for value in (role_id, secret_id, root_token, restricted, replacement):
                assert value not in app_text, "Vault credential leaked to audit"
            process.stdin.close()
            process.wait(timeout=6)
            process = None

            # Independent proactive lifecycle: no invocation occurs during
            # a lease longer than its 30s TTL. A call at 36s can succeed ONLY
            # if the provider-side background renewal kept the Vault lease
            # alive; request-time renewal alone would be too late.
            api("POST", "auth/approle/role/hostmarshal", {
                "bind_secret_id": True,
                "secret_id_num_uses": 0,
                "token_no_default_policy": True,
                "token_policies": ["hostmarshal-sign-only"],
                "token_type": "service",
                "token_ttl": "30s",
                "token_max_ttl": "6m",
            }, root_token)
            proactive = dict(app_cfg)
            proactive["appRole"] = dict(app_cfg["appRole"])
            proactive["appRole"]["renewBeforeSeconds"] = 15
            proactive_config = root / "vault-proactive.json"
            proactive_config.write_text(json.dumps(proactive))
            proactive_config.chmod(0o600)
            process = subprocess.Popen([
                str(BIN), "--config-dir", str(config),
                "--principal", "example-operator",
                "--vault-ssh-config", str(proactive_config),
                "--audit-log", str(app_audit),
            ], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, bufsize=1, env=environment)
            proactive_client = MCP(process)

            def observe_proactive(success):
                result = proactive_client.tool("linux.uname", TARGET)
                assert (result.get("isError") is not True) == success, result
                assert not list(ephemeral.iterdir())

            observe_proactive(True)
            time.sleep(36)
            observe_proactive(True)  # lease survived idle period beyond TTL
            # Removing renew privilege causes the next background renewal
            # to quarantine the session. A repaired policy alone is NOT a
            # recovery authorization.
            api("PUT", "sys/policies/acl/hostmarshal-sign-only",
                {"policy": policy}, root_token)
            time.sleep(19)
            observe_proactive(False)
            api("PUT", "sys/policies/acl/hostmarshal-sign-only",
                {"policy": renewable_policy}, root_token)
            observe_proactive(False)
            advance_recovery_epoch(102)
            observe_proactive(True)
            process.stdin.close()
            process.wait(timeout=6)
            process = None

            # JWT workload authentication is provider-neutral: the signed
            # assertion can be delivered by any operator-trusted workload
            # identity issuer. Vault validates signature, exact issuer,
            # audience and subject before minting signing-only Vault tokens.
            # Real Vault's JWT auth plugin is exercised, NOT a mocked API.
            import base64

            api("POST", "sys/auth/jwt", {"type": "jwt"}, root_token)
            jwt_key = root / "workload-signing.pem"
            jwt_pub = root / "workload-signing.pub.pem"
            subprocess.run([
                "openssl", "genpkey", "-algorithm", "RSA",
                "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(jwt_key)
            ], check=True, capture_output=True, timeout=15)
            subprocess.run([
                "openssl", "pkey", "-in", str(jwt_key), "-pubout",
                "-out", str(jwt_pub)
            ], check=True, capture_output=True, timeout=10)
            jwt_issuer = "https://issuer.example.invalid/"
            jwt_audience = "https://vault.example.invalid/workload"
            api("POST", "auth/jwt/config", {
                "jwt_validation_pubkeys": [jwt_pub.read_text()],
                "jwt_supported_algs": ["RS256"],
                "bound_issuer": jwt_issuer,
            }, root_token)
            api("POST", "auth/jwt/role/read-only-workload", {
                "role_type": "jwt",
                "user_claim": "sub",
                "bound_subject": "workload-observer",
                "bound_audiences": [jwt_audience],
                "token_no_default_policy": True,
                "token_policies": ["hostmarshal-sign-only"],
                "token_type": "service",
                "token_ttl": "90s",
                "token_max_ttl": "6m",
            }, root_token)

            def workload_token(subject="workload-observer", audience=jwt_audience,
                               issuer=jwt_issuer):
                def b64(value):
                    return base64.urlsafe_b64encode(value).decode().rstrip("=")
                now = int(time.time())
                h = b64(json.dumps({"alg": "RS256", "typ": "JWT"},
                                   separators=(",", ":")).encode())
                payload = b64(json.dumps({
                    "iss": issuer, "sub": subject, "aud": audience,
                    "iat": now, "nbf": now - 2, "exp": now + 240,
                }, separators=(",", ":")).encode())
                signed = (h + "." + payload).encode()
                result = subprocess.run([
                    "openssl", "dgst", "-sha256", "-sign", str(jwt_key)
                ], input=signed, capture_output=True, check=True, timeout=10)
                return signed.decode() + "." + b64(result.stdout)

            workload_file = root / "workload.jwt"
            workload_file.write_text(workload_token())
            workload_file.chmod(0o600)
            jwt_config = json.loads(signer_config.read_text())
            jwt_config.pop("tokenFile")
            jwt_config["jwtAuth"] = {
                "authMount": "jwt",
                "role": "read-only-workload",
                "jwtFile": str(workload_file),
                "expectedPolicy": "hostmarshal-sign-only",
                "renewBeforeSeconds": 120,
                "recoveryEpochFile": str(recovery_file),
            }
            config_jwt = root / "vault-jwt.json"
            config_jwt.write_text(json.dumps(jwt_config))
            config_jwt.chmod(0o600)

            # All authentication sources are exclusive, not fallback chains.
            ambiguous_jwt = dict(jwt_config)
            ambiguous_jwt["appRole"] = app_cfg["appRole"]
            invalid_jwt = root / "invalid-mixed-jwt.json"
            invalid_jwt.write_text(json.dumps(ambiguous_jwt))
            invalid_jwt.chmod(0o600)
            reject = subprocess.run([
                str(BIN), "--config-dir", str(config),
                "--principal", "example-operator",
                "--vault-ssh-config", str(invalid_jwt),
            ], capture_output=True, text=True, timeout=8)
            assert reject.returncode != 0 and "exactly one" in reject.stderr

            jwt_audit = root / "jwt-audit.jsonl"
            process = subprocess.Popen([
                str(BIN), "--config-dir", str(config),
                "--principal", "example-operator",
                "--vault-ssh-config", str(config_jwt),
                "--audit-log", str(jwt_audit),
            ], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, bufsize=1, env=environment)
            jwt_client = MCP(process)

            def observe_jwt(succeed):
                result = jwt_client.tool("linux.uname", TARGET)
                assert (result.get("isError") is not True) == succeed, result
                if succeed:
                    assert result["structuredContent"] == {"id": TARGET, "os": "Linux"}
                assert not list(ephemeral.iterdir())

            observe_jwt(True)   # genuine Vault JWT authentication
            observe_jwt(True)   # forced, policy-constrained renew-self
            api("PUT", "sys/policies/acl/hostmarshal-sign-only",
                {"policy": policy}, root_token)
            observe_jwt(False)  # renewal revoked => sticky quarantine
            api("PUT", "sys/policies/acl/hostmarshal-sign-only",
                {"policy": renewable_policy}, root_token)
            observe_jwt(False)  # cannot silently re-login with JWT
            advance_recovery_epoch(103)
            observe_jwt(True)        # fresh JWT signature/role policy validated
            process.stdin.close()
            process.wait(timeout=6)
            process = None

            # Wrong subject, audience and signature are rejected by *real*
            # Vault JWT role validation. Each test uses an independent cold
            # session. A failure stays quarantined after valid JWT replacement.
            for forged in (
                workload_token(subject="other-workload"),
                workload_token(audience="https://untrusted.example.invalid/workload"),
                workload_token(issuer="https://untrusted.example.invalid/"),
            ):
                workload_file.write_text(forged)
                negative = subprocess.Popen([
                    str(BIN), "--config-dir", str(config),
                    "--principal", "example-operator",
                    "--vault-ssh-config", str(config_jwt),
                ], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, bufsize=1, env=environment)
                try:
                    negative_client = MCP(negative)
                    denial = negative_client.tool("linux.uname", TARGET)
                    assert denial.get("isError") is True, denial
                    workload_file.write_text(workload_token())
                    sticky = negative_client.tool("linux.uname", TARGET)
                    assert sticky.get("isError") is True, sticky
                finally:
                    negative.stdin.close()
                    negative.wait(timeout=6)

            # A rotated valid JWT is read at the next fresh workload login.
            workload_file.write_text(workload_token())
            process = subprocess.Popen([
                str(BIN), "--config-dir", str(config),
                "--principal", "example-operator",
                "--vault-ssh-config", str(config_jwt),
            ], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, bufsize=1, env=environment)
            jwt_client = MCP(process)
            observe_jwt(True)
            process.stdin.close()
            process.wait(timeout=6)
            process = None
            jwt_audit_text = jwt_audit.read_text()
            for value in (workload_file.read_text(), root_token, restricted,
                          role_id, secret_id, jwt_key.read_text()):
                assert value not in jwt_audit_text, "JWT/Vault credentials leaked"

            # Preserve the independent real-Vault outage check using a live
            # session, not the token-file MCP client closed before AppRole.
            process = subprocess.Popen([
                str(BIN), "--config-dir", str(config),
                "--principal", "example-operator",
                "--vault-ssh-config", str(signer_config),
                "--audit-log", str(audit),
            ], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, bufsize=1, env=environment)
            client = MCP(process)

            subprocess.run(
                ["docker", "stop", container],
                check=True, capture_output=True, timeout=20,
            )
            observe(False)  # Vault outage must not re-enable a cached key.
            audit_text = audit.read_text()
            for secret in (root_token, restricted, replacement, "BEGIN OPENSSH PRIVATE KEY"):
                assert secret not in audit_text
            assert "succeeded" in audit_text and "failed" in audit_text
            print("Real Vault 2.2.1 TLS, restricted SSH signing, proactive renewal, "
                  "AppRole/JWT operator-gated recovery, sticky revocation, outage and cleanup passed")
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
            if "operator_directory" in locals():
                subprocess.run(
                    ["sudo", "rm", "-rf", "--", str(operator_directory)],
                    capture_output=True, text=True, timeout=15,
                )


if __name__ == "__main__":
    main()
