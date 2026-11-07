"""M2 audit integration: file-backed JSONL decisions and execution (FR-009).

This suite exercises the actual stdio process and does not need any real hosts.
"""
import json
import subprocess
import tempfile
from pathlib import Path

from mcp_smoke import BIN, response, send

CONFIG = Path("config/v1alpha1").resolve()


def run():
    with tempfile.TemporaryDirectory() as temp:
        audit_file = Path(temp) / "events.jsonl"
        process = subprocess.Popen(
            [
                str(BIN), "--config-dir", str(CONFIG), "--principal", "example-operator",
                "--audit-log", str(audit_file),
            ],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1,
        )

        def rpc(id_value, method, params=None):
            packet = {"jsonrpc": "2.0", "id": id_value, "method": method}
            if params is not None:
                packet["params"] = params
            send(process, packet)
            return response(process, id_value)

        try:
            init = rpc(1, "initialize", {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "untrusted-clientinfo", "version": "9.9"},
            })
            assert "tools" in init["capabilities"]
            send(process, {"jsonrpc": "2.0", "method": "notifications/initialized"})
            tools = rpc(2, "tools/list")["tools"]
            assert [tool["name"] for tool in tools] == ["inventory.inspect"]

            good = rpc(3, "tools/call", {
                "name": "inventory.inspect", "arguments": {"target": "sample-linux"},
            })
            assert good.get("isError") is not True, good
            assert good["structuredContent"]["id"] == "sample-linux"

            rejected = rpc(4, "tools/call", {
                "name": "inventory.inspect",
                "arguments": {"target": "sample-linux", "command": "SECRET-NEVER-LOG"},
            })
            assert rejected.get("isError") is True

            wrong_target = rpc(5, "tools/call", {
                "name": "inventory.inspect", "arguments": {"target": "no-such-host"},
            })
            assert wrong_target.get("isError") is True
        finally:
            process.stdin.close()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

        events = [
            json.loads(line)
            for line in audit_file.read_text(encoding="utf-8").splitlines()
        ]
        assert len(events) == 4, events
        assert [e["phase"] for e in events] == [
            "authorized", "succeeded", "denied", "denied",
        ], events
        assert events[0]["requestId"] == events[1]["requestId"]
        assert events[0]["snapshotDigest"].startswith("sha256:")
        assert all(e["issuer"] == "local://trusted-launcher" for e in events)
        assert all(e["subject"] == "example-operator" for e in events)
        assert all("timestampMs" in e and "operation" in e for e in events)

        encoded = audit_file.read_text()
        assert "SECRET-NEVER-LOG" not in encoded
        assert "untrusted-clientinfo" not in encoded
        assert '"arguments"' not in encoded
        assert '"hostname"' not in encoded
        assert "token" not in encoded

        if hasattr(audit_file.stat(), "st_mode"):
            import stat
            assert stat.S_IMODE(audit_file.stat().st_mode) == 0o600
        print("Audited MCP execution and denial smoke tests passed")


if __name__ == "__main__":
    run()
