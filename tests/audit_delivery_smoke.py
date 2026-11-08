"""FR-035: actual MCP stdio + protected bounded-audit-delivery config."""
import json
import stat
import subprocess
import tempfile
from pathlib import Path

from mcp_smoke import BIN, response, send

CONFIG = Path("config/v1alpha1").resolve()


def call(process, sequence, method, params=None):
    packet = {"jsonrpc": "2.0", "id": sequence, "method": method}
    if params is not None:
        packet["params"] = params
    send(process, packet)
    return response(process, sequence)


def launch_spec(path, audit_path):
    return [
        str(BIN), "--config-dir", str(CONFIG), "--principal", "example-operator",
        "--audit-log", str(audit_path),
        "--audit-delivery-config", str(path),
    ]


def run():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        audit_path = root / "events.jsonl"
        config_path = root / "delivery.json"
        good = {
            "apiVersion": "hostmarshal.io/audit-delivery/v1alpha1",
            "queueCapacity": 8,
            "ackTimeoutMs": 5000,
        }
        config_path.write_text(json.dumps(good))
        config_path.chmod(0o600)

        process = subprocess.Popen(
            launch_spec(config_path, audit_path),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1,
        )
        try:
            init = call(process, 1, "initialize", {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "untrusted-audit-client", "version": "1.0"},
            })
            assert "tools" in init["capabilities"], init
            send(process, {"jsonrpc": "2.0", "method": "notifications/initialized"})
            ok = call(process, 2, "tools/call", {
                "name": "inventory.inspect",
                "arguments": {"target": "sample-linux"},
            })
            assert not ok.get("isError"), ok
            denied = call(process, 3, "tools/call", {
                "name": "inventory.inspect",
                "arguments": {"target": "untrusted-target", "secret": "NEVER-IN-AUDIT"},
            })
            assert denied.get("isError") is True, denied
        finally:
            process.stdin.close()
            try:
                process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=6)

        events = [json.loads(line) for line in audit_path.read_text().splitlines()]
        assert [e["phase"] for e in events] == ["authorized", "succeeded", "denied"], events
        assert events[0]["requestId"] == events[1]["requestId"]
        assert all(event["subject"] == "example-operator" for event in events)
        assert "NEVER-IN-AUDIT" not in audit_path.read_text()
        assert "untrusted-audit-client" not in audit_path.read_text()
        assert stat.S_IMODE(audit_path.stat().st_mode) == 0o600

        # Rejections must happen before MCP startup, with no fallback sink.
        bad = root / "bad-delivery.json"
        bad.write_text(json.dumps({**good, "queueCapacity": 0}))
        bad.chmod(0o600)
        denied_start = subprocess.run(
            launch_spec(bad, root / "invalid.jsonl"),
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=8,
        )
        assert denied_start.returncode != 0, denied_start

        config_path.chmod(0o644)
        denied_start = subprocess.run(
            launch_spec(config_path, root / "permissive.jsonl"),
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=8,
        )
        assert denied_start.returncode != 0, denied_start

        alias = root / "symlink-delivery.json"
        alias.symlink_to(config_path)
        denied_start = subprocess.run(
            launch_spec(alias, root / "symlink.jsonl"),
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=8,
        )
        assert denied_start.returncode != 0, denied_start

        print("Bounded audit dispatcher stdio and launch-denial tests passed")


if __name__ == "__main__":
    run()
