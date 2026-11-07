"""Black-box legacy MCP 2025-11-25 wire conformance over the secured runtime.

All server invocations use the declarative coordinator. The retired JSON
configuration and hard-coded tools must never bypass the M2 audit boundary.
"""
import json
import select
import subprocess
from pathlib import Path

BIN = Path("target/debug/hostmarshal").resolve()
CONFIG = Path("config/v1alpha1").resolve()


def send(process, payload):
    process.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
    process.stdin.flush()


def response(process, expected_id):
    ready, _, _ = select.select([process.stdout], [], [], 15)
    if not ready:
        raise TimeoutError(f"no MCP response for request {expected_id}")
    line = process.stdout.readline()
    if not line:
        raise RuntimeError("MCP server terminated unexpectedly")
    data = json.loads(line)
    assert data.get("jsonrpc") == "2.0", data
    assert data.get("id") == expected_id, data
    assert "error" not in data, data
    return data["result"]


def run_session(principal, expected_tools):
    process = subprocess.Popen(
        [str(BIN), "--config-dir", str(CONFIG), "--principal", principal],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1,
    )
    try:
        send(process, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "untrusted-client", "version": "0.1.0"},
            },
        })
        init = response(process, 1)
        assert "tools" in init["capabilities"], init
        send(process, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        send(process, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        discovered = response(process, 2)["tools"]
        assert {t["name"] for t in discovered} == expected_tools
        send(process, {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {
                "name": "inventory.inspect",
                "arguments": {"target": "sample-linux"},
            },
        })
        result = response(process, 3)
        if expected_tools:
            assert result.get("isError") is not True, result
            assert result["structuredContent"]["id"] == "sample-linux"
        else:
            assert result.get("isError") is True, result
        send(process, {
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "inventory.inspect", "arguments": {"target": "other"}},
        })
        assert response(process, 4).get("isError") is True
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def verify_legacy_json_is_retired():
    proc = subprocess.run(
        [str(BIN), "--config", "config/example.json"],
        capture_output=True, text=True, timeout=5,
    )
    assert proc.returncode != 0
    assert "legacy" in proc.stderr.lower() or "usage" in proc.stderr.lower()


if __name__ == "__main__":
    run_session("example-operator", {"inventory.inspect"})
    run_session("untrusted-subject", set())
    verify_legacy_json_is_retired()
    print("Legacy MCP wire conformance and JSON-mode retirement tests passed")
