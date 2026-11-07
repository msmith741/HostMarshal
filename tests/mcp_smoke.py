"""Black-box MCP stdio smoke test using only the Python standard library."""

import json
import select
import subprocess
import tempfile
from pathlib import Path

BIN = Path("target/debug/hostmarshal").resolve()


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
    data = json.loads(line)  # Also ensures stdout was not polluted by logs.
    assert data.get("jsonrpc") == "2.0", data
    assert data.get("id") == expected_id, data
    assert "error" not in data, data
    return data["result"]


def run_session(config, expect_hosts):
    process = subprocess.Popen(
        [str(BIN), "--config", str(config)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    try:
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "hostmarshal-smoke", "version": "0.1.0"},
                },
            },
        )
        initialized = response(process, 1)
        assert "tools" in initialized["capabilities"], initialized
        send(process, {"jsonrpc": "2.0", "method": "notifications/initialized"})

        send(process, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        discovered = response(process, 2)["tools"]
        names = {tool["name"] for tool in discovered}
        assert {"list_hosts", "get_host"} <= names, names

        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "list_hosts", "arguments": {}},
            },
        )
        listed = response(process, 3)
        actual = [host["id"] for host in json.loads(listed["content"][0]["text"])]
        assert actual == expect_hosts, actual

        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "get_host",
                    "arguments": {"host_id": "sample-proxmox"},
                },
            },
        )
        denied = response(process, 4)
        assert denied.get("isError") is True, denied

        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "get_host", "arguments": {"host_id": "sample-linux"}},
            },
        )
        fetched = response(process, 5)
        if expect_hosts:
            assert fetched.get("isError") is not True, fetched
            assert json.loads(fetched["content"][0]["text"])["id"] == "sample-linux"
        else:
            assert fetched.get("isError") is True, fetched
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


if __name__ == "__main__":
    run_session(Path("config/example.json").resolve(), ["sample-linux"])
    with tempfile.TemporaryDirectory() as directory:
        denied_path = Path(directory) / "deny-all.json"
        denied_path.write_text(
            json.dumps(
                {
                    "principal": "hermes",
                    "hosts": [
                        {"id": "sample-linux", "hostname": "sample-linux.invalid"},
                        {"id": "sample-proxmox", "hostname": "sample-proxmox.invalid"},
                    ],
                    "grants": [],
                }
            ),
            encoding="utf-8",
        )
        run_session(denied_path, [])
    print("MCP stdio smoke tests passed")
