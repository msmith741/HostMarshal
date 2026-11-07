"""End-to-end declarative MCP tests. No network, SSH, or real infrastructure."""
import json
import subprocess
import tempfile
from pathlib import Path

from mcp_smoke import BIN, response, send

EXAMPLE = Path("config/v1alpha1").resolve()


def session(config_dir, principal, expected_names):
    process = subprocess.Popen(
        [str(BIN), "--config-dir", str(config_dir), "--principal", principal],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1,
    )
    try:
        send(process, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "m1-smoke", "version": "0.1.0"},
            },
        })
        response(process, 1)
        send(process, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        send(process, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tools = response(process, 2)["tools"]
        names = {x["name"] for x in tools}
        assert names == expected_names, names
        send(process, {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "inventory.inspect", "arguments": {"target": "sample-linux"}},
        })
        outcome = response(process, 3)
        if principal == "example-operator":
            assert outcome.get("isError") is not True, outcome
            assert outcome["structuredContent"]["id"] == "sample-linux", outcome
        else:
            assert outcome.get("isError") is True, outcome
        send(process, {
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "inventory.inspect", "arguments": {"target": "arbitrary-host"}},
        })
        outcome = response(process, 4)
        assert outcome.get("isError") is True, outcome
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def cli_validate(directory, success=True):
    p = subprocess.run(
        [str(BIN), "config", "validate", str(directory)],
        capture_output=True, text=True, timeout=10,
    )
    assert (p.returncode == 0) == success, p.stderr


if __name__ == "__main__":
    cli_validate(EXAMPLE)
    session(EXAMPLE, "example-operator", {"inventory.inspect"})
    session(EXAMPLE, "unauthorized-subject", set())
    with tempfile.TemporaryDirectory() as temp_dir:
        temp = Path(temp_dir)
        for source in EXAMPLE.glob("*.yaml"):
            (temp / source.name).write_text(source.read_text())
        cap = (temp / "capability.yaml").read_text()
        # Same trusted operation, different YAML tool name, no Rust handler changes.
        (temp / "capability-two.yaml").write_text(
            cap.replace("  name: inventory.inspect", "  name: inventory.alternate")
        )
        grant = (temp / "grant.yaml").read_text()
        (temp / "grant-two.yaml").write_text(
            grant.replace("example-inventory-reader", "another-reader")
                 .replace("    - inventory.inspect", "    - inventory.alternate")
        )
        cli_validate(temp)
        session(temp, "example-operator", {"inventory.inspect", "inventory.alternate"})
        # Privilege-widening attempts fail config validation.
        (temp / "capability-two.yaml").write_text(
            cap.replace("inventory.inspect", "inventory.alternate")
               .replace("  targetKind: Host", "  targetKind: Host\n  command: whoami")
        )
        cli_validate(temp, success=False)
    print("Declarative MCP security smoke tests passed")
