"""MCP 2026-07-28 stateless stdio protocol conformance (FR-011).

Exercises the actual wire interface, including server/discover without initialize.
No network and no caller-provided identity trust.
"""
import json
import select
import subprocess
from pathlib import Path

from mcp_smoke import BIN, response, send

CONFIG = Path("config/v1alpha1").resolve()
META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
    "io.modelcontextprotocol/clientInfo": {
        "name": "hostmarshal-modern-smoke",
        "version": "1.0.0",
    },
}


def run(principal, expected_tools):
    process = subprocess.Popen(
        [str(BIN), "--config-dir", str(CONFIG), "--principal", principal],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    request_id = 0
    try:
        def call(method, arguments=None):
            nonlocal request_id
            request_id += 1
            params = {"_meta": dict(META)}
            if arguments is not None:
                params.update(arguments)
            send(process, {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params,
            })
            return response(process, request_id)

        # No initialize/initialized handshake in the 2026-07-28 era.
        discovery = call("server/discover")
        assert "2026-07-28" in json.dumps(discovery), discovery
        assert "tools" in discovery.get("capabilities", {}), discovery

        listing = call("tools/list")
        names = {tool["name"] for tool in listing["tools"]}
        assert names == expected_tools, names
        assert listing.get("ttlMs", 0) == 0, listing
        assert listing.get("cacheScope", "private").lower() == "private", listing
        for item in listing["tools"]:
            assert item["inputSchema"]["additionalProperties"] is False

        good = call("tools/call", {
            "name": "inventory.inspect",
            "arguments": {"target": "sample-linux"},
        })
        if expected_tools:
            assert good.get("isError") is not True, good
            assert good["structuredContent"]["id"] == "sample-linux", good
        else:
            assert good.get("isError") is True, good

        denied = call("tools/call", {
            "name": "inventory.inspect",
            "arguments": {"target": "another-host"},
        })
        assert denied.get("isError") is True, denied

        injection = call("tools/call", {
            "name": "inventory.inspect",
            "arguments": {"target": "sample-linux", "command": "whoami"},
        })
        assert injection.get("isError") is True, injection
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


if __name__ == "__main__":
    run("example-operator", {"inventory.inspect"})
    run("untrusted-subject", set())
    print("MCP 2026-07-28 stateless protocol smoke tests passed")
