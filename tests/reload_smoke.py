"""OS-controlled configuration reload and revocation integration test (FR-014).

Uses only fictional inventory and the MCP stdio transport. Unix-only.
"""
import os
import select
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from mcp_smoke import BIN, response, send

FIXTURE = Path("config/v1alpha1").resolve()


def expect_log(process, needle, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([process.stderr], [], [], max(0, deadline - time.monotonic()))
        if not ready:
            break
        line = process.stderr.readline()
        if needle in line:
            return
    raise AssertionError(f"expected server status containing {needle!r}")


def run():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        for file in FIXTURE.glob("*.yaml"):
            shutil.copyfile(file, root / file.name)
        host = (root / "host.yaml").read_text()
        grant = (root / "grant.yaml").read_text()
        process = subprocess.Popen(
            [str(BIN), "--config-dir", str(root), "--principal", "example-operator"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1,
        )
        request_id = 1

        def rpc(method, params=None):
            nonlocal request_id
            request_id += 1
            packet = {"jsonrpc": "2.0", "id": request_id, "method": method}
            if params is not None:
                packet["params"] = params
            send(process, packet)
            return response(process, request_id)

        def names():
            return {tool["name"] for tool in rpc("tools/list")["tools"]}

        def call():
            return rpc("tools/call", {
                "name": "inventory.inspect",
                "arguments": {"target": "sample-linux"},
            })

        try:
            initialized = rpc("initialize", {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "reload-smoke", "version": "1.0.0"},
            })
            assert "tools" in initialized["capabilities"]
            send(process, {"jsonrpc": "2.0", "method": "notifications/initialized"})
            assert names() == {"inventory.inspect"}
            assert call().get("isError") is not True

            # Valid new configuration atomically removes the grant.
            (root / "grant.yaml").unlink()
            os.kill(process.pid, signal.SIGHUP)
            expect_log(process, "reload Applied")
            assert names() == set()
            assert call().get("isError") is True

            # Invalid reload retains last-known-good DENY snapshot.
            (root / "host.yaml").write_text(host + "\nrunAs: root\n")
            os.kill(process.pid, signal.SIGHUP)
            expect_log(process, "reload rejected")
            assert names() == set()

            # Valid re-grant is an explicit administrative config deployment.
            (root / "host.yaml").write_text(host)
            (root / "grant.yaml").write_text(grant)
            os.kill(process.pid, signal.SIGHUP)
            expect_log(process, "reload Applied")
            assert names() == {"inventory.inspect"}
            assert call().get("isError") is not True

            # OS-controlled emergency deny is immediate for new invocations.
            os.kill(process.pid, signal.SIGUSR1)
            expect_log(process, "emergency lockdown active")
            assert names() == set()
            assert call().get("isError") is True

            # Only a subsequent validated reload can reactivate after lockout.
            os.kill(process.pid, signal.SIGHUP)
            expect_log(process, "reload Applied")
            assert names() == {"inventory.inspect"}
            print("Atomic reload and emergency revocation smoke tests passed")
        finally:
            process.stdin.close()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    run()
