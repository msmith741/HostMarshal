"""FR-036 opt-in audit evidence: real stdio MCP, chained log and offline verification."""
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path

from mcp_smoke import BIN, response, send

CONFIG = Path("config/v1alpha1").resolve()

def verify(path, expected=None, success=True):
    args = [str(BIN), "audit", "verify", str(path)]
    if expected is not None:
        args += ["--expected-head", expected]
    result = subprocess.run(args, capture_output=True, text=True, timeout=8)
    if not success:
        assert result.returncode != 0, result
        return None
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)

def run():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        evidence = root / "audit-evidence.jsonl"
        policy = root / "bounded.json"
        policy.write_text(json.dumps({
            "apiVersion": "hostmarshal.io/audit-delivery/v1alpha1",
            "queueCapacity": 8,
            "ackTimeoutMs": 5000,
        }))
        policy.chmod(0o600)
        cmd = [
            str(BIN), "--config-dir", str(CONFIG), "--principal", "example-operator",
            "--audit-evidence-log", str(evidence),
            "--audit-delivery-config", str(policy),
        ]
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, bufsize=1)
        try:
            def rpc(number, method, params=None):
                packet = {"jsonrpc": "2.0", "id": number, "method": method}
                if params is not None:
                    packet["params"] = params
                send(proc, packet)
                return response(proc, number)
            result = rpc(1, "initialize", {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "untrusted-evidence-client", "version": "1"},
            })
            assert "tools" in result["capabilities"], result
            send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
            authorized = rpc(2, "tools/call", {
                "name": "inventory.inspect", "arguments": {"target": "sample-linux"},
            })
            assert authorized.get("isError") is not True, authorized
            rejected = rpc(3, "tools/call", {
                "name": "inventory.inspect",
                "arguments": {"target": "sample-linux", "secret": "SENSITIVE-NOT-LOGGED"},
            })
            assert rejected.get("isError") is True, rejected
        finally:
            proc.stdin.close()
            proc.wait(timeout=8)
        check = verify(evidence)
        assert check["sequence"] == 3, check
        assert len(check["head"]) == 64
        assert verify(evidence, check["head"]) == check
        assert stat.S_IMODE(evidence.stat().st_mode) == 0o600
        original = evidence.read_bytes()
        assert b"SENSITIVE-NOT-LOGGED" not in original
        assert b"untrusted-evidence-client" not in original

        tampered = original.replace(b"sample-linux", b"sample-other", 1)
        assert tampered != original
        evidence.write_bytes(tampered)
        verify(evidence, success=False)
        fail_start = subprocess.run(
            cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=8
        )
        assert fail_start.returncode != 0, fail_start

        evidence.write_bytes(original)
        prefix = original.split(b"\n", 1)[0] + b"\n"
        evidence.write_bytes(prefix)
        prefix_check = verify(evidence)
        assert prefix_check["sequence"] == 1
        verify(evidence, check["head"], success=False)
        evidence.write_bytes(original[:-1])
        verify(evidence, success=False)
        print("Audit evidence chain, external checkpoint, and tamper-denial smoke passed")

if __name__ == "__main__":
    run()
