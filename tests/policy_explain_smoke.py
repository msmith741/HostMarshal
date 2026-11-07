"""Offline local policy explanation (FR-010), with no broker or adapter access."""
import json
import subprocess
from pathlib import Path
from mcp_smoke import BIN

CONFIG = Path("config/v1alpha1").resolve()


def explain(subject, capability="inventory.inspect", target="sample-linux"):
    proc = subprocess.run(
        [
            str(BIN), "policy", "explain", str(CONFIG),
            "--subject", subject, "--capability", capability, "--target", target,
        ],
        capture_output=True, text=True, timeout=10, check=True,
    )
    output = json.loads(proc.stdout)
    assert proc.stderr == ""
    assert output["diagnosticOnly"] is True
    assert output["snapshotDigest"].startswith("sha256:")
    assert output["issuer"] == "local://trusted-launcher"
    assert "hostname" not in output
    return output


if __name__ == "__main__":
    yes = explain("example-operator")
    assert yes["allowed"] is True
    assert yes["reason"] == "explicit_grant"
    assert explain("unknown-operator")["allowed"] is False
    assert explain("example-operator", target="not-in-inventory")["allowed"] is False
    assert explain("example-operator", capability="unpublished.tool")["allowed"] is False
    bad = subprocess.run(
        [
            str(BIN), "policy", "explain", str(CONFIG),
            "--subject", "example-operator\nroot",
            "--capability", "inventory.inspect", "--target", "sample-linux",
        ],
        capture_output=True, text=True, timeout=10,
    )
    assert bad.returncode != 0
    assert "invalid launcher identity" in bad.stderr
    assert bad.stdout == ""
    print("Offline policy explain authorization tests passed")
