"""Conservative change-based regression selection for HostMarshal GitHub Actions.

Every unknown/unsafe input selects ALL suites. Only a proven documentation-
only change may suppress builds entirely. A full run is always available by
workflow_dispatch or the weekly scheduled acceptance run.
"""
import argparse
import json
import os
import subprocess
from pathlib import PurePosixPath

SUITES = ("core", "vault", "oauth", "fuzz", "k3s", "isolation")
ALL = {key: True for key in SUITES}
NONE = {key: False for key in SUITES}

def changed_files(base, head):
    if not base or not head or base == "0" * 40 or head == "0" * 40:
        return None
    try:
        completed = subprocess.run(
            ["git", "diff", "--name-only", "-z", "--no-renames", base, head],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=15,
        )
        return [path.decode("utf-8") for path in completed.stdout.split(b"\x00") if path]
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return None

def classify(paths):
    if paths is None or not paths:
        return ALL.copy()
    result = NONE.copy()
    # Exact known source and test paths prevent a newly added similarly
    # named module from inheriting a narrow classification by accident.
    parser_files = {
        "src/declarative.rs", "src/schema.rs", "src/snapshot.rs",
        "tests/schema_conformance.py", "tests/declarative_smoke.py",
    }
    vault_files = {
        "src/vault_auth.rs", "src/vault_ssh.rs", "src/credentials.rs",
        "src/provider_router.rs", "tests/vault_real_smoke.py",
        "tests/vault_ssh_smoke.py",
    }
    remote_files = {
        "src/remote_auth.rs", "src/remote_http.rs",
        "tests/remote_http_smoke.py", "tests/remote_hardening_smoke.py",
        "tests/ingress_oidc_ci.py",
    }
    shared_security_files = {
        "src/audit.rs", "src/audit_delivery.rs", "src/audit_evidence.rs",
        "src/main.rs", "src/runtime.rs", "src/adapter.rs",
        "src/authorization.rs", "src/identity.rs",
        "src/dynamic_mcp.rs", "src/lib.rs",
        "tests/audit_smoke.py", "tests/audit_delivery_smoke.py",
        "tests/audit_evidence_smoke.py",
    }
    observation_files = {
        "src/observation.rs", "src/transport.rs",
        "tests/transport_smoke.py",
    }
    protocol_tests = {
        "tests/mcp_smoke.py", "tests/mcp_modern_smoke.py",
        "tests/policy_explain_smoke.py", "tests/reload_smoke.py",
    }
    for path in paths:
        if not path or path.startswith("/") or "\\" in path or ".." in PurePosixPath(path).parts:
            return ALL.copy()
        if ((path.startswith("docs/") and path.endswith(".md"))
                or path in {"README.md", "SECURITY.md", "LICENSE", "NOTICE"}):
            continue
        # CI selector and workflow modifications must prove every lane.
        if path.startswith(".github/") or path in {"tests/ci_select.py", "tests/test_ci_select.py"}:
            return ALL.copy()
        if path.startswith(("Cargo.", "rust-toolchain", "build.rs")):
            return ALL.copy()
        if path.startswith(("deploy/k3s/", "tests/k3s_", "deploy/traefik/")):
            result["k3s"] = True
            result["isolation"] = True
            result["oauth"] = True
            continue
        if path in parser_files or path.startswith(("fuzz/", "schemas/", "config/")):
            result["core"] = True
            result["fuzz"] = True
            continue
        if path in vault_files:
            result["core"] = True
            result["vault"] = True
            continue
        if path in remote_files:
            result["core"] = True
            result["oauth"] = True
            result["k3s"] = True
            continue
        if path in shared_security_files:
            result["core"] = True
            result["vault"] = True
            result["oauth"] = True
            result["k3s"] = True
            continue
        if path in observation_files:
            result["core"] = True
            result["vault"] = True
            continue
        if path in protocol_tests:
            result["core"] = True
            continue
        if path.startswith("examples/"):
            result["core"] = True
            continue
        # Unrecognized code, scripts, tests, docs assets and future security
        # modules are always broad integration candidates.
        return ALL.copy()
    return result

def choose(event, base, head, paths=None):
    if event not in ("pull_request", "push"):
        return ALL.copy()
    return classify(paths if paths is not None else changed_files(base, head))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", required=True)
    parser.add_argument("--base", default="")
    parser.add_argument("--head", default="")
    parser.add_argument("--output", default="")
    args = parser.parse_args()
    selected = choose(args.event, args.base, args.head)
    print(json.dumps(selected, sort_keys=True))
    if args.output:
        with open(args.output, "a", encoding="utf-8") as stream:
            for key in SUITES:
                stream.write(f"{key}={'true' if selected[key] else 'false'}\n")

if __name__ == "__main__":
    main()
