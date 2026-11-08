"""Conservative, auditable change-impact selection for HostMarshal CI (FR-036).

Only explicitly known, narrowly scoped paths may omit expensive suites.
Unrecognized paths, selection failures, shared security boundaries and
dependency/workflow changes always request the full regression matrix.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

SUITES = ("verify", "protocol", "vault", "oauth", "fuzz", "k3s")


def full():
    return {name: True for name in SUITES}


def docs_only(path):
    return (path.endswith(".md") and
            (path.startswith("docs/") or "/" not in path))


def classify(paths, force_full=False):
    """Pure policy: false skips only suites proven unrelated by known paths."""
    if force_full or not paths:
        return full()
    if all(docs_only(path) for path in paths):
        return {name: False for name in SUITES}

    selected = {name: False for name in SUITES}
    selected["verify"] = True
    global_boundaries = {
        "Cargo.toml", "Cargo.lock", "build.rs",
        "src/main.rs", "src/lib.rs", "src/audit.rs", "src/runtime.rs",
        "src/adapter.rs", "src/authorization.rs", "src/identity.rs",
        "src/credentials.rs", "src/provider_router.rs",
        "src/snapshot.rs", "src/transport.rs",
    }
    # A known security-sensitive change or the selector itself cannot
    # relax its own enforcement or skip integration.
    for path in paths:
        if path in global_boundaries or path.startswith(".github/workflows/"):
            return full()
        if path in ("tests/ci_impact.py", "tests/test_ci_impact.py"):
            return full()
        if docs_only(path):
            continue
        if path in {
            "src/vault_auth.rs", "src/vault_ssh.rs",
            "tests/vault_real_smoke.py", "tests/vault_ssh_smoke.py",
        }:
            selected["vault"] = selected["protocol"] = True
        elif path in {
            "src/remote_auth.rs", "src/remote_http.rs",
            "tests/ingress_oidc_ci.py", "tests/remote_http_smoke.py",
            "tests/remote_hardening_smoke.py",
        } or path.startswith("deploy/traefik/"):
            selected["oauth"] = selected["protocol"] = True
            if path in ("src/remote_auth.rs", "src/remote_http.rs"):
                selected["k3s"] = True
        elif path in {
            "src/declarative.rs", "src/schema.rs",
            "tests/schema_conformance.py",
        } or path.startswith(("schemas/", "fuzz/")):
            selected["protocol"] = selected["fuzz"] = True
        elif path.startswith("deploy/k3s/") or path in {
            "tests/k3s_cluster_ci.py", "tests/k3s_manifest_contract.py",
        }:
            selected["k3s"] = True
        elif path in {
            "src/audit_delivery.rs", "src/dynamic_mcp.rs",
            "src/observation.rs", "tests/audit_delivery_smoke.py",
            "tests/audit_smoke.py", "tests/mcp_smoke.py",
            "tests/mcp_modern_smoke.py", "tests/declarative_smoke.py",
            "tests/reload_smoke.py", "tests/transport_smoke.py",
            "tests/policy_explain_smoke.py",
        }:
            selected["protocol"] = True
        elif path.startswith("config/v1alpha1/"):
            selected["protocol"] = selected["fuzz"] = True
        else:
            # New Rust files, renamed paths, unknown scripts and any
            # governance/CI changes are not automatically classified safe.
            return full()
    return selected


def changed_files(base, head):
    """Git diff failure or shallow-history failure forces full CI."""
    if not base or not head or set(base) == {"0"} or set(head) == {"0"}:
        return None
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "-z", "--no-ext-diff",
             base, head],
            check=True, capture_output=True,
        )
        return [p.decode("utf-8", "surrogateescape")
                for p in result.stdout.split(b"\0") if p]
    except (subprocess.CalledProcessError, OSError) as error:
        print(f"CI impact: diff unavailable; require all suites ({type(error).__name__})",
              file=sys.stderr)
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="")
    parser.add_argument("--head", default="")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--paths-json")
    parser.add_argument("--github-output", default=os.getenv("GITHUB_OUTPUT"))
    args = parser.parse_args()
    paths = (json.loads(args.paths_json)
             if args.paths_json is not None
             else changed_files(args.base, args.head))
    selected = classify(paths, force_full=args.full or paths is None)
    entries = [f"{suite}={str(selected[suite]).lower()}" for suite in SUITES]
    entries.append(f"scope={'full' if all(selected.values()) else 'selective'}")
    if args.github_output:
        with Path(args.github_output).open("a", encoding="utf-8") as output:
            output.write("\n".join(entries) + "\n")
    print(f"CI impact: {len(paths) if paths is not None else 'unknown'} changed paths;"
          f" {', '.join(entries)}")


if __name__ == "__main__":
    main()
