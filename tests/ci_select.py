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
    for path in paths:
        if not path or path.startswith("/") or "\\" in path or ".." in PurePosixPath(path).parts:
            return ALL.copy()
        if path.startswith(("docs/",)) or path in {"README.md", "SECURITY.md", "LICENSE", "NOTICE"}:
            continue
        # CI selector and GitHub policy modifications must prove every lane,
        # even if this increases testing for the change that introduces them.
        if path.startswith(".github/") or path in {"tests/ci_select.py", "tests/test_ci_select.py"}:
            return ALL.copy()
        if path.startswith(("Cargo.", "rust-toolchain", "build.rs")):
            return ALL.copy()
        if path.startswith(("deploy/k3s/", "tests/k3s_", "deploy/traefik/")):
            result["k3s"] = True
            result["isolation"] = True
            result["oauth"] = True
            continue
        if path.startswith(("fuzz/", "schemas/", "config/")) or path.startswith(
            ("src/declarative", "src/schema", "src/snapshot", "tests/schema_", "tests/declarative_")
        ):
            result["core"] = True
            result["fuzz"] = True
            continue
        if path.startswith(("src/vault", "src/credentials", "src/provider_router", "tests/vault_")):
            result["core"] = True
            result["vault"] = True
            continue
        if path.startswith(("src/remote_", "src/http_", "tests/remote_", "tests/ingress_")):
            result["core"] = True
            result["oauth"] = True
            result["k3s"] = True
            continue
        if path.startswith(("src/audit", "tests/audit_", "src/main.rs", "src/runtime")):
            result["core"] = True
            result["vault"] = True
            result["oauth"] = True
            result["k3s"] = True
            continue
        if path.startswith(("src/", "tests/", "examples/", "scripts/")):
            result["core"] = True
            continue
        # Unrecognized project assets should never accidentally skip tests.
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
