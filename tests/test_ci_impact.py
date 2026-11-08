"""Policy regression tests for conservative, change-based CI impact."""
import unittest

from ci_impact import SUITES, classify


class ImpactSelectionTests(unittest.TestCase):
    def assert_suites(self, paths, expected):
        result = classify(paths)
        assert set(result) == set(SUITES)
        self.assertEqual(
            {name for name, enabled in result.items() if enabled},
            set(expected),
            paths,
        )

    def test_documentation_only_skips_compilation_and_integration(self):
        self.assert_suites(["README.md", "docs/ROADMAP.md"], [])

    def test_vault_auth_and_signing_changes_are_targeted(self):
        self.assert_suites(
            ["src/vault_auth.rs"],
            ["verify", "vault", "protocol"],
        )

    def test_remote_identity_changes_include_issuer_and_k3s_gates(self):
        self.assert_suites(
            ["src/remote_auth.rs"],
            ["verify", "oauth", "protocol", "k3s"],
        )

    def test_audit_worker_is_covered_by_protocol_but_not_real_vault(self):
        self.assert_suites(
            ["src/audit_delivery.rs"],
            ["verify", "protocol"],
        )

    def test_manifests_trigger_k3s_without_real_vault(self):
        self.assert_suites(
            ["deploy/k3s/ci/resources.yaml"],
            ["verify", "k3s"],
        )

    def test_declarative_parser_triggers_fuzz(self):
        self.assert_suites(
            ["src/declarative.rs", "docs/SECURITY_ARCHITECTURE.md"],
            ["verify", "protocol", "fuzz"],
        )

    def test_traefik_fixture_affects_oauth(self):
        self.assert_suites(
            ["deploy/traefik/ingress-static.yml"],
            ["verify", "oauth", "protocol"],
        )

    def test_shared_runtime_and_dependencies_force_full(self):
        for path in ("src/runtime.rs", "src/audit.rs", "Cargo.lock",
                     "src/main.rs", "src/lib.rs"):
            self.assertEqual(classify([path]), {name: True for name in SUITES})

    def test_new_unknown_rust_path_cannot_bypass_security_gates(self):
        self.assertEqual(
            classify(["src/new_network_auth.rs"]),
            {name: True for name in SUITES},
        )

    def test_unknown_test_or_workflow_forces_full(self):
        for path in ("tests/new_auth_smoke.py", ".github/workflows/ci.yml",
                     "tests/ci_impact.py"):
            self.assertEqual(classify([path]), {name: True for name in SUITES})

    def test_unknown_mixed_with_docs_or_known_paths_forces_full(self):
        self.assertEqual(
            classify(["docs/ROADMAP.md", "src/vault_auth.rs",
                      "src/unknown_authentication.rs"]),
            {name: True for name in SUITES},
        )

    def test_empty_diff_and_forced_full_require_all_suites(self):
        self.assertEqual(classify([]), {name: True for name in SUITES})
        self.assertEqual(
            classify(["docs/ROADMAP.md"], force_full=True),
            {name: True for name in SUITES},
        )


if __name__ == "__main__":
    unittest.main()
