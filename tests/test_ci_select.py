"""Fail-safe regression selection contract: all new paths must be classified."""
import unittest
import ci_select as selected

class SelectionTests(unittest.TestCase):
    def test_documentation_only_is_cheap(self):
        self.assertFalse(any(selected.classify(["docs/ROADMAP.md", "README.md"]).values()))

    def test_unknown_or_git_failures_force_all(self):
        for files in (None, [], ["new-unclassified.asset"], ["/etc/passwd"], ["../unsafe"], [".github/workflows/ci.yml"], ["tests/ci_select.py"], ["Cargo.lock"]):
            with self.subTest(files=files):
                self.assertTrue(all(selected.classify(files).values()))
        self.assertTrue(all(selected.choose("workflow_dispatch", "", "", []).values()))
        self.assertTrue(all(selected.choose("schedule", "", "", []).values()))
        self.assertTrue(all(selected.choose("push", "0" * 40, "abcdef").values()))

    def test_vault_only_skips_unrelated_clusters_and_fuzz(self):
        value = selected.classify(["src/vault_auth.rs"])
        self.assertTrue(value["core"] and value["vault"])
        self.assertFalse(value["oauth"] or value["k3s"] or value["fuzz"] or value["isolation"])

    def test_parser_only_keeps_fuzz_and_core(self):
        value = selected.classify(["src/declarative.rs", "schemas/v1alpha1/resources.schema.json"])
        self.assertTrue(value["fuzz"] and value["core"])
        self.assertFalse(value["vault"] or value["oauth"] or value["k3s"])

    def test_security_crosscutting_and_network(self):
        cross = selected.classify(["src/audit_delivery.rs"])
        for name in ("core", "vault", "oauth", "k3s"):
            self.assertTrue(cross[name])
        self.assertFalse(cross["fuzz"] or cross["isolation"])
        network = selected.classify(["deploy/k3s/ci/resources.yaml"])
        self.assertTrue(network["k3s"] and network["isolation"] and network["oauth"])

    def test_remote_auth_and_misc(self):
        remote = selected.classify(["src/remote_auth.rs"])
        self.assertTrue(remote["core"] and remote["oauth"] and remote["k3s"])
        self.assertFalse(remote["vault"] or remote["fuzz"])
        other = selected.classify(["src/adapter.rs"])
        self.assertTrue(other["core"])
        self.assertFalse(other["vault"] or other["k3s"])

if __name__ == "__main__":
    unittest.main()
