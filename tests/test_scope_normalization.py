import csv
import tempfile
import unittest
from pathlib import Path

from scope_normalization import ScopePolicy, normalize_csv


class ScopeNormalizationTests(unittest.TestCase):
    def test_alias_based_csv_normalization_and_exclusions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scope.csv"
            with path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["Asset", "Asset Type", "Scope Status", "Notes"])
                writer.writeheader()
                writer.writerows([
                    {"Asset": "https://portal.example.test/path", "Asset Type": "Website", "Scope Status": "In Scope", "Notes": "authorized"},
                    {"Asset": "*.api.example.test", "Asset Type": "Wildcard", "Scope Status": "included", "Notes": ""},
                    {"Asset": "admin.example.test", "Asset Type": "Domain", "Scope Status": "Out of Scope", "Notes": ""},
                    {"Asset": "192.0.2.10", "Asset Type": "IP", "Scope Status": "In Scope", "Notes": ""},
                ])
            records = normalize_csv(path)

        allowed = [record for record in records if record.web_target]
        excluded = [record for record in records if not record.web_target]
        self.assertEqual({record.host for record in allowed}, {"portal.example.test", "api.example.test"})
        self.assertTrue(next(record for record in allowed if record.host == "api.example.test").wildcard)
        self.assertEqual(len(excluded), 2)
        self.assertIn("explicitly marked out of scope", excluded[0].exclusion_reason)

    def test_scope_policy_does_not_expand_exact_domains(self):
        policy = ScopePolicy([
            {"web_target": True, "host": "app.example.test", "wildcard": False},
            {"web_target": True, "host": "api.example.test", "wildcard": True},
        ])
        self.assertTrue(policy.allows_url("https://app.example.test/index.html"))
        self.assertFalse(policy.allows_url("https://other.app.example.test/"))
        self.assertTrue(policy.allows_url("https://v1.api.example.test/openapi.json"))
        self.assertFalse(policy.allows_url("https://api.example.test.evil.test/"))
        self.assertFalse(policy.allows_url("ftp://api.example.test/file"))

