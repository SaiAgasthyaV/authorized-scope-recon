import json
import unittest

from secret_detection import find_secrets, redact_value


class SecretDetectionTests(unittest.TestCase):
    def test_provider_match_is_redacted_and_unverified(self):
        raw = "const key = 'sk_live_1234567890abcdef1234567890abcdef';"
        findings = find_secrets(raw, "https://app.example.test/app.js", "app.example.test")
        stripe = next(finding for finding in findings if finding["finding_type"] == "Stripe live secret key")
        self.assertEqual(stripe["severity"], "High")
        self.assertIn("****", stripe["redacted_evidence"])
        self.assertNotIn("1234567890abcdef1234567890abcdef", json.dumps(stripe))
        self.assertIn("Unverified", stripe["status"])

    def test_false_positive_api_base_url_and_placeholder_are_ignored(self):
        source = """
        const API_BASE_URL = 'https://api.example.test';
        const API_KEY = 'YOUR_API_KEY_HERE';
        const docs = 'this is a long but non-sensitive documentation string';
        """
        self.assertEqual(find_secrets(source, "https://app.example.test/app.js", "app.example.test"), [])

    def test_redaction_retains_only_safe_hint(self):
        self.assertEqual(redact_value("sk_live_abcdefghijklmnopabcd"), "sk_live_****abcd")
        self.assertNotIn("abcdefgh", redact_value("sk_live_abcdefghijklmnopabcd"))

