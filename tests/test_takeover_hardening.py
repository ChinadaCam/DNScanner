import unittest

from DNScanner.passive import parse_crtsh_wildcards
from DNScanner.takeover import (
    FINGERPRINT_SOURCE,
    check_takeover,
    evaluate_takeover,
    same_org,
)


class TestSameOrg(unittest.TestCase):
    def test_same_org(self):
        self.assertTrue(same_org("app.example.com", "assets.example.com"))
        self.assertFalse(same_org("app.example.com", "foo.github.io"))
        self.assertFalse(same_org("app.example.com", None))


class TestEvaluateMetadata(unittest.TestCase):
    def test_candidate_requires_manual_validation(self):
        r = evaluate_takeover("s.example.com", "foo.github.io")
        self.assertTrue(r["requires_manual_validation"])
        self.assertEqual(r["fingerprint_source"], FINGERPRINT_SOURCE)
        self.assertIsNotNone(r["fingerprint_date"])

    def test_non_candidate_no_validation(self):
        r = evaluate_takeover("s.example.com", "safe.internal.example.net")
        self.assertFalse(r["requires_manual_validation"])


class TestExcludeSameOrg(unittest.TestCase):
    class _R:
        def query(self, name, rtype):
            return ["other.github.io"] if rtype == "CNAME" else []

    def test_excluded_when_enabled(self):
        r = check_takeover("app.github.io", self._R(), fetch=False, exclude_same_org=True)
        self.assertIsNone(r["service"])
        self.assertEqual(r.get("skipped"), "same-org")

    def test_detected_when_disabled(self):
        r = check_takeover("app.github.io", self._R(), fetch=False, exclude_same_org=False)
        self.assertEqual(r["service"], "GitHub Pages")
        self.assertTrue(r["requires_manual_validation"])


class TestCtWildcards(unittest.TestCase):
    def test_wildcards(self):
        data = [{"name_value": "*.example.com\nwww.example.com"},
                {"common_name": "*.sub.example.com"},
                {"name_value": "*.other.org"}]
        w = parse_crtsh_wildcards(data, "example.com")
        self.assertIn("*.example.com", w)
        self.assertIn("*.sub.example.com", w)
        self.assertNotIn("*.other.org", w)


if __name__ == "__main__":
    unittest.main()
