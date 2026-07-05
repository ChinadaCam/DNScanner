import unittest

from DNScanner.passive import merge, parse_crtsh
from DNScanner.takeover import check_takeover, evaluate_takeover, match_service


class TestCrtsh(unittest.TestCase):
    def test_parse(self):
        data = [{"name_value": "www.example.com\n*.example.com"},
                {"common_name": "api.example.com"},
                {"name_value": "example.com"},     # apex -> excluded
                {"name_value": "other.org"}]        # other domain -> excluded
        names = parse_crtsh(data, "example.com")
        self.assertIn("www.example.com", names)
        self.assertIn("api.example.com", names)
        self.assertNotIn("example.com", names)
        self.assertNotIn("other.org", names)
        self.assertEqual(names, sorted(set(names)))  # deduped + sorted

    def test_parse_empty(self):
        self.assertEqual(parse_crtsh(None, "example.com"), [])


class TestMerge(unittest.TestCase):
    def test_merge(self):
        active = [{"name": "www.example.com", "ips": ["1.2.3.4"]}]
        passive = ["www.example.com", "api.example.com"]
        by_name = {x["name"]: x for x in merge(active, passive)}
        self.assertEqual(by_name["www.example.com"]["source"], "dns+ct")
        self.assertEqual(by_name["www.example.com"]["ips"], ["1.2.3.4"])
        self.assertEqual(by_name["api.example.com"]["source"], "ct")
        self.assertEqual(by_name["api.example.com"]["ips"], [])


class TestTakeover(unittest.TestCase):
    def test_match(self):
        self.assertEqual(match_service("foo.github.io")["service"], "GitHub Pages")
        self.assertEqual(match_service("bucket.s3.amazonaws.com")["service"], "AWS S3")
        self.assertIsNone(match_service("example.com"))
        self.assertIsNone(match_service(None))

    def test_evaluate_potential(self):
        r = evaluate_takeover("sub.example.com", "foo.github.io")
        self.assertEqual(r["service"], "GitHub Pages")
        self.assertEqual(r["confidence"], "potential")
        self.assertFalse(r["vulnerable"])

    def test_evaluate_confirmed(self):
        r = evaluate_takeover("sub.example.com", "foo.github.io",
                              body="<html>There isn't a GitHub Pages site here.</html>")
        self.assertEqual(r["confidence"], "confirmed")
        self.assertTrue(r["vulnerable"])
        self.assertTrue(r["fingerprints_matched"])

    def test_evaluate_no_service(self):
        r = evaluate_takeover("sub.example.com", "safe.internal.example.net")
        self.assertIsNone(r["service"])
        self.assertFalse(r["vulnerable"])

    def test_check_takeover_with_fake_resolver(self):
        class FakeResolver:
            def query(self, name, rtype):
                return ["foo.github.io"] if rtype == "CNAME" else []

        r = check_takeover("sub.example.com", FakeResolver(), fetch=False)
        self.assertEqual(r["service"], "GitHub Pages")
        self.assertEqual(r["confidence"], "potential")


if __name__ == "__main__":
    unittest.main()
