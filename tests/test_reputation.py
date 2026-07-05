import unittest

from DNScanner.reputation import (
    evaluate_reputation,
    parse_dbl,
    parse_sb,
    parse_vt,
    safe_browsing,
    spamhaus_dbl,
    virustotal,
)


class TestDbl(unittest.TestCase):
    def test_listed(self):
        self.assertTrue(parse_dbl(["127.0.1.4"])["listed"])

    def test_not_listed(self):
        self.assertFalse(parse_dbl([])["listed"])

    def test_blocked_resolver(self):
        p = parse_dbl(["127.255.255.254"])
        self.assertFalse(p["listed"])
        self.assertTrue(p["blocked_resolver"])

    def test_with_fake_resolver(self):
        class FR:
            def query(self, name, rtype):
                return ["127.0.1.2"] if name.endswith("dbl.spamhaus.org") else []

        r = spamhaus_dbl("e.com", FR())
        self.assertEqual(r["status"], "ok")
        self.assertTrue(r["listed"])


class TestVt(unittest.TestCase):
    def test_parse(self):
        data = {"data": {"attributes": {"last_analysis_stats": {"malicious": 3, "harmless": 80},
                                        "reputation": -5}}}
        p = parse_vt(data)
        self.assertEqual(p["malicious"], 3)
        self.assertEqual(p["reputation"], -5)

    def test_skipped_without_key(self):
        self.assertEqual(virustotal("e.com", config=None)["status"], "skipped")


class TestSb(unittest.TestCase):
    def test_parse(self):
        data = {"matches": [{"threatType": "MALWARE"}, {"threatType": "SOCIAL_ENGINEERING"}]}
        p = parse_sb(data)
        self.assertTrue(p["listed"])
        self.assertIn("MALWARE", p["matches"])

    def test_empty(self):
        self.assertFalse(parse_sb({})["listed"])

    def test_skipped_without_key(self):
        self.assertEqual(safe_browsing("e.com", config=None)["status"], "skipped")


class TestEvaluate(unittest.TestCase):
    def test_high_findings(self):
        rep = {"spamhaus": {"status": "ok", "listed": True, "codes": ["127.0.1.2"]},
               "virustotal": {"status": "ok", "malicious": 4},
               "safebrowsing": {"status": "ok", "listed": True, "matches": ["MALWARE"]}}
        ids = {f["id"] for f in evaluate_reputation(rep)}
        self.assertEqual(ids, {"reputation-spamhaus", "reputation-virustotal", "reputation-safebrowsing"})

    def test_clean(self):
        rep = {"spamhaus": {"status": "ok", "listed": False},
               "virustotal": {"status": "skipped"}, "safebrowsing": {"status": "skipped"}}
        self.assertEqual({f["id"] for f in evaluate_reputation(rep)}, {"reputation-clean"})


if __name__ == "__main__":
    unittest.main()
