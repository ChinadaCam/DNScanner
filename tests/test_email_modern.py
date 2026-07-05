import unittest

from DNScanner.email_modern import (
    evaluate_modern_email,
    parse_bimi,
    parse_mta_sts_policy,
    parse_mta_sts_txt,
    parse_tls_rpt,
    parse_tlsa,
)


class TestMtaSts(unittest.TestCase):
    def test_txt(self):
        self.assertTrue(parse_mta_sts_txt(["v=STSv1; id=20230101"])["present"])
        self.assertFalse(parse_mta_sts_txt(["v=spf1 -all"])["present"])

    def test_policy(self):
        p = parse_mta_sts_policy(
            "version: STSv1\nmode: enforce\nmx: a.example.com\nmx: b.example.com\nmax_age: 604800")
        self.assertEqual(p["mode"], "enforce")
        self.assertEqual(p["max_age"], 604800)
        self.assertEqual(p["mx"], ["a.example.com", "b.example.com"])

    def test_policy_missing(self):
        self.assertFalse(parse_mta_sts_policy(None)["fetched"])


class TestOthers(unittest.TestCase):
    def test_tls_rpt(self):
        self.assertTrue(parse_tls_rpt(["v=TLSRPTv1; rua=mailto:t@e.com"])["present"])
        self.assertFalse(parse_tls_rpt([])["present"])

    def test_bimi(self):
        b = parse_bimi(["v=BIMI1; l=https://e.com/logo.svg; a=https://e.com/vmc.pem"])
        self.assertTrue(b["present"])
        self.assertEqual(b["location"], "https://e.com/logo.svg")


class TestTlsaDnssec(unittest.TestCase):
    def test_protected(self):
        t = parse_tlsa(["3 1 1 abcdef0123456789"], authenticated=True)
        self.assertTrue(t["present"])
        self.assertTrue(t["dnssec_protected"])
        self.assertIsNone(t["note"])
        self.assertEqual(t["records"][0]["usage"], "3")

    def test_unprotected_is_noted(self):
        t = parse_tlsa(["3 1 1 abcdef"], authenticated=False)
        self.assertTrue(t["present"])
        self.assertFalse(t["dnssec_protected"])
        self.assertIn("not protective", t["note"])

    def test_absent(self):
        self.assertFalse(parse_tlsa([], True)["present"])


class TestEvaluate(unittest.TestCase):
    def test_findings(self):
        modern = {"mta_sts": {"present": False}, "tls_rpt": {"present": False},
                  "bimi": {"present": False},
                  "dane": parse_tlsa(["3 1 1 ab"], authenticated=False)}
        ids = {f["id"] for f in evaluate_modern_email(modern)}
        self.assertIn("mta-sts-missing", ids)
        self.assertIn("tls-rpt-missing", ids)
        self.assertIn("dane-no-dnssec", ids)

    def test_clean_posture(self):
        modern = {"mta_sts": {"present": True, "mode": "enforce"},
                  "tls_rpt": {"present": True}, "dane": parse_tlsa([], True)}
        self.assertEqual(evaluate_modern_email(modern), [])


if __name__ == "__main__":
    unittest.main()
