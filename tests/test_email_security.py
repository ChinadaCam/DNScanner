import unittest

from DNScanner.email_security import (
    evaluate_email_security,
    parse_dkim,
    parse_dmarc,
    parse_spf,
)


class TestSPF(unittest.TestCase):
    def test_absent(self):
        self.assertFalse(parse_spf(["something=else", "v=DMARC1; p=none"])["present"])

    def test_hardfail_and_includes(self):
        r = parse_spf(["v=spf1 include:_spf.google.com ~all"])
        self.assertTrue(r["present"])
        self.assertEqual(r["all"], "~all")
        self.assertIn("_spf.google.com", r["includes"])
        self.assertEqual(r["issues"], [])

    def test_permissive(self):
        r = parse_spf(["v=spf1 +all"])
        self.assertEqual(r["all"], "+all")
        self.assertTrue(any("permissive" in i for i in r["issues"]))

    def test_no_all(self):
        r = parse_spf(["v=spf1 include:a.com include:b.com"])
        self.assertTrue(any("no 'all'" in i for i in r["issues"]))


class TestDMARC(unittest.TestCase):
    def test_absent(self):
        self.assertFalse(parse_dmarc(["v=spf1 -all"])["present"])

    def test_policy_none(self):
        r = parse_dmarc(["v=DMARC1; p=none; rua=mailto:x@e.com"])
        self.assertEqual(r["policy"], "none")
        self.assertTrue(any("none" in i for i in r["issues"]))

    def test_reject_clean(self):
        r = parse_dmarc(["v=DMARC1; p=reject; rua=mailto:x@e.com"])
        self.assertEqual(r["policy"], "reject")
        self.assertEqual(r["issues"], [])


class TestDKIM(unittest.TestCase):
    def test_present(self):
        self.assertTrue(parse_dkim("google", ["v=DKIM1; k=rsa; p=MIGf"])["present"])

    def test_absent(self):
        self.assertFalse(parse_dkim("google", [])["present"])


class TestEvaluate(unittest.TestCase):
    def test_all_missing(self):
        findings = evaluate_email_security(
            parse_spf([]), parse_dmarc([]), [parse_dkim("default", [])]
        )
        ids = {f["id"] for f in findings}
        self.assertIn("spf-missing", ids)
        self.assertIn("dmarc-missing", ids)
        self.assertIn("dkim-none", ids)

    def test_good_posture_no_findings(self):
        findings = evaluate_email_security(
            parse_spf(["v=spf1 -all"]),
            parse_dmarc(["v=DMARC1; p=reject; rua=mailto:x@e.com"]),
            [parse_dkim("google", ["v=DKIM1; p=abc"])],
        )
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
