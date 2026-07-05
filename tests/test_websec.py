import unittest

from DNScanner.websec import evaluate_websec, parse_cookies, parse_csp, parse_security_txt


class TestSecurityTxt(unittest.TestCase):
    def test_valid_future(self):
        st = parse_security_txt("Contact: mailto:s@e.com\nExpires: 2999-01-01T00:00:00Z\n")
        self.assertTrue(st["present"])
        self.assertFalse(st["expired"])
        self.assertEqual(st["issues"], [])

    def test_expired(self):
        st = parse_security_txt("Contact: mailto:s@e.com\nExpires: 2000-01-01T00:00:00Z\n")
        self.assertTrue(st["expired"])
        self.assertTrue(any("passed" in i for i in st["issues"]))

    def test_missing_fields(self):
        st = parse_security_txt("# comment\nPolicy: https://e.com/p\n")
        self.assertTrue(any("Contact" in i for i in st["issues"]))
        self.assertTrue(any("Expires" in i for i in st["issues"]))

    def test_absent(self):
        self.assertFalse(parse_security_txt(None)["present"])


class TestCsp(unittest.TestCase):
    def test_weaknesses(self):
        c = parse_csp("default-src 'self'; script-src 'self' 'unsafe-inline' *")
        self.assertTrue(c["present"])
        joined = " ".join(c["weaknesses"])
        self.assertIn("unsafe-inline", joined)
        self.assertIn("script-src allows *", joined)

    def test_no_default_src(self):
        self.assertIn("no default-src directive", parse_csp("script-src 'self'")["weaknesses"])

    def test_absent(self):
        self.assertFalse(parse_csp(None)["present"])


class TestCookies(unittest.TestCase):
    def test_flags(self):
        c = parse_cookies(["sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax", "track=1; Path=/"])
        by = {x["name"]: x for x in c["cookies"]}
        self.assertTrue(by["sid"]["secure"] and by["sid"]["httponly"])
        self.assertEqual(by["sid"]["samesite"], "Lax")
        self.assertFalse(by["track"]["secure"])
        self.assertTrue(any("track" in i for i in c["issues"]))


class TestEvaluate(unittest.TestCase):
    def test_findings_have_remediation(self):
        http = {"reachable": True, "security_txt": parse_security_txt(None),
                "csp": parse_csp("script-src 'self' 'unsafe-inline'"),
                "cookies": parse_cookies(["a=1"])}
        findings = evaluate_websec(http)
        ids = {f["id"] for f in findings}
        self.assertIn("security-txt-missing", ids)
        self.assertIn("csp-weak", ids)
        self.assertIn("cookie-flags", ids)
        for f in findings:
            self.assertTrue(f["remediation"] and f["reference"])


if __name__ == "__main__":
    unittest.main()
