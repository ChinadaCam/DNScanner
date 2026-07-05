import unittest

from DNScanner.dns_records import evaluate_caa, evaluate_soa, parse_caa, parse_soa


class TestCAA(unittest.TestCase):
    def test_parse(self):
        p = parse_caa(['0 issue "letsencrypt.org"', '0 issuewild "; "',
                       '0 iodef "mailto:sec@example.com"'])
        self.assertTrue(p["present"])
        self.assertIn("letsencrypt.org", p["issue"])
        self.assertEqual(p["iodef"], ["mailto:sec@example.com"])
        self.assertFalse(p["allows_any_ca"])

    def test_absent(self):
        p = parse_caa([])
        self.assertFalse(p["present"])
        self.assertTrue(p["allows_any_ca"])
        ids = {f["id"] for f in evaluate_caa(p)}
        self.assertIn("caa-missing", ids)

    def test_no_iodef_finding(self):
        p = parse_caa(['0 issue "letsencrypt.org"'])
        ids = {f["id"] for f in evaluate_caa(p)}
        self.assertIn("caa-no-iodef", ids)
        self.assertNotIn("caa-missing", ids)


class TestSOA(unittest.TestCase):
    def test_in_range(self):
        p = parse_soa({"expire": 1209600, "serial": 1, "refresh": 7200,
                       "retry": 3600, "minimum": 3600, "mname": "ns", "rname": "h"})
        self.assertTrue(p["present"])
        self.assertEqual(p["issues"], [])
        self.assertEqual(evaluate_soa(p), [])

    def test_out_of_range(self):
        p = parse_soa({"expire": 100, "serial": 1})
        self.assertTrue(any("expire" in i for i in p["issues"]))
        f = evaluate_soa(p)
        self.assertEqual(f[0]["id"], "soa-expire-range")
        self.assertIn("RFC 1912", f[0]["reference"])

    def test_absent(self):
        p = parse_soa(None)
        self.assertFalse(p["present"])
        self.assertEqual(evaluate_soa(p), [])


if __name__ == "__main__":
    unittest.main()
