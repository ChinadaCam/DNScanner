import unittest

from DNScanner import checks
from DNScanner.checks import (
    detect_wildcard,
    email_security,
    enumerate_subdomains,
    get_records,
)


class FakeResolver:
    """Maps (name, rtype) -> [records]; everything else returns []."""

    def __init__(self, mapping=None, ad=False):
        self.mapping = mapping or {}
        self.ad = ad

    def query(self, name, rtype):
        return list(self.mapping.get((name, rtype), []))

    def query_with_ad(self, name, rtype):
        return list(self.mapping.get((name, rtype), [])), self.ad

    def reverse(self, ip):
        return list(self.mapping.get((ip, "PTR"), []))


class WildcardResolver:
    """Any unmapped *.domain A query resolves to the wildcard IP."""

    def __init__(self, mapping, wildcard_ip="9.9.9.9"):
        self.mapping = mapping
        self.wildcard_ip = wildcard_ip

    def query(self, name, rtype):
        if (name, rtype) in self.mapping:
            return list(self.mapping[(name, rtype)])
        if rtype == "A" and name.endswith(".example.com"):
            return [self.wildcard_ip]
        return []


class TestRecords(unittest.TestCase):
    def test_get_records(self):
        fr = FakeResolver({("example.com", "A"): ["1.2.3.4"],
                           ("example.com", "MX"): ["10 mail.example.com"]})
        recs = get_records("example.com", fr, rtypes=["A", "MX"])
        self.assertEqual(recs["a"], ["1.2.3.4"])
        self.assertEqual(recs["mx"], ["10 mail.example.com"])


class TestDnssec(unittest.TestCase):
    def test_signed(self):
        fr = FakeResolver({("example.com", "DNSKEY"): ["257 3 13 key"],
                           ("example.com", "DS"): ["12345 13 2 hash"]}, ad=True)
        d = checks.dnssec("example.com", fr)
        self.assertTrue(d["enabled"])
        self.assertTrue(d["ds_present"])
        self.assertTrue(d["authenticated_data"])

    def test_unsigned(self):
        d = checks.dnssec("example.com", FakeResolver())
        self.assertFalse(d["enabled"])


class TestWildcard(unittest.TestCase):
    def test_detected(self):
        d = detect_wildcard("example.com", WildcardResolver({}))
        self.assertTrue(d["wildcard"])
        self.assertEqual(d["wildcard_ips"], ["9.9.9.9"])

    def test_absent(self):
        self.assertFalse(detect_wildcard("example.com", FakeResolver())["wildcard"])


class TestEnumerate(unittest.TestCase):
    def test_finds_real_and_filters_wildcard(self):
        mapping = {
            ("www.example.com", "A"): ["1.1.1.1"],
            ("mail.example.com", "A"): ["2.2.2.2"],
            ("ghost.example.com", "A"): ["9.9.9.9"],  # equals wildcard -> filtered
        }
        res = enumerate_subdomains(
            "example.com", ["www", "mail", "ghost", "nope", ""],
            WildcardResolver(mapping), threads=4,
        )
        self.assertTrue(res["wildcard"])
        self.assertEqual(res["tested"], 4)
        names = {f["name"] for f in res["found"]}
        self.assertIn("www.example.com", names)
        self.assertIn("mail.example.com", names)
        self.assertNotIn("ghost.example.com", names)
        self.assertNotIn("nope.example.com", names)


class TestEmailSecurityAggregation(unittest.TestCase):
    def test_aggregates(self):
        mapping = {
            ("example.com", "TXT"): ["v=spf1 -all"],
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:a@e.com"],
            ("google._domainkey.example.com", "TXT"): ["v=DKIM1; p=abc"],
        }
        es = email_security("example.com", FakeResolver(mapping),
                            selectors=["google", "default"])
        self.assertTrue(es["spf"]["present"])
        self.assertEqual(es["dmarc"]["policy"], "reject")
        self.assertTrue(any(d["present"] for d in es["dkim"]))


if __name__ == "__main__":
    unittest.main()
