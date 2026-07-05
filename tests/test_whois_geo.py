import unittest

import DNScanner.checks as checks
from DNScanner.checks import normalize_legacy_whois, normalize_rdap, parse_ipapi
from DNScanner.engine import DNScanner


class FakeResolver:
    def __init__(self, mapping=None):
        self.mapping = mapping or {}

    def query(self, name, rtype):
        return list(self.mapping.get((name, rtype), []))

    def query_with_ad(self, name, rtype):
        return list(self.mapping.get((name, rtype), [])), False

    def reverse(self, ip):
        return []


class TestWhoisNormalize(unittest.TestCase):
    def test_rdap(self):
        data = {
            "asn": "15169", "asn_description": "GOOGLE, US", "asn_registry": "arin",
            "asn_country_code": "US", "asn_cidr": "8.8.8.0/24",
            "network": {"name": "GOOGLE", "cidr": "8.8.8.0/24", "country": "US",
                        "start_address": "8.8.8.0", "end_address": "8.8.8.255",
                        "events": [{"action": "registration", "timestamp": "2014-03-14"},
                                   {"action": "last changed", "timestamp": "2023-01-01"}]},
            "objects": {
                "AB": {"roles": ["abuse"],
                       "contact": {"name": "Abuse", "email": [{"value": "abuse@google.com"}]}},
                "RG": {"roles": ["registrant"], "contact": {"name": "Google LLC"}},
            },
        }
        w = normalize_rdap("8.8.8.8", data)
        self.assertEqual(w["asn"], "15169")
        self.assertEqual(w["network_name"], "GOOGLE")
        self.assertEqual(w["network_range"], "8.8.8.0 - 8.8.8.255")
        self.assertEqual(w["abuse_email"], "abuse@google.com")
        self.assertEqual(w["registrant"], "Google LLC")
        self.assertEqual(w["created"], "2014-03-14")
        self.assertEqual(w["updated"], "2023-01-01")

    def test_legacy(self):
        data = {"asn": "15169", "asn_description": "GOOGLE", "asn_registry": "arin",
                "asn_country_code": "US", "asn_cidr": "8.8.8.0/24",
                "nets": [{"name": "LVLT", "cidr": "8.0.0.0/9", "country": "US",
                          "range": "8.0.0.0 - 8.127.255.255", "emails": ["abuse@x.com"],
                          "description": "Google", "created": "2000", "updated": "2012"}]}
        w = normalize_legacy_whois("8.8.8.8", data)
        self.assertEqual(w["network_name"], "LVLT")
        self.assertEqual(w["abuse_email"], "abuse@x.com")
        self.assertEqual(w["registrant"], "Google")
        self.assertEqual(w["network_range"], "8.0.0.0 - 8.127.255.255")


class TestIpapi(unittest.TestCase):
    def test_success(self):
        g = parse_ipapi("8.8.8.8", {"status": "success", "country": "United States",
                                    "countryCode": "US", "regionName": "California",
                                    "city": "Mountain View", "lat": 37.4, "lon": -122.0,
                                    "isp": "Google LLC", "org": "Google",
                                    "as": "AS15169 Google LLC"})
        self.assertEqual(g["country"], "United States")
        self.assertEqual(g["city"], "Mountain View")
        self.assertEqual(g["asn"], "AS15169 Google LLC")
        self.assertEqual(g["source"], "ip-api.com")

    def test_failure(self):
        g = parse_ipapi("10.0.0.1", {"status": "fail", "message": "private range"})
        self.assertEqual(g["error"], "private range")

    def test_bad_response(self):
        self.assertIn("error", parse_ipapi("x", None))


class TestScanIntegration(unittest.TestCase):
    def test_scan_includes_geo_and_whois(self):
        orig_geo, orig_whois = checks.geolocation, checks.whois
        checks.geolocation = lambda ip, timeout=6.0: {"ip": ip, "country": "US", "city": "MV"}
        checks.whois = lambda ip, timeout=5.0: {"ip": ip, "asn": "15169", "network_name": "GOOGLE"}
        try:
            s = DNScanner("example.com",
                          resolver=FakeResolver({("example.com", "A"): ["8.8.8.8"]}))
            s._ip = "8.8.8.8"  # avoid a real gethostbyname() in the whois path
            r = s.scan(checks=["records", "geo", "whois"])
            self.assertEqual(r.geolocation[0]["country"], "US")
            self.assertEqual(r.whois["network_name"], "GOOGLE")
            self.assertEqual(r.to_dict()["geolocation"][0]["city"], "MV")
        finally:
            checks.geolocation, checks.whois = orig_geo, orig_whois


if __name__ == "__main__":
    unittest.main()
