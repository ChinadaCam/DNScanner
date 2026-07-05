import unittest

from DNScanner.engine import DNScanner


class FakeResolver:
    def __init__(self, mapping=None, ad=False):
        self.mapping = mapping or {}
        self.ad = ad

    def query(self, name, rtype):
        return list(self.mapping.get((name, rtype), []))

    def query_with_ad(self, name, rtype):
        return list(self.mapping.get((name, rtype), [])), self.ad

    def reverse(self, ip):
        return list(self.mapping.get((ip, "PTR"), []))


class TestScan(unittest.TestCase):
    def test_offline_scan_aggregates_findings(self):
        mapping = {
            ("example.com", "A"): ["1.2.3.4"],
            ("example.com", "NS"): ["ns1.example.com"],
            # no TXT/SPF, no DMARC, no DNSSEC -> findings expected
        }
        scanner = DNScanner("example.com", resolver=FakeResolver(mapping))
        result = scanner.scan(checks=["records", "email", "dnssec"])

        self.assertEqual(result.domain, "example.com")
        self.assertEqual(result.resolved_ips["a"], ["1.2.3.4"])

        data = result.to_dict()
        self.assertEqual(data["schema_version"], "1.0")
        ids = {f["id"] for f in data["findings"]}
        self.assertIn("spf-missing", ids)
        self.assertIn("dmarc-missing", ids)
        self.assertIn("dnssec-missing", ids)
        self.assertIn("caa-missing", ids)

    def test_normalizes_dirty_input(self):
        scanner = DNScanner("HTTPS://Example.com:443/path")
        self.assertEqual(scanner.domain, "example.com")

    def test_json_serializable(self):
        scanner = DNScanner("example.com", resolver=FakeResolver())
        result = scanner.scan(checks=["dnssec"])  # minimal, no network
        # must not raise
        self.assertIn('"domain"', result.to_json())


if __name__ == "__main__":
    unittest.main()
