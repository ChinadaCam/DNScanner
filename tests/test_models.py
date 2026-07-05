import json
import unittest

from DNScanner.models import ScanResult, Severity


class TestModels(unittest.TestCase):
    def test_json_roundtrip(self):
        r = ScanResult(domain="example.com")
        r.resolved_ips = {"a": ["1.2.3.4"]}
        r.add_finding("x", "Test", Severity.HIGH, "detail")
        data = r.to_dict()
        self.assertEqual(data["domain"], "example.com")
        self.assertEqual(data["schema_version"], "1.0")
        self.assertEqual(data["findings"][0]["severity"], "high")
        parsed = json.loads(r.to_json())
        self.assertEqual(parsed["findings"][0]["title"], "Test")
        self.assertEqual(parsed["resolved_ips"]["a"], ["1.2.3.4"])

    def test_highest_severity(self):
        r = ScanResult(domain="x")
        self.assertEqual(r.highest_severity, "info")
        r.add_finding("a", "A", "low")
        r.add_finding("b", "B", "high")
        r.add_finding("c", "C", "medium")
        self.assertEqual(r.highest_severity, "high")

    def test_add_findings_bulk(self):
        r = ScanResult(domain="x")
        r.add_findings([{"id": "i", "title": "t", "severity": "medium", "detail": "d"}])
        self.assertEqual(len(r.findings), 1)
        self.assertEqual(r.findings[0].severity, "medium")


if __name__ == "__main__":
    unittest.main()
