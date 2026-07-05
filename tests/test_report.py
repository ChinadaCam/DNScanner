import os
import tempfile
import unittest

from DNScanner.report import ReportError, render_html, render_text, write_report

SAMPLE = {
    "domain": "exa<mple>.com", "scanned_at": "2026-06-30T00:00:00Z", "duration_ms": 12,
    "resolved_ips": {"a": ["1.2.3.4"], "aaaa": []},
    "records": {"mx": ["10 mail.example.com"], "ns": ["ns1.example.com"], "caa": []},
    "email_security": {"spf": {"record": "v=spf1 -all"}, "dmarc": {"record": None},
                       "dkim": [{"selector": "google", "present": True}]},
    "dnssec": {"enabled": False, "ds_present": False, "authenticated_data": False},
    "tls": {"reachable": True, "issuer": "Let's Encrypt", "not_after": "Jan 1 2027",
            "days_to_expiry": 40, "san": ["example.com"]},
    "http": {"reachable": True, "url": "https://example.com", "status_code": 200,
             "present": {"HSTS": "x"}, "missing": ["CSP"]},
    "geolocation": [{"ip": "1.2.3.4", "city": "Townsville", "region": "R",
                     "country": "US", "isp": "ISP"}],
    "whois": {"asn": "15169", "network_name": "GOOGLE", "abuse_email": "abuse@x.com"},
    "subdomains": {"found": [{"name": "www.example.com", "ips": ["1.2.3.4"]}]},
    "findings": [{"id": "x", "title": "No DMARC record", "severity": "medium", "detail": "d"},
                 {"id": "y", "title": "Zone transfer", "severity": "high", "detail": "axfr"}],
    "errors": ["geo: timeout"],
}


class TestHtml(unittest.TestCase):
    def test_contains_and_escapes(self):
        h = render_html(SAMPLE)
        self.assertIn("DNScanner report", h)
        self.assertIn("exa&lt;mple&gt;.com", h)          # domain is HTML-escaped
        self.assertIn("No DMARC record", h)
        self.assertIn("GOOGLE", h)
        self.assertIn("Townsville", h)
        # high severity is sorted above medium
        self.assertLess(h.index("Zone transfer"), h.index("No DMARC record"))

    def test_no_findings(self):
        h = render_html({"domain": "x.com", "findings": []})
        self.assertIn("No issues to fix", h)
        self.assertIn("Issues to fix (0)", h)

    def test_issues_vs_passed_split(self):
        # SAMPLE has one high + one medium (both issues), no info -> no passed section
        h = render_html(SAMPLE)
        self.assertIn("Issues to fix (2)", h)
        self.assertNotIn("Findings (", h)             # old heading is gone
        self.assertNotIn("checks passed", h)          # nothing to pass here

    def test_passed_findings_are_separated_and_collapsed(self):
        d = {"domain": "x.com", "findings": [
            {"id": "ok", "title": "DMARC enforced", "severity": "info", "detail": "good"},
            {"id": "bad", "title": "Missing HSTS", "severity": "medium", "detail": "no hsts"}]}
        h = render_html(d)
        self.assertIn("Issues to fix (1)", h)
        self.assertIn("1 checks passed", h)
        self.assertIn("<details", h)                  # passes are collapsed
        # the info finding lives in the passed block, not the issues list
        self.assertLess(h.index("Missing HSTS"), h.index("DMARC enforced"))

    def test_same_id_findings_merge(self):
        d = {"domain": "x.com", "findings": [
            {"id": "cookie-flags", "title": "Cookie flags", "severity": "low", "detail": "SOCS missing HttpOnly"},
            {"id": "cookie-flags", "title": "Cookie flags", "severity": "low", "detail": "BUCKET missing SameSite"}]}
        h = render_html(d)
        self.assertIn("Issues to fix (1)", h)         # merged into one row
        self.assertIn("2 items", h)
        self.assertIn("SOCS missing HttpOnly", h)
        self.assertIn("BUCKET missing SameSite", h)


class TestText(unittest.TestCase):
    def test_text(self):
        t = render_text(SAMPLE)
        self.assertIn("DNScanner report", t)
        self.assertIn("No DMARC record", t)
        self.assertIn("GOOGLE", t)


class TestWrite(unittest.TestCase):
    def test_write_html(self):
        with tempfile.TemporaryDirectory() as dd:
            p = os.path.join(dd, "r.html")
            write_report(SAMPLE, p)
            self.assertTrue(os.path.exists(p))
            with open(p, encoding="utf-8") as fh:
                self.assertIn("DNScanner report", fh.read())

    def test_write_txt_by_extension(self):
        with tempfile.TemporaryDirectory() as dd:
            p = os.path.join(dd, "r.txt")
            write_report(SAMPLE, p)
            with open(p, encoding="utf-8") as fh:
                self.assertIn("DNScanner report", fh.read())

    def test_unknown_format_raises(self):
        with tempfile.TemporaryDirectory() as dd:
            with self.assertRaises(ReportError):
                write_report(SAMPLE, os.path.join(dd, "r.docx"))

    def test_pdf_without_reportlab(self):
        try:
            import reportlab  # noqa: F401
            self.skipTest("reportlab is installed")
        except Exception:
            pass
        with tempfile.TemporaryDirectory() as dd:
            with self.assertRaises(ReportError):
                write_report(SAMPLE, os.path.join(dd, "r.pdf"))


if __name__ == "__main__":
    unittest.main()
