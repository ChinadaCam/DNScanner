import unittest
from types import SimpleNamespace

from DNScanner.posture import derive_findings


def R(**kw):
    base = dict(records={}, email_security={}, tls={}, http={}, dnssec={},
                reachability={}, zone_transfer={}, subdomains={}, takeover=[], checks_run=[])
    base.update(kw)
    return SimpleNamespace(**base)


class TestPosture(unittest.TestCase):
    def test_positive_confirmations(self):
        r = R(dnssec={"enabled": True, "authenticated_data": True},
              records={"caa_parsed": {"present": True, "allows_any_ca": False}},
              email_security={"spf": {"present": True, "all": "-all"},
                              "dmarc": {"strength": "strong", "policy": "reject"},
                              "dkim": [{"present": True}],
                              "mta_sts": {"present": True, "mode": "enforce"},
                              "dane": {"present": True, "dnssec_protected": True}},
              tls={"reachable": True, "valid": True, "days_to_expiry": 90, "issuer": "X"},
              http={"reachable": True, "present": {"HSTS": "y"},
                    "security_txt": {"present": True, "expired": False},
                    "csp": {"present": True, "weaknesses": []}},
              reachability={"reachable": True},
              zone_transfer={"tested": True, "vulnerable_servers": []},
              subdomains={"found": [{"name": "a"}], "wildcard": True},
              takeover=[], checks_run=["takeover"])
        ids = {f["id"] for f in derive_findings(r)}
        for expected in ["dnssec-enabled", "caa-restricts", "spf-hardfail", "dmarc-enforced",
                         "dkim-present", "mta-sts-enforce", "dane-active", "tls-valid",
                         "hsts-present", "security-txt-present", "csp-strong", "reachable",
                         "axfr-refused", "subdomains-found", "wildcard-dns", "takeover-none"]:
            self.assertIn(expected, ids)
        self.assertTrue(all(f["severity"] == "info" for f in derive_findings(r)))

    def test_empty_result_no_positives(self):
        self.assertEqual(derive_findings(R()), [])


if __name__ == "__main__":
    unittest.main()
