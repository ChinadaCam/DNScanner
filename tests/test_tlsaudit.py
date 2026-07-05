import unittest

from DNScanner.tlsaudit import evaluate_tls_audit


class TestEvaluate(unittest.TestCase):
    def test_deprecated_protocol(self):
        a = {"reachable": True,
             "protocols": {"SSLv3": None, "TLS1.0": True, "TLS1.1": False, "TLS1.2": True, "TLS1.3": True},
             "negotiated": {"version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "forward_secret": True}}
        ids = {f["id"] for f in evaluate_tls_audit(a)}
        self.assertIn("tls-deprecated-protocol", ids)
        self.assertNotIn("tls-modern", ids)   # deprecated present blocks the positive

    def test_no_forward_secrecy(self):
        a = {"reachable": True, "protocols": {"TLS1.2": True, "TLS1.3": False},
             "negotiated": {"version": "TLSv1.2", "cipher": "AES256-SHA", "forward_secret": False}}
        self.assertIn("tls-no-forward-secrecy", {f["id"] for f in evaluate_tls_audit(a)})

    def test_modern_only(self):
        a = {"reachable": True,
             "protocols": {"SSLv3": None, "TLS1.0": False, "TLS1.1": False, "TLS1.2": True, "TLS1.3": True},
             "negotiated": {"version": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256", "forward_secret": True}}
        ids = {f["id"] for f in evaluate_tls_audit(a)}
        self.assertIn("tls-modern", ids)
        self.assertNotIn("tls-deprecated-protocol", ids)

    def test_unreachable_no_findings(self):
        self.assertEqual(evaluate_tls_audit({"reachable": False}), [])

    def test_findings_have_reference(self):
        a = {"reachable": True, "protocols": {"TLS1.0": True}, "negotiated": {}}
        for f in evaluate_tls_audit(a):
            if f["severity"] != "info":
                self.assertTrue(f["remediation"] and f["reference"])


if __name__ == "__main__":
    unittest.main()
