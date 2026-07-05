import base64
import unittest

from DNScanner.checks import spf_lookup_count
from DNScanner.email_security import (
    _rsa_bits_from_spki,
    evaluate_email_security,
    parse_dkim,
    parse_dmarc,
    parse_spf,
)


# --- helpers to build a DER SubjectPublicKeyInfo with a known modulus size ---
def _der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag, body):
    return bytes([tag]) + _der_len(len(body)) + body


def build_spki(mod_sig_bytes):
    modulus = b"\x00" + b"\xff" * mod_sig_bytes        # leading 0x00 = positive
    exp = b"\x01\x00\x01"
    rsapub = _tlv(0x30, _tlv(0x02, modulus) + _tlv(0x02, exp))
    bitstring = _tlv(0x03, b"\x00" + rsapub)
    alg = _tlv(0x30, bytes.fromhex("06092a864886f70d010101") + bytes.fromhex("0500"))
    return _tlv(0x30, alg + bitstring)


class FakeResolver:
    def __init__(self, txt_map):
        self.txt = txt_map

    def query(self, name, rtype):
        return list(self.txt.get(name, [])) if rtype == "TXT" else []


class TestDmarcStrength(unittest.TestCase):
    def test_strength_levels(self):
        self.assertEqual(parse_dmarc(["v=DMARC1; p=reject; rua=mailto:a@e.com"])["strength"], "strong")
        self.assertEqual(parse_dmarc(["v=DMARC1; p=quarantine; rua=mailto:a@e.com"])["strength"], "moderate")
        self.assertEqual(parse_dmarc(["v=DMARC1; p=none; rua=mailto:a@e.com"])["strength"], "weak")

    def test_pct_downgrades(self):
        r = parse_dmarc(["v=DMARC1; p=reject; pct=50; rua=mailto:a@e.com"])
        self.assertEqual(r["strength"], "moderate")
        self.assertTrue(any("pct" in i for i in r["issues"]))


class TestRsaBits(unittest.TestCase):
    def test_known_sizes(self):
        self.assertEqual(_rsa_bits_from_spki(build_spki(128)), 1024)
        self.assertEqual(_rsa_bits_from_spki(build_spki(256)), 2048)

    def test_garbage_is_none(self):
        self.assertIsNone(_rsa_bits_from_spki(b"\x00\x01\x02"))


class TestDkimKey(unittest.TestCase):
    def test_revoked(self):
        d = parse_dkim("s", ["v=DKIM1; k=rsa; p="])
        self.assertTrue(d["present"])
        self.assertTrue(d["revoked"])

    def test_key_bits_and_weak_finding(self):
        rec = "v=DKIM1; k=rsa; p=" + base64.b64encode(build_spki(128)).decode()
        d = parse_dkim("s", [rec])
        self.assertEqual(d["key_bits"], 1024)
        ids = {f["id"] for f in evaluate_email_security(
            parse_spf(["v=spf1 -all"]),
            parse_dmarc(["v=DMARC1; p=reject; rua=mailto:a@e.com"]), [d])}
        self.assertNotIn("dkim-weak-key", ids)  # 1024 is the threshold, not below
        d512 = parse_dkim("s", ["v=DKIM1; k=rsa; p=" + base64.b64encode(build_spki(64)).decode()])
        self.assertEqual(d512["key_bits"], 512)
        ids2 = {f["id"] for f in evaluate_email_security(
            parse_spf(["v=spf1 -all"]),
            parse_dmarc(["v=DMARC1; p=reject; rua=mailto:a@e.com"]), [d512])}
        self.assertIn("dkim-weak-key", ids2)


class TestSpfRecursive(unittest.TestCase):
    def test_counts_recursively(self):
        txt = {
            "e.com": ["v=spf1 include:a.com include:b.com -all"],
            "a.com": ["v=spf1 include:c.com a mx -all"],
            "b.com": ["v=spf1 ip4:1.2.3.4 -all"],
            "c.com": ["v=spf1 a mx exists:x.d.com -all"],
        }
        r = spf_lookup_count("e.com", FakeResolver(txt))
        # include:a, include:b, include:c, a, mx (in a), a, mx, exists (in c) = 8
        self.assertEqual(r["dns_lookups"], 8)
        self.assertFalse(r["exceeds_limit"])

    def test_void_lookup(self):
        r = spf_lookup_count("e.com", FakeResolver({"e.com": ["v=spf1 include:nope.com -all"]}))
        self.assertEqual(r["void_lookups"], 1)

    def test_exceeds_limit(self):
        txt = {"e.com": ["v=spf1 " + " ".join("include:i%d.com" % i for i in range(11)) + " -all"]}
        for i in range(11):
            txt["i%d.com" % i] = ["v=spf1 -all"]
        r = spf_lookup_count("e.com", FakeResolver(txt))
        self.assertEqual(r["dns_lookups"], 11)
        self.assertTrue(r["exceeds_limit"])


if __name__ == "__main__":
    unittest.main()
