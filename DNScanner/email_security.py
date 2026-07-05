"""Pure parsers/evaluators for email-authentication DNS records.

No DNS here — callers pass the TXT strings they already fetched, which keeps
this logic fully unit-testable offline.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

__all__ = [
    "DKIM_SELECTORS",
    "parse_spf",
    "parse_dmarc",
    "parse_dkim",
    "evaluate_email_security",
]

# Common DKIM selectors worth probing when the real selector is unknown.
DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2",
    "k1", "mail", "dkim", "s1", "s2",
]


def _find(txt_values: List[str], prefix: str) -> Optional[str]:
    for value in txt_values or []:
        v = str(value).strip().strip('"')
        if v.lower().startswith(prefix.lower()):
            return v
    return None


def parse_spf(txt_values: List[str]) -> Dict[str, Any]:
    """Parse the SPF (v=spf1) record out of a domain's TXT values."""
    record = _find(txt_values, "v=spf1")
    if not record:
        return {"present": False, "record": None, "all": None,
                "includes": [], "lookups": 0, "issues": []}

    tokens = record.split()
    includes = [t.split(":", 1)[1] for t in tokens
                if t.lower().startswith("include:") and ":" in t]

    all_token = None
    for t in tokens:
        if t.lstrip("+-~?") == "all":
            all_token = t

    # SPF allows at most 10 DNS-querying mechanisms.
    lookups = 0
    for t in tokens:
        tl = t.lower()
        if (tl.startswith(("include:", "exists:", "redirect="))
                or tl in ("a", "mx", "ptr")
                or tl.startswith(("a:", "mx:", "ptr:"))):
            lookups += 1

    issues: List[str] = []
    if all_token in ("+all", "?all"):
        issues.append("SPF 'all' qualifier is permissive (%s)" % all_token)
    elif all_token is None:
        issues.append("SPF record has no 'all' mechanism")
    if lookups > 10:
        issues.append("SPF exceeds 10 DNS lookups (%d) — validation may fail" % lookups)

    return {"present": True, "record": record, "all": all_token,
            "includes": includes, "lookups": lookups, "issues": issues}


def parse_dmarc(txt_values: List[str]) -> Dict[str, Any]:
    """Parse the DMARC (v=DMARC1) record from the _dmarc TXT values."""
    record = _find(txt_values, "v=DMARC1")
    if not record:
        return {"present": False, "record": None, "policy": None,
                "subdomain_policy": None, "pct": None, "rua": None, "issues": []}

    tags: Dict[str, str] = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()

    policy = (tags.get("p") or "").lower() or None
    pct = tags.get("pct")
    issues: List[str] = []
    if policy is None:
        issues.append("DMARC record missing required p= policy")
    elif policy == "none":
        issues.append("DMARC policy is 'none' (monitoring only, not enforced)")
    if "rua" not in tags:
        issues.append("DMARC has no aggregate-report address (rua)")
    try:
        pct_val = int(pct) if pct is not None else 100
    except ValueError:
        pct_val = 100
    if pct is not None and pct_val < 100:
        issues.append("DMARC pct=%s applies the policy to only part of the mail" % pct)

    if policy == "reject" and pct_val >= 100:
        strength = "strong"
    elif policy in ("reject", "quarantine"):
        strength = "moderate"
    elif policy == "none":
        strength = "weak"
    else:
        strength = "none"

    return {"present": True, "record": record, "policy": policy,
            "subdomain_policy": tags.get("sp"), "pct": pct,
            "rua": tags.get("rua"), "ruf": tags.get("ruf"),
            "aspf": tags.get("aspf", "r"), "adkim": tags.get("adkim", "r"),
            "fo": tags.get("fo"), "strength": strength, "issues": issues}


def parse_dkim(selector: str, txt_values: List[str]) -> Dict[str, Any]:
    """Detect a DKIM key at ``selector._domainkey`` and parse its key length."""
    record = _find(txt_values, "v=DKIM1")
    if not record:                       # some publish without an explicit v=
        record = _find(txt_values, "k=") or _find(txt_values, "p=")
    out: Dict[str, Any] = {"selector": selector, "present": record is not None,
                           "record": record, "key_type": None, "key_bits": None,
                           "revoked": False}
    if record:
        tags = _dkim_tags(record)
        out["key_type"] = (tags.get("k") or "rsa").lower()
        p = tags.get("p")
        if p is not None and p.strip() == "":
            out["revoked"] = True                       # empty p= means revoked
        elif p and out["key_type"] == "rsa":
            out["key_bits"] = _rsa_bits_from_spki(_b64decode(p))
    return out


def _dkim_tags(record: str) -> Dict[str, str]:
    tags: Dict[str, str] = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def _b64decode(data: str) -> bytes:
    import base64
    s = "".join(str(data).split())
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s)
    except Exception:
        return b""


def _read_len(b: bytes, i: int):
    n = b[i]
    i += 1
    if n < 0x80:
        return n, i
    cnt = n & 0x7F
    return int.from_bytes(b[i:i + cnt], "big"), i + cnt


def _rsa_bits_from_spki(der: bytes) -> Optional[int]:
    """Best-effort RSA modulus bit length from a DER SubjectPublicKeyInfo.

    Returns ``None`` when the structure can't be parsed confidently (we never
    fabricate a number).
    """
    try:
        i = 0
        if der[i] != 0x30:
            return None
        _, i = _read_len(der, i + 1)               # outer SEQUENCE body
        if der[i] != 0x30:
            return None
        alg_len, j = _read_len(der, i + 1)         # AlgorithmIdentifier SEQUENCE
        i = j + alg_len                            # skip it
        if der[i] != 0x03:                         # BIT STRING
            return None
        _, i = _read_len(der, i + 1)
        i += 1                                     # skip the unused-bits octet
        if der[i] != 0x30:                         # RSAPublicKey SEQUENCE
            return None
        _, i = _read_len(der, i + 1)
        if der[i] != 0x02:                         # INTEGER modulus
            return None
        mod_len, i = _read_len(der, i + 1)
        modulus = der[i:i + mod_len].lstrip(b"\x00")
        return (len(modulus) * 8) or None
    except Exception:
        return None


_SPF_REF = "RFC 7208"
_DMARC_REF = "RFC 7489"
_DKIM_REF = "RFC 6376"


def evaluate_email_security(spf: Dict[str, Any], dmarc: Dict[str, Any],
                            dkim: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Turn parsed SPF/DMARC/DKIM into finding dicts (with remediation + reference)."""
    findings: List[Dict[str, str]] = []

    if not spf.get("present"):
        findings.append({"id": "spf-missing", "title": "No SPF record", "severity": "medium",
                         "detail": "No v=spf1 TXT record; sender spoofing is easier.",
                         "remediation": "Publish an SPF record ending in -all (hardfail).",
                         "reference": _SPF_REF})
    else:
        for issue in spf.get("issues", []):
            findings.append({"id": "spf-weak", "title": "SPF weakness", "severity": "low",
                             "detail": issue,
                             "remediation": "Use -all and remove +all/?all.",
                             "reference": _SPF_REF})
        if spf.get("exceeds_limit"):
            findings.append({"id": "spf-lookup-limit", "title": "SPF exceeds DNS-lookup limit",
                             "severity": "medium",
                             "detail": "SPF needs %s DNS lookups (limit 10) and %s void (limit 2); "
                                       "evaluators return PermError." % (spf.get("dns_lookups"),
                                                                         spf.get("void_lookups")),
                             "remediation": "Flatten includes / reduce mechanisms to <=10 DNS lookups.",
                             "reference": "RFC 7208 §4.6.4"})

    if not dmarc.get("present"):
        findings.append({"id": "dmarc-missing", "title": "No DMARC record", "severity": "medium",
                         "detail": "No _dmarc TXT record; recipients have no failure policy.",
                         "remediation": "Publish _dmarc starting at p=none with rua, then move to reject.",
                         "reference": _DMARC_REF})
    else:
        if dmarc.get("strength") == "weak":
            findings.append({"id": "dmarc-policy-none", "title": "DMARC policy is 'none'",
                             "severity": "medium",
                             "detail": "p=none only monitors; spoofed mail is not quarantined or rejected.",
                             "remediation": "Move to p=quarantine, then p=reject once reports are clean.",
                             "reference": _DMARC_REF})
        for issue in dmarc.get("issues", []):
            if "none" in issue:                       # covered by dmarc-policy-none above
                continue
            findings.append({"id": "dmarc-weak", "title": "DMARC weakness", "severity": "low",
                             "detail": issue,
                             "remediation": "Add rua and enforce pct=100.",
                             "reference": _DMARC_REF})

    if not any(d.get("present") for d in (dkim or [])):
        findings.append({"id": "dkim-none", "title": "No DKIM selector found", "severity": "low",
                         "detail": "None of the common DKIM selectors resolved "
                                   "(a custom selector may still exist).",
                         "remediation": "Publish a DKIM key and sign outbound mail.",
                         "reference": _DKIM_REF})
    for d in (dkim or []):
        if d.get("revoked"):
            findings.append({"id": "dkim-revoked", "title": "DKIM key revoked", "severity": "low",
                             "detail": "Selector %s has an empty p= (revoked key)." % d.get("selector"),
                             "remediation": "Remove or replace the revoked DKIM selector.",
                             "reference": _DKIM_REF})
        bits = d.get("key_bits")
        if isinstance(bits, int) and bits < 1024:
            findings.append({"id": "dkim-weak-key", "title": "DKIM key shorter than 1024 bits",
                             "severity": "medium",
                             "detail": "Selector %s uses a %d-bit RSA key." % (d.get("selector"), bits),
                             "remediation": "Rotate to a >=2048-bit DKIM key.",
                             "reference": _DKIM_REF})
    return findings
