"""Modern email-security records: MTA-STS, TLS-RPT, BIMI, DANE/TLSA.

Pure parsers + evaluator (no DNS/IO here). DANE/TLSA is reported as *protective*
only when the TLSA lookup was DNSSEC-authenticated (RFC 7672); otherwise its
presence is noted with an explicit "not protected without DNSSEC" caveat, per the
DNSSEC-dependency hard constraint.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

_MTA_STS_REF = "RFC 8461"
_TLSRPT_REF = "RFC 8460"
_DANE_REF = "RFC 7672"


def _find(txt_values: List[str], prefix: str) -> Optional[str]:
    for v in txt_values or []:
        s = str(v).strip().strip('"')
        if s.lower().startswith(prefix.lower()):
            return s
    return None


def _tags(record: Optional[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for part in (record or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip()
    return out


def parse_mta_sts_txt(txt_values: List[str]) -> Dict[str, Any]:
    rec = _find(txt_values, "v=STSv1")
    if not rec:
        return {"present": False, "id": None}
    return {"present": True, "id": _tags(rec).get("id"), "record": rec}


def parse_mta_sts_policy(text: Optional[str]) -> Dict[str, Any]:
    """Parse the policy file fetched from mta-sts.<domain>/.well-known/mta-sts.txt."""
    if not text:
        return {"fetched": False, "mode": None, "mx": [], "max_age": None, "version": None}
    mode = version = None
    mx: List[str] = []
    max_age: Optional[int] = None
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key, value = key.strip().lower(), value.strip()
        if key == "mode":
            mode = value.lower()
        elif key == "mx":
            mx.append(value)
        elif key == "max_age":
            try:
                max_age = int(value)
            except ValueError:
                pass
        elif key == "version":
            version = value
    return {"fetched": True, "mode": mode, "mx": mx, "max_age": max_age, "version": version}


def parse_tls_rpt(txt_values: List[str]) -> Dict[str, Any]:
    rec = _find(txt_values, "v=TLSRPTv1")
    return {"present": rec is not None,
            "rua": _tags(rec).get("rua") if rec else None, "record": rec}


def parse_bimi(txt_values: List[str]) -> Dict[str, Any]:
    rec = _find(txt_values, "v=BIMI1")
    t = _tags(rec) if rec else {}
    return {"present": rec is not None, "location": t.get("l"),
            "authority": t.get("a"), "record": rec}


def parse_tlsa(tlsa_strings: List[str], authenticated: bool) -> Dict[str, Any]:
    records: List[Dict[str, Any]] = []
    for s in tlsa_strings or []:
        parts = str(s).split()
        if len(parts) >= 4:
            data = parts[3]
            records.append({"usage": parts[0], "selector": parts[1],
                            "matching": parts[2],
                            "data": data[:32] + ("..." if len(data) > 32 else "")})
        elif s:
            records.append({"raw": str(s)})
    present = bool(records)
    return {"present": present, "records": records,
            "dnssec_protected": present and bool(authenticated),
            "note": ("TLSA present but the zone is not DNSSEC-validated; not protective"
                     if present and not authenticated else None)}


def evaluate_modern_email(modern: Dict[str, Any]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []

    mta = modern.get("mta_sts") or {}
    if not mta.get("present"):
        findings.append({"id": "mta-sts-missing", "title": "No MTA-STS policy", "severity": "low",
                         "detail": "No _mta-sts TXT record; inbound SMTP can be downgraded (STARTTLS stripping).",
                         "remediation": "Publish an MTA-STS record + enforce-mode policy at mta-sts.<domain>.",
                         "reference": _MTA_STS_REF})
    elif (mta.get("mode") or "").lower() != "enforce":
        findings.append({"id": "mta-sts-not-enforcing", "title": "MTA-STS not enforcing", "severity": "low",
                         "detail": "MTA-STS mode is '%s' (not 'enforce'); downgrades are reported but not blocked."
                                   % (mta.get("mode") or "unknown"),
                         "remediation": "Set the MTA-STS policy mode to enforce once testing is clean.",
                         "reference": _MTA_STS_REF})

    if not (modern.get("tls_rpt") or {}).get("present"):
        findings.append({"id": "tls-rpt-missing", "title": "No TLS-RPT record", "severity": "info",
                         "detail": "No _smtp._tls TXT record; you won't receive SMTP TLS failure reports.",
                         "remediation": "Publish a TLS-RPT record with a rua reporting endpoint.",
                         "reference": _TLSRPT_REF})

    dane = modern.get("dane") or {}
    if dane.get("present") and not dane.get("dnssec_protected"):
        findings.append({"id": "dane-no-dnssec", "title": "TLSA present without DNSSEC", "severity": "medium",
                         "detail": "TLSA/DANE records exist but the zone isn't DNSSEC-validated, so they "
                                   "provide no protection.",
                         "remediation": "Enable DNSSEC so TLSA records can be validated.",
                         "reference": _DANE_REF})
    return findings
