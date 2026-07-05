"""Pure parsers + sanity checks for CAA and SOA records.

CAA strings arrive from ``resolver.query(..., 'CAA')`` as ``'<flags> <tag> "<value>"'``.
SOA arrives structured from ``Resolver.soa()``. Evaluators return finding dicts
(id/title/severity/detail/remediation/reference). No DNS/IO here.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

_CAA_RE = re.compile(r'^\s*(\d+)\s+(\w+)\s+"?(.*?)"?\s*$')

# RFC 1912 §2.2 recommends an SOA expire of 2–4 weeks.
SOA_EXPIRE_MIN = 1209600
SOA_EXPIRE_MAX = 2419200


def parse_caa(caa_strings: List[str]) -> Dict[str, Any]:
    issue: List[str] = []
    issuewild: List[str] = []
    iodef: List[str] = []
    other: List[str] = []
    for s in caa_strings or []:
        m = _CAA_RE.match(str(s))
        if not m:
            other.append(str(s))
            continue
        flags, tag, value = m.group(1), m.group(2).lower(), m.group(3)
        if tag == "issue":
            issue.append(value)
        elif tag == "issuewild":
            issuewild.append(value)
        elif tag == "iodef":
            iodef.append(value)
        else:
            other.append("%s %s %s" % (flags, tag, value))
    present = bool(issue or issuewild or iodef or other)
    return {"present": present, "issue": issue, "issuewild": issuewild,
            "iodef": iodef, "other": other,
            "allows_any_ca": not (issue or issuewild)}


def evaluate_caa(parsed: Dict[str, Any]) -> List[Dict[str, str]]:
    if not parsed.get("present"):
        return [{"id": "caa-missing", "title": "No CAA record", "severity": "low",
                 "detail": "No CAA record: any public CA may issue certificates for this domain.",
                 "remediation": "Publish a CAA record restricting issuance to your CA(s).",
                 "reference": "RFC 8659 (CAA); CA/Browser Forum Ballot 187"}]
    findings: List[Dict[str, str]] = []
    if not parsed.get("iodef"):
        findings.append({"id": "caa-no-iodef", "title": "CAA has no iodef contact",
                         "severity": "info",
                         "detail": "No iodef tag; CAs cannot report policy-violating issuance attempts.",
                         "remediation": "Add an iodef mailto:/https: reporting endpoint to the CAA RRset.",
                         "reference": "RFC 8659 §4.4"})
    return findings


def parse_soa(soa: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not soa:
        return {"present": False, "issues": []}
    out = dict(soa)
    out["present"] = True
    issues: List[str] = []
    expire = soa.get("expire")
    if isinstance(expire, int) and not (SOA_EXPIRE_MIN <= expire <= SOA_EXPIRE_MAX):
        issues.append("expire=%ds is outside RFC 1912's recommended 2-4 weeks "
                      "(1209600-2419200s)" % expire)
    out["issues"] = issues
    return out


def evaluate_soa(parsed: Dict[str, Any]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    for issue in parsed.get("issues", []):
        findings.append({"id": "soa-expire-range", "title": "SOA expire out of range",
                         "severity": "low", "detail": issue,
                         "remediation": "Set SOA expire between 1209600 and 2419200 seconds (2-4 weeks).",
                         "reference": "RFC 1912 §2.2"})
    return findings
