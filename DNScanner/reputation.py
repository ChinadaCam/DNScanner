"""Domain reputation lookups (read-only, optional).

- **Spamhaus DBL** via DNSBL — no API key needed (a DNS query).
- **VirusTotal** and **Google Safe Browsing** — require API keys (read env-first via
  :mod:`config`); when a key is absent the provider returns ``status: "skipped"`` and
  never blocks or crashes the scan.

Parsers are pure (unit-testable); network helpers use the rate-limited :mod:`netutil`.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import netutil


# --------------------------------------------------------------------------- #
# Spamhaus DBL (DNSBL — no key)
# --------------------------------------------------------------------------- #
def parse_dbl(records: List[str]) -> Dict[str, Any]:
    """Interpret the A records returned by a DBL query.

    127.0.1.2–127.0.1.99 indicate a listing; 127.255.255.x indicates the query was
    refused (e.g. from a public/open resolver), which is NOT a listing.
    """
    listed = False
    codes: List[str] = []
    blocked = False
    for r in records or []:
        codes.append(r)
        if r.startswith("127.255.255."):
            blocked = True
        elif r.startswith("127.0.1."):
            try:
                if 2 <= int(r.rsplit(".", 1)[1]) <= 99:
                    listed = True
            except ValueError:
                pass
    return {"listed": listed, "codes": codes, "blocked_resolver": blocked}


def spamhaus_dbl(domain: str, resolver) -> Dict[str, Any]:
    try:
        records = resolver.query("%s.dbl.spamhaus.org" % domain, "A")
    except Exception as exc:
        return {"provider": "spamhaus-dbl", "status": "error", "listed": False,
                "codes": [], "error": str(exc)}
    parsed = parse_dbl(records)
    parsed.update({"provider": "spamhaus-dbl", "status": "ok"})
    return parsed


# --------------------------------------------------------------------------- #
# VirusTotal (key required)
# --------------------------------------------------------------------------- #
def parse_vt(data: Any) -> Dict[str, Any]:
    attrs = ((data or {}).get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    return {"malicious": stats.get("malicious"), "suspicious": stats.get("suspicious"),
            "harmless": stats.get("harmless"), "undetected": stats.get("undetected"),
            "reputation": attrs.get("reputation")}


def virustotal(domain: str, config=None, timeout: float = 8.0) -> Dict[str, Any]:
    key = config.api_key("virustotal") if config else None
    if not key:
        return {"provider": "virustotal", "status": "skipped", "reason": "no api key"}
    data = netutil.get_json_or_none(
        "https://www.virustotal.com/api/v3/domains/%s" % domain,
        timeout=timeout, headers={"x-apikey": key}, min_interval=15.0)
    if data is None:
        return {"provider": "virustotal", "status": "error"}
    out = {"provider": "virustotal", "status": "ok"}
    out.update(parse_vt(data))
    return out


# --------------------------------------------------------------------------- #
# Google Safe Browsing (key required)
# --------------------------------------------------------------------------- #
def parse_sb(data: Any) -> Dict[str, Any]:
    matches = (data or {}).get("matches") or []
    types = sorted({m.get("threatType") for m in matches if m.get("threatType")})
    return {"listed": bool(matches), "matches": types, "match_count": len(matches)}


def safe_browsing(domain: str, config=None, timeout: float = 8.0) -> Dict[str, Any]:
    key = config.api_key("safebrowsing") if config else None
    if not key:
        return {"provider": "safebrowsing", "status": "skipped", "reason": "no api key"}
    try:
        import requests  # lazy
        body = {
            "client": {"clientId": "dnscanner", "clientVersion": "0.3"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": "http://%s/" % domain}, {"url": "https://%s/" % domain}],
            },
        }
        resp = requests.post("https://safebrowsing.googleapis.com/v4/threatMatches:find",
                             params={"key": key}, json=body, timeout=timeout,
                             headers={"User-Agent": netutil.DEFAULT_UA})
        data = resp.json()
    except Exception as exc:
        return {"provider": "safebrowsing", "status": "error", "error": str(exc)}
    out = {"provider": "safebrowsing", "status": "ok"}
    out.update(parse_sb(data))
    return out


# --------------------------------------------------------------------------- #
# Orchestrator + evaluation
# --------------------------------------------------------------------------- #
def reputation(domain: str, resolver, config=None, timeout: float = 8.0) -> Dict[str, Any]:
    return {"spamhaus": spamhaus_dbl(domain, resolver),
            "virustotal": virustotal(domain, config, timeout),
            "safebrowsing": safe_browsing(domain, config, timeout)}


def evaluate_reputation(rep: Dict[str, Any]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []

    sh = rep.get("spamhaus") or {}
    if sh.get("listed"):
        findings.append({"id": "reputation-spamhaus", "title": "Domain listed on Spamhaus DBL",
                         "severity": "high",
                         "detail": "Listed on the Spamhaus Domain Block List (codes: %s)."
                                   % ", ".join(sh.get("codes", [])),
                         "remediation": "Investigate the listing and request delisting at spamhaus.org.",
                         "reference": "Spamhaus DBL"})

    vt = rep.get("virustotal") or {}
    if vt.get("status") == "ok" and (vt.get("malicious") or 0) > 0:
        findings.append({"id": "reputation-virustotal", "title": "Flagged malicious on VirusTotal",
                         "severity": "high",
                         "detail": "%s VirusTotal engine(s) flagged this domain as malicious."
                                   % vt.get("malicious"),
                         "remediation": "Investigate the detections; request re-analysis once remediated.",
                         "reference": "VirusTotal"})

    sb = rep.get("safebrowsing") or {}
    if sb.get("status") == "ok" and sb.get("listed"):
        findings.append({"id": "reputation-safebrowsing", "title": "Listed by Google Safe Browsing",
                         "severity": "high",
                         "detail": "Safe Browsing threat types: %s." % ", ".join(sb.get("matches", [])),
                         "remediation": "Remediate and request review in Google Search Console.",
                         "reference": "Google Safe Browsing"})

    if not findings and sh.get("status") == "ok":
        findings.append({"id": "reputation-clean", "title": "No reputation hits", "severity": "info",
                         "detail": "Not listed on Spamhaus DBL / VirusTotal / Safe Browsing (as checked).",
                         "remediation": "", "reference": "Spamhaus DBL / VirusTotal / Google Safe Browsing"})
    return findings
