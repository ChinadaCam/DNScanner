"""Subdomain-takeover detection.

A dangling CNAME pointing at a de-provisioned third-party service can let an
attacker claim that hostname. We match the CNAME target against known services
and (optionally) confirm with the service's characteristic error page.

``match_service`` / ``evaluate_takeover`` are pure and unit-tested; only
``check_takeover`` touches the network (DNS via the injected resolver, HTTP via a
lazily-imported ``requests``).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

__all__ = ["FINGERPRINTS", "match_service", "same_org", "evaluate_takeover", "check_takeover"]

# Curated from the community "can-i-take-over-xyz" data set (subset).
FINGERPRINTS: List[Dict[str, Any]] = [
    {"service": "GitHub Pages", "cnames": [".github.io"],
     "fingerprints": ["There isn't a GitHub Pages site here.",
                      "For root URLs (like http://example.com/) you must provide an index.html file"]},
    {"service": "AWS S3", "cnames": [".s3.amazonaws.com", ".s3-website", ".s3.dualstack"],
     "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"]},
    {"service": "Heroku", "cnames": [".herokuapp.com", ".herokudns.com"],
     "fingerprints": ["No such app", "herokucdn.com/error-pages/no-such-app.html"]},
    {"service": "Microsoft Azure", "cnames": [".azurewebsites.net", ".cloudapp.net",
                                              ".trafficmanager.net", ".blob.core.windows.net",
                                              ".azureedge.net"],
     "fingerprints": ["404 Web Site not found"]},
    {"service": "Shopify", "cnames": [".myshopify.com"],
     "fingerprints": ["Sorry, this shop is currently unavailable"]},
    {"service": "Fastly", "cnames": [".fastly.net", ".fastlylb.net"],
     "fingerprints": ["Fastly error: unknown domain"]},
    {"service": "Bitbucket", "cnames": [".bitbucket.io"],
     "fingerprints": ["Repository not found"]},
    {"service": "Surge.sh", "cnames": [".surge.sh"],
     "fingerprints": ["project not found"]},
    {"service": "Pantheon", "cnames": [".pantheonsite.io"],
     "fingerprints": ["The gods are wise, but do not know of the site which you seek.",
                      "404 error unknown site!"]},
    {"service": "Tumblr", "cnames": [".domains.tumblr.com"],
     "fingerprints": ["Whatever you were looking for doesn't currently exist at this address."]},
    {"service": "Ghost", "cnames": [".ghost.io"],
     "fingerprints": ["The thing you were looking for is no longer here, or never was"]},
    {"service": "Webflow", "cnames": [".proxy.webflow.com", ".proxy-ssl.webflow.com"],
     "fingerprints": ["The page you are looking for doesn't exist or has been moved"]},
    {"service": "Wordpress", "cnames": [".wordpress.com"],
     "fingerprints": ["Do you want to register"]},
    {"service": "Zendesk", "cnames": [".zendesk.com"],
     "fingerprints": ["Help Center Closed"]},
    {"service": "Cargo", "cnames": ["cargocollective.com"],
     "fingerprints": ["404 Not Found"]},
]

# Provenance for the fingerprint set (recorded on every advisory finding).
FINGERPRINT_SOURCE = "can-i-take-over-xyz"
FINGERPRINT_DATE = "2024-06"


def _base_domain(host: str) -> str:
    parts = (host or "").strip(".").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (host or "")


def same_org(hostname: str, cname: str) -> bool:
    """Heuristic: hostname and CNAME target share the same registrable base domain
    (e.g. app.example.com -> assets.example.com). Used by the opt-in same-org filter."""
    return bool(cname) and _base_domain(hostname) == _base_domain(cname)


def match_service(cname: str) -> Optional[Dict[str, Any]]:
    """Return the fingerprint entry whose CNAME pattern matches, else None."""
    if not cname:
        return None
    target = cname.strip().rstrip(".").lower()
    for fp in FINGERPRINTS:
        if any(pattern in target for pattern in fp["cnames"]):
            return fp
    return None


def evaluate_takeover(hostname: str, cname: Optional[str],
                      body: Optional[str] = None) -> Dict[str, Any]:
    """Decide whether ``hostname`` (with the given CNAME and optional HTTP body)
    is a takeover candidate. Pure — no I/O."""
    base = {"hostname": hostname, "cname": cname, "service": None,
            "vulnerable": False, "confidence": None, "fingerprints_matched": [],
            "requires_manual_validation": False,
            "fingerprint_source": None, "fingerprint_date": None}
    if not cname:
        return base
    svc = match_service(cname)
    if not svc:
        return base

    matched: List[str] = []
    confidence = "potential"
    if body:
        low = body.lower()
        matched = [f for f in svc["fingerprints"] if f.lower() in low]
        if matched:
            confidence = "confirmed"
    return {"hostname": hostname, "cname": cname, "service": svc["service"],
            "vulnerable": confidence == "confirmed", "confidence": confidence,
            "fingerprints_matched": matched,
            "requires_manual_validation": True,
            "fingerprint_source": FINGERPRINT_SOURCE,
            "fingerprint_date": FINGERPRINT_DATE}


def _fetch_body(hostname: str, timeout: float) -> Optional[str]:
    try:
        import requests  # lazy
    except Exception:
        return None
    for scheme in ("https://", "http://"):
        try:
            return requests.get(scheme + hostname, timeout=timeout, allow_redirects=True).text
        except Exception:
            continue
    return None


def check_takeover(hostname: str, resolver, fetch: bool = True,
                   timeout: float = 6.0, exclude_same_org: bool = False) -> Dict[str, Any]:
    """Resolve ``hostname``'s CNAME, match a known service, and (if matched and
    ``fetch``) confirm via the service's error page. With ``exclude_same_org`` a
    CNAME to the same registrable base domain is skipped (opt-in, off by default)."""
    cnames = resolver.query(hostname, "CNAME")
    cname = cnames[0] if cnames else None
    if not cname or not match_service(cname):
        return evaluate_takeover(hostname, cname, None)
    if exclude_same_org and same_org(hostname, cname):
        result = evaluate_takeover(hostname, cname, None)
        result["service"] = None
        result["skipped"] = "same-org"
        return result
    body = _fetch_body(hostname, timeout) if fetch else None
    return evaluate_takeover(hostname, cname, body)
