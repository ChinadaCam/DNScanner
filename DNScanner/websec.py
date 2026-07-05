"""Web-layer depth: security.txt (RFC 9116), CSP analysis, and cookie flags.

Pure parsers + evaluator — callers pass the fetched text/headers. No network here.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_SECTXT_REF = "RFC 9116"
_CSP_REF = "OWASP Secure Headers Project / CSP Level 3"
_COOKIE_REF = "OWASP WSTG (Session Management) / RFC 6265bis"


# --------------------------------------------------------------------------- #
# security.txt (RFC 9116)
# --------------------------------------------------------------------------- #
def _is_expired(value: str) -> Optional[bool]:
    try:
        s = value.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt < datetime.now(timezone.utc)
    except Exception:
        return None


def parse_security_txt(text: Optional[str]) -> Dict[str, Any]:
    if not text:
        return {"present": False, "fields": {}, "expires": None, "expired": None, "issues": []}
    fields: Dict[str, List[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields.setdefault(key.strip().lower(), []).append(value.strip())

    issues: List[str] = []
    if "contact" not in fields:
        issues.append("security.txt missing required Contact field")
    expires = expired = None
    if "expires" not in fields:
        issues.append("security.txt missing required Expires field")
    else:
        expires = fields["expires"][0]
        expired = _is_expired(expires)
        if expired:
            issues.append("security.txt Expires date has passed")
    return {"present": True, "fields": fields, "expires": expires,
            "expired": expired, "issues": issues}


# --------------------------------------------------------------------------- #
# Content-Security-Policy
# --------------------------------------------------------------------------- #
def parse_csp(csp: Optional[str]) -> Dict[str, Any]:
    if not csp:
        return {"present": False, "directives": {}, "weaknesses": []}
    directives: Dict[str, List[str]] = {}
    for part in csp.split(";"):
        toks = part.split()
        if toks:
            directives[toks[0].lower()] = toks[1:]

    weaknesses: List[str] = []
    low = csp.lower()
    if "'unsafe-inline'" in low:
        weaknesses.append("uses 'unsafe-inline'")
    if "'unsafe-eval'" in low:
        weaknesses.append("uses 'unsafe-eval'")
    if "default-src" not in directives:
        weaknesses.append("no default-src directive")
    for d in ("default-src", "script-src"):
        if "*" in directives.get(d, []):
            weaknesses.append("%s allows * (any host)" % d)
    return {"present": True, "directives": directives, "weaknesses": weaknesses}


# --------------------------------------------------------------------------- #
# Cookies
# --------------------------------------------------------------------------- #
def parse_cookies(set_cookie_headers: List[str]) -> Dict[str, Any]:
    cookies: List[Dict[str, Any]] = []
    for raw in set_cookie_headers or []:
        if not raw:
            continue
        attrs = [a.strip() for a in str(raw).split(";")]
        name = attrs[0].split("=", 1)[0].strip() if attrs else ""
        rest = attrs[1:]
        lowered = [a.lower() for a in rest]
        samesite = None
        for a in rest:
            if a.lower().startswith("samesite="):
                samesite = a.split("=", 1)[1]
        cookies.append({"name": name,
                        "secure": "secure" in lowered,
                        "httponly": "httponly" in lowered,
                        "samesite": samesite})

    issues: List[str] = []
    for c in cookies:
        missing = []
        if not c["secure"]:
            missing.append("Secure")
        if not c["httponly"]:
            missing.append("HttpOnly")
        if not c["samesite"]:
            missing.append("SameSite")
        if missing:
            issues.append("cookie '%s' missing %s" % (c["name"], ", ".join(missing)))
    return {"cookies": cookies, "issues": issues}


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #
def evaluate_websec(http: Dict[str, Any]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []

    st = http.get("security_txt") or {}
    if not st.get("present"):
        findings.append({"id": "security-txt-missing", "title": "No security.txt", "severity": "low",
                         "detail": "No /.well-known/security.txt; researchers have no disclosure contact.",
                         "remediation": "Publish /.well-known/security.txt with Contact and Expires.",
                         "reference": _SECTXT_REF})
    else:
        for issue in st.get("issues", []):
            findings.append({"id": "security-txt-issue", "title": "security.txt issue",
                             "severity": "low", "detail": issue,
                             "remediation": "Add/refresh the required security.txt fields.",
                             "reference": _SECTXT_REF})

    csp = http.get("csp") or {}
    if csp.get("present"):
        for weakness in csp.get("weaknesses", []):
            findings.append({"id": "csp-weak", "title": "Weak Content-Security-Policy",
                             "severity": "low", "detail": "CSP %s." % weakness,
                             "remediation": "Remove unsafe-inline/unsafe-eval and wildcards; set a strict default-src.",
                             "reference": _CSP_REF})

    cookies = http.get("cookies") or {}
    for issue in cookies.get("issues", []):
        findings.append({"id": "cookie-flags", "title": "Cookie missing security flags",
                         "severity": "low", "detail": issue,
                         "remediation": "Set Secure, HttpOnly, and SameSite on cookies.",
                         "reference": _COOKIE_REF})
    return findings
