"""Derive extra findings from an assembled ScanResult.

This enriches the findings list with **positive/observed confirmations** (info
level) and a few cross-cutting signals, so the findings section reflects what is
configured *well*, not only what is missing. Pure — reads the result, returns
finding dicts, performs no I/O and never fabricates (only reports observed state).
"""
from __future__ import annotations

from typing import Any, Dict, List


def _f(fid: str, title: str, detail: str, severity: str = "info",
       remediation: str = "", reference: str = "") -> Dict[str, str]:
    return {"id": fid, "title": title, "severity": severity, "detail": detail,
            "remediation": remediation, "reference": reference}


def _attr(result: Any, name: str, default: Any) -> Any:
    value = getattr(result, name, default)
    return default if value is None else value


def derive_findings(result: Any) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    records = _attr(result, "records", {})
    es = _attr(result, "email_security", {})
    tls = _attr(result, "tls", {})
    http = _attr(result, "http", {})

    # --- DNSSEC ---
    dnssec = _attr(result, "dnssec", {})
    if dnssec.get("enabled"):
        validated = " and validated" if dnssec.get("authenticated_data") else ""
        out.append(_f("dnssec-enabled", "DNSSEC enabled",
                      "Zone is signed%s." % validated, reference="RFC 4033"))

    # --- CAA ---
    caa = records.get("caa_parsed") or {}
    if caa.get("present") and not caa.get("allows_any_ca"):
        out.append(_f("caa-restricts", "CAA restricts certificate issuance",
                      "Only the listed CA(s) may issue certificates.", reference="RFC 8659"))

    # --- Email posture (positives) ---
    spf = es.get("spf") or {}
    if spf.get("present") and spf.get("all") == "-all":
        out.append(_f("spf-hardfail", "SPF hardfail (-all)",
                      "SPF rejects mail from unlisted senders.", reference="RFC 7208"))
    dmarc = es.get("dmarc") or {}
    if dmarc.get("strength") in ("strong", "moderate"):
        verb = "rejected" if dmarc.get("policy") == "reject" else "quarantined"
        out.append(_f("dmarc-enforced", "DMARC enforced (p=%s)" % dmarc.get("policy"),
                      "Spoofed mail is %s." % verb, reference="RFC 7489"))
    if any(d.get("present") for d in (es.get("dkim") or [])):
        out.append(_f("dkim-present", "DKIM configured",
                      "Outbound mail is cryptographically signed.", reference="RFC 6376"))
    mta = es.get("mta_sts") or {}
    if mta.get("present") and (mta.get("mode") or "").lower() == "enforce":
        out.append(_f("mta-sts-enforce", "MTA-STS in enforce mode",
                      "Inbound SMTP downgrade attacks are blocked.", reference="RFC 8461"))
    dane = es.get("dane") or {}
    if dane.get("present") and dane.get("dnssec_protected"):
        out.append(_f("dane-active", "DANE/TLSA active",
                      "TLSA records are DNSSEC-validated.", reference="RFC 7672"))

    # --- TLS ---
    days = tls.get("days_to_expiry")
    if tls.get("reachable") and tls.get("valid") and isinstance(days, int) and days >= 15:
        out.append(_f("tls-valid", "TLS certificate valid",
                      "Expires in %d days (issuer: %s)." % (days, tls.get("issuer")),
                      reference="RFC 5280"))

    # --- HTTP positives ---
    if http.get("reachable"):
        present = http.get("present") or {}
        if "HSTS" in present:
            out.append(_f("hsts-present", "HSTS enabled",
                          "Browsers are pinned to HTTPS.", reference="RFC 6797"))
        st = http.get("security_txt") or {}
        if st.get("present") and not st.get("expired"):
            out.append(_f("security-txt-present", "security.txt published",
                          "A vulnerability-disclosure contact is published.", reference="RFC 9116"))
        csp = http.get("csp") or {}
        if csp.get("present") and not csp.get("weaknesses"):
            out.append(_f("csp-strong", "Content-Security-Policy present",
                          "CSP is set with no obvious weaknesses.",
                          reference="OWASP Secure Headers Project / CSP Level 3"))

    # --- Reachability ---
    if (_attr(result, "reachability", {})).get("reachable"):
        out.append(_f("reachable", "Host reachable", "Responds on TCP 80/443.",
                      reference="RFC 9293"))

    # --- AXFR refused (good) ---
    zt = _attr(result, "zone_transfer", {})
    if zt.get("tested") and not zt.get("vulnerable_servers"):
        out.append(_f("axfr-refused", "Zone transfer refused",
                      "Nameservers refused AXFR.", reference="RFC 5936"))

    # --- Subdomains ---
    sd = _attr(result, "subdomains", {})
    if sd.get("found"):
        out.append(_f("subdomains-found", "%d subdomain(s) discovered" % len(sd["found"]),
                      "Review for forgotten/unexpected hosts.",
                      reference="OWASP WSTG-INFO-04 (Enumerate Applications)"))
    if sd.get("wildcard") or sd.get("ct_wildcards"):
        out.append(_f("wildcard-dns", "Wildcard DNS in use",
                      "A wildcard answers arbitrary labels; treat brute-force results with care.",
                      reference="RFC 4592"))

    # --- Takeover clean ---
    if "takeover" in _attr(result, "checks_run", []) and not _attr(result, "takeover", []):
        out.append(_f("takeover-none", "No takeover candidates",
                      "No dangling CNAMEs matched known-service fingerprints.",
                      reference="OWASP WSTG: Test for Subdomain Takeover"))

    return out
