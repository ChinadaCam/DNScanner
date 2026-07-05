"""Render a scan result into a shareable report (HTML, text, or PDF).

This is a **pure consumer** of the scan's ``to_dict()`` output — pass either a
``ScanResult`` or its dict. HTML and text need no dependencies; PDF uses
``reportlab`` if it is installed (``pip install reportlab`` / ``dnscanner[report]``).

Because it depends on nothing inside the package, it can be embedded or tested in
isolation.
"""
from __future__ import annotations

import html as _html
from pathlib import Path
from typing import Any, Dict, List, Tuple

__all__ = ["render_html", "render_text", "write_report", "ReportError"]

_SEV_COLOR = {"high": "#c0392b", "medium": "#e67e22", "low": "#d4ac0d", "info": "#2980b9"}
_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
_SEV_CLASS = {"high": "sev-high", "medium": "sev-medium", "low": "sev-low", "info": "sev-info"}
_ISSUE_SEV = ("high", "medium", "low")   # everything else (info) is an observed pass
# grade -> (badge colour, why-strip background, why-strip text)
_GRADE = {"A+": ("#1e7e34", "#eaf5ec", "#1e5b2a"), "A": ("#2e9e4f", "#eaf5ec", "#1e5b2a"),
          "B": ("#c9a227", "#fbf3d9", "#6b5307"), "C": ("#e67e22", "#fde7d3", "#7a4a06"),
          "D": ("#d35400", "#fce3d6", "#7a3010"), "F": ("#c0392b", "#fbe9e7", "#7f1d1d")}

_CSS = (
    ":root{--fg:#1a1f29;--muted:#5b6675;--line:#e6e9ef;--card:#f7f8fa;--ok:#1e7e34}"
    "*{box-sizing:border-box}"
    "body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;"
    "max-width:960px;margin:0 auto;padding:24px 18px 48px;color:var(--fg);line-height:1.5;background:#fff}"
    ".head{display:flex;align-items:center;gap:16px}"
    ".head h1{margin:0;font-size:22px;word-break:break-word}"
    ".grade{font-size:30px;font-weight:800;color:#fff;border-radius:12px;padding:6px 18px;line-height:1}"
    ".score-label{color:var(--muted);font-size:13px;margin-top:3px}"
    ".sub{color:var(--muted);margin:8px 0 4px;font-size:13px}"
    ".why{border-radius:8px;padding:10px 14px;margin:14px 0 4px;font-size:13px;line-height:1.55}"
    ".why b{font-weight:700}"
    ".nav{margin:14px 0 2px;font-size:13px}"
    ".nav a{color:#1c5e94;text-decoration:none;margin-right:14px;white-space:nowrap}"
    ".nav a:hover{text-decoration:underline}"
    "h2{font-size:16px;margin:26px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line);scroll-margin-top:12px}"
    ".chips{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0 2px}"
    ".chip{font-size:12px;font-weight:700;border-radius:14px;padding:3px 11px}"
    ".chip-pass{background:#eef4ec;color:#33623f;border:1px solid #d6e3d9}"
    ".grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:10px;margin:10px 0}"
    ".fact{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}"
    ".fact .k{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}"
    ".fact .v{font-size:15px;font-weight:600;margin-top:3px;word-break:break-word}"
    "ul.findings{list-style:none;padding:0;margin:0}"
    "ul.findings li{margin:8px 0;padding:10px 12px;background:var(--card);border:1px solid var(--line);"
    "border-left:4px solid #ccc;border-radius:6px}"
    "li.li-high{border-left-color:#c0392b}li.li-medium{border-left-color:#e67e22}li.li-low{border-left-color:#b4b7bd}"
    ".sev{display:inline-block;font-size:11px;font-weight:700;padding:1px 9px;border-radius:10px;"
    "margin-right:8px;text-transform:uppercase;letter-spacing:.02em}"
    ".sev-high{background:#fbe9e7;color:#7f1d1d}"
    ".sev-medium{background:#fde7d3;color:#7a4a06}"
    ".sev-low{background:#eef0f3;color:#464e5b;border:1px solid #e0e3e9}"
    ".sev-info{background:#eef4fb;color:#1c4e80}"
    ".f-title{font-weight:600}.f-detail{color:#39424e;font-size:13px;margin-top:3px}"
    ".f-fix{font-size:13px;margin-top:4px}.f-fix b{color:var(--ok)}"
    ".f-ref{color:var(--muted);font-size:12px;margin-top:2px}"
    "details.passed{margin:8px 0 4px}"
    "details.passed summary{cursor:pointer;font-size:14px;color:var(--muted);padding:10px 12px;"
    "background:var(--card);border:1px solid var(--line);border-radius:6px}"
    "details.passed summary b{color:var(--fg)}"
    "details.passed[open] summary{border-bottom-left-radius:0;border-bottom-right-radius:0}"
    "details.passed ul{list-style:none;padding:8px 0 2px;margin:0;border:1px solid var(--line);"
    "border-top:0;border-radius:0 0 6px 6px}"
    "details.passed li{font-size:13px;color:#39424e;padding:5px 12px}"
    "details.passed li b{font-weight:600}"
    "table.kv{border-collapse:collapse;width:100%;font-size:14px}"
    "table.kv th{text-align:left;width:150px;vertical-align:top;color:var(--muted);font-weight:600;"
    "padding:4px 8px;border-bottom:1px solid var(--line)}"
    "table.kv td{padding:4px 8px;border-bottom:1px solid var(--line);word-break:break-word}"
    ".tag{display:inline-block;font-size:11px;background:#eef1f6;border-radius:4px;padding:1px 6px;margin-left:6px;color:var(--muted)}"
    ".good{color:var(--ok)}.bad{color:#c0392b}.warn{color:#b9770e}.na{color:var(--muted)}"
    "footer{margin-top:36px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:10px}"
    "footer a{color:#2980b9;text-decoration:none}footer a:hover{text-decoration:underline}"
)


class ReportError(RuntimeError):
    """Raised when a report cannot be produced (e.g. PDF without reportlab)."""


def _as_dict(result: Any) -> Dict[str, Any]:
    return result.to_dict() if hasattr(result, "to_dict") else dict(result)


def _sections(d: Dict[str, Any]) -> List[Tuple[str, List[Tuple[str, Any]]]]:
    """Flat key/value sections shared by every renderer."""
    out: List[Tuple[str, List[Tuple[str, Any]]]] = []

    ips = d.get("resolved_ips") or {}
    out.append(("IP addresses", [(k.upper(), ", ".join(v)) for k, v in ips.items() if v]))

    rec_pairs = []
    for rtype, vals in (d.get("records") or {}).items():
        if rtype in ("caa_parsed", "soa_parsed"):
            continue
        if isinstance(vals, dict):  # PTR map {ip: [names]}
            joined = "; ".join("%s -> %s" % (k, "/".join(x))
                               for k, x in vals.items() if isinstance(x, (list, tuple)) and x)
            if joined:
                rec_pairs.append((rtype.upper(), joined))
        elif isinstance(vals, (list, tuple)) and vals:
            rec_pairs.append((rtype.upper(), ", ".join(vals)))
    out.append(("DNS records", rec_pairs))

    es = d.get("email_security") or {}
    if es:
        dkim = ", ".join(x["selector"] for x in (es.get("dkim") or []) if x.get("present"))
        out.append(("Email security", [
            ("SPF", (es.get("spf") or {}).get("record") or "missing"),
            ("DMARC", (es.get("dmarc") or {}).get("record") or "missing"),
            ("DKIM", dkim or "none found"),
        ]))

    ds = d.get("dnssec") or {}
    if ds:
        out.append(("DNSSEC", [("Enabled", ds.get("enabled")),
                               ("DS present", ds.get("ds_present")),
                               ("Authenticated", ds.get("authenticated_data"))]))

    tls = d.get("tls") or {}
    if tls:
        if tls.get("reachable"):
            out.append(("TLS certificate", [
                ("Issuer", tls.get("issuer")), ("Expires", tls.get("not_after")),
                ("Days left", tls.get("days_to_expiry")),
                ("SAN", ", ".join(tls.get("san") or []))]))
        else:
            out.append(("TLS certificate", [("Status", "not reachable: %s" % tls.get("error"))]))

    http = d.get("http") or {}
    if http and http.get("reachable"):
        out.append(("HTTP security headers", [
            ("URL", http.get("url")), ("Status", http.get("status_code")),
            ("Present", ", ".join((http.get("present") or {}).keys()) or "none"),
            ("Missing", ", ".join(http.get("missing") or []) or "none")]))

    geo = d.get("geolocation") or []
    if geo:
        gp = []
        for g in geo:
            if g.get("error"):
                gp.append((g.get("ip", "?"), "error: %s" % g["error"]))
            else:
                place = ", ".join(p for p in (g.get("city"), g.get("region"), g.get("country")) if p)
                if g.get("isp"):
                    place = (place + " - " + g["isp"]) if place else g["isp"]
                gp.append((g.get("ip", "?"), place or "unknown"))
        out.append(("Geolocation", gp))

    who = d.get("whois") or {}
    if who and not who.get("error"):
        out.append(("WHOIS", [
            ("ASN", who.get("asn")), ("Org", who.get("asn_description")),
            ("Registry", who.get("asn_registry")), ("Network", who.get("network_name")),
            ("CIDR", who.get("network_cidr") or who.get("asn_cidr")),
            ("Range", who.get("network_range")), ("Country", who.get("network_country")),
            ("Abuse", who.get("abuse_email")), ("Registrant", who.get("registrant")),
            ("Created", who.get("created")), ("Updated", who.get("updated"))]))

    tk = d.get("takeover") or []
    if tk:
        out.append(("Subdomain takeover", [
            (t.get("hostname", "?"),
             "%s via %s (%s)" % (t.get("service"), t.get("cname"), t.get("confidence")))
            for t in tk]))

    rep = d.get("reputation") or {}
    if rep:
        sh = rep.get("spamhaus") or {}
        vt = rep.get("virustotal") or {}
        sb = rep.get("safebrowsing") or {}
        out.append(("Reputation", [
            ("Spamhaus DBL", "listed" if sh.get("listed") else (sh.get("status") or "n/a")),
            ("VirusTotal", ("%s malicious" % vt.get("malicious")) if vt.get("status") == "ok"
                           else (vt.get("status") or "n/a")),
            ("Safe Browsing", "listed" if sb.get("listed") else (sb.get("status") or "n/a"))]))

    return out


def _sorted_findings(d: Dict[str, Any]) -> List[Dict[str, Any]]:
    return sorted(d.get("findings") or [],
                  key=lambda f: _SEV_ORDER.get(f.get("severity"), 9))


def _merge_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collapse findings that share an ``id`` (e.g. two ``cookie-flags`` rows) into
    one entry, concatenating distinct details and recording how many were merged in
    ``_count``. Non-destructive: operates on copies."""
    order: List[Dict[str, Any]] = []
    by_id: Dict[Any, Dict[str, Any]] = {}
    for f in findings:
        fid = f.get("id")
        if fid is not None and fid in by_id:
            base = by_id[fid]
            d1, d2 = str(base.get("detail") or ""), str(f.get("detail") or "")
            if d2 and d2 not in d1:
                base["detail"] = (d1 + "; " + d2).strip("; ")
            base["_count"] = base.get("_count", 1) + 1
            continue
        nf = dict(f)
        nf["_count"] = 1
        order.append(nf)
        if fid is not None:
            by_id[fid] = nf
    return order


def _split_findings(findings: List[Dict[str, Any]]):
    """Separate real issues (high/medium/low) from observed passes (info)."""
    issues = [f for f in findings if f.get("severity") in _ISSUE_SEV]
    passed = [f for f in findings if f.get("severity") not in _ISSUE_SEV]
    return issues, passed


def _issue_summary(issues: List[Dict[str, Any]]) -> str:
    counts: Dict[str, int] = {}
    for f in issues:
        sev = f.get("severity", "low")
        counts[sev] = counts.get(sev, 0) + 1
    return ", ".join("%d %s" % (counts[k], k) for k in _ISSUE_SEV if counts.get(k))


def _why_text(issues: List[Dict[str, Any]]) -> str:
    top = ", ".join(str(f.get("title", "")) for f in issues[:3])
    return "%s. Top: %s." % (_issue_summary(issues), top)


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #
def _sev_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _kv_html(title: str, rows, e) -> str:
    rows = [(k, v) for k, v in rows if v not in (None, "", [], {})]
    if not rows:
        return ""
    out = ["<h2>%s</h2><table class='kv'>" % e(title)]
    for k, v in rows:
        out.append("<tr><th>%s</th><td>%s</td></tr>" % (e(str(k)), e(str(v))))
    out.append("</table>")
    return "".join(out)


def _key_facts(d: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    """(label, value, css-class) tiles giving an at-a-glance verdict."""
    facts: List[Tuple[str, str, str]] = []
    ips = d.get("resolved_ips") or {}
    a, aaaa = ips.get("a") or [], ips.get("aaaa") or []
    if a or aaaa:
        val = ", ".join(a[:2]) + (" +%d" % (len(a) - 2) if len(a) > 2 else "")
        if aaaa:
            val += " · %d IPv6" % len(aaaa)
        facts.append(("Resolves to", val or "IPv6 only", "good"))
    elif ips:
        facts.append(("Resolves to", "does not resolve", "bad"))

    ds = d.get("dnssec") or {}
    if ds:
        facts.append(("DNSSEC", "enabled" if ds.get("enabled") else "not enabled",
                      "good" if ds.get("enabled") else "warn"))

    es = d.get("email_security") or {}
    if es:
        spf = es.get("spf") or {}
        if spf.get("present"):
            # only a hardfail (-all) is fully protective; ~all softfail is amber
            facts.append(("SPF", spf.get("all") or "present", "good" if spf.get("all") == "-all" else "warn"))
        else:
            facts.append(("SPF", "missing", "warn"))
        dm = es.get("dmarc") or {}
        if dm.get("present"):
            facts.append(("DMARC", "%s (%s)" % (dm.get("policy") or "?", dm.get("strength") or "?"),
                          "good" if dm.get("strength") in ("strong", "moderate") else "warn"))
        else:
            facts.append(("DMARC", "missing", "warn"))
        mta = es.get("mta_sts") or {}
        if mta.get("present"):
            facts.append(("MTA-STS", mta.get("mode") or "present",
                          "good" if mta.get("mode") == "enforce" else "warn"))

    tls = d.get("tls") or {}
    if tls:
        if tls.get("reachable"):
            days = tls.get("days_to_expiry")
            facts.append(("TLS cert", ("valid, %s days left" % days) if isinstance(days, int) else "valid",
                          "good" if (not isinstance(days, int) or days > 15) else "warn"))
        else:
            facts.append(("TLS cert", "not reachable", "na"))

    http = d.get("http") or {}
    if http.get("reachable"):
        facts.append(("HSTS", "present" if "HSTS" in (http.get("present") or {}) else "missing",
                      "good" if "HSTS" in (http.get("present") or {}) else "warn"))

    rep = d.get("reputation") or {}
    if rep:
        sh, vt, sb = rep.get("spamhaus") or {}, rep.get("virustotal") or {}, rep.get("safebrowsing") or {}
        flagged = sh.get("listed") or (vt.get("malicious") or 0) or sb.get("listed")
        facts.append(("Reputation", "flagged" if flagged else "clean", "bad" if flagged else "good"))

    sd = d.get("subdomains") or {}
    if sd:
        facts.append(("Subdomains", "%d found" % len(sd.get("found") or []), "na"))
    return facts


def _records_html(d, e) -> str:
    recs = d.get("records") or {}
    rows = []
    for rt in ("a", "aaaa", "mx", "ns", "cname", "txt", "soa", "caa"):
        vals = recs.get(rt)
        if isinstance(vals, (list, tuple)) and vals:
            rows.append((rt.upper(), ", ".join(vals)))
    ptr = recs.get("ptr")
    if isinstance(ptr, dict) and ptr:
        rows.append(("PTR", "; ".join("%s -> %s" % (k, "/".join(v))
                                      for k, v in ptr.items() if isinstance(v, (list, tuple)) and v)))
    caa = recs.get("caa_parsed") or {}
    if caa.get("present"):
        rows.append(("CAA issue", ", ".join(caa.get("issue") or [])))
        rows.append(("CAA iodef", ", ".join(caa.get("iodef") or [])))
    soa = recs.get("soa_parsed") or {}
    if soa.get("present"):
        rows.append(("SOA serial", soa.get("serial")))
        rows.append(("SOA expire", soa.get("expire")))
    return _kv_html("DNS records", rows, e)


def _email_html(d, e) -> str:
    es = d.get("email_security") or {}
    if not es:
        return ""
    spf, dm = es.get("spf") or {}, es.get("dmarc") or {}
    dkim = [x for x in (es.get("dkim") or []) if x.get("present")]
    mta, dane = es.get("mta_sts") or {}, es.get("dane") or {}
    rows = [
        ("SPF", spf.get("record") or "missing"),
        ("SPF DNS lookups", ("%s / 10" % spf.get("dns_lookups")) if spf.get("present") else None),
        ("DMARC", dm.get("record") or "missing"),
        ("DMARC policy", ("%s — %s" % (dm.get("policy"), dm.get("strength"))) if dm.get("present") else None),
        ("DKIM", (", ".join("%s (%s-bit)" % (x["selector"], x.get("key_bits") or "?") for x in dkim))
                 if dkim else "none found"),
        ("MTA-STS", (mta.get("mode") or "present") if mta.get("present") else "missing"),
        ("TLS-RPT", "present" if (es.get("tls_rpt") or {}).get("present") else "missing"),
        ("BIMI", "present" if (es.get("bimi") or {}).get("present") else "missing"),
        ("DANE/TLSA", ("present, " + ("DNSSEC-validated" if dane.get("dnssec_protected")
                                      else "NOT protected without DNSSEC")) if dane.get("present") else "none"),
    ]
    return _kv_html("Email authentication", rows, e)


def _web_html(d, e) -> str:
    http = d.get("http") or {}
    if not http:
        return ""
    if not http.get("reachable"):
        return _kv_html("Web security", [("Status", "not reachable: %s" % http.get("error"))], e)
    csp, cookies, st = http.get("csp") or {}, http.get("cookies") or {}, http.get("security_txt") or {}
    rows = [
        ("URL", "%s (%s)" % (http.get("url"), http.get("status_code"))),
        ("Headers present", ", ".join((http.get("present") or {}).keys()) or "none"),
        ("Headers missing", ", ".join(http.get("missing") or []) or "none"),
        ("CSP", ("present; weak: %s" % ", ".join(csp.get("weaknesses"))) if csp.get("present") and csp.get("weaknesses")
                else ("present, no obvious weakness" if csp.get("present") else "missing")),
        ("Cookies", "; ".join(cookies.get("issues")) if cookies.get("issues") else "ok / none set"),
        ("security.txt", ("present" + (" (EXPIRED)" if st.get("expired") else "")) if st.get("present") else "missing"),
    ]
    return _kv_html("Web security", rows, e)


def _tls_html(d, e) -> str:
    tls = d.get("tls") or {}
    ta = d.get("tls_audit") or {}
    rows = []
    if tls.get("reachable"):
        rows += [("Issuer", tls.get("issuer")), ("Subject", tls.get("subject")),
                 ("Expires", tls.get("not_after")), ("Days left", tls.get("days_to_expiry")),
                 ("SAN", ", ".join(tls.get("san") or []))]
    elif tls:
        rows.append(("Status", "not reachable: %s" % tls.get("error")))
    if ta.get("reachable"):
        protos = ta.get("protocols") or {}
        rows.append(("Protocols", ", ".join(p for p, v in protos.items() if v is True) or "?"))
        neg = ta.get("negotiated") or {}
        if neg.get("version"):
            rows.append(("Negotiated", "%s / %s%s" % (neg.get("version"), neg.get("cipher"),
                                                      " (FS)" if neg.get("forward_secret") else " (no FS)")))
    if not rows:
        return ""
    return _kv_html("TLS certificate", rows, e)


def _subdomains_html(d, e) -> str:
    sd = d.get("subdomains") or {}
    if not sd:
        return ""
    out = ["<h2>Subdomains</h2>",
           "<div class='sub'>wildcard: %s &nbsp;·&nbsp; active: %s &nbsp;·&nbsp; passive/CT: %s "
           "&nbsp;·&nbsp; found: %d</div>" % (e(str(sd.get("wildcard"))), e(str(sd.get("active"))),
                                              e(str(sd.get("passive"))), len(sd.get("found") or []))]
    if sd.get("ct_wildcards"):
        out.append("<div class='sub'>CT wildcards: %s</div>" % e(", ".join(sd["ct_wildcards"])))
    found = sd.get("found") or []
    if found:
        out.append("<table class='kv'>")
        for f in found:
            out.append("<tr><th>%s</th><td>%s<span class='tag'>%s</span></td></tr>"
                       % (e(str(f.get("name"))), e(", ".join(f.get("ips") or []) or "—"),
                          e(str(f.get("source", "")))))
        out.append("</table>")
    return "".join(out)


def _takeover_html(d, e) -> str:
    tk = d.get("takeover") or []
    if not tk:
        return ""
    out = ["<h2>Subdomain takeover</h2>",
           "<div class='sub'>Advisory — every candidate below requires manual validation.</div>",
           "<table class='kv'>"]
    for t in tk:
        detail = "%s via %s — %s" % (t.get("service"), t.get("cname"), t.get("confidence"))
        if t.get("fingerprint_source"):
            detail += " (fingerprint: %s %s)" % (t.get("fingerprint_source"), t.get("fingerprint_date"))
        out.append("<tr><th>%s</th><td>%s</td></tr>" % (e(str(t.get("hostname"))), e(detail)))
    out.append("</table>")
    return "".join(out)


def _reputation_html(d, e) -> str:
    rep = d.get("reputation") or {}
    if not rep:
        return ""
    sh, vt, sb = rep.get("spamhaus") or {}, rep.get("virustotal") or {}, rep.get("safebrowsing") or {}
    rows = [
        ("Spamhaus DBL", ("listed (%s)" % ", ".join(sh.get("codes") or [])) if sh.get("listed")
                         else ("blocked resolver" if sh.get("blocked_resolver")
                               else ("clean" if sh.get("status") == "ok" else sh.get("status")))),
        ("VirusTotal", ("%s malicious / %s harmless" % (vt.get("malicious"), vt.get("harmless")))
                       if vt.get("status") == "ok" else vt.get("status")),
        ("Safe Browsing", (", ".join(sb.get("matches") or []) or "listed")
                          if (sb.get("status") == "ok" and sb.get("listed"))
                          else ("clean" if sb.get("status") == "ok" else sb.get("status"))),
    ]
    return _kv_html("Reputation", rows, e)


def _whois_geo_html(d, e) -> str:
    out = []
    who = d.get("whois") or {}
    if who and not who.get("error"):
        out.append(_kv_html("WHOIS / network", [
            ("ASN", who.get("asn")), ("Org", who.get("asn_description")),
            ("Registry", who.get("asn_registry")), ("Network", who.get("network_name")),
            ("CIDR", who.get("network_cidr") or who.get("asn_cidr")),
            ("Range", who.get("network_range")), ("Country", who.get("network_country")),
            ("Abuse", who.get("abuse_email")), ("Registrant", who.get("registrant")),
            ("Created", who.get("created")), ("Updated", who.get("updated"))], e))
    geo = d.get("geolocation") or []
    if geo:
        rows = []
        for g in geo:
            if g.get("error"):
                rows.append((g.get("ip", "?"), "error: %s" % g["error"]))
            else:
                place = ", ".join(p for p in (g.get("city"), g.get("region"), g.get("country")) if p)
                if g.get("isp"):
                    place = (place + " — " + g["isp"]) if place else g["isp"]
                rows.append((g.get("ip", "?"), place or "unknown"))
        out.append(_kv_html("Geolocation", rows, e))
    return "".join(out)


def render_html(result: Any) -> str:
    d = _as_dict(result)
    e = _html.escape
    findings = _merge_findings(_sorted_findings(d))
    issues, passed = _split_findings(findings)
    sc = d.get("score") or {}
    domain = e(str(d.get("domain", "")))
    s: List[str] = ["<!doctype html><html lang='en'><head><meta charset='utf-8'>",
                    "<meta name='viewport' content='width=device-width, initial-scale=1'>",
                    "<title>DNScanner report - %s</title><style>%s</style></head><body>" % (domain, _CSS)]

    # Header: grade badge + domain (the report's subject) + score label
    grade_col, why_bg, why_fg = _GRADE.get(sc.get("grade"), ("#888", "#eef1f6", "#39424e"))
    s.append("<div class='head'>")
    if sc:
        s.append("<div class='grade' style='background:%s'>%s</div>" % (grade_col, e(str(sc.get("grade", "")))))
    s.append("<div><h1>%s</h1>" % (domain or "DNScanner report"))
    if sc:
        s.append("<div class='score-label'>%s / 100 security posture score</div>" % e(str(sc.get("score", ""))))
    s.append("</div></div>")

    profile = d.get("scan_profile")
    plabel = {"standard": "Standard scan", "extended": "Extended scan"}.get(
        profile, "Custom scan" if profile else "")
    raw_when = str(d.get("scanned_at", ""))
    when = e(raw_when[:19])                               # trim microseconds/offset
    tz = " UTC" if ("+00:00" in raw_when or raw_when.endswith("Z")) else ""
    bits = ([e(plabel)] if plabel else []) + \
           ["scanned %s%s" % (when, tz), "took %s ms" % e(str(d.get("duration_ms", 0)))]
    s.append("<div class='sub'>%s</div>" % " &middot; ".join(bits))

    # Why this grade — connect the score to its drivers
    if sc and issues:
        s.append("<div class='why' style='background:%s;color:%s'><b>Why %s:</b> %s</div>"
                 % (why_bg, why_fg, e(str(sc.get("grade", ""))), e(_why_text(issues))))
    elif sc:
        s.append("<div class='why' style='background:#eaf5ec;color:#1e5b2a'>"
                 "No issues flagged &mdash; all checks passed.</div>")

    # Severity summary — issue chips + a single muted pass count
    isum: Dict[str, int] = {}
    for f in issues:
        isum[f.get("severity", "low")] = isum.get(f.get("severity", "low"), 0) + 1
    s.append("<div class='chips'>")
    for sev in _ISSUE_SEV:
        if isum.get(sev):
            s.append("<span class='chip %s'>%d %s</span>" % (_SEV_CLASS[sev], isum[sev], sev))
    if passed:
        s.append("<span class='chip chip-pass'>%d passed</span>" % len(passed))
    if not issues and not passed:
        s.append("<span class='chip chip-pass'>No findings</span>")
    s.append("</div>")

    # Build detailed sections once (reused by the jump-nav and the body)
    sections = [("records", "DNS", _records_html(d, e)), ("email", "Email", _email_html(d, e)),
                ("web", "Web", _web_html(d, e)), ("tls", "TLS", _tls_html(d, e)),
                ("subdomains", "Subdomains", _subdomains_html(d, e)),
                ("takeover", "Takeover", _takeover_html(d, e)),
                ("reputation", "Reputation", _reputation_html(d, e)),
                ("whois", "WHOIS", _whois_geo_html(d, e))]
    present = [(key, label, part) for key, label, part in sections if part]

    # Jump navigation
    nav = ["<a href='#issues'>Issues</a>"]
    if passed:
        nav.append("<a href='#passed'>Passed</a>")
    nav += ["<a href='#sec-%s'>%s</a>" % (key, e(label)) for key, label, _ in present]
    s.append("<div class='nav'>%s</div>" % "".join(nav))

    # At-a-glance facts
    facts = _key_facts(d)
    if facts:
        s.append("<h2>At a glance</h2><div class='grid'>")
        for label, value, cls in facts:
            s.append("<div class='fact'><div class='k'>%s</div><div class='v %s'>%s</div></div>"
                     % (e(label), cls, e(value)))
        s.append("</div>")

    # Issues to fix (real problems only; same id merged)
    s.append("<h2 id='issues'>Issues to fix (%d)</h2>" % len(issues))
    if issues:
        s.append("<ul class='findings'>")
        for f in issues:
            sev = f.get("severity", "low")
            s.append("<li class='li-%s'>" % sev)
            s.append("<span class='sev %s'>%s</span>" % (_SEV_CLASS.get(sev, "sev-info"), e(sev)))
            s.append("<span class='f-title'>%s</span>" % e(str(f.get("title", ""))))
            if f.get("_count", 1) > 1:
                s.append("<span class='tag'>%d items</span>" % f["_count"])
            if f.get("detail"):
                s.append("<div class='f-detail'>%s</div>" % e(str(f["detail"])))
            if f.get("remediation"):
                s.append("<div class='f-fix'><b>Fix:</b> %s</div>" % e(str(f["remediation"])))
            if f.get("reference"):
                s.append("<div class='f-ref'>Reference: %s</div>" % e(str(f["reference"])))
            s.append("</li>")
        s.append("</ul>")
    else:
        s.append("<p class='good'>No issues to fix &mdash; nothing needs attention.</p>")

    # Passed checks — observed confirmations, collapsed so issues stay in focus
    if passed:
        s.append("<details class='passed' id='passed'><summary><b>%d checks passed</b> "
                 "&mdash; confirmations of good configuration (click to expand)</summary><ul>" % len(passed))
        for f in passed:
            ref = " <span class='f-ref'>(%s)</span>" % e(str(f["reference"])) if f.get("reference") else ""
            s.append("<li><b>%s</b> &mdash; %s%s</li>"
                     % (e(str(f.get("title", ""))), e(str(f.get("detail", ""))), ref))
        s.append("</ul></details>")

    # Detailed sections (anchored for the jump-nav)
    for key, _label, part in present:
        s.append("<div id='sec-%s'>%s</div>" % (key, part))

    errs = d.get("errors") or []
    if errs:
        s.append("<h2>Errors / unavailable</h2><ul>")
        for err in errs:
            s.append("<li>%s</li>" % e(str(err)))
        s.append("</ul>")

    s.append("<footer>Generated by <a href='https://github.com/ChinadaCam/DNScanner' "
             "title='ChinadaCam/DNScanner: Scan domains like a pro'>DNScanner</a>"
             " &middot; schema %s</footer></body></html>" % e(str(d.get("schema_version", ""))))
    return "".join(s)


# --------------------------------------------------------------------------- #
# Plain text
# --------------------------------------------------------------------------- #
def render_text(result: Any) -> str:
    d = _as_dict(result)
    lines = ["DNScanner report", "=" * 40,
             "Domain : %s" % d.get("domain", ""),
             "Scanned: %s" % d.get("scanned_at", "")]
    sc = d.get("score") or {}
    if sc:
        lines.append("Grade  : %s (%s/100)" % (sc.get("grade"), sc.get("score")))
    lines.append("")
    findings = _merge_findings(_sorted_findings(d))
    issues, passed = _split_findings(findings)
    if sc and issues:
        lines.append("Why %s: %s" % (sc.get("grade"), _why_text(issues)))
        lines.append("")
    lines.append("ISSUES TO FIX (%d)" % len(issues))
    if issues:
        for f in issues:
            lines.append("  [%s] %s - %s" % (str(f.get("severity", "")).upper(),
                                             f.get("title", ""), f.get("detail", "")))
            if f.get("remediation"):
                lines.append("        Fix: %s" % f["remediation"])
            if f.get("reference"):
                lines.append("        Ref: %s" % f["reference"])
    else:
        lines.append("  None - nothing needs attention.")
    if passed:
        lines.append("")
        lines.append("PASSED CHECKS (%d)" % len(passed))
        for f in passed:
            lines.append("  [OK] %s - %s" % (f.get("title", ""), f.get("detail", "")))
    for title, pairs in _sections(d):
        rows = [(k, v) for k, v in pairs if v not in (None, "", [], {})]
        if not rows:
            continue
        lines.append("")
        lines.append(title.upper())
        for k, v in rows:
            lines.append("  %-14s %s" % (k + ":", v))
    sd = d.get("subdomains") or {}
    if sd.get("found"):
        lines.append("")
        lines.append("SUBDOMAINS (%d)" % len(sd["found"]))
        for f in sd["found"]:
            lines.append("  %s -> %s" % (f["name"], ", ".join(f["ips"])))
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# PDF (reportlab, optional)
# --------------------------------------------------------------------------- #
def _write_pdf(d: Dict[str, Any], path: str) -> None:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
    except Exception:
        raise ReportError(
            "PDF output needs reportlab. Install it with `pip install reportlab` "
            "(or `pip install dnscanner[report]`), or write a .html report instead."
        )

    def p(x):
        return _html.escape(str(x))

    styles = getSampleStyleSheet()
    flow = [Paragraph("DNScanner report", styles["Title"]),
            Paragraph("%s &mdash; %s" % (p(d.get("domain")), p(d.get("scanned_at"))), styles["Normal"]),
            Spacer(1, 10)]

    findings = _sorted_findings(d)
    flow.append(Paragraph("Findings (%d)" % len(findings), styles["Heading2"]))
    if findings:
        for f in findings:
            flow.append(Paragraph("[%s] <b>%s</b> &mdash; %s" % (
                p(str(f.get("severity", "")).upper()), p(f.get("title", "")),
                p(f.get("detail", ""))), styles["Normal"]))
    else:
        flow.append(Paragraph("No issues flagged.", styles["Normal"]))
    flow.append(Spacer(1, 8))

    for title, pairs in _sections(d):
        rows = [(k, v) for k, v in pairs if v not in (None, "", [], {})]
        if not rows:
            continue
        flow.append(Paragraph(p(title), styles["Heading2"]))
        for k, v in rows:
            flow.append(Paragraph("<b>%s:</b> %s" % (p(k), p(v)), styles["Normal"]))
        flow.append(Spacer(1, 6))

    SimpleDocTemplate(str(path), pagesize=A4, title="DNScanner report").build(flow)


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #
def _infer_format(path: str) -> str:
    name = str(path)
    return name.rsplit(".", 1)[-1].lower() if "." in name else "html"


def write_report(result: Any, path: str, fmt: str = None) -> str:
    """Write ``result`` to ``path`` as html / txt / pdf (inferred from extension
    unless ``fmt`` is given). Returns the path. Raises :class:`ReportError`."""
    d = _as_dict(result)
    fmt = (fmt or _infer_format(path)).lower()
    target = Path(path)
    if target.parent and not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)

    if fmt in ("html", "htm"):
        target.write_text(render_html(d), encoding="utf-8")
    elif fmt in ("txt", "text"):
        target.write_text(render_text(d), encoding="utf-8")
    elif fmt == "pdf":
        _write_pdf(d, str(target))
    else:
        raise ReportError("unknown report format %r (use html, txt, or pdf)" % fmt)
    return str(target)
