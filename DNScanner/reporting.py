"""Console rendering of scan data. Presentation only — no scanning here."""
from __future__ import annotations

from typing import Dict, List

import click

from .models import ScanResult

_SEV_COLOR = {"info": "cyan", "low": "yellow", "medium": "bright_red", "high": "red"}
_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def section(title: str) -> None:
    click.secho("\n#----- %s -----#" % title, fg="blue", bold=True)


def _items(values: List[str]) -> None:
    if not values:
        click.secho("  (none)", fg="bright_black")
        return
    for i, value in enumerate(values, 1):
        click.echo("  (%d) %s" % (i, value))


def render_records(records: Dict[str, object]) -> None:
    for rtype, values in records.items():
        if rtype in ("caa_parsed", "soa_parsed"):
            continue  # structured detail lives in the JSON + findings
        click.secho("%s:" % rtype.upper(), bold=True)
        if isinstance(values, dict):  # e.g. PTR map {ip: [names]}
            for key, vals in values.items():
                shown = ", ".join(vals) if isinstance(vals, (list, tuple)) else str(vals)
                click.echo("  %s -> %s" % (key, shown))
        else:
            _items(values)


def render_findings(findings) -> None:
    issues = [f for f in findings if f.severity in ("high", "medium", "low")]
    passed = [f for f in findings if f.severity not in ("high", "medium", "low")]

    section("ISSUES TO FIX (%d)" % len(issues))
    if not issues:
        click.secho("  None - nothing needs attention.", fg="green")
    else:
        for f in sorted(issues, key=lambda x: _SEV_ORDER.get(x.severity, 9)):
            click.secho("  [%s] %s" % (f.severity.upper(), f.title),
                        fg=_SEV_COLOR.get(f.severity, "white"), bold=True)
            if f.detail:
                click.echo("        %s" % f.detail)
            if getattr(f, "remediation", ""):
                click.secho("        Fix: %s" % f.remediation, fg="green")

    if passed:
        section("PASSED CHECKS (%d)" % len(passed))
        for f in passed:
            click.secho("  [OK] %s" % f.title, fg="cyan")
            if f.detail:
                click.echo("        %s" % f.detail)


def render_whois(w: dict) -> None:
    if not w:
        click.echo("  (no data)")
        return
    if w.get("error"):
        click.secho("  lookup failed: %s" % w["error"], fg="yellow")
        return
    rows = [
        ("ASN", w.get("asn")),
        ("ASN org", w.get("asn_description")),
        ("Registry", w.get("asn_registry")),
        ("ASN country", w.get("asn_country")),
        ("Network", w.get("network_name")),
        ("CIDR", w.get("network_cidr") or w.get("asn_cidr")),
        ("Range", w.get("network_range")),
        ("Country", w.get("network_country")),
        ("Abuse", w.get("abuse_email")),
        ("Registrant", w.get("registrant")),
        ("Created", w.get("created")),
        ("Updated", w.get("updated")),
    ]
    for label, value in rows:
        if value:
            click.echo("  %-13s %s" % (label + ":", value))


def render_geo(geos) -> None:
    if not geos:
        click.echo("  (no data)")
        return
    for g in geos:
        ip = g.get("ip", "?")
        if g.get("error"):
            click.secho("  %s: %s" % (ip, g["error"]), fg="yellow")
            continue
        place = ", ".join(p for p in (g.get("city"), g.get("region"), g.get("country")) if p)
        click.echo("  %s -> %s" % (ip, place or "unknown"))
        extra = []
        if g.get("lat") is not None and g.get("lon") is not None:
            extra.append("%s,%s" % (g["lat"], g["lon"]))
        if g.get("isp"):
            extra.append("ISP: %s" % g["isp"])
        if g.get("asn"):
            extra.append(g["asn"])
        if extra:
            click.echo("       %s" % " | ".join(extra))


def render_result(result: ScanResult) -> None:
    click.secho("=" * 52, fg="cyan")
    click.secho(" DNScanner report: %s" % result.domain, fg="cyan", bold=True)
    click.secho("=" * 52, fg="cyan")

    sc = result.score or {}
    if sc:
        b = sc.get("breakdown", {})
        gcolor = {"A+": "green", "A": "green", "B": "yellow", "C": "yellow",
                  "D": "red", "F": "red"}.get(sc.get("grade"), "white")
        click.secho("  Security posture: %s  (%s/100)   high:%s  medium:%s  low:%s"
                    % (sc.get("grade"), sc.get("score"), b.get("high", 0),
                       b.get("medium", 0), b.get("low", 0)), fg=gcolor, bold=True)

    if result.resolved_ips:
        section("IP ADDRESSES")
        click.secho("A:", bold=True)
        _items(result.resolved_ips.get("a", []))
        click.secho("AAAA:", bold=True)
        _items(result.resolved_ips.get("aaaa", []))

    if result.records:
        section("DNS RECORDS")
        render_records(result.records)

    if result.email_security:
        section("EMAIL SECURITY")
        es = result.email_security
        click.echo("  SPF:   %s" % (es.get("spf", {}).get("record") or "missing"))
        click.echo("  DMARC: %s" % (es.get("dmarc", {}).get("record") or "missing"))
        dkim = [d["selector"] for d in es.get("dkim", []) if d.get("present")]
        click.echo("  DKIM:  %s" % (", ".join(dkim) if dkim else "none found"))
        mta = es.get("mta_sts") or {}
        click.echo("  MTA-STS: %s" % ((mta.get("mode") or "present") if mta.get("present") else "missing"))
        click.echo("  TLS-RPT: %s  |  BIMI: %s" % (
            "present" if (es.get("tls_rpt") or {}).get("present") else "missing",
            "present" if (es.get("bimi") or {}).get("present") else "missing"))
        dane = es.get("dane") or {}
        if dane.get("present"):
            click.echo("  DANE:  present (%s)" % ("DNSSEC-validated" if dane.get("dnssec_protected")
                                                  else "not protected without DNSSEC"))

    if result.dnssec:
        section("DNSSEC")
        click.echo("  enabled: %s | DS present: %s | authenticated: %s" % (
            result.dnssec.get("enabled"), result.dnssec.get("ds_present"),
            result.dnssec.get("authenticated_data")))

    if result.tls:
        section("TLS CERTIFICATE")
        t = result.tls
        if t.get("reachable"):
            click.echo("  issuer:  %s" % t.get("issuer"))
            click.echo("  expires: %s (%s days)" % (t.get("not_after"), t.get("days_to_expiry")))
            if t.get("san"):
                click.echo("  SAN:     %s" % ", ".join(t["san"][:8]))
        else:
            click.echo("  not reachable: %s" % t.get("error"))

    ta = result.tls_audit or {}
    if ta.get("reachable"):
        section("TLS PROTOCOLS")
        protos = ta.get("protocols") or {}
        click.echo("  supported: %s" % (", ".join(p for p, v in protos.items() if v is True) or "?"))
        neg = ta.get("negotiated") or {}
        if neg.get("version"):
            click.echo("  negotiated: %s / %s%s" % (neg.get("version"), neg.get("cipher"),
                                                    " (FS)" if neg.get("forward_secret") else " (no FS)"))

    if result.http:
        section("HTTP SECURITY HEADERS")
        h = result.http
        if h.get("reachable"):
            click.echo("  %s -> %s" % (h.get("url"), h.get("status_code")))
            click.echo("  present: %s" % (", ".join(h.get("present", {}).keys()) or "none"))
            click.echo("  missing: %s" % (", ".join(h.get("missing", [])) or "none"))
            csp = h.get("csp") or {}
            if csp.get("present"):
                click.echo("  CSP:     present%s" % ((" — weak: " + ", ".join(csp.get("weaknesses", [])))
                                                     if csp.get("weaknesses") else ", no obvious weakness"))
            cookies = h.get("cookies") or {}
            if cookies.get("issues"):
                click.echo("  cookies: %s" % "; ".join(cookies["issues"]))
            st = h.get("security_txt") or {}
            click.echo("  security.txt: %s" % (("present" + (" (EXPIRED)" if st.get("expired") else ""))
                                               if st.get("present") else "missing"))
        else:
            click.echo("  not reachable: %s" % h.get("error"))

    if result.zone_transfer:
        section("ZONE TRANSFER (AXFR)")
        zt = result.zone_transfer
        if zt.get("vulnerable_servers"):
            click.secho("  VULNERABLE: %s" % ", ".join(zt["vulnerable_servers"]),
                        fg="red", bold=True)
        elif zt.get("tested"):
            click.secho("  not vulnerable", fg="green")
        else:
            click.echo("  not tested (%s)" % zt.get("error", ""))

    if result.subdomains:
        section("SUBDOMAINS")
        sd = result.subdomains
        click.echo("  wildcard: %s | active: %s | passive: %s | found: %s" % (
            sd.get("wildcard"), sd.get("active"), sd.get("passive"), len(sd.get("found", []))))
        for f in sd.get("found", []):
            click.echo("  - %s [%s] %s" % (f["name"], f.get("source", "?"),
                                           ", ".join(f.get("ips", [])) or "-"))

    if result.takeover:
        section("SUBDOMAIN TAKEOVER")
        for t in result.takeover:
            click.secho("  [%s] %s -> %s (%s)" % (
                (t.get("confidence") or "?").upper(), t.get("hostname"),
                t.get("cname"), t.get("service")),
                fg="red" if t.get("vulnerable") else "yellow")

    if result.reputation:
        section("REPUTATION")
        rep = result.reputation
        sh = rep.get("spamhaus") or {}
        click.echo("  Spamhaus DBL:  %s" % ("LISTED (%s)" % ", ".join(sh.get("codes", []))
                                            if sh.get("listed") else (sh.get("status") or "n/a")))
        vt = rep.get("virustotal") or {}
        click.echo("  VirusTotal:    %s" % (("%s malicious" % vt.get("malicious"))
                                            if vt.get("status") == "ok" else (vt.get("status") or "n/a")))
        sb = rep.get("safebrowsing") or {}
        click.echo("  Safe Browsing: %s" % ("LISTED" if sb.get("listed")
                                            else (sb.get("status") or "n/a")))

    if result.geolocation:
        section("GEOLOCATION")
        render_geo(result.geolocation)

    if result.whois:
        section("WHOIS")
        render_whois(result.whois)

    render_findings(result.findings)

    if result.errors:
        section("ERRORS")
        for err in result.errors:
            click.secho("  %s" % err, fg="yellow")


def to_json(result: ScanResult, indent: int = 2) -> str:
    return result.to_json(indent=indent)
