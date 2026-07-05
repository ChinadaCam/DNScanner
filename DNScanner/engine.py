"""The DNScanner engine: orchestration plus a structured ``scan()`` API.

Importing this module has **no side effects** and requires **no heavy
dependencies** — dnspython / ipwhois / requests are pulled in lazily only when a
scan actually runs. The class also keeps the legacy print-style methods so the
interactive menu and older callers keep working.
"""
from __future__ import annotations

import json
import logging
import socket
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import click

from . import checks as _checks
from . import dns_records as _dns_records
from . import email_modern as _email_modern
from . import email_security as _email
from . import passive as _passive
from . import posture as _posture
from . import reporting as _report
from . import reputation as _reputation
from . import score as _score
from . import takeover as _takeover
from . import tlsaudit as _tlsaudit
from . import websec as _websec
from .models import ScanResult, Severity
from .resolver import DEFAULT_TIMEOUT, Resolver
from .validation import InvalidDomainError, normalize_domain

log = logging.getLogger("dnscanner")

# Scan profiles. STANDARD is fast and target-only (no third-party APIs / AXFR /
# takeover). EXTENDED adds the heavier, third-party-touching passive checks.
STANDARD_CHECKS = ["records", "email", "dnssec", "tls", "http", "reachability", "whois", "geo"]
EXTENDED_CHECKS = STANDARD_CHECKS + ["axfr", "takeover", "reputation", "tls_audit"]
DEFAULT_CHECKS = EXTENDED_CHECKS
_PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_WORDLIST = _PACKAGE_DIR / "Others" / "wordlists" / "subdomainlist.txt"
_UNSET = object()


class DNScanner:
    """Scan one domain. Use :meth:`scan` for structured data, or the legacy
    print methods for the interactive/CLI experience."""

    def __init__(self, url: str, resolver: Optional[Resolver] = None,
                 timeout: float = DEFAULT_TIMEOUT):
        try:
            self.domain = normalize_domain(url)
        except InvalidDomainError:
            self.domain = str(url or "").strip().lower()
        self.url = self.domain
        self.timeout = timeout
        self.resolver = resolver or Resolver(timeout=timeout)
        self._ip = _UNSET
        # legacy-compat attributes
        self.mxlist: List[str] = []
        self.CurrentDate = datetime.now().strftime("%d-%b-%Y_%H-%M-%S")
        self.formatedDate = datetime.now().strftime("%d/%b/%Y %H:%M:%S")
        self.savesys = sys.stdout
        self.outputpath = ""
        self.subdomainspath = str(DEFAULT_WORDLIST)
        self.subdomainbool = False

    @property
    def ip(self) -> Optional[str]:
        """First A record (resolved lazily, cached, ``None`` on failure)."""
        if self._ip is _UNSET:
            try:
                self._ip = socket.gethostbyname(self.domain)
            except Exception:
                self._ip = None
        return self._ip

    # ===================================================================
    #  Structured API  (what the parent tool consumes)
    # ===================================================================
    def scan(self, checks: Optional[List[str]] = None, *,
             include_subdomains: bool = False,
             passive: bool = False,
             wordlist: Optional[str] = None,
             selectors: Optional[List[str]] = None,
             threads: int = 20,
             config=None,
             profile: Optional[str] = None) -> ScanResult:
        selected = set(checks if checks is not None else DEFAULT_CHECKS)
        if config is not None:
            selected = {c for c in selected if config.is_enabled(c)}
        result = ScanResult(domain=self.domain)
        result.scan_profile = profile
        result.checks_run = (sorted(selected)
                             + (["subdomains"] if include_subdomains else [])
                             + (["passive"] if passive else []))
        res = self.resolver
        started = time.time()
        ns_list: List[str] = []
        a_ips: List[str] = []

        need_records = bool(selected & {"records", "reverse", "axfr"}) or include_subdomains
        if need_records:
            try:
                result.resolved_ips = _checks.resolved_ips(self.domain, res)
                a_ips = result.resolved_ips.get("a", [])
                result.records = _checks.get_records(self.domain, res)
                ns_list = result.records.get("ns", [])
                if not a_ips and not result.resolved_ips.get("aaaa"):
                    result.add_finding("no-a", "Domain does not resolve",
                                       Severity.HIGH, "No A/AAAA records returned.",
                                       remediation="Publish A/AAAA records so the domain resolves.",
                                       reference="RFC 1035")
                if "records" in selected:
                    result.records["caa_parsed"] = _dns_records.parse_caa(
                        result.records.get("caa") or [])
                    result.records["soa_parsed"] = _dns_records.parse_soa(res.soa(self.domain))
                    result.add_findings(_dns_records.evaluate_caa(result.records["caa_parsed"]))
                    result.add_findings(_dns_records.evaluate_soa(result.records["soa_parsed"]))
            except Exception as exc:
                result.add_error("records: %s" % exc)

        if "reverse" in selected and a_ips:
            try:
                result.records["ptr"] = _checks.reverse_dns(a_ips, res)
            except Exception as exc:
                result.add_error("reverse: %s" % exc)

        if "email" in selected:
            try:
                es = _checks.email_security(self.domain, res, selectors)
                es.update(_checks.modern_email(self.domain, res))
                result.email_security = es
                result.add_findings(_email.evaluate_email_security(
                    es["spf"], es["dmarc"], es["dkim"]))
                result.add_findings(_email_modern.evaluate_modern_email(es))
            except Exception as exc:
                result.add_error("email: %s" % exc)

        if "dnssec" in selected:
            try:
                result.dnssec = _checks.dnssec(self.domain, res)
                if not result.dnssec.get("enabled"):
                    result.add_finding("dnssec-missing", "DNSSEC not enabled",
                                       Severity.MEDIUM,
                                       "Zone is unsigned; responses cannot be cryptographically validated.",
                                       remediation="Sign the zone with DNSSEC and add a DS record at the registrar.",
                                       reference="RFC 4033-4035")
            except Exception as exc:
                result.add_error("dnssec: %s" % exc)

        if "axfr" in selected and ns_list:
            try:
                zt = _checks.zone_transfer(self.domain, ns_list, timeout=self.timeout)
                result.zone_transfer = zt
                if zt.get("vulnerable_servers"):
                    result.add_finding("axfr", "Zone transfer (AXFR) allowed",
                                       Severity.HIGH,
                                       "Nameservers allowed a full zone transfer: %s"
                                       % ", ".join(zt["vulnerable_servers"]),
                                       remediation="Restrict zone transfers to authorized secondary nameservers only.",
                                       reference="RFC 5936")
            except Exception as exc:
                result.add_error("axfr: %s" % exc)

        if "tls" in selected:
            try:
                result.tls = _checks.tls_certificate(self.domain, timeout=self.timeout)
                days = result.tls.get("days_to_expiry")
                if result.tls.get("reachable") and days is not None:
                    if days < 0:
                        result.add_finding("tls-expired", "TLS certificate expired",
                                           Severity.HIGH, "Expired %d days ago." % -days,
                                           remediation="Renew the TLS certificate immediately.",
                                           reference="RFC 5280")
                    elif days < 15:
                        result.add_finding("tls-expiring", "TLS certificate expiring soon",
                                           Severity.MEDIUM, "Expires in %d days." % days,
                                           remediation="Renew or rotate the certificate before it expires.",
                                           reference="RFC 5280")
            except Exception as exc:
                result.add_error("tls: %s" % exc)

        if "tls_audit" in selected:
            try:
                result.tls_audit = _tlsaudit.audit_tls(self.domain, timeout=self.timeout + 2)
                result.add_findings(_tlsaudit.evaluate_tls_audit(result.tls_audit))
            except Exception as exc:
                result.add_error("tls_audit: %s" % exc)

        if "http" in selected:
            try:
                result.http = _checks.http_security(self.domain, timeout=self.timeout + 1)
                if result.http.get("reachable"):
                    missing = result.http.get("missing", [])
                    if "HSTS" in missing:
                        result.add_finding("hsts-missing", "Missing HSTS header",
                                           Severity.MEDIUM, "No Strict-Transport-Security header.",
                                           remediation="Send Strict-Transport-Security with a long max-age.",
                                           reference="RFC 6797")
                    other = [m for m in missing if m != "HSTS"]
                    if other:
                        result.add_finding("headers-missing", "Missing security headers",
                                           Severity.LOW, "Missing: %s" % ", ".join(other),
                                           remediation="Add the missing response security headers.",
                                           reference="OWASP Secure Headers Project")
                    result.add_findings(_websec.evaluate_websec(result.http))
            except Exception as exc:
                result.add_error("http: %s" % exc)

        if "reachability" in selected:
            try:
                result.reachability = _checks.tcp_reachable(self.domain, timeout=self.timeout)
                if not result.reachability.get("reachable"):
                    result.add_finding("unreachable", "Host not reachable on 80/443",
                                       Severity.INFO, "No TCP connection on common web ports.",
                                       remediation="Ensure the host accepts TCP on 80/443 if it is meant to be web-facing.",
                                       reference="RFC 9293")
            except Exception as exc:
                result.add_error("reachability: %s" % exc)

        if "whois" in selected:
            try:
                result.whois = self._whois_data()
            except Exception as exc:
                result.add_error("whois: %s" % exc)

        if "geo" in selected:
            try:
                geo_ips = a_ips or ([self.ip] if self.ip else [])
                result.geolocation = [_checks.geolocation(ip, timeout=self.timeout)
                                      for ip in dict.fromkeys(geo_ips)]
            except Exception as exc:
                result.add_error("geo: %s" % exc)

        if "reputation" in selected:
            try:
                result.reputation = _reputation.reputation(
                    self.domain, res, config=config, timeout=self.timeout + 3)
                result.add_findings(_reputation.evaluate_reputation(result.reputation))
            except Exception as exc:
                result.add_error("reputation: %s" % exc)

        if include_subdomains or passive:
            try:
                active = {"found": [], "wildcard": False, "wildcard_ips": [], "tested": 0}
                if include_subdomains:
                    words = _read_wordlist(wordlist or self.subdomainspath)
                    active = _checks.enumerate_subdomains(self.domain, words, res, threads=threads)
                passive_names = []
                ct_wildcards = []
                if passive:
                    ct = _passive.crtsh_subdomains(self.domain, timeout=max(self.timeout, 10))
                    passive_names = ct.get("subdomains", [])
                    ct_wildcards = ct.get("wildcards", [])
                result.subdomains = {
                    "wildcard": active.get("wildcard", False),
                    "wildcard_ips": active.get("wildcard_ips", []),
                    "tested": active.get("tested", 0),
                    "active": len(active.get("found", [])),
                    "passive": len(passive_names),
                    "ct_wildcards": ct_wildcards,
                    "found": _passive.merge(active.get("found", []), passive_names),
                }
            except Exception as exc:
                result.add_error("subdomains: %s" % exc)

        if "takeover" in selected:
            try:
                exclude_same_org = (bool(config.option("takeover_same_org_exclusion", False))
                                    if config is not None else False)
                hosts = [self.domain] + [f["name"] for f in (result.subdomains.get("found") or [])]
                tk = []
                for host in list(dict.fromkeys(hosts))[:100]:
                    r = _takeover.check_takeover(host, res, fetch=True, timeout=self.timeout,
                                                 exclude_same_org=exclude_same_org)
                    if not r.get("service"):
                        continue
                    tk.append(r)
                    src = "%s %s" % (r.get("fingerprint_source"), r.get("fingerprint_date"))
                    if r.get("vulnerable"):
                        result.add_finding(
                            "takeover", "Subdomain takeover: %s" % r["service"], Severity.HIGH,
                            "%s -> %s is claimable on %s. Requires manual validation (fingerprint: %s)."
                            % (host, r["cname"], r["service"], src),
                            remediation="Remove the dangling DNS record or reclaim the resource.",
                            reference="OWASP WSTG: Test for Subdomain Takeover")
                    elif r.get("confidence") == "potential":
                        result.add_finding(
                            "takeover-potential", "Possible subdomain takeover: %s" % r["service"],
                            Severity.MEDIUM,
                            "%s -> %s points to %s; verify manually (fingerprint: %s)."
                            % (host, r["cname"], r["service"], src),
                            remediation="Confirm the service is unclaimed, then remove or reclaim it.",
                            reference="OWASP WSTG: Test for Subdomain Takeover")
                result.takeover = tk
            except Exception as exc:
                result.add_error("takeover: %s" % exc)

        result.add_findings(_posture.derive_findings(result))
        result.score = _score.compute_score(result)
        result.duration_ms = int((time.time() - started) * 1000)
        return result

    def _whois_data(self) -> Optional[Dict[str, Any]]:
        return _checks.whois(self.ip, timeout=self.timeout)

    # ===================================================================
    #  Legacy / presentation methods (menu + old callers)
    # ===================================================================
    def records(self, rtypes=None) -> Dict[str, List[str]]:
        return _checks.get_records(self.domain, self.resolver, rtypes)

    def getInfo(self):
        ips = _checks.resolved_ips(self.domain, self.resolver)
        _report.section("IP ADDRESSES")
        click.secho("A:", bold=True)
        _report._items(ips.get("a", []))
        click.secho("AAAA:", bold=True)
        _report._items(ips.get("aaaa", []))
        return ips

    def getMX(self):
        vals = self.resolver.query(self.domain, "MX")
        _report.section("MX RECORDS")
        _report._items(vals)
        return vals

    def getNS(self):
        vals = self.resolver.query(self.domain, "NS")
        _report.section("NAMESERVERS")
        _report._items(vals)
        return vals

    def getCN(self):
        vals = self.resolver.query(self.domain, "CNAME")
        _report.section("CANONICAL NAMES")
        _report._items(vals)
        return vals

    def getTXT(self):
        vals = self.resolver.query(self.domain, "TXT")
        _report.section("TXT RECORDS")
        _report._items(vals)
        return vals

    def emailSecurity(self):
        es = _checks.email_security(self.domain, self.resolver)
        _report.section("EMAIL SECURITY")
        click.echo("  SPF:   %s" % (es["spf"].get("record") or "missing"))
        click.echo("  DMARC: %s" % (es["dmarc"].get("record") or "missing"))
        dkim = [d["selector"] for d in es["dkim"] if d.get("present")]
        click.echo("  DKIM:  %s" % (", ".join(dkim) if dkim else "none found"))
        for f in _email.evaluate_email_security(es["spf"], es["dmarc"], es["dkim"]):
            click.secho("  [%s] %s" % (f["severity"].upper(), f["detail"]), fg="yellow")
        return es

    def whoIs(self):
        _report.section("WHOIS")
        _report.render_whois(self._whois_data())

    def whoIsJson(self):
        _report.section("WHOIS (JSON)")
        click.echo(json.dumps(self._whois_data(), indent=2, default=str))

    def getGeo(self):
        a_ips = _checks.resolved_ips(self.domain, self.resolver).get("a") or []
        ips = a_ips or ([self.ip] if self.ip else [])
        geos = [_checks.geolocation(ip, timeout=self.timeout) for ip in dict.fromkeys(ips)]
        _report.section("GEOLOCATION")
        _report.render_geo(geos)
        return geos

    def urlStatus(self):
        reach = _checks.tcp_reachable(self.domain, timeout=self.timeout)
        if reach["reachable"]:
            open_ports = ",".join(str(p) for p, ok in reach["ports"].items() if ok)
            click.secho("\n%s reachable (TCP %s)" % (self.domain, open_ports), fg="green")
        else:
            click.secho("\n%s not reachable on 80/443" % self.domain, fg="red")
        return reach

    def getSubdomains(self, path=None):
        words = _read_wordlist(path or self.subdomainspath)
        _report.section("SUBDOMAINS")
        click.secho("Scanning %d candidates (Ctrl+C to stop)..." % len(words), fg="yellow")
        try:
            data = _checks.enumerate_subdomains(self.domain, words, self.resolver)
        except KeyboardInterrupt:
            click.secho("\nStopped.", fg="yellow")
            return {}
        if data.get("wildcard"):
            click.secho("  (wildcard DNS detected: %s)" % ", ".join(data["wildcard_ips"]),
                        fg="bright_black")
        for f in data.get("found", []):
            click.echo("  %s -> %s" % (f["name"], ", ".join(f["ips"])))
        if not data.get("found"):
            click.secho("  none found", fg="bright_black")
        return data

    def fullScan(self, include_subdomains: bool = False) -> ScanResult:
        result = self.scan(include_subdomains=include_subdomains)
        _report.render_result(result)
        return result

    def start(self):
        click.secho("#----- Initial Process -----#", fg="blue", bold=True)
        click.secho("Process started at %s" % self.formatedDate)
        self.urlStatus()
        self.getInfo()
        if self.subdomainbool:
            self.getSubdomains(self.subdomainspath)

    # ---- file output / dirs (cross-platform) ---------------------------
    def output(self, path=None):
        directory = Path(path) if path else (_PACKAGE_DIR / "Others" / "Discovers")
        directory.mkdir(parents=True, exist_ok=True)
        filename = directory / ("DNScanner-%s.txt" % self.CurrentDate)
        self.outputpath = str(filename)
        sys.stdout = open(filename, "a", encoding="utf-8")
        return self.outputpath

    def restore_output(self):
        if sys.stdout is not self.savesys:
            try:
                sys.stdout.close()
            except Exception:
                pass
            sys.stdout = self.savesys

    def dirList(self, add=None):
        base = _PACKAGE_DIR / "Others"
        for directory in (base, base / "Discovers", base / "wordlists", _PACKAGE_DIR / "logs"):
            Path(directory).mkdir(parents=True, exist_ok=True)

    def logger(self, importance, text):
        logdir = _PACKAGE_DIR / "logs"
        logdir.mkdir(parents=True, exist_ok=True)
        with open(logdir / ("ScanLog-%s.txt" % self.CurrentDate), "a", encoding="utf-8") as fh:
            fh.write("%s | %s\n" % (importance, text))


def _read_wordlist(path) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]
    except OSError:
        return []
