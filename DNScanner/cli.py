"""Command-line front-end for DNScanner.

Backward compatible with the original flags, plus:
  * ``--json``         machine-readable single JSON object (no banners)
  * ``-S/--security``  one-shot full security scan
  * ``--email/--tls/--http/--dnssec/--axfr/-txt``  individual security checks
"""
from __future__ import annotations

import argparse
import os
import sys

import click

from . import report
from . import reporting as _report
from ._version import __version__
from .config import Config
from .engine import DEFAULT_CHECKS, EXTENDED_CHECKS, STANDARD_CHECKS, DNScanner

LIGHT_CHECKS = ["records", "reachability", "email", "dnssec"]

BANNER = (
    "------------------------------------------------\n"
    "   DNScanner %s\n"
    "   Domain security review  -  by Tiago Faustino\n"
    "------------------------------------------------" % __version__
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dnscanner",
        description="Scan domains for DNS & security posture. "
                    "https://github.com/ChinadaCam/DNScanner",
    )
    p.add_argument("-d", "--domain", help="Target domain (example.com)")
    p.add_argument("-m", "--menu", action="store_true",
                   help="Launch the interactive menu (default when no args)")
    p.add_argument("--json", action="store_true",
                   help="Emit one JSON result object (machine-readable, no banners)")
    p.add_argument("-S", "--security", action="store_true",
                   help="Extended scan (all checks incl. AXFR, takeover, reputation)")
    p.add_argument("-A", "--all", action="store_true", help="Alias for --security/--extended")
    p.add_argument("--extended", action="store_true", help="Extended scan (alias for -S)")
    p.add_argument("--standard", action="store_true",
                   help="Standard scan (fast, target-only; no AXFR/takeover/reputation)")
    p.add_argument("--checks", metavar="LIST",
                   help="Comma-separated custom check set (e.g. records,email,tls)")
    # individual record toggles
    p.add_argument("-mx", "--mxrecords", action="store_true", help="MX records")
    p.add_argument("-ns", "--Nameserver", action="store_true", help="NS records")
    p.add_argument("-cn", "--cname", action="store_true", help="CNAME records")
    p.add_argument("-txt", "--txt", action="store_true", help="TXT records")
    # individual security toggles
    p.add_argument("--email", action="store_true", help="Email security (SPF/DMARC/DKIM)")
    p.add_argument("--dnssec", action="store_true", help="DNSSEC status")
    p.add_argument("--tls", action="store_true", help="TLS certificate")
    p.add_argument("--http", action="store_true", help="HTTP security headers")
    p.add_argument("--axfr", action="store_true", help="Zone-transfer (AXFR) test")
    p.add_argument("-W", "--whois", action="store_true", help="WHOIS (clean)")
    p.add_argument("-WJ", "--whoisJ", action="store_true", help="WHOIS (JSON)")
    p.add_argument("--geo", action="store_true", help="IP geolocation (country/city/ISP)")
    p.add_argument("-cS", "--subdomains", "--checkSubdomains", dest="subdomains",
                   action="store_true", help="Subdomain discovery (active brute force)")
    p.add_argument("--passive", action="store_true",
                   help="Passive subdomain discovery via crt.sh (CT logs)")
    p.add_argument("--takeover", action="store_true",
                   help="Check for subdomain takeover (dangling CNAMEs)")
    p.add_argument("--wordlist", help="Custom subdomain wordlist path")
    p.add_argument("--report", metavar="PATH",
                   help="Write a report to PATH (.html, .txt, or .pdf)")
    p.add_argument("--report-format", choices=["html", "txt", "pdf"],
                   help="Force report format (otherwise inferred from the extension)")
    p.add_argument("-O", "--Output", nargs="?", const="",
                   help="Write output to a file (optionally pass a directory)")
    p.add_argument("-D", "--Directory", help="Directory for -O output")
    p.add_argument("--timeout", type=float, default=5.0,
                   help="Per-query timeout in seconds (default: 5)")
    p.add_argument("--no-color", action="store_true", help="Disable colored output")
    p.add_argument("--version", action="version", version="DNScanner " + __version__)
    return p


def _selected_checks(args) -> list:
    if args.security or args.all:
        return list(DEFAULT_CHECKS)
    checks = []
    if args.mxrecords or args.Nameserver or args.cname or args.txt:
        checks.append("records")
    if args.email:
        checks.append("email")
    if args.dnssec:
        checks.append("dnssec")
    if args.tls:
        checks.append("tls")
    if args.http:
        checks.append("http")
    if args.axfr:
        checks.extend(["axfr", "records"])
    if args.whois or args.whoisJ:
        checks.append("whois")
    if args.geo:
        checks.append("geo")
    if args.takeover:
        checks.append("takeover")
    return checks or list(STANDARD_CHECKS)


def _resolve_profile(args):
    """Return (checks_list, profile_name) from the profile flags / custom checks."""
    if args.checks:
        return [c.strip() for c in args.checks.split(",") if c.strip()], "custom"
    if args.security or args.all or args.extended:
        return list(EXTENDED_CHECKS), "extended"
    if args.standard:
        return list(STANDARD_CHECKS), "standard"
    individual = any([args.mxrecords, args.Nameserver, args.cname, args.txt, args.email,
                      args.dnssec, args.tls, args.http, args.axfr, args.whois, args.whoisJ,
                      args.geo, args.takeover])
    return _selected_checks(args), ("custom" if individual else "standard")


def main(argv=None):
    args = build_parser().parse_args(argv)

    # No domain (or -m) -> interactive menu.
    if args.menu or not args.domain:
        from .menu import run_menu
        run_menu(args.domain)
        return

    if args.no_color:
        os.environ["NO_COLOR"] = "1"

    scanner = DNScanner(args.domain, timeout=args.timeout)
    cfg = Config.load()
    checks, profile = _resolve_profile(args)

    # ---- report mode (html / txt / pdf) ----------------------------------
    if args.report:
        result = scanner.scan(checks=checks, include_subdomains=args.subdomains,
                              passive=args.passive, wordlist=args.wordlist,
                              config=cfg, profile=profile)
        try:
            path = report.write_report(result, args.report, args.report_format)
            click.secho("[+] Report written to %s" % path, fg="green")
        except report.ReportError as exc:
            click.secho("[!] %s" % exc, fg="red")
        if args.json:
            sys.stdout.write(result.to_json() + "\n")
        return

    # ---- machine-readable mode -------------------------------------------
    if args.json:
        result = scanner.scan(checks=checks, include_subdomains=args.subdomains,
                              passive=args.passive, wordlist=args.wordlist,
                              config=cfg, profile=profile)
        sys.stdout.write(result.to_json() + "\n")
        return

    # ---- human mode ------------------------------------------------------
    redirected = False
    if args.Output is not None:
        scanner.output(args.Directory or (args.Output or None))
        redirected = True

    try:
        click.secho(BANNER, fg="cyan")
        use_profile = bool(args.standard or args.security or args.all or args.extended or args.checks)
        record_or_whois = any([args.mxrecords, args.Nameserver, args.cname,
                               args.txt, args.whois, args.whoisJ, args.geo,
                               args.subdomains, args.passive])
        security = [c for c, on in (("email", args.email), ("dnssec", args.dnssec),
                                    ("tls", args.tls), ("http", args.http),
                                    ("axfr", args.axfr), ("takeover", args.takeover)) if on]

        if use_profile or not (record_or_whois or security):
            result = scanner.scan(
                checks=checks, include_subdomains=args.subdomains, passive=args.passive,
                wordlist=args.wordlist, config=cfg, profile=profile)
            _report.render_result(result)
        else:
            if args.mxrecords:
                scanner.getMX()
            if args.Nameserver:
                scanner.getNS()
            if args.cname:
                scanner.getCN()
            if args.txt:
                scanner.getTXT()
            if args.whois:
                scanner.whoIs()
            if args.whoisJ:
                scanner.whoIsJson()
            if args.geo:
                scanner.getGeo()
            if args.subdomains or args.passive:
                if args.passive:
                    _report.render_result(scanner.scan(
                        checks=[], include_subdomains=args.subdomains, passive=True, config=cfg))
                else:
                    scanner.getSubdomains(args.wordlist)
            if security:
                if "axfr" in security:
                    security.append("records")
                result = scanner.scan(checks=security, config=cfg, profile="custom")
                _report.render_result(result)
        click.secho("\n[+] Finished", fg="green")
    finally:
        if redirected:
            scanner.restore_output()
            click.secho("[+] Saved to %s" % scanner.outputpath, fg="green")


if __name__ == "__main__":
    main()
