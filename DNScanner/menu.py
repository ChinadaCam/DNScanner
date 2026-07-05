"""Interactive (menu-driven) front-end for DNScanner.

Alternative to the flag-based CLI in :mod:`DNScanner.cli`. Pick a domain, then
choose actions from a looped menu — including the new security checks and a
JSON export. The flag CLI stays the scripting/automation path.
"""
from __future__ import annotations

import contextlib
import os
import socket
from datetime import datetime
from pathlib import Path

import click

from . import report
from . import reporting as _report
from ._version import __version__
from .config import IMPACTFUL_CHECKS, Config
from .engine import DEFAULT_WORDLIST, EXTENDED_CHECKS, STANDARD_CHECKS, DNScanner
from .validation import InvalidDomainError, normalize_domain

RESULTS_DIR = Path(__file__).resolve().parent / "Others" / "Discovers"

BANNER = """\
------------------------------------------------
   DNScanner %s  -  interactive menu
   Domain security review  -  by Tiago Faustino
------------------------------------------------""" % __version__


# --------------------------------------------------------------------------- #
# Domain prompt
# --------------------------------------------------------------------------- #
def _prepare(raw):
    try:
        return normalize_domain(raw)
    except InvalidDomainError:
        return None


def _resolves(domain) -> bool:
    try:
        socket.gethostbyname(domain)
        return True
    except OSError:
        return False


def prompt_domain(current=None):
    while True:
        try:
            raw = click.prompt("Target domain%s (or 'q' to cancel)"
                               % ((" [%s]" % current) if current else ""),
                               default=current or "", show_default=False)
        except (EOFError, KeyboardInterrupt):
            return None
        if raw.strip().lower() in ("q", "quit", "exit"):
            return None
        domain = _prepare(raw)
        if not domain:
            click.secho("[!] That doesn't look like a valid domain.", fg="yellow")
            continue
        if not _resolves(domain):
            click.secho("[!] '%s' does not resolve — scanning anyway may return little."
                        % domain, fg="yellow")
        return domain


# --------------------------------------------------------------------------- #
# Action helpers
# --------------------------------------------------------------------------- #
def _confirm_impactful(cfg, checks) -> bool:
    """Warn before checks that touch third-party infra (AXFR/takeover/reputation)."""
    if not cfg.option("warn_before_impactful", True):
        return True
    hits = sorted(set(checks) & IMPACTFUL_CHECKS)
    if not hits:
        return True
    click.secho("[!] This runs impactful/third-party checks: %s" % ", ".join(hits), fg="yellow")
    click.secho("    AXFR probes nameservers; takeover fetches CNAME targets; "
                "reputation calls external APIs.", fg="bright_black")
    try:
        answer = click.prompt("    Continue? [y/N]", default="n", show_default=False)
    except (EOFError, KeyboardInterrupt):
        return False
    return answer.strip().lower() in ("y", "yes")


def _scan_section(checks):
    def runner(scanner, cfg):
        if _confirm_impactful(cfg, checks):
            _report.render_result(scanner.scan(checks=list(checks), config=cfg, profile="custom"))
    return runner


def _profile_scan(scanner, cfg, checks, profile):
    if not _confirm_impactful(cfg, checks):
        return
    passive = profile == "extended" and cfg.option("ct_default_in_extended", True)
    _report.render_result(scanner.scan(checks=list(checks), passive=passive,
                                       config=cfg, profile=profile))


def _export_json(scanner, cfg):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%d-%b-%Y_%H-%M-%S")
    path = RESULTS_DIR / ("DNScanner-%s-%s.json" % (scanner.domain, stamp))
    path.write_text(scanner.scan(config=cfg).to_json(), encoding="utf-8")
    click.secho("[+] Full scan exported to %s" % path, fg="green")


def _export_report(scanner, cfg):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%d-%b-%Y_%H-%M-%S")
    path = RESULTS_DIR / ("DNScanner-%s-%s.html" % (scanner.domain, stamp))
    report.write_report(scanner.scan(config=cfg), str(path))
    click.secho("[+] HTML report written to %s" % path, fg="green")


def _settings_menu(cfg):
    all_checks = sorted(set(STANDARD_CHECKS) | set(EXTENDED_CHECKS))
    while True:
        click.secho("\n=== Settings ===", fg="cyan")
        click.echo("  1. Enable/disable checks")
        click.echo("  2. API keys (VirusTotal, Safe Browsing)")
        click.echo("  3. Same-org takeover exclusion: %s"
                   % ("ON" if cfg.option("takeover_same_org_exclusion") else "off"))
        click.echo("  4. Warn before impactful actions: %s"
                   % ("ON" if cfg.option("warn_before_impactful", True) else "off"))
        click.echo("  5. Show config file path")
        click.echo("  0. Back (save)")
        try:
            ch = click.prompt("Settings", default="0", show_default=False).strip()
        except (EOFError, KeyboardInterrupt):
            ch = "0"
        if ch == "0":
            click.secho("[+] Saved to %s" % cfg.save(), fg="green")
            return
        if ch == "1":
            for c in all_checks:
                click.echo("   %-14s %s" % (c, "enabled" if cfg.is_enabled(c) else "DISABLED"))
            name = click.prompt("Toggle which check (blank to cancel)",
                                default="", show_default=False).strip()
            if name in all_checks:
                cfg.set_enabled(name, not cfg.is_enabled(name))
                click.secho("   %s -> %s" % (name, "enabled" if cfg.is_enabled(name) else "disabled"),
                            fg="green")
        elif ch == "2":
            vt = click.prompt("VirusTotal API key (blank keeps current)",
                              default="", show_default=False).strip()
            if vt:
                cfg.set_api_key("virustotal", vt)
            sb = click.prompt("Safe Browsing API key (blank keeps current)",
                              default="", show_default=False).strip()
            if sb:
                cfg.set_api_key("safebrowsing", sb)
            click.secho("   keys updated (environment variables still take precedence)", fg="green")
        elif ch == "3":
            cfg.set_option("takeover_same_org_exclusion",
                           not cfg.option("takeover_same_org_exclusion"))
        elif ch == "4":
            cfg.set_option("warn_before_impactful",
                           not cfg.option("warn_before_impactful", True))
        elif ch == "5":
            click.echo("   %s" % cfg.path)


# key -> (label, callable(scanner, cfg))
ACTIONS = {
    "1": ("Extended scan — all checks (email, DNSSEC, TLS, HTTP, AXFR, takeover, reputation)",
          lambda s, c: _profile_scan(s, c, EXTENDED_CHECKS, "extended")),
    "2": ("Standard scan — fast, target-only (no AXFR/takeover/reputation)",
          lambda s, c: _profile_scan(s, c, STANDARD_CHECKS, "standard")),
    "3": ("IP addresses (A / AAAA)", lambda s, c: s.getInfo()),
    "4": ("MX records", lambda s, c: s.getMX()),
    "5": ("NS records", lambda s, c: s.getNS()),
    "6": ("CNAME records", lambda s, c: s.getCN()),
    "7": ("TXT records", lambda s, c: s.getTXT()),
    "8": ("Email security (SPF / DMARC / DKIM + MTA-STS / DANE)", lambda s, c: s.emailSecurity()),
    "9": ("DNSSEC status", _scan_section(["dnssec"])),
    "10": ("TLS certificate", _scan_section(["tls"])),
    "11": ("HTTP + web security (headers, CSP, cookies, security.txt)", _scan_section(["http"])),
    "12": ("Zone transfer (AXFR) test", _scan_section(["axfr", "records"])),
    "13": ("WHOIS (registration / abuse contact)", lambda s, c: s.whoIs()),
    "14": ("Geolocation (IP -> country/city/ISP)", lambda s, c: s.getGeo()),
    "15": ("Reputation (Spamhaus / VirusTotal / Safe Browsing)", _scan_section(["reputation"])),
    "16": ("Subdomain discovery (active brute force)", lambda s, c: s.getSubdomains()),
    "17": ("Passive subdomains (crt.sh / CT logs)",
           lambda s, c: _report.render_result(s.scan(checks=[], passive=True, config=c))),
    "18": ("Subdomain takeover check", _scan_section(["takeover"])),
    "19": ("Reachability (TCP 80/443)", lambda s, c: s.urlStatus()),
    "20": ("Export full scan to JSON file", _export_json),
    "21": ("Export HTML report", _export_report),
}


def _run(action, save, label):
    try:
        if save:
            RESULTS_DIR.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now().strftime("%d-%b-%Y_%H-%M-%S")
            path = RESULTS_DIR / ("DNScanner-%s-%s.txt" % (label, stamp))
            with open(path, "w", encoding="utf-8") as fh, contextlib.redirect_stdout(fh):
                action()
            click.secho("\n[+] Saved output to %s" % path, fg="green")
        else:
            action()
    except (KeyboardInterrupt, SystemExit):
        click.secho("\n[!] Action stopped.", fg="yellow")
    except Exception as exc:  # keep the menu alive on any scan error
        click.secho("\n[!] Error in '%s': %s" % (label, exc), fg="red")


def _print_menu(domain, save):
    state = click.style("ON", fg="green") if save else click.style("off", fg="bright_black")
    click.secho("\nDomain: %s   |   Save-to-file: %s"
                % (click.style(domain, fg="cyan"), state))
    click.secho("-" * 52)
    for key, (text, _) in ACTIONS.items():
        click.echo("  %2s. %s" % (key, text))
    click.echo("   g. Settings (checks, API keys, options)")
    click.echo("   s. Toggle save-to-file")
    click.echo("   c. Change domain")
    click.echo("   0. Exit")


def run_menu(initial_domain=None):
    click.secho(BANNER, fg="cyan")

    domain = _prepare(initial_domain) if initial_domain else None
    if not domain:
        domain = prompt_domain()
    if not domain:
        click.secho("Nothing to do. Bye!", fg="yellow")
        return

    scanner = DNScanner(domain)
    cfg = Config.load()
    save = False
    while True:
        _print_menu(domain, save)
        try:
            choice = click.prompt("Select", default="0", show_default=False).strip().lower()
        except (EOFError, KeyboardInterrupt):
            click.secho("\nExiting.", fg="yellow")
            return

        if choice in ("0", "q", "quit", "exit"):
            click.secho("\n[+] Finished. Bye!", fg="green")
            return
        if choice == "s":
            save = not save
            continue
        if choice in ("g", "settings"):
            _settings_menu(cfg)
            continue
        if choice == "c":
            new_domain = prompt_domain(current=domain)
            if new_domain:
                domain = new_domain
                scanner = DNScanner(domain)
            continue

        action = ACTIONS.get(choice)
        if not action:
            click.secho("[!] Invalid choice.", fg="yellow")
            continue
        _, func = action
        _run(lambda: func(scanner, cfg), save, label=choice)


if __name__ == "__main__":
    import sys
    run_menu(sys.argv[1] if len(sys.argv) > 1 else None)
