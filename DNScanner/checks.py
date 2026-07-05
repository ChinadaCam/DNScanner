"""High-level domain checks. Each function returns plain JSON-able data.

``dnspython`` and ``requests`` are imported lazily (here or in :mod:`resolver`),
so importing this module needs no heavy dependencies. The resolver is passed in,
which makes every DNS-backed check trivially mockable in tests.
"""
from __future__ import annotations

import concurrent.futures
import random
import socket
import ssl
import string
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import email_modern as _modern
from . import email_security as _email
from . import netutil
from . import websec as _websec
from .resolver import Resolver

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "CNAME", "TXT", "SOA", "CAA"]

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


# --------------------------------------------------------------------------- #
# DNS records
# --------------------------------------------------------------------------- #
def get_records(domain: str, resolver: Resolver,
                rtypes: Optional[List[str]] = None) -> Dict[str, List[str]]:
    rtypes = rtypes or RECORD_TYPES
    return {rt.lower(): resolver.query(domain, rt) for rt in rtypes}


def resolved_ips(domain: str, resolver: Resolver) -> Dict[str, List[str]]:
    return {"a": resolver.query(domain, "A"),
            "aaaa": resolver.query(domain, "AAAA")}


def reverse_dns(ips: List[str], resolver: Resolver) -> Dict[str, List[str]]:
    return {ip: resolver.reverse(ip) for ip in ips}


# --------------------------------------------------------------------------- #
# Email authentication (SPF / DMARC / DKIM)
# --------------------------------------------------------------------------- #
_SPF_QUERY_CAP = 30  # hard safety bound on total DNS lookups during expansion


def _spf_record(name: str, resolver: Resolver) -> Optional[str]:
    for txt in resolver.query(name, "TXT"):
        t = str(txt).strip().strip('"')
        if t.lower().startswith("v=spf1"):
            return t
    return None


def spf_lookup_count(domain: str, resolver: Resolver) -> Dict[str, Any]:
    """Recursively expand SPF (include/redirect/a/mx/ptr/exists) and count
    DNS-querying mechanisms against RFC 7208's limit of 10 (+ 2 void lookups)."""
    visited: set = set()
    counters = {"dns_lookups": 0, "void_lookups": 0}

    def walk(name: str) -> None:
        if name in visited or counters["dns_lookups"] > _SPF_QUERY_CAP:
            return
        visited.add(name)
        record = _spf_record(name, resolver)
        if not record:
            return
        for tok in record.split()[1:]:
            mech = tok.lower().lstrip("+-~?")
            if mech.startswith("include:"):
                counters["dns_lookups"] += 1
                target = tok.split(":", 1)[1]
                if not _spf_record(target, resolver):
                    counters["void_lookups"] += 1
                walk(target)
            elif mech.startswith("redirect="):
                counters["dns_lookups"] += 1
                walk(tok.split("=", 1)[1])
            elif mech in ("a", "mx", "ptr") or mech.startswith(("a:", "mx:", "ptr:", "exists:")):
                counters["dns_lookups"] += 1

    walk(domain)
    exceeds = counters["dns_lookups"] > 10 or counters["void_lookups"] > 2
    return {"dns_lookups": counters["dns_lookups"],
            "void_lookups": counters["void_lookups"],
            "exceeds_limit": exceeds, "chain": sorted(visited)}


def email_security(domain: str, resolver: Resolver,
                   selectors: Optional[List[str]] = None) -> Dict[str, Any]:
    selectors = selectors or _email.DKIM_SELECTORS
    spf = _email.parse_spf(resolver.query(domain, "TXT"))
    if spf.get("present"):
        spf.update(spf_lookup_count(domain, resolver))
    dmarc = _email.parse_dmarc(resolver.query("_dmarc." + domain, "TXT"))

    dkim: List[Dict[str, Any]] = []
    for sel in selectors:
        parsed = _email.parse_dkim(
            sel, resolver.query("%s._domainkey.%s" % (sel, domain), "TXT")
        )
        if parsed["present"]:
            dkim.append(parsed)
    if not dkim:  # record that we looked, even if nothing was found
        dkim = [{"selector": selectors[0], "present": False, "record": None}]

    return {"spf": spf, "dmarc": dmarc, "dkim": dkim}


def modern_email(domain: str, resolver: Resolver, fetch: bool = True,
                 max_mx: int = 3) -> Dict[str, Any]:
    """MTA-STS / TLS-RPT / BIMI / DANE-TLSA detection. DANE is DNSSEC-gated via the
    TLSA query's AD flag. All lookups degrade gracefully (empty/None)."""
    mta = _modern.parse_mta_sts_txt(resolver.query("_mta-sts." + domain, "TXT"))
    if mta.get("present") and fetch:
        text = netutil.get_text_or_none(
            "https://mta-sts.%s/.well-known/mta-sts.txt" % domain, timeout=8.0)
        policy = _modern.parse_mta_sts_policy(text)
        mta.update({"mode": policy.get("mode"), "mx": policy.get("mx"),
                    "max_age": policy.get("max_age"), "policy_fetched": policy.get("fetched")})

    tls_rpt = _modern.parse_tls_rpt(resolver.query("_smtp._tls." + domain, "TXT"))
    bimi = _modern.parse_bimi(resolver.query("default._bimi." + domain, "TXT"))

    dane_records: List[str] = []
    authenticated = False
    checked: List[str] = []
    mx_hosts = [m.split()[-1].rstrip(".") for m in resolver.query(domain, "MX") if m][:max_mx]
    for host in mx_hosts:
        try:
            recs, ad = resolver.query_with_ad("_25._tcp.%s" % host, "TLSA")
        except Exception:
            recs, ad = [], False
        checked.append(host)
        if recs:
            dane_records += recs
            authenticated = authenticated or ad
    dane = _modern.parse_tlsa(dane_records, authenticated)
    dane["mx_checked"] = checked

    return {"mta_sts": mta, "tls_rpt": tls_rpt, "bimi": bimi, "dane": dane}


# --------------------------------------------------------------------------- #
# DNSSEC
# --------------------------------------------------------------------------- #
def dnssec(domain: str, resolver: Resolver) -> Dict[str, Any]:
    try:
        dnskey, ad = resolver.query_with_ad(domain, "DNSKEY")
    except Exception:
        dnskey, ad = [], False
    ds = resolver.query(domain, "DS")
    return {"enabled": bool(dnskey) or bool(ds),
            "dnskey_count": len(dnskey),
            "ds_present": bool(ds),
            "authenticated_data": ad}


# --------------------------------------------------------------------------- #
# Zone transfer (AXFR)
# --------------------------------------------------------------------------- #
def zone_transfer(domain: str, nameservers: List[str],
                  timeout: float = 5.0) -> Dict[str, Any]:
    """Attempt AXFR against each NS. A successful transfer is a serious finding."""
    try:
        import dns.query  # lazy
        import dns.zone
    except Exception:
        return {"tested": False, "vulnerable_servers": [], "error": "dnspython missing"}

    vulnerable: List[str] = []
    details: Dict[str, int] = {}
    for ns in nameservers:
        host = ns.rstrip(".")
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(host, domain, lifetime=timeout))
            vulnerable.append(host)
            details[host] = len(list(zone.nodes.keys()))
        except Exception:
            continue
    return {"tested": True, "vulnerable_servers": vulnerable,
            "records_per_server": details}


# --------------------------------------------------------------------------- #
# TLS certificate
# --------------------------------------------------------------------------- #
def tls_certificate(domain: str, port: int = 443,
                    timeout: float = 5.0) -> Dict[str, Any]:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
    except Exception as exc:
        return {"reachable": False, "error": str(exc)}

    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    not_after = cert.get("notAfter")
    days = None
    try:
        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (exp - datetime.now(timezone.utc)).days
    except Exception:
        pass
    sans = [v for (k, v) in cert.get("subjectAltName", []) if k.lower() == "dns"]
    return {"reachable": True,
            "subject": subject.get("commonName"),
            "issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "not_after": not_after, "days_to_expiry": days, "san": sans,
            "valid": days is None or days > 0}


# --------------------------------------------------------------------------- #
# HTTP security headers
# --------------------------------------------------------------------------- #
def http_security(domain: str, timeout: float = 6.0) -> Dict[str, Any]:
    try:
        import requests  # lazy
    except Exception:
        return {"reachable": False, "error": "requests missing"}

    for scheme in ("https://", "http://"):
        try:
            resp = requests.get(scheme + domain, timeout=timeout, allow_redirects=True)
        except Exception:
            continue
        headers = {k.lower(): v for k, v in resp.headers.items()}
        present = {label: headers[h] for h, label in SECURITY_HEADERS.items() if h in headers}
        missing = [label for h, label in SECURITY_HEADERS.items() if h not in headers]
        try:
            set_cookies = resp.raw.headers.getlist("Set-Cookie")
        except Exception:
            sc = resp.headers.get("Set-Cookie")
            set_cookies = [sc] if sc else []
        sectxt = netutil.get_text_or_none(
            "%s%s/.well-known/security.txt" % (scheme, domain), timeout=timeout)
        return {"reachable": True, "url": resp.url, "status_code": resp.status_code,
                "final_scheme": scheme.split(":", 1)[0],
                "present": present, "missing": missing,
                "csp": _websec.parse_csp(headers.get("content-security-policy")),
                "cookies": _websec.parse_cookies(set_cookies),
                "security_txt": _websec.parse_security_txt(sectxt)}
    return {"reachable": False, "error": "no HTTP(S) response"}


# --------------------------------------------------------------------------- #
# Reachability (cross-platform, no ICMP/privileges needed)
# --------------------------------------------------------------------------- #
def tcp_reachable(host: str, ports=(443, 80), timeout: float = 4.0) -> Dict[str, Any]:
    results: Dict[int, bool] = {}
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                results[port] = True
        except Exception:
            results[port] = False
    return {"reachable": any(results.values()), "ports": results}


# --------------------------------------------------------------------------- #
# WHOIS / RDAP (normalized to a flat set of key fields)
# --------------------------------------------------------------------------- #
def whois(ip: str, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
    """Look up an IP's registration data and return a flat, readable dict.

    Prefers RDAP (richer/structured); falls back to legacy WHOIS. Returns
    ``{"ip": ip, "error": ...}`` rather than raising when a lookup fails.
    """
    if not ip:
        return None
    try:
        from ipwhois import IPWhois  # lazy
    except Exception:
        return {"ip": ip, "error": "ipwhois not installed"}
    try:
        return normalize_rdap(ip, IPWhois(ip, timeout=timeout).lookup_rdap(depth=1))
    except Exception:
        try:
            return normalize_legacy_whois(ip, IPWhois(ip, timeout=timeout).lookup_whois())
        except Exception as exc:
            return {"ip": ip, "error": str(exc)}


def normalize_rdap(ip: str, data: Dict[str, Any]) -> Dict[str, Any]:
    data = data or {}
    net = data.get("network") or {}
    events = {e.get("action"): e.get("timestamp")
              for e in (net.get("events") or []) if isinstance(e, dict)}
    abuse_email = None
    registrant = None
    for obj in (data.get("objects") or {}).values():
        roles = obj.get("roles") or []
        contact = obj.get("contact") or {}
        emails = [e.get("value") for e in (contact.get("email") or []) if e.get("value")]
        if "abuse" in roles and emails and not abuse_email:
            abuse_email = emails[0]
        if not registrant and ({"registrant", "administrative"} & set(roles)):
            registrant = contact.get("name") or obj.get("handle")
    start, end = net.get("start_address"), net.get("end_address")
    return {
        "ip": ip,
        "source": "rdap",
        "asn": data.get("asn"),
        "asn_description": data.get("asn_description"),
        "asn_registry": data.get("asn_registry"),
        "asn_country": data.get("asn_country_code"),
        "asn_cidr": data.get("asn_cidr"),
        "network_name": net.get("name"),
        "network_cidr": net.get("cidr"),
        "network_country": net.get("country"),
        "network_range": ("%s - %s" % (start, end)) if start and end else None,
        "abuse_email": abuse_email,
        "registrant": registrant,
        "created": events.get("registration"),
        "updated": events.get("last changed"),
    }


def normalize_legacy_whois(ip: str, data: Dict[str, Any]) -> Dict[str, Any]:
    data = data or {}
    nets = data.get("nets") or [{}]
    n0 = nets[0] or {}
    emails = n0.get("emails") or []
    return {
        "ip": ip,
        "source": "whois",
        "asn": data.get("asn"),
        "asn_description": data.get("asn_description"),
        "asn_registry": data.get("asn_registry"),
        "asn_country": data.get("asn_country_code"),
        "asn_cidr": data.get("asn_cidr"),
        "network_name": n0.get("name"),
        "network_cidr": n0.get("cidr"),
        "network_country": n0.get("country"),
        "network_range": n0.get("range"),
        "abuse_email": emails[0] if emails else None,
        "registrant": n0.get("description"),
        "created": n0.get("created"),
        "updated": n0.get("updated"),
    }


# --------------------------------------------------------------------------- #
# Geolocation (IP -> location, via the free ip-api.com endpoint)
# --------------------------------------------------------------------------- #
_IPAPI_FIELDS = "status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,query"


def geolocation(ip: str, timeout: float = 6.0) -> Dict[str, Any]:
    if not ip:
        return {"ip": ip, "error": "no IP to locate"}
    try:
        import requests  # lazy
    except Exception:
        return {"ip": ip, "error": "requests not installed"}
    url = "http://ip-api.com/json/%s?fields=%s" % (ip, _IPAPI_FIELDS)
    try:
        return parse_ipapi(ip, requests.get(url, timeout=timeout).json())
    except Exception as exc:
        return {"ip": ip, "error": str(exc), "source": "ip-api.com"}


def parse_ipapi(ip: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Pure parser for an ip-api.com JSON response (unit-testable)."""
    if not isinstance(data, dict) or data.get("status") != "success":
        message = (data or {}).get("message", "lookup failed") if isinstance(data, dict) else "bad response"
        return {"ip": ip, "error": message, "source": "ip-api.com"}
    return {
        "ip": ip,
        "source": "ip-api.com",
        "country": data.get("country"),
        "country_code": data.get("countryCode"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "lat": data.get("lat"),
        "lon": data.get("lon"),
        "isp": data.get("isp"),
        "org": data.get("org"),
        "asn": data.get("as"),
    }


# --------------------------------------------------------------------------- #
# Subdomain enumeration (DNS-based, concurrent, wildcard-aware)
# --------------------------------------------------------------------------- #
def _random_label(n: int = 12) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def detect_wildcard(domain: str, resolver: Resolver) -> Dict[str, Any]:
    """A zone has a wildcard if a random label resolves."""
    ips = resolver.query("%s.%s" % (_random_label(), domain), "A")
    return {"wildcard": bool(ips), "wildcard_ips": sorted(ips)}


def enumerate_subdomains(domain: str, words: List[str], resolver: Resolver,
                         threads: int = 20) -> Dict[str, Any]:
    wc = detect_wildcard(domain, resolver)
    wildcard_ips = set(wc["wildcard_ips"])
    candidates = [w.strip() for w in words if w and w.strip()]

    def _check(word: str) -> Optional[Dict[str, Any]]:
        host = "%s.%s" % (word, domain)
        ips = resolver.query(host, "A")
        if not ips:
            return None
        if wc["wildcard"] and set(ips) == wildcard_ips:
            return None  # indistinguishable from the wildcard answer
        return {"name": host, "ips": sorted(ips), "source": "dns"}

    found: List[Dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        for res in pool.map(_check, candidates):
            if res:
                found.append(res)
    found.sort(key=lambda d: d["name"])
    return {"wildcard": wc["wildcard"], "wildcard_ips": sorted(wildcard_ips),
            "tested": len(candidates), "found": found}
