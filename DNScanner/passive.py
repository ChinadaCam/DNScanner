"""Passive subdomain discovery via Certificate Transparency (crt.sh).

"Passive" because it queries public CT logs instead of brute-forcing or touching
the target. The parser/merge are pure; the HTTP fetch imports ``requests`` lazily.
"""
from __future__ import annotations

from typing import Any, Dict, List

__all__ = ["parse_crtsh", "parse_crtsh_wildcards", "crtsh_subdomains", "merge"]


def parse_crtsh(data: Any, domain: str) -> List[str]:
    """Extract unique sub-domains of ``domain`` from a crt.sh JSON response.

    crt.sh ``name_value`` fields can hold several names separated by newlines and
    may include wildcards (``*.example.com``); these are normalized away.
    """
    domain = (domain or "").strip(".").lower()
    names = set()
    for entry in data or []:
        if not isinstance(entry, dict):
            continue
        for field in ("name_value", "common_name"):
            value = entry.get(field) or ""
            for raw in str(value).split("\n"):
                name = raw.strip().lower().lstrip("*.").strip(".")
                if not name or "@" in name or " " in name:
                    continue
                if name != domain and name.endswith("." + domain):
                    names.add(name)
    return sorted(names)


def parse_crtsh_wildcards(data: Any, domain: str) -> List[str]:
    """Collect wildcard certificate names (``*.example.com``) seen in CT logs."""
    domain = (domain or "").strip(".").lower()
    wilds = set()
    for entry in data or []:
        if not isinstance(entry, dict):
            continue
        for field in ("name_value", "common_name"):
            for raw in str(entry.get(field) or "").split("\n"):
                name = raw.strip().lower().strip(".")
                if name.startswith("*.") and (name[2:] == domain or name[2:].endswith("." + domain)):
                    wilds.add(name)
    return sorted(wilds)


def crtsh_subdomains(domain: str, timeout: float = 12.0) -> Dict[str, Any]:
    """Query crt.sh for sub-domains of ``domain``. Never raises."""
    try:
        import requests  # lazy
    except Exception:
        return {"source": "crt.sh", "subdomains": [], "wildcards": [], "count": 0,
                "error": "requests not installed"}
    url = "https://crt.sh/?q=%25.{}&output=json".format(domain)
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "DNScanner"})
        data = resp.json()
    except Exception as exc:
        return {"source": "crt.sh", "subdomains": [], "wildcards": [], "count": 0, "error": str(exc)}
    names = parse_crtsh(data, domain)
    return {"source": "crt.sh", "subdomains": names,
            "wildcards": parse_crtsh_wildcards(data, domain), "count": len(names)}


def merge(active_found: List[Dict[str, Any]], passive_names: List[str]) -> List[Dict[str, Any]]:
    """Merge active (resolved, with IPs) and passive (name-only) results.

    Deduplicates by name; a name seen by both is tagged ``dns+ct``.
    """
    by_name: Dict[str, Dict[str, Any]] = {}
    for f in active_found or []:
        by_name[f["name"]] = {"name": f["name"], "ips": f.get("ips", []), "source": "dns"}
    for name in passive_names or []:
        if name in by_name:
            by_name[name]["source"] = "dns+ct"
        else:
            by_name[name] = {"name": name, "ips": [], "source": "ct"}
    return sorted(by_name.values(), key=lambda d: d["name"])
