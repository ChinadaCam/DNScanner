"""DNScanner — a domain security-review engine and CLI.

Importing this package is side-effect free and does **not** require the optional
DNS/HTTP dependencies until you actually run a scan, so it is safe to embed in a
larger tool:

    from DNScanner import DNScanner, scan

    result = DNScanner("example.com").scan()
    data = result.to_dict()          # JSON-serializable, schema_version "1.0"
"""
from ._version import __version__
from .engine import DNScanner
from .models import Finding, ScanResult, Severity
from .report import render_html, write_report
from .resolver import Resolver
from .validation import InvalidDomainError, normalize_domain


def scan(domain: str, **kwargs):
    """Convenience wrapper: ``DNScanner(domain).scan(**kwargs)``."""
    return DNScanner(domain).scan(**kwargs)


__all__ = [
    "DNScanner",
    "Resolver",
    "ScanResult",
    "Finding",
    "Severity",
    "normalize_domain",
    "InvalidDomainError",
    "scan",
    "write_report",
    "render_html",
    "__version__",
]
