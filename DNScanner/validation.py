"""Domain input validation and normalization.

Pure / stdlib (plus optional ``idna``). No DNS or network here.
"""
from __future__ import annotations

import re

__all__ = ["normalize_domain", "is_valid_domain", "InvalidDomainError"]

# One DNS label: 1-63 chars, alphanumeric or hyphen, not starting/ending with '-'.
_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_HOSTNAME_RE = re.compile(r"^(?:%s\.)+%s$" % (_LABEL, _LABEL))


class InvalidDomainError(ValueError):
    """Raised when a string cannot be interpreted as a domain name."""


def normalize_domain(raw: str) -> str:
    """Normalize arbitrary user input into a bare, DNS-ready domain.

    Strips scheme, credentials, path/query/fragment, port, whitespace and a
    trailing dot; lowercases; and IDNA-encodes unicode to punycode. Raises
    :class:`InvalidDomainError` on empty or malformed input.

    >>> normalize_domain("https://www.Example.com:443/path?x=1")
    'www.example.com'
    """
    if raw is None:
        raise InvalidDomainError("no domain provided")
    domain = str(raw).strip()
    if not domain:
        raise InvalidDomainError("empty domain")
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    if "@" in domain:                       # strip user:pass@
        domain = domain.split("@", 1)[1]
    for sep in ("/", "?", "#"):             # strip path/query/fragment
        domain = domain.split(sep, 1)[0]
    domain = domain.split(":", 1)[0]        # strip port
    domain = domain.strip().strip(".").lower()
    if not domain:
        raise InvalidDomainError("no host found in input: %r" % (raw,))

    domain = _to_ascii(domain)

    if not is_valid_domain(domain):
        raise InvalidDomainError("not a valid domain: %r" % (domain,))
    return domain


def _to_ascii(domain: str) -> str:
    """Best-effort IDNA/punycode encoding; returns input unchanged on failure."""
    try:
        import idna  # optional dependency, imported lazily
        return idna.encode(domain, uts46=True).decode("ascii")
    except Exception:
        try:
            return domain.encode("idna").decode("ascii")
        except Exception:
            return domain


def is_valid_domain(domain: str) -> bool:
    """Return True if ``domain`` is a syntactically valid hostname (<=253 chars)."""
    if not domain or len(domain) > 253:
        return False
    return bool(_HOSTNAME_RE.match(domain))
