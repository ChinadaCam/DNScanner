"""Thin, lazily-imported wrapper around dnspython.

All DNS access in the package goes through here, giving the rest of the code a
small, mockable surface. ``dnspython`` is imported *inside* methods, so importing
this module (and the whole package) never requires it to be installed.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

DEFAULT_TIMEOUT = 5.0


class Resolver:
    """A configurable DNS resolver returning plain strings."""

    def __init__(self, nameservers: Optional[List[str]] = None,
                 timeout: float = DEFAULT_TIMEOUT):
        self.nameservers = nameservers
        self.timeout = timeout
        self._backend_resolver = None

    def _backend(self):
        if self._backend_resolver is None:
            import dns.resolver  # lazy
            res = dns.resolver.Resolver(configure=True)
            res.lifetime = self.timeout
            res.timeout = self.timeout
            if self.nameservers:
                res.nameservers = self.nameservers
            self._backend_resolver = res
        return self._backend_resolver

    def query(self, name: str, rtype: str) -> List[str]:
        """Return record data as strings; ``[]`` when there are no such records."""
        import dns.exception
        import dns.resolver
        try:
            answers = self._backend().resolve(name, rtype)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.DNSException):
            return []
        return [self._rdata_str(rtype, rd) for rd in answers]

    def query_with_ad(self, name: str, rtype: str) -> Tuple[List[str], bool]:
        """Like :meth:`query` but also returns the AD (authenticated-data) flag."""
        import dns.exception
        import dns.flags
        try:
            answer = self._backend().resolve(name, rtype, raise_on_no_answer=False)
            ad = bool(answer.response.flags & dns.flags.AD)
            records = [self._rdata_str(rtype, rd) for rd in answer] if answer.rrset else []
            return records, ad
        except dns.exception.DNSException:
            return [], False

    def reverse(self, ip: str) -> List[str]:
        """PTR lookup for an IP address."""
        try:
            import dns.reversename
            rev = dns.reversename.from_address(ip)
            return self.query(str(rev), "PTR")
        except Exception:
            return []

    def soa(self, name: str) -> Optional[dict]:
        """Structured SOA (mname/rname/serial/refresh/retry/expire/minimum) or None."""
        import dns.exception
        try:
            answer = self._backend().resolve(name, "SOA")
        except dns.exception.DNSException:
            return None
        for rd in answer:
            return {"mname": str(rd.mname).rstrip("."),
                    "rname": str(rd.rname).rstrip("."),
                    "serial": int(rd.serial), "refresh": int(rd.refresh),
                    "retry": int(rd.retry), "expire": int(rd.expire),
                    "minimum": int(rd.minimum)}
        return None

    @staticmethod
    def _rdata_str(rtype: str, rdata) -> str:
        rtype = rtype.upper()
        if rtype == "MX":
            return "%s %s" % (rdata.preference, str(rdata.exchange).rstrip("."))
        if rtype in ("NS", "CNAME", "PTR"):
            target = getattr(rdata, "target", rdata)
            return str(target).rstrip(".")
        if rtype == "TXT":
            try:
                return b"".join(rdata.strings).decode("utf-8", "replace")
            except Exception:
                return str(rdata).strip('"')
        if rtype == "SOA":
            return "%s %s" % (str(rdata.mname).rstrip("."), str(rdata.rname).rstrip("."))
        if rtype == "CAA":
            value = rdata.value.decode() if isinstance(rdata.value, bytes) else rdata.value
            tag = rdata.tag.decode() if isinstance(rdata.tag, bytes) else rdata.tag
            return '%s %s "%s"' % (rdata.flags, tag, value)
        return str(rdata).rstrip(".")
