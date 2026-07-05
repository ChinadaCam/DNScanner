"""Stage 2 (start): TLS protocol audit via the standard-library ``ssl``.

Probes which TLS versions a server accepts and inspects the negotiated cipher for
forward secrecy. Full cipher-suite enumeration and vulnerability tests
(Heartbleed / POODLE / ROBOT, …) need sslyze / testssl.sh and are tracked in
FUTURE_ADDITIONS.md.

``evaluate_tls_audit`` is pure and unit-tested. The probes use stdlib ssl + socket
and degrade gracefully — a protocol the local OpenSSL cannot test is reported as
``null`` (never guessed).
"""
from __future__ import annotations

import socket
import ssl
from typing import Any, Dict, List, Optional

# display label -> ssl.TLSVersion attribute name
_VERSIONS = [("SSLv3", "SSLv3"), ("TLS1.0", "TLSv1"), ("TLS1.1", "TLSv1_1"),
             ("TLS1.2", "TLSv1_2"), ("TLS1.3", "TLSv1_3")]
_DEPRECATED = {"SSLv3", "TLS1.0", "TLS1.1"}
_FS_KX = ("ECDHE", "DHE")


def _supports(host: str, port: int, version_name: str, timeout: float) -> Optional[bool]:
    """True/False if the server accepts exactly this TLS version; ``None`` if the
    local OpenSSL cannot test it (e.g. old protocols compiled out)."""
    ver = getattr(ssl.TLSVersion, version_name, None)
    if ver is None:
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ver
        ctx.maximum_version = ver
    except (ValueError, OSError):
        return None
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except (ssl.SSLError, OSError):
        return False
    except Exception:
        return None


def _negotiated(host: str, port: int, timeout: float) -> Dict[str, Any]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher() or (None, None, None)
                name = cipher[0]
                return {"version": ssock.version(), "cipher": name,
                        "forward_secret": bool(name and any(k in name for k in _FS_KX))}
    except Exception as exc:
        return {"error": str(exc)}


def audit_tls(host: str, port: int = 443, timeout: float = 6.0) -> Dict[str, Any]:
    neg = _negotiated(host, port, timeout)
    if "version" not in neg:
        return {"reachable": False, "error": neg.get("error"), "protocols": {}, "negotiated": {}}
    protocols = {label: _supports(host, port, vname, timeout) for label, vname in _VERSIONS}
    return {"reachable": True, "protocols": protocols, "negotiated": neg}


def evaluate_tls_audit(audit: Dict[str, Any]) -> List[Dict[str, str]]:
    if not audit.get("reachable"):
        return []
    protocols = audit.get("protocols") or {}
    findings: List[Dict[str, str]] = []

    deprecated_on = sorted(p for p in _DEPRECATED if protocols.get(p) is True)
    if deprecated_on:
        findings.append({"id": "tls-deprecated-protocol",
                         "title": "Deprecated TLS protocol supported", "severity": "medium",
                         "detail": "Server accepts %s. TLS 1.0/1.1 were deprecated in 2021 and "
                                   "SSL Labs caps such servers to grade B." % ", ".join(deprecated_on),
                         "remediation": "Disable SSLv3 / TLS 1.0 / TLS 1.1; serve only TLS 1.2+.",
                         "reference": "RFC 8996"})

    neg = audit.get("negotiated") or {}
    if neg.get("cipher") and neg.get("forward_secret") is False:
        findings.append({"id": "tls-no-forward-secrecy", "title": "No forward secrecy",
                         "severity": "low",
                         "detail": "Negotiated cipher %s does not use ECDHE/DHE key exchange." % neg.get("cipher"),
                         "remediation": "Prefer ECDHE cipher suites for forward secrecy.",
                         "reference": "Mozilla TLS guidelines"})

    if protocols.get("TLS1.3") is True and not deprecated_on:
        findings.append({"id": "tls-modern", "title": "Modern TLS only", "severity": "info",
                         "detail": "TLS 1.3 supported and no deprecated protocols detected.",
                         "remediation": "", "reference": "RFC 8446 (TLS 1.3)"})
    return findings
