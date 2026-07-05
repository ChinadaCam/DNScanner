"""Structured, JSON-serializable result models for a scan.

The parent OSINT/pentest tool consumes :meth:`ScanResult.to_dict` /
:meth:`ScanResult.to_json` directly — this is the stable integration contract.
Pure stdlib only.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = "1.1"


class Severity:
    """Finding severities, ordered so callers can sort/aggregate."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    _ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}

    @classmethod
    def rank(cls, severity: str) -> int:
        return cls._ORDER.get(severity, 0)


@dataclass
class Finding:
    """A single security-relevant observation."""
    id: str
    title: str
    severity: str = Severity.INFO
    detail: str = ""
    remediation: str = ""
    reference: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """Everything a scan produced about one domain."""
    domain: str
    schema_version: str = SCHEMA_VERSION
    scanned_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    duration_ms: int = 0
    scan_profile: Optional[str] = None
    checks_run: List[str] = field(default_factory=list)
    resolved_ips: Dict[str, List[str]] = field(default_factory=dict)
    records: Dict[str, Any] = field(default_factory=dict)
    whois: Optional[Dict[str, Any]] = None
    geolocation: List[Dict[str, Any]] = field(default_factory=list)
    email_security: Dict[str, Any] = field(default_factory=dict)
    dnssec: Dict[str, Any] = field(default_factory=dict)
    zone_transfer: Dict[str, Any] = field(default_factory=dict)
    tls: Optional[Dict[str, Any]] = None
    tls_audit: Dict[str, Any] = field(default_factory=dict)
    http: Dict[str, Any] = field(default_factory=dict)
    reachability: Dict[str, Any] = field(default_factory=dict)
    subdomains: Dict[str, Any] = field(default_factory=dict)
    takeover: List[Dict[str, Any]] = field(default_factory=list)
    reputation: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    score: Dict[str, Any] = field(default_factory=dict)

    # ---- mutation helpers ------------------------------------------------
    def add_finding(self, id: str, title: str,
                    severity: str = Severity.INFO, detail: str = "",
                    remediation: str = "", reference: str = "") -> None:
        self.findings.append(
            Finding(id=id, title=title, severity=severity, detail=detail,
                    remediation=remediation, reference=reference)
        )

    def add_findings(self, finding_dicts: List[Dict[str, str]]) -> None:
        for f in finding_dicts or []:
            self.add_finding(
                id=f.get("id", "finding"),
                title=f.get("title", ""),
                severity=f.get("severity", Severity.INFO),
                detail=f.get("detail", ""),
                remediation=f.get("remediation", ""),
                reference=f.get("reference", ""),
            )

    def add_error(self, message: str) -> None:
        self.errors.append(str(message))

    @property
    def highest_severity(self) -> str:
        if not self.findings:
            return Severity.INFO
        return max((f.severity for f in self.findings), key=Severity.rank)

    # ---- serialization ---------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)
