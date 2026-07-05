# FUTURE_ADDITIONS

Items intentionally **not** built in the Stage 1 pass, parked here per the plan.

## Deferred within Stage 1 (passive)

- **A-record → released-cloud-IP takeover.** Full detection needs current cloud
  provider IP-range data (AWS/Azure/GCP published ranges) to tell a released elastic
  IP from a live one. Today takeover covers the CNAME case; the A-record and
  NS-delegation cases are only lightly signalled.
- **NS-delegation (lame delegation) takeover confirmation.** Detecting an abandoned
  delegated nameserver reliably (and safely) needs more than the current passive check.
- **More passive asset sources.** Censys, SecurityTrails, DNSdumpster, RapidDNS,
  AlienVault OTX (API-keyed) to complement crt.sh.
- **DKIM depth.** Enumerate/display multiple selectors and key details; handle SPF
  macro (`%{...}`) edge cases in the lookup counter.

## Stage 2 — deeper passive + light active (not in scope now)

- **Full TLS audit** — protocol enumeration + forward-secrecy flagging are **done**
  (`tlsaudit.py`, stdlib `ssl`). Remaining (needs sslyze / testssl.sh): full cipher-suite
  enumeration + weak-cipher flagging, known-vuln tests (Heartbleed, POODLE, ROBOT, …),
  chain/OCSP, HSTS-preload eligibility, and testing all TLS-wrapped mail ports
  (465/587/993/995/636).
- **Technology fingerprinting** (WhatWeb/Wappalyzer-style) → CVE mapping.
- **WAF / CDN / cloud-provider detection + ASN/CIDR mapping.**
- **Typosquatting / homograph** (dnstwist) and **newly-registered-domain** monitoring.
- **A–F scoring engine** — **done** (`score.py`); could be refined toward SSL Labs /
  Mozilla Observatory-style category weighting.
- **HTML/CSV/PDF board reports and historical diffing** (alert on new subdomains,
  new dangling records, grade regressions, unexpected CT certs).

## Stage 3 — active / intrusive (opt-in, authorization-gated, rate-limited)

- Port scanning / banner grabbing.
- Content discovery (`/.git`, `/.env`, admin panels, backups).
- Open-resolver / DNS-amplification testing.
- SMTP open-relay / STARTTLS testing.

> Guidance: if DNScanner will be run against third-party domains the operator does
> not own, keep Stage 3 disabled by default and surface a legal/authorization warning.
> The existing `warn_before_impactful` config option and the menu confirmation prompt
> are the seam to build that gating on.
