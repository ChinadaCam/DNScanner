
 <h1 align="center"> DNScanner </h1>
<h2 align="center">Domain DNS &amp; security review — CLI, interactive menu, and importable module</h2>

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]

<!-- TABLE OF CONTENTS -->
## Table of Contents

* [About The Project](#about-the-project)
* [Features](#features)
* [Getting Started](#getting-started)
  * [Prerequisites](#prerequisites)
  * [Installation](#installation)
* [Usage](#usage)
  * [Command line](#command-line)
  * [Interactive menu](#interactive-menu)
  * [JSON output](#json-output)
  * [As a library](#as-a-library)
* [Configuration](#configuration)
* [Roadmap](#roadmap)
* [License](#license)
* [Contact](#contact)

<img width="963" height="1301" alt="image" src="https://github.com/user-attachments/assets/4522217b-898c-4f07-ae63-66abd8bd6927" />


<!-- ABOUT THE PROJECT -->
## About The Project

DNScanner automates a domain's DNS and security review. It started as a module for a
larger OSINT/pentest tool and is built to be used **three ways**:

1. a flag-based **CLI** (`dnscanner` / `python3 start.py`),
2. an **interactive menu** (run with no arguments), and
3. an **importable Python module** that returns a structured, JSON-serializable result
   so a parent tool can embed it without parsing console output.

Importing the package is side-effect free and pulls in DNS/HTTP dependencies lazily, so
it is cheap and safe to embed. Scans run under one of two **profiles** — `standard`
(fast, target-only) or `extended` (adds the heavier, third-party-touching checks) and a
persisted config lets you enable/disable individual checks and supply API keys.

## Features

DNS & resolution
* A / AAAA, MX, NS, CNAME, TXT, SOA, CAA records
* **CAA & SOA parsing** — CAA split into `issue` / `issuewild` / `iodef` (flags an
  "any CA may issue" posture); SOA checked against the RFC 1912 expire range
* Reverse DNS (PTR) for resolved IPs
* WHOIS / RDAP — **normalized key fields** (ASN, network, abuse contact, created/updated), clean or JSON
* IP **geolocation** (country, city, ISP / ASN)
* Subdomain discovery — **active** (concurrent, wildcard-aware) and **passive** (crt.sh / CT logs)

Security posture
* **Email authentication:** SPF (incl. permissive `all` / >10-lookup checks), DMARC
  (policy/`rua`), DKIM (common selectors)
* **DNSSEC** status (DNSKEY/DS, AD flag)
* **Zone transfer (AXFR)** test against each nameserver
* **TLS certificate** (issuer, expiry countdown, SANs)
* **HTTP security headers** (HSTS, CSP, X-Frame-Options, …)
* **Subdomain takeover** detection — dangling CNAMEs matched against ~15 known-service
  fingerprints (S3, GitHub Pages, Heroku, Azure, Shopify, …) with optional error-page confirmation
* Cross-platform TCP reachability (no root/ICMP needed)
* Every finding is tagged with a **severity** (`info`/`low`/`medium`/`high`) and carries a
  one-line **remediation** and a governing **reference** (RFC / OWASP)
* **Domain reputation** (VirusTotal / Google Safe Browsing) — *reserved*: the config and
  key handling are in place; results land in a later release

Profiles & integration
* Two **scan profiles** — `standard` (records, email, DNSSEC, TLS, HTTP, reachability,
  WHOIS, geo) and `extended` (standard + AXFR, takeover, reputation)
* Persisted **config**: turn checks off, set options, and supply **env-first API keys**
* One JSON result object with `schema_version` `1.1` — the stable contract for the parent tool
* `--json` flag for machine-readable output; `from DNScanner import DNScanner` for direct use
* Reports: HTML / text (no deps) or PDF (with reportlab) via `--report` or `write_report()`

<!-- GETTING STARTED -->
## Getting Started

### Prerequisites

Python 3.7+ and pip.

### Installation

```sh
git clone https://github.com/ChinadaCam/DNScanner.git
cd DNScanner
pip install -r requirements.txt
# optional: install the `dnscanner` console command
pip install -e .
# optional: PDF reports
pip install -e ".[report]"
```

## Usage

### Command line

```sh
# Quick review (records + reachability + email + DNSSEC)
python3 start.py -d example.com

# Full extended scan (records, email, DNSSEC, TLS, HTTP, reachability, WHOIS, geo, AXFR, takeover)
python3 start.py -d example.com -S

# Individual checks
python3 start.py -d example.com -ns                 # nameservers
python3 start.py -d example.com --email             # SPF/DMARC/DKIM
python3 start.py -d example.com --tls --http        # TLS + security headers
python3 start.py -d example.com --geo               # IP geolocation
python3 start.py -d example.com -cS --passive       # active + passive (crt.sh) subdomains
python3 start.py -d example.com --takeover          # subdomain-takeover check

# Save a run to a file, or set a custom timeout
python3 start.py -d example.com -S -O results/ --timeout 8

# Generate a report — format inferred from the extension (or forced with --report-format)
python3 start.py -d example.com -S --report report.html
python3 start.py -d example.com -S --report report.pdf   # PDF needs: pip install "dnscanner[report]"

python3 start.py --version
```

If installed with `pip install -e .`, use `dnscanner` instead of `python3 start.py`.

### Interactive menu

Run with no arguments (or `-m`) to get a guided menu — full scan, per-record and
per-security checks, active/passive subdomains, takeover, reachability, plus
JSON and HTML export:

```sh
python3 start.py
```

### JSON output

`--json` prints a single result object (`schema_version` `1.1`) and nothing else — ideal
for piping into other tools:

```sh
python3 start.py -d example.com -S --json > example.json
```

### As a library

```python
from DNScanner import DNScanner

# The default scan runs the "extended" check set; pass checks=[...] to narrow it.
result = DNScanner("example.com").scan(
    checks=["records", "email", "dnssec", "tls", "http", "axfr"],
    include_subdomains=False,
)

data = result.to_dict()              # JSON-serializable, schema_version "1.1"
print(data["checks_run"])            # exactly which checks ran (vs. "ran, found nothing")
for f in result.findings:            # f.severity in info|low|medium|high
    print(f.severity, f.title, "—", f.remediation, f.reference)
```

The result is the stable integration contract: every key is additive across `1.x`, and
`to_dict()` / `to_json()` mean the parent tool never has to parse stdout. Beyond the
per-check sections it includes `scan_profile`, `checks_run`, and, on each finding,
`remediation` and `reference`.

## Configuration

DNScanner reads a persisted config from `~/.config/dnscanner/config.json` (respects
`$XDG_CONFIG_HOME`; override the path entirely with `$DNSCANNER_CONFIG`). It lets you
disable specific checks, tweak options, and store API keys.

API keys are read **env-first**, then from the config file, and are **never hardcoded**.
They back the (reserved) reputation check:

```sh
export DNSCANNER_VT_API_KEY=...     # VirusTotal
export DNSCANNER_GSB_API_KEY=...    # Google Safe Browsing
```

When a `config` is passed to `scan()`, checks the user has disabled are filtered out
before the scan runs.




<!-- LICENSE -->
## License

Distributed under the GPL-3.0 License. See `LICENSE` for more information.

<!-- CONTACT -->
## Contact

[![LinkedIn][linkedin-shield]][linkedin-url]

Tiago Faustino - tiagfaustino@gmail.com

Project Link: [https://github.com/ChinadaCam/DNScanner](https://github.com/ChinadaCam/DNScanner)
See the [open issues](https://github.com/ChinadaCam/DNScanner/issues) for proposed
features and known issues.

<!-- MARKDOWN LINKS & IMAGES -->
[contributors-shield]: https://img.shields.io/github/contributors/ChinadaCam/DNScanner.svg?style=flat-square
[contributors-url]: https://github.com/ChinadaCam/DNScanner/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/ChinadaCam/DNScanner.svg?style=flat-square
[forks-url]: https://github.com/ChinadaCam/DNScanner/network/members
[stars-shield]: https://img.shields.io/github/stars/ChinadaCam/DNScanner.svg?style=flat-square
[stars-url]: https://github.com/ChinadaCam/DNScanner/stargazers
[issues-shield]: https://img.shields.io/github/issues/ChinadaCam/DNScanner.svg?style=flat-square
[issues-url]: https://github.com/ChinadaCam/DNScanner/issues
[license-shield]: https://img.shields.io/github/license/ChinadaCam/DNScanner.svg?style=flat-square
[license-url]: https://github.com/ChinadaCam/DNScanner/blob/master/LICENSE
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=flat-square&logo=linkedin&colorB=555
[linkedin-url]: https://www.linkedin.com/in/tiago-faustino-b07523166/
