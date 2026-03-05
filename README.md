> ⚠️ **Work in Progress** — This project is actively being developed as part of a security engineering portfolio. Core pipeline is functional; reporter and GitHub Actions automation are coming soon.

# Vulnerability Intelligence Pipeline

A security engineering portfolio project that replicates enterprise-grade vulnerability prioritization — the kind of intelligence layer that commercial tools like Snyk, Wiz, and JFrog Xray provide, built from scratch using open-source tools and public threat intelligence feeds.

## The Problem

Free scanners like Trivy detect vulnerabilities but treat a LOW severity CVE from 2011 the same as a CRITICAL CVE actively exploited in the wild today. Security teams waste time chasing noise instead of fixing what actually matters.

## The Solution

This pipeline enriches raw scan data with real-world threat intelligence and business context to produce a **risk-based priority score** for each vulnerability — so engineers fix the right things first.

## How It Works
```
Docker Image → Trivy Scan → Parser → Enricher → Prioritized Report
```

1. **Scanner** — Runs Trivy against a Docker image and produces structured JSON output
2. **Parser** — Normalizes raw Trivy output, extracting CVE ID, package, version, severity, CVSS score (with NVD → GHSA → RedHat fallback), remediation advice differentiated by OS vs language packages
3. **Enricher** — Enriches each CVE with:
   - **EPSS score** (FIRST.org API) — probability of exploitation in the next 30 days
   - **CISA KEV flag** — is this CVE actively exploited in the wild right now?
   - **Asset context** — is this service internet-facing? Does it handle PII? What's the blast radius?
   - **Priority score** — combines all signals into a single actionable number
4. **Reporter** _(coming soon)_ — Generates Markdown and HTML reports with SLA assignments
5. **GitHub Actions** _(coming soon)_ — Weekly automated scans committed to repo, showing vulnerability trends over time

## Priority Scoring Formula

Each vulnerability receives a score from 0-10 based on:

| Signal | Weight |
|--------|--------|
| CVSS v3 base score | Baseline |
| EPSS > 0.7 (high exploitation probability) | ×2.0 |
| EPSS > 0.3 (medium exploitation probability) | ×1.5 |
| In CISA KEV (actively exploited) | ×2.0 + forced Critical |
| Internet-facing service | ×1.15 |
| Sensitive data (PII/financial) | ×1.15 |
| High blast radius | ×1.10 |
| Production environment | ×1.05 |
| WAF present (lang-pkgs only) | ×0.9 compensating control |

## SLA Tiers

| Priority Score | SLA |
|----------------|-----|
| ≥ 9.0 | Critical — fix within 24 hours |
| ≥ 7.0 | High — fix within 7 days |
| ≥ 4.0 | Medium — fix within 30 days |
| < 4.0 | Low — fix within 90 days |

Any CVE in CISA KEV is automatically escalated to Critical regardless of score.

## Threat Intelligence Sources

- **CVSS** — National Vulnerability Database (NVD), GHSA, RedHat
- **EPSS** — [FIRST.org](https://www.first.org/epss/) — Exploit Prediction Scoring System
- **KEV** — [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

## Asset Context

Vulnerabilities are scored in the context of the scanned asset, configured via `asset-context.yaml`:
```yaml
image: python:3.11-slim
context:
  internet_facing: true
  data_classification: PII
  environment: production
  blast_radius: high
  has_waf: true
```

This means the same CVE receives a different priority score depending on whether it affects an internal dev service or a production internet-facing service handling PII data.

## Tech Stack

- **Python 3** — core pipeline
- **Trivy** — container vulnerability scanner
- **GitHub Actions** — automated weekly scans _(coming soon)_
- **FIRST.org EPSS API** — exploitation probability scores
- **CISA KEV Feed** — known exploited vulnerabilities

## Project Structure
```
vuln-intel-pipeline/
├── scanner/
│   └── parse_trivy.py        # Trivy JSON parser and normalizer
├── enricher/
│   └── enrich.py             # EPSS + KEV enrichment and priority scoring
├── reporter/                 # Report generation (coming soon)
├── dashboard/                # Visual dashboard (coming soon)
├── sample-data/              # Real Trivy scan output for development
├── asset-context.yaml        # Asset business context configuration
└── .github/workflows/        # GitHub Actions automation (coming soon)
```

## Running Locally
```bash
# Install dependencies
pip install requests pyyaml

# Install Trivy
sudo apt install trivy

# Run a scan
trivy image --format json --output sample-data/scan.json python:3.11-slim

# Parse and enrich
python3 enricher/enrich.py
```

## Author

Ghinwa Badawi — Security Architect & Engineer  
[github.com/ghinwabadawi](https://github.com/ghinwabadawi)