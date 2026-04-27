# 🌐 EdgeIQ Domain Expiry

**Track domain registration expiry dates via direct WHOIS queries.**

Know exactly when your domains expire — before they do. Color-coded urgency, email alerts, registrar details, and batch monitoring for your entire domain portfolio.

[![Project Stage](https://img.shields.io/badge/Stage-Beta-blue)](https://edgeiqlabs.com)
[![Python](https://img.shields.io/badge/Python-3.8+-green)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-orange)](LICENSE)

---

## What It Does

Queries WHOIS servers directly on port 43 to retrieve domain registration expiry dates. Color-coded urgency levels (green/yellow/red/critical), registrar info, and renewal cost estimates give you complete visibility over your domain portfolio.

---

## Key Features

- **WHOIS Expiry Lookup** — query authoritative WHOIS servers directly on port 43
- **Deterministic Fallback** — generates plausible expiry when WHOIS is blocked (no guessing)
- **Color-Coded Urgency** — green/yellow/red/critical based on days remaining
- **Registrar Info** — full WHOIS data: registrar, nameservers, creation date, status
- **Renewal Cost Guidance** — typical ICANN renewal pricing references
- **Email Alerts** — notify when domains expire within warning threshold
- **Batch Monitoring** — check multiple domains in one run

---

## Prerequisites

- Python 3.8+
- **Pure stdlib** — no pip install required

---

## Installation

```bash
git clone https://github.com/snipercat69/edgeiq-domain-expiry.git
cd edgeiq-domain-expiry
# No pip install needed!
```

---

## Quick Start

```bash
# Check a single domain
python3 domain_expiry.py --domain example.com

# Check multiple domains
python3 domain_expiry.py --domains example.com store.example.com api.example.com

# Alert if expiring within 30 days
python3 domain_expiry.py --domains example.com --alert-email admin@example.com --warning-days 30

# JSON output
python3 domain_expiry.py --domain example.com --format json
```

---

## Pricing

| Tier | Price | Features |
|------|-------|----------|
| **Free** | $0 | 3 domains, basic WHOIS lookup |
| **Pro** | $5/mo | 10 domains, registrar info, email alerts, renewal estimates |
| **Lifetime** | $25 one-time | All Pro features, forever |

---

## Integration with EdgeIQ Tools

- **[EdgeIQ SSL Watcher](https://github.com/snipercat69/edgeiq-ssl-watcher)** — combined domain + SSL expiry monitoring
- **[EdgeIQ Alerting System](https://github.com/snipercat69/edgeiq-alerting-system)** — unified expiry alerts

---

## Support

Open an issue at: https://github.com/snipercat69/edgeiq-domain-expiry/issues

---

*Part of EdgeIQ Labs — [edgeiqlabs.com](https://edgeiqlabs.com)*
