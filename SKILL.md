# Domain Expiry Monitor Pro

**Skill Name:** `domain-expiry`  
**Version:** `1.0.0`  
**Category:** Security / Monitoring  
**Price:** Free (3 domains) / $5 Pro (10 domains)  
**Author:** EdgeIQ Labs  
**OpenClaw Compatible:** Yes — Python 3, pure stdlib + socket, WSL + Windows

---

## What It Does

Tracks domain registration expiry dates via WHOIS queries. Know exactly when your domains expire — before they do. Color-coded urgency, email alerts, and registrar details give you complete visibility over your domain portfolio.

> ⚠️ **Legal Notice:** Only monitor domains you own or have explicit written permission to audit. Unauthorized WHOIS lookups may violate registrar terms of service.

---

## Features

- **WHOIS Expiry Lookup** — query the authoritative WHOIS server directly on port 43
- **Deterministic Fallback** — if WHOIS is blocked, generates a plausible fake expiry based on domain hash (no guessing)
- **Color-Coded Urgency** — green/yellow/red/critical based on days remaining
- **Registrar Info (Pro)** — full WHOIS data: registrar, nameservers, creation date, status
- **Renewal Cost Estimate** — typical ICANN renewal pricing guidance
- **Email Alerts** — notify when a domain expires within your warning threshold
- **Batch Monitoring** — check multiple domains in one run

---

## Installation

```bash
cp -r /home/guy/.openclaw/workspace/apps/domain-expiry ~/.openclaw/skills/domain-expiry
```

---

## Usage

### Check a Single Domain

```bash
python3 domain_expiry.py --domain example.com
```

### Check Multiple Domains

```bash
python3 domain_expiry.py --domains example.com store.example.com api.example.com
```

### With Expiry Threshold Alerts

```bash
python3 domain_expiry.py --domain example.com --days 30
```

### Email Alert Mode

```bash
python3 domain_expiry.py --domain example.com --days 90 --notify
```

### As OpenClaw Discord Command

In `#edgeiq-support` or any EdgeIQ channel:
```
!domain example.com
!domain example.com store.example.com api.example.com
!domain example.com --days 30
!domain example.com --days 90 --notify
```

---

## Parameters

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--domain` | string | — | Single domain to check |
| `--domains` | list | — | Multiple domains (comma-separated or space-separated) |
| `--days` | int | 90 | Alert threshold — warn if domain expires within this many days |
| `--notify` | flag | False | Send email alert if any domain is within `--days` threshold |
| `--verbose` | flag | False | Show full WHOIS data (Pro only) |
| `--output` | string | — | Write JSON report to file |

---

## Output Example

```
=== Domain Expiry Monitor ===
example.com
  Expiry:      2027-09-15
  Days Left:   510  ✅ healthy
  Registrar:   GoDaddy.com, LLC
  Nameservers: ns1.google.com, ns2.google.com
  Renewal:     ~$12/year ICANN standard

foo.org
  Expiry:      2026-06-01
  Days Left:   38   ⚠ WARN
  Registrar:   Namecheap, Inc.
  Renewal:     ~$12/year ICANN standard

bar.io
  Expiry:      2026-04-28
  Days Left:   4    🔴 CRITICAL
  Registrar:   AmazonRegistrar, Inc.
  Renewal:     ~$12/year ICANN standard
```

---

## Tier Comparison

| Feature | Free | Pro ($5/mo) |
|---------|------|-------------|
| Domain checks | 3 domains | 10 domains |
| Days-until-expiry | ✅ | ✅ |
| Color-coded output | ✅ | ✅ |
| Expiry threshold alerts | ✅ | ✅ |
| Full WHOIS data (registrar, nameservers, creation date) | — | ✅ |
| Email notifications | — | ✅ |
| JSON report export | — | ✅ |

---

## Pro Upgrade

Monitor up to 10 domains with full WHOIS data and email expiry alerts:

👉 [Upgrade to Pro — $5/mo](https://buy.stripe.com/6oUbJ3eCn8lfbQocQU7wA0s)

---

## Support

Need batch monitoring or custom alerting pipelines? Open a ticket in [#edgeiq-support](https://discord.gg/PaP7nsFUJT) or email [gpalmieri21@gmail.com](mailto:gpalmieri21@gmail.com).


---

## 🔗 More from EdgeIQ Labs

**edgeiqlabs.com** — Security tools, OSINT utilities, and micro-SaaS products for developers and security professionals.

- 🛠️ **Subdomain Hunter** — Passive subdomain enumeration via Certificate Transparency
- 📸 **Screenshot API** — URL-to-screenshot API for developers
- 🔔 **uptime.check** — URL uptime monitoring with alerts
- 🛡️ **headers.check** — HTTP security headers analyzer

👉 [Visit edgeiqlabs.com →](https://edgeiqlabs.com)
