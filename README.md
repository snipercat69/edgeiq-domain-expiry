# Domain Expiry Monitor — Quick Start

Check when your domains expire before they do.

## Prerequisites

- Python 3.7+
- No external dependencies (pure stdlib + socket)

## Basic Usage

```bash
# Single domain
python3 domain_expiry.py --domain example.com

# Multiple domains
python3 domain_expiry.py --domains example.com store.example.com api.example.com

# Alert if domain expires within 30 days
python3 domain_expiry.py --domain example.com --days 30

# Send email alert when domain is at risk
python3 domain_expiry.py --domain example.com --days 90 --notify
```

## Environment Variables

For email notifications, set:
```bash
export SUBALERTS_SMTP_USER="your-smtp-user"
export SUBALERTS_SMTP_PASS="your-smtp-password"
```

## Discord Commands

In any EdgeIQ channel:
```
!domain example.com
!domain example.com --days 30
```

## Output Codes

| Days Left | Status | Color |
|-----------|--------|-------|
| >90 | Healthy | Green |
| 30–90 | Warning | Yellow |
| 7–30 | Danger | Red |
| <7 | Critical | Blinking Red |

## Pro Features

Upgrade at [https://buy.stripe.com/6oUbJ3eCn8lfbQocQU7wA0s](https://buy.stripe.com/6oUbJ3eCn8lfbQocQU7wA0s) for:
- Up to 10 domains (vs 3 free)
- Full WHOIS data: registrar, nameservers, creation date, status
- Email expiry alerts
- JSON report export
