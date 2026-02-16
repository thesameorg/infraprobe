# Technology Detection Check

Identifies web technologies, frameworks, CDNs, and WAFs running on the target.

- **Check type:** `tech` (light), `tech_deep` (deep)
- **Endpoint:** `POST /v1/check/tech` or `POST /v1/check_deep/tech_deep`
- **Default:** Yes (all targets)

## What Is Checked

### Light scan

Detects technologies using HTTP response headers, HTML body patterns, and cookies. Covers 30+ technologies including:

- **Web servers:** Nginx, Apache, LiteSpeed, IIS, Caddy
- **CDNs:** Cloudflare, Fastly, Akamai, CloudFront, Vercel
- **WAFs:** Cloudflare WAF, AWS WAF, Sucuri
- **Frameworks:** PHP, ASP.NET, Express, Django, Rails, Next.js
- **CMS:** WordPress, Drupal, Joomla, Shopify, Squarespace
- **Analytics:** Google Analytics, Google Tag Manager
- **Caching:** Varnish, Redis

### Deep scan

Uses the Wappalyzer fingerprint database with 1500+ technology signatures. Provides version numbers and confidence scores when available.

## Understanding Findings

| Severity | Example findings |
|----------|-----------------|
| low | PHP version exposed in headers, server version exposed |
| info | WordPress detected, CDN detected (Cloudflare), WAF detected |

Technology detection primarily produces informational findings. Version exposure findings are flagged as low severity because they help attackers identify specific vulnerabilities.

### Deep scan additions

The deep scan detects more technologies and includes version numbers and confidence scores. Findings follow the same severity pattern.

## Raw Data Fields

### Light scan

| Field | Description |
|-------|-------------|
| `url` | URL that was checked |
| `detected` | List of detected technologies, each with `name` and `category` |
| `technologies_count` | Total number of technologies detected |

### Deep scan

| Field | Description |
|-------|-------------|
| `url` | URL that was checked |
| `detected` | List of detected technologies, each with `name`, `version`, `confidence`, `categories`, and `groups` |
| `technologies_count` | Total number of technologies detected |

---

[Back to overview](../README.md) | [Getting Started](../getting-started.md)
