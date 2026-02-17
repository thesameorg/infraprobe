# Technology Detection Check

Identifies web technologies, frameworks, CDNs, and WAFs running on the target using the Wappalyzer fingerprint database.

- **Check type:** `tech`
- **Endpoint:** `POST /v1/check/tech`
- **Default:** Yes (all targets)

## What Is Checked

Uses the Wappalyzer fingerprint database with 1500+ technology signatures. Detects technologies via HTTP response headers, HTML body patterns, cookies, and JavaScript. Provides version numbers and confidence scores when available.

Categories include:

- **Web servers:** Nginx, Apache, LiteSpeed, IIS, Caddy
- **CDNs:** Cloudflare, Fastly, Akamai, CloudFront, Vercel
- **WAFs:** Cloudflare WAF, AWS WAF, Sucuri
- **Frameworks:** PHP, ASP.NET, Express, Django, Rails, Next.js
- **CMS:** WordPress, Drupal, Joomla, Shopify, Squarespace
- **Analytics:** Google Analytics, Google Tag Manager
- **Caching:** Varnish, Redis

## Understanding Findings

| Severity | Example findings |
|----------|-----------------|
| low | PHP version exposed in headers, server version exposed |
| info | WordPress detected, CDN detected (Cloudflare), WAF detected |

Technology detection primarily produces informational findings. Version exposure findings are flagged as low severity because they help attackers identify specific vulnerabilities.

## Raw Data Fields

| Field | Description |
|-------|-------------|
| `url` | URL that was checked |
| `detected` | List of detected technologies, each with `name`, `version`, `confidence`, `categories`, and `groups` |
| `technologies_count` | Total number of technologies detected |

---

[Back to overview](../README.md) | [Getting Started](../getting-started.md)
