# Web Security Check

Checks for CORS misconfigurations, exposed sensitive files, robots.txt leaks, mixed content, and security.txt presence.

- **Check type:** `web`
- **Endpoint:** `POST /v1/check/web`
- **Default:** Opt-in (not included in default scans)
- **Deep variant:** None

## What Is Checked

### Exposed Paths

Probes for sensitive files and endpoints that should not be publicly accessible:

| Path | Risk |
|------|------|
| `.env` | Environment variables, credentials |
| `.git/HEAD`, `.git/config` | Source code exposure |
| `.htpasswd` | Password hashes |
| `wp-config.php.bak` | WordPress database credentials |
| `phpinfo.php` | PHP configuration details |
| `server-status`, `server-info` | Apache status pages |
| `.svn/entries` | Subversion metadata |
| `elmah.axd` | ASP.NET error logs |
| `/actuator` | Spring Boot management endpoints |
| `/debug/pprof/` | Go profiling endpoints |

Each probe validates that the response contains expected content, not just a 200 status code, to avoid false positives.

### CORS Analysis

Tests CORS configuration by sending a request with a test Origin header:

- Whether the server reflects arbitrary origins
- Whether credentials are allowed with permissive origins
- Whether `null` origin is allowed

### Robots.txt

Parses robots.txt for disallowed paths that may reveal sensitive areas (admin panels, backups, config directories, staging environments).

### Mixed Content

On HTTPS sites, checks for HTTP resources (scripts, images, stylesheets) that could be intercepted.

### security.txt (RFC 9116)

Checks for a security.txt file that provides a way for security researchers to report vulnerabilities.

## Understanding Findings

| Severity | Example findings |
|----------|-----------------|
| critical | .env file exposed, .htpasswd exposed, wp-config.php.bak exposed |
| high | .git repository exposed, phpinfo.php accessible, elmah.axd exposed, /actuator exposed, /debug/pprof/ exposed, CORS reflects arbitrary origin with credentials |
| medium | Server-status/server-info exposed, CORS reflects arbitrary origin, CORS allows null origin, mixed HTTP content on HTTPS page |
| low | CORS allows wildcard origin, sensitive paths in robots.txt, no security.txt found |
| info | No CORS configured, security.txt present |

## Raw Data Fields

| Field | Description |
|-------|-------------|
| `url` | URL that was checked |
| `status_code` | HTTP response status code |
| `cors` | CORS headers (`acao`, `acac`) |
| `exposed_paths` | Paths found to be accessible |
| `robots_txt` | Robots.txt content |
| `mixed_content` | List of HTTP resource URLs found on HTTPS page |
| `security_txt` | Whether security.txt was found |

---

[Back to overview](../README.md) | [Getting Started](../getting-started.md)
