# RapidAPI Listing Copy

---

## Short Description (300 chars max)

Scan any domain or IP for security issues in seconds. InfraProbe checks SSL/TLS, HTTP security headers, DNS misconfigurations, exposed web paths, CORS policies, and WHOIS data — all in one API call. Get a severity score, structured findings, and SARIF/CSV export. Built for CI/CD pipelines.

---

## Long Description

### InfraProbe — Infrastructure Security Scanner API

InfraProbe is a fast, developer-friendly API that scans domains and IP addresses for common infrastructure security issues. Send a single POST request with your target, and InfraProbe runs five security checks in parallel — returning structured findings with severity levels and an overall security score.

**What gets checked:**

- **SSL/TLS** — Certificate validity, expiration, protocol version, cipher strength, and chain issues
- **HTTP Security Headers** — Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, Permissions-Policy, and 20+ other headers analyzed against best practices
- **DNS Security** — SPF, DMARC, DKIM, CAA records, DNSSEC validation, and zone transfer exposure
- **Web Exposure** — CORS misconfigurations, exposed admin paths, sensitive files (`.env`, `.git/config`, `debug/`), `robots.txt` analysis, and `security.txt` presence
- **WHOIS** — Domain registration details, expiration alerts, and registrar info

**Why developers choose InfraProbe:**

- **One endpoint, full coverage** — No complex workflows. One `POST /v1/scan` call returns everything.
- **Severity scoring** — Every finding is ranked critical/high/medium/low/info, with an aggregate 0–100 security score.
- **CI/CD-ready** — JSON, SARIF 2.1.0, and CSV output formats. SARIF integrates directly with GitHub Code Scanning and VS Code.
- **Authenticated scanning** — Scan staging environments and protected pages with bearer tokens, basic auth, API keys, or session cookies.
- **Fast** — Parallel execution. Most scans complete in 2–5 seconds.
- **No infrastructure needed** — No agents, no installs, no credentials to manage. Just an API call.

InfraProbe is ideal for security teams running continuous posture checks, DevOps engineers adding security gates to deployment pipelines, and SaaS builders embedding security scanning into their products.

---

## Terms of Use

By subscribing to and using the InfraProbe API, you agree to the following terms:

**Permitted Use.** InfraProbe is provided for legitimate security assessment purposes. You may scan domains, servers, and IP addresses that you own, operate, or have explicit written authorization to test. Typical use cases include: security posture monitoring for your own infrastructure, CI/CD pipeline security gates, penetration testing engagements with proper authorization, and building security features into your own products.

**Prohibited Use.** You may not use InfraProbe to scan targets without authorization, perform denial-of-service attacks or abuse the API to generate excessive traffic against third-party systems, attempt to exploit vulnerabilities discovered by the scanner, resell raw API access without adding substantial value, or use the service in violation of any applicable law or regulation.

**Rate Limits & Fair Use.** Usage is subject to the rate limits of your subscription plan. Excessive or abusive request patterns that degrade service for other users may result in throttling or suspension.

**Data Handling.** InfraProbe does not store scan results beyond the duration of the request. Credentials passed via the `auth` field are used only for the active scan and are never logged, persisted, or included in API responses.

**Availability.** The API is provided on an "as-is" basis. While we strive for high uptime, we do not guarantee uninterrupted availability. Scanner results reflect point-in-time observations and should not be treated as a comprehensive security audit.

**Liability.** InfraProbe is a scanning tool, not a security guarantee. You are responsible for interpreting results and acting on findings. We are not liable for any damages resulting from the use or inability to use this service.

By making your first API request, you acknowledge that you have read and agree to these terms.

---

## Endpoint: POST /v1/scan

### Method Description

Run a comprehensive security scan against a single target. InfraProbe automatically selects the appropriate checks based on target type: domains receive headers, SSL, DNS, web, and WHOIS checks; IP addresses receive headers, SSL, and web checks. All checks execute in parallel and results are returned synchronously in the response body. The response includes individual findings with severity levels, raw scanner output, per-check timing, and an aggregate security score from 0 to 100.

### Request Body Arguments

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `target` | string | **Yes** | — | The domain name, IP address, or `host:port` to scan. Examples: `"example.com"`, `"93.184.216.34"`, `"example.com:8443"`. Maximum 2048 characters. |
| `format` | string | No | `"json"` | Output format for the response. One of: `"json"` (structured JSON, default), `"sarif"` (SARIF 2.1.0 — compatible with GitHub Code Scanning), `"csv"` (one row per finding). Error responses are always JSON regardless of this setting. |
| `auth` | object | No | `null` | Credentials to send to the scan target for authenticated scanning. Supports four auth types: `bearer`, `basic`, `header`, and `cookie`. See **Target Authentication** below. Credentials are never logged or included in the response. |

### Target Authentication

The `auth` field lets you scan targets that require authentication. HTTP-based scanners (headers, web) will include the provided credentials in their requests. Non-HTTP scanners (SSL, DNS, WHOIS) accept the field but ignore it — they operate at the protocol level, not HTTP.

**Bearer Token** — For APIs and services using JWT or OAuth tokens:

```json
{
  "target": "api.staging.example.com",
  "auth": {
    "type": "bearer",
    "token": "eyJhbGciOiJSUzI1NiIs..."
  }
}
```

| Field | Type | Limits | Description |
|-------|------|--------|-------------|
| `type` | string | — | Must be `"bearer"` |
| `token` | string | Max 8,192 chars | The bearer token value (sent as `Authorization: Bearer <token>`) |

**Basic Auth** — For services using HTTP Basic authentication:

```json
{
  "target": "staging.internal.com",
  "auth": {
    "type": "basic",
    "username": "qa-user",
    "password": "testpass123"
  }
}
```

| Field | Type | Limits | Description |
|-------|------|--------|-------------|
| `type` | string | — | Must be `"basic"` |
| `username` | string | Max 256 chars | Username for Basic auth |
| `password` | string | Max 256 chars | Password for Basic auth |

**Custom Headers** — For API keys, custom auth schemes, or any header-based authentication:

```json
{
  "target": "api.example.com",
  "auth": {
    "type": "header",
    "headers": {
      "X-API-Key": "sk-live-abc123",
      "X-Tenant-ID": "acme-corp"
    }
  }
}
```

| Field | Type | Limits | Description |
|-------|------|--------|-------------|
| `type` | string | — | Must be `"header"` |
| `headers` | object | 1–10 entries | Key-value pairs of headers to include. `Host`, `Content-Length`, `Transfer-Encoding`, and `Connection` are forbidden (422 error). |

**Cookie Auth** — For session-based authentication (paste cookies from browser DevTools):

```json
{
  "target": "app.example.com",
  "auth": {
    "type": "cookie",
    "cookies": {
      "session_id": "abc123def456",
      "csrf_token": "xyz789"
    }
  }
}
```

| Field | Type | Limits | Description |
|-------|------|--------|-------------|
| `type` | string | — | Must be `"cookie"` |
| `cookies` | object | 1–20 entries | Key-value pairs of cookies to include in requests |

**Security notes:** Credentials are never logged, stored, or returned in API responses. When a redirect crosses to a different host, `Authorization` and `Cookie` headers are automatically stripped to prevent credential leakage.

### JSON Schema

```json
{
  "$defs": {
    "BasicAuth": {
      "properties": {
        "type": { "const": "basic", "type": "string" },
        "username": { "maxLength": 256, "type": "string" },
        "password": { "maxLength": 256, "type": "string" }
      },
      "required": ["type", "username", "password"],
      "type": "object"
    },
    "BearerAuth": {
      "properties": {
        "type": { "const": "bearer", "type": "string" },
        "token": { "maxLength": 8192, "type": "string" }
      },
      "required": ["type", "token"],
      "type": "object"
    },
    "CookieAuth": {
      "properties": {
        "type": { "const": "cookie", "type": "string" },
        "cookies": {
          "additionalProperties": { "type": "string" },
          "maxProperties": 20,
          "minProperties": 1,
          "type": "object"
        }
      },
      "required": ["type", "cookies"],
      "type": "object"
    },
    "HeaderAuth": {
      "properties": {
        "type": { "const": "header", "type": "string" },
        "headers": {
          "additionalProperties": { "type": "string" },
          "maxProperties": 10,
          "minProperties": 1,
          "type": "object"
        }
      },
      "required": ["type", "headers"],
      "type": "object"
    },
    "OutputFormat": {
      "enum": ["json", "sarif", "csv"],
      "type": "string"
    }
  },
  "examples": [
    { "target": "example.com", "format": "json" }
  ],
  "properties": {
    "target": {
      "description": "Domain name, IP address, or host:port to scan (e.g. 'example.com', '93.184.216.34').",
      "maxLength": 2048,
      "type": "string"
    },
    "format": {
      "$ref": "#/$defs/OutputFormat",
      "default": "json",
      "description": "Output format: json (default), sarif, or csv."
    },
    "auth": {
      "anyOf": [
        {
          "discriminator": {
            "mapping": {
              "basic": "#/$defs/BasicAuth",
              "bearer": "#/$defs/BearerAuth",
              "cookie": "#/$defs/CookieAuth",
              "header": "#/$defs/HeaderAuth"
            },
            "propertyName": "type"
          },
          "oneOf": [
            { "$ref": "#/$defs/HeaderAuth" },
            { "$ref": "#/$defs/BasicAuth" },
            { "$ref": "#/$defs/BearerAuth" },
            { "$ref": "#/$defs/CookieAuth" }
          ]
        },
        { "type": "null" }
      ],
      "default": null,
      "description": "Credentials to send to the scan target (header, basic, bearer, or cookie auth)."
    }
  },
  "required": ["target"],
  "type": "object"
}
```

---

## Listing README

### What is InfraProbe?

InfraProbe is an infrastructure security scanning API. Give it a domain or IP address, and it runs five security checks in parallel — SSL/TLS, HTTP headers, DNS, web exposure, and WHOIS — returning structured results with severity ratings and a 0–100 security score.

### Quick Start

```bash
curl -X POST https://infraprobe.p.rapidapi.com/v1/scan \
  -H "Content-Type: application/json" \
  -H "x-rapidapi-host: infraprobe.p.rapidapi.com" \
  -H "x-rapidapi-key: YOUR_API_KEY" \
  -d '{"target": "example.com"}'
```

### What You Get Back

```json
{
  "results": [
    {
      "target": "example.com",
      "results": {
        "headers": { "check": "headers", "findings": [...], "raw": {...} },
        "ssl":     { "check": "ssl",     "findings": [...], "raw": {...} },
        "dns":     { "check": "dns",     "findings": [...], "raw": {...} },
        "web":     { "check": "web",     "findings": [...], "raw": {...} },
        "whois":   { "check": "whois",   "findings": [...], "raw": {...} }
      },
      "duration_ms": 2340,
      "summary": { "critical": 0, "high": 1, "medium": 3, "low": 2, "info": 4, "total": 10, "score": 78 }
    }
  ],
  "summary": { "critical": 0, "high": 1, "medium": 3, "low": 2, "info": 4, "total": 10, "score": 78 }
}
```

Every finding includes a `severity` (critical / high / medium / low / info), a human-readable `title` and `description`, and structured `details`. The `summary` gives you aggregate counts and a **security score** — 100 means no issues found, and it decreases based on finding severity.

### Checks Included

| Check | What it covers |
|-------|---------------|
| **headers** | 20+ HTTP security headers: CSP, HSTS, X-Frame-Options, Permissions-Policy, Referrer-Policy, and more |
| **ssl** | Certificate validity, expiration, protocol version, cipher strength, chain completeness |
| **dns** | SPF, DMARC, DKIM, CAA, DNSSEC, MX records, zone transfer exposure |
| **web** | CORS policy, exposed paths (`.env`, `.git`, admin panels), `robots.txt`, `security.txt` |
| **whois** | Registrar, creation/expiry dates, nameservers, domain age |

Domains get all five checks. IP addresses get headers + ssl + web (DNS and WHOIS require a domain name).

### Output Formats

Set `"format"` in the request body:

- **`"json"`** (default) — Structured JSON with findings, raw data, and severity summaries
- **`"sarif"`** — SARIF 2.1.0 output for GitHub Code Scanning, VS Code SARIF Viewer, and other SARIF tools
- **`"csv"`** — One row per finding: `target, check, severity, title, description, details`

### Scan Authenticated Targets

Need to scan a staging environment or an API behind auth? Pass credentials in the `auth` field:

```json
{
  "target": "staging.yourapp.com",
  "auth": { "type": "bearer", "token": "eyJhbGciOi..." }
}
```

Supports bearer tokens, basic auth, custom headers (API keys), and cookies. Credentials are never logged or returned.

### Use Cases

- **CI/CD security gates** — Add a scan step to your pipeline. Fail the build if critical findings appear.
- **Continuous monitoring** — Schedule periodic scans and track your security score over time.
- **Penetration testing** — Use InfraProbe for reconnaissance during authorized security assessments.
- **SaaS security features** — Embed infrastructure scanning into your product with a single API call.
- **Compliance checks** — Verify SSL configuration, security headers, and DNS hardening before audits.

### Example: CI/CD Pipeline Check

```bash
SCORE=$(curl -s -X POST https://infraprobe.p.rapidapi.com/v1/scan \
  -H "Content-Type: application/json" \
  -H "x-rapidapi-host: infraprobe.p.rapidapi.com" \
  -H "x-rapidapi-key: $RAPIDAPI_KEY" \
  -d "{\"target\": \"$DEPLOY_URL\"}" | jq '.summary.score')

if [ "$SCORE" -lt 70 ]; then
  echo "Security score $SCORE is below threshold (70). Failing build."
  exit 1
fi
```

---

## RapidAPI Spotlight

### InfraProbe: One API Call to Scan Your Infrastructure Security

Security scanning shouldn't require installing agents, configuring complex tools, or reading 50-page setup guides. InfraProbe is a single API endpoint that scans any domain or IP for the security issues that matter most — and returns results in seconds.

**The problem:** Development teams ship fast, but infrastructure security checks lag behind. SSL certificates expire unnoticed. Security headers are missing after a framework upgrade. DNS records have SPF misconfigurations that let phishing emails through. Admin panels and `.env` files sit exposed on production servers. These are the low-hanging-fruit vulnerabilities that attackers scan for first.

**The solution:** `POST /v1/scan` with a target, get back structured findings with severity ratings and a 0–100 security score. That's it. No agents. No SDKs to install. No infrastructure to manage.

InfraProbe runs five checks in parallel:

1. **SSL/TLS** — Is the certificate valid? Is TLS 1.3 supported? Are weak ciphers enabled?
2. **HTTP Security Headers** — Are CSP, HSTS, X-Frame-Options, and Permissions-Policy properly configured?
3. **DNS Security** — Are SPF, DMARC, and CAA records set up correctly? Is DNSSEC enabled?
4. **Web Exposure** — Are sensitive paths like `.env`, `.git/config`, or `/admin` publicly accessible?
5. **WHOIS** — Is the domain about to expire? Who's the registrar?

Results come back as structured JSON with a clear severity taxonomy: critical, high, medium, low, and info. Each finding has a title, description, and machine-readable details. Need a different format? Set `format` to `sarif` for GitHub Code Scanning integration, or `csv` for spreadsheets and reporting.

**Built for developers who automate everything:**

- Drop InfraProbe into your CI/CD pipeline. Fail deploys if the security score drops below your threshold.
- Schedule hourly scans and alert on new critical findings.
- Scan staging environments with bearer tokens, API keys, or session cookies via the `auth` field.
- Export SARIF to GitHub and see security findings right in your pull requests.

InfraProbe is fast (most scans complete in 2–5 seconds), stateless (nothing is stored after the request completes), and privacy-conscious (credentials are never logged or returned in responses).

Whether you're building a security dashboard, hardening your deployment pipeline, or adding infrastructure scanning to your SaaS product — InfraProbe gives you production-grade security scanning through a simple API.
