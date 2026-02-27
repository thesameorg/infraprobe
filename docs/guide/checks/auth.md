# Authenticated Scanning

InfraProbe can scan targets that sit behind authentication. Pass credentials via the optional `auth` field on the request body, and HTTP-based scanners (headers, web) will include them in their requests. Non-HTTP scanners (ssl, dns, whois) accept the field but ignore it.

## Auth Types

### Bearer Token

```bash
curl -X POST https://your-instance/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "api.staging.example.com",
    "auth": {"type": "bearer", "token": "eyJhbGciOi..."}
  }'
```

### Basic Auth

```bash
curl -X POST https://your-instance/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "staging.internal.com",
    "auth": {"type": "basic", "username": "qa", "password": "testpass123"}
  }'
```

### Custom Headers

Covers API keys, custom auth schemes, or any header-based auth.

```bash
curl -X POST https://your-instance/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "api.example.com",
    "auth": {"type": "header", "headers": {"X-API-Key": "sk-live-abc123"}}
  }'
```

Forbidden headers (`Host`, `Content-Length`, `Transfer-Encoding`, `Connection`) are rejected with 422.

### Cookie Auth

Pass session cookies extracted from browser DevTools.

```bash
curl -X POST https://your-instance/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "app.example.com",
    "auth": {"type": "cookie", "cookies": {"session_id": "abc123"}}
  }'
```

## Which Scanners Use Auth?

| Scanner | Uses auth? | Notes |
|---------|-----------|-------|
| headers | Yes | Security headers on authenticated pages often differ |
| web | Yes | Path probes, CORS, robots.txt use auth via shared client |
| ssl | No | Direct TLS handshake, no HTTP layer |
| dns | No | DNS protocol |
| whois | No | WHOIS protocol |

## Security Notes

- **Credentials are never logged or returned in API responses.** The `auth` field uses `exclude=True` in the data model, so it won't appear in `model_dump()` or JSON responses.
- **Cross-origin redirect protection.** When auth is set and a redirect crosses to a different host, `Authorization` and `Cookie` headers are automatically stripped to prevent credential leakage. This matches browser behavior.
- **Size limits.** Headers: max 10 entries. Token: max 8,192 chars. Username/password: max 256 chars each. Cookies: max 20 entries.

## Works on the Scan Endpoint

The `auth` field is supported on `POST /v1/scan`.

---

[Back to overview](../README.md) | [Getting Started](../getting-started.md)
