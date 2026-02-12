import re
from typing import Any

import httpx

from infraprobe.models import CheckResult, CheckType, Finding, Severity

# --- Detection patterns ---
# Each entry: (technology_name, category, patterns_dict)
# patterns_dict keys: "headers" (header_name: regex), "meta" (name_attr: regex on content),
#                     "cookies" (cookie_name_regex), "html" (regex on body)

_TECHNOLOGIES: list[tuple[str, str, dict[str, Any]]] = [
    # --- Web servers ---
    ("Nginx", "web-server", {"headers": {"server": r"nginx"}}),
    ("Apache", "web-server", {"headers": {"server": r"apache"}}),
    ("LiteSpeed", "web-server", {"headers": {"server": r"litespeed"}}),
    ("IIS", "web-server", {"headers": {"server": r"microsoft-iis"}}),
    ("Caddy", "web-server", {"headers": {"server": r"caddy"}}),
    # --- CDN ---
    ("Cloudflare", "cdn", {"headers": {"server": r"cloudflare", "cf-ray": r"."}}),
    ("Fastly", "cdn", {"headers": {"x-served-by": r"cache-", "via": r"varnish"}}),
    ("Akamai", "cdn", {"headers": {"x-akamai-transformed": r"."}}),
    ("Amazon CloudFront", "cdn", {"headers": {"x-amz-cf-id": r".", "via": r"cloudfront"}}),
    ("Vercel", "cdn", {"headers": {"x-vercel-id": r".", "server": r"vercel"}}),
    # --- WAF ---
    ("Cloudflare WAF", "waf", {"headers": {"cf-mitigated": r"."}}),
    ("AWS WAF", "waf", {"headers": {"x-amzn-waf-action": r"."}}),
    ("Sucuri", "waf", {"headers": {"x-sucuri-id": r".", "server": r"sucuri"}}),
    # --- Frameworks / Languages ---
    ("PHP", "language", {"headers": {"x-powered-by": r"php"}}),
    ("ASP.NET", "framework", {"headers": {"x-powered-by": r"asp\.net", "x-aspnet-version": r"."}}),
    ("Express", "framework", {"headers": {"x-powered-by": r"express"}}),
    ("Django", "framework", {"headers": {"x-framework": r"django"}, "html": [r"csrfmiddlewaretoken"]}),
    ("Ruby on Rails", "framework", {"headers": {"x-powered-by": r"phusion|rails"}, "html": [r"csrf-token"]}),
    ("Next.js", "framework", {"headers": {"x-nextjs-cache": r".", "x-powered-by": r"next\.js"}}),
    # --- CMS ---
    (
        "WordPress",
        "cms",
        {
            "html": [r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress', r"/wp-content/", r"/wp-includes/"],
            "cookies": ["wordpress_", "wp-settings"],
        },
    ),
    (
        "Drupal",
        "cms",
        {
            "headers": {"x-generator": r"drupal", "x-drupal-cache": r"."},
            "html": [r'<meta\s+name=["\']Generator["\']\s+content=["\']Drupal'],
        },
    ),
    (
        "Joomla",
        "cms",
        {
            "html": [r'<meta\s+name=["\']generator["\']\s+content=["\']Joomla'],
            "cookies": ["joomla_"],
        },
    ),
    ("Shopify", "ecommerce", {"headers": {"x-shopid": r"."}, "html": [r"cdn\.shopify\.com"]}),
    ("Squarespace", "cms", {"html": [r"squarespace\.com", r"<!-- This is Squarespace"]}),
    # --- Analytics / Tag managers ---
    ("Google Analytics", "analytics", {"html": [r"google-analytics\.com/analytics\.js", r"gtag/js\?id=G-"]}),
    ("Google Tag Manager", "analytics", {"html": [r"googletagmanager\.com/gtm\.js"]}),
    # --- Caching ---
    ("Varnish", "cache", {"headers": {"via": r"varnish", "x-varnish": r"."}}),
    ("Redis", "cache", {"headers": {"x-cache-engine": r"redis"}}),
]


async def _fetch(target: str, timeout: float) -> httpx.Response:
    """Try HTTPS first, fall back to HTTP."""
    host = target.split(":")[0] if ":" in target and not target.startswith("[") else target

    if "://" in target:
        async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=True) as client:
            return await client.get(target)

    try:
        connect_timeout = min(3.0, timeout)
        timeouts = httpx.Timeout(timeout, connect=connect_timeout)
        async with httpx.AsyncClient(verify=False, timeout=timeouts, follow_redirects=True) as client:
            return await client.get(f"https://{target}")
    except httpx.HTTPError:
        pass

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        return await client.get(f"http://{host}")


def _detect(
    headers_lower: dict[str, str],
    body: str,
    cookie_names: list[str],
) -> list[dict[str, str]]:
    """Run detection patterns against response data. Returns list of detected technologies."""
    detected: list[dict[str, str]] = []
    seen: set[str] = set()

    for tech_name, category, patterns in _TECHNOLOGIES:
        if tech_name in seen:
            continue

        matched = False

        # Header patterns
        header_patterns: dict[str, str] = patterns.get("headers", {})
        for header_name, regex in header_patterns.items():
            value = headers_lower.get(header_name, "")
            if value and re.search(regex, value, re.IGNORECASE):
                matched = True
                break

        # HTML body patterns
        if not matched:
            html_patterns: list[str] = patterns.get("html", [])
            for regex in html_patterns:
                if re.search(regex, body, re.IGNORECASE):
                    matched = True
                    break

        # Cookie patterns
        if not matched:
            cookie_patterns: list[str] = patterns.get("cookies", [])
            for cookie_prefix in cookie_patterns:
                if any(cookie_prefix.lower() in cn.lower() for cn in cookie_names):
                    matched = True
                    break

        if matched:
            seen.add(tech_name)
            detected.append({"name": tech_name, "category": category})

    return detected


async def scan(target: str, timeout: float = 10.0) -> CheckResult:
    try:
        resp = await _fetch(target, timeout)
    except httpx.HTTPError as exc:
        return CheckResult(check=CheckType.TECH, error=f"Cannot connect to {target}: {exc}")

    headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
    body = resp.text[:200_000]  # Cap body size for pattern matching
    cookie_names = list(resp.cookies.keys())

    detected = _detect(headers_lower, body, cookie_names)

    findings: list[Finding] = []

    # Flag outdated/risky tech detections
    for tech in detected:
        name = tech["name"]
        # Info-leak: server software version exposed via headers is already covered by headers scanner
        # Here we flag tech that has security implications
        if name == "WordPress":
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title="WordPress detected",
                    description="WordPress CMS detected. Ensure core, themes, and plugins are up to date.",
                    details=tech,
                )
            )
        elif name == "Joomla":
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title="Joomla detected",
                    description="Joomla CMS detected. Ensure core and extensions are up to date.",
                    details=tech,
                )
            )
        elif name == "Drupal":
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title="Drupal detected",
                    description="Drupal CMS detected. Ensure core and modules are up to date.",
                    details=tech,
                )
            )
        elif name == "PHP":
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    title="PHP version exposed",
                    description="PHP detected via X-Powered-By header. Version exposure aids attackers.",
                    details=tech,
                )
            )

    # Positive findings for security-relevant tech
    categories_seen = {t["category"] for t in detected}
    if "cdn" in categories_seen:
        cdn_names = [t["name"] for t in detected if t["category"] == "cdn"]
        findings.append(
            Finding(
                severity=Severity.INFO,
                title=f"CDN detected ({', '.join(cdn_names)})",
                description="A CDN provides DDoS protection and improved performance.",
            )
        )
    if "waf" in categories_seen:
        waf_names = [t["name"] for t in detected if t["category"] == "waf"]
        findings.append(
            Finding(
                severity=Severity.INFO,
                title=f"WAF detected ({', '.join(waf_names)})",
                description="A Web Application Firewall helps protect against common attacks.",
            )
        )

    raw = {
        "url": str(resp.url),
        "detected": detected,
        "technologies_count": len(detected),
    }

    return CheckResult(check=CheckType.TECH, findings=findings, raw=raw)
