"""Target pools for load tests.

Three tiers:
  - FAST:  respond quickly, low variance (example.com, httpbin.org)
  - MEDIUM: real-world sites, moderate latency (github.com, cloudflare.com)
  - SLOW:  large DNS records, heavy pages (google.com)

Plus failure targets for degradation testing.
"""

import random

# ---------------------------------------------------------------------------
# Domain targets — tiered by expected response time
# ---------------------------------------------------------------------------
FAST_DOMAINS = [
    "example.com",
    "httpbin.org",
]

MEDIUM_DOMAINS = [
    "testphp.vulnweb.com",
    "github.com",
    "cloudflare.com",
]

SLOW_DOMAINS = [
    "google.com",  # 12 TXT records, 886 bytes — stresses DNS resolver
]

# Failure domains — for degradation/cascade tests only
FAILURE_DOMAINS = [
    "thisdomaindoesnotexist.invalid",  # NXDOMAIN
    "timeout.example.invalid",  # NXDOMAIN (simulates unreachable)
]

# Composite pools
DOMAIN_TARGETS = FAST_DOMAINS + MEDIUM_DOMAINS + SLOW_DOMAINS
ALL_DOMAINS_WITH_FAILURES = DOMAIN_TARGETS + FAILURE_DOMAINS

# ---------------------------------------------------------------------------
# IP targets
# ---------------------------------------------------------------------------
IP_TARGETS = [
    "8.8.8.8",  # Google DNS — fast, always up
    "1.1.1.1",  # Cloudflare DNS — fast, always up
    "93.184.216.34",  # example.com
]

ALL_TARGETS = DOMAIN_TARGETS + IP_TARGETS
ALL_TARGETS_WITH_FAILURES = ALL_DOMAINS_WITH_FAILURES + IP_TARGETS

# ---------------------------------------------------------------------------
# Check types
# ---------------------------------------------------------------------------
LIGHT_CHECKS = ["headers", "ssl", "dns", "tech", "blacklist", "web", "whois"]
DEEP_CHECKS = ["ssl", "dns", "tech", "blacklist", "ports"]
IP_LIGHT_CHECKS = ["headers", "ssl", "tech", "blacklist", "web"]
IP_DEEP_CHECKS = ["ssl", "tech", "blacklist", "ports"]


# ---------------------------------------------------------------------------
# Selection helpers
# ---------------------------------------------------------------------------
def random_domain() -> str:
    return random.choice(DOMAIN_TARGETS)


def random_ip() -> str:
    return random.choice(IP_TARGETS)


def random_target() -> str:
    return random.choice(ALL_TARGETS)


def random_domains(n: int = 3) -> list[str]:
    return random.sample(DOMAIN_TARGETS, min(n, len(DOMAIN_TARGETS)))


def random_ips(n: int = 2) -> list[str]:
    return random.sample(IP_TARGETS, min(n, len(IP_TARGETS)))


def random_targets(n: int = 3) -> list[str]:
    return random.sample(ALL_TARGETS, min(n, len(ALL_TARGETS)))


def weighted_domain() -> str:
    """Pick a domain with realistic distribution: mostly fast/medium, rarely slow."""
    pool = FAST_DOMAINS * 4 + MEDIUM_DOMAINS * 3 + SLOW_DOMAINS * 1
    return random.choice(pool)


def domain_with_failures() -> str:
    """Pick from full pool including failure targets (~20% failure rate)."""
    pool = DOMAIN_TARGETS * 3 + FAILURE_DOMAINS * 2
    return random.choice(pool)


def domains_with_failures(n: int = 3) -> list[str]:
    """Pick n targets, mix of good and bad."""
    pool = DOMAIN_TARGETS * 3 + FAILURE_DOMAINS * 2
    return [random.choice(pool) for _ in range(n)]
