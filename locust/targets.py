"""Target pools and check type definitions for load tests."""

import random

# ---------------------------------------------------------------------------
# Domain targets (real, publicly reachable)
# ---------------------------------------------------------------------------
DOMAIN_TARGETS = [
    "example.com",
    "httpbin.org",
    "testphp.vulnweb.com",
    "github.com",
    "cloudflare.com",
]

# ---------------------------------------------------------------------------
# IP targets
# ---------------------------------------------------------------------------
IP_TARGETS = [
    "8.8.8.8",
    "1.1.1.1",
    "93.184.216.34",  # example.com
]

# All targets (domains + IPs) for generic endpoints
ALL_TARGETS = DOMAIN_TARGETS + IP_TARGETS

# ---------------------------------------------------------------------------
# Check types grouped by endpoint prefix
# ---------------------------------------------------------------------------
LIGHT_CHECKS = ["headers", "ssl", "dns", "tech", "blacklist", "web", "whois"]
DEEP_CHECKS = ["ssl", "dns", "tech", "blacklist", "ports"]

# Checks valid for IP targets (no DNS/whois)
IP_LIGHT_CHECKS = ["headers", "ssl", "tech", "blacklist", "web"]
IP_DEEP_CHECKS = ["ssl", "tech", "blacklist", "ports"]


def random_domain() -> str:
    return random.choice(DOMAIN_TARGETS)


def random_ip() -> str:
    return random.choice(IP_TARGETS)


def random_target() -> str:
    return random.choice(ALL_TARGETS)


def random_domains(n: int = 3) -> list[str]:
    """Pick up to n unique domains (capped at pool size)."""
    return random.sample(DOMAIN_TARGETS, min(n, len(DOMAIN_TARGETS)))


def random_ips(n: int = 2) -> list[str]:
    return random.sample(IP_TARGETS, min(n, len(IP_TARGETS)))


def random_targets(n: int = 3) -> list[str]:
    return random.sample(ALL_TARGETS, min(n, len(ALL_TARGETS)))
