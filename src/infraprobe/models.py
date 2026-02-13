from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CheckType(StrEnum):
    SSL = "ssl"
    SSL_DEEP = "ssl_deep"
    HEADERS = "headers"
    DNS = "dns"
    DNS_DEEP = "dns_deep"
    TECH = "tech"
    TECH_DEEP = "tech_deep"
    BLACKLIST = "blacklist"
    WEB = "web"


# Default checks for domain targets (light only — deep checks are opt-in)
DOMAIN_CHECKS: list[CheckType] = [
    CheckType.HEADERS,
    CheckType.SSL,
    CheckType.DNS,
    CheckType.TECH,
    CheckType.BLACKLIST,
]

# Default checks for IP targets (no DNS — meaningless for raw IPs)
IP_CHECKS: list[CheckType] = [
    CheckType.HEADERS,
    CheckType.SSL,
    CheckType.TECH,
    CheckType.BLACKLIST,
]

# Checks that require a domain name (not applicable to IP targets)
DNS_ONLY_CHECKS: frozenset[CheckType] = frozenset({CheckType.DNS, CheckType.DNS_DEEP})

# Backward-compatible alias
LIGHT_CHECKS = DOMAIN_CHECKS


class Finding(BaseModel):
    severity: Severity
    title: str
    description: str
    details: dict[str, Any] = Field(default_factory=dict)


class CheckResult(BaseModel):
    check: CheckType
    findings: list[Finding] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class SingleCheckRequest(BaseModel):
    target: str


class ScanRequest(BaseModel):
    targets: list[str] = Field(min_length=1, max_length=10)
    checks: list[CheckType] = Field(default_factory=lambda: list(LIGHT_CHECKS))


class DomainScanRequest(BaseModel):
    targets: list[str] = Field(min_length=1, max_length=10)
    checks: list[CheckType] = Field(default_factory=lambda: list(DOMAIN_CHECKS))


class IpScanRequest(BaseModel):
    targets: list[str] = Field(min_length=1, max_length=10)
    checks: list[CheckType] = Field(default_factory=lambda: list(IP_CHECKS))


class SeveritySummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class TargetResult(BaseModel):
    target: str
    score: str
    summary: SeveritySummary
    results: dict[str, CheckResult]
    duration_ms: int


class ScanResponse(BaseModel):
    results: list[TargetResult]
