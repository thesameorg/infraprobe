from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any

from pydantic import BaseModel, Field

TargetStr = Annotated[str, Field(max_length=2048)]


class OutputFormat(StrEnum):
    JSON = "json"
    SARIF = "sarif"
    CSV = "csv"


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
    BLACKLIST_DEEP = "blacklist_deep"
    WEB = "web"
    PORTS = "ports"
    PORTS_DEEP = "ports_deep"
    CVE = "cve"
    WHOIS = "whois"


# Default checks for domain targets (light only — deep checks are opt-in)
DOMAIN_CHECKS: list[CheckType] = [
    CheckType.HEADERS,
    CheckType.SSL,
    CheckType.DNS,
    CheckType.TECH,
    CheckType.BLACKLIST,
    CheckType.WHOIS,
]

# Default checks for IP targets (no DNS — meaningless for raw IPs)
IP_CHECKS: list[CheckType] = [
    CheckType.HEADERS,
    CheckType.SSL,
    CheckType.TECH,
    CheckType.BLACKLIST,
]

# Checks that require a domain name (not applicable to IP targets)
DNS_ONLY_CHECKS: frozenset[CheckType] = frozenset({CheckType.DNS, CheckType.DNS_DEEP, CheckType.WHOIS})

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
    target: TargetStr


class ScanRequest(BaseModel):
    targets: list[TargetStr] = Field(min_length=1, max_length=10)
    checks: list[CheckType] = Field(default_factory=lambda: list(LIGHT_CHECKS))
    webhook_url: Annotated[str, Field(max_length=2048)] | None = None
    webhook_secret: str | None = Field(default=None, exclude=True)


class DomainScanRequest(BaseModel):
    targets: list[TargetStr] = Field(min_length=1, max_length=10)
    checks: list[CheckType] = Field(default_factory=lambda: list(DOMAIN_CHECKS))


class IpScanRequest(BaseModel):
    targets: list[TargetStr] = Field(min_length=1, max_length=10)
    checks: list[CheckType] = Field(default_factory=lambda: list(IP_CHECKS))


class TargetResult(BaseModel):
    target: str
    results: dict[str, CheckResult]
    duration_ms: int


class ScanResponse(BaseModel):
    results: list[TargetResult]


# ---------------------------------------------------------------------------
# Async job models
# ---------------------------------------------------------------------------


class ErrorResponse(BaseModel):
    error: str
    detail: str


class JobStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class JobCreate(BaseModel):
    job_id: str
    status: JobStatus
    created_at: datetime


class Job(BaseModel):
    job_id: str
    status: JobStatus
    created_at: datetime
    updated_at: datetime
    request: ScanRequest
    result: ScanResponse | None = None
    error: str | None = None
    webhook_status: str | None = None
    webhook_delivered_at: datetime | None = None
