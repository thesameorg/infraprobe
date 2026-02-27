from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

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
    HEADERS = "headers"
    DNS = "dns"
    WEB = "web"
    WHOIS = "whois"


# Default checks for domain targets
DOMAIN_CHECKS: list[CheckType] = [
    CheckType.HEADERS,
    CheckType.SSL,
    CheckType.DNS,
    CheckType.WEB,
    CheckType.WHOIS,
]

# Default checks for IP targets (no DNS — meaningless for raw IPs)
IP_CHECKS: list[CheckType] = [
    CheckType.HEADERS,
    CheckType.SSL,
    CheckType.WEB,
]

# Checks that require a domain name (not applicable to IP targets)
DNS_ONLY_CHECKS: frozenset[CheckType] = frozenset({CheckType.DNS, CheckType.WHOIS})


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
    duration_ms: int | None = None
    timeout_ms: int | None = None


# ---------------------------------------------------------------------------
# Auth config (discriminated union)
# ---------------------------------------------------------------------------

_FORBIDDEN_HEADERS = frozenset({"host", "content-length", "transfer-encoding", "connection"})


class HeaderAuth(BaseModel):
    type: Literal["header"]
    headers: dict[str, str] = Field(min_length=1, max_length=10)

    @model_validator(mode="after")
    def _reject_hop_by_hop(self) -> "HeaderAuth":
        bad = {k for k in self.headers if k.lower() in _FORBIDDEN_HEADERS}
        if bad:
            msg = f"Forbidden header(s): {', '.join(sorted(bad))}"
            raise ValueError(msg)
        return self


class BasicAuth(BaseModel):
    type: Literal["basic"]
    username: str = Field(max_length=256)
    password: str = Field(max_length=256)


class BearerAuth(BaseModel):
    type: Literal["bearer"]
    token: str = Field(max_length=8192)


class CookieAuth(BaseModel):
    type: Literal["cookie"]
    cookies: dict[str, str] = Field(min_length=1, max_length=20)


AuthConfig = Annotated[
    HeaderAuth | BasicAuth | BearerAuth | CookieAuth,
    Field(discriminator="type"),
]


class SingleCheckRequest(BaseModel):
    model_config = ConfigDict(json_schema_extra={"examples": [{"target": "example.com"}]})

    target: TargetStr = Field(
        description="Domain name, IP address, or host:port to scan (e.g. 'example.com', '93.184.216.34')."
    )
    auth: AuthConfig | None = Field(
        default=None,
        exclude=True,
        description="Credentials to send to the scan target (header, basic, bearer, or cookie auth).",
    )


_SCORE_PENALTY: dict[str, int] = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class SeveritySummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0
    score: int = 100


def _compute_summary(findings: list[Finding]) -> SeveritySummary:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    penalty = sum(count * _SCORE_PENALTY.get(sev, 0) for sev, count in counts.items())
    return SeveritySummary(
        critical=counts.get(Severity.CRITICAL, 0),
        high=counts.get(Severity.HIGH, 0),
        medium=counts.get(Severity.MEDIUM, 0),
        low=counts.get(Severity.LOW, 0),
        info=counts.get(Severity.INFO, 0),
        total=len(findings),
        score=max(0, 100 - penalty),
    )


class TargetResult(BaseModel):
    target: str
    results: dict[str, CheckResult]
    duration_ms: int
    summary: SeveritySummary = Field(default_factory=SeveritySummary)

    @model_validator(mode="after")
    def _compute_target_summary(self) -> "TargetResult":
        all_findings: list[Finding] = []
        for check_result in self.results.values():
            all_findings.extend(check_result.findings)
        self.summary = _compute_summary(all_findings)
        return self


class ScanResponse(BaseModel):
    results: list[TargetResult]
    summary: SeveritySummary = Field(default_factory=SeveritySummary)

    @model_validator(mode="after")
    def _compute_scan_summary(self) -> "ScanResponse":
        all_findings: list[Finding] = []
        for target_result in self.results:
            for check_result in target_result.results.values():
                all_findings.extend(check_result.findings)
        self.summary = _compute_summary(all_findings)
        return self


class ErrorResponse(BaseModel):
    error: str
    detail: str
