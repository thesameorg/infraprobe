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
    HEADERS = "headers"
    DNS = "dns"
    TECH = "tech"


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


class ScanRequest(BaseModel):
    targets: list[str] = Field(min_length=1, max_length=10)
    checks: list[CheckType] = Field(default_factory=lambda: list(CheckType))


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
