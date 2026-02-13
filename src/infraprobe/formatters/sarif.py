"""Convert InfraProbe scan results to SARIF 2.1.0 format.

SARIF (Static Analysis Results Interchange Format) is a JSON-based standard
used by GitHub Security tab, Azure DevOps, and CI/CD pipelines.
"""

import re

from infraprobe import __version__
from infraprobe.models import CheckResult, ScanResponse, Severity, TargetResult

_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"

_SEVERITY_MAP: dict[Severity, tuple[str, float]] = {
    Severity.CRITICAL: ("error", 9.5),
    Severity.HIGH: ("error", 8.0),
    Severity.MEDIUM: ("warning", 5.5),
    Severity.LOW: ("note", 3.0),
    Severity.INFO: ("note", 1.0),
}


def _slugify(text: str) -> str:
    """Convert a finding title to a URL-safe slug for rule IDs."""
    slug = text.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    return slug.strip("-")


def _make_rule_id(check_name: str, title: str) -> str:
    return f"{check_name}/{_slugify(title)}"


def scan_response_to_sarif(response: ScanResponse) -> dict:
    """Convert a full ScanResponse (multi-target) to a SARIF 2.1.0 dict."""
    rules: dict[str, dict] = {}  # rule_id → rule object (deduped)
    results: list[dict] = []

    for target_result in response.results:
        _collect_target(target_result, rules, results)

    return {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "InfraProbe",
                        "version": __version__,
                        "informationUri": "https://github.com/dmitrykozlov/infraprobe",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def target_result_to_sarif(result: TargetResult) -> dict:
    """Convert a single TargetResult to SARIF by wrapping it in a ScanResponse."""
    response = ScanResponse(results=[result])
    return scan_response_to_sarif(response)


def _collect_target(
    target_result: TargetResult,
    rules: dict[str, dict],
    results: list[dict],
) -> None:
    """Process one target's results into shared rules + results lists."""
    target = target_result.target

    for check_name, check_result in target_result.results.items():
        if check_result.error and not check_result.findings:
            continue
        _collect_check(target, check_name, check_result, rules, results)


def _collect_check(
    target: str,
    check_name: str,
    check_result: CheckResult,
    rules: dict[str, dict],
    results: list[dict],
) -> None:
    """Process one check's findings into shared rules + results lists."""
    for finding in check_result.findings:
        rule_id = _make_rule_id(check_name, finding.title)
        level, security_severity = _SEVERITY_MAP[finding.severity]

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "properties": {"security-severity": str(security_severity)},
            }

        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": finding.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": target},
                            "region": {"startLine": 1},
                        }
                    }
                ],
            }
        )
