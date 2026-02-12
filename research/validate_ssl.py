#!/usr/bin/env python3
"""Validate SSL/TLS scanner against known targets."""

import asyncio
import sys
from pathlib import Path

import yaml

from infraprobe.scanners.ssl import scan

# Severity ordering for max_severity check
_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def check_result(result, expected):
    """Compare scanner result against expected values. Returns list of (ok, message)."""
    checks = []

    # Error check
    if "error" in expected:
        if expected["error"] is None:
            checks.append((result.error is None, f"error is None (got: {result.error!r})"))
        else:
            checks.append(
                (result.error is not None and expected["error"] in result.error, f"error contains '{expected['error']}'")
            )

    # Min findings count
    if "min_findings" in expected:
        n = len(result.findings)
        checks.append((n >= expected["min_findings"], f"findings count >= {expected['min_findings']} (got: {n})"))

    # Finding titles contain expected strings
    if "finding_titles_contain" in expected:
        titles = [f.title.lower() for f in result.findings]
        for needle in expected["finding_titles_contain"]:
            found = any(needle.lower() in t for t in titles)
            checks.append((found, f"finding title contains '{needle}'"))

    # Expected severities present
    if "severities_present" in expected:
        severities = {f.severity.value for f in result.findings}
        for sev in expected["severities_present"]:
            checks.append((sev in severities, f"severity '{sev}' present in findings"))

    # Max severity — no finding should exceed this level
    if "max_severity" in expected:
        max_allowed = _SEVERITY_ORDER[expected["max_severity"]]
        worst = max((_SEVERITY_ORDER.get(f.severity.value, 0) for f in result.findings), default=0)
        worst_name = next((name for name, val in _SEVERITY_ORDER.items() if val == worst), "none")
        checks.append(
            (worst <= max_allowed, f"worst severity <= '{expected['max_severity']}' (got: '{worst_name}')")
        )

    # Raw dict has expected keys
    if "raw_keys" in expected:
        for key in expected["raw_keys"]:
            checks.append((key in result.raw, f"raw has key '{key}'"))

    # Raw value checks
    if "raw_checks" in expected:
        rc = expected["raw_checks"]

        if "protocol_version_contains" in rc:
            val = result.raw.get("protocol_version", "")
            needle = rc["protocol_version_contains"]
            checks.append((needle in val, f"protocol_version contains '{needle}' (got: '{val}')"))

        if "cipher_bits_min" in rc:
            val = result.raw.get("cipher_bits", 0)
            checks.append((val >= rc["cipher_bits_min"], f"cipher_bits >= {rc['cipher_bits_min']} (got: {val})"))

        if "key_bits_min" in rc:
            val = result.raw.get("key_bits", 0)
            checks.append((val >= rc["key_bits_min"], f"key_bits >= {rc['key_bits_min']} (got: {val})"))

        if "days_until_expiry_min" in rc:
            val = result.raw.get("days_until_expiry", 0)
            checks.append(
                (val >= rc["days_until_expiry_min"], f"days_until_expiry >= {rc['days_until_expiry_min']} (got: {val})")
            )

    return checks


async def main():
    targets_file = Path(__file__).parent / "ssl.yaml"
    data = yaml.safe_load(targets_file.read_text())

    total_pass = total_fail = 0
    failed_targets = []

    for entry in data["targets"]:
        target = entry["target"]
        print(f"\n--- {target} ---")
        print(f"    {entry['description']}")

        try:
            result = await scan(target, timeout=15.0)
        except Exception as exc:
            print(f"  [ERROR] Scanner crashed: {exc}")
            total_fail += 1
            failed_targets.append(target)
            continue

        target_failed = False
        for ok, msg in check_result(result, entry["expected"]):
            status = "PASS" if ok else "FAIL"
            print(f"  [{status}] {msg}")
            if ok:
                total_pass += 1
            else:
                total_fail += 1
                target_failed = True

        if target_failed:
            failed_targets.append(target)

    print(f"\n{'=' * 60}")
    print(f"SSL scanner: {total_pass} passed, {total_fail} failed")
    if failed_targets:
        print(f"Failed targets: {', '.join(failed_targets)}")

    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
