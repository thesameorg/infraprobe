#!/usr/bin/env python3
"""Validate headers scanner against known targets."""

import asyncio
import sys
from pathlib import Path

import yaml

from infraprobe.scanners.headers import scan


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

    # Finding titles contain expected strings (case-insensitive)
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

    # Raw dict has expected keys
    if "raw_keys" in expected:
        for key in expected["raw_keys"]:
            checks.append((key in result.raw, f"raw has key '{key}'"))

    return checks


async def main():
    targets_file = Path(__file__).parent / "headers.yaml"
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
    print(f"Headers scanner: {total_pass} passed, {total_fail} failed")
    if failed_targets:
        print(f"Failed targets: {', '.join(failed_targets)}")

    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
