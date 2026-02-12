#!/usr/bin/env python3
"""Validate tech detection scanner against known targets.

NOTE: Tech scanner is not yet implemented. This script will fail gracefully
until scanners/tech.py exists. Once implemented, it validates real results.
"""

import asyncio
import sys
from pathlib import Path

import yaml


def check_result(result, expected):
    """Compare scanner result against expected values. Returns list of (ok, message)."""
    checks = []

    if "error" in expected:
        if expected["error"] is None:
            checks.append((result.error is None, f"error is None (got: {result.error!r})"))

    if result.error is None:
        # Tech detection checks — look in raw dict for detected technologies
        if "technologies_contain" in expected:
            # The scanner should put detected tech names in raw (exact key TBD)
            detected = str(result.raw).lower()
            for tech in expected["technologies_contain"]:
                checks.append((tech.lower() in detected, f"detected technology '{tech}'"))

        if "version_detected" in expected:
            raw_str = str(result.raw).lower()
            for tech, version in expected["version_detected"].items():
                checks.append((version.lower() in raw_str, f"detected {tech} version '{version}'"))

    return checks


async def main():
    try:
        from infraprobe.scanners.tech import scan
    except ImportError:
        print("Tech scanner not yet implemented (scanners/tech.py not found).")
        print("Targets are defined in tech.yaml — run this script after implementing the scanner.")
        return 0

    targets_file = Path(__file__).parent / "tech.yaml"
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
    print(f"Tech scanner: {total_pass} passed, {total_fail} failed")
    if failed_targets:
        print(f"Failed targets: {', '.join(failed_targets)}")

    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
