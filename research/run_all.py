#!/usr/bin/env python3
"""Run all scanner validation scripts and report summary."""

import subprocess
import sys


VALIDATORS = [
    ("Headers", "validate_headers.py"),
    ("SSL", "validate_ssl.py"),
    ("DNS", "validate_dns.py"),
    ("Tech", "validate_tech.py"),
]


def main():
    results = {}
    research_dir = str(__import__("pathlib").Path(__file__).parent)

    for name, script in VALIDATORS:
        print(f"\n{'=' * 60}")
        print(f"  {name} Scanner Validation")
        print(f"{'=' * 60}")

        ret = subprocess.run(
            [sys.executable, f"{research_dir}/{script}"],
            cwd=research_dir,
        )
        results[name] = ret.returncode

    print(f"\n{'=' * 60}")
    print("  SUMMARY")
    print(f"{'=' * 60}")
    for name, code in results.items():
        status = "PASS" if code == 0 else "FAIL"
        print(f"  [{status}] {name}")

    failed = sum(1 for c in results.values() if c != 0)
    print(f"\n{len(results) - failed}/{len(results)} scanners passed validation")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
