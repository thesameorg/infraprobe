#!/usr/bin/env python3
"""Validate DNS scanner against known targets.

NOTE: DNS scanner is not yet implemented. This script will fail gracefully
until scanners/dns.py exists. Once implemented, it validates real results.
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

    # DNS-specific checks would go here once scanner is implemented:
    # - dns_records_present: check raw dict for A, AAAA, MX, NS, TXT records
    # - spf.present / spf.policy: check TXT records for SPF
    # - dmarc.present / dmarc.policy: check _dmarc TXT record
    # - caa.present / caa.issuers_contain: check CAA records

    # For now, just verify we got a result with expected structure
    if result.error is None:
        if "dns_records_present" in expected:
            for record_type in expected["dns_records_present"]:
                found = record_type.lower() in {k.lower() for k in result.raw.keys()}
                checks.append((found, f"raw has '{record_type}' records"))

        if "spf" in expected:
            spf_data = result.raw.get("spf", {})
            if expected["spf"]["present"]:
                checks.append((bool(spf_data), "SPF record present"))
                if "policy" in expected["spf"] and spf_data:
                    record = spf_data if isinstance(spf_data, str) else str(spf_data)
                    checks.append(
                        (expected["spf"]["policy"] in record, f"SPF policy contains '{expected['spf']['policy']}'")
                    )
            else:
                checks.append((not spf_data, "SPF record absent (expected missing)"))

        if "dmarc" in expected:
            dmarc_data = result.raw.get("dmarc", {})
            if expected["dmarc"]["present"]:
                checks.append((bool(dmarc_data), "DMARC record present"))
                if "policy" in expected["dmarc"] and dmarc_data:
                    record = dmarc_data if isinstance(dmarc_data, str) else str(dmarc_data)
                    checks.append(
                        (expected["dmarc"]["policy"] in record, f"DMARC policy contains '{expected['dmarc']['policy']}'")
                    )
            else:
                checks.append((not dmarc_data, "DMARC record absent (expected missing)"))

        if "caa" in expected:
            caa_data = result.raw.get("caa", [])
            if expected["caa"]["present"]:
                checks.append((bool(caa_data), "CAA records present"))
                if "issuers_contain" in expected["caa"] and caa_data:
                    caa_str = str(caa_data).lower()
                    for issuer in expected["caa"]["issuers_contain"]:
                        checks.append((issuer.lower() in caa_str, f"CAA contains issuer '{issuer}'"))
            else:
                checks.append((not caa_data, "CAA records absent (expected missing)"))

    return checks


async def main():
    # Try to import the DNS scanner
    try:
        from infraprobe.scanners.dns import scan
    except ImportError:
        print("DNS scanner not yet implemented (scanners/dns.py not found).")
        print("Targets are defined in dns.yaml — run this script after implementing the scanner.")
        return 0

    targets_file = Path(__file__).parent / "dns.yaml"
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
    print(f"DNS scanner: {total_pass} passed, {total_fail} failed")
    if failed_targets:
        print(f"Failed targets: {', '.join(failed_targets)}")

    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
