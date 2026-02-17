# CVE Check

Detects known vulnerabilities (CVEs) by identifying running service versions and querying the National Vulnerability Database (NVD).

- **Check type:** `cve`
- **Endpoint:** `POST /v1/check/cve`
- **Default:** Opt-in (not included in default scans)
- **Deep variant:** This is itself a deep-level check (30-second timeout)

## How It Works

1. **Port scan with version detection** — scans the top 20 ports with service fingerprinting to identify running software and versions
2. **CPE matching** — converts detected services to Common Platform Enumeration (CPE) identifiers
3. **NVD lookup** — queries the NIST National Vulnerability Database for known CVEs matching each CPE

This check requires open ports with identifiable services. If no services are detected, no CVEs can be found.

## Understanding Findings

CVE findings are classified by CVSS (Common Vulnerability Scoring System) score:

| Severity | CVSS Score | Meaning |
|----------|-----------|---------|
| critical | 9.0 - 10.0 | Exploitable with severe impact |
| high | 7.0 - 8.9 | Serious vulnerability |
| medium | 4.0 - 6.9 | Moderate risk |
| low | 0.1 - 3.9 | Minor vulnerability |
| info | < 0.1 | Minimal risk |

Each finding includes the CVE ID, CVSS score, affected product and version, and the port where the service was detected.

Findings are sorted by severity (most critical first), then by CVE ID.

## Raw Data Fields

| Field | Description |
|-------|-------------|
| `host` | Scanned host |
| `services_scanned` | Number of services with version info |
| `services` | List of detected services with `cpe`, `product`, `version` |
| `cves_found` | Total number of CVEs found |
| `cves` | List of CVEs, each with `cve_id`, `cvss_score`, `product`, `version`, `port` |

## Notes

- The CVE check uses a 30-second timeout, split between port scanning (~70%) and NVD queries (~25%)
- Results depend on nmap's ability to fingerprint service versions — services that don't expose version banners may not produce CVE results
- An NVD API key (configured server-side) increases query rate limits and improves reliability for targets with many services
- OS-level CPEs are excluded from lookups to focus on application-level vulnerabilities

---

[Back to overview](../README.md) | [Getting Started](../getting-started.md)
