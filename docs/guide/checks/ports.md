# Port Scan Check

Scans for open TCP ports and classifies them by security risk using nmap.

- **Check type:** `ports`
- **Endpoint:** `POST /v1/check/ports`
- **Default:** Opt-in (not included in default scans)

## What Is Checked

Scans the **top 20** most common TCP ports using nmap. Identifies open ports and their services.

For service version detection and CVE vulnerability lookups, use the [CVE check](cve.md) which performs its own nmap version scan (`-sV`) plus NVD API lookups.

## Understanding Findings

Open ports are classified by the security risk of the service:

| Severity | Ports / Services |
|----------|-----------------|
| critical | Telnet (23), NFS (2049), CouchDB (5984), Redis (6379), Elasticsearch (9200/9300), Memcached (11211), MongoDB (27017) |
| high | FTP (21), SMB (139/445), rexec/rlogin/rsh (512-514), Java RMI (1099), MSSQL (1433), Oracle (1521), MySQL (3306), RDP (3389), PostgreSQL (5432), VNC (5900) |
| medium | SMTP (25), POP3 (110), IMAP (143), SNMP (161/162), LDAP (389/636), MQTT (1883) |
| info | SSH (22), DNS (53), HTTP (80), HTTPS (443) |
| low | Other open ports |

Services like databases (Redis, MongoDB, Elasticsearch) and remote access tools (Telnet, VNC, RDP) are flagged at higher severity because they are frequent targets for exploitation, especially when exposed to the public internet.

## Raw Data Fields

| Field | Description |
|-------|-------------|
| `host` | Scanned host |
| `open_ports` | List of open ports, each with `port`, `protocol`, `service`, `state`, `product`, and `version` |
| `open_count` | Total number of open ports found |
| `command_line` | nmap command that was executed |

---

[Back to overview](../README.md) | [Getting Started](../getting-started.md)
