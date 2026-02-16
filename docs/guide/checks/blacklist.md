# Blacklist Check

Checks whether the target's IP address appears on DNS-based blocklists (DNSBLs) used by email providers and security services to identify spam, malware, and abuse.

- **Check type:** `blacklist` (light), `blacklist_deep` (deep)
- **Endpoint:** `POST /v1/check/blacklist` or `POST /v1/check_deep/blacklist_deep`
- **Default:** Yes (all targets)

## What Is Checked

### Light scan

Queries 2 major blocklists:

- **Spamhaus ZEN** — composite list covering known spam sources, exploited machines, and policy blocklists
- **Barracuda (BRBL)** — real-time blocklist for spam and abuse

### Deep scan

Queries 15 blocklists for comprehensive coverage:

| Zone | Category |
|------|----------|
| Spamhaus ZEN | Major composite list |
| Barracuda BRBL | Major spam list |
| SpamCop | Spam reports |
| SORBS combined | Aggregate list |
| SORBS spam | Spam-specific |
| UCEPROTECT Level 1 | Single IP listings |
| CBL (Composite Blocking List) | Botnet/exploit |
| DroneBL | DDoS/drone |
| WPBL | Abuse |
| Mailspike | Reputation |
| PSBL | Passive spam |
| UBL (URIBL) | URI blacklist |
| SpamRATS | Automated spam |
| s5h.net | Spam |

## Understanding Findings

| Severity | Example findings |
|----------|-----------------|
| high | Listed on Spamhaus ZEN, listed on Barracuda, listed on SpamCop |
| medium | Listed on SORBS, UCEPROTECT, CBL, DroneBL, WPBL, Mailspike |
| low | Listed on PSBL, UBL, SpamRATS, s5h.net |
| info | Not listed on any checked blocklists |

Being listed on a blocklist can cause email delivery failures and may indicate the IP has been compromised or used for abuse. Major lists (Spamhaus, Barracuda, SpamCop) are widely used by email providers, making those listings more impactful.

## Raw Data Fields

| Field | Description |
|-------|-------------|
| `ip` | IP address that was checked |
| `reversed_ip` | Reversed IP used for DNSBL queries |
| `listings` | Results per zone (listed or not) |
| `listed_count` | Number of lists the IP appears on |
| `total_checked` | Total number of lists queried |

---

[Back to overview](../README.md) | [Getting Started](../getting-started.md)
