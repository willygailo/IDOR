# IDOR References & Cheatsheet

> Quick reference for IDOR research, reporting, and learning.

---

## OWASP References

| Resource | URL |
|----------|-----|
| OWASP BOLA (API1:2023) | https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/ |
| OWASP IDOR Testing Guide | https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References |
| OWASP Top 10 — Broken Access Control | https://owasp.org/Top10/A01_2021-Broken_Access_Control/ |

---

## Learning Resources

| Resource | URL |
|----------|-----|
| PortSwigger IDOR Lab | https://portswigger.net/web-security/access-control/idor |
| HackTricks IDOR | https://book.hacktricks.xyz/pentesting-web/idor |
| PentesterLab IDOR | https://pentesterlab.com/exercises/web_for_pentester/course |

---

## Bug Bounty Platform Guides

| Platform | Severity Guide |
|----------|---------------|
| HackerOne | https://docs.hackerone.com/hackers/severity.html |
| Bugcrowd | https://bugcrowd.com/vulnerability-rating-taxonomy |
| Intigriti | https://blog.intigriti.com/2021/01/05/how-to-write-a-good-bug-report/ |

---

## CVSS Calculator

- Online: https://www.first.org/cvss/calculator/3.1

### Common IDOR Vectors

```
Read-only IDOR (authenticated, PII):
  AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5 (Medium)

Write IDOR (modify/delete victim data):
  AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N = 8.1 (High)

Unauthenticated read + PII:
  AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5 (High)

Unauthenticated write + data destruction:
  AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 (Critical)
```

---

## Useful Tools

| Tool | Purpose | Install |
|------|---------|---------|
| Burp Suite | Intercept & replay HTTP | https://portswigger.net/burp |
| ffuf | Endpoint fuzzing | `apt install ffuf` |
| gau | Fetch URLs from AlienVault, Wayback | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| waybackurls | Historical URL discovery | `go install github.com/tomnomnom/waybackurls@latest` |
| LinkFinder | JS file endpoint extraction | https://github.com/GerbenJavado/LinkFinder |
| Autorize (Burp ext.) | Automated IDOR detection | Burp BApp Store |
| Agartha (Burp ext.) | Privilege escalation testing | Burp BApp Store |

---

## Writeups & Real-World Examples

| Title | URL |
|-------|-----|
| IDOR on Facebook — $1M Bug | https://www.hackerone.com/blog/how-to-find-idors |
| Shopify Partner IDOR | https://hackerone.com/reports/980598 |
| Twitter IDOR — Draft Tweets | https://hackerone.com/reports/462807 |
| IDOR in Gitlab Issues | https://hackerone.com/reports/1125927 |

---

## Quick Payload List

```
# Sequential IDs
1, 2, 3, 100, 101, 1000, 9999

# Zero/Negative
0, -1, -999

# Other users (common test values)
1337, 99999, 123456

# Admin IDs (vertical escalation)
1, 0, admin, root

# Parameter pollution
?id=MINE&id=VICTIM
?id[]=MINE&id[]=VICTIM
```

---

## Reporting Severity Guide

| Finding | Recommended Severity |
|---------|---------------------|
| Read other users' public data | Low / Info |
| Read other users' private data (no PII) | Medium |
| Read PII (name, address, email) | High |
| Read financial/payment data | High |
| Modify or delete victim data | High–Critical |
| Account takeover via IDOR | Critical |
| Admin access via IDOR | Critical |
