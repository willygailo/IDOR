#!/usr/bin/env python3
"""
Auto Report Generator
=====================
Converts IDOR scan JSON results → Professional HTML + Markdown reports.

Supports:
  - JSON from idor_enum.py, threaded_idor_enum.py, graphql_idor_tester.py, uuid_idor_brute.py
  - CVSS severity scoring
  - Evidence table with snippets
  - One-click HTML report with dark theme

Usage:
    python3 report_generator.py --input idor_results.json --target https://target.com --title "Billing API IDOR"
    python3 report_generator.py --input graphql_idor_results.json --format html --severity high --output report.html

⚠️  For authorized reporting only.
"""

import argparse
import json
import os
import sys
from datetime import datetime
from typing import Optional
from pathlib import Path

from jinja2 import Template
from rich.console import Console

console = Console()

# ─── CVSS Auto-Scorer ─────────────────────────────────────────────────────────
def auto_severity(findings: list) -> tuple:
    """
    Simple severity estimator based on finding count and data exposed.
    Returns (severity_label, color, cvss_estimate, rationale)
    """
    count = len(findings)
    # Check if any finding contains PII keywords
    pii_keywords = ["email", "phone", "ssn", "password", "credit", "card",
                    "dob", "address", "balance", "token", "secret"]
    snippets = " ".join(
        json.dumps(f.get("snippet", "") or f.get("response", "")).lower()
        for f in findings
    )
    has_pii = any(k in snippets for k in pii_keywords)

    if count == 0:
        return ("Informational", "#6c757d", "0.0", "No confirmed IDOR findings")
    if has_pii and count >= 10:
        return ("Critical", "#dc3545", "9.1", "Large-scale PII data exposure via IDOR")
    if has_pii:
        return ("High", "#fd7e14", "8.1", "PII data exposed via IDOR")
    if count >= 50:
        return ("High", "#fd7e14", "7.5", "Mass object enumeration confirmed")
    if count >= 10:
        return ("Medium", "#ffc107", "6.5", "Moderate object enumeration")
    return ("Low", "#20c997", "4.3", f"{count} resource(s) accessible without authorization")


# ─── HTML Report Template ─────────────────────────────────────────────────────
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{ title }} — IDOR Bug Bounty Report</title>
  <style>
    :root {
      --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
      --border: #30363d; --text: #c9d1d9; --text2: #8b949e;
      --accent: #58a6ff; --green: #3fb950; --red: #f85149;
      --orange: #f0883e; --yellow: #e3b341; --purple: #d2a8ff;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; line-height: 1.6; }
    .header { background: linear-gradient(135deg, #0d1117 0%, #161b22 50%, #1c2333 100%);
              border-bottom: 1px solid var(--border); padding: 40px 60px; }
    .header h1 { font-size: 2rem; color: var(--accent); }
    .header .meta { color: var(--text2); font-size: 0.9rem; margin-top: 8px; }
    .badge { display: inline-block; padding: 4px 12px; border-radius: 20px;
             font-weight: 700; font-size: 0.85rem; background: {{ sev_color }}22;
             color: {{ sev_color }}; border: 1px solid {{ sev_color }}44; }
    .container { max-width: 1100px; margin: 0 auto; padding: 40px 60px; }
    .section { margin-bottom: 40px; }
    .section h2 { font-size: 1.2rem; color: var(--accent); border-bottom: 1px solid var(--border);
                  padding-bottom: 8px; margin-bottom: 16px; }
    .card { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px;
            padding: 20px; margin-bottom: 16px; }
    .card pre { background: var(--bg3); border-radius: 6px; padding: 12px; font-size: 0.8rem;
                overflow-x: auto; color: #a5d6ff; border: 1px solid var(--border); margin-top: 10px; white-space: pre-wrap; }
    .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; }
    .stat { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px;
            padding: 20px; text-align: center; }
    .stat .num { font-size: 2rem; font-weight: 700; color: var(--accent); }
    .stat .lbl { color: var(--text2); font-size: 0.85rem; }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    th { background: var(--bg3); color: var(--text2); padding: 10px 14px; text-align: left;
         border-bottom: 1px solid var(--border); }
    td { padding: 10px 14px; border-bottom: 1px solid var(--border)22; vertical-align: top; }
    tr:hover td { background: var(--bg3); }
    .status-200 { color: var(--green); font-weight: 700; }
    .status-403 { color: var(--orange); font-weight: 700; }
    code { background: var(--bg3); padding: 2px 6px; border-radius: 4px; font-size: 0.82rem; color: var(--purple); }
    .footer { border-top: 1px solid var(--border); padding: 20px 60px; text-align: center; color: var(--text2); font-size: 0.8rem; }
    .sev-bar { height: 6px; border-radius: 3px; background: {{ sev_color }}; margin: 8px 0; }
    .tag { display: inline-block; background: var(--bg3); border: 1px solid var(--border);
           border-radius: 4px; padding: 2px 8px; font-size: 0.8rem; margin: 2px; }
    .cve-box { background: {{ sev_color }}11; border: 1px solid {{ sev_color }}44;
               border-radius: 8px; padding: 16px; }
    .cve-box .cvss { font-size: 2.5rem; font-weight: 900; color: {{ sev_color }}; }
  </style>
</head>
<body>

<div class="header">
  <h1>🔍 {{ title }}</h1>
  <div class="meta">
    <span>📅 {{ date }}</span> &nbsp;|&nbsp;
    <span>🎯 Target: <code>{{ target }}</code></span> &nbsp;|&nbsp;
    <span>📋 Researcher: {{ researcher }}</span> &nbsp;|&nbsp;
    <span class="badge">{{ severity }}</span>
  </div>
</div>

<div class="container">

  <!-- Summary Stats -->
  <div class="section">
    <h2>📊 Summary</h2>
    <div class="stat-grid">
      <div class="stat">
        <div class="num">{{ total_tested }}</div>
        <div class="lbl">IDs Tested</div>
      </div>
      <div class="stat">
        <div class="num" style="color: var(--green)">{{ total_found }}</div>
        <div class="lbl">Confirmed Hits</div>
      </div>
      <div class="stat">
        <div class="num" style="color: var(--orange)">{{ hit_rate }}</div>
        <div class="lbl">Hit Rate</div>
      </div>
      <div class="stat">
        <div class="num" style="color: var(--purple)">{{ scan_type }}</div>
        <div class="lbl">Scan Type</div>
      </div>
    </div>
  </div>

  <!-- Severity -->
  <div class="section">
    <h2>⚠️ Severity Assessment</h2>
    <div class="cve-box">
      <div class="cvss">CVSS {{ cvss }}</div>
      <div class="sev-bar"></div>
      <strong style="color: {{ sev_color }}">{{ severity }}</strong> — {{ rationale }}
    </div>
  </div>

  <!-- Description -->
  <div class="section">
    <h2>📝 Vulnerability Description</h2>
    <div class="card">
      <p>An <strong>Insecure Direct Object Reference (IDOR)</strong> vulnerability was identified at
      <code>{{ target }}</code>. The application fails to enforce proper authorization checks before
      returning object data, allowing an authenticated attacker to access resources belonging to
      other users by manipulating object identifiers.</p>
      <br>
      <p><strong>CWE:</strong> <span class="tag">CWE-639</span> <span class="tag">CWE-284</span> &nbsp;
         <strong>OWASP:</strong> <span class="tag">API1:2023</span> <span class="tag">A01:2021</span></p>
    </div>
  </div>

  <!-- Evidence Table -->
  <div class="section">
    <h2>📋 Evidence — Confirmed Findings</h2>
    {% if findings %}
    <div style="overflow-x:auto">
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th>ID / Object</th>
          <th>URL</th>
          <th>Status</th>
          <th>Response Size</th>
          <th>Snippet</th>
        </tr>
      </thead>
      <tbody>
        {% for f in findings[:50] %}
        <tr>
          <td>{{ loop.index }}</td>
          <td><code>{{ f.get('id', f.get('uuid', f.get('type', '-'))) }}</code></td>
          <td><code style="font-size:0.75rem">{{ f.get('url', '-')[:80] }}</code></td>
          <td class="status-{{ f.get('status', 200) }}">{{ f.get('status', '200') }}</td>
          <td>{{ f.get('length', '-') }}</td>
          <td style="font-size:0.75rem;max-width:300px">{{ f.get('snippet', f.get('note', ''))[:120] }}</td>
        </tr>
        {% endfor %}
        {% if findings|length > 50 %}
        <tr><td colspan="6" style="text-align:center;color:var(--text2)">
          ... and {{ findings|length - 50 }} more findings (see JSON output)
        </td></tr>
        {% endif %}
      </tbody>
    </table>
    </div>
    {% else %}
    <p style="color:var(--text2)">No confirmed findings in this scan.</p>
    {% endif %}
  </div>

  <!-- Reproduction Steps -->
  <div class="section">
    <h2>🔄 Steps to Reproduce</h2>
    <div class="card">
      <ol style="padding-left:20px;line-height:2.2">
        <li>Authenticate as <strong>User A</strong> (attacker account) and note the session token.</li>
        <li>Identify an API endpoint that accepts a user-controlled object identifier (e.g., <code>id</code>, <code>user_id</code>, <code>invoice_id</code>).</li>
        <li>Replace the authenticated user's object ID with the ID of another user's resource (e.g., ID belonging to <strong>User B</strong>).</li>
        <li>Observe that the server returns User B's data without any authorization error.</li>
        <li>Confirm by iterating over multiple IDs — data is returned for all tested IDs.</li>
      </ol>
      <pre>
# Curl PoC
curl -s -H "Authorization: Bearer ATTACKER_TOKEN" \\
     "{{ target }}"
# Response: Returns data belonging to other users
      </pre>
    </div>
  </div>

  <!-- Impact -->
  <div class="section">
    <h2>💥 Impact</h2>
    <div class="card">
      <ul style="padding-left:20px;line-height:2">
        <li>Unauthorized access to other users' private data</li>
        <li>Potential exposure of PII (names, emails, addresses, financial data)</li>
        <li>Mass data exfiltration via automated ID enumeration</li>
        <li>Violation of data privacy laws (GDPR, PDPA, HIPAA)</li>
        <li>Reputational and legal risk to the organization</li>
      </ul>
    </div>
  </div>

  <!-- Remediation -->
  <div class="section">
    <h2>🛠️ Remediation</h2>
    <div class="card">
      <ul style="padding-left:20px;line-height:2">
        <li><strong>Implement server-side authorization:</strong> Verify the requesting user owns the requested resource on every API call.</li>
        <li><strong>Use indirect references:</strong> Replace sequential numeric IDs with UUIDs or opaque tokens mapped server-side.</li>
        <li><strong>Enforce RBAC/ABAC:</strong> Apply role-based or attribute-based access control at the data layer.</li>
        <li><strong>Rate limiting:</strong> Detect and block high-frequency ID enumeration attempts.</li>
        <li><strong>Audit logging:</strong> Log all resource access attempts for anomaly detection.</li>
      </ul>
    </div>
  </div>

</div>

<div class="footer">
  Generated by IDOR Bug Bounty Workspace · {{ date }} · For authorized disclosure only
</div>
</body>
</html>
"""

MD_TEMPLATE = """# {{ title }} — IDOR Bug Bounty Report

**Date:** {{ date }}  
**Target:** `{{ target }}`  
**Researcher:** {{ researcher }}  
**Severity:** {{ severity }} (CVSS {{ cvss }})  
**CWE:** CWE-639, CWE-284  
**OWASP:** API1:2023, A01:2021

---

## Summary

| Metric | Value |
|--------|-------|
| IDs Tested | {{ total_tested }} |
| Confirmed Hits | {{ total_found }} |
| Hit Rate | {{ hit_rate }} |
| Scan Type | {{ scan_type }} |

**Severity Rationale:** {{ rationale }}

---

## Vulnerability Description

An **Insecure Direct Object Reference (IDOR)** vulnerability was identified at `{{ target }}`.
The application fails to enforce proper authorization checks before returning object data,
allowing an authenticated attacker to access resources belonging to other users.

---

## Steps to Reproduce

1. Authenticate as **User A** (attacker account) and obtain session token.
2. Identify the target API endpoint accepting a user-controlled object ID.
3. Replace your object ID with another user's ID (e.g., increment `id=1` → `id=2`).
4. Observe server returns other user's data without authorization error.
5. Iterate over ID range — confirm mass enumeration is possible.

```bash
# PoC Request
curl -s -H "Authorization: Bearer ATTACKER_TOKEN" "{{ target }}"
```

---

## Evidence (First 20 findings)

| # | ID | Status | Size | Snippet |
|---|----|--------|------|---------|
{% for f in findings[:20] %}| {{ loop.index }} | `{{ f.get('id', f.get('uuid', '-')) }}` | {{ f.get('status', 200) }} | {{ f.get('length', '-') }} | {{ f.get('snippet', '')[:80] }} |
{% endfor %}

---

## Impact

- Unauthorized access to other users' private data
- Potential PII exposure (names, emails, financial data)  
- Mass data exfiltration via ID enumeration
- Regulatory violation risk (GDPR, PDPA)

---

## Remediation

1. **Server-side authorization** — verify resource ownership on every API call
2. **Indirect references** — use UUIDs/opaque tokens instead of sequential IDs  
3. **RBAC/ABAC** — enforce access control at the data layer
4. **Rate limiting** — block high-frequency enumeration
5. **Audit logging** — monitor all resource access attempts

---

*Generated by IDOR Bug Bounty Workspace · {{ date }}*
"""


def main():
    parser = argparse.ArgumentParser(description="IDOR Auto Report Generator")
    parser.add_argument("--input",      required=True, help="JSON results file from any scan tool")
    parser.add_argument("--target",     default="https://target.com", help="Target URL")
    parser.add_argument("--title",      default="IDOR Vulnerability", help="Report title")
    parser.add_argument("--researcher", default="Security Researcher", help="Your name/handle")
    parser.add_argument("--format",     default="both", choices=["html", "md", "both"])
    parser.add_argument("--output",     default=None, help="Output filename (without extension)")

    args = parser.parse_args()

    # Load results
    with open(args.input) as f:
        findings = json.load(f)

    if not isinstance(findings, list):
        findings = [findings]

    severity, sev_color, cvss, rationale = auto_severity(findings)
    date = datetime.now().strftime("%Y-%m-%d %H:%M")
    total_tested = max(
        findings[-1].get("id", len(findings)) if findings else 0,
        len(findings)
    )
    total_found = len([f for f in findings if f.get("status", 200) in (200, 201)])
    hit_rate = f"{(total_found / max(total_tested,1)) * 100:.1f}%" if total_tested else "N/A"

    # Detect scan type
    if any("query" in f for f in findings):
        scan_type = "GraphQL"
    elif any("uuid" in str(f.get("id","")).lower() or "-" in str(f.get("id","")) for f in findings):
        scan_type = "UUID"
    else:
        scan_type = "REST"

    ctx = {
        "title": args.title,
        "target": args.target,
        "researcher": args.researcher,
        "date": date,
        "findings": findings,
        "severity": severity,
        "sev_color": sev_color,
        "cvss": cvss,
        "rationale": rationale,
        "total_tested": total_tested,
        "total_found": total_found,
        "hit_rate": hit_rate,
        "scan_type": scan_type,
    }

    base = args.output or Path(args.input).stem + "_report"
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    if args.format in ("html", "both"):
        html_out = reports_dir / f"{base}.html"
        Template(HTML_TEMPLATE).stream(**ctx).dump(str(html_out))
        console.print(f"[green][+] HTML report → {html_out}[/green]")

    if args.format in ("md", "both"):
        md_out = reports_dir / f"{base}.md"
        Template(MD_TEMPLATE).stream(**ctx).dump(str(md_out))
        console.print(f"[green][+] Markdown report → {md_out}[/green]")

    console.print(f"\n[bold cyan]Severity: {severity} | CVSS: {cvss} | Findings: {total_found}[/bold cyan]")


if __name__ == "__main__":
    main()
