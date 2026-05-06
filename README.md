# IDOR Bug Bounty Workspace — Advanced Edition

> A professional-grade research and automation workspace for **Insecure Direct Object Reference (IDOR)** vulnerability hunting.
> Built for authorized bug bounty testing only. ⚠️ Always stay within program scope.

---

## 🚀 Quick Start

```bash
cd /home/willygailo/Documents/IDOR

# Install dependencies
pip install -r requirements.txt

# Launch interactive menu (11 tools)
python3 run.py
```

---

## 🛠️ Tools — 11 Scripts Across 4 Categories

### Core IDOR Tools
| Script | Purpose |
|--------|---------|
| `idor_enum.py` | GET parameter enumeration over numeric ID ranges |
| `post_idor_tester.py` | IDOR via POST/PUT/PATCH/DELETE request bodies |
| `threaded_idor_enum.py` | Fast concurrent enumeration with threading |
| `blind_idor_differ.py` | Victim vs attacker response diff (blind IDOR) |
| `jwt_idor_tester.py` | IDOR via JWT payload or base64 cookie manipulation |
| `js_endpoint_extractor.py` | Extract hidden API endpoints from JavaScript files |

### Advanced Tools
| Script | Purpose |
|--------|---------|
| `graphql_idor_tester.py` | GraphQL schema introspection + query fuzzing + session diff |
| `uuid_idor_brute.py` | UUID/GUID brute-force (wordlist, predict, known, hex, random) |

### Reporting & Database
| Script | Purpose |
|--------|---------|
| `report_generator.py` | Scan JSON → dark-theme HTML report + Markdown with CVSS scoring |
| `findings_db.py` | SQLite database — multi-target tracking, stats, search, export |

### Safety
| Script | Purpose |
|--------|---------|
| `scope_validator.py` | Validate URLs against bug bounty scope before scanning |

---

## 📁 Folder Structure

```
IDOR/
├── run.py                          # Interactive menu launcher (11 tools)
├── requirements.txt                # Python dependencies
├── HOW_TO_USE.md                   # Full step-by-step usage guide
├── IDOR-methodology-checklist.md   # Testing methodology reference
├── IDOR-tracker.md                 # Findings tracker across programs
├── findings.db                     # SQLite findings database (auto-created)
│
├── poc/                            # Proof of Concept materials
│   ├── scripts/                    # All automation scripts (11 tools)
│   │   ├── config.py               # Shared config (target, tokens, settings)
│   │   ├── idor_enum.py            # GET enumerator
│   │   ├── post_idor_tester.py     # POST/PUT/PATCH/DELETE tester
│   │   ├── threaded_idor_enum.py   # Threaded fast enumerator
│   │   ├── blind_idor_differ.py    # Blind IDOR differ
│   │   ├── jwt_idor_tester.py      # JWT / cookie tester
│   │   ├── js_endpoint_extractor.py# JS endpoint extractor
│   │   ├── graphql_idor_tester.py  # GraphQL IDOR tester [ADVANCED]
│   │   ├── uuid_idor_brute.py      # UUID/GUID brute-forcer [ADVANCED]
│   │   ├── report_generator.py     # Auto report generator
│   │   ├── findings_db.py          # Findings database
│   │   └── scope_validator.py      # Scope validator [SAFETY]
│   ├── requests/                   # Raw HTTP request captures (Burp)
│   └── screenshots/                # Visual evidence
│
├── reports/                        # Bug bounty reports by status
│   ├── drafts/                     # Work-in-progress reports
│   ├── submitted/                  # Sent to programs
│   ├── accepted/                   # Confirmed / rewarded
│   └── rejected/                   # Declined / informative
│
├── targets/                        # Per-target research
│   ├── recon/                      # Reconnaissance notes
│   ├── scope/                      # Program scope files
│   └── notes/                      # General research notes
│
├── templates/                      # Reusable document templates
│   ├── idor-report-template.md     # Full vulnerability report template
│   ├── disclosure-email-template.md# Private disclosure email template
│   └── pre-submission-checklist.md # Pre-submission quality checklist
│
└── resources/
    └── references/                 # CVEs, writeups, external references
```

---

## ⚡ Recommended Workflow

```bash
# 1. Validate scope first (never skip this)
python3 poc/scripts/scope_validator.py check --url https://target.com/api --scope-file scope.txt

# 2. Discover endpoints
python3 poc/scripts/js_endpoint_extractor.py --target https://target.com --token TOKEN

# 3. Scan (choose based on target type)
python3 poc/scripts/idor_enum.py --url URL --param id --start 1 --end 500 --token TOKEN         # REST numeric
python3 poc/scripts/graphql_idor_tester.py --url URL/graphql --token TOKEN --mode enum           # GraphQL
python3 poc/scripts/uuid_idor_brute.py --url "URL/UUID_VAL" --token TOKEN --mode wordlist        # UUID

# 4. Store findings in database
python3 poc/scripts/findings_db.py import --file results.json --target URL --program "HackerOne"

# 5. Generate professional report
python3 poc/scripts/report_generator.py --input results.json --target URL --title "IDOR Finding"

# 6. Open HTML report
xdg-open reports/results_report.html
```

---

## 📦 Dependencies

```
requests>=2.28.0
jinja2>=3.1.0
rich>=13.0.0
colorama>=0.4.6
```

Install:
```bash
pip install -r requirements.txt
```

---

## 📖 Documentation

| File | Description |
|------|-------------|
| [`HOW_TO_USE.md`](HOW_TO_USE.md) | Complete step-by-step guide for all 11 tools |
| [`IDOR-methodology-checklist.md`](IDOR-methodology-checklist.md) | Full IDOR testing methodology |
| [`IDOR-tracker.md`](IDOR-tracker.md) | Track findings across programs |
| [`templates/pre-submission-checklist.md`](templates/pre-submission-checklist.md) | Pre-submission quality checklist |

---

> **Legal Disclaimer:** This workspace is for authorized security research and bug bounty programs only.
> Unauthorized testing is illegal. Always obtain written permission before testing any system.
