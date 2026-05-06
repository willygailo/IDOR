# HOW TO USE — IDOR Bug Bounty Workspace (Advanced Edition)

> Complete step-by-step guide: setup, configuration, running all 11 tools, reporting, and submitting.
> ⚠️ For authorized bug bounty testing only. Always stay within program scope.

---

## STEP 1 — First Time Setup (One Time Only)

Open a terminal and go to the workspace folder:

```bash
cd /home/willygailo/Documents/IDOR
```

Make scripts executable and install dependencies:

```bash
chmod +x setup.sh
./setup.sh
```

Or manually install with pip:

```bash
pip install -r requirements.txt
```

Verify everything is working:

```bash
python3 test_setup.py
```

---

## STEP 2 — Configure Your Target & Session

Open the config file:

```bash
nano poc/scripts/config.py
```

Edit these fields:

```python
CONFIG = {
    "base_url":       "https://your-target.com",   # ← your target URL
    "attacker_token": "YOUR_BEARER_TOKEN",          # ← your session token
    "attacker_cookie": "session=YOUR_COOKIE",       # ← OR your cookie
    "victim_token":   "VICTIM_BEARER_TOKEN",        # ← victim account token
}
```

### How to get your session token (Burp Suite):
1. Open Burp Suite → Proxy → Intercept ON
2. Log in to the target website
3. Intercept the request → copy the `Authorization: Bearer ...` value
4. Paste it into `attacker_token` in config.py

### How to get your session cookie:
1. Open browser DevTools → Application → Cookies
2. Copy the value of the `session` or `auth` cookie
3. Paste it into `attacker_cookie` in config.py as `session=VALUE`

---

## STEP 3 — [SAFETY FIRST] Validate Scope Before Testing

**Always run this before scanning any target.**

Generate a scope file template:

```bash
python3 poc/scripts/scope_validator.py generate --output scope.txt
nano scope.txt  # fill in the program's allowed domains
```

Check your target URL is in scope:

```bash
python3 poc/scripts/scope_validator.py check \
  --url https://target.com/api/user \
  --scope-file scope.txt
```

Validate a list of URLs at once:

```bash
python3 poc/scripts/scope_validator.py check \
  --url-file urls.txt \
  --domains "*.target.com,api.target.com"
```

Interactive real-time checker:

```bash
python3 poc/scripts/scope_validator.py interactive --scope-file scope.txt
```

> ✅ Green = safe to test | ⚠️ Yellow = out of scope | 🚫 Red = globally blocked

---

## STEP 4 — Run the Interactive Menu (Easiest Way)

```bash
python3 run.py
```

You will see the full menu with 11 tools across 4 categories:

```
── Core IDOR Tools ──────────────────────────
  [ 1] GET Parameter Enumerator
  [ 2] POST Body Tester
  [ 3] Threaded Mass Enumerator
  [ 4] Blind IDOR Response Differ
  [ 5] JWT / Cookie IDOR Tester
  [ 6] JavaScript Endpoint Extractor

── Advanced Tools ───────────────────────────
  [ 7] GraphQL IDOR Tester  [ADVANCED]
  [ 8] UUID / GUID Brute-Forcer  [ADVANCED]

── Reporting & Database ─────────────────────
  [ 9] Auto Report Generator  [REPORTING]
  [10] Findings Database  [REPORTING]

── Safety Tools ─────────────────────────────
  [11] Scope Validator  [SAFETY]

  [h] Show usage examples
  [q] Quit
```

- Type **1–11** to launch a tool
- Type **h** then a number to see the usage example for that tool
- Type **q** to quit

---

## STEP 5 — Core IDOR Tools (Direct Usage)

### Tool 6 — Find Hidden API Endpoints from JavaScript

```bash
python3 poc/scripts/js_endpoint_extractor.py \
  --target https://target.com \
  --token YOUR_TOKEN
```

> Run this **first** to discover all API endpoints on the target.

---

### Tool 1 — GET Parameter Enumerator

```bash
python3 poc/scripts/idor_enum.py \
  --url https://target.com/api/invoice \
  --param invoice_id \
  --start 1 \
  --end 500 \
  --token YOUR_TOKEN \
  --output idor_results.json
```

> Tests if you can access other users' data by changing the `invoice_id` value.

---

### Tool 3 — Threaded Mass Enumerator (Faster)

```bash
python3 poc/scripts/threaded_idor_enum.py \
  --url https://target.com/api/invoice \
  --param invoice_id \
  --start 1 \
  --end 5000 \
  --threads 15 \
  --token YOUR_TOKEN \
  --output threaded_results.json
```

> Same as Tool 1 but uses 15 parallel threads — much faster for large ranges.

---

### Tool 2 — POST Body Tester

```bash
python3 poc/scripts/post_idor_tester.py \
  --url https://target.com/api/user/update \
  --method POST \
  --body '{"user_id": 1, "action": "view"}' \
  --param user_id \
  --start 1 \
  --end 200 \
  --token YOUR_TOKEN \
  --output post_idor_results.json
```

> Tests IDOR inside the JSON body of POST/PUT/PATCH/DELETE requests.

---

### Tool 4 — Blind IDOR Response Differ

```bash
python3 poc/scripts/blind_idor_differ.py \
  --url "https://target.com/api/invoice?id=12345" \
  --victim-token  VICTIM_TOKEN \
  --attacker-token YOUR_TOKEN \
  --diff \
  --output blind_idor_report.json
```

> Compares the victim's response vs your response.
> If they are **identical** → IDOR confirmed even if status code is the same.

---

### Tool 5 — JWT / Cookie IDOR Tester

**JWT mode** (swap user_id inside JWT token):

```bash
python3 poc/scripts/jwt_idor_tester.py \
  --url https://target.com/api/profile \
  --mode jwt \
  --token YOUR_JWT_TOKEN \
  --field user_id \
  --victim-id 456 \
  --output jwt_idor_report.json
```

**Cookie mode** (swap user_id inside base64 cookie):

```bash
python3 poc/scripts/jwt_idor_tester.py \
  --url https://target.com/api/profile \
  --mode cookie \
  --token BASE64_COOKIE_VALUE \
  --field user_id \
  --victim-id 456 \
  --cookie-name session \
  --output jwt_idor_report.json
```

---

## STEP 6 — Advanced Tools

### Tool 7 — GraphQL IDOR Tester

Modern apps use GraphQL instead of REST. This tool attacks the GraphQL layer.

**Introspect the schema first** (discover all types and fields):

```bash
python3 poc/scripts/graphql_idor_tester.py \
  --url https://target.com/graphql \
  --token YOUR_TOKEN \
  --mode introspect
```

**Enumerate numeric IDs** across all common query types:

```bash
python3 poc/scripts/graphql_idor_tester.py \
  --url https://target.com/graphql \
  --token YOUR_TOKEN \
  --mode enum \
  --start 1 \
  --end 100 \
  --output graphql_results.json
```

**Diff mode** — compare victim vs attacker responses:

```bash
python3 poc/scripts/graphql_idor_tester.py \
  --url https://target.com/graphql \
  --victim-token VICTIM_TOKEN \
  --attacker-token YOUR_TOKEN \
  --mode diff \
  --ids "100,101,102,103" \
  --output graphql_diff_results.json
```

**UUID fuzz mode** — fuzz with random UUIDs:

```bash
python3 poc/scripts/graphql_idor_tester.py \
  --url https://target.com/graphql \
  --token YOUR_TOKEN \
  --mode uuid \
  --end 50 \
  --output graphql_uuid_results.json
```

> Types tested: `user`, `order`, `invoice`, `document`, `profile`, `account`, `ticket`, `transaction`

---

### Tool 8 — UUID / GUID Brute-Forcer

Many apps use UUID instead of numeric IDs. This tool attacks them.

**Wordlist mode** (most predictable / common UUIDs):

```bash
python3 poc/scripts/uuid_idor_brute.py \
  --url "https://target.com/api/document/UUID_VAL" \
  --token YOUR_TOKEN \
  --mode wordlist \
  --output uuid_results.json
```

**Predict mode** (time-based UUID v1/v7 prefix attack):

```bash
python3 poc/scripts/uuid_idor_brute.py \
  --url "https://target.com/api/document/UUID_VAL" \
  --token YOUR_TOKEN \
  --mode predict \
  --prefix "018f0a" \
  --count 500 \
  --output uuid_predict_results.json
```

**Known list mode** (test UUIDs harvested from responses/JS files):

```bash
python3 poc/scripts/uuid_idor_brute.py \
  --url "https://target.com/api/document/UUID_VAL" \
  --token YOUR_TOKEN \
  --mode known \
  --uuid-file harvested_uuids.txt \
  --output uuid_known_results.json
```

**POST body mode** (UUID inside request body):

```bash
python3 poc/scripts/uuid_idor_brute.py \
  --url "https://target.com/api/document" \
  --token YOUR_TOKEN \
  --method POST \
  --body '{"doc_id": "UUID_VAL"}' \
  --mode wordlist
```

> 💡 Use `UUID_VAL` as the placeholder in `--url` or `--body` — it gets replaced automatically.

| Mode | Best For |
|------|----------|
| `wordlist` | First pass — common/predictable IDs |
| `predict` | Time-based UUID v1/v7 (when you know part of the prefix) |
| `known` | IDs harvested from JS files or API responses |
| `random` | Shotgun fuzzing (low hit rate, for discovery) |
| `hex` | Short hex IDs (non-UUID format) |

---

## STEP 7 — Generate a Professional Report

After any scan, convert the JSON output into a polished HTML + Markdown report:

```bash
python3 poc/scripts/report_generator.py \
  --input idor_results.json \
  --target https://target.com \
  --title "Billing API IDOR — Invoice Enumeration" \
  --researcher "YourHandle" \
  --format both
```

Reports are saved to the `reports/` folder:
- `reports/idor_results_report.html` — Dark-theme HTML with CVSS score, evidence table, remediation
- `reports/idor_results_report.md` — Markdown version ready for HackerOne / Bugcrowd

Open the HTML report in your browser:

```bash
xdg-open reports/idor_results_report.html
```

> The report auto-detects severity (Critical / High / Medium / Low) and CVSS score based on findings.

---

## STEP 8 — Save Findings to the Database

Track all findings across multiple targets in the SQLite database:

**Import scan results:**

```bash
python3 poc/scripts/findings_db.py import \
  --file idor_results.json \
  --target https://target.com \
  --program "HackerOne — TargetProgram"
```

**List all confirmed findings:**

```bash
python3 poc/scripts/findings_db.py list
python3 poc/scripts/findings_db.py list --target target.com --limit 20
```

**View statistics across all targets:**

```bash
python3 poc/scripts/findings_db.py stats
```

**Mark a specific finding as confirmed + set severity:**

```bash
python3 poc/scripts/findings_db.py confirm --id 42 --severity High
```

**Export findings for a target:**

```bash
python3 poc/scripts/findings_db.py export \
  --target https://target.com \
  --output confirmed_findings.json
```

---

## STEP 9 — Understand the Results

| Output | Meaning |
|--------|---------|
| `[FOUND] ID=12345 \| Status=200` | ✅ IDOR found — you accessed victim's data |
| `[403]` | ❌ Access denied — properly blocked |
| `[404]` | Resource doesn't exist |
| `[IDOR LEAK]` | ✅ Blind IDOR — attacker got victim's data |
| `[SAME DATA]` | ⚠️ Possible IDOR — investigate manually |
| `[UUID HIT]` | ✅ UUID-based IDOR confirmed |
| `[DATA]` | ✅ GraphQL query returned data |

Check the output `.json` file for full details:

```bash
cat idor_results.json | python3 -m json.tool | head -50
```

---

## STEP 10 — Document & Submit the Finding

1. Copy the report template:

```bash
cp templates/idor-report-template.md reports/drafts/IDOR-target-endpoint-$(date +%Y-%m-%d).md
```

2. Open and fill it in:

```bash
nano reports/drafts/IDOR-target-endpoint-$(date +%Y-%m-%d).md
```

3. Save the raw HTTP request from Burp Suite to:

```
poc/requests/
```

4. Save screenshots to:

```
poc/screenshots/
```

5. Pre-submission checklist:

```bash
nano templates/pre-submission-checklist.md
```

6. Submit → move to submitted folder:

```bash
mv reports/drafts/IDOR-target-*.md reports/submitted/
```

7. Update the tracker:

```bash
nano IDOR-tracker.md
```

---

## Recommended Workflow (Start to Finish)

```bash
# 1. Validate scope
python3 poc/scripts/scope_validator.py check --url https://target.com/api --scope-file scope.txt

# 2. Discover endpoints
python3 poc/scripts/js_endpoint_extractor.py --target https://target.com --token TOKEN

# 3. Scan (pick one or more based on target type)

  # REST numeric IDs
  python3 poc/scripts/idor_enum.py --url https://target.com/api/invoice --param id --start 1 --end 500 --token TOKEN

  # REST fast (large range)
  python3 poc/scripts/threaded_idor_enum.py --url https://target.com/api/invoice --param id --start 1 --end 5000 --threads 20 --token TOKEN

  # GraphQL endpoint
  python3 poc/scripts/graphql_idor_tester.py --url https://target.com/graphql --token TOKEN --mode enum

  # UUID-based resources
  python3 poc/scripts/uuid_idor_brute.py --url "https://target.com/api/doc/UUID_VAL" --token TOKEN --mode wordlist

  # JWT/session-based IDOR
  python3 poc/scripts/jwt_idor_tester.py --url https://target.com/api/profile --mode jwt --token JWT --field user_id --victim-id 456

# 4. Save to database
python3 poc/scripts/findings_db.py import --file idor_results.json --target https://target.com --program "HackerOne"

# 5. Generate report
python3 poc/scripts/report_generator.py --input idor_results.json --target https://target.com --title "IDOR Finding"

# 6. Open report
xdg-open reports/idor_results_report.html
```

---

## Quick Command Reference

```bash
# Setup
./setup.sh && python3 test_setup.py

# Interactive menu (all 11 tools)
python3 run.py

# ── Core Tools ────────────────────────────────────────────────────────
python3 poc/scripts/js_endpoint_extractor.py  --target URL --token TOKEN
python3 poc/scripts/idor_enum.py              --url URL --param PARAM --start 1 --end 500 --token TOKEN
python3 poc/scripts/threaded_idor_enum.py     --url URL --param PARAM --threads 15 --token TOKEN
python3 poc/scripts/post_idor_tester.py       --url URL --method POST --body '{"id":1}' --param id --token TOKEN
python3 poc/scripts/blind_idor_differ.py      --url URL --victim-token VT --attacker-token AT --diff
python3 poc/scripts/jwt_idor_tester.py        --url URL --mode jwt --token JWT --field user_id --victim-id 456

# ── Advanced Tools ─────────────────────────────────────────────────────
python3 poc/scripts/graphql_idor_tester.py    --url URL/graphql --token TOKEN --mode enum
python3 poc/scripts/uuid_idor_brute.py        --url "URL/UUID_VAL" --token TOKEN --mode wordlist

# ── Reporting ──────────────────────────────────────────────────────────
python3 poc/scripts/report_generator.py       --input results.json --target URL --title "Title"
python3 poc/scripts/findings_db.py import     --file results.json --target URL --program "Program"
python3 poc/scripts/findings_db.py stats
python3 poc/scripts/findings_db.py list

# ── Safety ─────────────────────────────────────────────────────────────
python3 poc/scripts/scope_validator.py check  --url URL --scope-file scope.txt
python3 poc/scripts/scope_validator.py interactive --scope-file scope.txt
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `ModuleNotFoundError: requests` | Run `pip install -r requirements.txt` |
| `ModuleNotFoundError: rich` | Run `pip install rich` |
| `ModuleNotFoundError: jinja2` | Run `pip install jinja2` |
| `Permission denied` on scripts | Run `chmod +x poc/scripts/*.py run.py setup.sh` |
| All responses return 403 | Session token expired — get a fresh one from Burp Suite |
| All responses return 404 | Wrong endpoint — use `js_endpoint_extractor.py` first |
| Script not found | Run `python3 test_setup.py` to check missing files |
| JWT error: not 3 parts | Your token is a cookie — use `--mode cookie` instead |
| GraphQL returns empty data | Try `--mode introspect` first to see what types exist |
| UUID brute returns 0 hits | Switch from `wordlist` to `predict` mode with a prefix |
| Report HTML is empty | Check your JSON file has data: `cat results.json` |
| DB import fails | Check the JSON file is a valid list — `python3 -m json.tool results.json` |
