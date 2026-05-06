"""
IDOR Workspace — Shared Config
================================
Edit this file to set your default session tokens, target URL,
and output preferences before running any tool.

Import in any script with:
    from config import CONFIG
"""

CONFIG = {
    # ─── Target Settings ──────────────────────────────────────────────────────
    "base_url":      "https://e.gov.ph/",  # Change to your target
    "param_name":    "id",                           # Default parameter to test

    # ─── Auth — Attacker Session (your account) ───────────────────────────────
    "attacker_token":  "",   # Bearer token
    "attacker_cookie": "",   # Cookie string e.g. "session=abc123"

    # ─── Auth — Victim Session (test account) ─────────────────────────────────
    "victim_token":    "",   # Bearer token
    "victim_cookie":   "",   # Cookie string

    # ─── Enumeration Settings ─────────────────────────────────────────────────
    "id_start":   1,
    "id_end":     500,
    "threads":    10,
    "delay":      0.3,       # Seconds between requests

    # ─── Output ───────────────────────────────────────────────────────────────
    "output_dir": "poc/screenshots",
    "results_file": "idor_results.json",
}
