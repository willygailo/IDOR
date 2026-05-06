#!/usr/bin/env python3
"""
IDOR Workspace — Setup Verifier
=================================
Checks that all dependencies and scripts are correctly installed.

Usage:
    python3 test_setup.py
"""

import importlib
import sys
import os

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), "poc", "scripts")

def check(label, condition, fix=""):
    if condition:
        print(f"  {GREEN}[✓]{RESET} {label}")
    else:
        print(f"  {RED}[✗]{RESET} {label}")
        if fix:
            print(f"      {YELLOW}Fix: {fix}{RESET}")
    return condition

def main():
    print(f"\n{CYAN}{BOLD}")
    print("╔══════════════════════════════════════════╗")
    print("║    IDOR Workspace — Setup Verifier       ║")
    print("╚══════════════════════════════════════════╝")
    print(f"{RESET}")

    passed = 0
    failed = 0

    # ── Python version ──────────────────────────────────────────────────────
    print(f"\n{BOLD}[1] Python Version{RESET}")
    ok = sys.version_info >= (3, 8)
    check(f"Python {sys.version.split()[0]} (need ≥ 3.8)", ok, "Upgrade Python: sudo apt install python3")
    passed += ok; failed += not ok

    # ── Dependencies ────────────────────────────────────────────────────────
    print(f"\n{BOLD}[2] Python Dependencies{RESET}")
    deps = ["requests"]
    for dep in deps:
        try:
            importlib.import_module(dep)
            ok = True
        except ImportError:
            ok = False
        check(f"import {dep}", ok, f"pip install {dep}")
        passed += ok; failed += not ok

    # ── Scripts present ─────────────────────────────────────────────────────
    print(f"\n{BOLD}[3] Scripts Present{RESET}")
    scripts = [
        "idor_enum.py",
        "post_idor_tester.py",
        "threaded_idor_enum.py",
        "blind_idor_differ.py",
        "jwt_idor_tester.py",
        "js_endpoint_extractor.py",
        "config.py",
    ]
    for s in scripts:
        path = os.path.join(SCRIPTS_DIR, s)
        ok = os.path.isfile(path)
        check(f"poc/scripts/{s}", ok, "Re-run workspace setup")
        passed += ok; failed += not ok

    # ── Config check ────────────────────────────────────────────────────────
    print(f"\n{BOLD}[4] Config Validation{RESET}")
    try:
        sys.path.insert(0, SCRIPTS_DIR)
        from config import CONFIG
        has_url = bool(CONFIG.get("base_url", "").strip())
        check("base_url is set in config.py", has_url, "Edit poc/scripts/config.py → set base_url")
        passed += has_url; failed += not has_url

        has_attacker = bool(CONFIG.get("attacker_token") or CONFIG.get("attacker_cookie"))
        check("Attacker session configured", has_attacker, "Edit poc/scripts/config.py → set attacker_token or attacker_cookie")
        # Don't count this as failure — tokens filled per-run
        if not has_attacker:
            print(f"      {YELLOW}⚠  Fill in your session token before running tools{RESET}")
    except Exception as e:
        print(f"  {RED}[✗]{RESET} Could not load config.py: {e}")
        failed += 1

    # ── run.py present ──────────────────────────────────────────────────────
    print(f"\n{BOLD}[5] Runner Scripts{RESET}")
    for f in ["run.py", "setup.sh", "requirements.txt"]:
        path = os.path.join(os.path.dirname(__file__), f)
        ok = os.path.isfile(path)
        check(f"{f}", ok)
        passed += ok; failed += not ok

    # ── Summary ─────────────────────────────────────────────────────────────
    total = passed + failed
    print(f"\n{BOLD}{'─'*45}")
    print(f"  Results: {GREEN}{passed} passed{RESET} / {RED}{failed} failed{RESET} / {total} total")
    print(f"{'─'*45}{RESET}\n")

    if failed == 0:
        print(f"{GREEN}{BOLD}  ✅ All checks passed! Run: python3 run.py{RESET}\n")
    else:
        print(f"{YELLOW}{BOLD}  ⚠  Fix the issues above, then re-run: python3 test_setup.py{RESET}\n")

if __name__ == "__main__":
    main()
