#!/usr/bin/env python3
"""
IDOR Bug Bounty Workspace — Main Runner
========================================
Interactive menu to launch all IDOR testing tools.

Usage:
    python3 run.py

⚠️  For authorized testing only. Always stay within program scope.
"""

import os
import sys
import subprocess

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), "poc", "scripts")

TOOLS = {
    # ─── Core IDOR Tools ──────────────────────────────────────────────────────
    "1": {
        "name": "GET Parameter Enumerator",
        "file": "idor_enum.py",
        "desc": "Enumerate IDOR via URL query parameter (GET requests)",
        "example": "--url https://target.com/api/invoice --param invoice_id --start 1 --end 500 --token YOUR_TOKEN",
        "category": "CORE"
    },
    "2": {
        "name": "POST Body Tester",
        "file": "post_idor_tester.py",
        "desc": "Test IDOR in POST/PUT/PATCH/DELETE request bodies",
        "example": "--url https://target.com/api/user/update --method POST --body '{\"user_id\":1}' --param user_id --token YOUR_TOKEN",
        "category": "CORE"
    },
    "3": {
        "name": "Threaded Mass Enumerator",
        "file": "threaded_idor_enum.py",
        "desc": "Fast concurrent IDOR enumeration over large ID ranges",
        "example": "--url https://target.com/api/invoice --param invoice_id --start 1 --end 5000 --threads 20 --token YOUR_TOKEN",
        "category": "CORE"
    },
    "4": {
        "name": "Blind IDOR Response Differ",
        "file": "blind_idor_differ.py",
        "desc": "Compare victim vs attacker responses to detect blind IDOR",
        "example": "--url https://target.com/api/invoice?id=12345 --victim-token VICTIM_TOKEN --attacker-token ATTACKER_TOKEN --diff",
        "category": "CORE"
    },
    "5": {
        "name": "JWT / Cookie IDOR Tester",
        "file": "jwt_idor_tester.py",
        "desc": "Test IDOR by modifying user ID inside JWT payload or base64 cookie",
        "example": "--url https://target.com/api/profile --mode jwt --token YOUR_JWT --field user_id --victim-id 456",
        "category": "CORE"
    },
    "6": {
        "name": "JavaScript Endpoint Extractor",
        "file": "js_endpoint_extractor.py",
        "desc": "Extract hidden API endpoints from JavaScript files",
        "example": "--target https://target.com",
        "category": "CORE"
    },
    # ─── Advanced Tools ───────────────────────────────────────────────────────
    "7": {
        "name": "GraphQL IDOR Tester  [ADVANCED]",
        "file": "graphql_idor_tester.py",
        "desc": "Test IDOR in GraphQL APIs — introspect schema, fuzz queries, diff sessions",
        "example": "--url https://target.com/graphql --token YOUR_TOKEN --mode enum --start 1 --end 100",
        "category": "ADVANCED"
    },
    "8": {
        "name": "UUID / GUID Brute-Forcer  [ADVANCED]",
        "file": "uuid_idor_brute.py",
        "desc": "Brute-force UUID, GUID, ULID-based resource IDs with multiple strategies",
        "example": "--url https://target.com/api/doc/UUID_VAL --token YOUR_TOKEN --mode wordlist",
        "category": "ADVANCED"
    },
    # ─── Workflow Tools ───────────────────────────────────────────────────────
    "9": {
        "name": "Auto Report Generator  [REPORTING]",
        "file": "report_generator.py",
        "desc": "Convert scan JSON → Professional HTML dark-theme report + Markdown with CVSS scoring",
        "example": "--input idor_results.json --target https://target.com --title 'Billing API IDOR'",
        "category": "REPORT"
    },
    "10": {
        "name": "Findings Database  [REPORTING]",
        "file": "findings_db.py",
        "desc": "SQLite database for multi-target IDOR tracking, stats, and export",
        "example": "import --file idor_results.json --target https://target.com --program HackerOne",
        "category": "REPORT"
    },
    "11": {
        "name": "Scope Validator  [SAFETY]",
        "file": "scope_validator.py",
        "desc": "Validate URLs against bug bounty scope BEFORE scanning — prevent out-of-scope testing",
        "example": "check --url https://target.com/api --scope-file scope.txt",
        "category": "SAFETY"
    },
}

def banner():
    os.system("clear")
    print(f"{CYAN}{BOLD}")
    print("╔══════════════════════════════════════════════════════════╗")
    print("║     IDOR Bug Bounty Workspace — Advanced Edition        ║")
    print("║     For authorized bug bounty testing only              ║")
    print("║     11 Tools  |  GraphQL  |  UUID  |  Reports  |  DB   ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"{RESET}")

CATEGORY_COLORS = {
    "CORE":     CYAN,
    "ADVANCED":  "\033[95m",  # Magenta
    "REPORT":   GREEN,
    "SAFETY":   YELLOW,
}
CATEGORY_LABELS = {
    "CORE":     "── Core IDOR Tools ──────────────────────────",
    "ADVANCED": "── Advanced Tools ───────────────────────────",
    "REPORT":   "── Reporting & Database ─────────────────────",
    "SAFETY":   "── Safety Tools ─────────────────────────────",
}

def show_menu():
    print(f"{BOLD}  Available Tools:{RESET}\n")
    last_cat = None
    for key, tool in TOOLS.items():
        cat = tool.get("category", "CORE")
        if cat != last_cat:
            color = CATEGORY_COLORS.get(cat, CYAN)
            label = CATEGORY_LABELS.get(cat, "")
            print(f"  {color}{DIM}{label}{RESET}")
            last_cat = cat
        color = CATEGORY_COLORS.get(cat, CYAN)
        print(f"  {color}[{key:>2}]{RESET} {BOLD}{tool['name']}{RESET}")
        print(f"       {DIM}{tool['desc']}{RESET}")
        print()
    print(f"  {YELLOW}[h]{RESET} Show usage examples for a tool")
    print(f"  {RED}[q]{RESET} Quit")
    print()

def show_help(key):
    if key not in TOOLS:
        print(f"{RED}[!] Invalid tool number{RESET}")
        return
    tool = TOOLS[key]
    print(f"\n{BOLD}{'─'*55}")
    print(f"  {tool['name']}")
    print(f"{'─'*55}{RESET}")
    print(f"\n  {BOLD}Script:{RESET}  poc/scripts/{tool['file']}")
    print(f"  {BOLD}Purpose:{RESET} {tool['desc']}")
    print(f"\n  {BOLD}Example:{RESET}")
    print(f"  {CYAN}python3 poc/scripts/{tool['file']} {tool['example']}{RESET}\n")

def run_tool(key):
    if key not in TOOLS:
        print(f"{RED}[!] Invalid selection{RESET}")
        return

    tool = TOOLS[key]
    script_path = os.path.join(SCRIPTS_DIR, tool["file"])

    if not os.path.exists(script_path):
        print(f"{RED}[!] Script not found: {script_path}{RESET}")
        return

    print(f"\n{BOLD}{'─'*55}")
    print(f"  Launching: {tool['name']}")
    print(f"{'─'*55}{RESET}")
    print(f"\n  {DIM}Tip — Usage example:{RESET}")
    print(f"  {CYAN}python3 poc/scripts/{tool['file']} {tool['example']}{RESET}\n")

    print(f"  Enter arguments (or press Enter to see --help):")
    args_input = input(f"  {CYAN}>{RESET} ").strip()

    if not args_input:
        args_input = "--help"

    cmd = [sys.executable, script_path] + args_input.split()

    print(f"\n{YELLOW}[*] Running: python3 {tool['file']} {args_input}{RESET}\n")
    print("─" * 55)

    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted by user{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")

    input(f"\n{DIM}  Press Enter to return to menu...{RESET}")

def main():
    while True:
        banner()
        show_menu()

        choice = input(f"  {BOLD}Select [{'/'.join(TOOLS.keys())}/h/q]:{RESET} ").strip().lower()

        if choice == "q":
            print(f"\n{GREEN}[+] Exiting. Stay within scope!{RESET}\n")
            sys.exit(0)

        elif choice == "h":
            banner()
            tool_key = input(f"  Enter tool number to show help [{'/'.join(TOOLS.keys())}]: ").strip()
            show_help(tool_key)
            input(f"\n{DIM}  Press Enter to return to menu...{RESET}")

        elif choice in TOOLS:
            run_tool(choice)

        else:
            valid = "/".join(TOOLS.keys())
            print(f"{RED}[!] Invalid input — enter {valid}, h, or q{RESET}")
            import time; time.sleep(1)

if __name__ == "__main__":
    main()
