#!/usr/bin/env python3
"""
Blind IDOR Response Differ
===========================
Compares responses between an attacker session and a victim session
to detect IDOR even when HTTP status codes look identical (blind IDOR).

Logic:
  - Fetch resource as VICTIM   → baseline response
  - Fetch same resource as ATTACKER → compare response body, length, fields
  - If attacker gets victim's data → IDOR confirmed

Usage: python3 blind_idor_differ.py --help

⚠️  For authorized testing only. Always stay within program scope.
"""

import argparse
import requests
import json
from datetime import datetime
from difflib import unified_diff

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def banner():
    print(f"""{CYAN}{BOLD}
╔══════════════════════════════════════════╗
║      Blind IDOR Response Differ v1.0     ║
║   For authorized bug bounty testing only ║
╚══════════════════════════════════════════╝{RESET}
""")

def fetch(url: str, token: str = None, cookie: str = None) -> requests.Response:
    headers = {"User-Agent": "BlindIDOR-Differ/1.0", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if cookie:
        headers["Cookie"] = cookie
    return requests.get(url, headers=headers, timeout=10)

def compare(args):
    banner()

    print(f"{BOLD}[*] Endpoint       : {args.url}{RESET}")
    print(f"{BOLD}[*] Victim token   : {args.victim_token[:20]}...{RESET}" if args.victim_token else "")
    print(f"{BOLD}[*] Attacker token : {args.attacker_token[:20]}...{RESET}" if args.attacker_token else "")
    print()

    # Fetch as VICTIM (baseline)
    try:
        victim_resp = fetch(args.url, token=args.victim_token, cookie=args.victim_cookie)
        print(f"{GREEN}[VICTIM]{RESET}   Status={victim_resp.status_code} | Len={len(victim_resp.text)}")
    except Exception as e:
        print(f"{RED}[!] Failed to fetch as victim: {e}{RESET}")
        return

    # Fetch as ATTACKER
    try:
        attacker_resp = fetch(args.url, token=args.attacker_token, cookie=args.attacker_cookie)
        print(f"{YELLOW}[ATTACKER]{RESET} Status={attacker_resp.status_code} | Len={len(attacker_resp.text)}")
    except Exception as e:
        print(f"{RED}[!] Failed to fetch as attacker: {e}{RESET}")
        return

    print()

    # Compare
    if victim_resp.text == attacker_resp.text:
        print(f"{GREEN}[!] RESPONSES ARE IDENTICAL — Possible IDOR!{RESET}")
        print(f"    Attacker received exact same data as victim.")
    elif victim_resp.status_code == attacker_resp.status_code:
        print(f"{YELLOW}[~] Same status code but different body — partial match, investigate manually.{RESET}")
    else:
        print(f"{RED}[-] Different responses — likely NOT vulnerable (or properly denied).{RESET}")

    # Diff output
    if args.diff:
        print(f"\n{BOLD}─── Unified Diff ───────────────────────────────{RESET}")
        victim_lines   = victim_resp.text.splitlines(keepends=True)
        attacker_lines = attacker_resp.text.splitlines(keepends=True)
        diff = list(unified_diff(victim_lines, attacker_lines,
                                 fromfile="victim_response",
                                 tofile="attacker_response"))
        if diff:
            for line in diff:
                if line.startswith("+"):
                    print(f"{GREEN}{line}{RESET}", end="")
                elif line.startswith("-"):
                    print(f"{RED}{line}{RESET}", end="")
                else:
                    print(line, end="")
        else:
            print("  (No diff — responses are byte-identical)")

    # Save
    if args.output:
        report = {
            "timestamp": datetime.now().isoformat(),
            "url": args.url,
            "victim_status": victim_resp.status_code,
            "attacker_status": attacker_resp.status_code,
            "victim_length": len(victim_resp.text),
            "attacker_length": len(attacker_resp.text),
            "identical": victim_resp.text == attacker_resp.text,
            "victim_body": victim_resp.text[:500],
            "attacker_body": attacker_resp.text[:500],
        }
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n{GREEN}[+] Report saved to: {args.output}{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="Blind IDOR Response Differ — authorized testing only",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--url",            required=True,  help="Full URL with victim's resource ID")
    parser.add_argument("--victim-token",   default=None,   help="Victim's Bearer token")
    parser.add_argument("--victim-cookie",  default=None,   help="Victim's cookie string")
    parser.add_argument("--attacker-token", default=None,   help="Attacker's Bearer token")
    parser.add_argument("--attacker-cookie",default=None,   help="Attacker's cookie string")
    parser.add_argument("--diff",           action="store_true", help="Show unified diff of responses")
    parser.add_argument("--output",         default="blind_idor_report.json", help="Output report file")
    args = parser.parse_args()
    compare(args)

if __name__ == "__main__":
    main()
