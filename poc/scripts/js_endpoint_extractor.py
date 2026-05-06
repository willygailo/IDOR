#!/usr/bin/env python3
"""
JavaScript Endpoint Extractor
==============================
Extracts API endpoints from JavaScript files to discover hidden IDOR candidates.

Usage: python3 js_endpoint_extractor.py --help

⚠️  For authorized testing only. Always stay within program scope.
"""

import argparse
import re
import requests
from urllib.parse import urljoin, urlparse

GREEN  = "\033[92m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
RED    = "\033[91m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

# Regex patterns to find API endpoints and parameters
PATTERNS = [
    r'["\'](/api/[^\s"\'<>{}|\\^`\[\]]*)["\']',
    r'["\'](/v\d+/[^\s"\'<>{}|\\^`\[\]]*)["\']',
    r'fetch\(["\']([^"\']+)["\']',
    r'axios\.(get|post|put|delete|patch)\(["\']([^"\']+)["\']',
    r'url:\s*["\']([^"\']+)["\']',
    r'endpoint:\s*["\']([^"\']+)["\']',
    r'path:\s*["\']([/][^"\']+)["\']',
]

# Common IDOR-prone parameter patterns
PARAM_PATTERNS = [
    r'[?&](\w*id\w*)[=]',
    r'[?&](\w*_id)[=]',
    r'/\{(\w+_?id\w*)\}',
    r'/:(\w+Id)',
    r'/:(\w+_id)',
]

def banner():
    print(f"""{CYAN}{BOLD}
╔══════════════════════════════════════════╗
║    JavaScript Endpoint Extractor v1.0    ║
║   For authorized bug bounty testing only ║
╚══════════════════════════════════════════╝{RESET}
""")

def fetch_js(url: str, token: str = None) -> str:
    headers = {"User-Agent": "JSExtractor/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        print(f"{RED}[!] Failed to fetch {url}: {e}{RESET}")
        return ""

def extract_js_urls(html: str, base_url: str) -> list[str]:
    """Find all .js file references in an HTML page."""
    pattern = r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']'
    matches = re.findall(pattern, html)
    full_urls = []
    for match in matches:
        if match.startswith("http"):
            full_urls.append(match)
        else:
            full_urls.append(urljoin(base_url, match))
    return list(set(full_urls))

def extract_endpoints(js_content: str) -> list[str]:
    found = set()
    for pattern in PATTERNS:
        matches = re.findall(pattern, js_content)
        for m in matches:
            endpoint = m if isinstance(m, str) else m[-1]
            if endpoint.startswith("/") or endpoint.startswith("http"):
                found.add(endpoint.strip())
    return sorted(found)

def find_idor_params(endpoints: list[str]) -> list[str]:
    candidates = []
    for ep in endpoints:
        for pat in PARAM_PATTERNS:
            if re.search(pat, ep, re.IGNORECASE):
                candidates.append(ep)
                break
    return candidates

def run(args):
    banner()

    all_endpoints = set()
    idor_candidates = []

    if args.js_url:
        urls_to_scan = [args.js_url]
    elif args.target:
        print(f"{BOLD}[*] Crawling page for JS files: {args.target}{RESET}")
        html = fetch_js(args.target, args.token)
        urls_to_scan = extract_js_urls(html, args.target)
        print(f"{GREEN}[+] Found {len(urls_to_scan)} JS files{RESET}\n")
    else:
        print(f"{RED}[!] Provide --target or --js-url{RESET}")
        return

    for js_url in urls_to_scan:
        print(f"  {CYAN}[JS]{RESET} Scanning: {js_url}")
        content = fetch_js(js_url, args.token)
        if not content:
            continue
        endpoints = extract_endpoints(content)
        all_endpoints.update(endpoints)
        print(f"      Found {len(endpoints)} endpoints")

    all_endpoints = sorted(all_endpoints)
    idor_candidates = find_idor_params(all_endpoints)

    print(f"\n{BOLD}{'─'*50}")
    print(f"  Total Endpoints    : {len(all_endpoints)}")
    print(f"  IDOR Candidates    : {len(idor_candidates)}")
    print(f"{'─'*50}{RESET}\n")

    if all_endpoints:
        print(f"{BOLD}[*] All Endpoints:{RESET}")
        for ep in all_endpoints:
            print(f"  {ep}")

    if idor_candidates:
        print(f"\n{BOLD}{GREEN}[!] IDOR Candidates (contain ID parameters):{RESET}")
        for ep in idor_candidates:
            print(f"  {GREEN}→{RESET} {ep}")

    if args.output:
        import json
        with open(args.output, "w") as f:
            json.dump({
                "all_endpoints": list(all_endpoints),
                "idor_candidates": idor_candidates
            }, f, indent=2)
        print(f"\n{GREEN}[+] Results saved to: {args.output}{RESET}")

def main():
    parser = argparse.ArgumentParser(
        description="JavaScript Endpoint Extractor — authorized testing only",
        formatter_class=argparse.RawTextHelpFormatter
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--target", help="Target web page URL (auto-discovers JS files)")
    group.add_argument("--js-url", help="Direct URL to a specific JS file")
    parser.add_argument("--token",  default=None, help="Bearer token if auth required")
    parser.add_argument("--output", default="endpoints.json", help="Output file (default: endpoints.json)")
    args = parser.parse_args()
    run(args)

if __name__ == "__main__":
    main()
