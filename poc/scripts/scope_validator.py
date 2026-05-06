#!/usr/bin/env python3
"""
Scope Validator
===============
Validates that all target URLs are within the authorized bug bounty scope
BEFORE running any scan tool. Prevents out-of-scope requests.

Usage:
    python3 scope_validator.py --url https://target.com/api/user --scope-file scope.txt
    python3 scope_validator.py --url https://target.com/api/user --domains "*.target.com,api.target.com"

⚠️  Always validate scope before testing. Out-of-scope testing is illegal.
"""

import argparse
import re
import sys
from urllib.parse import urlparse
from typing import List, Optional
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich import box
from rich.table import Table

console = Console()

BANNER = """
╔══════════════════════════════════════════════════╗
║         Scope Validator v2.0                    ║
║   Always test within authorized scope!          ║
╚══════════════════════════════════════════════════╝
"""

# ─── Common bug bounty program out-of-scope indicators ────────────────────────
ALWAYS_OUT_OF_SCOPE = [
    "gov.ph",         # Government sites — usually excluded
    "facebook.com",
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "cloudflare.com",
]

SAFE_HEADERS_TO_CHECK = [
    "X-Frame-Options",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "X-XSS-Protection",
]


def load_scope_file(path: str) -> List[str]:
    """Load scope domains/patterns from a file (one per line, supports # comments)."""
    p = Path(path)
    if not p.exists():
        console.print(f"[red][!] Scope file not found: {path}[/red]")
        sys.exit(1)
    lines = p.read_text().splitlines()
    return [l.strip() for l in lines if l.strip() and not l.startswith("#")]


def wildcard_match(pattern: str, hostname: str) -> bool:
    """Match wildcard domain patterns like *.example.com"""
    if pattern.startswith("*."):
        domain_suffix = pattern[2:]
        return hostname == domain_suffix or hostname.endswith("." + domain_suffix)
    return pattern == hostname or hostname.endswith("." + pattern)


def check_url(url: str, scope: List[str], strict: bool = True) -> dict:
    """Check a single URL against scope list."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    result = {
        "url": url,
        "hostname": hostname,
        "in_scope": False,
        "matched_pattern": None,
        "always_blocked": False,
        "reason": "",
        "scheme_ok": parsed.scheme in ("http", "https"),
    }

    # Always-blocked domains
    for blocked in ALWAYS_OUT_OF_SCOPE:
        if wildcard_match(blocked, hostname) or blocked in hostname:
            result["always_blocked"] = True
            result["reason"] = f"Globally blocked domain: {blocked}"
            return result

    # Check against scope list
    for pattern in scope:
        pattern_clean = pattern.lstrip("http://").lstrip("https://").split("/")[0]
        if wildcard_match(pattern_clean, hostname):
            result["in_scope"] = True
            result["matched_pattern"] = pattern
            result["reason"] = f"Matched scope pattern: {pattern}"
            return result

    result["reason"] = "Not found in any scope pattern"
    return result


def validate_urls(urls: List[str], scope: List[str], strict: bool) -> tuple:
    """Validate a list of URLs. Returns (all_in_scope: bool, results: list)."""
    results = []
    for url in urls:
        r = check_url(url, scope, strict)
        results.append(r)
    all_ok = all(r["in_scope"] and not r["always_blocked"] for r in results)
    return all_ok, results


def print_results(results: list):
    table = Table(title="Scope Validation Results", box=box.ROUNDED, show_lines=True)
    table.add_column("URL", style="cyan", no_wrap=False)
    table.add_column("Hostname", style="bold")
    table.add_column("Status", style="bold")
    table.add_column("Reason")

    for r in results:
        if r["always_blocked"]:
            status = "[red]🚫 BLOCKED[/red]"
        elif r["in_scope"]:
            status = "[green]✅ IN SCOPE[/green]"
        else:
            status = "[yellow]⚠️ OUT OF SCOPE[/yellow]"

        table.add_row(r["url"][:70], r["hostname"], status, r["reason"])

    console.print(table)


def interactive_checker(scope: List[str]):
    """Interactive URL checker mode."""
    console.print(Panel(
        "[cyan]Interactive Scope Checker[/cyan]\n"
        "Type a URL to check if it's in scope. Type [bold]quit[/bold] to exit.",
        border_style="cyan"
    ))
    while True:
        url = console.input("[bold cyan]URL to check:[/bold cyan] ").strip()
        if url.lower() in ("quit", "exit", "q"):
            break
        if not url.startswith("http"):
            url = "https://" + url
        r = check_url(url, scope)
        if r["always_blocked"]:
            console.print(f"  [red]🚫 BLOCKED — {r['reason']}[/red]")
        elif r["in_scope"]:
            console.print(f"  [green]✅ IN SCOPE — {r['reason']}[/green]")
        else:
            console.print(f"  [yellow]⚠️ OUT OF SCOPE — {r['reason']}[/yellow]")


def generate_scope_file(args):
    """Generate a scope.txt template."""
    template = """# Bug Bounty Scope File
# Format: one pattern per line
# Wildcards: *.example.com matches all subdomains
# Lines starting with # are comments

# ─── In-Scope Domains ────────────────────
*.target.com
api.target.com
app.target.com

# ─── Specific Endpoints ──────────────────
# https://api.target.com/v1/

# ─── Notes ───────────────────────────────
# Program: HackerOne / Bugcrowd / etc.
# Added: {date}
"""
    from datetime import datetime
    out = args.output or "scope.txt"
    Path(out).write_text(template.replace("{date}", datetime.now().strftime("%Y-%m-%d")))
    console.print(f"[green][+] Scope file template created → {out}[/green]")


def main():
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")

    parser = argparse.ArgumentParser(description="Bug Bounty Scope Validator")
    sub = parser.add_subparsers(dest="cmd")

    # check
    p_check = sub.add_parser("check", help="Check URL(s) against scope")
    p_check.add_argument("--url",        help="Single URL to check")
    p_check.add_argument("--url-file",   help="File with URLs to check (one per line)")
    p_check.add_argument("--scope-file", help="Scope file (one domain/pattern per line)")
    p_check.add_argument("--domains",    help="Comma-separated scope domains: '*.target.com,api.target.com'")
    p_check.add_argument("--strict",     action="store_true", help="Exit with error if any URL is out of scope")

    # interactive
    p_int = sub.add_parser("interactive", help="Interactive URL checker")
    p_int.add_argument("--scope-file", help="Scope file")
    p_int.add_argument("--domains",    help="Comma-separated scope domains")

    # generate
    p_gen = sub.add_parser("generate", help="Generate scope.txt template")
    p_gen.add_argument("--output", default="scope.txt")

    args = parser.parse_args()

    if args.cmd == "generate":
        generate_scope_file(args)
        return

    # Build scope list
    scope = []
    if hasattr(args, "scope_file") and args.scope_file:
        scope.extend(load_scope_file(args.scope_file))
    if hasattr(args, "domains") and args.domains:
        scope.extend([d.strip() for d in args.domains.split(",")])

    if not scope:
        console.print("[red][!] No scope defined. Use --scope-file or --domains[/red]")
        sys.exit(1)

    console.print(f"[cyan][*] Loaded {len(scope)} scope patterns[/cyan]")

    if args.cmd == "interactive":
        interactive_checker(scope)
        return

    # Collect URLs
    urls = []
    if args.url:
        urls.append(args.url)
    if args.url_file:
        with open(args.url_file) as f:
            urls.extend([l.strip() for l in f if l.strip()])

    if not urls:
        console.print("[red][!] No URLs provided. Use --url or --url-file[/red]")
        sys.exit(1)

    all_ok, results = validate_urls(urls, scope, getattr(args, "strict", False))
    print_results(results)

    if all_ok:
        console.print(f"\n[green][✓] All {len(urls)} URL(s) are within scope — safe to proceed![/green]")
        sys.exit(0)
    else:
        out_of_scope = [r for r in results if not r["in_scope"] or r["always_blocked"]]
        console.print(f"\n[red][✗] {len(out_of_scope)} URL(s) are OUT OF SCOPE — do NOT test these![/red]")
        if getattr(args, "strict", False):
            sys.exit(1)


if __name__ == "__main__":
    main()
