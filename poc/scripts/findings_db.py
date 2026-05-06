#!/usr/bin/env python3
"""
Findings Database (SQLite)
==========================
Persistent storage for all IDOR scan results.
Supports multi-target tracking, search, filtering, and stats.

Usage:
    python3 findings_db.py import --file idor_results.json --target https://target.com --program HackerOne
    python3 findings_db.py list
    python3 findings_db.py search --target https://target.com
    python3 findings_db.py stats
    python3 findings_db.py export --target https://target.com --output findings.json

⚠️  Authorized testing only.
"""

import argparse
import json
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel

console = Console()
DB_PATH = Path(__file__).parent.parent.parent / "findings.db"


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS targets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            url         TEXT NOT NULL UNIQUE,
            program     TEXT,
            scope       TEXT,
            added_at    TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id   INTEGER REFERENCES targets(id),
            scan_type   TEXT,
            tool        TEXT,
            started_at  TEXT,
            finished_at TEXT DEFAULT (datetime('now')),
            total_tested INTEGER DEFAULT 0,
            total_found  INTEGER DEFAULT 0,
            severity    TEXT DEFAULT 'Unknown',
            notes       TEXT
        );

        CREATE TABLE IF NOT EXISTS findings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER REFERENCES scans(id),
            target_id   INTEGER REFERENCES targets(id),
            object_id   TEXT,
            endpoint    TEXT,
            method      TEXT DEFAULT 'GET',
            status_code INTEGER,
            response_size INTEGER,
            snippet     TEXT,
            is_confirmed INTEGER DEFAULT 0,
            severity    TEXT DEFAULT 'Medium',
            cwe         TEXT DEFAULT 'CWE-639',
            notes       TEXT,
            created_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id);
        CREATE INDEX IF NOT EXISTS idx_findings_scan   ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status_code);
    """)
    conn.commit()


def upsert_target(conn: sqlite3.Connection, url: str, program: str, scope: str) -> int:
    cur = conn.execute("SELECT id FROM targets WHERE url = ?", (url,))
    row = cur.fetchone()
    if row:
        return row["id"]
    cur = conn.execute(
        "INSERT INTO targets (url, program, scope) VALUES (?, ?, ?)",
        (url, program, scope)
    )
    conn.commit()
    return cur.lastrowid


def import_findings(args):
    with open(args.file) as f:
        data = json.load(f)
    if not isinstance(data, list):
        data = [data]

    conn = get_conn()
    init_db(conn)

    target_id = upsert_target(conn, args.target, args.program or "Unknown", args.scope or "")

    # Detect tool type from data structure
    if any("query" in item for item in data):
        tool = "graphql_idor_tester"
        scan_type = "GraphQL"
    elif any("uuid" in str(item.get("id", "")).lower() or "-" in str(item.get("id","")) for item in data):
        tool = "uuid_idor_brute"
        scan_type = "UUID"
    elif any("attacker_data" in item for item in data):
        tool = "blind_idor_differ"
        scan_type = "Blind-Diff"
    else:
        tool = "idor_enum"
        scan_type = "REST-GET"

    total_found = len([d for d in data if d.get("status", 200) in (200, 201)])

    cur = conn.execute(
        """INSERT INTO scans (target_id, scan_type, tool, total_tested, total_found)
           VALUES (?, ?, ?, ?, ?)""",
        (target_id, scan_type, tool, len(data), total_found)
    )
    scan_id = cur.lastrowid

    inserted = 0
    for item in data:
        conn.execute(
            """INSERT INTO findings
               (scan_id, target_id, object_id, endpoint, method, status_code, response_size, snippet, is_confirmed)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                target_id,
                str(item.get("id", item.get("uuid", item.get("type", "?")))),
                item.get("url", item.get("endpoint", args.target)),
                item.get("method", "GET"),
                item.get("status", 200),
                item.get("length", item.get("response_size", 0)),
                item.get("snippet", item.get("note", ""))[:500],
                1 if item.get("status", 200) in (200, 201) else 0,
            )
        )
        inserted += 1

    conn.commit()
    console.print(f"[green][+] Imported {inserted} findings → target_id={target_id}, scan_id={scan_id}[/green]")
    conn.close()


def list_findings(args):
    conn = get_conn()
    init_db(conn)

    query = """
        SELECT f.id, t.url, t.program, f.object_id, f.endpoint, f.status_code,
               f.response_size, f.severity, f.created_at
        FROM findings f
        JOIN targets t ON t.id = f.target_id
        WHERE f.is_confirmed = 1
    """
    params = []
    if args.target:
        query += " AND t.url LIKE ?"
        params.append(f"%{args.target}%")
    if args.severity:
        query += " AND f.severity = ?"
        params.append(args.severity)
    query += " ORDER BY f.created_at DESC LIMIT ?"
    params.append(args.limit)

    rows = conn.execute(query, params).fetchall()

    table = Table(title=f"IDOR Findings ({len(rows)})", box=box.ROUNDED,
                  show_lines=True, border_style="cyan")
    table.add_column("ID", style="dim")
    table.add_column("Program", style="yellow")
    table.add_column("Target", style="cyan", no_wrap=True)
    table.add_column("Object ID", style="green")
    table.add_column("Status", style="bold")
    table.add_column("Size")
    table.add_column("Severity", style="red")
    table.add_column("Found At", style="dim")

    for r in rows:
        table.add_row(
            str(r["id"]),
            r["program"] or "-",
            r["url"][:50],
            r["object_id"],
            str(r["status_code"]),
            str(r["response_size"] or "-"),
            r["severity"],
            r["created_at"][:16],
        )

    console.print(table)
    conn.close()


def show_stats(args):
    conn = get_conn()
    init_db(conn)

    stats = conn.execute("""
        SELECT
            COUNT(DISTINCT t.id)          AS targets,
            COUNT(DISTINCT s.id)          AS scans,
            COUNT(f.id)                   AS total_findings,
            SUM(f.is_confirmed)           AS confirmed,
            COUNT(DISTINCT t.program)     AS programs
        FROM findings f
        JOIN scans s   ON s.id = f.scan_id
        JOIN targets t ON t.id = f.target_id
    """).fetchone()

    top_targets = conn.execute("""
        SELECT t.url, t.program, COUNT(f.id) AS hits
        FROM findings f JOIN targets t ON t.id = f.target_id
        WHERE f.is_confirmed = 1
        GROUP BY t.id ORDER BY hits DESC LIMIT 10
    """).fetchall()

    console.print(Panel(
        f"[bold cyan]Total Targets:[/bold cyan] {stats['targets']}\n"
        f"[bold cyan]Total Scans:[/bold cyan]   {stats['scans']}\n"
        f"[bold cyan]Total Findings:[/bold cyan] {stats['total_findings']}\n"
        f"[bold green]Confirmed IDOR:[/bold green] {stats['confirmed']}\n"
        f"[bold yellow]Programs:[/bold yellow]  {stats['programs']}",
        title="📊 Workspace Stats", border_style="cyan"
    ))

    if top_targets:
        t = Table(title="Top Targets by Findings", box=box.SIMPLE)
        t.add_column("URL"); t.add_column("Program"); t.add_column("Hits", style="green")
        for row in top_targets:
            t.add_row(row["url"][:60], row["program"] or "-", str(row["hits"]))
        console.print(t)

    conn.close()


def export_findings(args):
    conn = get_conn()
    init_db(conn)
    query = """
        SELECT f.*, t.url AS target_url, t.program
        FROM findings f JOIN targets t ON t.id = f.target_id
        WHERE f.is_confirmed = 1
    """
    params = []
    if args.target:
        query += " AND t.url LIKE ?"
        params.append(f"%{args.target}%")

    rows = conn.execute(query, params).fetchall()
    data = [dict(r) for r in rows]

    out = args.output or "exported_findings.json"
    with open(out, "w") as f:
        json.dump(data, f, indent=2)
    console.print(f"[green][+] Exported {len(data)} findings → {out}[/green]")
    conn.close()


def mark_confirmed(args):
    conn = get_conn()
    init_db(conn)
    conn.execute("UPDATE findings SET is_confirmed = 1, severity = ? WHERE id = ?",
                 (args.severity or "High", args.id))
    conn.commit()
    console.print(f"[green][+] Finding #{args.id} marked as confirmed ({args.severity})[/green]")
    conn.close()


def main():
    parser = argparse.ArgumentParser(description="IDOR Findings Database")
    sub = parser.add_subparsers(dest="cmd")

    # import
    p_import = sub.add_parser("import", help="Import scan results JSON")
    p_import.add_argument("--file",     required=True)
    p_import.add_argument("--target",   required=True, help="Target base URL")
    p_import.add_argument("--program",  default="Unknown", help="Bug bounty program name")
    p_import.add_argument("--scope",    default="")

    # list
    p_list = sub.add_parser("list", help="List findings")
    p_list.add_argument("--target",   default=None)
    p_list.add_argument("--severity", default=None)
    p_list.add_argument("--limit",    type=int, default=50)

    # stats
    sub.add_parser("stats", help="Show workspace statistics")

    # export
    p_export = sub.add_parser("export", help="Export findings to JSON")
    p_export.add_argument("--target", default=None)
    p_export.add_argument("--output", default=None)

    # confirm
    p_confirm = sub.add_parser("confirm", help="Mark finding as confirmed")
    p_confirm.add_argument("--id",       required=True, type=int)
    p_confirm.add_argument("--severity", default="High")

    args = parser.parse_args()

    if args.cmd == "import":   import_findings(args)
    elif args.cmd == "list":   list_findings(args)
    elif args.cmd == "stats":  show_stats(args)
    elif args.cmd == "export": export_findings(args)
    elif args.cmd == "confirm":mark_confirmed(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
