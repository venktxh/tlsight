"""Console (rich) and JSON output."""

import json

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from .ciphers import group_name, lookup, suite_name, version_name
from .models import Report

GRADE_STYLE = {"A": "bold green", "B": "green", "C": "yellow", "D": "dark_orange",
               "F": "bold red", "N/A": "dim"}
SEV_STYLE = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan",
             "INFO": "dim", "GOOD": "green"}


def kex_label(conn) -> str:
    s = lookup(conn.cipher) if conn.cipher is not None else None
    group = conn.key_share_group or conn.ske_group
    if group is not None:
        return group_name(group)
    if conn.dh_bits:
        return f"DHE-{conn.dh_bits}"
    return s.kex if s else "-"


def cert_label(conn) -> str:
    if not conn.certs:
        return "-"
    leaf = conn.certs[0]
    return f"{leaf.key_type.split()[0]}-{leaf.key_size} ({leaf.days_left}d)"


def print_report(report: Report, console: Console = None, show_good: bool = False):
    console = console or Console()
    table = Table(title=f"TLS connections in {report.source}", show_lines=False)
    for col in ("#", "Server", "Version", "Cipher suite", "Key exch.", "Cert", "JA3", "Grade"):
        table.add_column(col, overflow="fold")
    for c in report.connections:
        table.add_row(str(c.id), c.target, version_name(c.version), suite_name(c.cipher),
                      kex_label(c), cert_label(c), (c.ja3_hash or "-")[:12],
                      f"[{GRADE_STYLE.get(c.grade, '')}]{c.grade}[/]")
    console.print(table)

    for c in report.connections:
        shown = [f for f in c.findings if show_good or f.severity != "GOOD"]
        if not shown and not c.notes:
            continue
        console.print(f"\n[bold]#{c.id} {c.target}[/] ({c.client} -> {c.server})  "
                      f"grade [{GRADE_STYLE.get(c.grade, '')}]{c.grade}[/]"
                      + (f"  score {c.score}" if c.score is not None else ""))
        for f in shown:
            side = escape(f"[{f.side}]".ljust(13))
            line = f"  [{SEV_STYLE[f.severity]}]{f.severity:<8}[/] {side} {escape(f.title)}"
            if f.detail:
                line += f"\n             [dim]{escape(f.detail)}[/]"
            console.print(line)
        for note in c.notes:
            console.print(f"  [dim]note: {escape(note)}[/]")

    s = report.summary()
    grades = "  ".join(f"{g}: {n}" for g, n in sorted(s["grades"].items()))
    console.print(f"\n[bold]{s['connections']} TLS connection(s)[/]  {grades}")


def to_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, default=str)
