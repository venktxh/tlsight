"""TLSight command line.

  python cli.py analyze capture.pcap [--json out.json] [--probe] [--all]
  python cli.py check example.com[:port] [--json out.json] [--all]
"""

import argparse
import sys

from rich.console import Console

from tlsight.analyzer import analyze_pcap, check_host
from tlsight.report import print_report, to_json


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="tlsight", description="TLS handshake & cipher suite analyzer")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="analyze TLS handshakes in a pcap/pcapng file")
    a.add_argument("pcap")
    a.add_argument("--probe", action="store_true",
                   help="connect to TLS 1.3 servers to fetch their (encrypted) certificates")
    a.add_argument("--max-bytes", type=int, default=65536,
                   help="bytes of each TCP direction to reassemble (default 65536)")

    c = sub.add_parser("check", help="connect to one server and grade what it negotiates")
    c.add_argument("target", help="host or host:port")

    for p in (a, c):
        p.add_argument("--json", metavar="FILE", help="also write the full report as JSON")
        p.add_argument("--all", action="store_true", help="also show positive (GOOD) findings")

    args = ap.parse_args(argv)
    console = Console()

    if args.cmd == "analyze":
        report = analyze_pcap(args.pcap, do_probe=args.probe, max_bytes=args.max_bytes)
    else:
        host, _, port = args.target.partition(":")
        report = check_host(host, int(port or 443))

    if not report.connections:
        console.print("[yellow]No TLS handshakes found.[/]")
    else:
        print_report(report, console, show_good=args.all)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(to_json(report))
        console.print(f"JSON report written to {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
