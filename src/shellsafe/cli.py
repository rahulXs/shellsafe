"""CLI: audit, version. Business logic lives in the stages."""

import argparse
import platform
import sys

from . import exitcodes
from ._version import __version__

_SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="shellsafe")
    parser.add_argument("-V", "--version", action="store_true")
    sub = parser.add_subparsers(dest="command")

    audit = sub.add_parser("audit", help="scan code for dangerous command construction")
    audit.add_argument("paths", nargs="*", default=["."], help="files or directories to scan")
    audit.add_argument("--json", action="store_true", dest="json_output", help="output JSON report")
    audit.add_argument(
        "--severity",
        choices=["error", "warning", "info"],
        default="warning",
        help="minimum severity to report (default: warning)",
    )

    sub.add_parser("version", help="detailed version and capability matrix")
    return parser


def _run_audit(args: argparse.Namespace) -> int:
    from .audit.scanner import Finding, report_json, report_terminal, scan_report

    report = scan_report(args.paths)
    findings = report.get("findings", [])

    min_sev = _SEVERITY_ORDER.get(args.severity, 1)
    filtered = [
        f for f in findings
        if _SEVERITY_ORDER.get(str(f.get("severity", "")), 9) <= min_sev
    ]

    if args.json_output:
        print(report_json(report))
    else:
        print(report_terminal([Finding(**f) for f in filtered]))

    summary = report.get("summary", {})
    return exitcodes.FINDINGS if summary.get("errors", 0) > 0 else exitcodes.OK


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"shellsafe {__version__}")
        return exitcodes.OK
    if args.command == "version":
        py = platform.python_version()
        print(f"shellsafe {__version__} . python {py} . {sys.platform}")
        print("argv-mode: available")
        print("shell-mode: available (posix)")
        print("audit: available (AU001-AU004)")
        return exitcodes.OK
    if args.command == "audit":
        return _run_audit(args)
    parser.print_help()
    return exitcodes.OK
