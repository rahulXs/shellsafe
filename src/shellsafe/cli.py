"""CLI wiring: audit, demo, version. Business logic lives in the stages."""

from __future__ import annotations

import argparse
import platform
import sys

from . import exitcodes
from ._version import __version__


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="shellsafe")
    parser.add_argument("-V", "--version", action="store_true")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("audit", help="scan code for dangerous command construction (v0.3)")
    sub.add_parser("version", help="detailed version and capability matrix")
    return parser


def _print_version_matrix() -> None:
    py = platform.python_version()
    print(f"shellsafe {__version__} · python {py} · {sys.platform}")
    print("argv-mode: available")
    print("shell-mode: arriving in 0.2")
    print("audit: arriving in 0.3")


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.version:
        print(f"shellsafe {__version__}")
        return exitcodes.OK
    if args.command == "version":
        _print_version_matrix()
        return exitcodes.OK
    if args.command == "audit":
        print("audit arrives in shellsafe 0.3", file=sys.stderr)
        return exitcodes.USAGE
    _build_parser().print_help()
    return exitcodes.OK
