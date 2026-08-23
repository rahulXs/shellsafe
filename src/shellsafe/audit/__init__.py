"""Offline AST audit for dangerous command construction. Ships with v0.3.0."""

from __future__ import annotations

from ..errors import ShellSafeError


def scan(paths: list[str]) -> list[dict[str, object]]:
    """Scan paths for AU001-AU004 findings. Arrives in shellsafe 0.3."""
    raise ShellSafeError("audit arrives in shellsafe 0.3")
