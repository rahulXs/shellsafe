"""Platform policy tables and helpers. This module IS the security policy."""

from __future__ import annotations

import sys

# Static template text containing any of these routes the command to shell mode.
# Whitespace is not here: it splits words in argv mode.
METACHARACTERS: frozenset[str] = frozenset("|&;()<>$`\"'*?!#\\\n\r\t")

IS_WINDOWS = sys.platform.startswith("win")


def route_for(static_text: str) -> str:
    """Return "argv" or "shell" for the given static template text.

    Raises UnsupportedPlatformError when shell features are requested on Windows;
    cmd.exe quoting cannot be made injection-safe, so the refusal is the feature.
    """
    has_meta = any(ch in METACHARACTERS for ch in static_text)
    if not has_meta:
        return "argv"
    if IS_WINDOWS:
        raise _windows_error()
    return "shell"


def _windows_error() -> Exception:
    from .errors import UnsupportedPlatformError

    return UnsupportedPlatformError(
        "shell metacharacters in a shellsafe template require posix sh; "
        "windows cmd.exe quoting cannot be made injection-safe. "
        "restructure without pipes/redirections, or run under wsl."
    )
