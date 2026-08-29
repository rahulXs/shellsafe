"""Platform policy tables and route decision."""

import sys

METACHARACTERS = frozenset("|&;()<>$`\"'*?!#\\\n\r\t")

IS_WINDOWS = sys.platform.startswith("win")


def route_for(static_text: str) -> str:
    """Return "argv" or "shell" for the given static template text.

    Raises UnsupportedPlatformError on Windows when shell features are requested.
    """
    if not any(ch in METACHARACTERS for ch in static_text):
        return "argv"
    if IS_WINDOWS:
        from .errors import UnsupportedPlatformError

        raise UnsupportedPlatformError(
            "shell metacharacters in a shellsafe template require posix sh; "
            "windows cmd.exe quoting cannot be made injection-safe. "
            "restructure without pipes/redirections, or run under wsl."
        )
    return "shell"
