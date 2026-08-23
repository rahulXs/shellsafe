"""Exception hierarchy for shellsafe.

Every error raised publicly inherits from ShellSafeError so callers can catch
broadly. Messages are lowercase, state got and expected, and include the fix.
"""


class ShellSafeError(Exception):
    """Base class for every error shellsafe raises."""


class ShellSafeTypeError(ShellSafeError):
    """A template or interpolated value has an unsupported type."""


class UnsupportedPlatformError(ShellSafeError):
    """The requested shell route cannot be made safe on this platform.

    Interpolated shell routes are refused on Windows by policy; restructure the
    command as argv mode (no pipes or redirections) instead.
    """


class ArgvOnlyError(ShellSafeError):
    """shx() was called with a template that needs no shell at all.

    Use run() for plain commands; shx() exists for pipes and redirections.
    """


class RawUsageError(ShellSafeError):
    """RAW() was used incorrectly.

    RAW takes exactly one argument: a list of strings in argv mode or a string
    in shell mode. RAW values are never nested and never modified.
    """
