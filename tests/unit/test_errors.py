from shellsafe.errors import (
    ArgvOnlyError,
    RawUsageError,
    ShellSafeError,
    ShellSafeTypeError,
    UnsupportedPlatformError,
)


def test_hierarchy():
    for exc in (ShellSafeTypeError, UnsupportedPlatformError, ArgvOnlyError, RawUsageError):
        assert issubclass(exc, ShellSafeError)
    assert issubclass(ShellSafeError, Exception)
