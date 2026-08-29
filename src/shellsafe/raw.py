"""RAW marker: the single explicit trust boundary."""


from .errors import RawUsageError


class Raw:
    """Wraps pre-trusted content that rendering must not modify.

    In argv mode the wrapped value must be a list of strings and is spliced
    into the argv positionally. In POSIX shell mode a str value is inserted
    verbatim into the shell line. Nothing else is accepted, nesting is refused,
    and every use site is greppable.
    """

    __slots__ = ("value",)

    def __init__(self, value: list[str] | str) -> None:
        if isinstance(value, Raw):
            raise RawUsageError("raw cannot wrap another raw")
        self.value = value

    def __repr__(self) -> str:
        return f"<RAW {self.value!r}>"


def RAW(value: list[str] | str) -> Raw:
    """Mark content as pre-trusted. See Raw for mode-specific rules."""
    return Raw(value)
