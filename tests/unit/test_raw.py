"""RAW marker invariants: nesting refused, verbatim display, single argument."""

import pytest

from shellsafe import RAW
from shellsafe.errors import RawUsageError


def test_raw_repr_shows_trust_boundary():
    assert "<RAW" in repr(RAW("pre-quoted"))


def test_nested_raw_refused():
    with pytest.raises(RawUsageError):
        RAW(RAW(["x"]))
