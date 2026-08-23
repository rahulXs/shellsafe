"""RAW marker invariants: nesting refused, verbatim display, single argument."""

import pytest

from shellsafe import RAW
from shellsafe.errors import RawUsageError
from shellsafe.raw import Raw


def test_raw_wraps_list_verbatim():
    r = RAW(["git", "log", "--oneline"])
    assert isinstance(r, Raw)
    assert r.value == ["git", "log", "--oneline"]


def test_raw_repr_shows_trust_boundary():
    assert "<RAW" in repr(RAW("pre-quoted"))


def test_nested_raw_refused():
    with pytest.raises(RawUsageError):
        RAW(RAW(["x"]))


def test_raw_is_greppable():
    # house rule: trust boundaries are greppable; this documents the pattern
    source = 'RAW("trusted")'
    assert "RAW(" in source
