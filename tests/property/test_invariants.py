"""Property tests: invariants that must hold for arbitrary inputs."""

import shlex
import sys
from string.templatelib import Interpolation, Template

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from shellsafe.render import plan

# NUL bytes are refused at resolution; everything else must render safely.
text_values = st.text(st.characters(blacklist_characters="\x00"), max_size=200)




@settings(max_examples=300)
@given(value=text_values)
def test_one_interpolation_is_exactly_one_argument(value: str):
    p = plan(Template("run ", Interpolation(value, "v", None, "")))
    assert p.argv == ("run", value)


@settings(max_examples=200)
@given(a=text_values, b=text_values)
def test_two_interpolations_stay_separate(a: str, b: str):
    p = plan(
        Template("copy ", Interpolation(a, "x", None, ""), " ", Interpolation(b, "y", None, ""))
    )
    assert p.argv == ("copy", a, b)


@settings(max_examples=200)
@given(value=text_values)
def test_repr_round_trip_is_byte_stable(value: str):
    p1 = plan(Template("run ", Interpolation(value, "v", None, "")))
    p2 = plan(Template("run ", Interpolation(value, "v", None, "")))
    assert repr(p1) == repr(p2)




@pytest.mark.skipif(sys.platform == "win32", reason="shell mode is posix-only")
@settings(max_examples=300)
@given(value=text_values)
def test_shell_interpolation_stays_single_token(value: str):
    """INV-shell: under a pipe template, shlex.split yields value as one token."""
    p = plan(Template("cat ", Interpolation(value, "v", None, ""), " | wc -l"))
    assert p.mode == "shell"
    assert p.shell_line is not None
    tokens = shlex.split(p.shell_line)
    # "cat", VALUE, "|", "wc", "-l" = 5 tokens
    assert len(tokens) == 5
    assert tokens[1] == value


@pytest.mark.skipif(sys.platform == "win32", reason="shell mode is posix-only")
@settings(max_examples=200)
@given(a=text_values, b=text_values)
def test_shell_two_interpolations_stay_separate(a: str, b: str):
    """Two shell-mode interpolations must each occupy one token."""
    p = plan(
        Template(
            "grep ", Interpolation(a, "x", None, ""), " ", Interpolation(b, "y", None, ""),
            " | sort",
        )
    )
    assert p.mode == "shell"
    assert p.shell_line is not None
    tokens = shlex.split(p.shell_line)
    # "grep", A, B, "|", "sort" = 5 tokens
    assert len(tokens) == 5
    assert tokens[1] == a
    assert tokens[2] == b
