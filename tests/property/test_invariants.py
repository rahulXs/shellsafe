"""Property tests: invariants that must hold for arbitrary inputs."""

from string.templatelib import Interpolation, Template

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
