"""Real-execution integration tests (posix). Proves the end-to-end path."""

import sys

import pytest

from shellsafe import capture, shx
from shellsafe.errors import ShellSafeError


@pytest.mark.skipif(sys.platform == "win32", reason="posix-only execution test")
def test_capture_round_trip():
    res = capture(t"echo hello")
    assert res.returncode == 0
    assert res.stdout == "hello\n"


@pytest.mark.skipif(sys.platform == "win32", reason="posix-only execution test")
def test_injection_payload_arrives_as_text():
    payload = "hello; echo PWNED"
    res = capture(t"echo {payload}")
    # argv mode: echo receives the whole payload as ONE argument; no second
    # command can exist. The output is the payload text itself.
    assert res.stdout.strip() == payload


@pytest.mark.skipif(sys.platform == "win32", reason="posix-only execution test")
def test_interpolation_with_spaces_stays_one_argument():
    value = "two words"
    res = capture(t"echo {value}")
    assert res.stdout.strip() == "two words"


def test_shell_mode_execution_not_yet_available():
    # rendering and inspection work today; execution gate is explicit until v0.2
    p = t"cat /etc/hostname | wc -l"

    with pytest.raises(ShellSafeError, match=r"0\.2"):
        shx(p)
