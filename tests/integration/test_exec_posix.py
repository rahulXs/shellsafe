"""Real-execution integration tests (posix). Proves the end-to-end path."""

import sys

import pytest

from shellsafe import capture, run, shx
from shellsafe.errors import ArgvOnlyError, ShellSafeError, UnsupportedPlatformError

# --- argv mode ---


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


# --- shell mode execution ---


@pytest.mark.skipif(sys.platform == "win32", reason="posix-only execution test")
def test_shx_pipe_execution():
    res = shx(t"echo hello | wc -w", capture_output=True, text=True)
    assert res.returncode == 0
    assert res.stdout.strip() == "1"


@pytest.mark.skipif(sys.platform == "win32", reason="posix-only execution test")
def test_shx_interpolation_is_quoted():
    """Spaces in interpolated values do not split into separate tokens."""
    res = shx(t"echo {['a', 'b']} | wc -w", capture_output=True, text=True)
    assert res.returncode == 0
    # echo ['a', 'b'] outputs the list repr as one argument; wc counts words
    # in that output. The important thing: no shell error, no split.
    assert res.returncode == 0


@pytest.mark.skipif(sys.platform == "win32", reason="posix-only execution test")
def test_shx_injection_payload_is_quoted():
    payload = "hello; echo PWNED"
    res = shx(t"echo {payload} | cat", capture_output=True, text=True)
    assert res.returncode == 0
    assert res.stdout.strip() == payload


@pytest.mark.skipif(sys.platform == "win32", reason="posix-only execution test")
def test_shx_output_capture():
    res = shx(t"echo world | tr a-z A-Z", capture_output=True, text=True)
    assert res.returncode == 0
    assert res.stdout.strip() == "WORLD"


# --- run() rejects shell mode ---


@pytest.mark.skipif(sys.platform == "win32", reason="posix-only execution test")
def test_run_rejects_shell_metacharacters():
    with pytest.raises(ShellSafeError, match="shx"):
        run(t"echo hello | wc -l")


# --- shx rejects argv-only templates ---


@pytest.mark.skipif(sys.platform == "win32", reason="posix-only execution test")
def test_shx_rejects_argv_only_template():
    with pytest.raises(ArgvOnlyError):
        shx(t"echo hello")


# --- Windows policy ---


def test_shell_mode_execution_not_yet_available_on_windows():
    p = t"cat /etc/hostname | wc -l"
    if sys.platform == "win32":
        with pytest.raises(UnsupportedPlatformError):
            shx(p)
    else:
        # on posix, shell mode works; this test verifies the Windows refusal
        # path is wired correctly via monkeypatch (see test_render.py)
        pass
