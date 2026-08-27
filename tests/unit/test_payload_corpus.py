"""Payload corpus gate: every injection case renders inert.

Argv mode: each .txt file in cases/ holds exactly one interpolated value. The
command is argv mode "echo <value>"; the invariant under test: the value occupies
exactly one argv element equal to the original payload. If any payload can escape
into a second command, this suite fails and the release is blocked.

Shell mode: the same payloads are tested under a pipe template. The invariant:
shlex.split(rendered_line) yields the interpolated value as exactly one token
equal to the original payload.
"""

import shlex
import sys
from pathlib import Path
from string.templatelib import Interpolation, Template

import pytest

from shellsafe.render import plan

CASES_DIR = Path(__file__).parent.parent / "payloads" / "cases"
CASE_FILES = sorted(CASES_DIR.glob("case_*.txt"))


def payloads() -> list[tuple[str, str]]:
    out = []
    for path in CASE_FILES:
        raw = path.read_text()
        # strip one trailing newline added by file storage; keep all else verbatim
        value = raw[:-1] if raw.endswith("\n") else raw
        out.append((path.stem, value))
    return out


# --- argv mode ---


@pytest.mark.parametrize(
    ("name", "payload"),
    payloads(),
    ids=[n for n, _ in payloads()],
)
def test_payload_stays_single_argument(name: str, payload: str):
    p = plan(Template("echo ", Interpolation(payload, "value", None, "")))
    assert p.mode == "argv"
    assert p.argv == ("echo", payload)


# --- shell mode ---


@pytest.mark.parametrize(
    ("name", "payload"),
    payloads(),
    ids=[n for n, _ in payloads()],
)
@pytest.mark.skipif(sys.platform == "win32", reason="shell mode is posix-only")
def test_shell_payload_stays_single_token(name: str, payload: str):
    """Pipe template: value must be shell-quoted, never splitting into tokens."""
    p = plan(
        Template("cat ", Interpolation(payload, "value", None, ""), " | wc -l")
    )
    assert p.mode == "shell"
    assert p.shell_line is not None
    tokens = shlex.split(p.shell_line)
    # static tokens: "cat", "|", "wc", "-l"  (4); value must be exactly one
    assert len(tokens) == 5
    assert tokens[1] == payload


def test_corpus_is_present():
    # guard against silent corpus deletion
    assert len(CASE_FILES) >= 10
