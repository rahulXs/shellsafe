"""Subprocess wrappers over rendered ExecutionPlans."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from typing import Any, cast

from .errors import ArgvOnlyError, ShellSafeError
from .raw import Raw  # noqa: F401  (re-exported through the package root)
from .render import ExecutionPlan

_ALLOWED_KWARGS = frozenset(
    {
        "check",
        "timeout",
        "env",
        "cwd",
        "capture_output",
        "input",
        "stdin",
        "stdout",
        "stderr",
        "start_new_session",
        "text",
        "encoding",
    }
)


def _validate_kwargs(kwargs: dict[str, object]) -> None:
    if "shell" in kwargs:
        raise ShellSafeError(
            "shellsafe never passes shell=True; use shx() for pipes and "
            "redirections on posix"
        )
    unknown = set(kwargs) - _ALLOWED_KWARGS
    if unknown:
        valid = ", ".join(sorted(_ALLOWED_KWARGS))
        raise ShellSafeError(
            f"unsupported keyword(s) {sorted(unknown)}; valid keywords: {valid}"
        )


def plan(template: object) -> ExecutionPlan:
    """Render a t-string into an inspectable ExecutionPlan without executing."""
    from .render import plan as render_plan

    return render_plan(template)


def _pass_through(kwargs: dict[str, object]) -> dict[str, Any]:
    """Filter kwargs to the allowed subprocess.run set."""
    return cast(
        "dict[str, Any]",
        {k: v for k, v in kwargs.items() if k in _ALLOWED_KWARGS},
    )


def run(template: object, /, **kwargs: object) -> subprocess.CompletedProcess[str]:
    """Render the template and execute it.

    Interpolated values always arrive as single argv elements. Keyword arguments
    pass through to subprocess.run with one exception: shell is rejected by
    design.
    """
    _validate_kwargs(kwargs)
    rendered = plan(template)
    if rendered.mode == "shell":
        if sys.platform.startswith("win"):
            raise ShellSafeError(
                "shell mode is posix-only; restructure the command without "
                "pipes or redirections, or run under wsl"
            )
        raise ShellSafeError(
            "this command contains shell metacharacters; use shx() instead of "
            "run() to execute pipes and redirections"
        )
    assert rendered.argv is not None
    result = subprocess.run(rendered.argv, **_pass_through(kwargs))
    return cast("subprocess.CompletedProcess[str]", result)


@dataclass(frozen=True, slots=True)
class CaptureResult:
    """Text-captured execution result plus the plan that produced it."""

    stdout: str
    stderr: str
    returncode: int
    plan: ExecutionPlan


def capture(template: object, /, **kwargs: object) -> CaptureResult:
    """Run with captured utf-8 stdout/stderr and return a CaptureResult."""
    kwargs["capture_output"] = True
    kwargs["text"] = True
    kwargs["encoding"] = "utf-8"
    completed = run(template, **kwargs)
    assert isinstance(completed.stdout, str)
    assert isinstance(completed.stderr, str)
    return CaptureResult(
        stdout=completed.stdout,
        stderr=completed.stderr,
        returncode=completed.returncode,
        plan=plan(template),
    )


def shx(template: object, /, **kwargs: object) -> subprocess.CompletedProcess[str]:
    """Execute a shell-routed template (pipes, redirections, globs).

    Interpolated values are POSIX shell-quoted automatically. The rendered line
    runs under /bin/sh -c. Raises ArgvOnlyError when the template has no shell
    metacharacters (use run() instead).
    """
    _validate_kwargs(kwargs)
    rendered = plan(template)
    if rendered.mode != "shell":
        raise ArgvOnlyError(
            "template contains no shell metacharacters; use run() instead"
        )
    assert rendered.shell_line is not None
    result = subprocess.run(
        ["/bin/sh", "-c", rendered.shell_line],
        **_pass_through(kwargs),
    )
    return cast("subprocess.CompletedProcess[str]", result)
