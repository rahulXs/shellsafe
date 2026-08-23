"""Subprocess wrappers over rendered ExecutionPlans."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Any, cast

from .errors import ArgvOnlyError, ShellSafeError
from .raw import Raw  # noqa: F401  (re-exported through the package root)
from .render import ExecutionPlan

_SHELL_MODE_PENDS = (
    "shell-mode execution arrives in shellsafe 0.2; "
    "this release covers argv-mode commands"
)

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
            "shellsafe never passes shell=True; use shx() on posix for pipes and "
            "redirections"
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


def run(template: object, /, **kwargs: object) -> subprocess.CompletedProcess[str]:
    """Render the template and execute it.

    Interpolated values always arrive as single argv elements. Keyword arguments
    pass through to subprocess.run with one exception: shell is rejected by
    design.
    """
    _validate_kwargs(kwargs)
    rendered = plan(template)
    if rendered.mode == "shell":
        raise ShellSafeError(_SHELL_MODE_PENDS)
    assert rendered.argv is not None
    # passthrough boundary: values are caller-owned subprocess kwargs
    typed_kwargs = cast(
        "dict[str, Any]",
        {k: v for k, v in kwargs.items() if k in _ALLOWED_KWARGS},
    )
    result = subprocess.run(rendered.argv, **typed_kwargs)
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


def shx(template: object, /, **kwargs: object) -> object:
    """Shell-route alias for templates that need pipes or redirections.

    Raises ArgvOnlyError when the template needs no shell at all, so a missing
    pipe is never silently ignored. Full shell execution ships in shellsafe 0.2;
    rendering and inspection work today via shellsafe.plan().
    """
    _validate_kwargs(kwargs)
    rendered = plan(template)
    if rendered.mode != "shell":
        raise ArgvOnlyError(
            "template contains no shell metacharacters; use run() instead"
        )
    raise ShellSafeError(_SHELL_MODE_PENDS)
