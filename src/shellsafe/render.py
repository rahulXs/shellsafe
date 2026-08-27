"""Template rendering: t-string in, ExecutionPlan out. Pure and deterministic.

Security invariants (property-tested, see docs/07_rendering_engine_spec.md):
- INV-1: every interpolation contributes exactly one argv element equal to its
  resolved string.
- INV-2: the executable comes from static template text only.
- INV-3: element count equals static words plus interpolations plus RAW splices.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from string.templatelib import Interpolation, Template

from .errors import RawUsageError, ShellSafeTypeError
from .platforms import route_for
from .raw import Raw

_NUL = "\x00"


@dataclass(frozen=True, slots=True)
class ExecutionPlan:
    """The exact thing that will execute. Inspect via repr before running."""

    mode: str  # "argv" or "shell"
    argv: tuple[str, ...] | None = None
    shell_line: str | None = None

    def __repr__(self) -> str:
        if self.mode == "argv":
            assert self.argv is not None
            body = ",".join(repr(a) for a in self.argv)
            return f"argv: [{body}]"
        assert self.shell_line is not None
        return f"shell: {self.shell_line}"


Segment = str | Interpolation[str] | Raw


def _walk(
    template: Template, seen: frozenset[int]
) -> list[Segment]:
    """Flatten a template into an ordered list of static text and interpolations.

    Nested templates (a t-string interpolated inside a t-string) splice their
    segments at the interpolation position. Cycle-guarded via object ids.
    """
    parts: list[Segment] = []
    for element in template:
        if isinstance(element, str):
            parts.append(element)
        elif isinstance(element, Interpolation):
            if isinstance(element.value, Raw):
                parts.append(Raw(element.value.value))
            elif isinstance(element.value, Template):
                if id(element.value) in seen:
                    raise ShellSafeTypeError("template references itself")
                parts.extend(_walk(element.value, seen | {id(element.value)}))
            else:
                parts.append(element)
        else:
            raise ShellSafeTypeError(
                f"unexpected template element {type(element).__name__}"
            )
    return parts


def _resolve(interpolation: Interpolation[str]) -> str:
    """Resolve one interpolation exactly as an f-string would."""
    value = interpolation.value
    if isinstance(value, (bytes, bytearray)):
        raise ShellSafeTypeError(
            "bytes interpolation is ambiguous; decode it explicitly first"
        )
    conversion = interpolation.conversion
    format_spec = interpolation.format_spec

    converted: object
    if conversion is None:
        converted = value
    elif conversion == "r":
        converted = repr(value)
    elif conversion == "s":
        converted = str(value)
    elif conversion == "a":
        converted = ascii(value)
    else:
        raise ShellSafeTypeError(
            f"unsupported conversion {conversion!r}; expected 'r', 's', 'a', or None"
        )

    if format_spec:
        return format(converted, format_spec)
    if conversion is None:
        return str(converted)
    assert isinstance(converted, str)
    return converted


def _reject_nul(resolved: str) -> None:
    if _NUL in resolved:
        raise ShellSafeTypeError(
            "interpolated value contains a NUL byte after formatting; "
            "executables cannot receive NUL bytes"
        )


def plan(template: object) -> ExecutionPlan:
    """Render a t-string into an inspectable ExecutionPlan."""
    if not isinstance(template, Template):
        raise ShellSafeTypeError(
            f"expected a t-string template, got {type(template).__name__}"
        )

    parts = _walk(template, frozenset({id(template)}))
    route = route_for("".join(p for p in parts if isinstance(p, str)))

    if route == "argv":
        return _render_argv(parts)
    return _render_shell(parts)


def _render_argv(parts: list[Segment]) -> ExecutionPlan:
    argv: list[str] = []
    origins: list[str] = []

    for part in parts:
        if isinstance(part, str):
            for word in part.split():
                argv.append(word)
                origins.append("static")
        elif isinstance(part, Raw):
            raw_value = part.value
            if not isinstance(raw_value, list):
                raise RawUsageError(
                    "RAW str values are only valid in shell mode; "
                    "in argv mode pass RAW(['one', 'argv', 'element'])"
                )
            for element in raw_value:
                if not isinstance(element, str):
                    raise RawUsageError(
                        "RAW lists in argv mode contain strings only; got "
                        f"{type(element).__name__}"
                    )
                _reject_nul(element)
                argv.append(element)
                origins.append("raw")
        else:
            resolved = _resolve(part)
            _reject_nul(resolved)
            argv.append(resolved)
            origins.append("interpolation")

    if not argv:
        raise ShellSafeTypeError("empty command")

    if origins[0] != "static":
        raise ShellSafeTypeError(
            "the executable must come from static template text; "
            "interpolate arguments instead of commands"
        )

    return ExecutionPlan(mode="argv", argv=tuple(argv))


def _render_shell(parts: list[Segment]) -> ExecutionPlan:
    line_parts: list[str] = []
    for part in parts:
        if isinstance(part, str):
            line_parts.append(part)
        elif isinstance(part, Raw):
            raw_value = part.value
            if not isinstance(raw_value, str):
                raise RawUsageError(
                    "RAW list values are only valid in argv mode; "
                    "in shell mode pass a single string"
                )
            _reject_nul(raw_value)
            line_parts.append(raw_value)
        else:
            resolved = _resolve(part)
            _reject_nul(resolved)
            line_parts.append(shlex.quote(resolved))
    line = "".join(line_parts).strip()
    if not line:
        raise ShellSafeTypeError("empty command")
    return ExecutionPlan(mode="shell", shell_line=line)
