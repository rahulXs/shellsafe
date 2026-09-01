"""Offline AST scanner for dangerous command construction.

Never imports from the scanned project. Reads code only.
"""

import ast
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class Finding:
    """One audit finding."""

    rule_id: str
    title: str
    severity: str
    confidence: float
    path: str
    lineno: int
    col: int
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)  # why: heterogeneous value types
    fix_hint: str = ""
    ignored: bool = False
    ignore_reason: str | None = None


_EXECUTORS = {
    "system": "os.system",
    "popen": "os.popen",
    "run": "subprocess.run",
    "call": "subprocess.call",
    "check_call": "subprocess.check_call",
    "check_output": "subprocess.check_output",
    "Popen": "subprocess.Popen",
    "getoutput": "subprocess.getoutput",
}

_IMPORT_ALIAS = {
    "os": "os",
    "subprocess": "subprocess",
}


def _resolve_callee(node: ast.expr, aliases: dict[str, str]):
    """Resolve a Call.func to an executor label like 'os.system'."""
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id in _IMPORT_ALIAS
    ):
        module = _IMPORT_ALIAS[node.value.id]
        if node.attr in _EXECUTORS:
            return f"{module}.{node.attr}"
    if isinstance(node, ast.Name):
        real = aliases.get(node.id, node.id)
        if real in _EXECUTORS:
            return _EXECUTORS[real]
        if "." in real:
            module, func = real.rsplit(".", 1)
            if func in _EXECUTORS:
                return f"{module}.{func}"
    return None


def au001(node: ast.Call, aliases: dict[str, str], path: str) -> Finding | None:
    """f-string passed to a shell-executing call."""
    callee = _resolve_callee(node.func, aliases)
    if callee is None:
        return None
    for arg in node.args:
        if isinstance(arg, ast.JoinedStr) and any(
            isinstance(v, ast.FormattedValue) for v in arg.values
        ):
            return Finding(
                rule_id="AU001",
                title="f-string passed to shell-executing call",
                severity="error",
                confidence=0.95,
                path=path,
                lineno=node.lineno,
                col=node.col_offset,
                message=f"{callee} receives an f-string with interpolated value(s)",
                evidence={
                    "callee": callee,
                    "interpolations": sum(
                        1 for v in arg.values if isinstance(v, ast.FormattedValue)
                    ),
                },
                fix_hint='use shellsafe.run(t"...") or pass an argv list',
            )
    return None


def _has_shell_true(node: ast.Call):
    for kw in node.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _is_dynamic_string(node: ast.expr):
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    return isinstance(node, (ast.Name, ast.Attribute))


def au002(node: ast.Call, aliases: dict[str, str], path: str) -> Finding | None:
    """shell=True with dynamic content in shell-executing call."""
    callee = _resolve_callee(node.func, aliases)
    if callee is None:
        return None
    if not _has_shell_true(node):
        return None
    for arg in node.args:
        if _is_dynamic_string(arg):
            kind = "f-string" if isinstance(arg, ast.JoinedStr) else "dynamic content"
            if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute):
                kind = ".format() call"
            elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                kind = "string concatenation"
            elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
                kind = "%-format string"
            elif isinstance(arg, (ast.Name, ast.Attribute)):
                kind = "variable"
            return Finding(
                rule_id="AU002",
                title="shell=True with dynamic content",
                severity="warning",
                confidence=0.90,
                path=path,
                lineno=node.lineno,
                col=node.col_offset,
                message=f"{callee} uses shell=True with {kind}",
                evidence={
                    "callee": callee,
                    "kind": kind,
                },
                fix_hint='use shellsafe.run(t"...") or pass an argv list without shell=True',
            )
    return None


def _track_dynamic_vars(tree: ast.Module):
    """Find variables assigned dynamic string expressions."""
    dynamic = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not _is_dynamic_string(node.value):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                dynamic.add(target.id)
    return dynamic


def au003(node: ast.Call, aliases: dict[str, str], path: str) -> Finding | None:
    """Command string built by assembly passed to shell executor."""
    callee = _resolve_callee(node.func, aliases)
    if callee is None:
        return None
    for arg in node.args:
        if isinstance(arg, ast.Name):
            return Finding(
                rule_id="AU003",
                title="command string passed to shell executor",
                severity="warning",
                confidence=0.80,
                path=path,
                lineno=node.lineno,
                col=node.col_offset,
                message=f"{callee} receives variable '{arg.id}' as command string",
                evidence={
                    "callee": callee,
                    "var": arg.id,
                },
                fix_hint='use shellsafe.run(t"...") or pass an argv list',
            )
        if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
            return Finding(
                rule_id="AU003",
                title="command string passed to shell executor",
                severity="warning",
                confidence=0.85,
                path=path,
                lineno=node.lineno,
                col=node.col_offset,
                message=f"{callee} receives concatenated string as command",
                evidence={
                    "callee": callee,
                    "kind": "concatenation",
                },
                fix_hint='use shellsafe.run(t"...") or pass an argv list',
            )
        if (
            isinstance(arg, ast.Call)
            and isinstance(arg.func, ast.Attribute)
            and arg.func.attr == "format"
        ):
            return Finding(
                rule_id="AU003",
                title="command string passed to shell executor",
                severity="warning",
                confidence=0.85,
                path=path,
                lineno=node.lineno,
                col=node.col_offset,
                message=f"{callee} receives .format() result as command string",
                evidence={
                    "callee": callee,
                    "kind": ".format()",
                },
                fix_hint='use shellsafe.run(t"...") or pass an argv list',
            )
        if (
            isinstance(arg, ast.JoinedStr)
            and any(isinstance(v, ast.FormattedValue) for v in arg.values)
        ):
            return Finding(
                rule_id="AU003",
                title="command string passed to shell executor",
                severity="error",
                confidence=0.95,
                path=path,
                lineno=node.lineno,
                col=node.col_offset,
                message=f"{callee} receives f-string as command string",
                evidence={
                    "callee": callee,
                    "kind": "f-string",
                },
                fix_hint='use shellsafe.run(t"...") or pass an argv list',
            )
    return None


def _has_timeout(node: ast.Call):
    return any(kw.arg == "timeout" for kw in node.keywords)


_EXECUTORS_WITH_TIMEOUT = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
}


def au004(node: ast.Call, aliases: dict[str, str], path: str) -> Finding | None:
    """Subprocess call without timeout."""
    callee = _resolve_callee(node.func, aliases)
    if callee is None:
        return None
    if callee not in _EXECUTORS_WITH_TIMEOUT:
        return None
    if _has_timeout(node):
        return None
    return Finding(
        rule_id="AU004",
        title="subprocess call without timeout",
        severity="info",
        confidence=0.95,
        path=path,
        lineno=node.lineno,
        col=node.col_offset,
        message=f"{callee} has no timeout parameter",
        evidence={
            "callee": callee,
        },
        fix_hint="add timeout= to prevent hanging",
    )


RULES = [
    ("AU001", au001),
    ("AU002", au002),
    ("AU003", au003),
    ("AU004", au004),
]


def _discover(paths: list[str]):
    files = []
    for raw in paths:
        p = Path(raw)
        if p.is_file() and p.suffix == ".py":
            files.append(p)
        elif p.is_dir():
            files.extend(
                f
                for f in sorted(p.rglob("*.py"))
                if not any(part.startswith(".") or part == "__pycache__" for part in f.parts)
            )
    return files


def _import_aliases(tree: ast.Module):
    """Map local names to real module.function for executor imports."""
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name
                aliases[local] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                local = alias.asname or alias.name
                aliases[local] = f"{module}.{alias.name}"
    return aliases


def _parse_suppression_comment(comment: str) -> tuple[list[str], str | None]:
    """Parse a shellsafe suppression comment.

    Returns (rule_ids, reason_or_None).
    Accepts: # shellsafe: ignore RULE[,RULE...] [reason: text]
    """
    stripped = comment.strip()
    if not stripped.startswith("#"):
        return [], None
    stripped = stripped[1:].strip()
    if not stripped.lower().startswith("shellsafe:"):
        return [], None
    directive = stripped[len("shellsafe:"):].strip()
    if not directive.lower().startswith("ignore "):
        return [], None
    rest = directive[len("ignore "):]
    reason = None
    reason_match = rest.split(" reason:", 1)
    if len(reason_match) == 2:
        rest = reason_match[0]
        reason = reason_match[1].strip() or None
    rule_ids = [r.strip().upper() for r in rest.split(",") if r.strip()]
    return rule_ids, reason


def _parse_suppressions(
    source_lines: list[str],
) -> tuple[set[int], dict[int, tuple[set[str], str | None]]]:
    """Parse source lines for suppression directives.

    Returns:
        file_level_rules: rule ids suppressed file-wide (from ignore-file)
        line_suppressions: line_no -> (set of rule ids, reason)
    """
    file_level_rules = set()
    line_suppressions = {}

    for i, line in enumerate(source_lines, 1):
        stripped = line.strip()
        if not stripped.startswith("#"):
            continue
        rule_ids, reason = _parse_suppression_comment(stripped)
        if not rule_ids:
            if stripped.lower() == "# shellsafe: ignore-file":
                file_level_rules.add("*")
            elif stripped.lower().startswith("# shellsafe: ignore-file "):
                for r in stripped.split(None, 4)[-1].split(","):
                    r = r.strip().upper()
                    if r:
                        file_level_rules.add(r)
            continue
        line_suppressions[i] = (set(rule_ids), reason)

    return file_level_rules, line_suppressions


def _find_suppressed_line(
    target_line: int,
    line_suppressions: dict[int, tuple[set[str], str | None]],
) -> tuple[set[str], str | None] | None:
    """Find which rules suppress findings at target_line.

    Checks previous non-blank, non-comment line, then target line itself.
    """
    for candidate in (target_line - 1, target_line):
        if candidate in line_suppressions:
            return line_suppressions[candidate]
    return None


def _apply_suppression(
    result: Finding,
    ignore: set[str] | None,
    file_rules: set[str],
    line_suppressions: dict[int, tuple[set[str], str | None]],
) -> Finding:
    """Apply suppression rules to a finding. Returns new Finding with ignored flag."""
    rule_id = result.rule_id
    suppressed = False
    ignore_reason = None

    if ignore and rule_id in ignore:
        return Finding(
            rule_id=result.rule_id,
            title=result.title,
            severity=result.severity,
            confidence=result.confidence,
            path=result.path,
            lineno=result.lineno,
            col=result.col,
            message=result.message,
            evidence=result.evidence,
            fix_hint=result.fix_hint,
            ignored=True,
            ignore_reason="CLI --ignore",
        )
    if rule_id in file_rules or "*" in file_rules:
        suppressed = True
        ignore_reason = "file-level suppression"
    else:
        match = _find_suppressed_line(result.lineno, line_suppressions)
        if match:
            rules, reason = match
            if rule_id in rules:
                suppressed = True
                ignore_reason = reason

    if not suppressed:
        return result
    return Finding(
        rule_id=result.rule_id,
        title=result.title,
        severity=result.severity,
        confidence=result.confidence,
        path=result.path,
        lineno=result.lineno,
        col=result.col,
        message=result.message,
        evidence=result.evidence,
        fix_hint=result.fix_hint,
        ignored=True,
        ignore_reason=ignore_reason,
    )


def _emit_au010(
    line_suppressions: dict[int, tuple[set[str], str | None]],
    rel: str,
) -> list[Finding]:
    """Emit AU010 warnings for suppression comments without reasons."""
    results = []
    for suppressed_rules, reason in line_suppressions.values():
        if not reason and suppressed_rules:
            first_line = next(
                (ln for ln, (r, _) in line_suppressions.items() if r == suppressed_rules),
                1,
            )
            results.append(
                Finding(
                    rule_id="AU010",
                    title="suppression comment without reason",
                    severity="info",
                    confidence=1.0,
                    path=rel,
                    lineno=first_line,
                    col=0,
                    message=(
                        f"Suppression for {', '.join(sorted(suppressed_rules))} "
                        f"has no reason. Add: reason: <why>"
                    ),
                    evidence={"rules": sorted(suppressed_rules)},
                )
            )
    return results


def scan(paths: list[str], ignore: set[str] | None = None) -> list[Finding]:
    """Scan Python files for audit findings.

    Args:
        paths: files or directories to scan.
        ignore: rule ids to suppress from CLI --ignore flag.
    """
    findings = []
    for path in _discover(paths):
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
        except (SyntaxError, UnicodeDecodeError):
            continue
        aliases = _import_aliases(tree)
        source_lines = source.splitlines()
        file_rules, line_suppressions = _parse_suppressions(source_lines)
        rel = str(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for _, rule in RULES:
                    result = rule(node, aliases, rel)
                    if result is not None:
                        findings.append(
                            _apply_suppression(result, ignore, file_rules, line_suppressions)
                        )
        findings.extend(_emit_au010(line_suppressions, rel))

    findings.sort(key=lambda f: (f.severity != "error", f.path, f.lineno))
    return findings


_COLORS = {
    "error": "\033[31m",
    "warning": "\033[33m",
    "info": "\033[36m",
    "ignored": "\033[90m",
    "reset": "\033[0m",
}


def _color(text: str, severity: str):
    c = _COLORS.get(severity, "")
    return f"{c}{text}{_COLORS['reset']}" if c else text


def report_terminal(findings: list[Finding], show_ignored: bool = False) -> str:
    """Render findings as a terminal table."""
    if not findings:
        return "no findings"
    use_color = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
    visible = findings if show_ignored else [f for f in findings if not f.ignored]
    if not visible:
        return "no findings"
    suppressed = sum(1 for f in findings if f.ignored)
    lines = [
        f"{'SEV':<9} {'RULE':<7} {'FILE':<40} {'LINE':>5}  MESSAGE",
        "-" * 90,
    ]
    for f in visible:
        if f.ignored:
            sev = _color("IGNORED", "ignored") if use_color else "IGNORED"
        else:
            sev = _color(f.severity.upper(), f.severity) if use_color else f.severity.upper()
        path = f.path if len(f.path) <= 40 else "..." + f.path[-37:]
        reason = f" [{f.ignore_reason}]" if f.ignore_reason else ""
        lines.append(f"{sev:<18} {f.rule_id:<7} {path:<40} {f.lineno:>5}  {f.message}{reason}")
    if suppressed and not show_ignored:
        lines.append(f"\n  {suppressed} finding(s) suppressed (use --show-ignored to display)")
    return "\n".join(lines)


def report_json(report: dict[str, object]) -> str:
    """Render the full report as JSON."""
    return json.dumps(report, indent=2)


def scan_report(paths: list[str], ignore: set[str] | None = None) -> dict[str, object]:
    """Scan and return a report dict matching schema v1."""
    start = time.monotonic()
    findings = scan(paths, ignore=ignore)
    duration_ms = round((time.monotonic() - start) * 1000, 1)

    errors = sum(1 for f in findings if f.severity == "error" and not f.ignored)
    warnings = sum(1 for f in findings if f.severity == "warning" and not f.ignored)
    info = sum(1 for f in findings if f.severity == "info" and not f.ignored)
    ignored = sum(1 for f in findings if f.ignored)

    from .._version import __version__

    return {
        "schema_version": 1,
        "tool": {"name": "shellsafe", "version": __version__},
        "run": {
            "duration_ms": duration_ms,
            "host_python": f"{sys.version_info.major}.{sys.version_info.minor}"
            f".{sys.version_info.micro}",
            "paths": paths,
        },
        "summary": {
            "errors": errors,
            "warnings": warnings,
            "info": info,
            "ignored": ignored,
            "verdict": "fail" if errors > 0 else "pass",
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "confidence": f.confidence,
                "path": f.path,
                "lineno": f.lineno,
                "col": f.col,
                "message": f.message,
                "evidence": f.evidence,
                "fix_hint": f.fix_hint,
                "ignored": f.ignored,
                "ignore_reason": f.ignore_reason,
            }
            for f in findings
        ],
    }
