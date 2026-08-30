"""Audit scanner tests: AU001 and AU002 rule detection against fixture corpus."""

from pathlib import Path

from shellsafe.audit.scanner import scan

FIXTURES = Path(__file__).parent.parent / "fixtures" / "audit"


def test_au001_detects_positive_cases():
    findings = scan([str(FIXTURES / "au001_sample.py")])
    au001 = [f for f in findings if f.rule_id == "AU001"]
    assert len(au001) == 6
    callees = {f.evidence["callee"] for f in au001}
    assert "os.system" in callees
    assert "subprocess.run" in callees
    assert "subprocess.call" in callees
    assert "subprocess.getoutput" in callees


def test_au001_ignores_safe_cases():
    findings = scan([str(FIXTURES / "au001_sample.py")])
    flagged_lines = {f.lineno for f in findings}
    # safe cases are on lines 26-32; none should appear
    for line in range(26, 33):
        assert line not in flagged_lines, f"false positive on line {line}"


def test_au001_confidence():
    findings = scan([str(FIXTURES / "au001_sample.py")])
    au001 = [f for f in findings if f.rule_id == "AU001"]
    for f in au001:
        assert f.confidence == 0.95


def test_au001_severity():
    findings = scan([str(FIXTURES / "au001_sample.py")])
    au001 = [f for f in findings if f.rule_id == "AU001"]
    for f in au001:
        assert f.severity == "error"


def test_au002_detects_positive_cases():
    findings = scan([str(FIXTURES / "au002_sample.py")])
    au002 = [f for f in findings if f.rule_id == "AU002"]
    assert len(au002) == 6
    kinds = {f.evidence["kind"] for f in au002}
    assert "f-string" in kinds
    assert ".format() call" in kinds
    assert "string concatenation" in kinds
    assert "%-format string" in kinds
    assert "variable" in kinds


def test_au002_ignores_safe_cases():
    findings = scan([str(FIXTURES / "au002_sample.py")])
    au002_lines = {f.lineno for f in findings if f.rule_id == "AU002"}
    # safe cases are on lines 28-38; none should appear
    for line in range(28, 39):
        assert line not in au002_lines, f"false positive on line {line}"


def test_au002_confidence():
    findings = scan([str(FIXTURES / "au002_sample.py")])
    au002 = [f for f in findings if f.rule_id == "AU002"]
    for f in au002:
        assert f.confidence == 0.90


def test_au002_severity():
    findings = scan([str(FIXTURES / "au002_sample.py")])
    au002 = [f for f in findings if f.rule_id == "AU002"]
    for f in au002:
        assert f.severity == "warning"


def test_au002_does_not_flag_au001_cases():
    findings = scan([str(FIXTURES / "au001_sample.py")])
    au002 = [f for f in findings if f.rule_id == "AU002"]
    # line 12 has shell=True with f-string, AU002 correctly flags it too
    # but lines without shell=True should not be flagged
    au002_lines = {f.lineno for f in au002}
    assert 12 in au002_lines
    assert len(au002) == 1


def test_scan_returns_sorted():
    findings = scan([str(FIXTURES / "au002_sample.py")])
    severities = [f.severity for f in findings]
    errors = [s for s in severities if s == "error"]
    warnings = [s for s in severities if s == "warning"]
    assert errors + warnings == severities


def test_scan_empty_dir(tmp_path: Path):
    findings = scan([str(tmp_path)])
    assert findings == []


def test_scan_syntax_error_skipped(tmp_path: Path):
    bad = tmp_path / "bad.py"
    bad.write_text("def x(\n")
    findings = scan([str(tmp_path)])
    assert findings == []
