"""Audit scanner tests: AU001 rule detection against fixture corpus."""

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
    for f in findings:
        assert f.confidence == 0.95


def test_au001_severity():
    findings = scan([str(FIXTURES / "au001_sample.py")])
    for f in findings:
        assert f.severity == "error"


def test_scan_returns_sorted():
    findings = scan([str(FIXTURES / "au001_sample.py")])
    severities = [f.severity for f in findings]
    assert severities == ["error"] * len(findings)


def test_scan_empty_dir(tmp_path: Path):
    findings = scan([str(tmp_path)])
    assert findings == []


def test_scan_syntax_error_skipped(tmp_path: Path):
    bad = tmp_path / "bad.py"
    bad.write_text("def x(\n")
    findings = scan([str(tmp_path)])
    assert findings == []
