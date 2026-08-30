"""Audit scanner tests: AU001-AU004 rule detection against fixture corpus."""

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
    au001_lines = {f.lineno for f in findings if f.rule_id == "AU001"}
    for line in range(26, 33):
        assert line not in au001_lines, f"false positive on line {line}"


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
    non_errors = [s for s in severities if s != "error"]
    assert severities == errors + non_errors


def test_scan_empty_dir(tmp_path: Path):
    findings = scan([str(tmp_path)])
    assert findings == []


def test_scan_syntax_error_skipped(tmp_path: Path):
    bad = tmp_path / "bad.py"
    bad.write_text("def x(\n")
    findings = scan([str(tmp_path)])
    assert findings == []


def test_au003_detects_positive_cases():
    findings = scan([str(FIXTURES / "au003_sample.py")])
    au003 = [f for f in findings if f.rule_id == "AU003"]
    assert len(au003) == 6
    callees = {f.evidence["callee"] for f in au003}
    assert "os.system" in callees
    assert "subprocess.run" in callees


def test_au003_ignores_safe_cases():
    findings = scan([str(FIXTURES / "au003_sample.py")])
    au003_lines = {f.lineno for f in findings if f.rule_id == "AU003"}
    for line in range(32, 40):
        assert line not in au003_lines, f"false positive on line {line}"


def test_au003_severity():
    findings = scan([str(FIXTURES / "au003_sample.py")])
    au003 = [f for f in findings if f.rule_id == "AU003"]
    for f in au003:
        assert f.severity in ("warning", "error")


def test_au004_detects_positive_cases():
    findings = scan([str(FIXTURES / "au004_sample.py")])
    au004 = [f for f in findings if f.rule_id == "AU004"]
    assert len(au004) == 5
    callees = {f.evidence["callee"] for f in au004}
    assert "subprocess.run" in callees
    assert "subprocess.call" in callees
    assert "subprocess.check_call" in callees
    assert "subprocess.check_output" in callees


def test_au004_ignores_safe_cases():
    findings = scan([str(FIXTURES / "au004_sample.py")])
    au004_lines = {f.lineno for f in findings if f.rule_id == "AU004"}
    for line in range(21, 29):
        assert line not in au004_lines, f"false positive on line {line}"


def test_au004_severity():
    findings = scan([str(FIXTURES / "au004_sample.py")])
    au004 = [f for f in findings if f.rule_id == "AU004"]
    for f in au004:
        assert f.severity == "info"


def test_au004_confidence():
    findings = scan([str(FIXTURES / "au004_sample.py")])
    au004 = [f for f in findings if f.rule_id == "AU004"]
    for f in au004:
        assert f.confidence == 0.95


def test_all_rules_found():
    findings = scan([str(FIXTURES)])
    rule_ids = {f.rule_id for f in findings}
    assert "AU001" in rule_ids
    assert "AU002" in rule_ids
    assert "AU003" in rule_ids
    assert "AU004" in rule_ids
