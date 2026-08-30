"""CLI integration tests for the audit command."""

import json
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).parent.parent / "fixtures" / "audit"


def test_audit_cli_finds_issues():
    out = subprocess.run(
        [sys.executable, "-m", "shellsafe", "audit", str(FIXTURES / "au001_sample.py")],
        capture_output=True,
        text=True,
    )
    assert out.returncode == 1
    assert "AU001" in out.stdout


def test_audit_cli_clean_dir(tmp_path: Path):
    out = subprocess.run(
        [sys.executable, "-m", "shellsafe", "audit", str(tmp_path)],
        capture_output=True,
        text=True,
    )
    assert out.returncode == 0
    assert "no findings" in out.stdout


def test_audit_cli_json_output():
    out = subprocess.run(
        [
            sys.executable,
            "-m",
            "shellsafe",
            "audit",
            str(FIXTURES / "au001_sample.py"),
            "--json",
        ],
        capture_output=True,
        text=True,
    )
    assert out.returncode == 1
    report = json.loads(out.stdout)
    assert report["schema_version"] == 1
    au001_findings = [f for f in report["findings"] if f["rule_id"] == "AU001"]
    assert len(au001_findings) == 6
    assert report["summary"]["errors"] >= 6


def test_audit_cli_severity_filter():
    out = subprocess.run(
        [
            sys.executable,
            "-m",
            "shellsafe",
            "audit",
            str(FIXTURES / "au001_sample.py"),
            "--severity",
            "info",
        ],
        capture_output=True,
        text=True,
    )
    assert out.returncode == 1
    assert "AU001" in out.stdout


def test_audit_cli_au002_finds_issues():
    out = subprocess.run(
        [sys.executable, "-m", "shellsafe", "audit", str(FIXTURES / "au002_sample.py")],
        capture_output=True,
        text=True,
    )
    assert out.returncode == 1
    assert "AU002" in out.stdout


def test_audit_cli_au002_json_output():
    out = subprocess.run(
        [
            sys.executable,
            "-m",
            "shellsafe",
            "audit",
            str(FIXTURES / "au002_sample.py"),
            "--json",
        ],
        capture_output=True,
        text=True,
    )
    assert out.returncode == 1
    report = json.loads(out.stdout)
    au002_findings = [f for f in report["findings"] if f["rule_id"] == "AU002"]
    assert len(au002_findings) == 6
    assert report["summary"]["warnings"] >= 6


def test_audit_cli_au002_severity_filter():
    out = subprocess.run(
        [
            sys.executable,
            "-m",
            "shellsafe",
            "audit",
            str(FIXTURES / "au002_sample.py"),
            "--severity",
            "error",
        ],
        capture_output=True,
        text=True,
    )
    # au002_sample.py has an f-string with shell=True (line 12) caught by AU001
    # but AU002 warnings should be excluded
    assert "AU002" not in out.stdout


def test_audit_cli_both_rules():
    out = subprocess.run(
        [
            sys.executable,
            "-m",
            "shellsafe",
            "audit",
            str(FIXTURES),
            "--json",
        ],
        capture_output=True,
        text=True,
    )
    assert out.returncode == 1
    report = json.loads(out.stdout)
    rule_ids = {f["rule_id"] for f in report["findings"]}
    assert "AU001" in rule_ids
    assert "AU002" in rule_ids


def test_audit_cli_au003_finds_issues():
    out = subprocess.run(
        [sys.executable, "-m", "shellsafe", "audit", str(FIXTURES / "au003_sample.py")],
        capture_output=True,
        text=True,
    )
    assert out.returncode == 1
    assert "AU003" in out.stdout


def test_audit_cli_au004_finds_issues():
    out = subprocess.run(
        [
            sys.executable,
            "-m",
            "shellsafe",
            "audit",
            str(FIXTURES / "au004_sample.py"),
            "--severity",
            "info",
        ],
        capture_output=True,
        text=True,
    )
    # AU004 is info severity, exit code 0 (no errors)
    assert "AU004" in out.stdout
    assert "subprocess.run has no timeout" in out.stdout


def test_audit_cli_au004_severity_filter():
    out = subprocess.run(
        [
            sys.executable,
            "-m",
            "shellsafe",
            "audit",
            str(FIXTURES / "au004_sample.py"),
            "--severity",
            "warning",
        ],
        capture_output=True,
        text=True,
    )
    # AU004 is info severity, should be excluded when filtering by warning
    assert "AU004" not in out.stdout


def test_audit_cli_all_rules():
    out = subprocess.run(
        [
            sys.executable,
            "-m",
            "shellsafe",
            "audit",
            str(FIXTURES),
            "--json",
        ],
        capture_output=True,
        text=True,
    )
    assert out.returncode == 1
    report = json.loads(out.stdout)
    rule_ids = {f["rule_id"] for f in report["findings"]}
    assert "AU001" in rule_ids
    assert "AU002" in rule_ids
    assert "AU003" in rule_ids
    assert "AU004" in rule_ids
