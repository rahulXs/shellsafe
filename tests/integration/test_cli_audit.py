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
    assert report["summary"]["errors"] == 6
    assert len(report["findings"]) == 6


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
