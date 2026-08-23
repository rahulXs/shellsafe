import subprocess
import sys


def test_version_flag():
    out = subprocess.run(
        [sys.executable, "-m", "shellsafe", "--version"],
        capture_output=True, text=True,
    )
    assert out.returncode == 0
    assert out.stdout.startswith("shellsafe ")
