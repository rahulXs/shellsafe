"""The public surface is contractual: these names must exist and be importable."""

import shellsafe


def test_public_names_exist():
    for name in ("run", "capture", "shx", "plan", "RAW", "CaptureResult", "__version__"):
        assert hasattr(shellsafe, name), name


def test_all_is_exact():
    assert set(shellsafe.__all__) == {
        "run",
        "capture",
        "shx",
        "plan",
        "RAW",
        "CaptureResult",
        "__version__",
    }
