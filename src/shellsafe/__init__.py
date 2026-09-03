"""shellsafe: safe shell commands via Python 3.14 template strings.

Public surface (stable names, additive only through 1.0):
run, capture, shx, plan, RAW, CaptureResult.
"""

from ._version import __version__
from .execute import CaptureResult, capture, plan, run, shx
from .raw import RAW

__all__ = [
    "RAW",
    "CaptureResult",
    "__version__",
    "capture",
    "plan",
    "run",
    "shx",
]
