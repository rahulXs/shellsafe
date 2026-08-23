"""Side-by-side demo: the classic injection, rendered inert.

Run from an environment where shellsafe is importable:

    python examples/demo.py
"""

import sys
from pathlib import Path
from string.templatelib import Interpolation, Template

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from shellsafe.render import plan


def main() -> int:
    message = "fix; rm -rf ~"

    print("UNSAFE (f-string into a shell):")
    print(f"  $ git commit -m {message}")
    print("  -> two commands; the second one deletes your home directory")
    print()

    print("SAFE (shellsafe):")
    p = plan(Template("git commit -m ", Interpolation(message, "message", None, "")))
    print(f"  $ {p!r}")
    print("  -> one command; the scary text is just an argument")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
