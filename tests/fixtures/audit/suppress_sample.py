"""Suppression test fixture: inline, file-level, multi-rule, AU010."""

import os
import subprocess

# Line-level suppression with reason

# shellsafe: ignore AU001 reason: tested, value is constant
os.system(f"echo {os.listdir('.')}")

# shellsafe: ignore AU001, AU002 reason: legacy code, tracked for migration
subprocess.run(f"echo {os.listdir('.')}", shell=True)

# Line-level suppression without reason (AU010 trigger)

# shellsafe: ignore AU004
subprocess.run(["ls"])

# No suppression (should still be flagged)

os.system(f"echo {os.listdir('.')}")

# Safe cases (should never be flagged regardless of suppression)

subprocess.run(["ls", "-la"])
subprocess.run(["echo", "hello"], timeout=5)
