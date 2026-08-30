"""AU004 fixture: planted violations and safe twins for missing timeout."""

import subprocess
from subprocess import run as subprocess_run

# --- positive cases (should produce AU004 findings) ---

subprocess.run(["echo", "hello"])

subprocess.call(["echo", "hello"])

subprocess.check_call(["echo", "hello"])

subprocess.check_output(["echo", "hello"])

subprocess_run(["echo", "hello"])


# --- safe cases (should NOT produce AU004 findings) ---

subprocess.run(["echo", "hello"], timeout=10)

subprocess.call(["echo", "hello"], timeout=5)

subprocess.check_output(["echo", "hello"], timeout=30)

# Popen does not have timeout in the same way
subprocess.Popen(["echo", "hello"])
