"""AU003 fixture: planted violations and safe twins for command-string assembly."""

import os
import subprocess

# positive cases (should produce AU003 findings)

# variable passed to executor
cmd = "echo " + user_input
os.system(cmd)

# concatenation in call
os.system("echo " + user_input)

# .format() in call
os.system("echo {}".format(user_input))  # noqa: UP032

# f-string in call (also AU001)
os.system(f"echo {user_input}")

# variable with subprocess
subprocess.run(cmd)

# concatenation with subprocess
subprocess.run("echo " + user_input)


# safe cases (should NOT produce AU003 findings)

# list form (safe)
subprocess.run(["echo", user_input])

# static string
os.system("echo hello")

# argv list
subprocess.run(["git", "commit", "-m", "fix"])
