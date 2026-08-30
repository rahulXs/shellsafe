"""AU002 fixture: planted violations and safe twins for shell=True rule."""

import subprocess

# --- positive cases (should produce AU002 findings) ---

# f-string with shell=True (also caught by AU001)
subprocess.run(f"echo {user_input}", shell=True)

# .format() with shell=True
subprocess.run("echo {}".format(name), shell=True)  # noqa: UP032

# string concatenation with shell=True
subprocess.run("echo " + name, shell=True)

# %-format with shell=True
subprocess.run("echo %s" % name, shell=True)  # noqa: UP031

# variable with shell=True
subprocess.run(cmd, shell=True)

# attribute with shell=True
subprocess.run(config.command, shell=True)


# --- safe cases (should NOT produce AU002 findings) ---

# shell=True with list (safe)
subprocess.run(["echo", user_input], shell=True)

# shell=True with static string (safe)
subprocess.run("echo hello", shell=True)

# no shell=True with f-string (AU001, not AU002)
subprocess.run(f"echo {user_input}")

# no shell=True with variable (safe)
subprocess.run(cmd)

# shell=False explicitly
subprocess.run("echo hello", shell=False)
