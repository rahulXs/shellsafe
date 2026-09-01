"""AU001 fixture: planted violations and safe twins for the f-string rule."""

import os
import subprocess
from os import system
from subprocess import run as subprocess_run

# positive cases (should produce AU001 findings)

os.system(f"echo {user_input}")

subprocess.run(f"echo {user_input}", shell=True)

subprocess.call(f"cat {filename}")

system(f"rm -rf {path}")

subprocess_run(f"grep {pattern} {file}")

subprocess.getoutput(f"echo {user_input}")


# safe cases (should NOT produce findings)

subprocess.run(["echo", user_input])

os.system("echo hello")

subprocess.run(["cat", filename], shell=True)

subprocess.run("echo hello")
