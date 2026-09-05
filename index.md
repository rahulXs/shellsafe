# Shell commands in Python just got safe

Python 3.14 shipped template strings last month. I built a library that uses them to make shell injection impossible. Here is what changed and why it matters.

## The one line that causes problems

Every Python developer has written this at some point:

```python
subprocess.run(f"git commit -m {message}", shell=True)
```

It works. It reads well. And it has a security problem that has been in the OWASP Top 10 for over ten years.

When `shell=True`, Python hands the entire string to `/bin/sh`. The shell parses it like a human typing a command. It does not know what was a variable and what was fixed text.

```python
message = "fix; rm -rf ~"
subprocess.run(f"git commit -m {message}", shell=True)
```

The shell sees this:

```
git commit -m fix; rm -rf ~
```

It runs two commands. The second one deletes your home directory.

Other inputs that break things:

```python
message = "`whoami`"           # backtick execution
message = "$(whoami)"          # dollar sign execution
message = "hello | cat /etc/passwd"  # pipe to read files
message = "hello && cat /etc/shadow" # logical operator
```

The f-string blends your value into the command with no boundary between them.

## Why the safe version never won

The safe version exists. Same length, one character different:

```python
subprocess.run(f"git commit -m {message}", shell=True)  # dangerous
subprocess.run(["git", "commit", "-m", message])         # safe
```

But the safe version breaks when you need pipes, redirections, or globs:

```python
# This does not work with list form:
subprocess.run(["cat", "file.log", "|", "grep", "error"], shell=False)
# The pipe is treated as a literal argument, not a shell operator

# So people write this instead:
subprocess.run("cat file.log | grep error", shell=True)
# Now you are back to injection risk
```

Developers choose between safety and features. Most choose features. That is why command injection is still everywhere.

## What Python 3.14 changed

Python 3.14 added template strings via PEP 750. The `t"..."` syntax gives you the fixed text and each value as separate pieces:

```python
# f-string: one blended string
f"git commit -m {message}"
# Result: "git commit -m fix; rm -rf ~"

# template string: separate pieces
t"git commit -m {message}"
# Result: Template with fixed text and message separately
```

This is a language-level change. Python now keeps your text and your values apart. A library can use that separation to guarantee values never become commands.

PEP 750 was approved in April 2025 and shipped in Python 3.14.

## PEP 787: the official fix that was deferred

PEP 787 proposed adding template string support to `subprocess` and `shlex`:

```python
# What PEP 787 would have added:
subprocess.run(t"cat {filename}", shell=True)
# subprocess would auto-quote values
```

PEP 787 was deferred in April 2025. The authors wanted to explore a more general approach that could handle non-POSIX shells. They built an experimental library called tstrprocess during the beta period.

PEP 787 is deferred to at least Python 3.15. Python 3.14 ships template strings but subprocess does not use them.

## How shellsafe works

shellsafe renders template strings into argument lists without invoking a shell.

```python
from shellsafe import run

message = "fix; rm -rf ~"
run(t"git commit -m {message}")
# builds: ["git", "commit", "-m", "fix; rm -rf ~"]
# one command, one argument, no shell
```

The `t"..."` syntax gives shellsafe the fixed text and the value separately. It builds an argv list. The semicolon, pipes, dollar signs, backticks, all of them are just characters inside one argument. The shell never sees them because no shell is involved.

### Pipes and redirections

When your template contains shell metacharacters like `|` or `>`, shellsafe uses `/bin/sh -c` on POSIX and quotes your values automatically:

```python
from shellsafe import shx

file = "access.log"
shx(t"cat {file} | grep 404 | wc -l")
# line: cat "access.log" | grep 404 | wc -l
# values are quoted with POSIX rules
```

On Windows, shellsafe refuses shell routes entirely. It would rather say no than pretend cmd.exe quoting is safe.

### See what would run

```python
from shellsafe import plan

message = "fix; rm -rf ~"
print(plan(t"git commit -m {message}"))
# argv: ["git", "commit", "-m", "fix; rm -rf ~"]
```

`plan()` shows you the argument list or shell line before anything executes.

### Get output

```python
from shellsafe import capture

res = capture(t"whoami")
print(res.stdout)
print(res.returncode)
```

### RAW for pre-trusted content

```python
from shellsafe import RAW

# you control the value, you vouch for it
safe_value = "hello world"
shx(t"echo {RAW(safe_value)}")
```

RAW is loud and uppercase on purpose. Code reviewers see it immediately.

## Injection payload corpus

shellsafe includes 15 injection payloads that are verified safe on every release:

```python
from shellsafe import plan

payloads = [
    "hello; rm -rf /",
    "`whoami`",
    "$(whoami)",
    "hello | cat /etc/passwd",
    "hello\nrm -rf /",
    "hello && cat /etc/shadow",
]

for p in payloads:
    print(f"payload: {p!r}")
    print(f"  plan:   {plan(t'echo {p}')}")
```

Output:

```
payload: 'hello; rm -rf /'
  plan:   argv: ["echo", "hello; rm -rf /"]
payload: '`whoami`'
  plan:   argv: ["echo", "`whoami`"]
payload: '$(whoami)'
  plan:   argv: ["echo", "$(whoami)"]
payload: 'hello | cat /etc/passwd'
  plan:   argv: ["echo", "hello | cat /etc/passwd"]
payload: 'hello\nrm -rf /'
  plan:   argv: ["echo", "hello\nrm -rf /"]
payload: 'hello && cat /etc/shadow'
  plan:   argv: ["echo", "hello && cat /etc/shadow"]
```

Every payload becomes one argument. No injection. No shell. No escape.

## Audit scanner

Already have code using f-strings in shell commands? The scanner finds them:

```bash
shellsafe audit src/
```

```
SEV       RULE    FILE                                      LINE  MESSAGE
------------------------------------------------------------------------------------------
ERROR     AU001   src/deploy.py                                12  os.system receives an f-string with interpolated value(s)
WARNING   AU002   src/deploy.py                                18  subprocess.run uses shell=True with variable
INFO      AU004   src/utils.py                                 25  subprocess.run has no timeout parameter
```

Filter by severity, get JSON output, suppress known-safe findings:

```bash
shellsafe audit src/ --severity error
shellsafe audit src/ --json
shellsafe audit src/ --ignore AU004
```

Suppress inline:

```python
# shellsafe: ignore AU001 reason: value is constant
os.system(f"echo {safe_value}")
```

## Why this is different from other tools

**bandit** and **semgrep** find dangerous patterns but cannot fix them. You still have to rewrite the code. shellsafe replaces the dangerous pattern with a safe one.

**plumbum** uses a different model: `cmd["ls"]["-la"]()`. You build commands from parts, not from templates. No template string support.

**xonsh** is a shell that feels like Python. Different goal: xonsh replaces bash, shellsafe is a library for running commands from Python scripts.

**subprocess list form** is safe for simple commands but breaks with pipes, redirections, and globs. shellsafe handles both cases.

## Install

```bash
pip install shellsafe
```

Requires Python 3.14 or newer.

## Links

- GitHub: https://github.com/rahulXs/shellsafe
- PyPI: https://pypi.org/project/shellsafe/
- PEP 750: https://peps.python.org/pep-0750/
- PEP 787: https://peps.python.org/pep-0787/
