# Shell commands in Python just got safe

Python 3.14 shipped in October 2025 with template strings (PEP 750). I built a library that uses them to make shell injection impossible.

[PyPI](https://pypi.org/project/shellsafe/) | [GitHub](https://github.com/rahulXs/shellsafe)

## The problem

One line. Every Python developer has written it:

```python
subprocess.run(f"git commit -m {message}", shell=True)
```

When `shell=True`, Python hands the entire string to `/bin/sh`. The shell parses it like a human typing a command. It does not know what was a variable and what was fixed text.

```python
message = "fix; rm -rf ~"
subprocess.run(f"git commit -m {message}", shell=True)
```

The shell sees:

```
git commit -m fix; rm -rf ~
```

Two commands run. The second one deletes your home directory.

Other inputs that work the same way:

```python
message = "`whoami`"                  # backtick execution
message = "$(whoami)"                 # dollar sign execution
message = "hello | cat /etc/passwd"   # pipe to read files
message = "hello && cat /etc/shadow"  # logical operator
```

The f-string blends your value into the command string with no boundary between them.

## Why the safe version never won

The safe version exists. One character different:

```python
subprocess.run(f"git commit -m {message}", shell=True)  # dangerous
subprocess.run(["git", "commit", "-m", message])         # safe
```

But list form breaks the moment you need pipes or redirections:

```python
# The pipe is treated as a literal argument, not a shell operator
subprocess.run(["cat", "file.log", "|", "grep", "error"], shell=False)

# So people write this instead:
subprocess.run("cat file.log | grep error", shell=True)
# Back to injection risk
```

Developers choose between safety and features. Most choose features. Command injection has been in the OWASP Top 10 for over ten years because of this tradeoff.

## What Python 3.14 changed

Template strings (`t"..."`) give you the fixed text and each interpolated value as separate pieces:

```python
# f-string: one blended string
f"git commit -m {message}"
# Result: "git commit -m fix; rm -rf ~"

# template string: separate pieces
t"git commit -m {message}"
# Result: Template with fixed text and message as distinct values
```

This is a language-level change. Python now keeps your text and your values apart. PEP 750 was approved in April 2025 and shipped in Python 3.14.

## PEP 787: the official fix that was deferred

PEP 787 proposed adding template string support to `subprocess` and `shlex`. The idea: let subprocess handle the rendering so you get safe commands with zero extra code.

```python
# What PEP 787 would have added:
subprocess.run(t"cat {filename}", shell=True)
```

PEP 787 was deferred in April 2025. The authors wanted to explore a more general approach that could handle non-POSIX shells (cmd.exe, PowerShell). They built an experimental library called tstrprocess during the beta period to test ideas.

The PEP is deferred to at least Python 3.15. Python 3.14 ships template strings but subprocess does not use them. That is the gap shellsafe fills.

## How shellsafe works

shellsafe renders template strings into argument lists without invoking a shell. Switch `f` to `t`, values never become commands:

```python
from shellsafe import run

message = "fix; rm -rf ~"
run(t"git commit -m {message}")
# builds: ["git", "commit", "-m", "fix; rm -rf ~"]
```

The semicolon, pipes, dollar signs, backticks, all of them are just characters inside one argument. No shell is involved, so there is nothing to interpret.

### Two execution modes

**argv mode** (default): No shell. Values become arguments. Works on all platforms.

```python
from shellsafe import run

run(t"mkdir {path}")
run(t"docker build -t {tag} .", check=True, timeout=300)
```

**shell mode**: Uses `/bin/sh -c` on POSIX. Your values are quoted automatically. Refused on Windows.

```python
from shellsafe import shx

shx(t"cat {file} | grep 404 | wc -l")
# line: cat "access.log" | grep 404 | wc -l
```

shellsafe decides which mode to use based on whether your template contains shell metacharacters. You do not choose.

### Inspect before executing

```python
from shellsafe import plan

message = "fix; rm -rf ~"
print(plan(t"git commit -m {message}"))
# argv: ["git", "commit", "-m", "fix; rm -rf ~"]
```

`plan()` shows you the argument list or shell line before anything runs. Use it for debugging or code review.

### Capture output

```python
from shellsafe import capture

res = capture(t"whoami")
print(res.stdout)       # rahul
print(res.returncode)   # 0
```

Works the same way as `run()`, but gives you stdout, stderr, and return code.

### RAW for pre-trusted content

```python
from shellsafe import RAW

safe_value = "hello world"
shx(t"echo {RAW(safe_value)}")
```

RAW marks content you have already made safe. It inserts the value verbatim into the shell line. Uppercase on purpose, easy to find in code review.

## Injection payload corpus

shellsafe includes 15 injection payloads verified safe on every release:

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

Every payload becomes one argument. The injection text is inert.

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

Five rules: AU001 (f-string in shell executor), AU002 (shell=True with dynamic content), AU003 (command string assembly), AU004 (missing timeout), AU010 (suppression without reason).

```bash
shellsafe audit src/ --severity error   # filter by severity
shellsafe audit src/ --json             # machine-readable output
shellsafe audit src/ --ignore AU004     # suppress from CLI
```

Suppress inline when a finding is known-safe:

```python
# shellsafe: ignore AU001 reason: value is constant
os.system(f"echo {safe_value}")
```

## How it compares

| Tool | What it does | What shellsafe adds |
|---|---|---|
| subprocess list form | Safe for simple commands | Handles pipes, redirections, globs |
| bandit / semgrep | Find dangerous patterns | Replaces the pattern with a safe one |
| plumbum | Build commands from parts | Template-based, same syntax as f-strings |
| xonsh | Shell that feels like Python | Library for running commands from scripts |
| PEP 787 (future) | Stdlib subprocess with templates | Available now on Python 3.14 |

## Install

```bash
pip install shellsafe
```

Requires Python 3.14 or newer. Zero runtime dependencies.

## Links

- [PyPI](https://pypi.org/project/shellsafe/)
- [GitHub](https://github.com/rahulXs/shellsafe)
- [PEP 750](https://peps.python.org/pep-0750/)
- [PEP 787](https://peps.python.org/pep-0787/)
