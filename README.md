# shellsafe

> Run shell commands safely using Python 3.14 template strings. Values can never
> turn into commands.

```python
from shellsafe import run

message = get_user_input()          # "fix; rm -rf ~"
run(t"git commit -m {message}")
# argv: ["git", "commit", "-m", "fix; rm -rf ~"]
# one command; the scary text is just an argument
```

## Why this package exists

Python 3.14 added template strings (PEP 750). Now Python keeps your fixed text
and your values separate at the language level.

Shell commands are the first place people want to use this. That is because
f-strings inside shell commands have caused real security bugs for ten years:

```python
subprocess.run(f"git commit -m {message}", shell=True)
# if message = "fix; rm -rf ~"  ->  two commands run. The second one is bad.
```

Python planned to solve this officially (PEP 787), but that plan was postponed.
So today there is no standard way to run shell commands safely with templates.
This package fills that gap.

## Install

```bash
pip install shellsafe
```

Needs Python 3.14 or newer.

## How to use

Run a command. Your values always stay one argument each:

```python
from shellsafe import run

run(t"mkdir {path}")
run(t"docker build -t {tag} .", check=True, timeout=300)
```

Get the output as text:

```python
from shellsafe import capture

res = capture(t"grep {pattern} {file}")
print(res.stdout, res.returncode)
```

Need pipes? Works on Linux and macOS. Your values are quoted safely first:

```python
from shellsafe import shx

shx(t"cat {file} | wc -l")
```

Want to see exactly what will run?

```python
from shellsafe import plan

print(plan(t"git commit -m {message}"))
# argv: ["git","commit","-m","fix; rm -rf ~"]
```

## Safety rules

| Case | What happens |
|---|---|
| Any value you pass | becomes one argument, exactly as given |
| Value used as the program name | error: program names must be written as fixed text |
| Shell features on Windows | error: we cannot make Windows safe this way, so we say no |
| RAW() misuse | error: one value only, used as-is, no nesting |

`RAW(...)` marks content you have already made safe by hand. It is loud and easy
to find in code review, so trust is never hidden.

## Find old dangerous patterns

Already have code using f-strings in shell commands? The scanner finds them:

```bash
shellsafe audit src/
```

It detects f-strings passed to `os.system`, `subprocess.run(shell=True)`, and
other shell executors. Get machine-readable output:

```bash
shellsafe audit src/ --json
```

Filter by severity:

```bash
shellsafe audit src/ --severity warning
```

## Limits

- Shell features (pipes, redirections) work on Linux and macOS only. Windows
  supports plain commands only.
- `run()` refuses templates that contain shell metacharacters. Use `shx()` for
  those.
- Byte values are rejected. Decode them first.
- We keep your command safe to build and run. Testing what your command does is
  still your job.

## Needs

- Python 3.14 or newer
- Linux, macOS, Windows (pipes work on Linux and macOS only)

## More

- Source and issues: [github.com/rahulXs/shellsafe](https://github.com/rahulXs/shellsafe)
- Want to help? See CONTRIBUTING.md in the repository.

License: MIT
