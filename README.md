# shellsafe

> Safe shell commands via Python 3.14 template strings. Injection-proof by
> construction.

```python
from shellsafe import run

message = get_user_input()          # "fix; rm -rf ~"
run(t"git commit -m {message}")
# argv: ["git", "commit", "-m", "fix; rm -rf ~"]
# one command; the scary text is just an argument
```

## Why

The dominant pattern in scripts and automation is still this:

```python
subprocess.run(f"git commit -m {message}", shell=True)   # injection waiting to happen
```

Python 3.14 template strings (`t"..."`) separate static text from interpolated
values. shellsafe turns that structure into argv lists where interpolated values
are always data, never commands. When you genuinely need pipes, shell mode quotes
every value with POSIX rules first.

## Install

```bash
pip install shellsafe
```

Requires Python 3.14+ (template strings).

## Usage

Run a command. Interpolated values are always single arguments:

```python
from shellsafe import run

run(t"mkdir {path}")
run(t"docker build -t {tag} .", check=True, timeout=300)
```

Capture output as text:

```python
from shellsafe import capture

res = capture(t"grep {pattern} {file}")
print(res.stdout, res.returncode)
```

Pipes and redirections on POSIX (values are quoted with `shlex.quote` first):

```python
from shellsafe import shx

shx(t"cat {file} | wc -l")
```

Inspect exactly what will execute:

```python
from shellsafe import plan  # lower-level: render without running

print(plan(t"git commit -m {message}"))
# argv: ["git","commit","-m","fix; rm -rf ~"]
```

## What it refuses

| Case | Behavior |
|---|---|
| Interpolation as the executable | error: the command comes from static text only |
| Shell route on Windows | error: cmd.exe quoting cannot be made injection-safe; use argv mode |
| RAW misuse | error: one argument, verbatim, nesting refused |

`RAW("...")` / `RAW(["a", "b"])` is the single explicit trust boundary for
pre-quoted content. Every use site is greppable.

## Limits

- Windows: interpolated shell routes are refused rather than approximated;
  argv-mode commands work fully.
- Bytes interpolations are rejected: decode explicitly first.
- Runtime behavior after import is your test suite's job, same trust model as
  calling subprocess yourself.

## Contributing

Issues and PRs welcome. Security reports go privately to the maintainer, never
through public issues.

## Requirements

- CPython >= 3.14 (uses template strings from PEP 750)
- Linux, macOS, Windows (Windows supports argv mode; POSIX-only shell mode)

## License

MIT
