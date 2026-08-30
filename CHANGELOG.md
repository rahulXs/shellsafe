# Changelog

All notable changes to this project are documented here. Format follows
Keep a Changelog; versioning follows SemVer.

## [0.3.1] - 2026-08-30

### Added

- AU002 rule: detect `shell=True` with dynamic content (.format(), string
  concatenation, %-formatting, variables) in shell executor calls
- AU002 fixture corpus: 6 positive cases + 5 safe cases
- Unit tests for AU002 detection, confidence, and severity
- Integration tests for CLI audit with AU002

## [0.3.0] - 2026-08-29

### Added

- Offline audit scanner: AST-based detection of f-strings passed to shell
  executors (`os.system`, `subprocess.run`, `subprocess.call`, etc.)
- AU001 rule: flags f-string interpolation in shell executor arguments with
  fix-hint suggesting template strings
- Import alias tracking: handles `import subprocess as sp`, `from os import
  system`, etc.
- CLI `shellsafe audit` command with terminal table and JSON output
- `--json` flag for machine-readable findings
- `--severity` flag to filter by minimum severity level
- Audit fixture corpus: 6 positive cases + 4 safe cases
- Unit tests for scanner, integration tests for CLI audit

### Changed

- Collapse `audit/rules.py` and `reporters.py` into single `audit/scanner.py`
- CLI refactored with dedicated `_run_audit` handler

### Removed

- mypy (ruff catches real bugs)
- `cast()` calls on values that already have the right type


## [0.2.0] - 2026-08-27

### Added

- Shell-mode execution: `shx()` runs pipes, redirections, and globs via
  `/bin/sh -c` on Linux and macOS; interpolated values are `shlex`-quoted
  automatically
- Shell-mode payload corpus: 15 injection cases verified as single tokens via
  `shlex.split` round-trip
- Shell-mode property tests: arbitrary values stay single shell tokens under
  pipe templates
- Cyclomatic complexity lint (`C901`, max-complexity 10) enabled in CI

### Changed

- `run()` now rejects templates that contain shell metacharacters with guidance
  to use `shx()` instead
- CLI version matrix shows shell-mode availability

### Removed

- Dead `METACHARACTERS` constant from render.py (platforms.py owns it)

## [0.1.1] - 2026-08-24

### Changed

- Project description rewritten
- README restructured for PyPI: package page now leads with the why, usage and
  limits; contributing details stay in the repository only

## [0.1.0] - 2026-08-24

### Added

- Argv-mode rendering and execution via template strings
- RAW trust marker with argv splicing
- capture() helper with utf-8 stdout/stderr
- plan() helper for inspecting commands before execution
- Injection payload corpus as a release gate; all cases render inert
