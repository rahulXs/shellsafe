# Changelog

All notable changes to this project are documented here. Format follows
Keep a Changelog; versioning follows SemVer.

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
