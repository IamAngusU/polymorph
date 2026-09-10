# Local validation without GitHub Actions

GitHub stores and reviews the code; it does not have to execute the tests.
`scripts/validate_local.py` runs the existing quality and workflow gates on a
local checkout. It does not install packages, download models, upload reports,
change Git history, or silently weaken a failed gate.

## Windows

Use the project's existing Python 3.11+ development environment:

```powershell
.\.venv\Scripts\python.exe scripts\validate_local.py
```

Alternatively, double-click `Validate-Local.cmd` at the repository root. The
starter prefers `.venv\Scripts\python.exe` and otherwise uses `py -3`.
No administrator privileges or PowerShell policy changes are needed.

On Linux, use `.venv/bin/python scripts/validate_local.py`.

The script uses the interpreter that started it and explicitly selects this
checkout's `src` directory for source-level tests. It does not rely on an editable
installation pointing to the right checkout by accident.

Missing tools produce `blocked`, not a successful skip. If setup is needed,
review and run the existing bootstrap separately:

```powershell
py -3 scripts\bootstrap.py --skip-models --skip-checks
```

Unlike the validator, that bootstrap installs dependencies using pip. The
validator itself never invokes it automatically.

## What runs

- Bytecode compilation, Ruff lint, Ruff formatting check, strict mypy.
- Dependency consistency and the executable example.
- The complete pytest suite with warnings as errors, coverage and JUnit output.
- The existing deterministic mapping safety regression.
- Three separate 1,000-record, 100-record-batch workflow processes by default.
- The existing integrity/performance report checker after each successful run.

Workflow measurements run after tests and in separate processes, without the
pytest coverage instrumentation. A failed test gate blocks the dependent
workflow runs, while unrelated quality gates may still run for diagnostics.

Default workflow thresholds are the existing coarse CI values: at least 125
records/second, at most 8 seconds and 200 MiB peak RSS. These are declared local
acceptance thresholds, not universal hardware guarantees. Overrides are recorded
in the report; they must not be presented as the default gate:

```powershell
.\.venv\Scripts\python.exe scripts\validate_local.py --runs 5 --timeout 1200
```

Use `--list` to inspect the steps without running them or creating output.

## Evidence

Each invocation creates a new directory under `.polymorph/validation/` containing
`summary.json`, per-step logs, JUnit/coverage files and workflow reports/state.
The summary records HEAD, whether the tree is dirty, a digest of actual tracked
and non-ignored source bytes, host OS/architecture/Python, step results, test
counts and successful workflow measurements. Source digests are checked before
and after; a detected edit prevents success. Keep other writing agents paused:
this detects changed endpoints, not an edit-and-revert during a running test.

`summary.json` intentionally omits stdout, tracebacks, test names, source filenames
and absolute local paths. Share it first. Raw logs and JUnit/coverage/workflow
reports can contain paths, test values or failure details; review them separately
before sharing. Nothing is uploaded automatically.

Timeouts, output-limit violations, unavailable tools, invalid JUnit, invalid
workflow measurements and changed sources all prevent exit code 0. Every step
has a default 15-minute timeout. Log size is monitored at 64 MiB; process cleanup
is best effort, not a sandbox or an aggregate resource guarantee.

A partially written report marked `running` is not a passing result. A failed or
all-skipped test run cannot be reported as successful merely because a process
returned zero. Platform skips remain explicit in the summary.

## Scope limits

This is local source validation, not release certification. A Windows run proves
neither Linux containment nor live PostgreSQL behavior. A Linux run proves no
native Windows behavior. Package builds and fresh wheel/sdist installation remain
separate checks using the existing build and `check_sdist.py` tools. The runner
also does not claim full parser isolation, a cross-version matrix or a security
audit. Keep those unexecuted requirements visible in the pull request.

The validator's own regression tests can run independently:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_validate_local.py
```
