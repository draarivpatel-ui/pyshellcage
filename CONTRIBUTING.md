# Contributing

Thank you for helping improve `pyshellcage`.

## Security invariants

These invariants are part of the project design and must not be weakened:

- Runtime `dependencies = []` in `pyproject.toml`.
- Python 3.9 compatibility. Use `from __future__ import annotations`; do not use `match`/`case` or `tomllib`.
- Never invoke a shell. `shell=False` is unconditional.
- Never accept a single string or bytes command line for execution. Input must be an argv sequence.
- Execution requires an explicit non-empty executable allowlist.
- Do not expand the default environment allowlist without a documented threat-model reason.
- The hard environment denylist wins over custom allowlists.
- Never print environment values in audits, errors, logs, or tests.
- `safe_popen` must reject output-cap options it cannot enforce.
- cwd containment must use realpaths and `os.path.commonpath`, never naive string prefix matching.

## Test requirements

Before sending a pull request, run:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
python3 -m build
```

Tests must use only the standard library. Add regression tests for every security fix. Tests for dangerous examples must not execute the dangerous payload; use static audit tests or a Python child process with explicit test-only overrides.

## Code style

- Keep the library small and auditable.
- Prefer explicit validation over clever parsing.
- Fail closed for unknown options and ambiguous ownership.
- Keep errors structured with stable `PYSHELLCAGE_*` codes.
- Do not add shell quoting helpers. Quoting can encourage the unsafe mental model that a shell command line exists.
- Do not add dependencies for convenience.

## Reporting security issues

Do not open a public issue for a vulnerability. Use the process in `SECURITY.md`.
