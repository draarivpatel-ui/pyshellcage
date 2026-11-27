# pyshellcage

Zero-dependency command injection, argument injection, and environment hijack defense for Python subprocesses.

`pyshellcage` is a small, auditable security library for applications that must execute local programs without turning attacker controlled input into a shell command. It is designed for Python AI agents, MCP servers, automation workers, CI helpers, backend job runners, desktop agents, and plugin systems that use `subprocess` but need a strict boundary around executable selection, argv construction, environment inheritance, working-directory containment, timeouts, and output size.

- Zero runtime dependencies. Only the Python standard library is used.
- Python 3.9 through 3.13, with typed package marker `py.typed`.
- No shell execution. String and bytes command lines are rejected, argv sequences are required, and `shell=False` is unconditional.
- Explicit executable allowlist. Shell interpreters, Windows batch and script extensions, trailing-dot spellings, NTFS alternate-data-stream spellings, UNC paths, and shell-resolving symlinks are blocked by default.
- CWE-88 positional argument defense. Typed argv builder slots validate untrusted positionals or place them after `--`.
- Environment scrubbing. A minimal allowlist is combined with a hard case-insensitive denylist for dynamic linker, runtime, shell, editor, and Git hijack variables.
- Bounded execution. Timeouts, terminate then kill escalation, stdin byte limits, and streaming stdout and stderr byte caps are enforced without unbounded buffering.

## Release status

This repository is release-ready source for `pyshellcage` version 1.0.0. The PyPI name was checked as unclaimed during preparation, but this source does not claim that the package has already been published. Until a maintainer publishes it, run it from a source checkout or a privately built wheel.

When published by a maintainer, installation will be:

```sh
python3 -m pip install pyshellcage
```

From a source checkout:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
PYTHONPATH=src python3 -m pyshellcage audit --json -- git status
```

## Threat model

`pyshellcage` addresses three concrete classes of child-process risk.

### CWE-78: operating system command injection

CWE-78 occurs when attacker controlled text is concatenated into a command line and interpreted by a shell. Metacharacters such as semicolons, pipes, command substitution, and redirection then become new commands.

`pyshellcage` removes the shell from the trust boundary. Execution APIs accept an argv sequence, never one command line string. They reject shell interpreters by default, reject `shell=True`, and never join argv elements into a command line.

Unsafe pattern:

```python
subprocess.run(f"pdfinfo {user_name}", shell=True)
```

Safe pattern:

```python
from pyshellcage import ShellCage

cage = ShellCage(allow_executables=["/opt/tools/bin/pdfinfo"])
result = cage.safe_run(
    ["/opt/tools/bin/pdfinfo", user_name],
    timeout_seconds=5,
    max_stdout_bytes=64 * 1024,
)
```

This example is intentionally simple. A real tool still needs application-level file authorization before deciding that `user_name` may be read.

### CWE-88: argument injection

CWE-88 occurs when a value intended to be positional is interpreted as an option. Examples include a repository named `--upload-pack=...` passed to `git clone`, a path interpreted as `--checkpoint-action=...` by GNU `tar`, a positional `-K` consumed by `curl`, or a file named `-exec` consumed by `find` in contexts where `--` is misunderstood.

`pyshellcage` provides typed argv construction so fixed flags and untrusted positionals are not confused. Untrusted positionals either reject a leading dash or are placed after an explicit end-of-options marker when the target tool is known to honor it.

```python
from pyshellcage import ShellCage

cage = ShellCage(
    allow_executables=["/usr/bin/git"],
    allowed_cwd_roots=["/srv/workspaces"],
)

argv = cage.build_argv([
    {"type": "literal", "value": "clone"},
    {"type": "flag", "name": "--depth", "value": "1"},
    {"type": "end_of_options"},
    {"type": "positional", "value": user_controlled_repository},
    {"type": "path", "value": user_controlled_destination},
])

result = cage.safe_run(["/usr/bin/git"] + list(argv), cwd=trusted_workspace)
```

The important property is not the specific `git` invocation. It is that `user_controlled_repository` cannot become `--upload-pack` because it is either behind `--` or rejected when it starts with a dash.

### Environment hijacking

Child processes inherit more than data. Variables such as `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `PYTHONPATH`, `NODE_OPTIONS`, `RUBYOPT`, `PERL5OPT`, `JAVA_TOOL_OPTIONS`, `BASH_ENV`, `GIT_SSH_COMMAND`, and `GIT_CONFIG_PARAMETERS` can load code, replace helpers, or change runtime behavior before the child reaches its own entry point.

`pyshellcage` starts from a minimal allowlist containing `PATH`, `HOME`, `LANG`, `LC_ALL`, and `TMPDIR`. On Windows it also includes `SYSTEMROOT` and `WINDIR`. It then applies a hard case-insensitive denylist covering dynamic linker variables, runtime preload variables, shell startup variables, editor and pager helpers, Git configuration and transport overrides, `COMSPEC`, and `PATHEXT`. A hard-denied name is removed even if a caller accidentally includes it in a custom allowlist.

### Windows batch, script, and path confusion

Windows batch-file handling has made child-process behavior dangerous even when a caller did not intentionally use a shell. `pyshellcage` rejects `.bat`, `.cmd`, `.btm`, `.vbs`, `.vbe`, `.js`, `.jse`, `.wsf`, `.wsh`, `.ps1`, and `.com` executables by default on every platform. It also rejects trailing-dot executable names, NTFS alternate-data-stream separators, and UNC paths cross-platform so Windows-specific behavior does not silently reappear when the same code is deployed on Windows.

Absolute executable paths are resolved with `os.path.realpath()`. If a symlink with a harmless name resolves to a shell interpreter or batch/script filename, the resolved target is blocked too. Bare executable names are resolved through the effective `PATH` when possible and receive the same policy check.

## Quick start

```python
from pyshellcage import ShellCage

cage = ShellCage(
    allow_executables=["/usr/bin/git"],
    allowed_cwd_roots=["/srv/workspaces"],
    allow_env=["PATH", "HOME", "LANG", "LC_ALL", "TMPDIR"],
)

report = cage.validate_invocation(["/usr/bin/git", "status"])
if not report.ok:
    raise ValueError(report.findings[0].message)

result = cage.safe_run(
    ["/usr/bin/git", "status", "--short"],
    cwd="/srv/workspaces/example",
    timeout_seconds=10,
    max_stdout_bytes=1024 * 1024,
    max_stderr_bytes=256 * 1024,
)

if result.timed_out:
    raise RuntimeError("git timed out")
if result.exit_code != 0:
    raise RuntimeError("git failed")
```

## Python AI agent example

An agent tool should validate schema input at the tool boundary, construct typed argv, and execute through a narrow cage. It should never pass a raw command string to `subprocess.run` or `os.system`.

```python
from pyshellcage import ShellCage, ShellCageError

pdf_cage = ShellCage(
    allow_executables=["/opt/tools/bin/pdfinfo"],
    allow_env=["PATH", "LANG", "LC_ALL", "TMPDIR"],
    allowed_cwd_roots=["/var/agent-work"],
)

def pdf_info_tool(file_name: str) -> dict:
    if not isinstance(file_name, str):
        raise ValueError("file_name must be a string")

    argv = pdf_cage.build_argv([
        {"type": "end_of_options"},
        {"type": "path", "value": file_name},
    ])

    try:
        result = pdf_cage.safe_run(
            ["/opt/tools/bin/pdfinfo"] + list(argv),
            cwd="/var/agent-work",
            timeout_seconds=5,
            max_stdout_bytes=64 * 1024,
            max_stderr_bytes=16 * 1024,
        )
    except ShellCageError as error:
        return {"ok": False, "code": error.code}

    return {
        "ok": result.exit_code == 0,
        "stdout": result.stdout,
        "truncated": result.truncated_stdout,
    }
```

This still requires a separate filesystem authorization layer. `safe_path_arg` is lexical validation, not proof that the file is one the user may read.

## MCP server example

An MCP server can expose a narrow, intentionally designed tool rather than a general shell tool. The following shape is representative:

```python
from pyshellcage import ShellCage

cage = ShellCage(
    allow_executables=["/opt/tools/bin/ffprobe"],
    allowed_cwd_roots=["/var/mcp-media"],
)

def probe_media(file_name: str) -> dict:
    argv = cage.build_argv([
        {"type": "flag", "name": "-v", value: "error"},
        {"type": "flag", "name": "-show_format"},
        {"type": "flag", "name": "-of", value: "json"},
        {"type": "end_of_options"},
        {"type": "path", "value": file_name},
    ])
    result = cage.safe_run(
        ["/opt/tools/bin/ffprobe"] + list(argv),
        cwd="/var/mcp-media",
        timeout_seconds=8,
        max_stdout_bytes=128 * 1024,
        max_stderr_bytes=16 * 1024,
    )
    return {
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "timed_out": result.timed_out,
        "truncated_stdout": result.truncated_stdout,
    }
```

## API

### `ShellCage(**options)`

Creates an immutable reusable policy object. `allow_executables` is required and must be a non-empty list or tuple of basenames or absolute paths. Absolute entries are resolved with `os.path.realpath()` when they exist. Basename entries match the basename of the invoked executable.

Methods:

- `validate_invocation(argv, **overrides)`
- `audit_argv(command, args=(), **overrides)`
- `safe_run(argv, **overrides)`
- `safe_popen(argv, **overrides)`
- `sanitize_env(source=None, **overrides)`
- `audit_env(source=None, **overrides)`
- `assert_safe_arg`, `safe_arg`, `safe_path_arg`, `build_argv`

Per-call overrides are shallowly merged and revalidated. List options such as `allow_executables` and `allow_env` are replaced, not concatenated.

Important options:

| Option | Default | Meaning |
| --- | --- | --- |
| `allow_executables` | required | Non-empty basename or absolute-path executable allowlist. |
| `allow_shell_binary` | `False` | Explicitly permit a shell interpreter executable. This does not permit inline command flags. |
| `allow_batch_extensions` | `False` | Explicitly permit Windows batch or script extensions. Avoid this outside a trusted migration boundary. |
| `allow_dangerous_flags` | `False` | Permit flags and gadgets normally found by the execution audit. Prefer removing the flag instead. |
| `allow_env` | minimal platform list | Complete environment allowlist. Passing a custom list replaces the default list. |
| `allowed_cwd_roots` | unset | Optional realpath containment roots for `cwd`. |
| `timeout_seconds` | 15 | Maximum child runtime for `safe_run`. |
| `kill_grace_seconds` | 0.25 | Grace period between `terminate()` and `kill()`. |
| `max_stdout_bytes` | 1 MiB | Streaming stdout cap. |
| `max_stderr_bytes` | 1 MiB | Streaming stderr cap. |
| `max_stdin_bytes` | 1 MiB | Input byte cap. |

Basename execution inherits the operating system's executable lookup behavior. Where possible, prefer absolute allowlist entries and absolute invocations so `PATH` lookup is not part of the trust decision. If a basename must be used, treat the scrubbed `PATH` value as security-sensitive configuration.

### `validate_invocation(argv, **options)`

Returns a frozen `ValidationReport` without executing anything:

```python
from pyshellcage import validate_invocation

report = validate_invocation(
    ["/usr/bin/git", "status"],
    allow_executables=["/usr/bin/git"],
)
print(report.ok)
print(report.findings)
```

A string or bytes command line is rejected even when it contains no spaces:

```python
validate_invocation("git status", allow_executables=["git"]).ok  # False
validate_invocation(b"git", allow_executables=["git"]).ok        # False
```

Validation failures are findings in the report. `safe_run` and `safe_popen` convert the first finding into `ShellCageError` and attach all findings in `error.details["findings"]`.

### `audit_argv(command, args=(), **options)`

Returns structured static findings for an already separated executable and argument sequence. It does not require an executable allowlist and never invokes the command.

The detector covers high-risk flags and gadgets for tools including:

- `git`: `-c`, `-C`, `--config`, `--config-env`, `--upload-pack` and abbreviated forms, `--exec-path`, `--git-dir`, `--work-tree`, `--template`, and `ext::` transport gadgets.
- GNU `tar`: `--checkpoint-action` and abbreviations such as `--checkpoint-a`, `--to-command`, `-I`, compression helper flags, `--rsh-command`, `--rmt-command`, `--info-script`, and `--new-volume-script`. Benign `--checkpoint` is not flagged.
- `find`: `-exec`, `-execdir`, `-ok`, and `-okdir`, including after `--`, because `find` does not treat `--` as the end of expression parsing.
- `curl`: `-K`, `--config`, `-o`, `--output`, upload flags, and file-output flags.
- `ssh`, `scp`, `sftp`, and `rsync`: `-o` proxy/local command gadgets, `-e`, `--rsh`, `--rsync-path`, and transport overrides.
- JavaScript runtimes: eval, print, require, import, and loader flags for `node`, `nodejs`, `bun`, and `deno`.
- Python runtimes: `-c`, `-m`, and stdin execution marker `-`.
- PowerShell: abbreviated, slash-prefixed, and Unicode-dash forms of command execution flags.
- Shell interpreters, `cmd`, `env`, and `xargs`.

The audit honors conventional `--` end-of-options semantics only where the tool does. `find`, `cmd`, and PowerShell remain active after that token. Detection is conservative about documented abbreviated forms for PowerShell, Git, and GNU tar. It is a detector and inventory tool, not a complete emulation of every CLI parser.

### `assert_safe_arg(value, **options)`

Validates one argv element and returns it unchanged. It raises `ShellCageError` for:

- non-string input
- NUL bytes
- line breaks unless `allow_newlines=True`
- other ASCII and C1 control characters
- bidirectional override controls
- lone UTF-16 surrogates
- byte length above `max_bytes`
- leading `-` when `positional=True` or `reject_leading_dash=True`

### `safe_arg(value, **options)`

Strict positional convenience wrapper. It enables positional validation, so a leading dash is rejected unless the value is deliberately placed after `--` by `build_argv` instead.

### `safe_path_arg(value, **options)`

Strict positional path convenience wrapper. It is like `safe_arg` but rejects an empty path. It performs lexical validation only. It does not prove existence, permissions, containment within a workspace, or freedom from symlink races.

### `build_argv(spec)`

Builds an immutable argv tuple from typed slots:

```python
from pyshellcage import build_argv

argv = build_argv([
    {"type": "literal", "value": "clone"},
    {"type": "flag", "name": "--depth", "value": "1"},
    {"type": "end_of_options"},
    {"type": "positional", "value": user_input},
])
```

Slot types:

- `literal`: fixed trusted literal. Do not use for untrusted input.
- `flag`: fixed ASCII flag spelling, with optional separate or equals-joined value.
- `positional`: untrusted positional value. Before `--`, a leading dash is rejected.
- `path`: non-empty untrusted positional path value with the same lexical rules.
- `end_of_options`: emits one `--` marker.

The builder validates control characters, NUL bytes, bidi controls, lone surrogates, and byte length in every slot.

### `sanitize_env(source=None, **options)` and `audit_env(source=None, **options)`

`sanitize_env` returns a read-only scrubbed environment mapping. Values are copied as data and never interpreted.

`audit_env` returns structured findings without exposing values. With `include_unlisted=True`, it also reports variables outside the explicit allowlist. Findings include key names where valid, never environment values.

### `safe_run(argv, **options)`

Runs an allowlisted argv with `shell=False` and returns a frozen `ExecResult`:

```python
ExecResult(
    command=("/usr/bin/git", "status"),
    exit_code=0,
    signal_num=None,
    stdout="...",
    stderr="",
    timed_out=False,
    truncated_stdout=False,
    truncated_stderr=False,
    duration_ms=12.5,
)
```

Execution properties:

- `stdin` may be text or bytes and is bounded by `max_stdin_bytes`.
- stdout and stderr are read concurrently in bounded chunks.
- If either cap is exceeded, the child is terminated immediately and the result keeps only bytes up to the cap.
- If a cap cuts through a multibyte UTF-8 sequence, the incomplete trailing bytes are omitted so truncation does not create a replacement character from a valid sequence.
- On timeout, the child receives `terminate()`, then `kill()` after `kill_grace_seconds` if it does not exit.
- `cwd` is resolved with `os.path.realpath()`. When `allowed_cwd_roots` is set, containment is checked with `os.path.commonpath([root, target]) == root`, which prevents sibling-prefix escapes such as `work-evil` and symlink escapes.

### `safe_popen(argv, **options)`

Returns a `subprocess.Popen` object after the same invocation validation, environment scrubbing, and cwd containment. It always uses `shell=False` and pipes stdin, stdout, and stderr. It rejects stdout/stderr cap options because a raw `Popen` object cannot enforce them. Use `safe_run` for the bounded harness. The caller owns and must close the returned pipes.

## CLI

Audit one argv without executing it:

```sh
pyshellcage audit -- git clone --upload-pack=evil
pyshellcage audit --json -- git status
```

Exit codes are `0` for clean, `1` when findings exist, and `2` for usage errors.

Audit environment keys without printing values:

```sh
pyshellcage audit-env --json
printf '{"PATH":"/bin"}' > env.json
pyshellcage audit-env --env-json env.json --json
```

The JSON file opener uses `os.lstat`, conditional `O_NOFOLLOW` and `O_NONBLOCK`, and `os.fstat` identity checks. Symlinks, FIFOs, devices, directories, oversized files, invalid UTF-8, and non-object JSON are rejected. Output is JSON-escaped or terminal-neutralized so ANSI control and bidirectional formatting characters cannot control the terminal.

## Security boundaries and non-goals

`pyshellcage` does not decide whether a file may be read or written. It does not implement authorization, sandboxing, resource limits, network policy, or filesystem race protection beyond the cwd containment check described above. Use OS sandboxing, least-privilege users, seccomp or job objects, and application-specific path policy where needed.

Argument auditing is conservative and tool-specific. It cannot perfectly emulate every version of every command-line parser. Treat overrides such as `allow_dangerous_flags`, `allow_shell_binary`, and `allow_batch_extensions` as migration escape hatches, not routine configuration.

## Development

Run the standard-library test suite:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
```

The test suite contains more than 1,000 tests on the current source tree, including real subprocess integration tests, cwd symlink containment tests, multibyte output truncation tests, CLI file-type attacks, and tool-specific argument-injection matrices.
