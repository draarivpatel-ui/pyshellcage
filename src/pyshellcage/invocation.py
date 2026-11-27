"""Executable policy, invocation validation, and dangerous argv auditing."""

from __future__ import annotations

import os
import re
import shutil
from collections.abc import Mapping, Sequence
from typing import Any, Dict, List, Optional, Tuple

from .args import DEFAULT_MAX_ARG_BYTES, MAX_ARG_BYTES, check_safe_arg, has_control_character, utf8_len
from .env import sanitize_env
from .errors import CODES, ShellCageError, fail
from .models import Finding, ValidationReport

DEFAULT_MAX_ARGS = 512
MAX_ARGS_LIMIT = 4096
DEFAULT_MAX_ARGV_BYTES = 256 * 1024
MAX_ARGV_BYTES_LIMIT = 1024 * 1024
MAX_EXECUTABLE_BYTES = 1024
MAX_ALLOWLIST_ENTRIES = 512

_WINDOWS_ABSOLUTE_RE = re.compile(r"^[A-Za-z]:[\\/]")
_BATCH_EXTENSIONS = (
    ".bat",
    ".cmd",
    ".btm",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".ps1",
    ".com",
)
_PATH_SPLIT_RE = re.compile(r"[\\/]+")
_PRINTABLE_ASCII_RE = re.compile(r"^[\x21-\x7e]+$")

SHELL_EXECUTABLES = frozenset(
    (
        "sh",
        "bash",
        "zsh",
        "dash",
        "ksh",
        "csh",
        "fish",
        "cmd",
        "powershell",
        "pwsh",
        "wscript",
        "cscript",
        "mshta",
        "command",
    )
)
POWERSHELL_EXECUTABLES = frozenset(("powershell", "pwsh"))

INVOCATION_OPTION_KEYS = frozenset(
    (
        "allow_executables",
        "allow_shell_binary",
        "allow_batch_extensions",
        "allow_dangerous_flags",
        "max_arg_bytes",
        "max_args",
        "max_argv_bytes",
        "env",
        "allow_env",
        "max_env_value_bytes",
        "cwd",
        "allowed_cwd_roots",
        "timeout_seconds",
        "kill_grace_seconds",
        "max_stdout_bytes",
        "max_stderr_bytes",
        "max_stdin_bytes",
        "stdin",
        "shell",
        "windows_verbatim_arguments",
        "windows_hide",
    )
)


def _finding(code: str, severity: str, message: str, **extra: Any) -> Finding:
    values = {}
    for key, value in extra.items():
        if value is not None:
            values[key] = value
    return Finding(code, severity, message, **values)


def _error_finding(error: BaseException) -> Finding:
    if isinstance(error, ShellCageError):
        return Finding(error.code, "high", error.message)
    return Finding(CODES["CONFIG_INVALID"], "high", "invalid pyshellcage configuration")


def _strict_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        fail(CODES["CONFIG_INVALID"], name + " must be a boolean")
    return value


def _strict_int(value: Any, minimum: int, maximum: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > maximum:
        fail(CODES["CONFIG_INVALID"], name + " must be an integer in range")
    return value


def normalize_invocation_options(options: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    source = {} if options is None else dict(options)
    for key in source:
        if key not in INVOCATION_OPTION_KEYS:
            fail(CODES["CONFIG_OPTION_UNKNOWN"], "options contains an unknown option", {"key": key})

    normalized = {
        "allow_shell_binary": False,
        "allow_batch_extensions": False,
        "allow_dangerous_flags": False,
        "max_arg_bytes": DEFAULT_MAX_ARG_BYTES,
        "max_args": DEFAULT_MAX_ARGS,
        "max_argv_bytes": DEFAULT_MAX_ARGV_BYTES,
    }
    for key in ("allow_shell_binary", "allow_batch_extensions", "allow_dangerous_flags", "windows_hide"):
        if key in source:
            normalized[key] = _strict_bool(source[key], key)
    for key, minimum, maximum in (
        ("max_arg_bytes", 1, MAX_ARG_BYTES),
        ("max_args", 1, MAX_ARGS_LIMIT),
        ("max_argv_bytes", 1, MAX_ARGV_BYTES_LIMIT),
    ):
        if key in source:
            normalized[key] = _strict_int(source[key], minimum, maximum, key)

    shell = source.get("shell", False)
    windows_verbatim = source.get("windows_verbatim_arguments", False)
    if not isinstance(shell, bool) or not isinstance(windows_verbatim, bool):
        fail(CODES["CONFIG_INVALID"], "shell and windows_verbatim_arguments must be booleans")
    if shell or windows_verbatim:
        fail(CODES["SHELL_OPTION_FORBIDDEN"], "shell execution and verbatim Windows arguments are forbidden")

    for key in (
        "allow_executables",
        "env",
        "allow_env",
        "max_env_value_bytes",
        "cwd",
        "allowed_cwd_roots",
        "timeout_seconds",
        "kill_grace_seconds",
        "max_stdout_bytes",
        "max_stderr_bytes",
        "max_stdin_bytes",
        "stdin",
    ):
        if key in source:
            normalized[key] = source[key]
    if "windows_hide" in source:
        normalized["windows_hide"] = source["windows_hide"]
    return normalized


def split_executable_path(value: str) -> List[str]:
    return [part for part in _PATH_SPLIT_RE.split(value) if part != ""]


def executable_basename(value: str) -> str:
    parts = _PATH_SPLIT_RE.split(value)
    return parts[-1] if parts else ""


def is_path_like_executable(value: str) -> bool:
    return "/" in value or "\\" in value


def is_unc_path(value: str) -> bool:
    return value.startswith("\\\\") or value.startswith("//")


def is_absolute_executable(value: str) -> bool:
    return os.path.isabs(value) or bool(_WINDOWS_ABSOLUTE_RE.match(value)) or is_unc_path(value)


def windows_policy_basename(name: str) -> str:
    return name.split(":", 1)[0].rstrip(". ")


def canonical_executable_name(name: str) -> str:
    lower = windows_policy_basename(name).lower()
    if lower.endswith(".exe"):
        lower = lower[:-4]
    return lower


def executable_names_equal(left: str, right: str) -> bool:
    if os.name == "nt":
        return left.lower() == right.lower()
    return left == right


def _has_non_ascii(value: str) -> bool:
    return any(ord(char) > 0x7E for char in value)


def inspect_executable_syntax(command: Any) -> Tuple[Dict[str, Any], List[Finding]]:
    findings = []
    info = {"valid": False, "basename": "", "path_like": False, "absolute": False}
    if not isinstance(command, str):
        findings.append(_finding(CODES["EXECUTABLE_TYPE"], "high", "executable must be a string"))
        return info, findings
    if command == "":
        findings.append(_finding(CODES["EXECUTABLE_EMPTY"], "high", "executable must not be empty"))
        return info, findings

    basename = executable_basename(command)
    path_like = is_path_like_executable(command)
    absolute = is_absolute_executable(command)
    info.update({"valid": True, "basename": basename, "path_like": path_like, "absolute": absolute})

    try:
        command_bytes = utf8_len(command)
    except UnicodeEncodeError:
        command_bytes = MAX_EXECUTABLE_BYTES + 1
    if command_bytes > MAX_EXECUTABLE_BYTES:
        info["valid"] = False
        findings.append(_finding(CODES["EXECUTABLE_TOO_LONG"], "high", "executable path exceeds the byte limit"))
    if "\x00" in command:
        info["valid"] = False
        findings.append(_finding(CODES["EXECUTABLE_NUL_BYTE"], "high", "executable contains a NUL byte"))
    if has_control_character(command.replace("\x00", "")):
        info["valid"] = False
        findings.append(_finding(CODES["EXECUTABLE_CONTROL_CHAR"], "high", "executable contains a control character"))
    if basename == "":
        info["valid"] = False
        findings.append(_finding(CODES["EXECUTABLE_EMPTY"], "high", "executable basename must not be empty"))
    if any(char.isspace() for char in basename):
        info["valid"] = False
        findings.append(_finding(CODES["EXECUTABLE_WHITESPACE"], "high", "executable basename must not contain whitespace"))
    if _has_non_ascii(basename):
        info["valid"] = False
        findings.append(
            _finding(CODES["EXECUTABLE_NON_ASCII"], "high", "executable basename must not contain non-ASCII confusables")
        )
    if basename.endswith("."):
        info["valid"] = False
        findings.append(
            _finding(
                CODES["EXECUTABLE_TRAILING_DOT"],
                "high",
                "executable basename must not end in a dot because Windows can normalize it away",
            )
        )
    if ":" in basename:
        info["valid"] = False
        findings.append(
            _finding(CODES["EXECUTABLE_NTFS_STREAM"], "high", "executable basename must not contain an NTFS alternate data stream separator")
        )
    if is_unc_path(command):
        info["valid"] = False
        findings.append(_finding(CODES["EXECUTABLE_UNC_PATH"], "critical", "UNC executable paths are forbidden"))
    if ".." in split_executable_path(command):
        info["valid"] = False
        findings.append(_finding(CODES["EXECUTABLE_TRAVERSAL"], "high", "executable path must not contain parent traversal"))
    if path_like and not absolute:
        info["valid"] = False
        findings.append(
            _finding(CODES["EXECUTABLE_RELATIVE_PATH"], "high", "executable path must be absolute when it contains a path separator")
        )
    return info, findings


def _realpath_if_possible(value: str) -> str:
    try:
        return os.path.realpath(value)
    except Exception:
        return os.path.normpath(value)


def _normalize_path_for_compare(value: str) -> str:
    return os.path.normcase(os.path.normpath(value))


def _paths_equal(left: str, right: str) -> bool:
    return _normalize_path_for_compare(left) == _normalize_path_for_compare(right)


def validate_allowlist_entry(entry: Any, index: int) -> Dict[str, str]:
    if not isinstance(entry, str) or entry == "":
        fail(CODES["EXECUTABLE_ALLOWLIST_INVALID"], "allowlist entries must be non-empty strings", {"index": index})
    try:
        entry_bytes = utf8_len(entry)
    except UnicodeEncodeError:
        fail(CODES["EXECUTABLE_ALLOWLIST_INVALID"], "allowlist entry contains an unpaired surrogate", {"index": index})
    if entry_bytes > MAX_EXECUTABLE_BYTES or "\x00" in entry or has_control_character(entry):
        fail(CODES["EXECUTABLE_ALLOWLIST_INVALID"], "allowlist entry contains forbidden characters", {"index": index})
    basename = executable_basename(entry)
    if (
        basename == ""
        or any(char.isspace() for char in basename)
        or _has_non_ascii(basename)
        or basename.endswith(".")
        or ":" in basename
    ):
        fail(CODES["EXECUTABLE_ALLOWLIST_INVALID"], "allowlist entry has an unsafe executable basename", {"index": index})
    if ".." in split_executable_path(entry):
        fail(CODES["EXECUTABLE_ALLOWLIST_INVALID"], "allowlist entry must not contain parent traversal", {"index": index})
    if is_unc_path(entry):
        fail(CODES["EXECUTABLE_ALLOWLIST_INVALID"], "allowlist entries must not be UNC paths", {"index": index})
    path_like = is_path_like_executable(entry)
    absolute = is_absolute_executable(entry)
    if path_like and not absolute:
        fail(
            CODES["EXECUTABLE_ALLOWLIST_INVALID"],
            "allowlist paths must be absolute paths or bare executable names",
            {"index": index},
        )
    if absolute:
        normalized = os.path.normpath(entry)
        return {"kind": "path", "value": entry, "normalized": normalized, "real": _realpath_if_possible(entry)}
    return {"kind": "basename", "value": entry, "name": entry}


def normalize_allowlist(value: Any) -> Tuple[Dict[str, str], ...]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, (list, tuple)) or len(value) == 0:
        fail(CODES["EXECUTABLE_ALLOWLIST_REQUIRED"], "an explicit non-empty executable allowlist is required")
    if len(value) > MAX_ALLOWLIST_ENTRIES:
        fail(CODES["EXECUTABLE_ALLOWLIST_INVALID"], "executable allowlist exceeds the entry limit")
    return tuple(validate_allowlist_entry(entry, index) for index, entry in enumerate(value))


def executable_is_allowlisted(command: str, info: Mapping[str, Any], allowlist: Tuple[Dict[str, str], ...]) -> bool:
    basename = info.get("basename", "")
    for entry in allowlist:
        if entry["kind"] == "basename" and executable_names_equal(entry["name"], basename):
            return True
    if not info.get("absolute"):
        return False
    real_command = _realpath_if_possible(command)
    normalized_command = os.path.normpath(command)
    for entry in allowlist:
        if entry["kind"] != "path":
            continue
        if _paths_equal(real_command, entry["real"]) or _paths_equal(normalized_command, entry["normalized"]):
            return True
    return False


def _environment_path(env: Any) -> Tuple[Optional[str], bool]:
    if env is None:
        return os.environ.get("PATH"), True
    if not isinstance(env, Mapping):
        return None, False
    for key, value in env.items():
        if not isinstance(key, str) or not isinstance(value, str):
            continue
        if os.name == "nt":
            if key.upper() == "PATH":
                return value, True
        elif key == "PATH":
            return value, True
    return os.defpath, True


def _resolution_environment(options: Mapping[str, Any], findings: List[Finding]) -> Any:
    source = options.get("env") if "env" in options else os.environ
    try:
        return sanitize_env(
            source,
            allow_env=options.get("allow_env"),
            max_value_bytes=options.get("max_env_value_bytes"),
        )
    except ShellCageError as error:
        findings.append(_error_finding(error))
        return None


def resolve_bare_executable(command: str, env: Any = None) -> Optional[str]:
    if is_path_like_executable(command):
        return None
    path_value, usable = _environment_path(env)
    if not usable:
        return None
    try:
        return shutil.which(command, path=path_value)
    except Exception:
        return None


def inspect_executable_policy(
    command: Any,
    info: Mapping[str, Any],
    options: Mapping[str, Any],
    findings: List[Finding],
    require_allowlist: bool,
) -> None:
    basename = info.get("basename", "")
    if not basename or not isinstance(command, str):
        return

    policy_names = {windows_policy_basename(basename)}
    resolved = None
    if info.get("absolute"):
        resolved = _realpath_if_possible(command)
    elif not info.get("path_like"):
        resolved = resolve_bare_executable(command, _resolution_environment(options, findings))
    if resolved:
        policy_names.add(windows_policy_basename(executable_basename(_realpath_if_possible(resolved))))

    shell_binary = False
    batch_extension = False
    for policy_name in policy_names:
        if canonical_executable_name(policy_name) in SHELL_EXECUTABLES:
            shell_binary = True
        lower_name = windows_policy_basename(policy_name).lower()
        if lower_name.endswith(_BATCH_EXTENSIONS):
            batch_extension = True

    if shell_binary and options.get("allow_shell_binary") is not True:
        findings.append(
            _finding(CODES["SHELL_BINARY"], "critical", "shell and script interpreter executables are blocked by default")
        )
    if batch_extension and options.get("allow_batch_extensions") is not True:
        findings.append(
            _finding(CODES["BATCH_EXTENSION"], "critical", "Windows batch and script executable extensions are blocked by default")
        )

    if "allow_executables" not in options:
        if require_allowlist:
            findings.append(
                _finding(CODES["EXECUTABLE_ALLOWLIST_REQUIRED"], "critical", "an explicit non-empty executable allowlist is required")
            )
        return

    try:
        allowlist = normalize_allowlist(options.get("allow_executables"))
    except ShellCageError as error:
        findings.append(_error_finding(error))
        return
    if not executable_is_allowlisted(command, info, allowlist):
        findings.append(
            _finding(CODES["EXECUTABLE_NOT_ALLOWLISTED"], "critical", "executable is not present in the explicit allowlist")
        )


def inspect_argv(args: Sequence[Any], options: Mapping[str, Any]) -> Tuple[List[Finding], bool]:
    findings = []
    if len(args) > options["max_args"]:
        findings.append(
            _finding(CODES["ARGV_TOO_MANY"], "high", "argument count exceeds the configured limit", count=len(args))
        )
    total_bytes = 0
    all_strings = True
    for index, value in enumerate(args):
        problem = check_safe_arg(value, max_bytes=options["max_arg_bytes"])
        if problem is not None:
            if problem[0] == CODES["ARG_TYPE"]:
                all_strings = False
            findings.append(_finding(problem[0], "high", problem[1], index=index))
        else:
            total_bytes += utf8_len(value)
    if total_bytes > options["max_argv_bytes"]:
        findings.append(
            _finding(CODES["ARGV_TOO_LONG"], "high", "combined argument byte length exceeds the configured limit", count=total_bytes)
        )
    return findings, all_strings


def _first_end_of_options(args: Sequence[str]) -> int:
    try:
        return list(args).index("--")
    except ValueError:
        return -1


def _active_option_index(index: int, end_index: int) -> bool:
    return end_index == -1 or index < end_index


def _long_option_token(raw: str) -> str:
    return raw.lower().split("=", 1)[0]


def _long_flag(raw: str, flag: str) -> bool:
    return _long_option_token(raw) == flag


def _long_flag_or_abbreviation(raw: str, flag: str, minimum: int = 3) -> bool:
    token = _long_option_token(raw)
    return len(token) >= minimum and flag.startswith(token)


def _short_flag(raw: str, flag: str) -> bool:
    return raw == flag or (raw.startswith(flag) and not raw.startswith("--") and len(raw) > len(flag))


def _short_cluster_includes(raw: str, letter: str) -> bool:
    return raw.startswith("-") and not raw.startswith("--") and len(raw) > 2 and letter in raw[1:]


def _single_dash_body(raw: str) -> str:
    if not raw.startswith("-") or raw.startswith("--") or len(raw) < 2:
        return ""
    return raw[1:]


def _short_option_position(raw: str, target: str, value_options: frozenset) -> Optional[int]:
    body = _single_dash_body(raw)
    for position, char in enumerate(body):
        if char == target:
            return position
        if char in value_options:
            return None
    return None


def _shell_command_option(raw: str) -> bool:
    for char in _single_dash_body(raw):
        if char == "c":
            return True
        if char in ("o", "O"):
            return False
    return False


def _python_dangerous_option(raw: str) -> Optional[str]:
    for char in _single_dash_body(raw):
        if char in ("c", "m"):
            return char
        if char in ("W", "X"):
            return None
    return None


def _perl_dangerous_option(raw: str) -> Optional[str]:
    for char in _single_dash_body(raw):
        if char in ("e", "E", "M", "m"):
            return char
        if char in ("C", "F", "I"):
            return None
    return None


def _ruby_dangerous_option(raw: str) -> Optional[str]:
    for char in _single_dash_body(raw):
        if char in ("e", "r"):
            return char
        if char in ("C", "E", "F", "I", "K", "T", "W"):
            return None
    return None


def _php_dangerous_option(raw: str) -> Optional[str]:
    for char in _single_dash_body(raw):
        if char in ("r", "R", "B", "E"):
            return char
        if char in ("c", "d", "f", "F", "S", "t", "z"):
            return None
    return None


_REMOTE_VALUE_OPTIONS = {
    "ssh": frozenset("BbcDEeFIiJLlmoOPpQRSWw"),
    "scp": frozenset("cDFiJloPSX"),
    "sftp": frozenset("BbcDFiJloPRSsX"),
    "rsync": frozenset(),
}


def _remote_short_option(raw: str, tool: str, letter: str) -> Tuple[bool, bool]:
    position = _short_option_position(raw, letter, _REMOTE_VALUE_OPTIONS.get(tool, frozenset()))
    if position is None:
        return False, False
    return True, position == len(_single_dash_body(raw)) - 1


def _powershell_option_token(raw: str) -> str:
    if not raw:
        return raw
    first = raw[0]
    if first in ("\u2010", "\u2011", "\u2012", "\u2013", "\u2014", "\u2015", "\u2212"):
        return "-" + raw[1:].lower()
    if first == "/":
        return "-" + raw[1:].lower()
    return raw.lower()


def _powershell_execution_token(raw: str) -> bool:
    token = _powershell_option_token(raw)
    if token in ("-c", "-e", "-cwa"):
        return True
    if len(token) < 3:
        return False
    return any(flag.startswith(token) for flag in ("-command", "-encodedcommand", "-commandwithargs"))


def _add_danger(findings: List[Finding], severity: str, message: str, index: int, flag: str) -> None:
    findings.append(_finding(CODES["DANGEROUS_FLAG"], severity, message, index=index, flag=flag))


def canonical_tool_name(command: str) -> str:
    return canonical_executable_name(executable_basename(command))


def _env_nested_command(args: Sequence[str]) -> bool:
    assignment_re = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
    long_options_with_values = {"--unset", "--chdir", "--split-string"}
    short_options_with_values = frozenset("uCS")
    index = 0
    options_done = False
    while index < len(args):
        raw = args[index]
        if raw == "--" and not options_done:
            options_done = True
            index += 1
            continue
        if not options_done and raw.startswith("--"):
            token = _long_option_token(raw)
            if token in long_options_with_values and "=" not in raw:
                index += 2
            else:
                index += 1
            continue
        if not options_done and raw.startswith("-") and raw != "-":
            body = raw[1:]
            consumed = False
            for position, char in enumerate(body):
                if char in short_options_with_values:
                    if position == len(body) - 1:
                        index += 2
                    else:
                        index += 1
                    consumed = True
                    break
            if not consumed:
                index += 1
            continue
        if assignment_re.match(raw):
            index += 1
            continue
        return True
    return False


def audit_dangerous_argv(command: str, args: Sequence[str]) -> List[Finding]:
    findings: List[Finding] = []
    if not isinstance(command, str):
        return findings
    tool = canonical_tool_name(command)
    is_powershell = tool in POWERSHELL_EXECUTABLES
    is_shell = tool in SHELL_EXECUTABLES
    honors_end_of_options = tool not in ("find", "cmd") and not is_powershell
    end_index = _first_end_of_options(args) if honors_end_of_options else -1

    for index, raw in enumerate(args):
        lower = raw.lower()
        active = _active_option_index(index, end_index)

        if tool == "git" and lower.startswith("ext::"):
            findings.append(
                _finding(
                    CODES["DANGEROUS_GADGET"],
                    "critical",
                    "git ext transport gadget can execute an external command",
                    index=index,
                    flag="ext::",
                )
            )

        if not active:
            continue

        if is_shell:
            if tool == "cmd" and lower in ("/c", "/k"):
                _add_danger(findings, "critical", "cmd command execution switch detected", index, raw)
                continue
            if is_powershell and _powershell_execution_token(raw):
                _add_danger(findings, "critical", "PowerShell command execution flag detected", index, raw)
                continue
            if not is_powershell and tool != "cmd" and _shell_command_option(raw):
                _add_danger(findings, "critical", "shell interpreter command execution flag detected", index, raw)
                continue

        if tool == "git":
            if raw == "-c" or _short_flag(raw, "-c"):
                _add_danger(findings, "critical", "git -c can redefine configuration and execution behavior", index, "-c")
            elif raw == "-C" or _short_flag(raw, "-C"):
                _add_danger(
                    findings,
                    "high",
                    "git -C changes the working directory used for repository and path resolution",
                    index,
                    "-C",
                )
            elif _long_option_token(raw) != "--config" and _long_flag_or_abbreviation(raw, "--config-env"):
                _add_danger(findings, "critical", "git --config-env can import attacker controlled configuration", index, "--config-env")
            elif _long_flag_or_abbreviation(raw, "--config"):
                _add_danger(findings, "critical", "git --config can redefine configuration and execution behavior", index, "--config")
            elif _long_flag_or_abbreviation(raw, "--upload-pack"):
                _add_danger(findings, "critical", "git --upload-pack can execute an arbitrary helper", index, "--upload-pack")
            elif _long_flag_or_abbreviation(raw, "--exec-path"):
                _add_danger(findings, "high", "git --exec-path changes where git resolves helper programs", index, "--exec-path")
            elif _long_flag_or_abbreviation(raw, "--git-dir"):
                _add_danger(findings, "high", "git --git-dir can select an attacker controlled repository configuration or hooks", index, "--git-dir")
            elif _long_flag_or_abbreviation(raw, "--work-tree"):
                _add_danger(findings, "high", "git --work-tree changes where repository content is read or written", index, "--work-tree")
            elif _long_flag_or_abbreviation(raw, "--template"):
                _add_danger(findings, "high", "git --template can install attacker controlled hooks or configuration", index, "--template")

        if tool == "tar":
            token = _long_option_token(raw)
            checkpoint_action = "--checkpoint-action"
            if token != "--checkpoint" and len(token) >= len("--checkpoint-a") and checkpoint_action.startswith(token):
                _add_danger(findings, "critical", "tar --checkpoint-action can execute commands while extracting", index, "--checkpoint-action")
            elif _long_flag_or_abbreviation(raw, "--to-command"):
                _add_danger(findings, "critical", "tar --to-command pipes archive members into a command", index, "--to-command")
            elif _short_flag(raw, "-I") or _short_cluster_includes(raw, "I") or _long_flag_or_abbreviation(raw, "--use-compress-program"):
                _add_danger(findings, "critical", "tar compression helper flags can execute arbitrary commands", index, raw)
            elif (
                _long_flag_or_abbreviation(raw, "--rsh-command")
                or _long_flag_or_abbreviation(raw, "--rmt-command")
                or _long_flag_or_abbreviation(raw, "--info-script")
                or _long_flag_or_abbreviation(raw, "--new-volume-script")
                or _short_flag(raw, "-F")
                or _short_cluster_includes(raw, "F")
            ):
                _add_danger(findings, "critical", "tar helper command flag detected", index, raw)

        if tool == "find" and raw in ("-exec", "-execdir", "-ok", "-okdir"):
            _add_danger(findings, "critical", "find execution primary detected", index, raw)

        if tool == "curl":
            if _short_flag(raw, "-K") or _short_cluster_includes(raw, "K") or _long_flag(raw, "--config"):
                _add_danger(findings, "high", "curl config file input can change output and transfer behavior", index, raw)
            elif _short_flag(raw, "-o") or _short_cluster_includes(raw, "o") or _long_flag(raw, "--output"):
                _add_danger(findings, "high", "curl output flags can overwrite attacker selected files", index, raw)
            elif _short_flag(raw, "-T") or _short_cluster_includes(raw, "T") or _long_flag(raw, "--upload-file"):
                _add_danger(findings, "high", "curl upload flags can read attacker selected files", index, raw)
            elif (
                _short_flag(raw, "-O")
                or _short_cluster_includes(raw, "O")
                or _short_flag(raw, "-J")
                or _short_cluster_includes(raw, "J")
                or _long_flag(raw, "--remote-name")
                or _long_flag(raw, "--remote-header-name")
                or _long_flag(raw, "--output-dir")
                or _long_flag(raw, "--dump-header")
                or _long_flag(raw, "--trace")
                or _long_flag(raw, "--trace-ascii")
                or _long_flag(raw, "--stderr")
                or _long_flag(raw, "--cookie-jar")
            ):
                _add_danger(findings, "high", "curl file output flags can write attacker selected files", index, raw)

        if tool in ("ssh", "scp", "sftp", "rsync"):
            next_value = args[index + 1].lower() if index + 1 < len(args) else ""
            proxy_in_next = (
                "proxycommand" in next_value
                or "permitlocalcommand" in next_value
                or "localcommand" in next_value
                or ("match" in next_value and "exec" in next_value)
            )
            proxy_in_raw = (
                "proxycommand" in lower
                or "permitlocalcommand" in lower
                or "localcommand" in lower
                or ("match" in lower and "exec" in lower)
            )
            option_o, option_o_needs_next = _remote_short_option(raw, tool, "o")
            proxy_option = option_o and ((option_o_needs_next and proxy_in_next) or proxy_in_raw)
            config_present = tool in ("ssh", "scp", "sftp") and _remote_short_option(raw, tool, "F")[0]
            transport_present = (
                _remote_short_option(raw, tool, "e")[0]
                or _long_flag(raw, "--rsh")
                or _long_flag(raw, "--rsync-path")
                or _remote_short_option(raw, tool, "S")[0]
                or (tool in ("scp", "sftp") and _remote_short_option(raw, tool, "D")[0])
            )
            if proxy_option:
                _add_danger(findings, "critical", "ssh option can execute a local proxy command", index, "-o")
            elif config_present:
                _add_danger(findings, "critical", "ssh client config file can contain a local proxy command", index, "-F")
            elif transport_present:
                _add_danger(findings, "critical", "remote shell or transport override can execute arbitrary commands", index, raw)

        if tool in ("node", "nodejs", "bun", "deno"):
            if raw in ("-e", "-p", "-pe") or _long_flag(raw, "--eval") or _long_flag(raw, "--print"):
                _add_danger(findings, "critical", "JavaScript runtime eval flag detected", index, raw)
            elif raw == "-r" or _long_flag(raw, "--require") or _long_flag(raw, "--import") or _long_flag(raw, "--experimental-loader"):
                _add_danger(
                    findings,
                    "critical",
                    "JavaScript runtime preload or import flag can execute attacker controlled code",
                    index,
                    raw,
                )

        if re.match(r"^python(?:\d+(?:\.\d+)*)?$", tool) or tool == "pypy":
            python_option = _python_dangerous_option(raw)
            if python_option == "c":
                _add_danger(findings, "critical", "Python -c executes attacker controlled code", index, raw)
            elif python_option == "m":
                _add_danger(findings, "high", "Python -m executes a module selected by argv", index, raw)
            elif raw == "-":
                _add_danger(findings, "critical", "Python stdin execution marker detected", index, "-")

        if tool == "perl":
            perl_option = _perl_dangerous_option(raw)
            if perl_option in ("e", "E"):
                _add_danger(findings, "critical", "Perl eval flag detected", index, raw)
            elif perl_option in ("M", "m"):
                _add_danger(findings, "critical", "Perl module preload flag can execute attacker controlled code", index, raw)
        if tool == "ruby" and _ruby_dangerous_option(raw) is not None:
            _add_danger(findings, "critical", "Ruby eval or require flag detected", index, raw)
        if tool == "php" and _php_dangerous_option(raw) is not None:
            _add_danger(findings, "critical", "PHP inline code execution flag detected", index, raw)

        if tool == "env" and (_short_flag(raw, "-S") or _long_flag(raw, "--split-string")):
            _add_danger(findings, "high", "env split-string mode can hide a nested command inside one argument", index, raw)

        if tool == "xargs" and (
            _short_flag(raw, "-I")
            or _short_cluster_includes(raw, "I")
            or _short_flag(raw, "-J")
            or _short_cluster_includes(raw, "J")
            or _long_flag(raw, "--replace")
        ):
            _add_danger(findings, "high", "xargs replacement mode can turn stdin into command arguments", index, raw)

    if tool == "env" and _env_nested_command(args):
        findings.append(
            _finding(
                CODES["DANGEROUS_GADGET"],
                "high",
                "env can invoke a nested command that must be audited separately",
                index=0,
                flag="env",
            )
        )
    return findings


def _coerce_argv(argv: Any) -> Optional[List[Any]]:
    if isinstance(argv, (str, bytes, bytearray)) or not isinstance(argv, Sequence):
        return None
    try:
        return list(argv)
    except Exception:
        return None


def _default_invocation_options() -> Dict[str, Any]:
    return {
        "allow_shell_binary": False,
        "allow_batch_extensions": False,
        "allow_dangerous_flags": False,
        "max_arg_bytes": DEFAULT_MAX_ARG_BYTES,
        "max_args": DEFAULT_MAX_ARGS,
        "max_argv_bytes": DEFAULT_MAX_ARGV_BYTES,
    }


def collect_invocation_findings(
    argv: Any,
    options: Optional[Mapping[str, Any]] = None,
    *,
    require_allowlist: bool,
    audit_mode: bool = False,
) -> Tuple[List[Finding], Dict[str, Any], List[Any], bool]:
    findings: List[Finding] = []
    try:
        normalized = normalize_invocation_options(options)
    except ShellCageError as error:
        findings.append(_error_finding(error))
        normalized = _default_invocation_options()

    coerced = _coerce_argv(argv)
    if coerced is None:
        findings.append(
            _finding(CODES["ARGV_TYPE"], "critical", "command input must be an argv sequence, never a command line string")
        )
        return findings, normalized, [], False
    if len(coerced) == 0:
        findings.append(_finding(CODES["ARGV_EMPTY"], "critical", "argv sequence must not be empty"))
        return findings, normalized, [], False

    command = coerced[0]
    args = coerced[1:]
    info, executable_findings = inspect_executable_syntax(command)
    findings.extend(executable_findings)
    inspect_executable_policy(command, info, normalized, findings, require_allowlist)
    arg_findings, args_are_strings = inspect_argv(args, normalized)
    findings.extend(arg_findings)
    if args_are_strings and (audit_mode or normalized.get("allow_dangerous_flags") is not True):
        string_args = [value for value in args if isinstance(value, str)]
        if len(string_args) == len(args) and isinstance(command, str):
            findings.extend(audit_dangerous_argv(command, string_args))
    return findings, normalized, coerced, args_are_strings


def validate_invocation(argv: Any, **options: Any) -> ValidationReport:
    """Validate a strict argv sequence without executing it.

    A string or bytes command line is always rejected. Pass a sequence such as
    ``["/usr/bin/git", "status"]``. Execution requires an explicit executable
    allowlist through ``allow_executables``.
    """

    findings, _normalized, coerced, _args_ok = collect_invocation_findings(
        argv,
        options,
        require_allowlist=True,
        audit_mode=False,
    )
    command = coerced[0] if coerced and isinstance(coerced[0], str) else ""
    args = tuple(coerced[1:]) if coerced else tuple()
    return ValidationReport(ok=len(findings) == 0, command=command, args=args, findings=tuple(findings))


def audit_argv(command: Any, args: Any = (), **options: Any) -> Tuple[Finding, ...]:
    """Audit an already separated executable and argument sequence.

    This is a static detector and does not require an executable allowlist.
    It never joins the values into a shell command line.
    """

    findings: List[Finding] = []
    if isinstance(args, (str, bytes, bytearray)) or not isinstance(args, Sequence):
        argv = [command]
        collected, _normalized, _coerced, _args_ok = collect_invocation_findings(
            argv,
            options,
            require_allowlist=False,
            audit_mode=True,
        )
        findings.extend(collected)
        findings.append(
            _finding(CODES["ARGS_NOT_ARRAY"], "critical", "arguments must be supplied as a sequence, never as a command line string")
        )
        return tuple(findings)
    argv = [command] + list(args)
    collected, _normalized, _coerced, _args_ok = collect_invocation_findings(
        argv,
        options,
        require_allowlist=False,
        audit_mode=True,
    )
    return tuple(collected)


def assert_valid_invocation(argv: Any, options: Optional[Mapping[str, Any]] = None) -> Tuple[List[str], Dict[str, Any]]:
    report = validate_invocation(argv, **dict(options or {}))
    if not report.ok:
        first = report.findings[0]
        fail(first.code, first.message, {"findings": tuple(finding.to_dict() for finding in report.findings)})
    normalized = normalize_invocation_options(options)
    coerced = _coerce_argv(argv) or []
    return [str(item) for item in coerced], normalized


def prepare_environment(options: Mapping[str, Any]) -> Mapping[str, str]:
    source = options.get("env") if "env" in options else os.environ
    return sanitize_env(
        source,
        allow_env=options.get("allow_env"),
        max_value_bytes=options.get("max_env_value_bytes"),
    )
