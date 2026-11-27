"""Command line audit interface for pyshellcage."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import unicodedata
from collections.abc import Mapping
from typing import Any, Optional, Sequence, Tuple

from .env import audit_env
from .errors import CODES, ShellCageError, fail
from .invocation import audit_argv

MAX_ENV_JSON_BYTES = 1024 * 1024


def neutralize_terminal_text(value: Any) -> str:
    """Remove terminal control and bidirectional formatting characters."""

    text = str(value)
    output = []
    for char in text:
        category = unicodedata.category(char)
        if category in ("Cc", "Cf"):
            output.append("?")
        else:
            output.append(char)
    return "".join(output)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pyshellcage",
        description="Audit argv and environment input without invoking a shell.",
        allow_abbrev=False,
    )
    subparsers = parser.add_subparsers(dest="subcommand")

    audit_parser = subparsers.add_parser("audit", allow_abbrev=False, help="audit one separated argv")
    audit_parser.add_argument("--json", action="store_true", dest="json_output")
    audit_parser.add_argument("argv", nargs=argparse.REMAINDER)

    env_parser = subparsers.add_parser("audit-env", allow_abbrev=False, help="audit environment keys without values")
    env_parser.add_argument("--env-json", dest="env_json")
    env_parser.add_argument("--json", action="store_true", dest="json_output")
    return parser


def _print_json(payload: Mapping[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")))


def _public_finding(finding: Any) -> dict[str, Any]:
    return finding.to_dict()


def _print_findings_human(findings: Sequence[Any]) -> None:
    if not findings:
        print("clean")
        return
    for finding in findings:
        location = ""
        if finding.index is not None:
            location = " index=" + str(finding.index)
        key = ""
        if finding.key is not None:
            key = " key=" + neutralize_terminal_text(finding.key)
        flag = ""
        if finding.flag is not None:
            flag = " flag=" + neutralize_terminal_text(finding.flag)
        print(
            neutralize_terminal_text(finding.severity)
            + " "
            + neutralize_terminal_text(finding.code)
            + location
            + key
            + flag
            + " - "
            + neutralize_terminal_text(finding.message)
        )


def _secure_read_env_json(path: str, max_bytes: int = MAX_ENV_JSON_BYTES) -> bytes:
    if not isinstance(path, str) or path == "" or "\x00" in path:
        fail(CODES["CONFIG_INVALID"], "environment JSON path must be a non-empty string")
    try:
        initial_stat = os.lstat(path)
    except OSError:
        fail(CODES["CONFIG_INVALID"], "environment JSON file cannot be inspected")
    if stat.S_ISLNK(initial_stat.st_mode):
        fail(CODES["CONFIG_INVALID"], "environment JSON file must not be a symlink")

    flags = os.O_RDONLY
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    nonblock = getattr(os, "O_NONBLOCK", 0)
    if nofollow:
        flags |= nofollow
    if nonblock:
        flags |= nonblock
    try:
        descriptor = os.open(path, flags)
    except OSError:
        fail(CODES["CONFIG_INVALID"], "environment JSON file cannot be opened safely")

    try:
        final_stat = os.fstat(descriptor)
        if not stat.S_ISREG(final_stat.st_mode):
            fail(CODES["CONFIG_INVALID"], "environment JSON input must be a regular file")
        if (initial_stat.st_dev, initial_stat.st_ino) != (final_stat.st_dev, final_stat.st_ino):
            fail(CODES["CONFIG_INVALID"], "environment JSON file changed while being opened")
        if final_stat.st_size > max_bytes:
            fail(CODES["CONFIG_INVALID"], "environment JSON file exceeds the byte limit")

        chunks = []
        total = 0
        while total <= max_bytes:
            try:
                chunk = os.read(descriptor, min(8192, max_bytes + 1 - total))
            except BlockingIOError:
                continue
            except OSError:
                fail(CODES["CONFIG_INVALID"], "environment JSON file cannot be read")
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > max_bytes:
            fail(CODES["CONFIG_INVALID"], "environment JSON file exceeds the byte limit")
        return b"".join(chunks)
    finally:
        try:
            os.close(descriptor)
        except Exception:
            pass


def _load_env_json(path: str) -> Mapping[str, Any]:
    raw = _secure_read_env_json(path)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        fail(CODES["CONFIG_INVALID"], "environment JSON file must be valid UTF-8")
    try:
        parsed = json.loads(text)
    except ValueError:
        fail(CODES["CONFIG_INVALID"], "environment JSON file must contain a JSON object")
    if not isinstance(parsed, dict):
        fail(CODES["CONFIG_INVALID"], "environment JSON file must contain a JSON object")
    return parsed


def _audit_command(argv: Sequence[str], json_output: bool) -> int:
    values = list(argv)
    if not values or values[0] != "--":
        print("usage error: audit requires -- followed by a command argv", file=sys.stderr)
        return 2
    values = values[1:]
    if not values:
        print("usage error: audit requires -- followed by a command argv", file=sys.stderr)
        return 2
    command = values[0]
    args = values[1:]
    findings = audit_argv(command, args)
    if json_output:
        _print_json(
            {
                "ok": len(findings) == 0,
                "command": command,
                "arg_count": len(args),
                "findings": [_public_finding(finding) for finding in findings],
            }
        )
    else:
        _print_findings_human(findings)
    return 1 if findings else 0


def _audit_environment(env_json: Optional[str], json_output: bool) -> int:
    try:
        source = _load_env_json(env_json) if env_json is not None else os.environ
    except ShellCageError as error:
        print("usage error: " + neutralize_terminal_text(error.message), file=sys.stderr)
        return 2
    findings = audit_env(source, include_unlisted=True)
    if json_output:
        _print_json(
            {
                "ok": len(findings) == 0,
                "entries": len(source),
                "values_printed": False,
                "findings": [_public_finding(finding) for finding in findings],
            }
        )
    else:
        _print_findings_human(findings)
    return 1 if findings else 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        parser.print_usage(sys.stderr)
        return 2
    try:
        namespace = parser.parse_args(arguments)
    except SystemExit as error:
        try:
            return int(error.code)
        except Exception:
            return 2

    if namespace.subcommand == "audit":
        return _audit_command(namespace.argv, namespace.json_output)
    if namespace.subcommand == "audit-env":
        return _audit_environment(namespace.env_json, namespace.json_output)
    parser.print_usage(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
