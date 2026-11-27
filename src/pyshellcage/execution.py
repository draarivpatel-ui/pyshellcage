"""Bounded no-shell child process execution."""

from __future__ import annotations

import math
import os
import subprocess
import threading
import time
from collections.abc import Sequence
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .errors import CODES, ShellCageError, fail
from .invocation import assert_valid_invocation, prepare_environment
from .models import ExecResult

DEFAULT_TIMEOUT_SECONDS = 15.0
MAX_TIMEOUT_SECONDS = 120.0
DEFAULT_KILL_GRACE_SECONDS = 0.25
MAX_KILL_GRACE_SECONDS = 10.0
DEFAULT_MAX_STDOUT_BYTES = 1024 * 1024
DEFAULT_MAX_STDERR_BYTES = 1024 * 1024
DEFAULT_MAX_STDIN_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
READ_CHUNK_BYTES = 8192
_STDIN_CHUNK_BYTES = 65536


def _strict_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        fail(CODES["CONFIG_INVALID"], name + " must be a boolean")
    return value


def _integer_limit(value: Any, default: int, minimum: int, maximum: int, name: str) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > maximum:
        fail(CODES["OUTPUT_LIMIT_INVALID"], name + " must be an integer in range")
    return value


def _timeout_value(value: Any, default: float = DEFAULT_TIMEOUT_SECONDS) -> float:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail(CODES["TIMEOUT_INVALID"], "timeout_seconds must be a finite number in range")
    result = float(value)
    if not math.isfinite(result) or result <= 0.0 or result > MAX_TIMEOUT_SECONDS:
        fail(CODES["TIMEOUT_INVALID"], "timeout_seconds must be a finite number in range")
    return result


def _grace_value(value: Any) -> float:
    if value is None:
        return DEFAULT_KILL_GRACE_SECONDS
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail(CODES["TIMEOUT_INVALID"], "kill_grace_seconds must be a finite number in range")
    result = float(value)
    if not math.isfinite(result) or result < 0.01 or result > MAX_KILL_GRACE_SECONDS:
        fail(CODES["TIMEOUT_INVALID"], "kill_grace_seconds must be a finite number in range")
    return result


def _has_forbidden_path_characters(value: str) -> bool:
    return "\x00" in value or any(ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F for char in value)


def _real_existing_directory(value: str, error_code: str) -> str:
    try:
        real = os.path.realpath(value)
    except Exception:
        fail(error_code, "working directory does not exist or cannot be resolved")
    if not os.path.exists(real):
        fail(error_code, "working directory does not exist or cannot be resolved")
    if not os.path.isdir(real):
        fail(CODES["CWD_NOT_DIRECTORY"], "working directory is not a directory")
    return real


def _path_contained(root: str, candidate: str) -> bool:
    root_compare = os.path.normcase(root)
    candidate_compare = os.path.normcase(candidate)
    try:
        return os.path.commonpath([root_compare, candidate_compare]) == root_compare
    except (ValueError, TypeError):
        return False


def prepare_cwd(options: Mapping[str, Any]) -> Optional[str]:
    has_cwd = "cwd" in options
    has_roots = "allowed_cwd_roots" in options
    if not has_cwd and not has_roots:
        return None

    if has_cwd:
        cwd = options.get("cwd")
        if not isinstance(cwd, str) or cwd == "" or _has_forbidden_path_characters(cwd):
            fail(CODES["CWD_TYPE"], "cwd must be a non-empty string without control characters")
        if not os.path.isabs(cwd):
            fail(CODES["CWD_NOT_ABSOLUTE"], "cwd must be an absolute path")
        candidate = _real_existing_directory(cwd, CODES["CWD_NOT_FOUND"])
    else:
        candidate = _real_existing_directory(os.getcwd(), CODES["CWD_NOT_FOUND"])

    if has_roots:
        roots_value = options.get("allowed_cwd_roots")
        if (
            isinstance(roots_value, (str, bytes, bytearray))
            or not isinstance(roots_value, (list, tuple))
            or len(roots_value) == 0
            or len(roots_value) > 64
        ):
            fail(CODES["CWD_ROOT_INVALID"], "allowed_cwd_roots must be a non-empty sequence of absolute directories")
        roots = []
        for root in roots_value:
            if not isinstance(root, str) or root == "" or _has_forbidden_path_characters(root) or not os.path.isabs(root):
                fail(CODES["CWD_ROOT_INVALID"], "allowed_cwd_roots entries must be absolute directory paths")
            roots.append(_real_existing_directory(root, CODES["CWD_ROOT_INVALID"]))
        if not any(_path_contained(root, candidate) for root in roots):
            fail(CODES["CWD_OUTSIDE_ROOT"], "working directory escapes every allowed root")
    return candidate


def normalize_execution_options(options: Mapping[str, Any]) -> Dict[str, Any]:
    normalized = dict(options)
    normalized["timeout_seconds"] = _timeout_value(normalized.get("timeout_seconds"))
    normalized["kill_grace_seconds"] = _grace_value(normalized.get("kill_grace_seconds"))
    normalized["max_stdout_bytes"] = _integer_limit(
        normalized.get("max_stdout_bytes"), DEFAULT_MAX_STDOUT_BYTES, 1, MAX_OUTPUT_BYTES, "max_stdout_bytes"
    )
    normalized["max_stderr_bytes"] = _integer_limit(
        normalized.get("max_stderr_bytes"), DEFAULT_MAX_STDERR_BYTES, 1, MAX_OUTPUT_BYTES, "max_stderr_bytes"
    )
    normalized["max_stdin_bytes"] = _integer_limit(
        normalized.get("max_stdin_bytes"), DEFAULT_MAX_STDIN_BYTES, 0, MAX_OUTPUT_BYTES, "max_stdin_bytes"
    )

    stdin_value = normalized.get("stdin")
    if stdin_value is not None and not isinstance(stdin_value, (str, bytes)):
        fail(CODES["STDIN_INVALID"], "stdin must be a string or bytes")
    if isinstance(stdin_value, str):
        try:
            stdin_bytes = stdin_value.encode("utf-8")
        except UnicodeEncodeError:
            fail(CODES["STDIN_INVALID"], "stdin must be valid UTF-8 when supplied as text")
    elif isinstance(stdin_value, bytes):
        stdin_bytes = stdin_value
    else:
        stdin_bytes = b""
    if len(stdin_bytes) > normalized["max_stdin_bytes"]:
        fail(CODES["STDIN_TOO_LARGE"], "stdin exceeds the configured byte limit")
    normalized["stdin_bytes"] = stdin_bytes
    normalized["env_object"] = prepare_environment(normalized)
    normalized["cwd_path"] = prepare_cwd(normalized)
    return normalized


def incomplete_utf8_suffix_length(data: bytes) -> int:
    """Return the trailing byte count of an incomplete UTF-8 sequence."""

    length = len(data)
    start = max(0, length - 4)
    index = length - 1
    while index >= start:
        byte = data[index]
        if byte & 0xC0 == 0x80:
            index -= 1
            continue
        if byte & 0x80 == 0:
            return 0
        if byte & 0xE0 == 0xC0:
            needed = 2
        elif byte & 0xF0 == 0xE0:
            needed = 3
        elif byte & 0xF8 == 0xF0:
            needed = 4
        else:
            return 0
        return length - index if length - index < needed else 0
    return 0


def decode_captured_utf8(data: bytes, truncated: bool) -> str:
    if truncated:
        incomplete = incomplete_utf8_suffix_length(data)
        if incomplete:
            data = data[:-incomplete]
        # A byte cap is a hard byte cap. Replacement characters can expand one
        # invalid input byte into three output bytes, so truncated output drops
        # undecodable bytes instead of decoding them to U+FFFD.
        return data.decode("utf-8", errors="ignore")
    return data.decode("utf-8", errors="replace")


def _os_error_failure(error: BaseException) -> ShellCageError:
    system_code = getattr(error, "errno", None)
    details = {"system_code": str(system_code) if system_code is not None else "UNKNOWN"}
    return ShellCageError(CODES["SPAWN_FAILED"], "child process failed to start", details)


def safe_run(argv: Sequence[str], **options: Any) -> ExecResult:
    """Run an allowlisted argv with no shell and bounded input, output, and time.

    The first sequence element is the executable. A string or bytes command
    line is rejected before this function reaches subprocess. ``shell=False``
    is unconditional and there is no API option that can enable a shell.
    """

    argv_list, invocation_options = assert_valid_invocation(argv, options)
    normalized = normalize_execution_options(invocation_options)

    popen_kwargs = {
        "shell": False,
        "env": dict(normalized["env_object"]),
        "stdin": subprocess.PIPE,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "close_fds": True,
    }
    if normalized["cwd_path"] is not None:
        popen_kwargs["cwd"] = normalized["cwd_path"]

    try:
        process = subprocess.Popen(argv_list, **popen_kwargs)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise _os_error_failure(error) from error

    started = time.monotonic()
    stdout_parts: List[bytes] = []
    stderr_parts: List[bytes] = []
    capture_state = {
        "stdout_bytes": 0,
        "stderr_bytes": 0,
        "truncated_stdout": False,
        "truncated_stderr": False,
    }
    state_lock = threading.Lock()
    terminate_lock = threading.Lock()
    terminate_state = {"requested": False, "timer": None}

    def force_kill() -> None:
        try:
            if process.poll() is None:
                process.kill()
        except Exception:
            pass

    def request_termination() -> None:
        with terminate_lock:
            if terminate_state["requested"]:
                return
            terminate_state["requested"] = True
        try:
            process.terminate()
        except Exception:
            pass
        timer = threading.Timer(normalized["kill_grace_seconds"], force_kill)
        timer.daemon = True
        terminate_state["timer"] = timer
        timer.start()

    def reader(stream: Any, stream_name: str) -> None:
        bytes_key = stream_name + "_bytes"
        truncated_key = "truncated_" + stream_name
        cap = normalized["max_" + stream_name + "_bytes"]
        try:
            while True:
                try:
                    chunk = os.read(stream.fileno(), READ_CHUNK_BYTES)
                except (OSError, ValueError):
                    break
                if not chunk:
                    break
                breach = False
                with state_lock:
                    captured = capture_state[bytes_key]
                    remaining = cap - captured
                    if remaining > 0:
                        accepted = chunk[:remaining]
                        if accepted:
                            if stream_name == "stdout":
                                stdout_parts.append(accepted)
                            else:
                                stderr_parts.append(accepted)
                        capture_state[bytes_key] = captured + len(accepted)
                    if len(chunk) > max(0, remaining):
                        capture_state[truncated_key] = True
                        breach = True
                if breach:
                    request_termination()
        finally:
            pass

    def writer(data: bytes) -> None:
        try:
            if process.stdin is None:
                return
            view = memoryview(data)
            offset = 0
            while offset < len(view):
                end = min(offset + _STDIN_CHUNK_BYTES, len(view))
                try:
                    written = process.stdin.write(view[offset:end])
                    process.stdin.flush()
                except (BrokenPipeError, OSError, ValueError):
                    return
                if written is None:
                    written = end - offset
                if written <= 0:
                    return
                offset += written
        finally:
            try:
                if process.stdin is not None:
                    process.stdin.close()
            except Exception:
                pass

    stdout_thread = threading.Thread(target=reader, args=(process.stdout, "stdout"), daemon=True)
    stderr_thread = threading.Thread(target=reader, args=(process.stderr, "stderr"), daemon=True)
    stdin_data = normalized["stdin_bytes"]
    writer_thread = threading.Thread(target=writer, args=(stdin_data,), daemon=True)
    stdout_thread.start()
    stderr_thread.start()
    writer_thread.start()

    timed_out = False
    try:
        try:
            process.wait(timeout=normalized["timeout_seconds"])
        except subprocess.TimeoutExpired:
            timed_out = True
            request_termination()
            while process.poll() is None:
                time.sleep(0.005)
    finally:
        timer = terminate_state.get("timer")
        if timer is not None:
            timer.cancel()
        # A child can spawn a grandchild that inherits the pipe and then exit.
        # The direct child is already finished, so joining forever would turn a
        # bounded run into an unbounded wait. Give readers a short drain window,
        # close the parent ends, and never let daemon cleanup threads block the
        # result. Captured bytes remain bounded regardless of when those threads
        # wake up.
        for thread, stream in (
            (stdout_thread, process.stdout),
            (stderr_thread, process.stderr),
            (writer_thread, process.stdin),
        ):
            thread.join(0.2)
            if thread.is_alive():
                try:
                    if stream is not None:
                        stream.close()
                except Exception:
                    pass
                thread.join(0.2)
        for stream in (process.stdin, process.stdout, process.stderr):
            try:
                if stream is not None:
                    stream.close()
            except Exception:
                pass

    duration_ms = (time.monotonic() - started) * 1000.0
    stdout_bytes = b"".join(stdout_parts)
    stderr_bytes = b"".join(stderr_parts)
    truncated_stdout = bool(capture_state["truncated_stdout"])
    truncated_stderr = bool(capture_state["truncated_stderr"])
    returncode = process.returncode
    if returncode is not None and returncode < 0:
        exit_code = None
        signal_num = -returncode
    else:
        exit_code = returncode
        signal_num = None

    return ExecResult(
        command=tuple(argv_list),
        exit_code=exit_code,
        signal_num=signal_num,
        stdout=decode_captured_utf8(stdout_bytes, truncated_stdout),
        stderr=decode_captured_utf8(stderr_bytes, truncated_stderr),
        timed_out=timed_out,
        truncated_stdout=truncated_stdout,
        truncated_stderr=truncated_stderr,
        duration_ms=duration_ms,
    )


def safe_popen(argv: Sequence[str], **options: Any) -> subprocess.Popen:
    """Open an allowlisted child process with ``shell=False`` and a scrubbed environment.

    The returned object uses pipes for stdin, stdout, and stderr. Output byte
    caps and stdin data are rejected because a raw Popen object cannot enforce
    them; use safe_run for the bounded harness. A supplied timeout is enforced
    by a terminate then kill watchdog thread.
    """

    if "stdin" in options or "max_stdin_bytes" in options:
        fail(CODES["STDIN_INVALID"], "safe_popen does not write stdin data; use the returned pipe or safe_run")
    if "max_stdout_bytes" in options or "max_stderr_bytes" in options:
        fail(CODES["CONFIG_INVALID"], "safe_popen cannot enforce stdout or stderr byte caps; use safe_run")
    argv_list, invocation_options = assert_valid_invocation(argv, options)
    env_object = prepare_environment(invocation_options)
    cwd_path = prepare_cwd(invocation_options)
    popen_kwargs = {
        "shell": False,
        "env": dict(env_object),
        "stdin": subprocess.PIPE,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "close_fds": True,
    }
    if cwd_path is not None:
        popen_kwargs["cwd"] = cwd_path
    try:
        process = subprocess.Popen(argv_list, **popen_kwargs)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise _os_error_failure(error) from error

    if "timeout_seconds" in invocation_options:
        timeout_seconds = _timeout_value(invocation_options.get("timeout_seconds"))
        grace_seconds = _grace_value(invocation_options.get("kill_grace_seconds"))

        def watchdog() -> None:
            try:
                process.wait(timeout=timeout_seconds)
                return
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                return
            try:
                process.terminate()
            except Exception:
                pass
            try:
                process.wait(timeout=grace_seconds)
                return
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                return
            try:
                process.kill()
            except Exception:
                pass

        watcher = threading.Thread(target=watchdog, daemon=True)
        watcher.start()
    return process
