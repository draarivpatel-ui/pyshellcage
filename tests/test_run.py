"""Real subprocess integration and bounded execution tests."""

from __future__ import annotations

import json
import os
import signal
import sys
import tempfile
import time
import unittest
from pathlib import Path

from pyshellcage import CODES, ExecResult, ShellCageError, safe_popen, safe_run
from _matrix import add_matrix

PYTHON = sys.executable


def run_python(code, extra_argv=(), **options):
    merged = {
        "allow_executables": [PYTHON],
        "allow_dangerous_flags": True,
        "timeout_seconds": 4,
    }
    merged.update(options)
    return safe_run([PYTHON, "-c", code] + list(extra_argv), **merged)


def assert_error_code(testcase, code, function, *args, **kwargs):
    with testcase.assertRaises(ShellCageError) as caught:
        function(*args, **kwargs)
    testcase.assertEqual(code, caught.exception.code)
    return caught.exception


class SafeRunBasicTests(unittest.TestCase):
    def test_stdout_capture(self):
        result = run_python("print('hello')")
        self.assertEqual("hello\n", result.stdout)
        self.assertEqual("", result.stderr)
        self.assertEqual(0, result.exit_code)

    def test_stderr_capture(self):
        result = run_python("import sys;sys.stderr.write('err\\n')")
        self.assertEqual("err\n", result.stderr)
        self.assertEqual(0, result.exit_code)

    def test_nonzero_exit_code(self):
        result = run_python("raise SystemExit(7)")
        self.assertEqual(7, result.exit_code)
        self.assertIsNone(result.signal_num)

    def test_result_type_and_command(self):
        result = run_python("pass")
        self.assertIsInstance(result, ExecResult)
        self.assertEqual(PYTHON, result.command[0])
        self.assertEqual("-c", result.command[1])

    def test_result_is_frozen(self):
        result = run_python("pass")
        with self.assertRaises(Exception):
            result.stdout = "changed"

    def test_duration_is_nonnegative_float(self):
        result = run_python("pass")
        self.assertIsInstance(result.duration_ms, float)
        self.assertGreaterEqual(result.duration_ms, 0.0)

    def test_not_timed_out_or_truncated_for_small_output(self):
        result = run_python("print('x')")
        self.assertFalse(result.timed_out)
        self.assertFalse(result.truncated_stdout)
        self.assertFalse(result.truncated_stderr)

    def test_metacharacters_are_data_not_shell_syntax(self):
        payload = "; echo injected | cat $(echo x) `echo y` > /tmp/nope"
        result = run_python("import sys;print(sys.argv[1])", (payload,))
        self.assertEqual(payload + "\n", result.stdout)

    def test_argv_element_with_spaces_is_not_split(self):
        payload = "one two three"
        result = run_python("import sys;print(len(sys.argv));print(sys.argv[1])", (payload,))
        self.assertEqual("2\n" + payload + "\n", result.stdout)

    def test_stdin_text_is_delivered(self):
        result = run_python("import sys;print(sys.stdin.read())", stdin="abc")
        self.assertEqual("abc\n", result.stdout)

    def test_stdin_bytes_are_delivered(self):
        result = run_python("import sys;data=sys.stdin.buffer.read();print(data.decode())", stdin=b"abc")
        self.assertEqual("abc\n", result.stdout)

    def test_stdin_multibyte_text(self):
        result = run_python("import sys;print(sys.stdin.read())", stdin="€")
        self.assertEqual("€\n", result.stdout)


class SafeRunEnvironmentTests(unittest.TestCase):
    def test_environment_is_scrubbed_by_default(self):
        source = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LD_PRELOAD": "evil", "PYSHELLCAGE_TEST": "yes"}
        result = run_python("import json,os;print(json.dumps(sorted(os.environ)))", env=source)
        keys = json.loads(result.stdout)
        self.assertIn("PATH", keys)
        self.assertNotIn("LD_PRELOAD", keys)
        self.assertNotIn("PYSHELLCAGE_TEST", keys)

    def test_custom_allowlist_can_pass_safe_variable(self):
        source = {"PYSHELLCAGE_TEST": "yes"}
        result = run_python("import os;print(os.environ.get('PYSHELLCAGE_TEST',''))", env=source, allow_env=["PYSHELLCAGE_TEST"])
        self.assertEqual("yes\n", result.stdout)

    def test_hard_denylist_wins_over_custom_allowlist(self):
        source = {"PYTHONPATH": "/evil"}
        result = run_python(
            "import os;print('PYTHONPATH' in os.environ)",
            env=source,
            allow_env=["PYTHONPATH"],
        )
        self.assertEqual("False\n", result.stdout)

    def test_environment_value_never_interpreted(self):
        source = {"PYSHELLCAGE_TEST": "$(echo nope)"}
        result = run_python("import os;print(os.environ.get('PYSHELLCAGE_TEST',''))", env=source, allow_env=["PYSHELLCAGE_TEST"])
        self.assertEqual("$(echo nope)\n", result.stdout)


class SafeRunTruncationTests(unittest.TestCase):
    def test_stdout_ascii_cap(self):
        result = run_python("print('abcdef')", max_stdout_bytes=3)
        self.assertEqual("abc", result.stdout)
        self.assertTrue(result.truncated_stdout)

    def test_stderr_ascii_cap(self):
        result = run_python("import sys;sys.stderr.write('abcdef')", max_stderr_bytes=3)
        self.assertEqual("abc", result.stderr)
        self.assertTrue(result.truncated_stderr)

    def test_exact_cap_is_not_truncated(self):
        result = run_python("import sys;sys.stdout.write('abc')", max_stdout_bytes=3)
        self.assertEqual("abc", result.stdout)
        self.assertFalse(result.truncated_stdout)

    def test_multibyte_truncation_omits_incomplete_suffix(self):
        result = run_python("import sys;sys.stdout.write('€€€€')", max_stdout_bytes=4)
        self.assertEqual("€", result.stdout)
        self.assertNotIn("\ufffd", result.stdout)
        self.assertLessEqual(len(result.stdout.encode("utf-8")), 4)
        self.assertTrue(result.truncated_stdout)

    def test_large_output_does_not_exceed_memory_cap(self):
        result = run_python("print('x' * 1000000)", max_stdout_bytes=16)
        self.assertEqual("x" * 16, result.stdout)
        self.assertTrue(result.truncated_stdout)

    def test_invalid_utf8_in_truncated_output_does_not_expand_byte_cap(self):
        code = "import sys;sys.stdout.buffer.write(b'\\xff' + b'x' * 1000)"
        result = run_python(code, max_stdout_bytes=4)
        self.assertNotIn("\ufffd", result.stdout)
        self.assertLessEqual(len(result.stdout.encode("utf-8")), 4)
        self.assertTrue(result.truncated_stdout)

    def test_cap_breach_kills_child(self):
        result = run_python("import sys,time;print('x' * 1000);sys.stdout.flush();time.sleep(10)", max_stdout_bytes=10)
        self.assertTrue(result.truncated_stdout)
        self.assertNotEqual(0, result.exit_code)
        self.assertLess(result.duration_ms, 3500)


class SafeRunTimeoutTests(unittest.TestCase):
    def test_timeout_terminates_sleeping_child(self):
        result = run_python("import time;time.sleep(10)", timeout_seconds=0.1)
        self.assertTrue(result.timed_out)
        self.assertNotEqual(0, result.exit_code)
        self.assertLess(result.duration_ms, 3000)

    def test_timeout_kill_escalation_sigterm_then_sigkill(self):
        code = "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(10)"
        result = run_python(code, timeout_seconds=0.1, kill_grace_seconds=0.05)
        self.assertTrue(result.timed_out)
        if os.name != "nt":
            self.assertEqual(signal.SIGKILL, result.signal_num)

    def test_fast_exit_before_timeout_not_marked(self):
        result = run_python("pass", timeout_seconds=2)
        self.assertFalse(result.timed_out)

    def test_exited_child_with_pipe_inheriting_grandchild_does_not_hang(self):
        sleeper = "/bin/sleep" if os.path.exists("/bin/sleep") else "sleep"
        code = "import subprocess;subprocess.Popen([%r, %r]);print('done')" % (sleeper, "2")
        started = time.monotonic()
        result = run_python(code, timeout_seconds=4)
        elapsed = time.monotonic() - started
        self.assertIn("done", result.stdout)
        self.assertLess(elapsed, 3.5)


class SafeRunCwdTests(unittest.TestCase):
    def test_cwd_inside_allowed_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = os.path.join(directory, "root")
            work = os.path.join(root, "work")
            os.makedirs(work)
            result = run_python("import os;print(os.path.realpath(os.getcwd()))", cwd=work, allowed_cwd_roots=[root])
        self.assertEqual(os.path.realpath(work) + "\n", result.stdout)

    def test_cwd_equal_to_allowed_root(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run_python("import os;print(os.path.realpath(os.getcwd()))", cwd=directory, allowed_cwd_roots=[directory])
        self.assertEqual(os.path.realpath(directory) + "\n", result.stdout)

    def test_sibling_prefix_escape_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = os.path.join(directory, "work")
            sibling = os.path.join(directory, "work-evil")
            os.makedirs(root)
            os.makedirs(sibling)
            assert_error_code(
                self,
                CODES["CWD_OUTSIDE_ROOT"],
                safe_run,
                [PYTHON, "-c", "pass"],
                allow_executables=[PYTHON],
                allow_dangerous_flags=True,
                cwd=sibling,
                allowed_cwd_roots=[root],
            )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_symlink_cwd_escape_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = os.path.join(directory, "root")
            outside = os.path.join(directory, "outside")
            link = os.path.join(root, "link")
            os.makedirs(root)
            os.makedirs(outside)
            os.symlink(outside, link)
            assert_error_code(
                self,
                CODES["CWD_OUTSIDE_ROOT"],
                safe_run,
                [PYTHON, "-c", "pass"],
                allow_executables=[PYTHON],
                allow_dangerous_flags=True,
                cwd=link,
                allowed_cwd_roots=[root],
            )

    def test_relative_cwd_rejected(self):
        assert_error_code(
            self,
            CODES["CWD_NOT_ABSOLUTE"],
            safe_run,
            [PYTHON, "-c", "pass"],
            allow_executables=[PYTHON],
            allow_dangerous_flags=True,
            cwd="relative",
        )

    def test_file_cwd_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            file_path = os.path.join(directory, "file")
            Path(file_path).write_text("x", encoding="ascii")
            assert_error_code(
                self,
                CODES["CWD_NOT_DIRECTORY"],
                safe_run,
                [PYTHON, "-c", "pass"],
                allow_executables=[PYTHON],
                allow_dangerous_flags=True,
                cwd=file_path,
            )


class SafeRunValidationTests(unittest.TestCase):
    def test_string_command_line_rejected_before_spawn(self):
        assert_error_code(self, CODES["ARGV_TYPE"], safe_run, "python3 -c pass", allow_executables=[PYTHON])

    def test_shell_true_rejected(self):
        assert_error_code(self, CODES["SHELL_OPTION_FORBIDDEN"], safe_run, [PYTHON], allow_executables=[PYTHON], shell=True)

    def test_missing_allowlist_rejected(self):
        assert_error_code(self, CODES["EXECUTABLE_ALLOWLIST_REQUIRED"], safe_run, [PYTHON])

    def test_dangerous_python_c_rejected_without_override(self):
        assert_error_code(
            self,
            CODES["DANGEROUS_FLAG"],
            safe_run,
            [PYTHON, "-c", "pass"],
            allow_executables=[PYTHON],
        )

    def test_nonexistent_allowlisted_executable_spawn_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = os.path.join(directory, "missing-tool")
            assert_error_code(self, CODES["SPAWN_FAILED"], safe_run, [missing], allow_executables=[missing])

    def test_stdin_too_large_rejected_before_spawn(self):
        assert_error_code(
            self,
            CODES["STDIN_TOO_LARGE"],
            safe_run,
            [PYTHON, "-c", "pass"],
            allow_executables=[PYTHON],
            allow_dangerous_flags=True,
            stdin="abcde",
            max_stdin_bytes=4,
        )

    def test_stdin_invalid_type_rejected(self):
        assert_error_code(
            self,
            CODES["STDIN_INVALID"],
            safe_run,
            [PYTHON, "-c", "pass"],
            allow_executables=[PYTHON],
            allow_dangerous_flags=True,
            stdin=123,
        )


class SafeRunInvalidConfigMatrixTests(unittest.TestCase):
    pass


_INVALID_EXECUTION_CASES = []
for _value in (0, -1, float("nan"), float("inf"), True, "1"):
    _INVALID_EXECUTION_CASES.append(({"timeout_seconds": _value}, CODES["TIMEOUT_INVALID"]))
for _value in (0, -1, True, 64 * 1024 * 1024 + 1):
    _INVALID_EXECUTION_CASES.append(({"max_stdout_bytes": _value}, CODES["OUTPUT_LIMIT_INVALID"]))
    _INVALID_EXECUTION_CASES.append(({"max_stderr_bytes": _value}, CODES["OUTPUT_LIMIT_INVALID"]))
for _value in (-1, True, 64 * 1024 * 1024 + 1):
    _INVALID_EXECUTION_CASES.append(({"max_stdin_bytes": _value}, CODES["OUTPUT_LIMIT_INVALID"]))


def _invalid_execution_body(self, extra, code):
    kwargs = {
        "allow_executables": [PYTHON],
        "allow_dangerous_flags": True,
    }
    kwargs.update(extra)
    assert_error_code(self, code, safe_run, [PYTHON, "-c", "pass"], **kwargs)


add_matrix(SafeRunInvalidConfigMatrixTests, "invalid_execution_config", _INVALID_EXECUTION_CASES, _invalid_execution_body)


class SafePopenTests(unittest.TestCase):
    def test_safe_popen_basic_stdout(self):
        process = safe_popen(
            [PYTHON, "-c", "print('popen')"],
            allow_executables=[PYTHON],
            allow_dangerous_flags=True,
        )
        stdout, stderr = process.communicate(timeout=4)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()
        self.assertEqual(b"popen\n", stdout)
        self.assertEqual(b"", stderr)
        self.assertEqual(0, process.returncode)

    def test_safe_popen_shell_true_rejected(self):
        assert_error_code(self, CODES["SHELL_OPTION_FORBIDDEN"], safe_popen, [PYTHON], allow_executables=[PYTHON], shell=True)

    def test_safe_popen_stdout_cap_rejected(self):
        assert_error_code(
            self,
            CODES["CONFIG_INVALID"],
            safe_popen,
            [PYTHON, "-c", "pass"],
            allow_executables=[PYTHON],
            allow_dangerous_flags=True,
            max_stdout_bytes=10,
        )

    def test_safe_popen_stdin_data_rejected(self):
        assert_error_code(
            self,
            CODES["STDIN_INVALID"],
            safe_popen,
            [PYTHON, "-c", "pass"],
            allow_executables=[PYTHON],
            allow_dangerous_flags=True,
            stdin=b"x",
        )

    def test_safe_popen_environment_is_scrubbed(self):
        process = safe_popen(
            [PYTHON, "-c", "import os;print('LD_PRELOAD' in os.environ)"],
            allow_executables=[PYTHON],
            allow_dangerous_flags=True,
            env={"LD_PRELOAD": "evil"},
        )
        stdout, _stderr = process.communicate(timeout=4)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()
        self.assertEqual(b"False\n", stdout)

    def test_safe_popen_timeout_watchdog_terminates(self):
        process = safe_popen(
            [PYTHON, "-c", "import time;time.sleep(10)"],
            allow_executables=[PYTHON],
            allow_dangerous_flags=True,
            timeout_seconds=0.1,
        )
        deadline = time.monotonic() + 4
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertIsNotNone(process.poll())
        self.assertNotEqual(0, process.returncode)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()


if __name__ == "__main__":
    unittest.main()
