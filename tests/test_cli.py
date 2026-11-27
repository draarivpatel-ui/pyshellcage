"""CLI behavior, secure file opening, and terminal output safety tests."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from pyshellcage.cli import build_parser, main, neutralize_terminal_text

REPO_ROOT = Path(__file__).resolve().parents[1]


def run_cli(args):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        status = main(args)
    return status, stdout.getvalue(), stderr.getvalue()


class AuditCliTests(unittest.TestCase):
    def test_parser_prog(self):
        self.assertEqual("pyshellcage", build_parser().prog)

    def test_no_arguments_is_usage_error(self):
        status, stdout, stderr = run_cli([])
        self.assertEqual(2, status)
        self.assertEqual("", stdout)
        self.assertIn("usage:", stderr)

    def test_unknown_subcommand_is_usage_error(self):
        status, _stdout, stderr = run_cli(["unknown"])
        self.assertEqual(2, status)
        self.assertIn("usage:", stderr)

    def test_audit_without_separator_is_usage_error(self):
        status, _stdout, stderr = run_cli(["audit", "git", "status"])
        self.assertEqual(2, status)
        self.assertIn("requires --", stderr)

    def test_audit_separator_without_command_is_usage_error(self):
        status, _stdout, stderr = run_cli(["audit", "--"])
        self.assertEqual(2, status)
        self.assertIn("requires --", stderr)

    def test_audit_clean_human_exit_zero(self):
        status, stdout, stderr = run_cli(["audit", "--", "git", "status"])
        self.assertEqual(0, status)
        self.assertIn("clean", stdout)
        self.assertEqual("", stderr)

    def test_audit_finding_human_exit_one(self):
        status, stdout, stderr = run_cli(["audit", "--", "git", "clone", "--upload-pack=x"])
        self.assertEqual(1, status)
        self.assertIn("PYSHELLCAGE_DANGEROUS_FLAG", stdout)
        self.assertIn("--upload-pack", stdout)
        self.assertEqual("", stderr)

    def test_audit_json_clean(self):
        status, stdout, stderr = run_cli(["audit", "--json", "--", "git", "status"])
        self.assertEqual(0, status)
        report = json.loads(stdout)
        self.assertTrue(report["ok"])
        self.assertEqual("git", report["command"])
        self.assertEqual(1, report["arg_count"])
        self.assertEqual([], report["findings"])
        self.assertEqual("", stderr)

    def test_audit_json_finding(self):
        status, stdout, _stderr = run_cli(["audit", "--json", "--", "git", "clone", "--upload-pack=x"])
        self.assertEqual(1, status)
        report = json.loads(stdout)
        self.assertFalse(report["ok"])
        self.assertEqual("PYSHELLCAGE_DANGEROUS_FLAG", report["findings"][0]["code"])

    def test_audit_json_uses_ascii_escapes(self):
        payload = "curl"
        status, stdout, _stderr = run_cli(["audit", "--json", "--", payload, "-o" + chr(0x202E)])
        self.assertEqual(1, status)
        self.assertNotIn(chr(0x202E), stdout)
        self.assertIn("\\u202e", stdout)

    def test_audit_human_neutralizes_escape_in_flag(self):
        escape = chr(27)
        status, stdout, _stderr = run_cli(["audit", "--", "curl", "-o" + escape + "[31m"])
        self.assertEqual(1, status)
        self.assertNotIn(escape, stdout)

    def test_audit_shell_finding(self):
        status, stdout, _stderr = run_cli(["audit", "--", "sh", "-c", "id"])
        self.assertEqual(1, status)
        self.assertIn("PYSHELLCAGE_SHELL_BINARY", stdout)

    def test_audit_batch_finding(self):
        status, stdout, _stderr = run_cli(["audit", "--", "job.bat"])
        self.assertEqual(1, status)
        self.assertIn("PYSHELLCAGE_BATCH_EXTENSION", stdout)

    def test_module_invocation_audit(self):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO_ROOT / "src")
        completed = subprocess.run(
            [sys.executable, "-m", "pyshellcage", "audit", "--json", "--", "git", "status"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            timeout=10,
            check=False,
        )
        self.assertEqual(0, completed.returncode)
        self.assertTrue(json.loads(completed.stdout)["ok"])
        self.assertEqual("", completed.stderr)


class EnvJsonCliTests(unittest.TestCase):
    def write_json(self, directory, text):
        path = os.path.join(directory, "env.json")
        Path(path).write_text(text, encoding="utf-8")
        return path

    def test_clean_env_json_exit_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(directory, '{"PATH":"/bin"}')
            status, stdout, stderr = run_cli(["audit-env", "--env-json", path, "--json"])
        self.assertEqual(0, status)
        report = json.loads(stdout)
        self.assertTrue(report["ok"])
        self.assertEqual(1, report["entries"])
        self.assertFalse(report["values_printed"])
        self.assertEqual("", stderr)

    def test_empty_env_json_exit_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(directory, "{}")
            status, stdout, _stderr = run_cli(["audit-env", "--env-json", path, "--json"])
        self.assertEqual(0, status)
        self.assertTrue(json.loads(stdout)["ok"])

    def test_dangerous_env_json_exit_one(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(directory, '{"LD_PRELOAD":"secret-value"}')
            status, stdout, _stderr = run_cli(["audit-env", "--env-json", path, "--json"])
        self.assertEqual(1, status)
        report = json.loads(stdout)
        self.assertEqual("PYSHELLCAGE_ENV_INJECTION", report["findings"][0]["code"])

    def test_env_json_never_prints_values_json(self):
        secret = "super-secret-environment-value"
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(directory, json.dumps({"LD_PRELOAD": secret, "PATH": secret}))
            status, stdout, stderr = run_cli(["audit-env", "--env-json", path, "--json"])
        self.assertEqual(1, status)
        self.assertNotIn(secret, stdout)
        self.assertNotIn(secret, stderr)

    def test_env_json_never_prints_values_human(self):
        secret = "super-secret-environment-value"
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(directory, json.dumps({"LD_PRELOAD": secret, "PATH": secret}))
            status, stdout, stderr = run_cli(["audit-env", "--env-json", path])
        self.assertEqual(1, status)
        self.assertNotIn(secret, stdout)
        self.assertNotIn(secret, stderr)

    def test_env_json_nonstring_value_is_finding_not_secret_leak(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(directory, '{"PATH":{"nested":"secret"}}')
            status, stdout, _stderr = run_cli(["audit-env", "--env-json", path, "--json"])
        self.assertEqual(1, status)
        report = json.loads(stdout)
        self.assertIn("PYSHELLCAGE_ENV_VALUE_TYPE", [item["code"] for item in report["findings"]])
        self.assertNotIn("secret", stdout)

    def test_missing_env_json_usage_error(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = os.path.join(directory, "missing.json")
            status, stdout, stderr = run_cli(["audit-env", "--env-json", missing])
        self.assertEqual(2, status)
        self.assertEqual("", stdout)
        self.assertIn("usage error", stderr)

    def test_invalid_json_usage_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(directory, "not json")
            status, _stdout, stderr = run_cli(["audit-env", "--env-json", path])
        self.assertEqual(2, status)
        self.assertIn("JSON", stderr)

    def test_json_array_usage_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(directory, "[]")
            status, _stdout, stderr = run_cli(["audit-env", "--env-json", path])
        self.assertEqual(2, status)
        self.assertIn("object", stderr)

    def test_nonfinite_json_numbers_rejected(self):
        for constant in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(constant=constant):
                with tempfile.TemporaryDirectory() as directory:
                    path = self.write_json(directory, '{"PATH":' + constant + '}')
                    status, stdout, stderr = run_cli(["audit-env", "--env-json", path])
                self.assertEqual(2, status)
                self.assertEqual("", stdout)
                self.assertNotIn("Traceback", stderr)

    def test_deep_json_nesting_rejected_without_traceback(self):
        nested = '{"a":' * 140 + '0' + '}' * 140
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(directory, nested)
            status, stdout, stderr = run_cli(["audit-env", "--env-json", path])
        self.assertEqual(2, status)
        self.assertEqual("", stdout)
        self.assertIn("depth limit", stderr)
        self.assertNotIn("Traceback", stderr)

    def test_invalid_utf8_usage_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "env.json")
            Path(path).write_bytes(b"\xff")
            status, _stdout, stderr = run_cli(["audit-env", "--env-json", path])
        self.assertEqual(2, status)
        self.assertIn("UTF-8", stderr)

    def test_oversized_env_json_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "env.json")
            with open(path, "wb") as handle:
                handle.write(b" " * (1024 * 1024 + 1))
            status, _stdout, stderr = run_cli(["audit-env", "--env-json", path])
        self.assertEqual(2, status)
        self.assertIn("byte limit", stderr)

    def test_directory_env_json_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            status, _stdout, stderr = run_cli(["audit-env", "--env-json", directory])
        self.assertEqual(2, status)
        self.assertIn("regular file", stderr)

    def test_device_env_json_rejected(self):
        if not os.path.exists("/dev/null"):
            self.skipTest("/dev/null unavailable")
        status, _stdout, stderr = run_cli(["audit-env", "--env-json", "/dev/null"])
        self.assertEqual(2, status)
        self.assertIn("regular file", stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_symlink_env_json_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            real = self.write_json(directory, "{}")
            link = os.path.join(directory, "link.json")
            os.symlink(real, link)
            status, _stdout, stderr = run_cli(["audit-env", "--env-json", link])
        self.assertEqual(2, status)
        self.assertIn("symlink", stderr)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO support required")
    def test_fifo_env_json_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo = os.path.join(directory, "env.fifo")
            os.mkfifo(fifo)
            status, _stdout, stderr = run_cli(["audit-env", "--env-json", fifo])
        self.assertEqual(2, status)
        self.assertIn("regular file", stderr)

    def test_unlisted_env_json_info_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_json(directory, '{"APP_MODE":"x"}')
            status, stdout, _stderr = run_cli(["audit-env", "--env-json", path, "--json"])
        self.assertEqual(1, status)
        report = json.loads(stdout)
        self.assertIn("PYSHELLCAGE_ENV_NOT_ALLOWLISTED", [item["code"] for item in report["findings"]])


class NeutralizeTerminalTextTests(unittest.TestCase):
    pass


_NEUTRALIZE_CASES = []
for _codepoint in list(range(0, 32)) + [127, 0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069]:
    _NEUTRALIZE_CASES.append((_codepoint,))


def _neutralize_body(self, codepoint):
    char = chr(codepoint)
    result = neutralize_terminal_text("a" + char + "b")
    self.assertNotIn(char, result)
    self.assertEqual("a?b", result)


add_matrix = None
if add_matrix is None:
    from _matrix import add_matrix
add_matrix(NeutralizeTerminalTextTests, "neutralize", _NEUTRALIZE_CASES, _neutralize_body)


class TerminalSafetyTests(unittest.TestCase):
    def test_neutralize_leaves_plain_unicode_text(self):
        self.assertEqual("plain text €", neutralize_terminal_text("plain text €"))

    def test_json_output_has_no_raw_escape_or_bidi(self):
        escape = chr(27)
        bidi = chr(0x202E)
        status, stdout, _stderr = run_cli(["audit", "--json", "--", "curl", "-o" + escape + bidi])
        self.assertEqual(1, status)
        self.assertNotIn(escape, stdout)
        self.assertNotIn(bidi, stdout)

    def test_human_output_has_no_raw_escape_or_bidi(self):
        escape = chr(27)
        bidi = chr(0x202E)
        status, stdout, _stderr = run_cli(["audit", "--", "curl", "-o" + escape + bidi])
        self.assertEqual(1, status)
        self.assertNotIn(escape, stdout)
        self.assertNotIn(bidi, stdout)

    def test_argparse_error_neutralizes_escape_newline_and_bidi(self):
        escape = chr(27)
        bidi = chr(0x202E)
        status, stdout, stderr = run_cli(["--bad" + escape + "[31m\n" + bidi])
        self.assertEqual(2, status)
        self.assertEqual("", stdout)
        self.assertNotIn(escape, stderr)
        self.assertNotIn(bidi, stderr)
        self.assertNotIn("[31m\n", stderr)


if __name__ == "__main__":
    unittest.main()
