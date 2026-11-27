"""Executable policy and invocation validation tests."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

from pyshellcage import CODES, ShellCageError, validate_invocation
from _matrix import add_matrix


def finding_codes(report):
    return [finding.code for finding in report.findings]


def has_code(report, code):
    return code in finding_codes(report)


class StrictArgvInputTests(unittest.TestCase):
    def test_plain_string_command_line_rejected(self):
        report = validate_invocation("echo hello", allow_executables=["echo"])
        self.assertFalse(report.ok)
        self.assertIn(CODES["ARGV_TYPE"], finding_codes(report))

    def test_single_word_string_still_rejected(self):
        report = validate_invocation("echo", allow_executables=["echo"])
        self.assertFalse(report.ok)
        self.assertIn(CODES["ARGV_TYPE"], finding_codes(report))

    def test_bytes_command_line_rejected(self):
        report = validate_invocation(b"echo hello", allow_executables=["echo"])
        self.assertFalse(report.ok)
        self.assertIn(CODES["ARGV_TYPE"], finding_codes(report))

    def test_bytearray_command_line_rejected(self):
        report = validate_invocation(bytearray(b"echo"), allow_executables=["echo"])
        self.assertFalse(report.ok)
        self.assertIn(CODES["ARGV_TYPE"], finding_codes(report))

    def test_empty_sequence_rejected(self):
        report = validate_invocation([], allow_executables=["echo"])
        self.assertFalse(report.ok)
        self.assertIn(CODES["ARGV_EMPTY"], finding_codes(report))

    def test_non_sequence_rejected(self):
        report = validate_invocation(123, allow_executables=["echo"])
        self.assertFalse(report.ok)
        self.assertIn(CODES["ARGV_TYPE"], finding_codes(report))

    def test_none_rejected(self):
        report = validate_invocation(None, allow_executables=["echo"])
        self.assertFalse(report.ok)
        self.assertIn(CODES["ARGV_TYPE"], finding_codes(report))

    def test_tuple_accepted(self):
        report = validate_invocation(("tool",), allow_executables=["tool"])
        self.assertTrue(report.ok)

    def test_clean_report_has_no_findings(self):
        report = validate_invocation(["tool", "value"], allow_executables=["tool"])
        self.assertTrue(report.ok)
        self.assertEqual(tuple(), report.findings)

    def test_report_is_frozen(self):
        report = validate_invocation(["tool"], allow_executables=["tool"])
        with self.assertRaises(Exception):
            report.ok = False

    def test_missing_allowlist_is_finding(self):
        report = validate_invocation(["tool"])
        self.assertFalse(report.ok)
        self.assertIn(CODES["EXECUTABLE_ALLOWLIST_REQUIRED"], finding_codes(report))

    def test_shell_true_is_reported_not_executed(self):
        report = validate_invocation(["tool"], allow_executables=["tool"], shell=True)
        self.assertFalse(report.ok)
        self.assertIn(CODES["SHELL_OPTION_FORBIDDEN"], finding_codes(report))

    def test_shell_false_is_accepted(self):
        report = validate_invocation(["tool"], allow_executables=["tool"], shell=False)
        self.assertTrue(report.ok)

    def test_windows_verbatim_arguments_rejected(self):
        report = validate_invocation(["tool"], allow_executables=["tool"], windows_verbatim_arguments=True)
        self.assertFalse(report.ok)
        self.assertIn(CODES["SHELL_OPTION_FORBIDDEN"], finding_codes(report))

    def test_unknown_option_rejected(self):
        report = validate_invocation(["tool"], allow_executables=["tool"], executable="sh")
        self.assertFalse(report.ok)
        self.assertIn(CODES["CONFIG_OPTION_UNKNOWN"], finding_codes(report))


class ShellExecutableMatrixTests(unittest.TestCase):
    pass


_SHELLS = ("sh", "bash", "zsh", "dash", "ksh", "csh", "fish", "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta")
_SHELL_CASES = []
for _name in _SHELLS:
    _SHELL_CASES.append((_name, _name))
    _SHELL_CASES.append((_name.upper(), _name.upper()))
    _SHELL_CASES.append((_name + ".exe", _name + ".exe"))
    _SHELL_CASES.append(("/opt/tools/bin/" + _name, _name))


def _shell_body(self, command, allowlist_entry):
    report = validate_invocation([command], allow_executables=[allowlist_entry])
    self.assertFalse(report.ok)
    self.assertIn(CODES["SHELL_BINARY"], finding_codes(report))


add_matrix(ShellExecutableMatrixTests, "shell", _SHELL_CASES, _shell_body)


class BatchExtensionMatrixTests(unittest.TestCase):
    pass


_BATCH_CASES = []
for _extension in (".bat", ".cmd", ".btm", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".com"):
    _BATCH_CASES.append(("job" + _extension,))
    _BATCH_CASES.append(("JOB" + _extension.upper(),))
    _BATCH_CASES.append(("/tmp/job" + _extension,))


def _batch_body(self, command):
    basename = os.path.basename(command)
    report = validate_invocation([command], allow_executables=[basename if "/" not in command else command])
    self.assertFalse(report.ok)
    self.assertIn(CODES["BATCH_EXTENSION"], finding_codes(report))


add_matrix(BatchExtensionMatrixTests, "batch", _BATCH_CASES, _batch_body)


class ExecutableSyntaxMatrixTests(unittest.TestCase):
    pass


_SYNTAX_CASES = [
    ("/bin/../bin/tool", CODES["EXECUTABLE_TRAVERSAL"]),
    ("../tool", CODES["EXECUTABLE_TRAVERSAL"]),
    ("./tool", CODES["EXECUTABLE_RELATIVE_PATH"]),
    ("bin/tool", CODES["EXECUTABLE_RELATIVE_PATH"]),
    ("x\\tool", CODES["EXECUTABLE_RELATIVE_PATH"]),
    ("\\\\server\\share\\tool", CODES["EXECUTABLE_UNC_PATH"]),
    ("//server/share/tool", CODES["EXECUTABLE_UNC_PATH"]),
    ("/tmp/", CODES["EXECUTABLE_EMPTY"]),
    ("/tmp/my tool", CODES["EXECUTABLE_WHITESPACE"]),
    ("/tmp/my\ttool", CODES["EXECUTABLE_CONTROL_CHAR"]),
    ("/tmp/étool", CODES["EXECUTABLE_NON_ASCII"]),
    ("/tmp/tool.", CODES["EXECUTABLE_TRAILING_DOT"]),
    ("/tmp/cmd.exe.", CODES["EXECUTABLE_TRAILING_DOT"]),
    ("/tmp/cmd.exe:stream", CODES["EXECUTABLE_NTFS_STREAM"]),
    ("/tmp/tool:stream", CODES["EXECUTABLE_NTFS_STREAM"]),
    ("/tmp/a\x00b", CODES["EXECUTABLE_NUL_BYTE"]),
    ("a" * 1025, CODES["EXECUTABLE_TOO_LONG"]),
]


def _syntax_body(self, command, code):
    report = validate_invocation([command], allow_executables=[command if "/" in command or "\\" in command else "tool"])
    self.assertFalse(report.ok)
    self.assertIn(code, finding_codes(report))


add_matrix(ExecutableSyntaxMatrixTests, "syntax", _SYNTAX_CASES, _syntax_body)


class AllowlistTests(unittest.TestCase):
    def test_bare_basename_match(self):
        report = validate_invocation(["tool"], allow_executables=["tool"])
        self.assertTrue(report.ok)

    def test_bare_basename_mismatch(self):
        report = validate_invocation(["tool"], allow_executables=["other"])
        self.assertFalse(report.ok)
        self.assertIn(CODES["EXECUTABLE_NOT_ALLOWLISTED"], finding_codes(report))

    def test_absolute_path_exact_match(self):
        report = validate_invocation([sys.executable], allow_executables=[sys.executable])
        self.assertTrue(report.ok)

    def test_absolute_path_sibling_mismatch(self):
        sibling = sys.executable + "-evil"
        report = validate_invocation([sibling], allow_executables=[sys.executable])
        self.assertFalse(report.ok)
        self.assertIn(CODES["EXECUTABLE_NOT_ALLOWLISTED"], finding_codes(report))

    def test_absolute_allowlist_does_not_match_bare_name(self):
        report = validate_invocation([os.path.basename(sys.executable)], allow_executables=[sys.executable])
        self.assertFalse(report.ok)
        self.assertIn(CODES["EXECUTABLE_NOT_ALLOWLISTED"], finding_codes(report))

    def test_basename_allowlist_matches_absolute_invocation_basename(self):
        report = validate_invocation([sys.executable], allow_executables=[os.path.basename(sys.executable)])
        self.assertTrue(report.ok)

    def test_path_allowlist_matches_symlink_target(self):
        with tempfile.TemporaryDirectory() as directory:
            link = os.path.join(directory, "python-link")
            os.symlink(sys.executable, link)
            report = validate_invocation([link], allow_executables=[sys.executable])
        self.assertTrue(report.ok)

    def test_non_empty_allowlist_required_type(self):
        report = validate_invocation(["tool"], allow_executables="tool")
        self.assertFalse(report.ok)
        self.assertIn(CODES["EXECUTABLE_ALLOWLIST_REQUIRED"], finding_codes(report))

    def test_empty_allowlist_rejected(self):
        report = validate_invocation(["tool"], allow_executables=[])
        self.assertFalse(report.ok)
        self.assertIn(CODES["EXECUTABLE_ALLOWLIST_REQUIRED"], finding_codes(report))

    def test_multiple_allowlist_entries(self):
        report = validate_invocation(["tool"], allow_executables=["one", "tool", "three"])
        self.assertTrue(report.ok)

    def test_nonexistent_allowlisted_path_is_statically_valid(self):
        path = os.path.join(tempfile.gettempdir(), "pyshellcage-no-such-tool")
        report = validate_invocation([path], allow_executables=[path])
        self.assertTrue(report.ok)


class AllowlistInvalidMatrixTests(unittest.TestCase):
    pass


_INVALID_ALLOWLIST_CASES = [
    ([""], CODES["EXECUTABLE_ALLOWLIST_INVALID"]),
    (["relative/path"], CODES["EXECUTABLE_ALLOWLIST_INVALID"]),
    (["../tool"], CODES["EXECUTABLE_ALLOWLIST_INVALID"]),
    (["/tmp/../tool"], CODES["EXECUTABLE_ALLOWLIST_INVALID"]),
    (["/tmp/my tool"], CODES["EXECUTABLE_ALLOWLIST_INVALID"]),
    (["/tmp/étool"], CODES["EXECUTABLE_ALLOWLIST_INVALID"]),
    (["/tmp/tool."], CODES["EXECUTABLE_ALLOWLIST_INVALID"]),
    (["/tmp/tool:stream"], CODES["EXECUTABLE_ALLOWLIST_INVALID"]),
    (["\\\\server\\share\\tool"], CODES["EXECUTABLE_ALLOWLIST_INVALID"]),
    ([None], CODES["EXECUTABLE_ALLOWLIST_INVALID"]),
    ([123], CODES["EXECUTABLE_ALLOWLIST_INVALID"]),
    (["a" * 1025], CODES["EXECUTABLE_ALLOWLIST_INVALID"]),
    (["tool"] * 513, CODES["EXECUTABLE_ALLOWLIST_INVALID"]),
]


def _invalid_allowlist_body(self, allowlist, code):
    report = validate_invocation(["tool"], allow_executables=allowlist)
    self.assertFalse(report.ok)
    self.assertIn(code, finding_codes(report))


add_matrix(AllowlistInvalidMatrixTests, "invalid_allowlist", _INVALID_ALLOWLIST_CASES, _invalid_allowlist_body)


class SymlinkPolicyTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_symlink_to_shell_named_target_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "bash")
            Path(target).write_text("#!/bin/sh\n", encoding="ascii")
            os.chmod(target, 0o755)
            link = os.path.join(directory, "innocent")
            os.symlink(target, link)
            report = validate_invocation([link], allow_executables=[link])
        self.assertFalse(report.ok)
        self.assertIn(CODES["SHELL_BINARY"], finding_codes(report))

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_symlink_to_batch_extension_target_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "job.bat")
            Path(target).write_text("echo off\n", encoding="ascii")
            link = os.path.join(directory, "innocent")
            os.symlink(target, link)
            report = validate_invocation([link], allow_executables=[link])
        self.assertFalse(report.ok)
        self.assertIn(CODES["BATCH_EXTENSION"], finding_codes(report))

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_bare_symlink_resolved_through_supplied_path_is_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "bash")
            Path(target).write_text("#!/bin/sh\n", encoding="ascii")
            os.chmod(target, 0o755)
            link = os.path.join(directory, "innocent")
            os.symlink(target, link)
            report = validate_invocation(["innocent"], allow_executables=["innocent"], env={"PATH": directory})
        self.assertFalse(report.ok)
        self.assertIn(CODES["SHELL_BINARY"], finding_codes(report))

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_symlink_to_non_shell_target_not_blocked_for_shell_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "tool")
            Path(target).write_text("#!/bin/true\n", encoding="ascii")
            os.chmod(target, 0o755)
            link = os.path.join(directory, "innocent")
            os.symlink(target, link)
            report = validate_invocation([link], allow_executables=[link])
        self.assertTrue(report.ok)

    def test_allow_shell_binary_explicit_override(self):
        report = validate_invocation(["sh"], allow_executables=["sh"], allow_shell_binary=True)
        self.assertTrue(report.ok)
        self.assertNotIn(CODES["SHELL_BINARY"], finding_codes(report))

    def test_allow_shell_binary_does_not_allow_inline_command_flag(self):
        report = validate_invocation(["sh", "-c", "id"], allow_executables=["sh"], allow_shell_binary=True)
        self.assertFalse(report.ok)
        self.assertIn(CODES["DANGEROUS_FLAG"], finding_codes(report))

    def test_allow_batch_extension_explicit_override(self):
        report = validate_invocation(["job.bat"], allow_executables=["job.bat"], allow_batch_extensions=True)
        self.assertTrue(report.ok)

    def test_shell_override_still_requires_allowlist(self):
        report = validate_invocation(["sh"], allow_shell_binary=True)
        self.assertFalse(report.ok)
        self.assertIn(CODES["EXECUTABLE_ALLOWLIST_REQUIRED"], finding_codes(report))


class ArgumentValidationInInvocationTests(unittest.TestCase):
    pass


_ARG_PROBLEM_CASES = [
    (["tool", "a\x00b"], CODES["ARG_NUL_BYTE"]),
    (["tool", "a\nb"], CODES["ARG_NEWLINE"]),
    (["tool", "a\rb"], CODES["ARG_NEWLINE"]),
    (["tool", "a\tb"], CODES["ARG_CONTROL_CHAR"]),
    (["tool", "a" + chr(0x202E) + "b"], CODES["ARG_BIDI_CONTROL"]),
    (["tool", "a" + chr(0xD800) + "b"], CODES["ARG_SURROGATE"]),
    (["tool", None], CODES["ARG_TYPE"]),
    (["tool", b"x"], CODES["ARG_TYPE"]),
    (["tool", "x" * 4097], CODES["ARG_TOO_LONG"]),
]


def _arg_problem_body(self, argv, code):
    report = validate_invocation(argv, allow_executables=["tool"])
    self.assertFalse(report.ok)
    self.assertIn(code, finding_codes(report))


add_matrix(ArgumentValidationInInvocationTests, "arg_problem", _ARG_PROBLEM_CASES, _arg_problem_body)


class InvocationLimitTests(unittest.TestCase):
    def test_max_args_boundary_clean(self):
        report = validate_invocation(["tool", "a", "b"], allow_executables=["tool"], max_args=2)
        self.assertTrue(report.ok)

    def test_max_args_exceeded(self):
        report = validate_invocation(["tool", "a", "b"], allow_executables=["tool"], max_args=1)
        self.assertFalse(report.ok)
        self.assertIn(CODES["ARGV_TOO_MANY"], finding_codes(report))

    def test_max_argv_bytes_boundary_clean(self):
        report = validate_invocation(["tool", "ab", "cd"], allow_executables=["tool"], max_argv_bytes=4)
        self.assertTrue(report.ok)

    def test_max_argv_bytes_exceeded(self):
        report = validate_invocation(["tool", "ab", "cd"], allow_executables=["tool"], max_argv_bytes=3)
        self.assertFalse(report.ok)
        self.assertIn(CODES["ARGV_TOO_LONG"], finding_codes(report))

    def test_custom_max_arg_bytes(self):
        report = validate_invocation(["tool", "abcde"], allow_executables=["tool"], max_arg_bytes=4)
        self.assertFalse(report.ok)
        self.assertIn(CODES["ARG_TOO_LONG"], finding_codes(report))

    def test_invalid_max_args_type(self):
        report = validate_invocation(["tool"], allow_executables=["tool"], max_args=True)
        self.assertFalse(report.ok)
        self.assertIn(CODES["CONFIG_INVALID"], finding_codes(report))

    def test_invalid_boolean_option_type(self):
        report = validate_invocation(["tool"], allow_executables=["tool"], allow_shell_binary=1)
        self.assertFalse(report.ok)
        self.assertIn(CODES["CONFIG_INVALID"], finding_codes(report))

    def test_dangerous_flag_blocks_validation_by_default(self):
        report = validate_invocation(["git", "clone", "--upload-pack=x"], allow_executables=["git"])
        self.assertFalse(report.ok)
        self.assertIn(CODES["DANGEROUS_FLAG"], finding_codes(report))

    def test_dangerous_flag_explicitly_allowed_for_execution(self):
        report = validate_invocation(
            ["git", "clone", "--upload-pack=x"],
            allow_executables=["git"],
            allow_dangerous_flags=True,
        )
        self.assertTrue(report.ok)

    def test_leading_dash_argument_not_automatically_positional_error(self):
        report = validate_invocation(["tool", "--fixed-flag"], allow_executables=["tool"])
        self.assertTrue(report.ok)


if __name__ == "__main__":
    unittest.main()
