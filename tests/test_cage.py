"""Reusable ShellCage policy object tests."""

from __future__ import annotations

import sys
import unittest
from types import MappingProxyType

from pyshellcage import CODES, ShellCage, ShellCageError, create_shell_cage

PYTHON = sys.executable


def assert_error_code(testcase, code, function, *args, **kwargs):
    with testcase.assertRaises(ShellCageError) as caught:
        function(*args, **kwargs)
    testcase.assertEqual(code, caught.exception.code)
    return caught.exception


class ShellCageConstructionTests(unittest.TestCase):
    def test_constructor_requires_allowlist(self):
        assert_error_code(self, CODES["EXECUTABLE_ALLOWLIST_REQUIRED"], ShellCage)

    def test_constructor_rejects_empty_allowlist(self):
        assert_error_code(self, CODES["EXECUTABLE_ALLOWLIST_REQUIRED"], ShellCage, allow_executables=[])

    def test_constructor_rejects_invalid_allowlist_entry(self):
        assert_error_code(self, CODES["EXECUTABLE_ALLOWLIST_INVALID"], ShellCage, allow_executables=["relative/path"])

    def test_constructor_rejects_unknown_option(self):
        assert_error_code(self, CODES["CONFIG_OPTION_UNKNOWN"], ShellCage, allow_executables=["tool"], shell_path="x")

    def test_constructor_rejects_shell_true(self):
        assert_error_code(self, CODES["SHELL_OPTION_FORBIDDEN"], ShellCage, allow_executables=["tool"], shell=True)

    def test_create_shell_cage_returns_cage(self):
        cage = create_shell_cage(allow_executables=["tool"])
        self.assertIsInstance(cage, ShellCage)

    def test_options_are_mapping_proxy(self):
        cage = ShellCage(allow_executables=["tool"])
        self.assertIsInstance(cage.options, MappingProxyType)

    def test_cage_attribute_mutation_rejected(self):
        cage = ShellCage(allow_executables=["tool"])
        with self.assertRaises(AttributeError):
            cage.allow = True

    def test_options_mutation_rejected(self):
        cage = ShellCage(allow_executables=["tool"])
        with self.assertRaises(TypeError):
            cage.options["allow_executables"] = ["evil"]

    def test_original_allowlist_mutation_does_not_reopen_policy(self):
        entries = ["tool"]
        cage = ShellCage(allow_executables=entries)
        entries.append("evil")
        report = cage.validate_invocation(["evil"])
        self.assertFalse(report.ok)

    def test_original_env_mutation_does_not_change_copy(self):
        env = {"PATH": "/bin"}
        cage = ShellCage(allow_executables=["tool"], env=env)
        env["PATH"] = "/evil"
        self.assertEqual("/bin", cage.options["env"]["PATH"])

    def test_nested_env_mapping_mutation_rejected(self):
        cage = ShellCage(allow_executables=["tool"], env={"PATH": "/bin"})
        with self.assertRaises(TypeError):
            cage.options["env"]["PATH"] = "/evil"
        self.assertEqual("/bin", cage.options["env"]["PATH"])


class ShellCageMethodTests(unittest.TestCase):
    def test_validate_uses_base_allowlist(self):
        cage = ShellCage(allow_executables=["tool"])
        self.assertTrue(cage.validate_invocation(["tool"]).ok)
        self.assertFalse(cage.validate_invocation(["other"]).ok)

    def test_per_call_allowlist_replaces_not_appends(self):
        cage = ShellCage(allow_executables=["tool"])
        report = cage.validate_invocation(["tool"], allow_executables=["other"])
        self.assertFalse(report.ok)
        self.assertTrue(cage.validate_invocation(["tool"]).ok)

    def test_unknown_per_call_override_rejected(self):
        cage = ShellCage(allow_executables=["tool"])
        assert_error_code(self, CODES["CONFIG_OPTION_UNKNOWN"], cage.validate_invocation, ["tool"], bad_option=True)

    def test_dangerous_flags_blocked_by_default(self):
        cage = ShellCage(allow_executables=["git"])
        report = cage.validate_invocation(["git", "clone", "--upload-pack=x"])
        self.assertFalse(report.ok)

    def test_dangerous_flags_override_per_call(self):
        cage = ShellCage(allow_executables=["git"])
        report = cage.validate_invocation(["git", "clone", "--upload-pack=x"], allow_dangerous_flags=True)
        self.assertTrue(report.ok)

    def test_audit_argv_still_reports_with_override(self):
        cage = ShellCage(allow_executables=["git"])
        findings = cage.audit_argv("git", ["clone", "--upload-pack=x"], allow_dangerous_flags=True)
        self.assertTrue(any(finding.code == CODES["DANGEROUS_FLAG"] for finding in findings))

    def test_safe_run_uses_base_policy(self):
        cage = ShellCage(allow_executables=[PYTHON], allow_dangerous_flags=True, timeout_seconds=4)
        result = cage.safe_run([PYTHON, "-c", "print('cage')"])
        self.assertEqual("cage\n", result.stdout)

    def test_safe_run_per_call_env(self):
        cage = ShellCage(allow_executables=[PYTHON], allow_dangerous_flags=True, timeout_seconds=4)
        result = cage.safe_run(
            [PYTHON, "-c", "import os;print(os.environ.get('SAFE_VAR',''))"],
            env={"SAFE_VAR": "yes"},
            allow_env=["SAFE_VAR"],
        )
        self.assertEqual("yes\n", result.stdout)

    def test_sanitize_env_uses_base_allowlist(self):
        cage = ShellCage(allow_executables=["tool"], allow_env=["SAFE_VAR"])
        scrubbed = cage.sanitize_env({"SAFE_VAR": "yes", "PATH": "/bin"})
        self.assertEqual({"SAFE_VAR": "yes"}, dict(scrubbed))

    def test_sanitize_env_override_replaces_allowlist(self):
        cage = ShellCage(allow_executables=["tool"], allow_env=["SAFE_VAR"])
        scrubbed = cage.sanitize_env({"SAFE_VAR": "yes", "PATH": "/bin"}, allow_env=["PATH"])
        self.assertEqual({"PATH": "/bin"}, dict(scrubbed))

    def test_audit_env_uses_include_unlisted_override(self):
        cage = ShellCage(allow_executables=["tool"])
        findings = cage.audit_env({"APP_MODE": "x"}, include_unlisted=True)
        self.assertTrue(any(finding.code == CODES["ENV_NOT_ALLOWLISTED"] for finding in findings))

    def test_environment_unknown_override_rejected(self):
        cage = ShellCage(allow_executables=["tool"])
        assert_error_code(self, CODES["CONFIG_OPTION_UNKNOWN"], cage.sanitize_env, {}, unknown=True)

    def test_static_assert_safe_arg_available(self):
        cage = ShellCage(allow_executables=["tool"])
        self.assertEqual("x", cage.assert_safe_arg("x"))

    def test_static_safe_path_arg_available(self):
        cage = ShellCage(allow_executables=["tool"])
        self.assertEqual("x", cage.safe_path_arg("x"))

    def test_static_build_argv_available(self):
        cage = ShellCage(allow_executables=["tool"])
        self.assertEqual(("x",), cage.build_argv([{"type": "literal", "value": "x"}]))


if __name__ == "__main__":
    unittest.main()
