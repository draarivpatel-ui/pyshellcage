"""Environment denylist, audit, and scrubbing tests."""

from __future__ import annotations

import os
import unittest
from types import MappingProxyType

from pyshellcage import CODES, DEFAULT_ALLOWED_ENV, ShellCageError, audit_env, is_dangerous_env_name, sanitize_env
from _matrix import add_matrix


def codes(findings):
    return [finding.code for finding in findings]


class DangerousExactMatrixTests(unittest.TestCase):
    pass


_EXACT_DANGEROUS = [
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_DEBUG",
    "BASH_ENV",
    "ENV",
    "CDPATH",
    "IFS",
    "SHELLOPTS",
    "PS4",
    "PROMPT_COMMAND",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONINSPECT",
    "PYTHONUSERBASE",
    "PYTHONHOME",
    "PYTHONBREAKPOINT",
    "NODE_OPTIONS",
    "NODE_EXTRA_CA_CERTS",
    "NODE_PATH",
    "NODE_REPL_EXTERNAL_MODULE",
    "RUBYOPT",
    "RUBYLIB",
    "PERL5OPT",
    "PERL5LIB",
    "JAVA_TOOL_OPTIONS",
    "DOTNET_STARTUP_HOOKS",
    "SSLKEYLOGFILE",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_EXEC_PATH",
    "GIT_EXT_TRANSPORT",
    "GIT_EDITOR",
    "GIT_SEQUENCE_EDITOR",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
    "GIT_PROXY_COMMAND",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_TEMPLATE_DIR",
    "EDITOR",
    "VISUAL",
    "PAGER",
    "COMSPEC",
    "PATHEXT",
]
_EXACT_CASES = []
for _name in _EXACT_DANGEROUS:
    _EXACT_CASES.append((_name,))
    _EXACT_CASES.append((_name.lower(),))
    _EXACT_CASES.append((_name.title().replace("_", "_"),))


def _dangerous_exact_body(self, name):
    self.assertTrue(is_dangerous_env_name(name), name)
    findings = audit_env({name: "x"})
    self.assertIn(CODES["ENV_INJECTION"], codes(findings))
    scrubbed = sanitize_env({name: "x"}, allow_env=[name])
    self.assertNotIn(name, scrubbed)
    self.assertEqual({}, dict(scrubbed))


add_matrix(DangerousExactMatrixTests, "dangerous_exact", _EXACT_CASES, _dangerous_exact_body)


class DangerousPrefixMatrixTests(unittest.TestCase):
    pass


_PREFIX_CASES = [
    "DYLD_INSERT_LIBRARIES",
    "DYLD_PRINT_LIBRARIES",
    "DYLD_IMAGE_SUFFIX",
    "BASH_FUNC_x%%",
    "BASH_FUNC_test()",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_KEY_0",
    "GIT_CONFIG_VALUE_0",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "LD_ANY_CUSTOM_LOADER_FLAG",
    "ld_preload",
    "dyld_insert_libraries",
    "bash_func_x",
    "git_config_key_0",
]


def _dangerous_prefix_body(self, name):
    self.assertTrue(is_dangerous_env_name(name), name)
    findings = audit_env({name: "x"})
    self.assertIn(CODES["ENV_INJECTION"], codes(findings))


add_matrix(DangerousPrefixMatrixTests, "dangerous_prefix", _PREFIX_CASES, _dangerous_prefix_body)


class BenignNameMatrixTests(unittest.TestCase):
    pass


_BENIGN_NAMES = [
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "SYSTEMROOT",
    "WINDIR",
    "APP_MODE",
    "PYTHONUNBUFFERED",
    "NODE_ENV",
    "GIT_EDITORAPP",
    "GIT_CONFIG",
    "GITTER",
    "LD",
    "DYLD",
    "BASH_FUNC",
    "USER",
    "LOGNAME",
    "SHELL",
    "TERM",
]


def _benign_name_body(self, name):
    self.assertFalse(is_dangerous_env_name(name), name)
    findings = audit_env({name: "x"})
    self.assertNotIn(CODES["ENV_INJECTION"], codes(findings))


add_matrix(BenignNameMatrixTests, "benign_name", _BENIGN_NAMES, _benign_name_body)


class SanitizeEnvTests(unittest.TestCase):
    def test_default_allowlist_constant(self):
        for name in ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR"):
            self.assertIn(name, DEFAULT_ALLOWED_ENV)
        if os.name == "nt":
            self.assertIn("SYSTEMROOT", DEFAULT_ALLOWED_ENV)
            self.assertIn("WINDIR", DEFAULT_ALLOWED_ENV)

    def test_default_allowlisted_values_survive(self):
        source = {"PATH": "/bin", "HOME": "/home/x", "LANG": "C", "LC_ALL": "C", "TMPDIR": "/tmp"}
        scrubbed = sanitize_env(source)
        self.assertEqual(source, dict(scrubbed))

    def test_unlisted_values_removed(self):
        scrubbed = sanitize_env({"PATH": "/bin", "TOKEN": "secret", "APP_MODE": "x"})
        self.assertEqual({"PATH": "/bin"}, dict(scrubbed))

    def test_result_is_read_only_mapping(self):
        scrubbed = sanitize_env({"PATH": "/bin"})
        self.assertIsInstance(scrubbed, MappingProxyType)
        with self.assertRaises(TypeError):
            scrubbed["PATH"] = "/evil"

    def test_custom_allowlist_replaces_default(self):
        scrubbed = sanitize_env({"PATH": "/bin", "APP_MODE": "x"}, allow_env=["APP_MODE"])
        self.assertEqual({"APP_MODE": "x"}, dict(scrubbed))

    def test_tuple_allowlist_accepted(self):
        scrubbed = sanitize_env({"APP_MODE": "x"}, allow_env=("APP_MODE",))
        self.assertEqual({"APP_MODE": "x"}, dict(scrubbed))

    def test_dangerous_allowlist_entry_still_removed(self):
        scrubbed = sanitize_env({"LD_PRELOAD": "x"}, allow_env=["LD_PRELOAD"])
        self.assertEqual({}, dict(scrubbed))

    def test_nonstring_value_removed(self):
        scrubbed = sanitize_env({"PATH": 123}, allow_env=["PATH"])
        self.assertEqual({}, dict(scrubbed))

    def test_nul_value_removed(self):
        scrubbed = sanitize_env({"PATH": "/bin\x00"}, allow_env=["PATH"])
        self.assertEqual({}, dict(scrubbed))

    def test_surrogate_value_removed(self):
        scrubbed = sanitize_env({"PATH": "/bin" + chr(0xD800)}, allow_env=["PATH"])
        self.assertEqual({}, dict(scrubbed))

    def test_too_long_value_removed(self):
        scrubbed = sanitize_env({"PATH": "abcde"}, allow_env=["PATH"], max_value_bytes=4)
        self.assertEqual({}, dict(scrubbed))

    def test_exact_length_value_survives(self):
        scrubbed = sanitize_env({"PATH": "abcd"}, allow_env=["PATH"], max_value_bytes=4)
        self.assertEqual({"PATH": "abcd"}, dict(scrubbed))

    def test_invalid_key_removed(self):
        scrubbed = sanitize_env({"BAD KEY": "x", "PATH": "/bin"}, allow_env=["BAD KEY", "PATH"] if False else ["PATH"])
        self.assertEqual({"PATH": "/bin"}, dict(scrubbed))

    def test_nonmapping_rejected(self):
        with self.assertRaises(ShellCageError) as caught:
            sanitize_env([("PATH", "/bin")])
        self.assertEqual(CODES["ENV_NOT_OBJECT"], caught.exception.code)

    def test_invalid_allowlist_entry_rejected(self):
        with self.assertRaises(ShellCageError) as caught:
            sanitize_env({"PATH": "/bin"}, allow_env=["BAD KEY"])
        self.assertEqual(CODES["CONFIG_INVALID"], caught.exception.code)

    def test_lowercase_path_is_not_posix_path(self):
        scrubbed = sanitize_env({"path": "/evil"}, allow_env=["PATH"])
        if os.name == "nt":
            self.assertEqual({"PATH": "/evil"}, dict(scrubbed))
        else:
            self.assertEqual({}, dict(scrubbed))


class AuditEnvTests(unittest.TestCase):
    def test_clean_allowlisted_env_has_no_findings(self):
        findings = audit_env({"PATH": "/bin", "HOME": "/home/x"})
        self.assertEqual(tuple(), findings)

    def test_unlisted_not_reported_by_default(self):
        findings = audit_env({"APP_MODE": "x"})
        self.assertNotIn(CODES["ENV_NOT_ALLOWLISTED"], codes(findings))

    def test_unlisted_reported_when_enabled(self):
        findings = audit_env({"APP_MODE": "x"}, include_unlisted=True)
        self.assertIn(CODES["ENV_NOT_ALLOWLISTED"], codes(findings))

    def test_unlisted_allowlisted_not_reported(self):
        findings = audit_env({"PATH": "/bin"}, include_unlisted=True)
        self.assertEqual(tuple(), findings)

    def test_nonstring_value(self):
        findings = audit_env({"PATH": 1})
        self.assertIn(CODES["ENV_VALUE_TYPE"], codes(findings))

    def test_nul_value(self):
        findings = audit_env({"PATH": "a\x00b"})
        self.assertIn(CODES["ENV_VALUE_NUL_BYTE"], codes(findings))

    def test_surrogate_value(self):
        findings = audit_env({"PATH": "a" + chr(0xD800)})
        self.assertIn(CODES["ENV_VALUE_SURROGATE"], codes(findings))

    def test_too_long_value(self):
        findings = audit_env({"PATH": "abcde"}, max_value_bytes=4)
        self.assertIn(CODES["ENV_VALUE_TOO_LONG"], codes(findings))

    def test_exact_length_value_clean(self):
        findings = audit_env({"PATH": "abcd"}, max_value_bytes=4)
        self.assertEqual(tuple(), findings)

    def test_case_duplicate_reported(self):
        findings = audit_env({"PATH": "/bin", "path": "/evil"})
        self.assertIn(CODES["ENV_DUPLICATE_KEY"], codes(findings))

    def test_exact_duplicate_impossible_but_single_key_clean(self):
        findings = audit_env({"PATH": "/bin"})
        self.assertNotIn(CODES["ENV_DUPLICATE_KEY"], codes(findings))

    def test_invalid_key_does_not_leak_key_text(self):
        key = "BAD\nKEY"
        findings = audit_env({key: "x"})
        invalid = [finding for finding in findings if finding.code == CODES["ENV_KEY_INVALID"]]
        self.assertTrue(invalid)
        self.assertEqual("[invalid key]", invalid[0].key)
        self.assertNotIn(key, repr(findings))

    def test_values_never_appear_in_findings_repr(self):
        secret = "super-secret-value"
        findings = audit_env({"LD_PRELOAD": secret, "PATH": secret}, include_unlisted=True)
        self.assertNotIn(secret, repr(findings))

    def test_nonmapping_rejected(self):
        with self.assertRaises(ShellCageError) as caught:
            audit_env("PATH=/bin")
        self.assertEqual(CODES["ENV_NOT_OBJECT"], caught.exception.code)

    def test_max_value_bytes_invalid(self):
        with self.assertRaises(ShellCageError):
            audit_env({"PATH": "x"}, max_value_bytes=0)

    def test_include_unlisted_type_invalid(self):
        with self.assertRaises(ShellCageError):
            audit_env({"PATH": "x"}, include_unlisted=1)


class InvalidEnvKeyMatrixTests(unittest.TestCase):
    pass


_INVALID_KEYS = [
    "",
    "BAD KEY",
    "BAD\tKEY",
    "BAD\nKEY",
    "BAD=KEY",
    "BAD\x00KEY",
    "é",
    "KEYé",
    " " ,
    "KEY ",
    "A" * 257,
]


def _invalid_key_body(self, key):
    findings = audit_env({key: "x"})
    invalid = [finding for finding in findings if finding.code == CODES["ENV_KEY_INVALID"]]
    self.assertTrue(invalid)
    self.assertEqual("[invalid key]", invalid[0].key)


add_matrix(InvalidEnvKeyMatrixTests, "invalid_key", _INVALID_KEYS, _invalid_key_body)


class ValidEnvKeyMatrixTests(unittest.TestCase):
    pass


_VALID_KEYS = [
    "A",
    "Z",
    "_",
    "_A",
    "A1",
    "A_B",
    "A-B",
    "A.B",
    "A:B",
    "A/B",
    "a",
    "z",
    "0",
    "123",
    "A" * 256,
]


def _valid_key_body(self, key):
    findings = audit_env({key: "x"})
    self.assertNotIn(CODES["ENV_KEY_INVALID"], codes(findings))


add_matrix(ValidEnvKeyMatrixTests, "valid_key", _VALID_KEYS, _valid_key_body)


if __name__ == "__main__":
    unittest.main()
