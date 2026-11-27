"""Tool-specific dangerous argv audit tests."""

from __future__ import annotations

import unittest

from pyshellcage import CODES, audit_argv
from _matrix import add_matrix


def codes(findings):
    return [finding.code for finding in findings]


def dangerous(findings):
    return [finding for finding in findings if finding.code in (CODES["DANGEROUS_FLAG"], CODES["DANGEROUS_GADGET"])]


def assert_dangerous(testcase, command, args):
    findings = audit_argv(command, args)
    testcase.assertTrue(dangerous(findings), "expected dangerous finding in " + repr((command, args, findings)))
    return dangerous(findings)


def assert_no_dangerous(testcase, command, args):
    findings = audit_argv(command, args)
    testcase.assertEqual([], dangerous(findings), "unexpected dangerous finding in " + repr((command, args, findings)))
    return findings


class AuditApiTests(unittest.TestCase):
    def test_clean_git_status_has_no_findings(self):
        self.assertEqual(tuple(), audit_argv("git", ["status"]))

    def test_does_not_require_allowlist(self):
        findings = audit_argv("definitely-not-allowlisted", ["value"])
        self.assertEqual(tuple(), findings)

    def test_string_args_rejected_as_command_line(self):
        findings = audit_argv("git", "status")
        self.assertIn(CODES["ARGS_NOT_ARRAY"], codes(findings))

    def test_bytes_args_rejected_as_command_line(self):
        findings = audit_argv("git", b"status")
        self.assertIn(CODES["ARGS_NOT_ARRAY"], codes(findings))

    def test_nonstring_arg_suppresses_gadget_scan_but_reports_type(self):
        findings = audit_argv("git", [None])
        self.assertIn(CODES["ARG_TYPE"], codes(findings))
        self.assertEqual([], dangerous(findings))

    def test_audit_reports_dangerous_even_when_execution_override_is_set(self):
        findings = audit_argv("git", ["clone", "--upload-pack=x"], allow_dangerous_flags=True)
        self.assertTrue(dangerous(findings))

    def test_audit_includes_shell_binary_policy(self):
        findings = audit_argv("sh", [])
        self.assertIn(CODES["SHELL_BINARY"], codes(findings))

    def test_audit_includes_batch_extension_policy(self):
        findings = audit_argv("job.bat", [])
        self.assertIn(CODES["BATCH_EXTENSION"], codes(findings))


class GitDangerousMatrixTests(unittest.TestCase):
    pass


_GIT_CASES = [
    ["-c", "x=y"],
    ["-ccore.sshCommand=evil"],
    ["-C", "/tmp/repo"],
    ["-C/tmp/repo"],
    ["--config"],
    ["--config=x"],
    ["--conf"],
    ["--config-env"],
    ["--config-env=x"],
    ["--config-e"],
    ["clone", "--upload-pack", "evil"],
    ["clone", "--upload-pack=evil"],
    ["clone", "--upload"],
    ["clone", "--upload-p"],
    ["--exec-path", "/tmp/evil"],
    ["--exec-path=/tmp/evil"],
    ["--exec"],
    ["--git-dir", "/tmp/evil/.git"],
    ["--git-dir=/tmp/evil/.git"],
    ["--git"],
    ["--work-tree", "/tmp/evil"],
    ["--work-tree=/tmp/evil"],
    ["--work"],
    ["init", "--template", "/tmp/evil"],
    ["init", "--template=/tmp/evil"],
    ["init", "--temp"],
    ["clone", "ext::sh -c id"],
    ["clone", "--", "ext::sh -c id"],
]


def _git_dangerous_body(self, args):
    assert_dangerous(self, "git", args)


add_matrix(GitDangerousMatrixTests, "git_dangerous", _GIT_CASES, _git_dangerous_body)


class GitBenignMatrixTests(unittest.TestCase):
    pass


_GIT_BENIGN_CASES = [
    ["status"],
    ["clone", "https://example.invalid/repo.git"],
    ["clone", "--depth", "1", "https://example.invalid/repo.git"],
    ["clone", "--", "--upload-pack=evil"],
    ["clone", "--", "-c"],
    ["clone", "--", "--config"],
    ["clone", "--uploads"],
    ["clone", "--templatex"],
    ["clone", "--work-treeish"],
    ["clone", "ssh://example.invalid/repo"],
]


def _git_benign_body(self, args):
    assert_no_dangerous(self, "git", args)


add_matrix(GitBenignMatrixTests, "git_benign", _GIT_BENIGN_CASES, _git_benign_body)


class TarDangerousMatrixTests(unittest.TestCase):
    pass


_TAR_CASES = [
    ["--checkpoint-action=exec=sh"],
    ["--checkpoint-action", "exec=sh"],
    ["--checkpoint-a"],
    ["--checkpoint-ac"],
    ["--checkpoint-act=exec=sh"],
    ["--to-command", "sh"],
    ["--to-command=sh"],
    ["--to-c"],
    ["-I", "sh"],
    ["-Ish"],
    ["-xI", "sh"],
    ["--use-compress-program", "sh"],
    ["--use-compress-program=sh"],
    ["--rsh-command", "sh"],
    ["--rsh-command=sh"],
    ["--rmt-command", "sh"],
    ["--rmt-command=sh"],
    ["--rmt"],
    ["--info-script", "sh"],
    ["--info-script=sh"],
    ["--new-volume-script", "sh"],
    ["--new-volume-script=sh"],
    ["--new-volume"],
    ["-F", "sh"],
    ["-Fsh"],
    ["-xF", "sh"],
]


def _tar_dangerous_body(self, args):
    assert_dangerous(self, "tar", args)


add_matrix(TarDangerousMatrixTests, "tar_dangerous", _TAR_CASES, _tar_dangerous_body)


class TarBenignMatrixTests(unittest.TestCase):
    pass


_TAR_BENIGN_CASES = [
    ["-xf", "archive.tar"],
    ["--checkpoint"],
    ["--checkpoint=10"],
    ["--checkpoint", "10"],
    ["--check"],
    ["--checkpoint-number"],
    ["--extract"],
    ["--", "--checkpoint-action=exec=sh"],
    ["--", "-I"],
]


def _tar_benign_body(self, args):
    assert_no_dangerous(self, "tar", args)


add_matrix(TarBenignMatrixTests, "tar_benign", _TAR_BENIGN_CASES, _tar_benign_body)


class FindAuditTests(unittest.TestCase):
    pass


_FIND_CASES = []
for _primary in ("-exec", "-execdir", "-ok", "-okdir"):
    _FIND_CASES.append(([".", _primary, "id", ";"],))
    _FIND_CASES.append(([".", "--", _primary, "id", ";"],))


def _find_dangerous_body(self, args):
    findings = assert_dangerous(self, "find", args)
    self.assertTrue(any(finding.flag in ("-exec", "-execdir", "-ok", "-okdir") for finding in findings))


add_matrix(FindAuditTests, "find_dangerous", _FIND_CASES, _find_dangerous_body)


class FindBenignTests(unittest.TestCase):
    def test_find_print_is_clean(self):
        assert_no_dangerous(self, "find", [".", "-print"])

    def test_find_name_is_clean(self):
        assert_no_dangerous(self, "find", [".", "-name", "x"])


class CurlDangerousMatrixTests(unittest.TestCase):
    pass


_CURL_CASES = [
    ["-K", "config"],
    ["-Kconfig"],
    ["-sK", "config"],
    ["--config", "config"],
    ["--config=config"],
    ["-o", "out"],
    ["-oout"],
    ["-so", "out"],
    ["--output", "out"],
    ["--output=out"],
    ["-T", "in"],
    ["-Tin"],
    ["--upload-file", "in"],
    ["-O"],
    ["-J"],
    ["--remote-name"],
    ["--remote-header-name"],
    ["--output-dir", "out"],
    ["--dump-header", "headers"],
    ["--trace", "trace"],
    ["--trace-ascii", "trace"],
    ["--stderr", "err"],
    ["--cookie-jar", "cookies"],
]


def _curl_dangerous_body(self, args):
    assert_dangerous(self, "curl", args)


add_matrix(CurlDangerousMatrixTests, "curl_dangerous", _CURL_CASES, _curl_dangerous_body)


class CurlBenignMatrixTests(unittest.TestCase):
    pass


_CURL_BENIGN_CASES = [
    ["https://example.invalid"],
    ["-sS", "https://example.invalid"],
    ["--", "-o", "out"],
    ["--", "--config", "x"],
    ["--fail", "https://example.invalid"],
]


def _curl_benign_body(self, args):
    assert_no_dangerous(self, "curl", args)


add_matrix(CurlBenignMatrixTests, "curl_benign", _CURL_BENIGN_CASES, _curl_benign_body)


class RemoteShellDangerousMatrixTests(unittest.TestCase):
    pass


_REMOTE_CASES = []
for _tool in ("ssh", "scp", "sftp", "rsync"):
    _REMOTE_CASES.append((_tool, ["-o", "ProxyCommand=sh", "host"]))
    _REMOTE_CASES.append((_tool, ["-oProxyCommand=sh", "host"]))
    _REMOTE_CASES.append((_tool, ["-o", "PermitLocalCommand=yes", "host"]))
    _REMOTE_CASES.append((_tool, ["-e", "sh", "host"]))
    _REMOTE_CASES.append((_tool, ["-esh", "host"]))
_REMOTE_CASES.extend(
    [
        ("rsync", ["--rsh", "sh", "a", "b"]),
        ("rsync", ["--rsh=sh", "a", "b"]),
        ("rsync", ["--rsync-path", "/tmp/evil", "a", "b"]),
        ("ssh", ["-S", "/tmp/socket", "host"]),
    ]
)


def _remote_dangerous_body(self, tool, args):
    assert_dangerous(self, tool, args)


add_matrix(RemoteShellDangerousMatrixTests, "remote_dangerous", _REMOTE_CASES, _remote_dangerous_body)


class RuntimeDangerousMatrixTests(unittest.TestCase):
    pass


_RUNTIME_CASES = []
for _tool in ("node", "nodejs", "bun", "deno"):
    for _args in (["-e", "code"], ["-p", "code"], ["--eval", "code"], ["--print", "code"], ["-r", "mod"], ["--require", "mod"], ["--import", "mod"], ["--experimental-loader", "mod"]):
        _RUNTIME_CASES.append((_tool, _args))
for _tool in ("python", "python3", "python3.11", "pypy"):
    for _args in (["-c", "code"], ["-m", "module"], ["-"]):
        _RUNTIME_CASES.append((_tool, _args))
_RUNTIME_CASES.extend(
    [
        ("perl", ["-e", "code"]),
        ("ruby", ["-e", "code"]),
        ("ruby", ["-r", "mod"]),
        ("php", ["-r", "code"]),
    ]
)


def _runtime_dangerous_body(self, tool, args):
    assert_dangerous(self, tool, args)


add_matrix(RuntimeDangerousMatrixTests, "runtime_dangerous", _RUNTIME_CASES, _runtime_dangerous_body)


class PowerShellMatrixTests(unittest.TestCase):
    pass


_POWERSHELL_CASES = []
for _tool in ("powershell", "powershell.exe", "pwsh", "pwsh.exe"):
    for _flag in ("-c", "-e", "-co", "-comm", "-command", "-enc", "-encodedcommand", "/c", "/command", chr(0x2013) + "command", chr(0x2212) + "encodedcommand"):
        _POWERSHELL_CASES.append((_tool, [_flag, "payload"]))


def _powershell_dangerous_body(self, tool, args):
    assert_dangerous(self, tool, args)


add_matrix(PowerShellMatrixTests, "powershell_dangerous", _POWERSHELL_CASES, _powershell_dangerous_body)


class ShellAndEnvGadgetMatrixTests(unittest.TestCase):
    pass


_SHELL_ENV_CASES = []
for _shell in ("sh", "bash", "zsh", "dash", "ksh", "csh", "fish"):
    _SHELL_ENV_CASES.append((_shell, ["-c", "id"]))
_SHELL_ENV_CASES.extend(
    [
        ("cmd", ["/c", "calc"]),
        ("cmd", ["/k", "calc"]),
        ("cmd.exe", ["/c", "calc"]),
        ("env", ["-S", "sh -c id"]),
        ("env", ["--split-string", "sh -c id"]),
        ("env", ["A=1", "id"]),
        ("env", ["--", "id"]),
        ("env", ["-u", "HOME", "id"]),
        ("xargs", ["-I", "{}", "sh"]),
        ("xargs", ["-I{}", "sh"]),
        ("xargs", ["-J", "%", "sh"]),
        ("xargs", ["--replace", "{}", "sh"]),
        ("xargs", ["--replace={}", "sh"]),
    ]
)


def _shell_env_dangerous_body(self, tool, args):
    assert_dangerous(self, tool, args)


add_matrix(ShellAndEnvGadgetMatrixTests, "shell_env_dangerous", _SHELL_ENV_CASES, _shell_env_dangerous_body)


class EndOfOptionsBehaviorTests(unittest.TestCase):
    def test_git_option_after_end_is_not_flagged(self):
        assert_no_dangerous(self, "git", ["clone", "--", "--upload-pack=x"])

    def test_curl_option_after_end_is_not_flagged(self):
        assert_no_dangerous(self, "curl", ["--", "-o", "x"])

    def test_ssh_option_after_end_is_not_flagged(self):
        assert_no_dangerous(self, "ssh", ["--", "-o", "ProxyCommand=x"])

    def test_node_option_after_end_is_not_flagged(self):
        assert_no_dangerous(self, "node", ["--", "-e", "x"])

    def test_find_option_after_end_is_still_flagged(self):
        assert_dangerous(self, "find", ["--", "-exec", "id", ";"])

    def test_powershell_option_after_end_is_still_flagged(self):
        assert_dangerous(self, "powershell", ["--", "-command", "x"])

    def test_cmd_option_after_end_is_still_flagged(self):
        assert_dangerous(self, "cmd", ["--", "/c", "x"])

    def test_git_ext_after_end_is_still_flagged(self):
        findings = assert_dangerous(self, "git", ["clone", "--", "ext::sh -c id"])
        self.assertTrue(any(finding.code == CODES["DANGEROUS_GADGET"] for finding in findings))


if __name__ == "__main__":
    unittest.main()
