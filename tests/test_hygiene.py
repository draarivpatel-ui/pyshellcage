"""Package metadata, documentation, workflow, typing, and repository hygiene tests."""

from __future__ import annotations

import ast
import os
import re
import subprocess
import unittest
from pathlib import Path

import pyshellcage
from pyshellcage import CODES, ERROR_CODES
from _matrix import add_matrix

REPO_ROOT = Path(__file__).resolve().parents[1]


def read(relative):
    return (REPO_ROOT / relative).read_text(encoding="utf-8")


def tracked_or_worktree_files():
    git_dir = REPO_ROOT / ".git"
    if git_dir.exists():
        completed = subprocess.run(
            ["git", "ls-files"],
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
        )
        if completed.returncode == 0:
            return [line for line in completed.stdout.splitlines() if line]
    output = []
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(REPO_ROOT).as_posix()
        if any(part in (".git", "__pycache__", "build", "dist") for part in path.parts):
            continue
        if ".egg-info" in relative:
            continue
        output.append(relative)
    return sorted(output)


class PackageSurfaceTests(unittest.TestCase):
    def test_version(self):
        self.assertEqual("1.0.0", pyshellcage.__version__)

    def test_version_constant_matches(self):
        self.assertEqual(pyshellcage.__version__, pyshellcage.PYSHELLCAGE_VERSION)

    def test_error_codes_unique(self):
        self.assertEqual(len(ERROR_CODES), len(set(ERROR_CODES)))

    def test_error_code_prefixes(self):
        for code in ERROR_CODES:
            self.assertTrue(code.startswith("PYSHELLCAGE_"), code)

    def test_error_codes_uppercase(self):
        for code in ERROR_CODES:
            self.assertRegex(code, r"^PYSHELLCAGE_[A-Z0-9_]+$")

    def test_codes_mapping_matches_tuple(self):
        self.assertEqual(set(CODES.values()), set(ERROR_CODES))

    def test_py_typed_exists(self):
        self.assertTrue((REPO_ROOT / "src" / "pyshellcage" / "py.typed").is_file())

    def test_py_typed_empty(self):
        self.assertEqual("", (REPO_ROOT / "src" / "pyshellcage" / "py.typed").read_text(encoding="utf-8"))


class PublicExportMatrixTests(unittest.TestCase):
    pass


_EXPORTS = [
    "ShellCage",
    "create_shell_cage",
    "validate_invocation",
    "audit_argv",
    "assert_safe_arg",
    "safe_arg",
    "safe_path_arg",
    "build_argv",
    "sanitize_env",
    "audit_env",
    "safe_run",
    "safe_popen",
    "ShellCageError",
    "Finding",
    "ValidationReport",
    "ExecResult",
    "DEFAULT_ALLOWED_ENV",
    "CODES",
    "ERROR_CODES",
]


def _export_body(self, name):
    self.assertIn(name, pyshellcage.__all__)
    self.assertTrue(hasattr(pyshellcage, name))


add_matrix(PublicExportMatrixTests, "export", _EXPORTS, _export_body)


class PyprojectTests(unittest.TestCase):
    def test_name(self):
        self.assertIn('name = "pyshellcage"', read("pyproject.toml"))

    def test_version(self):
        self.assertIn('version = "1.0.0"', read("pyproject.toml"))

    def test_license(self):
        self.assertIn('license = "MIT"', read("pyproject.toml"))

    def test_requires_python(self):
        self.assertIn('requires-python = ">=3.9"', read("pyproject.toml"))

    def test_zero_dependencies(self):
        self.assertIn("dependencies = []", read("pyproject.toml"))

    def test_src_layout(self):
        self.assertIn('package-dir = { "" = "src" }', read("pyproject.toml"))

    def test_package_data_py_typed(self):
        self.assertIn('pyshellcage = ["py.typed"]', read("pyproject.toml"))

    def test_cli_entry_point(self):
        self.assertIn('pyshellcage = "pyshellcage.cli:main"', read("pyproject.toml"))

    def test_tests_excluded_from_package_discovery(self):
        self.assertIn('exclude = ["tests*"]', read("pyproject.toml"))


class PyprojectClassifierMatrixTests(unittest.TestCase):
    pass


_CLASSIFIERS = [
    "3.9",
    "3.10",
    "3.11",
    "3.12",
    "3.13",
]


def _classifier_body(self, version):
    self.assertIn('"Programming Language :: Python :: ' + version + '"', read("pyproject.toml"))


add_matrix(PyprojectClassifierMatrixTests, "classifier", _CLASSIFIERS, _classifier_body)


class PyprojectUrlMatrixTests(unittest.TestCase):
    pass


_URLS = [
    "https://github.com/draarivpatel-ui/pyshellcage",
    "https://github.com/draarivpatel-ui/pyshellcage/issues",
]


def _url_body(self, url):
    self.assertIn(url, read("pyproject.toml"))


add_matrix(PyprojectUrlMatrixTests, "url", _URLS, _url_body)


class PythonCompatibilityTests(unittest.TestCase):
    def source_files(self):
        return sorted((REPO_ROOT / "src" / "pyshellcage").glob("*.py"))

    def test_expected_source_files_exist(self):
        names = [path.name for path in self.source_files()]
        for expected in ("__init__.py", "__main__.py", "args.py", "cage.py", "cli.py", "env.py", "errors.py", "execution.py", "invocation.py", "models.py"):
            self.assertIn(expected, names)

    def test_no_match_case_syntax(self):
        pattern = re.compile(r"^\s*(match\s+\S+|case\s+.+)\s*:\s*(#.*)?$", re.MULTILINE)
        for path in self.source_files():
            self.assertIsNone(pattern.search(path.read_text(encoding="utf-8")), path.name)

    def test_no_tomllib_import(self):
        for path in self.source_files():
            self.assertNotIn("tomllib", path.read_text(encoding="utf-8"), path.name)

    def test_future_annotations_present(self):
        for path in self.source_files():
            self.assertIn("from __future__ import annotations", path.read_text(encoding="utf-8"), path.name)

    def test_imports_are_stdlib_or_local(self):
        allowed = {
            "__future__",
            "argparse",
            "collections",
            "dataclasses",
            "json",
            "math",
            "os",
            "re",
            "shutil",
            "stat",
            "subprocess",
            "sys",
            "threading",
            "time",
            "types",
            "typing",
            "unicodedata",
        }
        for path in self.source_files():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertIn(alias.name.split(".", 1)[0], allowed, (path.name, alias.name))
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    self.assertIn((node.module or "").split(".", 1)[0], allowed, (path.name, node.module))


class ReadmeTests(unittest.TestCase):
    def test_threat_model_cwe78(self):
        self.assertIn("CWE-78", read("README.md"))
        self.assertIn("operating system command injection", read("README.md"))

    def test_threat_model_cwe88(self):
        self.assertIn("CWE-88", read("README.md"))
        self.assertIn("argument injection", read("README.md"))

    def test_environment_hijacking_documented(self):
        self.assertIn("Environment hijacking", read("README.md"))
        self.assertIn("LD_PRELOAD", read("README.md"))
        self.assertIn("GIT_CONFIG_PARAMETERS", read("README.md"))

    def test_windows_confusion_documented(self):
        text = read("README.md")
        for needle in ("trailing-dot", "NTFS", "UNC", ".bat", ".ps1"):
            self.assertIn(needle, text)

    def test_symlink_shell_documented(self):
        self.assertIn("symlink", read("README.md"))
        self.assertIn("os.path.realpath()", read("README.md"))

    def test_ai_agent_example_documented(self):
        self.assertIn("Python AI agent example", read("README.md"))

    def test_mcp_example_documented(self):
        self.assertIn("MCP server example", read("README.md"))

    def test_pypi_pending_is_honest(self):
        text = read("README.md")
        self.assertIn("does not claim that the package has already been published", text)
        self.assertIn("python3 -m pip install pyshellcage", text)

    def test_cli_documented(self):
        self.assertIn("pyshellcage audit --json -- git status", read("README.md"))
        self.assertIn("pyshellcage audit-env", read("README.md"))

    def test_commonpath_documented(self):
        self.assertIn("os.path.commonpath([root, target]) == root", read("README.md"))

    def test_non_goals_documented(self):
        self.assertIn("Security boundaries and non-goals", read("README.md"))


class DocsAndCommunityTests(unittest.TestCase):
    pass


_REQUIRED_FILES = [
    "CONTRIBUTING.md",
    "SECURITY.md",
    "LICENSE",
    "docs/GOOD_FIRST_ISSUES.md",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/ISSUE_TEMPLATE/bug_report.md",
    ".github/ISSUE_TEMPLATE/feature_request.md",
    ".github/workflows/ci.yml",
    ".github/workflows/publish.yml",
]


def _required_file_body(self, relative):
    self.assertTrue((REPO_ROOT / relative).is_file(), relative)


add_matrix(DocsAndCommunityTests, "required_file", _REQUIRED_FILES, _required_file_body)


class CommunityContentTests(unittest.TestCase):
    def test_license_is_mit(self):
        text = read("LICENSE")
        self.assertIn("MIT License", text)
        self.assertIn("Permission is hereby granted", text)

    def test_security_reporting_section(self):
        self.assertIn("Reporting a vulnerability", read("SECURITY.md"))

    def test_security_scope_section(self):
        self.assertIn("Out of scope", read("SECURITY.md"))

    def test_contributing_zero_dependencies_rule(self):
        self.assertIn("dependencies = []", read("CONTRIBUTING.md"))

    def test_contributing_python_39_rule(self):
        self.assertIn("Python 3.9 compatibility", read("CONTRIBUTING.md"))

    def test_good_first_issues_has_ten_numbered_specs(self):
        text = read("docs/GOOD_FIRST_ISSUES.md")
        for number in range(1, 11):
            self.assertIn(str(number) + ". **", text)

    def test_pull_request_template_has_test_plan(self):
        self.assertIn("Test plan", read(".github/PULL_REQUEST_TEMPLATE.md"))

    def test_issue_templates_have_security_note(self):
        self.assertIn("security", read(".github/ISSUE_TEMPLATE/bug_report.md").lower())


class WorkflowTests(unittest.TestCase):
    def test_ci_ubuntu_2404(self):
        self.assertIn("runs-on: ubuntu-24.04", read(".github/workflows/ci.yml"))

    def test_ci_permissions_read_only(self):
        self.assertIn("permissions:\n  contents: read", read(".github/workflows/ci.yml"))

    def test_ci_runs_unittest(self):
        self.assertIn("python3 -m unittest discover -s tests", read(".github/workflows/ci.yml"))

    def test_ci_cli_smoke(self):
        text = read(".github/workflows/ci.yml")
        self.assertIn("CLI smoke test", text)
        self.assertIn("python3 -m pyshellcage audit --json -- git status", text)
        self.assertIn("audit-env output leaked an environment value", text)

    def test_ci_builds_distributions(self):
        self.assertIn("python3 -m build", read(".github/workflows/ci.yml"))

    def test_ci_verifies_py_typed(self):
        self.assertIn("pyshellcage/py.typed", read(".github/workflows/ci.yml"))

    def test_ci_verifies_no_tests_or_bytecode_in_wheel(self):
        text = read(".github/workflows/ci.yml")
        self.assertIn("wheel includes tests", text)
        self.assertIn("wheel includes bytecode cache files", text)

    def test_publish_ubuntu_2404(self):
        self.assertIn("runs-on: ubuntu-24.04", read(".github/workflows/publish.yml"))

    def test_publish_oidc_permission(self):
        self.assertIn("id-token: write", read(".github/workflows/publish.yml"))

    def test_publish_environment(self):
        self.assertIn("name: pypi", read(".github/workflows/publish.yml"))

    def test_publish_action(self):
        self.assertIn("pypa/gh-action-pypi-publish@release/v1", read(".github/workflows/publish.yml"))

    def test_publish_has_no_pypi_token(self):
        self.assertNotIn("PYPI_TOKEN", read(".github/workflows/publish.yml"))
        self.assertNotIn("password", read(".github/workflows/publish.yml").lower())


class WorkflowMatrixTests(unittest.TestCase):
    pass


def _ci_version_body(self, version):
    self.assertIn('"' + version + '"', read(".github/workflows/ci.yml"))


add_matrix(WorkflowMatrixTests, "ci_python", _CLASSIFIERS, _ci_version_body)


class RepositoryHygieneTests(unittest.TestCase):
    def test_no_em_or_en_dash_characters(self):
        forbidden = ("\u2014", "\u2013")
        offenders = []
        for relative in tracked_or_worktree_files():
            path = REPO_ROOT / relative
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            if any(char in text for char in forbidden):
                offenders.append(relative)
        self.assertEqual([], offenders)

    def test_no_local_user_paths(self):
        offenders = []
        for relative in tracked_or_worktree_files():
            path = REPO_ROOT / relative
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            if ("/Users/" + "aarivpatel") in text or ("/home/" + "aarivpatel") in text:
                offenders.append(relative)
        self.assertEqual([], offenders)

    def test_no_private_email_markers(self):
        offenders = []
        forbidden = ("someone" + "@gmail.com", "handle-redacted286" + "@gmail.com", "123 Example Street" + " Manor Drive")
        for relative in tracked_or_worktree_files():
            path = REPO_ROOT / relative
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            if any(marker in text for marker in forbidden):
                offenders.append(relative)
        self.assertEqual([], offenders)

    def test_no_co_authored_by_trailer_in_repository_files(self):
        offenders = []
        for relative in tracked_or_worktree_files():
            try:
                text = (REPO_ROOT / relative).read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            if ("Co-Authored" + "-By:") in text:
                offenders.append(relative)
        self.assertEqual([], offenders)

    def test_gitignore_excludes_bytecode_and_build_outputs(self):
        text = read(".gitignore")
        for needle in ("__pycache__/", "*.py[cod]", "build/", "dist/", "*.egg-info/"):
            self.assertIn(needle, text)

    def test_gitattributes_normalizes_lines(self):
        self.assertIn("text=auto eol=lf", read(".gitattributes"))

    def test_no_vendor_secret_prefixes(self):
        forbidden = ("ts" + "key-", "s" + "k-", "gh" + "p_", "github" + "_pat_", "AK" + "IA", "x" + "ox", "gs" + "k_", "nv" + "api-", "tv" + "ly-", "AI" + "za")
        offenders = []
        for relative in tracked_or_worktree_files():
            try:
                text = (REPO_ROOT / relative).read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for marker in forbidden:
                if marker in text:
                    offenders.append((relative, marker))
        self.assertEqual([], offenders)


class GitLsFilesHygieneTests(unittest.TestCase):
    def test_git_ls_files_has_no_bytecode_or_build_outputs_when_git_exists(self):
        if not (REPO_ROOT / ".git").exists():
            self.skipTest("git repository not initialized yet")
        completed = subprocess.run(
            ["git", "ls-files"],
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        files = completed.stdout.splitlines()
        self.assertTrue(files)
        self.assertFalse(any("__pycache__" in name for name in files))
        self.assertFalse(any(name.endswith((".pyc", ".pyo")) for name in files))
        self.assertFalse(any(name.startswith(("build/", "dist/")) for name in files))
        self.assertFalse(any(".egg-info" in name for name in files))

    def test_git_ls_files_includes_key_files_when_git_exists(self):
        if not (REPO_ROOT / ".git").exists():
            self.skipTest("git repository not initialized yet")
        completed = subprocess.run(
            ["git", "ls-files"],
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        files = set(completed.stdout.splitlines())
        for required in ("pyproject.toml", "README.md", "LICENSE", "src/pyshellcage/py.typed", "tests/test_run.py"):
            self.assertIn(required, files)


if __name__ == "__main__":
    unittest.main()
