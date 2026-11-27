"""pyshellcage public API.

Zero-dependency CWE-78 command injection, CWE-88 argument injection, and
environment hijack defenses for Python subprocesses, AI agents, and MCP tools.
"""

from __future__ import annotations

from .args import assert_safe_arg, build_argv, safe_arg, safe_path_arg
from .cage import ShellCage, create_shell_cage
from .env import DEFAULT_ALLOWED_ENV, audit_env, is_dangerous_env_name, sanitize_env
from .errors import CODE, CODES, ERROR_CODES, ShellCageError
from .execution import safe_popen, safe_run
from .invocation import audit_argv, validate_invocation
from .models import ExecResult, Finding, ValidationReport

__version__ = "1.0.0"
PYSHELLCAGE_VERSION = __version__

__all__ = (
    "__version__",
    "PYSHELLCAGE_VERSION",
    "CODES",
    "CODE",
    "ERROR_CODES",
    "DEFAULT_ALLOWED_ENV",
    "ShellCageError",
    "Finding",
    "ValidationReport",
    "ExecResult",
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
    "is_dangerous_env_name",
    "safe_run",
    "safe_popen",
)
