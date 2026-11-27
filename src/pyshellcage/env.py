"""Environment allowlisting, auditing, and hijack resistant scrubbing."""

from __future__ import annotations

import os
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, Optional, Tuple

from .args import has_lone_surrogate, utf8_len
from .errors import CODES, fail
from .models import Finding

_BASE_ALLOWED_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR")
if os.name == "nt":
    DEFAULT_ALLOWED_ENV = _BASE_ALLOWED_ENV + ("SYSTEMROOT", "WINDIR")
else:
    DEFAULT_ALLOWED_ENV = _BASE_ALLOWED_ENV

DEFAULT_MAX_ENV_VALUE_BYTES = 32768
MAX_ENV_VALUE_BYTES_LIMIT = 1024 * 1024
MAX_ENV_KEY_BYTES = 256
MAX_ALLOW_ENV_ENTRIES = 512

_EXACT_DANGEROUS_ENV_NAMES = frozenset(
    (
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
        "ZDOTDIR",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONINSPECT",
        "PYTHONUSERBASE",
        "PYTHONHOME",
        "PYTHONBREAKPOINT",
        "PYTHONEXECUTABLE",
        "NODE_OPTIONS",
        "NODE_EXTRA_CA_CERTS",
        "NODE_PATH",
        "NODE_REPL_EXTERNAL_MODULE",
        "RUBYOPT",
        "RUBYLIB",
        "PERL5OPT",
        "PERL5LIB",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "DOTNET_STARTUP_HOOKS",
        "SSLKEYLOGFILE",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_EXEC_PATH",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_EXT_TRANSPORT",
        "GIT_EXTERNAL_DIFF",
        "GIT_PAGER",
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
        "INPUTRC",
        "TERMINFO",
        "TERMINFO_DIRS",
        "LESSOPEN",
        "LESSCLOSE",
        "SYSTEMD_PAGER",
    )
)

_DANGEROUS_ENV_PREFIXES = (
    "LD_",
    "DYLD_",
    "BASH_FUNC_",
    "PYTHON",
    "NODE_",
    "GIT_",
)


def is_dangerous_env_name(name: Any) -> bool:
    """Return True when a variable can hijack a loader, runtime, shell, or helper."""

    if not isinstance(name, str):
        return False
    upper = name.upper()
    if upper in _EXACT_DANGEROUS_ENV_NAMES:
        return True
    return any(upper.startswith(prefix) for prefix in _DANGEROUS_ENV_PREFIXES)


def validate_env_key_shape(key: Any) -> bool:
    """Return True for a portable, printable environment key shape."""

    if not isinstance(key, str) or key == "":
        return False
    try:
        if utf8_len(key) > MAX_ENV_KEY_BYTES:
            return False
    except UnicodeEncodeError:
        return False
    if "=" in key or "\x00" in key:
        return False
    for char in key:
        codepoint = ord(char)
        if codepoint < 0x21 or codepoint > 0x7E:
            return False
    return True


def _validate_allow_env(allow_env: Any) -> Tuple[str, ...]:
    if allow_env is None:
        return tuple(DEFAULT_ALLOWED_ENV)
    if isinstance(allow_env, (str, bytes, bytearray)) or not isinstance(allow_env, (tuple, list)):
        fail(CODES["CONFIG_INVALID"], "allow_env must be a list or tuple of environment variable names")
    if len(allow_env) > MAX_ALLOW_ENV_ENTRIES:
        fail(CODES["CONFIG_INVALID"], "allow_env exceeds the entry limit")
    result = []
    for key in allow_env:
        if not validate_env_key_shape(key):
            fail(CODES["CONFIG_INVALID"], "allow_env contains an invalid environment variable name", {"key": "[invalid key]"})
        result.append(key)
    return tuple(result)


def _validate_env_options(max_value_bytes: Any, include_unlisted: Any) -> Tuple[int, bool]:
    if max_value_bytes is None:
        max_value_bytes = DEFAULT_MAX_ENV_VALUE_BYTES
    if (
        isinstance(max_value_bytes, bool)
        or not isinstance(max_value_bytes, int)
        or max_value_bytes < 1
        or max_value_bytes > MAX_ENV_VALUE_BYTES_LIMIT
    ):
        fail(CODES["CONFIG_INVALID"], "max_value_bytes must be an integer in range")
    if include_unlisted is None:
        include_unlisted = False
    if not isinstance(include_unlisted, bool):
        fail(CODES["CONFIG_INVALID"], "include_unlisted must be a boolean")
    return max_value_bytes, include_unlisted


def _allowlist_lookup(allow_env: Tuple[str, ...]) -> dict[str, str]:
    lookup = {}
    for key in allow_env:
        normalized = key.upper() if os.name == "nt" else key
        if normalized not in lookup:
            lookup[normalized] = key
    return lookup


def _lookup_allowed_key(key: str, lookup: dict[str, str]) -> Optional[str]:
    normalized = key.upper() if os.name == "nt" else key
    return lookup.get(normalized)


def _assert_env_source(source: Any) -> Mapping:
    if not isinstance(source, Mapping):
        fail(CODES["ENV_NOT_OBJECT"], "environment input must be a mapping")
    return source


def audit_env(
    source: Optional[Mapping] = None,
    *,
    allow_env: Optional[Tuple[str, ...]] = None,
    max_value_bytes: int = DEFAULT_MAX_ENV_VALUE_BYTES,
    include_unlisted: bool = False,
) -> Tuple[Finding, ...]:
    """Audit an environment mapping without printing or returning values."""

    if source is None:
        source = os.environ
    source = _assert_env_source(source)
    allow_tuple = _validate_allow_env(allow_env)
    max_value_bytes, include_unlisted = _validate_env_options(max_value_bytes, include_unlisted)
    lookup = _allowlist_lookup(allow_tuple)
    findings = []
    seen_case_keys = {}

    for key, value in source.items():
        if not isinstance(key, str) or not validate_env_key_shape(key):
            findings.append(
                Finding(
                    CODES["ENV_KEY_INVALID"],
                    "high",
                    "environment key contains forbidden characters or is empty",
                    key="[invalid key]",
                )
            )
            continue

        upper = key.upper()
        previous = seen_case_keys.get(upper)
        if previous is not None and previous != key:
            findings.append(
                Finding(
                    CODES["ENV_DUPLICATE_KEY"],
                    "medium",
                    "environment contains duplicate keys that differ only by case",
                    key=key,
                )
            )
        elif previous is None:
            seen_case_keys[upper] = key

        if is_dangerous_env_name(key):
            findings.append(
                Finding(
                    CODES["ENV_INJECTION"],
                    "critical",
                    "environment variable can hijack a runtime, linker, shell, or helper command",
                    key=key,
                )
            )

        if include_unlisted and _lookup_allowed_key(key, lookup) is None:
            findings.append(
                Finding(
                    CODES["ENV_NOT_ALLOWLISTED"],
                    "info",
                    "environment variable is not present in the explicit allowlist",
                    key=key,
                )
            )

        if not isinstance(value, str):
            findings.append(Finding(CODES["ENV_VALUE_TYPE"], "high", "environment value must be a string", key=key))
            continue
        if "\x00" in value:
            findings.append(Finding(CODES["ENV_VALUE_NUL_BYTE"], "high", "environment value contains a NUL byte", key=key))
        if has_lone_surrogate(value):
            findings.append(
                Finding(CODES["ENV_VALUE_SURROGATE"], "high", "environment value contains a lone UTF-16 surrogate", key=key)
            )
            continue
        if utf8_len(value) > max_value_bytes:
            findings.append(
                Finding(CODES["ENV_VALUE_TOO_LONG"], "medium", "environment value exceeds the byte limit", key=key)
            )

    return tuple(findings)


def sanitize_env(
    source: Optional[Mapping] = None,
    *,
    allow_env: Optional[Tuple[str, ...]] = None,
    max_value_bytes: int = DEFAULT_MAX_ENV_VALUE_BYTES,
) -> Mapping:
    """Return a read-only scrubbed environment.

    Only allowlisted names can survive. Hard-denied loader, runtime, shell,
    editor, Git, and helper hijack names are removed even if a caller makes a
    mistake in a custom allowlist. Values are never interpreted.
    """

    if source is None:
        source = os.environ
    source = _assert_env_source(source)
    allow_tuple = _validate_allow_env(allow_env)
    max_value_bytes, _include = _validate_env_options(max_value_bytes, False)
    lookup = _allowlist_lookup(allow_tuple)
    output = {}
    used_canonical = set()

    for key, value in source.items():
        if not isinstance(key, str) or not validate_env_key_shape(key):
            continue
        canonical = _lookup_allowed_key(key, lookup)
        if canonical is None or canonical in used_canonical:
            continue
        if is_dangerous_env_name(key) or is_dangerous_env_name(canonical):
            continue
        if not isinstance(value, str):
            continue
        if "\x00" in value or has_lone_surrogate(value):
            continue
        if utf8_len(value) > max_value_bytes:
            continue
        output[canonical] = value
        used_canonical.add(canonical)

    return MappingProxyType(output)
