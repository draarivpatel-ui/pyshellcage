"""Reusable frozen policy object for pyshellcage."""

from __future__ import annotations

import os
from types import MappingProxyType
from typing import Any, Mapping, Optional, Sequence, Tuple

from .args import assert_safe_arg, build_argv, safe_arg, safe_path_arg
from .env import audit_env, sanitize_env
from .errors import CODES, fail
from .execution import safe_popen, safe_run
from .invocation import audit_argv, normalize_allowlist, normalize_invocation_options, validate_invocation

_ENV_OVERRIDE_KEYS = frozenset(("allow_env", "max_env_value_bytes", "include_unlisted"))


class ShellCage:
    """A reusable, immutable no-shell execution policy.

    ``allow_executables`` is required at construction. Per-call overrides are
    merged shallowly and validated again; they replace rather than append to
    allowlists.
    """

    __slots__ = ("_options",)

    def __init__(self, **options: Any) -> None:
        normalized = normalize_invocation_options(options)
        if "allow_executables" not in normalized:
            fail(CODES["EXECUTABLE_ALLOWLIST_REQUIRED"], "an explicit non-empty executable allowlist is required")
        normalize_allowlist(normalized["allow_executables"])
        copied = dict(normalized)
        for key in ("allow_executables", "allow_env", "allowed_cwd_roots"):
            if isinstance(copied.get(key), list):
                copied[key] = tuple(copied[key])
            elif isinstance(copied.get(key), tuple):
                copied[key] = tuple(copied[key])
        if isinstance(copied.get("env"), Mapping):
            copied["env"] = dict(copied["env"])
        object.__setattr__(self, "_options", MappingProxyType(copied))

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("ShellCage is immutable")

    @property
    def options(self) -> Mapping[str, Any]:
        return self._options

    def _merged(self, overrides: Mapping[str, Any]) -> dict[str, Any]:
        merged = dict(self._options)
        merged.update(dict(overrides))
        normalize_invocation_options(merged)
        return merged

    def validate_invocation(self, argv: Sequence[str], **overrides: Any):
        return validate_invocation(argv, **self._merged(overrides))

    def audit_argv(self, command: Any, args: Any = (), **overrides: Any):
        return audit_argv(command, args, **self._merged(overrides))

    def safe_run(self, argv: Sequence[str], **overrides: Any):
        return safe_run(argv, **self._merged(overrides))

    def safe_popen(self, argv: Sequence[str], **overrides: Any):
        return safe_popen(argv, **self._merged(overrides))

    def _merged_env(self, overrides: Mapping[str, Any]) -> dict[str, Any]:
        for key in overrides:
            if key not in _ENV_OVERRIDE_KEYS:
                fail(CODES["CONFIG_OPTION_UNKNOWN"], "environment overrides contain an unknown option", {"key": key})
        merged = {
            "allow_env": self._options.get("allow_env"),
            "max_value_bytes": self._options.get("max_env_value_bytes"),
        }
        merged.update(dict(overrides))
        return merged

    def sanitize_env(self, source: Optional[Mapping] = None, **overrides: Any):
        merged = self._merged_env(overrides)
        include_unlisted = merged.pop("include_unlisted", False)
        del include_unlisted
        return sanitize_env(
            os.environ if source is None else source,
            allow_env=merged.get("allow_env"),
            max_value_bytes=merged.get("max_value_bytes"),
        )

    def audit_env(self, source: Optional[Mapping] = None, **overrides: Any):
        merged = self._merged_env(overrides)
        return audit_env(
            os.environ if source is None else source,
            allow_env=merged.get("allow_env"),
            max_value_bytes=merged.get("max_value_bytes"),
            include_unlisted=merged.get("include_unlisted", False),
        )

    assert_safe_arg = staticmethod(assert_safe_arg)
    safe_arg = staticmethod(safe_arg)
    safe_path_arg = staticmethod(safe_path_arg)
    build_argv = staticmethod(build_argv)


def create_shell_cage(**options: Any) -> ShellCage:
    return ShellCage(**options)
