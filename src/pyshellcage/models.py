"""Frozen result and report models used by pyshellcage."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Tuple


@dataclass(frozen=True)
class Finding:
    """One structured security or validation finding."""

    code: str
    severity: str
    message: str
    index: Optional[int] = None
    flag: Optional[str] = None
    key: Optional[str] = None
    count: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        result = {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
        }
        if self.index is not None:
            result["index"] = self.index
        if self.flag is not None:
            result["flag"] = self.flag
        if self.key is not None:
            result["key"] = self.key
        if self.count is not None:
            result["count"] = self.count
        return result


@dataclass(frozen=True)
class ValidationReport:
    """Static validation result for one argv sequence."""

    ok: bool
    command: str
    args: Tuple[Any, ...]
    findings: Tuple[Finding, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "command": self.command,
            "args": list(self.args),
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(frozen=True)
class ExecResult:
    """Bounded result returned by safe_run."""

    command: Tuple[str, ...]
    exit_code: Optional[int]
    signal_num: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool
    truncated_stdout: bool
    truncated_stderr: bool
    duration_ms: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": list(self.command),
            "exit_code": self.exit_code,
            "signal_num": self.signal_num,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "truncated_stdout": self.truncated_stdout,
            "truncated_stderr": self.truncated_stderr,
            "duration_ms": self.duration_ms,
        }
