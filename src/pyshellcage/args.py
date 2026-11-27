"""CWE-88 argument validation and typed argv construction."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, Optional, Tuple

from .errors import CODES, fail

DEFAULT_MAX_ARG_BYTES = 4096
MAX_ARG_BYTES = 65536
MAX_ARGV_SLOTS = 512

_BIDI_CONTROLS = frozenset("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
_FLAG_NAME_RE = re.compile(r"^--?[A-Za-z0-9][A-Za-z0-9_.-]*$")

_SLOT_KEYS = {
    "literal": frozenset(("type", "value")),
    "flag": frozenset(("type", "name", "flag", "value", "join", "allow_leading_dash_value")),
    "positional": frozenset(("type", "value", "allow_empty")),
    "path": frozenset(("type", "value", "allow_empty")),
    "end_of_options": frozenset(("type",)),
}


def utf8_len(value: str) -> int:
    return len(value.encode("utf-8"))


def has_lone_surrogate(value: str) -> bool:
    for char in value:
        codepoint = ord(char)
        if 0xD800 <= codepoint <= 0xDFFF:
            return True
    return False


def has_bidi_control(value: str) -> bool:
    return any(char in _BIDI_CONTROLS for char in value)


def has_control_character(value: str, allow_newlines: bool = False) -> bool:
    for char in value:
        codepoint = ord(char)
        if allow_newlines and char in ("\r", "\n"):
            continue
        if codepoint < 0x20 or 0x7F <= codepoint <= 0x9F:
            return True
    return False


def _integer_option(value: Any, default: int, minimum: int, maximum: int, name: str) -> int:
    if value is None:
        value = default
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > maximum:
        fail(CODES["CONFIG_INVALID"], name + " must be an integer in range")
    return value


def _boolean_option(value: Any, default: bool, name: str) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        fail(CODES["CONFIG_INVALID"], name + " must be a boolean")
    return value


def check_safe_arg(
    value: Any,
    *,
    allow_newlines: bool = False,
    reject_leading_dash: bool = False,
    positional: bool = False,
    max_bytes: int = DEFAULT_MAX_ARG_BYTES,
    allow_empty: bool = True,
) -> Optional[Tuple[str, str]]:
    """Return the first argument validation problem, or None."""

    max_bytes = _integer_option(max_bytes, DEFAULT_MAX_ARG_BYTES, 1, MAX_ARG_BYTES, "max_bytes")
    allow_newlines = _boolean_option(allow_newlines, False, "allow_newlines")
    reject_leading_dash = _boolean_option(reject_leading_dash, False, "reject_leading_dash")
    positional = _boolean_option(positional, False, "positional")
    allow_empty = _boolean_option(allow_empty, True, "allow_empty")

    if not isinstance(value, str):
        return (CODES["ARG_TYPE"], "argument must be a string")
    if not allow_empty and value == "":
        return (CODES["ARG_EMPTY"], "argument must not be empty")
    if "\x00" in value:
        return (CODES["ARG_NUL_BYTE"], "argument contains a NUL byte")
    if not allow_newlines and ("\r" in value or "\n" in value):
        return (CODES["ARG_NEWLINE"], "argument contains a line break")
    if has_control_character(value, allow_newlines=allow_newlines):
        return (CODES["ARG_CONTROL_CHAR"], "argument contains a control character")
    if has_bidi_control(value):
        return (CODES["ARG_BIDI_CONTROL"], "argument contains a bidirectional override control")
    if has_lone_surrogate(value):
        return (CODES["ARG_SURROGATE"], "argument contains a lone UTF-16 surrogate")
    if utf8_len(value) > max_bytes:
        return (CODES["ARG_TOO_LONG"], "argument exceeds the byte limit")
    if (positional or reject_leading_dash) and value.startswith("-"):
        return (CODES["ARG_LEADING_DASH"], "positional argument must not begin with a dash")
    return None


def assert_safe_arg(
    value: Any,
    *,
    allow_newlines: bool = False,
    reject_leading_dash: bool = False,
    positional: bool = False,
    max_bytes: int = DEFAULT_MAX_ARG_BYTES,
    allow_empty: bool = True,
) -> str:
    """Validate one argv element and return it unchanged.

    This is lexical CWE-88 validation. It never quotes or interpolates the
    value because no shell is involved.
    """

    problem = check_safe_arg(
        value,
        allow_newlines=allow_newlines,
        reject_leading_dash=reject_leading_dash,
        positional=positional,
        max_bytes=max_bytes,
        allow_empty=allow_empty,
    )
    if problem is not None:
        fail(problem[0], problem[1])
    return value


def safe_arg(value: Any, **options: Any) -> str:
    """Strict positional argument convenience wrapper."""

    options["positional"] = True
    return assert_safe_arg(value, **options)


def safe_path_arg(value: Any, **options: Any) -> str:
    """Strict positional path convenience wrapper.

    This is lexical validation only. It does not authorize filesystem access,
    prove containment, or protect against symlink races.
    """

    options["positional"] = True
    options["allow_empty"] = False
    return assert_safe_arg(value, **options)


def _slot_mapping(slot: Any, index: int) -> dict[str, Any]:
    if not isinstance(slot, Mapping):
        fail(CODES["ARGV_SPEC_INVALID"], "argv builder slots must be mappings", {"index": index})
    result = dict(slot)
    slot_type = result.get("type")
    if not isinstance(slot_type, str):
        fail(CODES["ARGV_SPEC_INVALID"], "argv builder slot requires a type", {"index": index})
    allowed = _SLOT_KEYS.get(slot_type)
    if allowed is not None:
        for key in result:
            if key not in allowed:
                fail(
                    CODES["ARGV_SPEC_INVALID"],
                    "argv builder slot contains an unknown key",
                    {"index": index, "key": key},
                )
    return result


def _validate_flag_name(name: Any, index: int) -> str:
    if not isinstance(name, str) or name == "--" or not _FLAG_NAME_RE.match(name):
        fail(
            CODES["ARGV_SPEC_INVALID"],
            "flag slot name must be a simple ASCII option spelling",
            {"index": index},
        )
    return name


def build_argv(spec: Sequence[Mapping[str, Any]]) -> Tuple[str, ...]:
    """Build immutable argv from typed slots.

    ``positional`` and ``path`` slots are for untrusted values. Before an
    ``end_of_options`` slot they may not begin with a dash, so they cannot be
    reinterpreted as flags. Use ``end_of_options`` when the target tool is
    known to honor ``--``.
    """

    if isinstance(spec, (str, bytes, bytearray)) or not isinstance(spec, Sequence):
        fail(CODES["ARGV_SPEC_INVALID"], "argv builder input must be a sequence of typed slots")
    if len(spec) > MAX_ARGV_SLOTS:
        fail(CODES["ARGV_SPEC_INVALID"], "argv builder input exceeds the slot limit")

    output = []
    seen_end = False
    for index, original_slot in enumerate(spec):
        slot = _slot_mapping(original_slot, index)
        slot_type = slot.get("type")

        if slot_type == "end_of_options":
            if seen_end:
                fail(CODES["ARGV_SPEC_INVALID"], "argv builder accepts only one end-of-options marker", {"index": index})
            seen_end = True
            output.append("--")
            continue

        if slot_type == "literal":
            if "value" not in slot:
                fail(CODES["ARGV_SPEC_INVALID"], "literal slot requires a value", {"index": index})
            assert_safe_arg(slot["value"], positional=False, max_bytes=DEFAULT_MAX_ARG_BYTES)
            output.append(slot["value"])
            continue

        if slot_type == "flag":
            if "name" in slot and "flag" in slot:
                fail(CODES["ARGV_SPEC_INVALID"], "flag slot must use either name or flag, not both", {"index": index})
            if "allow_leading_dash_value" in slot and not isinstance(slot["allow_leading_dash_value"], bool):
                fail(CODES["ARGV_SPEC_INVALID"], "allow_leading_dash_value must be a boolean", {"index": index})
            if "name" not in slot and "flag" not in slot:
                fail(CODES["ARGV_SPEC_INVALID"], "flag slot requires a name", {"index": index})
            name = _validate_flag_name(slot.get("name", slot.get("flag")), index)
            if "value" not in slot:
                output.append(name)
                continue
            join = slot.get("join", "separate")
            if join not in ("separate", "equals"):
                fail(CODES["ARGV_SPEC_INVALID"], "flag slot join must be separate or equals", {"index": index})
            if join == "equals":
                assert_safe_arg(slot["value"], positional=False, max_bytes=DEFAULT_MAX_ARG_BYTES)
                combined = name + "=" + slot["value"]
                assert_safe_arg(combined, positional=False, max_bytes=DEFAULT_MAX_ARG_BYTES)
                output.append(combined)
            else:
                assert_safe_arg(
                    slot["value"],
                    positional=not slot.get("allow_leading_dash_value", False),
                    max_bytes=DEFAULT_MAX_ARG_BYTES,
                )
                output.extend((name, slot["value"]))
            continue

        if slot_type in ("positional", "path"):
            if "value" not in slot:
                fail(CODES["ARGV_SPEC_INVALID"], "positional and path slots require a value", {"index": index})
            if "allow_empty" in slot and not isinstance(slot["allow_empty"], bool):
                fail(CODES["ARGV_SPEC_INVALID"], "allow_empty must be a boolean", {"index": index})
            allow_empty = slot.get("allow_empty", slot_type != "path")
            assert_safe_arg(
                slot["value"],
                positional=not seen_end,
                allow_empty=allow_empty,
                max_bytes=DEFAULT_MAX_ARG_BYTES,
            )
            output.append(slot["value"])
            continue

        fail(CODES["ARGV_SPEC_INVALID"], "unknown argv builder slot type", {"index": index})

    return tuple(output)
