"""Argument validation and typed argv builder tests."""

from __future__ import annotations

import unittest

from pyshellcage import CODES, ShellCageError, assert_safe_arg, build_argv, safe_arg, safe_path_arg
from _matrix import add_matrix


def raised_code(testcase, function, *args, **kwargs):
    with testcase.assertRaises(ShellCageError) as caught:
        function(*args, **kwargs)
    return caught.exception.code


class SafeArgDirectTests(unittest.TestCase):
    def test_returns_same_string_object_value(self):
        value = "ordinary value with spaces"
        self.assertEqual(value, assert_safe_arg(value))

    def test_positional_rejects_leading_dash(self):
        self.assertEqual(CODES["ARG_LEADING_DASH"], raised_code(self, assert_safe_arg, "-x", positional=True))

    def test_reject_leading_dash_without_positional(self):
        self.assertEqual(CODES["ARG_LEADING_DASH"], raised_code(self, assert_safe_arg, "--x", reject_leading_dash=True))

    def test_nonpositional_allows_leading_dash(self):
        self.assertEqual("--fixed", assert_safe_arg("--fixed"))

    def test_safe_arg_is_positional(self):
        self.assertEqual(CODES["ARG_LEADING_DASH"], raised_code(self, safe_arg, "-file"))

    def test_safe_path_arg_rejects_empty(self):
        self.assertEqual(CODES["ARG_EMPTY"], raised_code(self, safe_path_arg, ""))

    def test_safe_path_arg_accepts_parent_traversal_lexically(self):
        self.assertEqual("../outside", safe_path_arg("../outside"))

    def test_safe_path_arg_rejects_leading_dash(self):
        self.assertEqual(CODES["ARG_LEADING_DASH"], raised_code(self, safe_path_arg, "-/tmp/x"))

    def test_max_bytes_boundary_accepts_exact_ascii(self):
        self.assertEqual("abcd", assert_safe_arg("abcd", max_bytes=4))

    def test_max_bytes_boundary_rejects_one_over_ascii(self):
        self.assertEqual(CODES["ARG_TOO_LONG"], raised_code(self, assert_safe_arg, "abcde", max_bytes=4))

    def test_max_bytes_counts_utf8_not_characters(self):
        self.assertEqual(CODES["ARG_TOO_LONG"], raised_code(self, assert_safe_arg, "€", max_bytes=2))

    def test_max_bytes_accepts_exact_multibyte(self):
        self.assertEqual("€", assert_safe_arg("€", max_bytes=3))

    def test_allow_newlines_accepts_lf(self):
        self.assertEqual("a\nb", assert_safe_arg("a\nb", allow_newlines=True))

    def test_allow_newlines_accepts_crlf(self):
        self.assertEqual("a\r\nb", assert_safe_arg("a\r\nb", allow_newlines=True))

    def test_allow_newlines_still_rejects_tab(self):
        self.assertEqual(CODES["ARG_CONTROL_CHAR"], raised_code(self, assert_safe_arg, "a\tb", allow_newlines=True))

    def test_invalid_max_bytes_type(self):
        self.assertEqual(CODES["CONFIG_INVALID"], raised_code(self, assert_safe_arg, "x", max_bytes=True))

    def test_invalid_allow_newlines_type(self):
        self.assertEqual(CODES["CONFIG_INVALID"], raised_code(self, assert_safe_arg, "x", allow_newlines=1))

    def test_empty_allowed_by_default(self):
        self.assertEqual("", assert_safe_arg(""))

    def test_empty_rejected_when_configured(self):
        self.assertEqual(CODES["ARG_EMPTY"], raised_code(self, assert_safe_arg, "", allow_empty=False))


class SafeArgValidMatrixTests(unittest.TestCase):
    pass


_VALID_ARG_CASES = [
    "plain",
    "with spaces",
    "equals=value",
    "unicode-",
    "€",
    "file.txt",
    "../parent",
    "a/b/c",
    "a\\b\\c",
    "colon:value",
    "dash-in-middle",
    "under_score",
    "digits123",
    "tilde~",
    "comma,value",
    "semicolon;value",
    "pipe|value",
    "ampersand&value",
    "dollar$value",
    "backtick`value",
]


def _valid_arg_body(self, value):
    self.assertEqual(value, assert_safe_arg(value))


add_matrix(SafeArgValidMatrixTests, "valid_arg", _VALID_ARG_CASES, _valid_arg_body)


class SafeArgRejectMatrixTests(unittest.TestCase):
    pass


_REJECT_CASES = []
_REJECT_CASES.append(("a\x00b", {}, CODES["ARG_NUL_BYTE"]))
_REJECT_CASES.append(("\x00", {}, CODES["ARG_NUL_BYTE"]))
_REJECT_CASES.append(("abc\x00", {}, CODES["ARG_NUL_BYTE"]))
for _char in ("\r", "\n"):
    _REJECT_CASES.append(("a" + _char + "b", {}, CODES["ARG_NEWLINE"]))
    _REJECT_CASES.append((_char, {}, CODES["ARG_NEWLINE"]))
for _codepoint in list(range(1, 9)) + [11, 12] + list(range(14, 32)) + list(range(127, 160)):
    if _codepoint in (10, 13):
        continue
    _REJECT_CASES.append(("a" + chr(_codepoint) + "b", {}, CODES["ARG_CONTROL_CHAR"]))
for _codepoint in (0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069):
    _REJECT_CASES.append(("a" + chr(_codepoint) + "b", {}, CODES["ARG_BIDI_CONTROL"]))
for _codepoint in (0xD800, 0xD801, 0xDB7F, 0xDB80, 0xDBFF, 0xDC00, 0xDC80, 0xDFFF):
    _REJECT_CASES.append(("a" + chr(_codepoint) + "b", {}, CODES["ARG_SURROGATE"]))
for _value in ("-", "-x", "--", "--flag", "-/", "-€"):
    _REJECT_CASES.append((_value, {"positional": True}, CODES["ARG_LEADING_DASH"]))
for _value in (None, b"abc", bytearray(b"abc"), 0, 1.5, object(), [], {}, ()):
    _REJECT_CASES.append((_value, {}, CODES["ARG_TYPE"]))


def _reject_arg_body(self, value, options, code):
    self.assertEqual(code, raised_code(self, assert_safe_arg, value, **options))


add_matrix(SafeArgRejectMatrixTests, "reject_arg", _REJECT_CASES, _reject_arg_body)


class BuildArgvValidTests(unittest.TestCase):
    def test_literal_only(self):
        self.assertEqual(("status",), build_argv([{"type": "literal", "value": "status"}]))

    def test_literal_may_be_fixed_flag(self):
        self.assertEqual(("--verbose",), build_argv([{"type": "literal", "value": "--verbose"}]))

    def test_flag_without_value(self):
        self.assertEqual(("--verbose",), build_argv([{"type": "flag", "name": "--verbose"}]))

    def test_flag_separate_value(self):
        self.assertEqual(
            ("--depth", "1"),
            build_argv([{"type": "flag", "name": "--depth", "value": "1"}]),
        )

    def test_flag_equals_value(self):
        self.assertEqual(
            ("--depth=1",),
            build_argv([{"type": "flag", "name": "--depth", "value": "1", "join": "equals"}]),
        )

    def test_flag_alias(self):
        self.assertEqual(("-q",), build_argv([{"type": "flag", "flag": "-q"}]))

    def test_flag_negative_value_explicitly_allowed(self):
        self.assertEqual(
            ("--number", "-1"),
            build_argv([{"type": "flag", "name": "--number", "value": "-1", "allow_leading_dash_value": True}]),
        )

    def test_positional_before_end_rejects_dash(self):
        code = raised_code(self, build_argv, [{"type": "positional", "value": "--evil"}])
        self.assertEqual(CODES["ARG_LEADING_DASH"], code)

    def test_positional_after_end_allows_dash(self):
        argv = build_argv([{"type": "end_of_options"}, {"type": "positional", "value": "--not-a-flag"}])
        self.assertEqual(("--", "--not-a-flag"), argv)

    def test_path_after_end_allows_dash(self):
        argv = build_argv([{"type": "end_of_options"}, {"type": "path", "value": "--file"}])
        self.assertEqual(("--", "--file"), argv)

    def test_full_git_like_spec(self):
        argv = build_argv(
            [
                {"type": "literal", "value": "clone"},
                {"type": "flag", "name": "--depth", "value": "1"},
                {"type": "end_of_options"},
                {"type": "positional", "value": "--upload-pack=evil"},
                {"type": "path", "value": "destination"},
            ]
        )
        self.assertEqual(("clone", "--depth", "1", "--", "--upload-pack=evil", "destination"), argv)

    def test_output_is_tuple(self):
        self.assertIsInstance(build_argv([]), tuple)

    def test_empty_spec_is_empty_tuple(self):
        self.assertEqual(tuple(), build_argv([]))

    def test_input_tuple_accepted(self):
        self.assertEqual(("x",), build_argv(({"type": "literal", "value": "x"},)))

    def test_positional_empty_allowed_by_default(self):
        self.assertEqual(("",), build_argv([{"type": "positional", "value": ""}]))

    def test_positional_empty_can_be_rejected(self):
        code = raised_code(self, build_argv, [{"type": "positional", "value": "", "allow_empty": False}])
        self.assertEqual(CODES["ARG_EMPTY"], code)

    def test_path_empty_rejected(self):
        code = raised_code(self, build_argv, [{"type": "path", "value": ""}])
        self.assertEqual(CODES["ARG_EMPTY"], code)


class BuildArgvValidMatrixTests(unittest.TestCase):
    pass


_VALID_FLAG_NAMES = [
    "-a",
    "-z",
    "-0",
    "--a",
    "--verbose",
    "--depth",
    "--output-dir",
    "--long_name",
    "--dot.name",
    "--x-y_z.1",
    "-A",
    "-Z",
    "--123",
    "--a1",
    "--a-",
]


def _valid_flag_body(self, name):
    self.assertEqual((name,), build_argv([{"type": "flag", "name": name}]))


add_matrix(BuildArgvValidMatrixTests, "valid_flag", _VALID_FLAG_NAMES, _valid_flag_body)


class BuildArgvInvalidMatrixTests(unittest.TestCase):
    pass


_INVALID_FLAG_NAMES = [
    "",
    "--",
    "-",
    "---",
    "--é",
    "--has space",
    "--has\ttab",
    "--has\nnewline",
    "--x=y",
    "/flag",
    "flag",
    "\u2013flag",
    "--flag\x00",
    "--flag:stream",
]


def _invalid_flag_body(self, name):
    self.assertEqual(CODES["ARGV_SPEC_INVALID"], raised_code(self, build_argv, [{"type": "flag", "name": name}]))


add_matrix(BuildArgvInvalidMatrixTests, "invalid_flag", _INVALID_FLAG_NAMES, _invalid_flag_body)


class BuildArgvSpecMatrixTests(unittest.TestCase):
    pass


_SPEC_CASES = [
    ("x", CODES["ARGV_SPEC_INVALID"]),
    (b"x", CODES["ARGV_SPEC_INVALID"]),
    (123, CODES["ARGV_SPEC_INVALID"]),
    (None, CODES["ARGV_SPEC_INVALID"]),
]


def _invalid_spec_type_body(self, spec, code):
    self.assertEqual(code, raised_code(self, build_argv, spec))


add_matrix(BuildArgvSpecMatrixTests, "invalid_spec_type", _SPEC_CASES, _invalid_spec_type_body)


class BuildArgvInvalidSlotTests(unittest.TestCase):
    def test_slot_must_be_mapping(self):
        self.assertEqual(CODES["ARGV_SPEC_INVALID"], raised_code(self, build_argv, ["x"]))

    def test_slot_type_required(self):
        self.assertEqual(CODES["ARGV_SPEC_INVALID"], raised_code(self, build_argv, [{"value": "x"}]))

    def test_unknown_slot_type(self):
        self.assertEqual(CODES["ARGV_SPEC_INVALID"], raised_code(self, build_argv, [{"type": "unknown", "value": "x"}]))

    def test_unknown_slot_key(self):
        self.assertEqual(
            CODES["ARGV_SPEC_INVALID"],
            raised_code(self, build_argv, [{"type": "literal", "value": "x", "extra": True}]),
        )

    def test_literal_requires_value(self):
        self.assertEqual(CODES["ARGV_SPEC_INVALID"], raised_code(self, build_argv, [{"type": "literal"}]))

    def test_literal_rejects_control(self):
        self.assertEqual(CODES["ARG_CONTROL_CHAR"], raised_code(self, build_argv, [{"type": "literal", "value": "a\tb"}]))

    def test_flag_name_and_flag_conflict(self):
        self.assertEqual(
            CODES["ARGV_SPEC_INVALID"],
            raised_code(self, build_argv, [{"type": "flag", "name": "-a", "flag": "-b"}]),
        )

    def test_flag_requires_name_or_flag(self):
        self.assertEqual(CODES["ARGV_SPEC_INVALID"], raised_code(self, build_argv, [{"type": "flag"}]))

    def test_flag_join_invalid(self):
        self.assertEqual(
            CODES["ARGV_SPEC_INVALID"],
            raised_code(self, build_argv, [{"type": "flag", "name": "--x", "value": "y", "join": "space"}]),
        )

    def test_flag_value_leading_dash_rejected_by_default(self):
        self.assertEqual(
            CODES["ARG_LEADING_DASH"],
            raised_code(self, build_argv, [{"type": "flag", "name": "--x", "value": "-y"}]),
        )

    def test_flag_equals_allows_dash_inside_value(self):
        argv = build_argv([{"type": "flag", "name": "--x", "value": "-y", "join": "equals"}])
        self.assertEqual(("--x=-y",), argv)

    def test_duplicate_end_marker_rejected(self):
        self.assertEqual(
            CODES["ARGV_SPEC_INVALID"],
            raised_code(self, build_argv, [{"type": "end_of_options"}, {"type": "end_of_options"}]),
        )

    def test_positional_requires_value(self):
        self.assertEqual(CODES["ARGV_SPEC_INVALID"], raised_code(self, build_argv, [{"type": "positional"}]))

    def test_path_requires_value(self):
        self.assertEqual(CODES["ARGV_SPEC_INVALID"], raised_code(self, build_argv, [{"type": "path"}]))

    def test_allow_empty_type_checked(self):
        self.assertEqual(
            CODES["ARGV_SPEC_INVALID"],
            raised_code(self, build_argv, [{"type": "positional", "value": "x", "allow_empty": 1}]),
        )

    def test_allow_leading_dash_value_type_checked(self):
        self.assertEqual(
            CODES["ARGV_SPEC_INVALID"],
            raised_code(
                self,
                build_argv,
                [{"type": "flag", "name": "--x", "value": "-1", "allow_leading_dash_value": 1}],
            ),
        )

    def test_spec_longer_than_limit_rejected(self):
        spec = [{"type": "literal", "value": "x"}] * 513
        self.assertEqual(CODES["ARGV_SPEC_INVALID"], raised_code(self, build_argv, spec))

    def test_builder_does_not_mutate_slot(self):
        slot = {"type": "positional", "value": "x"}
        build_argv([slot])
        self.assertEqual({"type": "positional", "value": "x"}, slot)


if __name__ == "__main__":
    unittest.main()
