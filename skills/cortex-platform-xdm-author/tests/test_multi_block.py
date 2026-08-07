# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A rule file routinely holds several [MODEL: ...] blocks, one per
dataset, so multi-block is the normal case rather than an edge case.

Every check reasons about a single rule -- its temps, its stages, its
assignments -- so analysing the concatenation of several blocks is wrong
in both directions, and both directions were observed:

  - a temp unused in its own block looked USED because a later block
    defined the same name, suppressing an error-severity finding and
    letting a tenant-rejecting defect lint clean;
  - a field assigned once per block looked assigned repeatedly, producing
    a warning that advised merging assignments which must stay separate.

The verifier could not parse a multi-block file at all, which mattered
because the prepend check is mandatory for a syslog rule and a pack
modelling several datasets could not run it on the file it ships.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _helpers import bundle_root  # noqa: E402

SCRIPTS = bundle_root() / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


_lint = _load("lint_rule")
_verify = _load("verify_rule")

_UNUSED_TEMP = """[MODEL: dataset = vendor_{sfx}_raw]
filter
    _raw_log != null
| alter
    tmp_used = arrayindex(regextract(_raw_log, "X-(\\w+)"), 0),
    tmp_never_used = arrayindex(regextract(_raw_log, "Y-(\\w+)"), 0)
| alter
    xdm.observer.vendor = "V",
    xdm.event.original_event_type = coalesce(tmp_used, "GOCORTEX_UNMODELLED")
;
"""

_TAGGED = """[MODEL: dataset = vendor_{sfx}_raw]
filter
    _raw_log != null
| alter
    tmp_u = arrayindex(regextract(_raw_log, "user=(\\S+)"), 0)
| alter
    xdm.source.user.username = tmp_u,
    xdm.event.original_event_type = coalesce(tmp_u, "GOCORTEX_UNMODELLED"),
    xdm.event.tags = if(tmp_u != null, arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION))
;
"""


def _ids(source):
    return [v["rule_id"] for v in _lint.lint(source)]


class TestBlockSplitting(unittest.TestCase):
    def test_single_block_is_one_block(self):
        blocks = _lint.split_model_blocks(_UNUSED_TEMP.format(sfx="a"))
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0]["dataset"], "vendor_a_raw")

    def test_each_model_header_starts_a_block(self):
        src = _UNUSED_TEMP.format(sfx="a") + _UNUSED_TEMP.format(sfx="b")
        blocks = _lint.split_model_blocks(src)
        self.assertEqual([b["dataset"] for b in blocks],
                         ["vendor_a_raw", "vendor_b_raw"])
        self.assertGreater(blocks[1]["line_offset"], 0)


class TestErr019NotSuppressedByASecondBlock(unittest.TestCase):
    """The unused-temp check is a hard block on every dataset, so a false
    negative lets a tenant-rejecting defect ship with a clean lint."""

    def test_single_block_reports_the_unused_temp(self):
        self.assertIn("ERR-019", _ids(_UNUSED_TEMP.format(sfx="a")))

    def test_duplicating_the_block_does_not_hide_it(self):
        src = _UNUSED_TEMP.format(sfx="a") + _UNUSED_TEMP.format(sfx="b")
        errs = [v for v in _lint.lint(src) if v["rule_id"] == "ERR-019"]
        self.assertEqual(len(errs), 2, errs)

    def test_findings_carry_their_dataset_and_file_line(self):
        src = _UNUSED_TEMP.format(sfx="a") + _UNUSED_TEMP.format(sfx="b")
        errs = [v for v in _lint.lint(src) if v["rule_id"] == "ERR-019"]
        self.assertEqual([e["dataset"] for e in errs],
                         ["vendor_a_raw", "vendor_b_raw"])
        # the second block's finding points into the second block
        self.assertGreater(errs[1]["line"], errs[0]["line"])


class TestTagsPerBlockIsNotADuplicate(unittest.TestCase):
    """Two blocks each assigning their own tags is correct and necessary.
    Warning about it advises a merge that would break the rule."""

    def _dup_findings(self, source):
        return [v for v in _lint.lint(source)
                if "assigned more than once" in v["message"]]

    def test_single_block_is_silent(self):
        self.assertEqual(self._dup_findings(_TAGGED.format(sfx="a")), [])

    def test_one_assignment_per_block_is_not_a_duplicate(self):
        src = _TAGGED.format(sfx="a") + _TAGGED.format(sfx="b")
        self.assertEqual(self._dup_findings(src), [])

    def test_a_real_duplicate_within_one_block_still_fires(self):
        doubled = _TAGGED.format(sfx="a").replace(
            "    xdm.event.tags = if(tmp_u != null, arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION))\n;",
            "    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION),\n"
            "    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_NETWORK)\n;",
        )
        self.assertTrue(self._dup_findings(doubled))


class TestVerifierHandlesMultiBlock(unittest.TestCase):
    def test_splitter_finds_every_block(self):
        src = _TAGGED.format(sfx="a") + _TAGGED.format(sfx="b")
        blocks = _verify.split_model_blocks(src)
        self.assertEqual([b["dataset"] for b in blocks],
                         ["vendor_a_raw", "vendor_b_raw"])

    def test_each_block_evaluates_on_its_own(self):
        src = _TAGGED.format(sfx="a") + _TAGGED.format(sfx="b")
        rec = {"_raw_log": "user=alice"}
        for blk in _verify.split_model_blocks(src):
            out = _verify.evaluate_rule(blk["text"], rec)
            self.assertEqual(out.get("xdm.source.user.username"), "alice")


class TestBlockStartAnchorsOnTheHeaderLine(unittest.TestCase):
    """A block start must anchor on the header LINE, not on the run of
    whitespace before it.

    `^\\s*\\[MODEL:` also matches the preceding newline, so a block with a
    blank line in front -- the normal way to format a multi-block rule --
    began on that blank line, and the dataset name was then parsed from
    an empty string and came back None. Every block after the first lost
    its name, which made `--dataset` unable to select it and made the
    linter label its findings with no dataset. Both tools shared the
    pattern, so both were wrong in the same way."""

    _TWO = (
        "[MODEL: dataset={first}]\n"
        "filter\n    _raw_log != null\n"
        '| alter\n    xdm.event.type = "x"\n;\n'
        "{gap}"
        "[MODEL: dataset={second}]\n"
        "filter\n    _raw_log != null\n"
        '| alter\n    xdm.event.type = "y"\n;\n'
    )

    def _names(self, src: str) -> list:
        lint_names = [b.get("dataset") for b in _lint.split_model_blocks(src)]
        verify_names = [b["dataset"] for b in _verify.split_model_blocks(src)]
        self.assertEqual(
            lint_names, verify_names, "the two splitters disagree on dataset names"
        )
        return verify_names

    def test_blank_line_between_blocks(self):
        src = self._TWO.format(first="a_raw", second="b_raw", gap="\n")
        self.assertEqual(self._names(src), ["a_raw", "b_raw"])

    def test_several_blank_lines_between_blocks(self):
        src = self._TWO.format(first="a_raw", second="b_raw", gap="\n\n\n")
        self.assertEqual(self._names(src), ["a_raw", "b_raw"])

    def test_no_blank_line_between_blocks(self):
        src = self._TWO.format(first="a_raw", second="b_raw", gap="")
        self.assertEqual(self._names(src), ["a_raw", "b_raw"])

    def test_spaced_equals_in_the_header(self):
        """`dataset = x` is accepted by the platform and deployed."""
        src = (
            "[MODEL: dataset = a_raw]\n"
            "filter\n    _raw_log != null\n"
            '| alter\n    xdm.event.type = "x"\n;\n\n'
            "[MODEL: dataset = b_raw]\n"
            "filter\n    _raw_log != null\n"
            '| alter\n    xdm.event.type = "y"\n;\n'
        )
        self.assertEqual(self._names(src), ["a_raw", "b_raw"])

    def test_mapped_header_comment_does_not_start_a_block(self):
        """A rule's MAPPED header routinely quotes the MODEL line. A
        commented-out header must not be mistaken for a real one."""
        src = (
            "// SPDX-License-Identifier: AGPL-3.0-or-later\n"
            "// MAPPED\n"
            "//   [MODEL: dataset = a_raw]  <- shown as an example\n"
            "//\n"
            "[MODEL: dataset = a_raw]\n"
            "filter\n    _raw_log != null\n"
            '| alter\n    xdm.event.type = "x"\n;\n\n'
            "[MODEL: dataset = b_raw]\n"
            "filter\n    _raw_log != null\n"
            '| alter\n    xdm.event.type = "y"\n;\n'
        )
        self.assertEqual(self._names(src), ["a_raw", "b_raw"])

    def test_indented_header_still_found(self):
        src = (
            "  [MODEL: dataset=a_raw]\n"
            "filter\n    _raw_log != null\n"
            '| alter\n    xdm.event.type = "x"\n;\n\n'
            "\t[MODEL: dataset=b_raw]\n"
            "filter\n    _raw_log != null\n"
            '| alter\n    xdm.event.type = "y"\n;\n'
        )
        self.assertEqual(self._names(src), ["a_raw", "b_raw"])


if __name__ == "__main__":
    unittest.main()
