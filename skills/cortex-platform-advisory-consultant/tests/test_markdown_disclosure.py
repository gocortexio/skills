# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The prose is held to the disclosure rule it documents.

corpus/README.md stated "No report identifier anywhere in the record. `validate.py` fails the
build if it finds one" and then printed a real licensed report's filing in its true form, two
lines below, as the worked example of the rule. It shipped that way, and TWO independent
defects had to hold for it to:

Every identifier below is SYNTHETIC. The first draft of this file used the real filing as its
fixture, which would have kept the thing in the repository under the test written to keep it
out -- the same instinct that put it in corpus/README.md, that an example is exempt.

  1. `check_disclosure` runs per record. No validator pass opened a markdown file at all, so
     the documents stating the rule were the only documents exempt from it.
  2. The identifier patterns carried a TRAILING `\\b`. A report identifier is almost always
     written inside the filename it was filed under, and `_` is a word character, so the
     boundary never fired after the digits. The check could not have caught the leak even had
     it been looking -- and could not have caught the same string inside a record either.

Both are fixed. These tests hold them fixed, because the second one is invisible: a regex that
silently fails to match reads exactly like a regex that found nothing.
"""
import os
import pathlib
import re
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import validate as V  # noqa: E402


def test_no_shipped_markdown_carries_a_report_identifier():
    """The live assertion. Every .md in the bundle, every identifier pattern."""
    problems = []
    V.check_markdown_disclosure(pathlib.Path(ROOT), problems)
    assert not problems, "\n".join(str(p) for p in problems)


@pytest.mark.parametrize("text", [
    "TR-1234-56_Synthetic_Filing_Name",
    "WV-1234_Some_Subject",
    "IR-2021-7_Another_Filing",
    "RPT-88_Filed_Under_This",
    "DRA-42_Report_Name",
])
def test_an_identifier_inside_a_filename_is_caught(text):
    """The defect that let the leak through: `_` is a word character.

    If a trailing `\\b` is ever restored to REPORT_ID_PATTERNS these all go quiet, and quiet
    is indistinguishable from clean. That is what makes this worth a test of its own.
    """
    assert any(p.search(text) for p in V.REPORT_ID_PATTERNS), (
        "{!r} matched no identifier pattern; a trailing word boundary has probably been "
        "reintroduced, and an identifier written in filename form is invisible again".format(text))


def test_the_bare_form_still_matches():
    """Widening the pattern must not have cost the case it already handled."""
    for text in ("TR-1234-56", "report TR-1234-56.", "see WV-4321 for detail"):
        assert any(p.search(text) for p in V.REPORT_ID_PATTERNS), text


def test_the_check_actually_reads_the_files_rather_than_passing_vacuously(tmp_path):
    """A check that scans nothing passes everything, which is the failure mode above."""
    (tmp_path / "planted.md").write_text(
        "An example citing TR-1234-56_Subject_Words inline.", encoding="utf-8")
    problems = []
    V.check_markdown_disclosure(tmp_path, problems)
    assert len(problems) == 1, "the planted identifier was not seen"
    assert "TR-1234-56" in str(problems[0])
