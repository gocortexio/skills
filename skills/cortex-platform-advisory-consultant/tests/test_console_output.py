# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The banner is pinned HERE, by this bundle, for the install this bundle actually ships into.

The banner rule is a standing one: every stage is announced, every time. Until now nothing in
this bundle checked it. The only banner pins lived in the maestro's `test_preflight.py`, they
reach ACROSS bundles to do it, and they open with

    sibs = _sibling_bundles()
    if not sibs:
        pytest.skip("standalone install: no sibling bundles to check")

which is exactly the shape of the install a public reader gets. Installed on its own -- the only
way this skill is meant to be installed -- the banner had no check at all. Four things named the
page and none opened it: the same defect this project keeps finding in itself, where a claim about
a control is mistaken for a control (LAW A56).

These assertions run inside this bundle, read only files inside this bundle, and cannot skip.
`test_bundle_standard.py` was the obvious home and is the wrong one: it must stay byte-identical
across all five bundles, and the maestro announces a PHASE where an instrument announces a STAGE,
so a shared assertion would have to be vague enough to pass on either -- which is how a check
stops being one.
"""
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PAGE = os.path.join(ROOT, "references", "console-output.md")

FILL = "#" * 8


def _page():
    with open(PAGE, encoding="utf-8") as handle:
        return handle.read()


def test_the_console_page_ships():
    """A bundle with no banner page cannot copy a banner, and will type one from memory."""
    assert os.path.isfile(PAGE), (
        "references/console-output.md is missing. Without it there is nothing to copy, and "
        "LAW A12's finding applies: a banner typed from memory is not the banner."
    )


def test_the_page_carries_the_banner_art_and_the_squirrel():
    """The squirrel is the mark of the method and is the first thing a typed banner loses.

    COUNTED PER BANNER, not merely present. A presence check passes while all but one banner
    loses its squirrel -- which is what the first draft of this test did, and deleting one
    squirrel left it green because the strokes still existed elsewhere on the page. The banners
    are counted from the page rather than hard-coded, so adding one does not silently lower the
    bar; the STAGE banner's rules cannot be used to count them, because only that banner is
    framed in `#`.
    """
    text = _page()
    assert FILL in text, "the banner fill is gone from the page it is copied from"

    fenced = text.split("```")[1::2]
    banners = [b for b in fenced if "y)-" in b]
    assert len(banners) >= 3, (
        "found {} banner block(s); the page documents three banners and a variant, and each is "
        "a fenced block an author copies whole.".format(len(banners))
    )
    for stroke in (')" .', "(\\-./", "y)-"):
        missing = [i for i, b in enumerate(banners, 1) if stroke not in b]
        assert not missing, (
            "banner block(s) {} have lost the squirrel stroke {!r}. It belongs on every one -- it "
            "is the mark of the method, and the first thing a banner typed from memory "
            "loses.".format(missing, stroke)
        )


def test_the_page_shows_a_stage_banner_an_instrument_can_copy():
    """An instrument announces a STAGE where the harness announces a PHASE."""
    text = _page()
    stage_lines = [
        line for line in text.splitlines()
        if line.startswith(FILL) and re.search(r"\bSTAGE\b", line)
    ]
    assert stage_lines, (
        "no STAGE banner line in the template block. This bundle announces stages, so a page "
        "carrying only the harness's PHASE form gives its author nothing to copy."
    )


def test_the_card_tells_the_author_to_print_it_and_where_to_copy_it_from():
    """The page is inert unless SKILL.md sends the reader to it at the right moment."""
    with open(os.path.join(ROOT, "SKILL.md"), encoding="utf-8") as handle:
        card = handle.read()
    assert re.search(r"STAGE banner", card), (
        "SKILL.md never tells the author to print a STAGE banner, so the page below it is decoration"
    )
    assert "references/console-output.md" in card, (
        "SKILL.md does not point at references/console-output.md, so an author has nowhere to "
        "copy from and will type one from memory"
    )
    assert re.search(r"COPY the templates", card), (
        "SKILL.md no longer says to COPY the templates. Typing a banner from memory is the "
        "documented failure mode, not a stylistic preference."
    )
