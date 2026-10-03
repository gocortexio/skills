# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""external_corroboration on patterns must be current, and must say what it counted.

The block is generated on the maintainer side from the Sigma and Splunk rule libraries, and
nothing in this bundle can re-run it. What the bundle CAN check is that the blocks agree with
the patterns they sit on. That catches both ways the block went stale before 0.42.0:

- A pattern added after the last run carried no block at all, and advise.py told a caller "no
  public rule library" implements it. 152 patterns were in that state for two months. Any
  technique another pattern is corroborated on has rules, so a pattern citing it with no block
  is stale, not uncorroborated.
- An ATT&CK id migration renamed a pattern's techniques and left its block counting rules for
  the old id. A matched technique the pattern no longer cites is stale.

Run with PYTHONDONTWRITEBYTECODE=1 (LAW A26).
"""
import json
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
with open(os.path.join(ROOT, "corpus", "patterns", "patterns.jsonl"), encoding="utf-8") as h:
    PATTERNS = [json.loads(line) for line in h if line.strip()]

SIGMA = "SigmaHQ/sigma (Detection Rule License 1.1)"
SPLUNK = "splunk/security_content (Apache 2.0)"


def techniques(pattern):
    return {t.upper() for t in pattern.get("technique") or []}


def test_every_matched_technique_is_one_the_pattern_still_cites():
    stale = []
    for p in PATTERNS:
        block = p.get("external_corroboration")
        if block:
            extra = set(block.get("techniques_matched") or []) - techniques(p)
            if extra:
                stale.append((p["id"], sorted(extra)))
    assert not stale, "blocks counting rules for ids their pattern no longer cites: {}".format(stale[:8])


def test_a_pattern_citing_a_corroborated_technique_carries_a_block_that_matches_it():
    corroborated = set()
    for p in PATTERNS:
        corroborated |= set((p.get("external_corroboration") or {}).get("techniques_matched") or [])
    missing = []
    for p in PATTERNS:
        owed = techniques(p) & corroborated
        got = set((p.get("external_corroboration") or {}).get("techniques_matched") or [])
        if owed - got:
            missing.append((p["id"], sorted(owed - got)))
    assert not missing, ("patterns citing techniques other patterns are corroborated on, with no "
                         "block matching them -- corroboration was not re-run after they were added "
                         "or changed: {}".format(missing[:8]))


@pytest.mark.parametrize("pattern", [p for p in PATTERNS if p.get("external_corroboration")],
                         ids=lambda p: p["id"])
def test_a_block_names_exactly_the_libraries_that_contributed(pattern):
    block = pattern["external_corroboration"]
    assert block["sigma_rules"] + block["splunk_detections"] > 0
    expected = [s for s, n in ((SIGMA, block["sigma_rules"]), (SPLUNK, block["splunk_detections"])) if n]
    assert block["sources"] == expected, (pattern["id"], block["sources"], expected)
