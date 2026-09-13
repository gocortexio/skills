# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The spread must be what the header says it is, and the key set must not move.

Two invariants, and they fail in opposite directions.

The first is the house one: a printed count describes what was emitted. LOCUS_MATCHED,
LOCUS_SHOWN, LOCUS_DISPLACED and LOCUS_RESERVED are four counts over the same set, and a
quota that silently dropped a finding it never accounted for would leave every one of
them looking authoritative. So the displacement is checked by differencing the spread run
against --no-locus-spread, rather than by trusting the number.

The second is new to this bundle. consult.py's contract says the key set does not vary
between findings even when a field is empty, because an absent key would have to be
distinguished from an empty one. Nothing tested it. RESPONSE_DOCTRINE was conditional in
code and only ever non-empty by accident of six always-on doctrine rules; it is now
unconditional, and this file is what stops the next block going the same way.

Run with PYTHONDONTWRITEBYTECODE=1 (LAW A26).
"""
import json
import pathlib
import re
import subprocess
import sys

import pytest

BUNDLE = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = BUNDLE / "scripts"
SCHEMA = BUNDLE / "corpus" / "schema"

# Fixed so ranking is reproducible: recency is an input to the score, and the score is
# what the quota reserves against.
TODAY = "2026-08-08"

# Cisco ASA resolves to 115 findings across five populated loci with one absent, which
# exercises every branch: displacement, reservation, an absent locus and underservice.
# The other two are a broad endpoint question and an OT one, so the key-set assertion is
# not made against a single product class.
QUESTIONS = ["I have a Cisco ASA", "Microsoft Windows", "SCADA"]

LOCI = sorted(json.loads((SCHEMA / "vocab.json").read_text(encoding="utf-8"))["locus"])


def run(*argv):
    done = subprocess.run(
        [sys.executable, str(SCRIPTS / "consult.py"), *argv],
        capture_output=True, text=True, timeout=180)
    return done.returncode, done.stdout, done.stderr


def consult(question, *extra):
    code, out, err = run(question, "--today", TODAY, *extra)
    assert code == 0, "consult.py exited {}: {}".format(code, err)
    return out


def dist(stdout, key):
    """Parse a 'KEY: A=1, B=2  (aside)' header line into a dict."""
    for line in stdout.splitlines():
        if line.startswith(key + ":"):
            body = line.split(":", 1)[1].split("(")[0].strip()
            if body in ("none", ""):
                return {}
            return {k.strip(): int(v) for k, v in
                    (part.split("=") for part in body.split(","))}
    raise AssertionError("{} not printed".format(key))


def shown_loci(stdout):
    return [l.split(":", 1)[1].strip() for l in stdout.splitlines()
            if l.startswith("LOCUS: ")]


def identities(stdout):
    """(RECORD_ID, PATTERN_ID) for each finding, in printed order."""
    rec = [l.split(":", 1)[1].strip() for l in stdout.splitlines() if l.startswith("RECORD_ID: ")]
    pat = [l.split(":", 1)[1].strip() for l in stdout.splitlines() if l.startswith("PATTERN_ID: ")]
    assert len(rec) == len(pat)
    return list(zip(rec, pat))


def bullets(stdout, key):
    """The indented body lines that follow a LOCUS_DISPLACED / LOCUS_RESERVED header."""
    lines = stdout.splitlines()
    for i, line in enumerate(lines):
        if line.startswith(key + ":"):
            out = []
            for follow in lines[i + 1:]:
                if not follow.startswith("  - "):
                    break
                out.append(follow)
            return out
    raise AssertionError("{} not printed".format(key))


@pytest.mark.parametrize("limit", [3, 6, 12, 500])
@pytest.mark.parametrize("question", QUESTIONS)
def test_locus_shown_distribution_matches_the_findings_printed(question, limit):
    out = consult(question, "--limit", str(limit))
    header = dist(out, "LOCUS_SHOWN")
    printed = shown_loci(out)
    for locus in LOCI:
        assert header.get(locus, 0) == printed.count(locus), \
            "LOCUS_SHOWN claims {} {}, printed {}".format(
                header.get(locus, 0), locus, printed.count(locus))
    assert sum(header.values()) == len(printed)
    assert len(printed) == out.count("=== FINDING ")
    matched = dist(out, "LOCUS_MATCHED")
    for locus in LOCI:
        assert header.get(locus, 0) <= matched.get(locus, 0)


@pytest.mark.parametrize("question", QUESTIONS)
def test_locus_matched_total_is_not_changed_by_the_limit(question):
    """The match set is a property of the question, never of the truncation."""
    totals = set()
    for limit in ("3", "12", "500"):
        out = consult(question, "--limit", limit)
        totals.add(tuple(sorted(dist(out, "LOCUS_MATCHED").items())))
        stated = re.search(r"FINDINGS: \d+ shown of (\d+) matched", out)
        assert stated, "FINDINGS line missing"
        assert sum(dist(out, "LOCUS_MATCHED").values()) == int(stated.group(1))
    assert len(totals) == 1, "LOCUS_MATCHED moved when --limit changed"


@pytest.mark.parametrize("question", QUESTIONS)
def test_locus_absent_names_every_locus_with_no_match(question):
    """Reads the vocabulary rather than hard-coding six, so a seventh cannot pass."""
    out = consult(question, "--limit", "12")
    matched = dist(out, "LOCUS_MATCHED")
    line = [l for l in out.splitlines() if l.startswith("LOCUS_ABSENT:")][0]
    body = line.split(":", 1)[1].split(" - ")[0].strip()
    named = set() if body.startswith("none") else {x.strip() for x in body.split(",")}
    assert named == {l for l in LOCI if not matched.get(l, 0)}
    assert set(matched) == set(LOCI), "LOCUS_MATCHED must list every locus, zeros included"


@pytest.mark.parametrize("question", QUESTIONS)
def test_displacement_count_matches_the_diff_against_no_spread(question):
    """The one that catches a quota dropping a finding it never accounted for."""
    limit = 12
    spread = consult(question, "--limit", str(limit))
    pure = consult(question, "--limit", str(limit), "--no-locus-spread")

    lost = [x for x in identities(pure) if x not in identities(spread)]
    reported = bullets(spread, "LOCUS_DISPLACED")
    assert len(lost) == len(reported), \
        "{} finding(s) vanished against pure order, {} reported".format(len(lost), len(reported))
    for record_id, pattern_id in lost:
        assert any(record_id in line and pattern_id in line for line in reported), \
            "{} / {} was displaced and not named".format(record_id, pattern_id)

    # Every slot taken from below the cut costs exactly one above it.
    assert len(bullets(spread, "LOCUS_RESERVED")) == len(reported)
    for key in ("LOCUS_DISPLACED", "LOCUS_RESERVED"):
        stated = int([l for l in spread.splitlines()
                      if l.startswith(key + ":")][0].split(":")[1].strip().split()[0])
        assert stated == len(bullets(spread, key))


@pytest.mark.parametrize("question", QUESTIONS)
def test_no_locus_spread_restores_pure_criticality_order(question):
    out = consult(question, "--limit", "12", "--no-locus-spread")
    scores = [float(m) for m in re.findall(r"PRIORITY_BASIS: score=([0-9.]+)", out)]
    assert scores == sorted(scores, reverse=True), "pure order is not descending by score"
    assert bullets(out, "LOCUS_DISPLACED") == []
    assert out.count("LOCUS_UNDERSERVED:") == 0
    # The distribution is still reported, which is the point of the flag.
    assert dist(out, "LOCUS_MATCHED") and dist(out, "LOCUS_SHOWN")


def test_underserved_appears_only_when_the_limit_is_below_the_populated_count():
    tight = consult("I have a Cisco ASA", "--limit", "3")
    populated = sum(1 for v in dist(tight, "LOCUS_MATCHED").values() if v)
    assert populated > 3, "fixture no longer exercises underservice"
    line = [l for l in tight.splitlines() if l.startswith("LOCUS_UNDERSERVED:")]
    assert len(line) == 1
    shown = dist(tight, "LOCUS_SHOWN")
    for locus in LOCI:
        if dist(tight, "LOCUS_MATCHED").get(locus, 0) and not shown.get(locus, 0):
            assert locus in line[0], "{} got no slot and was not named".format(locus)

    roomy = consult("I have a Cisco ASA", "--limit", str(populated))
    assert "LOCUS_UNDERSERVED:" not in roomy


def test_spread_reserves_a_slot_for_every_populated_locus_when_the_limit_allows():
    for question in QUESTIONS:
        out = consult(question, "--limit", "12")
        matched, shown = dist(out, "LOCUS_MATCHED"), dist(out, "LOCUS_SHOWN")
        populated = [l for l in LOCI if matched.get(l, 0)]
        if len(populated) > 12:
            continue
        for locus in populated:
            assert shown.get(locus, 0) >= 1, \
                "{} has {} match(es) and no slot in {}".format(locus, matched[locus], question)


@pytest.mark.parametrize("rank_by", ["criticality", "gap"])
@pytest.mark.parametrize("question", QUESTIONS)
def test_every_finding_carries_the_same_key_set(question, rank_by):
    """The contract consult.py states in its own docstring and never tested.

    Sub-lines are all indented, so a column-zero anchor is the key set.
    """
    extra = ["--rank-by", rank_by]
    if rank_by == "gap":
        extra += ["--covered", "T1190,T1078"]
    out = consult(question, "--limit", "12", *extra)

    blocks, current = [], None
    for line in out.splitlines():
        if line.startswith("=== FINDING "):
            current = set()
        elif line.startswith("=== END FINDING "):
            blocks.append(frozenset(current))
            current = None
        elif current is not None:
            match = re.match(r"^([A-Z][A-Z0-9_]*):", line)
            if match:
                current.add(match.group(1))

    assert blocks, "no findings emitted"
    assert len(set(blocks)) == 1, "key set varies between findings: {}".format(
        set.symmetric_difference(*map(set, (blocks[0], next(b for b in blocks if b != blocks[0])))))
    assert {"LOCUS", "LOCUS_SPAN", "LOCUS_BASIS"} <= blocks[0]
    assert "RESPONSE_DOCTRINE" in blocks[0], "the block that used to be conditional"


@pytest.mark.parametrize("question", QUESTIONS)
def test_locus_span_always_leads_with_the_primary(question):
    """One code path for the consumer: split on ', ' and get one or two, never '-'."""
    out = consult(question, "--limit", "12")
    primary = shown_loci(out)
    spans = [l.split(":", 1)[1].strip() for l in out.splitlines() if l.startswith("LOCUS_SPAN: ")]
    assert len(spans) == len(primary)
    for locus, span in zip(primary, spans):
        parts = [p.strip() for p in span.split(",")]
        assert 1 <= len(parts) <= 2
        assert parts[0] == locus
        assert len(set(parts)) == len(parts), "span repeats the primary"
        assert all(p in LOCI for p in parts)
