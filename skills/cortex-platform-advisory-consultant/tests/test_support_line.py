# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""How well-backed a finding is, on the axis nothing else in the block reported.

Ranking weighs recency and CORROBORATION names independent accounts, but until 0.21.0
nothing said when anybody last confirmed the source still says what the record claims.
A reader weighing twelve findings had no way to tell the well-attested from the
never-revisited. These tests hold the line in place and, more importantly, hold its
flags honest: a flag on every finding is noise, and a flag on none is a lie.
"""
import datetime
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import consult as C  # noqa: E402

TODAY = datetime.date(2026, 8, 19)


def records():
    path = os.path.join(ROOT, "corpus", "observations", "observations.jsonl")
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def test_every_finding_carries_a_support_line():
    out = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "consult.py"),
                          "Cisco ASA", "--limit", "8", "--today", "2026-08-19"],
                         capture_output=True, text=True, cwd=ROOT).stdout
    blocks = out.split("=== FINDING ")[1:]
    assert blocks
    assert all("SUPPORT:" in b for b in blocks)


def test_a_well_attested_record_carries_no_flags():
    """If everything is flagged the flags mean nothing."""
    good = {"status": "verified",
            "when": {"published": "2026-08-01"},
            "where": {"retrieved": "2026-08-18", "verified": True}}
    line = C.support(good, TODAY)
    assert "[" not in line, line
    assert "published=2026-08-01" in line and "source_last_read=2026-08-18" in line


def test_missing_read_date_and_verification_are_flagged():
    bare = {"status": "verified", "when": {"published": "2026-08-01"}, "where": {}}
    line = C.support(bare, TODAY)
    assert "NO_READ_DATE" in line and "VERIFICATION_UNSTATED" in line


def test_missing_publication_date_says_what_it_costs():
    """age_days() silently ranks an undated record as 3650 days old; the flag must say so."""
    undated = {"status": "verified", "when": {},
               "where": {"retrieved": "2026-08-18", "verified": True}}
    line = C.support(undated, TODAY)
    assert "NO_PUBLICATION_DATE:ranked-as-3650d" in line


def test_seed_status_is_flagged():
    seed = {"status": "seed", "when": {"published": "2026-08-01"},
            "where": {"retrieved": "2026-08-18", "verified": True}}
    assert "SEED" in C.support(seed, TODAY)


def test_age_is_reported_but_never_flagged():
    """Staleness duplicates PRIORITY_BASIS days_since_published and fires on KEV by design."""
    old = {"status": "verified", "when": {"published": "2019-01-01"},
           "where": {"retrieved": "2026-08-18", "verified": True}}
    line = C.support(old, TODAY)
    assert "published=2019-01-01" in line
    assert "[" not in line, "age alone must not raise a flag: {}".format(line)


def test_flags_stay_a_minority_of_the_corpus():
    """A flag has to be a signal. If most findings carry one it is decoration."""
    obs = [r for r in records() if r.get("record_type") == "observation"]
    flagged = sum(1 for r in obs if "[" in C.support(r, TODAY))
    assert flagged < len(obs) / 2, "{} of {} observations flagged".format(flagged, len(obs))
