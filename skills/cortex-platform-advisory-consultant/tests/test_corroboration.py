# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The corroboration list, and the failure it was introduced to stop.

Until 0.19.0 `where` carried a single `corroborating_publisher` and a single
`corroborating_url`. A third publisher on one mechanism therefore had nowhere to go, and
one was refused on 2026-08-18 for that reason rather than on its merits. These tests hold
the replacement in place: the list shape, the loud failure on the old shape, and the fact
that a consultation prints it -- the old fields were read by nothing at all, so a second
account changed no output anywhere and could not be seen by anyone consuming the corpus.
"""
import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OBS = os.path.join(ROOT, "corpus", "observations", "observations.jsonl")


def records():
    with open(OBS, encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def test_no_record_still_carries_the_flat_corroboration_fields():
    stragglers = [r["id"] for r in records()
                  if {"corroborating_publisher", "corroborating_url"} & set(r.get("where") or {})]
    assert stragglers == [], "migrate these to where.corroborations: {}".format(stragglers[:5])


def test_every_corroboration_carries_both_halves():
    """An entry missing either half asserts corroboration and supplies no way to check it."""
    broken = []
    for record in records():
        for i, entry in enumerate((record.get("where") or {}).get("corroborations") or []):
            if not (entry.get("publisher") or "").strip() or not (entry.get("url") or "").strip():
                broken.append("{}[{}]".format(record["id"], i))
    assert broken == [], "incomplete corroborations: {}".format(broken)


def test_the_list_can_hold_more_than_one_which_is_the_whole_point():
    """Regression guard on the defect itself: at least one record has three publishers."""
    counts = {r["id"]: len((r.get("where") or {}).get("corroborations") or []) for r in records()}
    assert max(counts.values()) >= 2, "no record carries a second corroboration; the list shape is untested in practice"


def test_validator_rejects_the_old_shape_by_name():
    """additionalProperties already rejects it; the message has to say what to do."""
    problem = {"id": "obs-test", "record_type": "observation", "status": "verified",
               "who": {"vendor": "any", "products": [], "product_class": []},
               "what": {"role": "victim", "summary": "x", "impact": [], "attack_surface": "api_endpoint"},
               "where": {"publisher": "P", "title": "T", "disclosure": "public",
                         "corroborating_publisher": "Q", "corroborating_url": "http://example.invalid"},
               "when": {"published": "2026-01-01", "precision": "day"}}
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    import validate as v
    problems = []
    vocab = json.load(open(os.path.join(ROOT, "corpus", "schema", "vocab.json"), encoding="utf-8"))
    v.check_vocab(problem, vocab, "test", problems)
    messages = " ".join(p.message for p in problems)
    assert "corroborations" in messages and "0.19.0" in messages, messages


@pytest.mark.parametrize("query", ["npm package registry worm"])
def test_consultation_prints_corroboration_for_every_finding(query):
    out = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "consult.py"), query, "--limit", "40"],
                         capture_output=True, text=True, cwd=ROOT).stdout
    findings = [b for b in out.split("=== FINDING ")[1:]]
    assert findings, "no findings returned for {!r}".format(query)
    missing = [b.splitlines()[3] for b in findings if "CORROBORATION:" not in b]
    assert missing == [], "findings with no CORROBORATION line: {}".format(missing[:3])
    multi = [b for b in findings if "CORROBORATION: 2 independent" in b]
    assert multi, "the three-publisher record did not render its corroborations"
