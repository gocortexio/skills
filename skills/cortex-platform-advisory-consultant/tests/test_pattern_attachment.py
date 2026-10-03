# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A how-block may cite a pattern only when the two describe the same detection scenario.

The schema defines `how.pattern_id` as "the same detection scenario across different
technologies", and nothing enforced it. Three places consume the link: consult.py prints the
pattern's name as the finding's ACTION, unions the pattern's techniques into COUNTERMEASURES,
and advise.py counts every citing record as OBSERVED. So a mis-attachment is not a labelling
slip. A CloudTrail enumeration of Lambda functions printed "Build a threshold rule:
Application configuration files read from the internet" with web-exploitation
countermeasures, a lookalike tenant's fetch hook printed "Malware watching the browser for a
banking session", and advise.py said three records had observed .env harvesting when one had.

Evidence is the test that can be made mechanically: a block and its pattern that share no
evidence type cannot be the same detection. Where they genuinely are the same scenario read
from another telemetry source, the exception is written down with its reason.

Run with PYTHONDONTWRITEBYTECODE=1 (LAW A26).
"""
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RECORDS, PATTERNS = [], {}
with open(os.path.join(ROOT, "corpus", "observations", "observations.jsonl"), encoding="utf-8") as h:
    for line in h:
        if line.strip():
            RECORDS.append(json.loads(line))
with open(os.path.join(ROOT, "corpus", "patterns", "patterns.jsonl"), encoding="utf-8") as h:
    for line in h:
        if line.strip():
            p = json.loads(line)
            PATTERNS[p["id"]] = p

# The same scenario, read from telemetry the pattern does not list. Keyed by (record, block).
SAME_SCENARIO_OTHER_EVIDENCE = {
    ("obs-mysql-native-encryption-and-schema-destruction-for-extortion", 0):
        "the platform's own encryption used as ransomware, one layer up in a database; the evidence "
        "is the query log, and vocab.json has no database-log evidence type to share",
    ("obs-mysql-native-encryption-and-schema-destruction-for-extortion", 1):
        "a ransom note over data already destroyed; the evidence is the database's query log, for "
        "which vocab.json has no evidence type",
    ("obs-siemens-s7-plc-commodity-library-tooling", 4):
        "defaults that survive commissioning, the pattern's own industrial example, read from the "
        "controllers' protection-level configuration because a PLC keeps no authentication log",
    ("obs-amazon-role-trust-policy-open-to-any-account", 1):
        "breadth in a short window from one source, read from the cloud audit trail as assumption "
        "attempts against role names that do not exist rather than from flow records",
    ("obs-generic-rust-crate-hijack-executes-at-compile-time", 4):
        "a retrospective sweep when a new indicator arrives, run over build records and package "
        "caches because the indicator is a withdrawn package version rather than a network address",
}

BLOCKS = [(r["id"], i, how) for r in RECORDS for i, how in enumerate(r.get("how") or [])
          if how.get("pattern_id")]


def test_a_how_block_shares_evidence_with_the_pattern_it_cites():
    """Failed on 18 of 771 blocks before 0.43.0: five mis-attachments, now unlinked; one
    re-pointed to the pattern it describes; seven blocks under four patterns whose evidence
    list was too narrow, now widened; and five kept above with their reasons, two of them
    the database blocks."""
    bad = []
    for rid, index, how in BLOCKS:
        pattern = PATTERNS[how["pattern_id"]]
        shared = set(how.get("evidence_type") or []) & set(pattern.get("evidence_type") or [])
        if (rid, index) in SAME_SCENARIO_OTHER_EVIDENCE:
            if shared:
                bad.append("{}#{} now shares evidence; drop its exception".format(rid, index))
        elif not shared:
            bad.append("{}#{} cites {} and shares no evidence type with it ({} against {})".format(
                rid, index, pattern["id"], how.get("evidence_type"), pattern.get("evidence_type")))
    missing = [k for k in SAME_SCENARIO_OTHER_EVIDENCE
               if not any((rid, i) == k for rid, i, _ in BLOCKS)]
    assert not missing, "an exception names a block that no longer cites a pattern: {}".format(missing)
    assert not bad, "\n".join(bad)


def _uncited():
    cited = {how["pattern_id"] for _, _, how in BLOCKS}
    return sorted(pid for pid in PATTERNS if pid not in cited)


def test_an_uncited_pattern_can_still_be_reached():
    """query.py's library block skips a pattern with no markers, so an uncited pattern needs
    both markers and classes or no lookup can return it. Unlinking a mis-attached block can
    leave a pattern uncited; pat-lnk-pointing-to-user-writable-path was that case in 0.43.0."""
    bad = [pid for pid in _uncited()
           if not PATTERNS[pid].get("markers") or not PATTERNS[pid].get("applies_to_classes")]
    assert not bad, "uncited and unreachable: {}".format(bad)


def test_the_corpus_readme_states_the_uncited_count():
    """The count in corpus/README.md was prose nothing checked, and a single unlinked block
    moves it."""
    with open(os.path.join(ROOT, "corpus", "README.md"), encoding="utf-8") as h:
        text = h.read()
    stated = re.search(r"(\d+) patterns\s+are cited by no record", text)
    assert stated, "corpus/README.md no longer states the uncited count"
    assert int(stated.group(1)) == len(_uncited())
