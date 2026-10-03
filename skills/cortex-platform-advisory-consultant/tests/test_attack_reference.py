# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The shipped ATT&CK and D3FEND references say which ids are withdrawn, and act on it.

Until 0.43.0 the ATT&CK reference listed T1562.001, T1070.001 and 209 other revoked ids as
ordinary entries, because its generator kept six fields and dropped the `revoked` and
`deprecated` flags its own harvest recorded. So validate.py counted a reintroduced revoked
id as resolving, advise.py could not tell "revoked, use T1685" from "no such id", and the
D3FEND table -- keyed on pre-19.2 ids -- joined T1685 to nothing while T1562.001 carried 19
countermeasures. The generators now emit the lifecycle and re-key through it, and these
tests hold the shipped files to that.

Run with PYTHONDONTWRITEBYTECODE=1 (LAW A26).
"""
import json
import pathlib
import shutil
import subprocess
import sys

import pytest

BUNDLE = pathlib.Path(__file__).resolve().parents[1]
REFERENCE = BUNDLE / "corpus" / "reference"
VALIDATE = BUNDLE / "scripts" / "validate.py"

sys.dont_write_bytecode = True
sys.path.insert(0, str(BUNDLE / "scripts"))
import query as Q  # noqa: E402

ATTACK = json.loads((REFERENCE / "attack-techniques.json").read_text(encoding="utf-8"))
TECHNIQUES = ATTACK["techniques"]
D3FEND = json.loads((REFERENCE / "d3fend-countermeasures.json").read_text(encoding="utf-8"))


def cited_ids():
    records, patterns = Q.load_corpus(str(BUNDLE / "corpus"))
    ids = {}
    for pid, pattern in patterns.items():
        for tid in pattern.get("technique") or []:
            ids.setdefault(tid.upper(), set()).add(pid)
    for record in records:
        for how in record.get("how") or []:
            for tid in how.get("technique") or []:
                ids.setdefault(tid.upper(), set()).add(record["id"])
    return ids


def test_every_entry_carries_its_lifecycle():
    missing = [tid for tid, v in TECHNIQUES.items()
               if not isinstance(v.get("revoked"), bool) or not isinstance(v.get("deprecated"), bool)]
    assert not missing, missing[:10]
    unexplained = [tid for tid, v in TECHNIQUES.items() if v["revoked"] and "replaced_by" not in v]
    assert not unexplained, "revoked with no replaced_by key: {}".format(unexplained[:10])


@pytest.mark.parametrize("old,new", [
    ("T1562.001", "T1685"),
    ("T1070.001", "T1685.005"),
    ("T1656", "T1684.001"),
    ("T1574.002", "T1574.001"),
    # Two hops: T1073 -> T1574.002 -> T1574.001. The first hop is itself revoked.
    ("T1073", "T1574.001"),
])
def test_revoked_ids_carry_their_replacement(old, new):
    assert TECHNIQUES[old]["revoked"] is True
    assert TECHNIQUES[old]["replaced_by"] == new


def test_every_replaced_by_is_live():
    for tid, entry in TECHNIQUES.items():
        new = entry.get("replaced_by")
        if new:
            assert new in TECHNIQUES, (tid, new)
            assert not TECHNIQUES[new]["revoked"] and not TECHNIQUES[new]["deprecated"], (tid, new)


def test_a_chain_ending_deprecated_names_its_dead_end():
    """T1455 -> T1477, and T1477 is deprecated: nothing live to follow, and it says why."""
    entry = TECHNIQUES["T1455"]
    assert entry["revoked"] and entry["replaced_by"] is None
    assert entry["successor_deprecated"] == "T1477"
    assert TECHNIQUES["T1477"]["deprecated"] is True


def test_shipped_corpus_cites_no_revoked_or_deprecated_id():
    withdrawn = {tid: sorted(who)[:3] for tid, who in cited_ids().items()
                 if tid in TECHNIQUES and (TECHNIQUES[tid]["revoked"] or TECHNIQUES[tid]["deprecated"])}
    assert not withdrawn, withdrawn


def test_validate_counts_every_shipped_citation_as_live():
    done = subprocess.run([sys.executable, str(VALIDATE)], capture_output=True, text=True,
                          timeout=300, cwd=str(BUNDLE))
    total = len(cited_ids())
    assert "resolving against the shipped reference: {0}/{0}; to a live id {0}, to a REVOKED " \
           "or DEPRECATED id 0".format(total) in done.stdout, done.stdout[-600:]


def test_validate_reports_a_reintroduced_revoked_id(tmp_path):
    corpus = tmp_path / "corpus"
    shutil.copytree(str(BUNDLE / "corpus"), str(corpus))
    path = corpus / "patterns" / "patterns.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["technique"] = list(first.get("technique") or []) + ["T1562.001"]
    lines[0] = json.dumps(first)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    done = subprocess.run([sys.executable, str(VALIDATE), "--corpus", str(corpus)],
                          capture_output=True, text=True, timeout=300, cwd=str(BUNDLE))
    assert "REVOKED" in done.stdout
    assert "T1562.001 -> T1685" in done.stdout, done.stdout[-600:]
    assert "to a REVOKED or DEPRECATED id 1" in done.stdout


def test_d3fend_via_entries_are_the_union_of_their_predecessors():
    """by_attack_via is MITRE's revoked-by relation, not a D3FEND mapping: every listed
    predecessor is revoked into that key, and the key's list is exactly theirs."""
    via = D3FEND["by_attack_via"]
    assert via, "the re-keying produced nothing; was the harvest run against the old reference?"
    for new, olds in via.items():
        union = set()
        for old in olds:
            assert TECHNIQUES[old]["revoked"] and TECHNIQUES[old]["replaced_by"] == new, (new, old)
            union |= set(D3FEND["by_attack"][old])
        assert set(D3FEND["by_attack"][new]) == union, new
    assert "T1685" in via and "T1562.001" in via["T1685"]


def test_d3fend_file_still_carries_the_mit_notice():
    """The regenerated file must keep the licence text MIT requires to travel with it. A
    2026-09 audit fixed this in the file and not the generator, and it came back."""
    text = D3FEND["licence_text"]
    assert text.startswith("MIT License\n\nCopyright (c) 2022 The MITRE Corporation\n\n")
    assert "The above copyright notice and this permission notice shall be included in all " \
           "copies or substantial portions of the Software." in text
    assert D3FEND["attribution"].startswith("MITRE D3FEND(TM) 1.6.0, (c) 2022 The MITRE "
                                            "Corporation, used under the MIT Licence.")


def test_d3fend_links_say_whether_d3fend_states_or_infers_them():
    """The harvest read the mapping file's query label only, so a class above or below the one
    D3FEND maps was listed as though mapped, and sorted by name: Access Mediation headed 21 of
    the 28 answers for T1685. Every link now carries its grade, and each list is ordered
    tactic, then grade, then a control acting on the artefact before a host-wide one, then
    name."""
    inferred = D3FEND["by_attack_inferred"]
    grades = ("direct", "narrower", "broader")
    rank = {name: i for i, name in enumerate(D3FEND["tactic_order"])}
    table = D3FEND["countermeasures"]
    counted = {"direct": 0, "narrower": 0, "broader": 0}
    for tid, ids in D3FEND["by_attack"].items():
        marks = inferred.get(tid) or {}
        assert set(marks) <= set(ids), tid
        assert set(marks.values()) <= {"narrower", "broader"}, tid
        key = [(rank.get(table[c]["tactic"], len(rank)), grades.index(marks.get(c, "direct")),
                c in D3FEND["host_wide"], table[c]["name"]) for c in ids]
        assert key == sorted(key), tid
        for c in ids:
            counted[marks.get(c, "direct")] += 1
    assert counted == D3FEND["counts"]["links_by_grade"]
    assert counted["direct"] and counted["narrower"] and counted["broader"]
    # The worked example: System Call Filtering is what D3FEND maps for LSASS memory; Access
    # Mediation is only the class above it.
    assert "D3-SCF" not in inferred["T1003.001"] and inferred["T1003.001"]["D3-AMED"] == "broader"
    assert "predates" not in D3FEND["note"]


def test_d3fend_host_wide_controls_are_read_from_their_definitions():
    """Host Reboot and Host Shutdown "terminate Process" as Process Termination does, so the
    mappings cannot separate them; the list says which act on the whole host, in the words of
    D3FEND's own definition, and the harvest refuses a definition that stops saying so."""
    host_wide = D3FEND["host_wide"]
    assert set(host_wide) == {"D3-HR", "D3-HS"}
    for cid, words in host_wide.items():
        assert words in D3FEND["countermeasures"][cid]["definition"], cid
    assert "host_wide" in D3FEND["note"]
    lsass = D3FEND["by_attack"]["T1003.001"]
    assert lsass.index("D3-PT") < lsass.index("D3-HR") and lsass.index("D3-PS") < lsass.index("D3-HS")


def test_d3fend_via_entries_take_their_predecessors_best_grade():
    for new, olds in D3FEND["by_attack_via"].items():
        for cid in D3FEND["by_attack"][new]:
            best = min(((D3FEND["by_attack_inferred"].get(old) or {}).get(cid, "direct")
                        for old in olds if cid in D3FEND["by_attack"][old]),
                       key=("direct", "narrower", "broader").index)
            assert (D3FEND["by_attack_inferred"].get(new) or {}).get(cid, "direct") == best
