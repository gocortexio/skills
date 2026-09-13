# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""One invariant, held across every script that prints a count.

A header count must describe what the script emitted, not what it was handed. advise.py
broke it one way in 0.11.1 by counting the arguments instead of the findings; query.py
broke it the other way by reporting the match count above a listing capped to twenty, so
a reader saw "42 observation(s)" over 20 of them and nothing said the rest existed.

Both failures are invisible in the output itself -- the numbers look authoritative and the
findings underneath look complete -- so they are only catchable by counting what was
printed and comparing. That is what these tests do, per script, per selection path.

advise.py has its own file. This one covers the rest, and exists so a script gaining a
truncation later cannot quietly acquire the same defect.

Run with PYTHONDONTWRITEBYTECODE=1 (LAW A26).
"""
import json
import pathlib
import re
import shutil
import subprocess
import sys

import pytest

BUNDLE = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = BUNDLE / "scripts"

# Resolves to enough records and library patterns that every default cap bites.
WIDE = "network.firewall"


def run(script, *argv):
    done = subprocess.run(
        [sys.executable, str(SCRIPTS / script), *argv],
        capture_output=True, text=True, timeout=180)
    return done.returncode, done.stdout, done.stderr


def counted(stdout, prefix):
    return len([l for l in stdout.splitlines() if l.startswith(prefix)])


# --------------------------------------------------------------------------- query.py

QUERY_HEADER = re.compile(
    r"^(\d+) of (\d+) observation\(s\) and (\d+) of (\d+) exposure\(s\) shown", re.M)


@pytest.mark.parametrize("argv", [
    pytest.param([WIDE], id="default-caps-bite"),
    pytest.param([WIDE, "--limit", "100", "--exposure-limit", "100"], id="uncapped"),
    pytest.param([WIDE, "--limit", "1", "--exposure-limit", "1"], id="capped-hard"),
])
def test_query_header_counts_what_it_printed(argv):
    code, out, _ = run("query.py", *argv)
    assert code == 0, out
    m = QUERY_HEADER.search(out)
    assert m, out[:400]
    shown_obs, matched_obs, shown_exp, matched_exp = (int(g) for g in m.groups())
    assert shown_obs == counted(out, "obs ")
    assert shown_exp == counted(out, "exp ")
    assert shown_obs <= matched_obs and shown_exp <= matched_exp


@pytest.mark.parametrize("argv,expect_notice", [
    pytest.param([WIDE], True, id="capped"),
    pytest.param([WIDE, "--limit", "100", "--exposure-limit", "100"], False, id="uncapped"),
])
def test_query_announces_a_cap_only_when_one_applies(argv, expect_notice):
    """A cap nobody is told about reads as "this is all there is"."""
    _, out, _ = run("query.py", *argv)
    assert ("OUTPUT CAPPED:" in out) is expect_notice


def test_query_library_block_reports_shown_of_matched():
    _, out, _ = run("query.py", WIDE)
    m = re.search(r"^library patterns .*?: (\d+) of (\d+) shown(.*)$", out, re.M)
    assert m, "no library block in:\n{}".format(out[:400])
    shown, matched, tail = int(m.group(1)), int(m.group(2)), m.group(3)
    assert shown == counted(out, "pat-")
    assert ("--pattern-limit" in tail) is (matched > shown)


def test_query_json_counts_match_the_arrays_they_describe():
    """A JSON consumer cannot see a cap at all, so the counts are its only signal."""
    code, out, _ = run("query.py", WIDE, "--json")
    assert code == 0
    payload = json.loads(out)
    counts = payload["counts"]
    records = payload["records"]
    obs = sum(1 for r in records
              if r["record"].get("record_type", "observation") == "observation")
    assert obs == counts["observations_shown"]
    assert len(records) - obs == counts["exposures_shown"]
    assert len(payload["library_patterns"]) == counts["library_patterns_shown"]
    assert counts["observations_matched"] >= counts["observations_shown"]
    assert counts["library_patterns_matched"] >= counts["library_patterns_shown"]


# ------------------------------------------------------------------------- consult.py

@pytest.mark.parametrize("limit", ["3", "12", "500"])
def test_consult_shown_count_matches_printed_findings(limit):
    code, out, _ = run("consult.py", "Cisco ASA", "--today", "2026-08-08", "--limit", limit)
    assert code == 0, out
    m = re.search(r"^FINDINGS: (\d+) shown of (\d+) matched", out, re.M)
    assert m, out[:400]
    shown, matched = int(m.group(1)), int(m.group(2))
    assert shown == counted(out, "=== FINDING ")
    assert shown <= matched


def test_consult_matched_total_is_not_changed_by_the_limit():
    """matched is the corpus's answer; only shown may move with --limit."""
    totals = set()
    for limit in ("3", "12", "500"):
        _, out, _ = run("consult.py", "Cisco ASA", "--today", "2026-08-08", "--limit", limit)
        totals.add(int(re.search(r"^FINDINGS: \d+ shown of (\d+) matched", out, re.M).group(1)))
    assert len(totals) == 1, "matched moved with --limit: {}".format(totals)


# ------------------------------------------------------------------------ emit_xql.py

def test_emit_xql_json_handoff_count_matches_the_array():
    code, out, err = run("emit_xql.py", "obs-cisco-asa-vpn-webvpn-implant", "--json")
    assert code == 0, err
    m = re.search(r"// (\d+) block\(s\) handed off", err)
    assert m, err
    assert int(m.group(1)) == len(json.loads(out))


def test_emit_xql_text_emitted_count_matches_the_blocks():
    code, out, err = run("emit_xql.py", "obs-cisco-asa-vpn-webvpn-implant")
    assert code == 0, err
    m = re.search(r"// (\d+) block\(s\) emitted", err)
    assert m, err
    assert int(m.group(1)) == len(re.findall(r":: how\[", out))


def how_blocks_in_corpus():
    total = 0
    with open(BUNDLE / "corpus" / "observations" / "observations.jsonl", encoding="utf-8") as h:
        for line in h:
            if line.strip():
                total += len(json.loads(line).get("how") or [])
    return total


EMIT_TALLY = re.compile(
    r"// (\d+) block\(s\) (?:emitted|handed off), (\d+) skipped for having no markers"
    r"(?:, (\d+) filtered out by --shape (\S+))?")


@pytest.mark.parametrize("argv", [
    pytest.param([], id="text-no-filter"),
    pytest.param(["--shape", "single_event"], id="text-shape"),
    pytest.param(["--shape", "correlation"], id="text-other-shape"),
    pytest.param(["--json"], id="json-no-filter"),
    pytest.param(["--json", "--shape", "single_event"], id="json-shape"),
])
def test_emit_xql_accounts_for_every_candidate_block(argv):
    """Emitted plus skipped plus shape-filtered must be every how-block in the corpus.

    Shape-filtered blocks were counted nowhere, so the tally silently failed to add up
    whenever --shape was passed and nothing said which of the two reasons dropped them.
    """
    code, _, err = run("emit_xql.py", *argv)
    assert code == 0, err
    m = EMIT_TALLY.search(err)
    assert m, err
    shown, skipped = int(m.group(1)), int(m.group(2))
    filtered = int(m.group(3)) if m.group(3) else 0
    assert shown + skipped + filtered == how_blocks_in_corpus()


def test_emit_xql_reports_the_shape_filter_only_when_one_was_given():
    _, _, plain = run("emit_xql.py", "obs-cisco-asa-vpn-webvpn-implant")
    assert "filtered out by --shape" not in plain
    _, _, shaped = run("emit_xql.py", "obs-cisco-asa-vpn-webvpn-implant",
                       "--shape", "single_event")
    assert "filtered out by --shape single_event" in shaped


def test_emit_xql_names_the_available_shapes_when_the_filter_took_everything():
    """The empty result is nearly always a typo in the shape name, so say what was there."""
    _, out, err = run("emit_xql.py", "obs-cisco-asa-vpn-webvpn-implant",
                      "--shape", "sngle_event")
    assert "0 block(s) emitted" in err
    assert "shapes present: single_event" in err
    assert ":: how[" not in out


# ------------------------------------------------------------------------ validate.py

def test_validate_problem_count_matches_the_problems_printed(tmp_path):
    """validate.py never truncates, so the count and the listing must agree exactly.

    The fixture omits corpus/reference, which validate.py degrades past rather than
    failing on, so the copy stays small.
    """
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    for part in ("observations", "patterns", "schema"):
        shutil.copytree(BUNDLE / "corpus" / part, corpus / part)

    obs = corpus / "observations" / "observations.jsonl"
    lines = obs.read_text(encoding="utf-8").rstrip("\n").split("\n")
    first = json.loads(lines[0])
    broken = dict(first, id="obs-deliberately-broken",
                  how=[{"pattern_id": "pat-not-a-real-pattern", "markers": []}])
    obs.write_text("\n".join(lines + [json.dumps(first), json.dumps(broken)]) + "\n",
                   encoding="utf-8")

    code, out, _ = run("validate.py", "--corpus", str(corpus))
    assert code == 1, "injected faults did not fail the validator:\n{}".format(out[:400])
    m = re.search(r"^\d+ record\(s\).*?(\d+) problem\(s\)", out, re.M)
    assert m, out[:400]
    printed = [l for l in out.split("\n")[:out.split("\n").index(m.group(0))] if l.strip()]
    assert int(m.group(1)) == len(printed)


def _corpus_copy(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    for part in ("observations", "patterns", "schema"):
        shutil.copytree(BUNDLE / "corpus" / part, corpus / part)
    return corpus


def test_validate_rejects_an_unknown_declared_locus(tmp_path):
    corpus = _corpus_copy(tmp_path)
    obs = corpus / "observations" / "observations.jsonl"
    lines = obs.read_text(encoding="utf-8").rstrip("\n").split("\n")
    for i, line in enumerate(lines):
        record = json.loads(line)
        if record.get("how"):
            record["how"][0]["locus"] = "PLANE_NINE"
            lines[i] = json.dumps(record)
            break
    else:
        pytest.fail("no record with a how block to inject into")
    obs.write_text("\n".join(lines) + "\n", encoding="utf-8")

    code, out, _ = run("validate.py", "--corpus", str(corpus))
    assert code == 1
    assert "not in vocab.locus" in out, out[:400]


def test_locus_map_covers_every_vocabulary_value(tmp_path):
    """A class added without a locus lands in the default and is quietly mislabelled.

    Pure data, no subprocess: the mapping and the two lists that key it must agree,
    and the schema enum must be the same set as the vocabulary. That last pair is the
    source_type drift shape, which is why it is asserted rather than assumed.
    """
    schema_dir = BUNDLE / "corpus" / "schema"
    vocab = json.loads((schema_dir / "vocab.json").read_text(encoding="utf-8"))
    lmap = json.loads((schema_dir / "locus-map.json").read_text(encoding="utf-8"))
    schema = json.loads((schema_dir / "observation.schema.json").read_text(encoding="utf-8"))

    loci = set(vocab["locus"])
    for table, key, defer in (("by_class", "product_class", None),
                              ("by_surface", "attack_surface", "defer_surface"),
                              ("by_evidence", "evidence_type", "defer_evidence")):
        mapped, deferred = set(lmap[table]), set(lmap.get(defer) or [])
        assert set(vocab[key]) <= mapped | deferred, \
            "unmapped in {}: {}".format(table, sorted(set(vocab[key]) - mapped - deferred))
        assert mapped <= set(vocab[key]), \
            "{} names values absent from vocab.{}: {}".format(
                table, key, sorted(mapped - set(vocab[key])))
        assert set(lmap[table].values()) <= loci
        assert not (mapped & deferred), "a value cannot be both mapped and deferred"

    assert lmap["default"] in loci
    assert set(lmap["locus_order"]) == loci
    assert set(lmap["nonproduct_class"]) <= set(vocab["product_class"])
    assert set(lmap["surface_supply"]) <= set(vocab["attack_surface"])

    enum = schema["properties"]["how"]["items"]["properties"]["locus"]["enum"]
    assert set(enum) == loci, "schema how[].locus enum has drifted from vocab.locus"
