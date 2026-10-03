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
import collections
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


# ------------------------------------------------------------------- argument floors

@pytest.mark.parametrize("script,argv,flag,floor", [
    pytest.param("consult.py", ["Cisco ASA", "--limit", "0"], "--limit", 1, id="consult-limit-0"),
    pytest.param("consult.py", ["Cisco ASA", "--limit=-1"], "--limit", 1, id="consult-limit-neg"),
    pytest.param("consult.py", ["Cisco ASA", "--per-locus", "0"], "--per-locus", 1,
                 id="consult-per-locus-0"),
    pytest.param("consult.py", ["Cisco ASA", "--per-locus=-2"], "--per-locus", 1,
                 id="consult-per-locus-neg"),
    pytest.param("consult.py", ["Cisco ASA", "--exposure-limit=-1"], "--exposure-limit", 0,
                 id="consult-exposure-limit-neg"),
    pytest.param("consult.py", ["Cisco ASA", "--pattern-limit=-1"], "--pattern-limit", 0,
                 id="consult-pattern-limit-neg"),
    pytest.param("query.py", [WIDE, "--limit", "0"], "--limit", 1, id="query-limit-0"),
    pytest.param("query.py", [WIDE, "--exposure-limit=-1"], "--exposure-limit", 0,
                 id="query-exposure-limit-neg"),
    pytest.param("query.py", [WIDE, "--pattern-limit=-1"], "--pattern-limit", 0,
                 id="query-pattern-limit-neg"),
    pytest.param("advise.py", ["--no-verify", "--per-shape", "0", "shell"], "--per-shape", 1,
                 id="advise-per-shape-0"),
    pytest.param("advise.py", ["--no-verify", "--per-shape=-1", "shell"], "--per-shape", 1,
                 id="advise-per-shape-neg"),
])
def test_limit_floors(script, argv, flag, floor):
    """A count below its floor is refused, never read as a slice from the end.

    Every cap here is applied as a Python slice, and `type=int` let anything through:
    `--limit -1` showed all but the last finding under a quota that reserved as though the
    limit were positive, and `consult.py --limit 0` printed "the resolver matched nothing"
    over 97 matches. Exit 2 and nothing on stdout, so no part of a refused run can be read
    as an answer.
    """
    code, out, err = run(script, *argv)
    assert code == 2, "{} {} exited {}".format(script, " ".join(argv), code)
    assert out == "", "a refused run printed an answer:\n{}".format(out[:400])
    assert "ERROR: {} must be {} or more".format(flag, floor) in err, err


@pytest.mark.parametrize("script,argv", [
    pytest.param("consult.py", ["Cisco ASA", "--today", "2026-08-08", "--limit", "1"], id="consult-limit-1"),
    pytest.param("consult.py", ["Cisco ASA", "--today", "2026-08-08", "--per-locus", "1"],
                 id="consult-per-locus-1"),
    pytest.param("query.py", [WIDE, "--limit", "1", "--exposure-limit", "0", "--pattern-limit", "0"],
                 id="query-zero-secondary"),
    pytest.param("consult.py", ["Cisco ASA", "--today", "2026-08-08", "--limit", "1",
                                "--exposure-limit", "0", "--pattern-limit", "0"],
                 id="consult-zero-secondary"),
    pytest.param("advise.py", ["--no-verify", "--per-shape", "1", "shell"], id="advise-per-shape-1"),
])
def test_the_floor_itself_is_accepted(script, argv):
    """The boundary is inclusive; a floor that refused its own value would be a new defect."""
    code, out, err = run(script, *argv)
    assert code == 0, err
    assert "ERROR:" not in err


def test_consult_secondary_limits_of_zero_still_count_what_they_did_not_list():
    """0 lists none of an EXPOSURE or LIBRARY block and leaves the header's counts whole."""
    code, out, _ = run("consult.py", "Cisco ASA", "--today", "2026-08-08", "--limit", "1",
                       "--exposure-limit", "0", "--pattern-limit", "0")
    assert code == 0
    exposures = re.search(r"^EXPOSURES: (\d+) shown of (\d+)", out, re.M)
    library = re.search(r"^LIBRARY_PATTERNS: (\d+) shown of (\d+)", out, re.M)
    assert exposures and int(exposures.group(1)) == 0 < int(exposures.group(2)), out[:400]
    assert library and int(library.group(1)) == 0 < int(library.group(2)), out[:400]
    assert counted(out, "=== EXPOSURE ") == counted(out, "=== LIBRARY ") == 0


def test_query_exposure_limit_zero_still_counts_what_it_did_not_list():
    code, out, _ = run("query.py", WIDE, "--exposure-limit", "0")
    assert code == 0
    m = QUERY_HEADER.search(out)
    assert m and int(m.group(3)) == 0 and int(m.group(4)) > 0, out[:400]
    assert counted(out, "exp ") == 0
    assert "--exposure-limit for the" in out, "a cap to zero must still be announced"


@pytest.mark.parametrize("question", ["Oracle", "Adobe", "Linux servers", "Splunk"])
def test_query_library_matched_is_not_changed_by_the_limit(question):
    """The library's scope came from the capped listing, so 'Oracle' matched 3 library
    patterns at the default caps and 29 uncapped, and 'Splunk' lost its block at
    --exposure-limit 0. The count must not move with any display cap."""
    seen = set()
    for cap in (0, 1, 20, 1000):
        code, out, _ = run("query.py", question, "--json", "--limit", str(max(cap, 1)),
                           "--exposure-limit", str(cap))
        assert code == 0
        data = json.loads(out)
        seen.add((data["counts"]["library_patterns_matched"], tuple(data["library_classes"]),
                  data["library_classes_basis"]))
    assert len(seen) == 1, seen
    matched, classes, basis = seen.pop()
    assert matched > 0 and classes and basis in ("resolved", "inferred", "inferred-weak")
    if question == "Splunk":
        _, plain, _ = run("query.py", question, "--exposure-limit", "0")
        assert counted(plain, "pat-") == matched
        assert "classes inferred from" in plain


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


EMIT_FILTER = re.compile(r"; filter: (\d+) complete, (\d+) partial, (\d+) none")


@pytest.mark.parametrize("argv", [
    pytest.param([], id="text"),
    pytest.param(["--json"], id="json"),
    pytest.param(["--shape", "threshold"], id="text-shape"),
])
def test_emit_xql_filter_status_tally_adds_up(argv):
    """The three statuses sum to the blocks shown, and match the blocks' own statuses."""
    code, out, err = run("emit_xql.py", "--all", *argv)
    assert code == 0, err
    shown = int(EMIT_TALLY.search(err).group(1))
    m = EMIT_FILTER.search(err)
    assert m, err
    counts = dict(zip(("complete", "partial", "none"), (int(g) for g in m.groups())))
    assert sum(counts.values()) == shown
    if "--json" in argv:
        printed = collections.Counter(b["filter_status"] for b in json.loads(out))
    else:
        printed = collections.Counter(re.findall(r":: how\[\d+\] .* filter=(\S+)  key=", out))
    assert {k: printed.get(k, 0) for k in counts} == counts


def test_emit_xql_accounts_for_records_without_how_blocks():
    """An exposure matched by id printed '0 block(s) emitted, 0 skipped', accounting for nothing."""
    for argv in (["exp-kev-linux-kernel"], ["exp-kev-linux-kernel", "--json"]):
        code, _, err = run("emit_xql.py", *argv)
        assert code == 0, err
        assert "1 matched record(s) carry no how-blocks" in err, err
    _, _, err = run("emit_xql.py", "obs-cisco-asa-vpn-webvpn-implant")
    assert "carry no how-blocks" not in err


def test_emit_xql_refuses_to_run_without_the_xdm_snapshot(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    for part in ("observations", "patterns", "schema"):
        shutil.copytree(BUNDLE / "corpus" / part, corpus / part)
    (corpus / "schema" / "xdm-fields.json").unlink()
    code, out, err = run("emit_xql.py", "--all", "--corpus", str(corpus))
    assert code == 2 and not out.strip()
    assert "xdm-fields.json is absent" in err


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
    # Every shape the record holds, sorted: how[0], a reload then a configuration write, is a
    # sequence since the third 0.43.0 review keyed its two events.
    assert "shapes present: sequence, single_event)" in err
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


def _break_the_map(corpus, change):
    path = corpus / "schema" / "locus-map.json"
    lmap = json.loads(path.read_text(encoding="utf-8"))
    change(lmap)
    path.write_text(json.dumps(lmap, indent=1), encoding="utf-8")


@pytest.mark.parametrize("change,named", [
    pytest.param(lambda m: m["surface_supply"].append("watering_hole"), "watering_hole",
                 id="supply-surface-with-no-mapping"),
    pytest.param(lambda m: m["by_class"].pop("process.service_desk"), "process.service_desk",
                 id="nonproduct-class-with-no-mapping"),
    pytest.param(lambda m: m["defer_surface"].append("email_flow"), "email_flow",
                 id="value-both-mapped-and-deferred"),
    pytest.param(lambda m: m["tier_order"].reverse(), "tier_order",
                 id="tier-order-reversed"),
    pytest.param(lambda m: m["span_order"].reverse(), "span_order",
                 id="span-order-reversed"),
    pytest.param(lambda m: m["surface_span_only"].append("watering_hole"), "watering_hole",
                 id="span-only-surface-deferred-and-unmapped"),
    pytest.param(lambda m: m["surface_span_only"].append("supply_chain_update"), "supply_chain_update",
                 id="span-only-surface-also-a-supply-surface"),
    pytest.param(lambda m: m["untrusted_surface_tags"].update({"psirt": "rumour"}),
                 "untrusted_surface_tags", id="generator-tag-names-an-unknown-source-type"),
])
def test_validate_reports_a_broken_locus_map_instead_of_crashing(tmp_path, change, named):
    """The first of these was a KeyError traceback, and the last passed silently.

    locus_for() looks a supply surface up in by_surface and a non-product class up in
    by_class, and the map was checked after every block had already been derived through
    it. tier_order was read by nothing at all. Each is now a Problem, and the tally that
    would have derived through a broken map says it was skipped rather than printing a
    distribution computed over one.
    """
    corpus = _corpus_copy(tmp_path)
    _break_the_map(corpus, change)
    code, out, err = run("validate.py", "--corpus", str(corpus))
    assert "Traceback" not in err, err[-800:]
    assert code == 1, out[-800:]
    assert any(named in l and l.startswith("corpus/schema/locus-map.json")
               for l in out.splitlines()), out[:800]
    assert "locus derivation: skipped - corpus/schema/locus-map.json has" in out


def _rewrite_records(corpus, change):
    """Apply change(record) to every record until it returns True once; fail if it never does."""
    obs = corpus / "observations" / "observations.jsonl"
    lines = obs.read_text(encoding="utf-8").rstrip("\n").split("\n")
    for i, line in enumerate(lines):
        record = json.loads(line)
        if change(record):
            lines[i] = json.dumps(record)
            break
    else:
        pytest.fail("no record the change applies to")
    obs.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _derive(record, how):
    sys.path.insert(0, str(SCRIPTS))
    import consult
    lmap = consult.load_locus_map(str(BUNDLE / "corpus"))
    return consult.locus_for(record, how, None, lmap)[0]


def test_validate_rejects_a_redundant_declared_locus(tmp_path):
    """A hand-set value that agrees with the derivation silently stops agreeing when the
    derivation changes, which is what the schema said and nothing enforced. Three of the
    corpus's first twelve overrides restated what the ladder already gave."""
    corpus = _corpus_copy(tmp_path)

    def restate(record):
        if record.get("record_type") != "observation" or record["how"][0].get("locus"):
            return False
        record["how"][0]["locus"] = _derive(record, record["how"][0])
        record["notes"] = "how[0].locus is set on purpose, to be refused."
        return True

    _rewrite_records(corpus, restate)
    code, out, _ = run("validate.py", "--corpus", str(corpus))
    assert code == 1, out[-800:]
    assert "which the derivation already gives; remove it" in out, out[:800]


def test_validate_rejects_an_override_with_no_reason(tmp_path):
    corpus = _corpus_copy(tmp_path)

    def override(record):
        if record.get("record_type") != "observation" or record.get("notes"):
            return False
        derived = _derive(record, record["how"][0])
        record["how"][0]["locus"] = "SUPPLY" if derived != "SUPPLY" else "DATA"
        return True

    _rewrite_records(corpus, override)
    code, out, _ = run("validate.py", "--corpus", str(corpus))
    assert code == 1, out[-800:]
    assert "with no reason in notes" in out, out[:800]


def test_every_declared_locus_carries_its_reason():
    """Over the shipped corpus: each override changes the answer and names itself in notes.
    The reasons existed only in commit messages, which do not ship."""
    declared = 0
    for line in (BUNDLE / "corpus" / "observations" / "observations.jsonl").read_text(
            encoding="utf-8").splitlines():
        record = json.loads(line)
        for i, how in enumerate(record.get("how") or []):
            if not how.get("locus"):
                continue
            declared += 1
            underived = {k: v for k, v in how.items() if k != "locus"}
            assert _derive(record, underived) != how["locus"], (record["id"], i)
            assert "how[{}].locus".format(i) in (record.get("notes") or ""), (record["id"], i)
    assert declared, "no declared override left to hold to its reason"


@pytest.mark.parametrize("change,expected", [
    pytest.param(lambda r: r["tags"].remove("known-exploited-catalogue"),
                 "no tag in locus-map.json untrusted_surface_tags", id="generator-forgot-its-tag"),
    pytest.param(lambda r: r["where"].update({"source_type": "government_advisory"}),
                 "and that generator writes 'database'", id="tag-and-source-disagree"),
])
def test_validate_refuses_an_exposure_whose_generator_tag_drifted(tmp_path, change, expected):
    """The tag decides whether an exposure's attack_surface is read, so a generator that
    forgot it would have its class-derived surface read as authored, silently."""
    corpus = _corpus_copy(tmp_path)

    def drift(record):
        if "known-exploited-catalogue" not in (record.get("tags") or []):
            return False
        change(record)
        return True

    _rewrite_records(corpus, drift)
    code, out, _ = run("validate.py", "--corpus", str(corpus))
    assert code == 1, out[-800:]
    assert expected in out, out[:800]


def test_tier_order_matches_the_code():
    sys.path.insert(0, str(SCRIPTS))
    import consult
    lmap = json.loads((BUNDLE / "corpus" / "schema" / "locus-map.json").read_text(encoding="utf-8"))
    assert lmap["tier_order"] == list(consult.LOCUS_TIERS)


def test_validate_runs_without_the_consultation_script(tmp_path):
    """The import is optional so that the validator runs alone, and it used not to.

    validate.py catches the ImportError and then dereferenced the missing module in the
    tally regardless, so the one situation the guard exists for was an AttributeError.
    """
    (tmp_path / "scripts").mkdir()
    shutil.copy2(SCRIPTS / "validate.py", tmp_path / "scripts" / "validate.py")
    _corpus_copy(tmp_path)
    done = subprocess.run([sys.executable, str(tmp_path / "scripts" / "validate.py")],
                          capture_output=True, text=True, timeout=180, cwd=str(tmp_path))
    assert "Traceback" not in done.stderr, done.stderr[-800:]
    assert done.returncode == 0, done.stdout[-800:]
    assert "locus derivation: skipped - scripts/consult.py is not importable" in done.stdout


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


def test_validate_refuses_an_alias_gate_that_points_at_nothing(tmp_path):
    """A gate on a key no table holds protects nothing, and resolve() fails closed on a gate
    mode it does not know, so a misspelt mode silently switches a class alias off."""
    corpus = _corpus_copy(tmp_path)
    path = corpus / "schema" / "aliases.json"
    aliases = json.loads(path.read_text(encoding="utf-8"))
    aliases["ambiguous_aliases"]["not-an-alias-anywhere"] = "a reason"
    aliases["ambiguous_vendor_aliases"]["ms"] = ""
    aliases["ambiguous_class_aliases"]["ids"]["mode"] = "uppercase"
    aliases["vendor_aliases"]["somebody"] = "any"
    aliases["platform_of"]["linux"] = "penguin"
    path.write_text(json.dumps(aliases, indent=2), encoding="utf-8")

    code, out, _ = run("validate.py", "--corpus", str(corpus))
    assert code == 1, out[:400]
    for expected in ("ambiguous_aliases key 'not-an-alias-anywhere' is not a key of "
                     "product_aliases",
                     "ambiguous_vendor_aliases key 'ms' gives no reason",
                     "ambiguous_class_aliases 'ids' has mode 'uppercase'",
                     "vendor alias 'somebody' names 'any', which is not a vendor",
                     "platform_of 'linux' is 'penguin'"):
        assert expected in out, expected
