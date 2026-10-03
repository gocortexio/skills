# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Library patterns reach a consultation, in blocks of their own.

A library pattern is one no record cites, so no incident here is behind it; it is matched on
product class alone, and says in derived_from where it came from. consult.py built findings only from records'
how-blocks, so none of the 34 ever reached a consultation, and the DERIVATION branch that was
to label one could never fire. SKILL.md's rule 6 described that branch as live. Over 24 probe
questions, 19 had library patterns query.py showed and consult.py never did, among them three
CONTROL patterns for SCADA and, for Kubernetes, a MANAGEMENT pattern while LOCUS_ABSENT named
MANAGEMENT.

The LIBRARY blocks follow the findings and the EXPOSURE blocks, under a header group of their
own, and never enter FINDINGS: a pattern has no date, no citation and no identifier, so it
cannot be scored against a finding. It never takes a slot and never clears LOCUS_ABSENT, whose
bullets count it.

Run with PYTHONDONTWRITEBYTECODE=1 (LAW A26).
"""
import json
import os
import re
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import consult as C  # noqa: E402
import query as Q  # noqa: E402

TODAY = "2026-09-25"
RECORDS, PATTERNS = Q.load_corpus(os.path.join(ROOT, "corpus"))
ALIASES = Q.normalise_alias_keys(
    json.load(open(os.path.join(ROOT, "corpus", "schema", "aliases.json"), encoding="utf-8")))
CITED = {how.get("pattern_id") for record in RECORDS for how in record.get("how") or []}
FINDING_KEYS = {"LOCUS", "LOCUS_SPAN", "LOCUS_BASIS", "RECORD_ID", "PATTERN_ID",
                "PRIORITY_BASIS", "FINDING_KEY", "RANK", "SLOT", "ATTACK", "MARKERS"}


def consult(question, *extra):
    done = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "consult.py"), question,
                           "--today", TODAY, *extra], capture_output=True, text=True, cwd=ROOT,
                          timeout=180)
    return done.returncode, done.stdout, done.stderr


def library_blocks(out):
    found, current = [], None
    for line in out.splitlines():
        if line.startswith("=== LIBRARY "):
            current = {}
        elif line.startswith("=== END LIBRARY "):
            found.append(current)
            current = None
        elif current is not None:
            key = re.match(r"^([A-Z][A-Z0-9_]*):(?: (.*))?$", line)
            if key:
                current[key.group(1)] = key.group(2) or ""
    return found


def header(out, key):
    found = [l for l in out.splitlines() if l.startswith(key + ":")]
    assert found, "{} not printed".format(key)
    return found[0]


def expected(classes):
    """The uncited patterns with markers whose applies_to_classes meet `classes`."""
    return {pid for pid, p in PATTERNS.items()
            if pid not in CITED and p.get("markers")
            and set(p.get("applies_to_classes") or []) & set(classes)}


def test_uncited_patterns_reach_the_consultation():
    code, out, _ = consult("Kubernetes", "--limit", "3")
    assert code == 0
    assert "LIBRARY_PATTERN_ID: pat-cloud-network-exposure-opened" in out


def test_the_matched_count_is_every_uncited_pattern_of_the_class():
    _, out, _ = consult("Microsoft Windows", "--limit", "1", "--pattern-limit", "100")
    classes = header(out, "RESOLVED_TO").split("classes=")[1].split(" | ")[0].split(", ")
    want = expected(classes)
    assert len(want) >= 20, "fixture no longer has many library patterns"
    shown, total = map(int, re.search(r"^LIBRARY_PATTERNS: (\d+) shown of (\d+)", out,
                                      re.M).groups())
    assert total == len(want)
    assert shown == total == len(library_blocks(out))
    assert {b["LIBRARY_PATTERN_ID"] for b in library_blocks(out)} == want
    loci = {k: int(v) for k, v in re.findall(r"([A-Z]+)=(\d+)",
                                              header(out, "LIBRARY_LOCUS").split("  (")[0])}
    assert sum(loci.values()) == total
    assert set(loci) == set(C.load_locus_map(C.CORPUS)["locus_order"])


@pytest.mark.parametrize("limit", ["0", "1", "6"])
def test_the_pattern_limit_caps_the_blocks_and_not_the_count(limit):
    _, out, _ = consult("Linux kernel", "--limit", "1", "--pattern-limit", limit)
    shown, total = map(int, re.search(r"^LIBRARY_PATTERNS: (\d+) shown of (\d+)", out,
                                      re.M).groups())
    assert shown == len(library_blocks(out)) == min(int(limit), total)
    assert total > 6
    assert ("raise --pattern-limit" in header(out, "LIBRARY_PATTERNS")) == (total > shown)


def test_every_library_block_carries_the_same_key_set():
    _, out, _ = consult("Microsoft Windows", "--limit", "1", "--pattern-limit", "100")
    blocks = library_blocks(out)
    keys = [tuple(b) for b in blocks]
    assert len(blocks) > 5 and len(set(keys)) == 1, "a library block varies its key set"
    assert all(k.startswith("LIBRARY_") for k in keys[0])
    assert not set(keys[0]) & FINDING_KEYS
    for key in ("LIBRARY_PATTERN_ID", "LIBRARY_LOCUS", "LIBRARY_LOCUS_BASIS", "LIBRARY_CLASSES",
                "LIBRARY_FIDELITY", "LIBRARY_RULE_SHAPE", "LIBRARY_ATTACK", "LIBRARY_MARKERS",
                "LIBRARY_TELEMETRY_REQUIRED", "LIBRARY_DATA_GAP", "LIBRARY_CAVEAT_VERBATIM",
                "LIBRARY_COUNTERMEASURES", "LIBRARY_CORROBORATED", "LIBRARY_OBSERVED"):
        assert key in keys[0], key


def test_the_library_never_moves_the_findings():
    _, none, _ = consult("Microsoft Windows", "--limit", "12", "--pattern-limit", "0")
    _, many, _ = consult("Microsoft Windows", "--limit", "12", "--pattern-limit", "50")
    for key in ("FINDINGS", "MATCH_TIERS", "LOCUS_MATCHED", "LOCUS_ELIGIBLE", "LOCUS_SHOWN",
                "LOCUS_ABSENT"):
        assert header(none, key) == header(many, key), key
    assert "=== LIBRARY " not in none and "=== LIBRARY " in many


def test_a_library_pattern_never_clears_an_absent_locus():
    """GitHub Actions's ENDPOINT holds no eligible finding and one library pattern; the pattern
    is counted on the bullet and the locus is still reported absent. Kubernetes's MANAGEMENT
    was the fixture until its cloud organisation-policy and instance-access blocks, whose only
    live test is a cloud administrative API, were placed on MANAGEMENT."""
    _, out, _ = consult("GitHub Actions", "--limit", "12")
    absent = header(out, "LOCUS_ABSENT").split(":", 1)[1].split(" - ")[0]
    assert "ENDPOINT" in absent, "fixture no longer leaves ENDPOINT absent"
    bullet = [l for l in out.splitlines() if l.startswith("  - ENDPOINT: matched ")][0]
    assert re.search(r"; library (\d+)", bullet).group(1) == "1", bullet
    assert [b["LIBRARY_LOCUS"] for b in library_blocks(out)].count("ENDPOINT") == 1


def test_the_order_is_platform_fit_then_corroboration_then_id():
    """A pattern whose markers are written for another platform than the one asked about comes
    last: 4 of the 6 query.py once showed for "Linux kernel" were Windows-only."""
    _, out, _ = consult("Linux kernel", "--limit", "1", "--pattern-limit", "100")
    blocks = library_blocks(out)
    keys = []
    for block in blocks:
        pattern = PATTERNS[block["LIBRARY_PATTERN_ID"]]
        corroboration = pattern.get("external_corroboration") or {}
        weight = (corroboration.get("sigma_rules") or 0) \
            + (corroboration.get("splunk_detections") or 0)
        fit = int(re.match(r"platform_fit=([+-]?\d+)", block["LIBRARY_ORDER_BASIS"]).group(1))
        keys.append((-fit, -weight, pattern["id"]))
    assert keys == sorted(keys)
    fits = [k[0] for k in keys]
    assert -1 in fits and 1 in fits, "fixture no longer exercises platform fit"


def test_the_basis_names_what_a_pattern_is_placed_on():
    """A pattern has applies_to_classes, not a product_class, and the basis said product_class
    for both."""
    _, out, _ = consult("SCADA", "--limit", "1")
    blocks = library_blocks(out)
    assert blocks and all(b["LIBRARY_LOCUS"] == "CONTROL" for b in blocks)
    assert all("input=applies_to_classes first-listed=" in b["LIBRARY_LOCUS_BASIS"]
               for b in blocks)


def test_a_vendor_only_question_reaches_the_library_through_its_derived_classes():
    _, out, _ = consult("Fortinet", "--limit", "1")
    line = header(out, "LIBRARY_PATTERNS")
    assert "network.firewall" in line and "CLASSES_FROM_VENDOR" in line
    assert library_blocks(out)


def test_no_class_means_no_library_and_says_why():
    _, out, _ = consult("Sitecore")
    assert header(out, "LIBRARY_PATTERNS").startswith(
        "LIBRARY_PATTERNS: 0 shown of 0 matched on class - the question resolved no class")
    assert "=== LIBRARY " not in out


def test_corroborated_and_observed_stay_separate_claims():
    _, out, _ = consult("Microsoft Windows", "--limit", "1", "--pattern-limit", "100")
    for block in library_blocks(out):
        assert block["LIBRARY_OBSERVED"].startswith("no - no record in the corpus cites")
        assert block["LIBRARY_CORROBORATED"].startswith(("yes - ", "no - "))
        assert "record" not in block["LIBRARY_CORROBORATED"]


def test_every_finding_is_a_cited_record_and_rule_6_says_so():
    """DERIVATION had a library-pattern branch that could never fire, and rule 6 described it."""
    _, out, _ = consult("Kubernetes", "--limit", "12")
    derivations = set(re.findall(r"^DERIVATION: (.*)$", out, re.M))
    assert derivations == {"cited record"}
    with open(os.path.join(ROOT, "SKILL.md"), encoding="utf-8") as handle:
        skill = handle.read()
    rule = " ".join(re.search(r"^6\. \*\*.*?(?=^7\. )", skill, re.M | re.S).group(0).split())
    assert "always a cited record" in rule and "`LIBRARY` blocks" in rule, rule


def raw_block(out, opener, key, value):
    """The printed lines of the block opened by `opener` whose `key` line holds `value`."""
    for chunk in out.split(opener)[1:]:
        lines = chunk.splitlines()
        if "{}: {}".format(key, value) in lines:
            return lines
    raise AssertionError("no block with {}: {}".format(key, value))


def marker_lines(lines, count_key):
    start = next(i for i, l in enumerate(lines) if l.startswith(count_key + ": "))
    count = int(lines[start].split(": ", 1)[1])
    found = lines[start + 1:start + 1 + count]
    assert all(l.startswith("  - type=") for l in found), found
    return found


def test_a_marker_line_carries_its_field_its_event_and_how_its_list_combines():
    """consult.py printed type, match, value and expr only, so a keyed list read as a flat
    conjunction: pat-command-history-cleared's three labelled arms were five bare lines."""
    marker = {"type": "event_type", "match": "in", "value": ["OPERATION_TYPE_FILE_REMOVE"],
              "xdm": "xdm.event.operation", "event": "history_file", "note": "not printed"}
    assert C.marker_line(marker, "any") == (
        '  - type=event_type match=in value=["OPERATION_TYPE_FILE_REMOVE"] '
        'xdm=xdm.event.operation event=history_file combine=any')
    # The expression stays last, because it holds spaces; an unkeyed list prints no key.
    computed = {"type": "computed", "match": "gt", "value": 4, "expr": "count(x) by y",
                "event": "utility"}
    assert C.marker_line(computed, "all") == (
        "  - type=computed match=gt value=4 event=utility combine=all expr=count(x) by y")
    plain = {"type": "process_name", "match": "equals", "value": "a.exe"}
    assert C.marker_line(plain) == '  - type=process_name match=equals value="a.exe"'
    # A finding prints the block's own markers with its own key, else the pattern's with the
    # pattern's, as emit_xql.py renders them.
    pattern = {"markers": [plain], "combine": "any"}
    assert C.markers_of({"markers": [marker]}, pattern) == ([marker], None)
    assert C.markers_of({"markers": [marker], "combine": "all"}, pattern) == ([marker], "all")
    assert C.markers_of({}, pattern) == ([plain], "any")


def test_a_consultation_keeps_the_combination_contract():
    code, out, _ = consult("Linux kernel", "--pattern-limit", "100")
    assert code == 0
    lines = marker_lines(raw_block(out, "=== LIBRARY ", "LIBRARY_PATTERN_ID",
                                   "pat-command-history-cleared"), "LIBRARY_MARKERS")
    assert len(lines) == 5 and all(l.endswith("combine=any") for l in lines), lines
    assert [re.search(r" event=(\S+)", l).group(1) for l in lines] == [
        "command", "run_history", "run_history", "history_file", "history_file"]
    assert sum(" xdm=xdm.event.operation " in l for l in lines) == 2
    # A finding's own keyed block: the key file and the note are alternatives.
    finding = raw_block(out, "=== FINDING ", "FINDING_KEY",
                        "obs-generic-hive-ransomware-as-a-service-with-log-and-recovery-"
                        "destruction#how5")
    lines = marker_lines(finding, "MARKERS")
    assert len(lines) == 2 and all(l.endswith(" combine=any") for l in lines), lines
    # An unkeyed list says nothing it does not hold.
    lines = marker_lines(raw_block(out, "=== LIBRARY ", "LIBRARY_PATTERN_ID",
                                   "pat-linux-privilege-escalation-via-permitted-binary"),
                         "LIBRARY_MARKERS")
    assert lines and not any("combine=" in l or " event=" in l for l in lines), lines


# --- 0.43.0, batch V5: where a library pattern came from is its own ------------------------

def test_library_provenance_is_the_patterns_own_derived_from():
    """LIBRARY_MATCH printed one template for every library pattern, "derived from technique
    space rather than from an incident and is about no one product", and it was false for
    pat-appliance-internal-handler-requested-directly: derived from CISA malware analysis
    reports, markers that are one vendor's appliance paths. SKILL.md says to say where a
    library pattern came from, and the only answer the block gave was wrong."""
    code, out, _ = consult("Palo Alto firewall")
    assert code == 0
    blocks = library_blocks(out)
    assert blocks, "fixture no longer lists a library pattern"
    for block in blocks:
        pattern = PATTERNS[block["LIBRARY_PATTERN_ID"]]
        match = block["LIBRARY_MATCH"]
        assert "technique space" not in match and "no one product" not in match, match
        origins = pattern.get("derived_from") or []
        if origins:
            assert match.endswith("derived from " + "; ".join(origins)), match
        else:
            assert "records no derived_from" in match, match
    cisa = [b for b in blocks
            if b["LIBRARY_PATTERN_ID"] == "pat-appliance-internal-handler-requested-directly"]
    assert cisa and "CISA malware analysis reports" in cisa[0]["LIBRARY_MATCH"]
    assert "  - DERIVED_FROM | CISA malware analysis reports" in out
    assert "technique space" not in header(out, "LIBRARY_PATTERNS")
    tally = header(out, "LIBRARY_PATTERNS").split("derived_from, over all ")[1]
    total = int(re.search(r"^LIBRARY_PATTERNS: \d+ shown of (\d+)", out, re.M).group(1))
    assert tally.startswith("{}: ".format(total))


def test_every_library_pattern_states_its_origin_or_says_it_has_none():
    """Over every uncited pattern with markers, not the ones one question reaches."""
    library = [p for pid, p in PATTERNS.items() if pid not in CITED and p.get("markers")]
    assert len(library) >= 30
    for pattern in library:
        assert C.library_origins(pattern), pattern["id"]
        assert C.library_origins(pattern) == [str(x) for x in pattern.get("derived_from") or []] \
            or C.library_origins(pattern) == [C.NO_DERIVED_FROM], pattern["id"]


def test_query_library_listing_prints_derived_from():
    done = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "query.py"), "firewall"],
                          capture_output=True, text=True, cwd=ROOT, timeout=180)
    listing = done.stdout.split("library patterns for", 1)[1]
    assert "  derived from: CISA malware analysis reports" in listing
