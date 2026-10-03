# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The ladder that places a block on a locus, pinned where it is derived.

tests/test_locus_axis.py holds the quota and the header to what they print. Nothing held
the derivation itself: no test named a tier, and the three callers of locus_for() agreed
only by circumstance. consult.py passes the cited pattern and validate.py passes None, and
the two give the same answer today because every record carries a product_class, so the
pattern's applies_to_classes fallback is never reached, and because the evidence tier never
fires. A record without a class, or an evidence tier that started to fire, would make the
distribution validate.py prints a different thing from the loci consult.py emits, and
nothing would have said so.

Parity is stated for the question-independent path, which is the only one there is for the
primary and for the record's own span: neither LOCUS nor the span locus_for() returns depends
on the question. A class the question resolved can only append a value after the record's own,
and test_question_never_changes_the_primary holds it to that. Until the 2026-09-30 validation
this docstring said the class "can only add a second locus" while test_span_source_order
pinned it replacing the record's own; 238 (block, matched class) pairs dropped one that way.

Import-level calls, so the whole corpus is derived in well under a second. Run with
PYTHONDONTWRITEBYTECODE=1 (LAW A26).
"""
import collections
import json
import pathlib
import re
import subprocess
import sys

import pytest

BUNDLE = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = BUNDLE / "scripts"
CORPUS = BUNDLE / "corpus"

sys.path.insert(0, str(SCRIPTS))
import consult  # noqa: E402
import query  # noqa: E402

RECORDS, PATTERNS = query.load_corpus(str(CORPUS))
LOCUS_MAP = consult.load_locus_map(str(CORPUS))
BLOCKS = [(record, how) for record in RECORDS for how in (record.get("how") or [])]


def tier(basis):
    found = re.match(r"^tier=([a-z_]+);", basis)
    assert found, "LOCUS_BASIS does not lead with its tier: {}".format(basis)
    return found.group(1)


def test_the_fixture_has_blocks_to_derive():
    assert len(BLOCKS) > 700, "corpus loaded {} how-blocks".format(len(BLOCKS))


def test_consult_and_validate_derive_identically_block_by_block():
    """consult.py hands locus_for() the cited pattern; validate.py hands it None."""
    differ = []
    for record, how in BLOCKS:
        with_pattern = consult.locus_for(record, how, PATTERNS.get(how.get("pattern_id")), LOCUS_MAP)
        without = consult.locus_for(record, how, None, LOCUS_MAP)
        if with_pattern != without:
            differ.append((record.get("id"), how.get("pattern_id"), with_pattern, without))
    assert not differ, "{} block(s) derive differently with and without the pattern, e.g. {}".format(
        len(differ), differ[:3])


def test_consult_and_validate_derive_identically():
    """The distribution validate.py prints is the one consult.py's loci add up to."""
    counts, spans, declared = collections.Counter(), 0, 0
    for record, how in BLOCKS:
        locus, span, basis = consult.locus_for(
            record, how, PATTERNS.get(how.get("pattern_id")), LOCUS_MAP)
        counts[locus] += 1
        spans += bool(span)
        declared += tier(basis) == "declared"

    done = subprocess.run([sys.executable, str(SCRIPTS / "validate.py")],
                          capture_output=True, text=True, timeout=180)
    line = [l for l in done.stdout.splitlines() if l.startswith("locus derivation:")]
    assert len(line) == 1, done.stdout[-800:]
    found = re.match(r"^locus derivation: (\d+) how-blocks -> (.*); (\d+) declared override\(s\), "
                     r"(\d+) carrying a span$", line[0])
    assert found, line[0]
    printed = {k: int(v) for k, v in (part.split("=") for part in found.group(2).split())}
    assert int(found.group(1)) == len(BLOCKS)
    assert printed == {k: counts.get(k, 0) for k in LOCUS_MAP["locus_order"]}
    assert sum(printed.values()) == len(BLOCKS), "a block derived to a locus outside locus_order"
    assert int(found.group(3)) == declared
    assert int(found.group(4)) == spans


def test_every_block_derives_by_a_listed_tier():
    """Every basis names a tier the map lists, and nothing is UNDERIVABLE.

    Library patterns are derived as well, because advise.py places a pattern with no
    record behind it through the same ladder.
    """
    listed = set(LOCUS_MAP["tier_order"])
    loci = set(LOCUS_MAP["locus_order"])
    derived = [consult.locus_for(r, h, PATTERNS.get(h.get("pattern_id")), LOCUS_MAP) for r, h in BLOCKS]
    derived += [consult.locus_for(None, None, p, LOCUS_MAP) for p in PATTERNS.values()]
    for locus, span, basis in derived:
        assert locus in loci, "derived {!r}: {}".format(locus, basis)
        assert tier(basis) in listed, basis
        assert span is None or (span in loci and span != locus), basis


def test_the_tiers_the_code_names_are_the_map_tiers_in_order():
    assert list(consult.LOCUS_TIERS) == LOCUS_MAP["tier_order"]


def test_a_declared_locus_is_honoured_on_every_path():
    declared = [(r, h) for r, h in BLOCKS if h.get("locus")]
    assert declared, "no declared override left in the corpus to pin"
    for record, how in declared:
        for pattern in (PATTERNS.get(how.get("pattern_id")), None):
            locus, _, basis = consult.locus_for(record, how, pattern, LOCUS_MAP)
            assert locus == how["locus"] and tier(basis) == "declared", basis


def test_a_missing_map_is_underivable_and_says_so():
    """The one key that exists to be machine-parsed never takes a silent default."""
    record, how = BLOCKS[0]
    locus, span, basis = consult.locus_for(record, how, None, {})
    assert locus == "UNDERIVABLE" and span is None
    assert "locus-map.json" in basis


# ---------------------------------------------------------------- 0.43.0: what places a block

BY_ID = {r["id"]: r for r in RECORDS}
EXPOSURES = [r for r in RECORDS if r.get("record_type") == "exposure"]
NONPRODUCT = set(LOCUS_MAP["nonproduct_class"])
GENERATOR_TAGS = set(LOCUS_MAP["untrusted_surface_tags"])


def block(record_id, pattern_id):
    record = BY_ID[record_id]
    found = [h for h in record["how"] if h.get("pattern_id") == pattern_id]
    assert len(found) == 1, "fixture {} no longer cites {} once".format(record_id, pattern_id)
    return record, found[0]


def synthetic(classes, surface="local_network", evidence=("syslog",), tags=(), kind="observation"):
    """A record carrying only what the ladder reads, so a rule is pinned without a fixture."""
    record = {"id": "obs-synthetic", "record_type": kind, "tags": list(tags),
              "who": {"product_class": list(classes)}, "what": {"attack_surface": surface}}
    return record, {"evidence_type": list(evidence), "rule_shape": "single_event"}


def test_the_span_sources_the_code_names_are_the_map_span_order():
    assert list(consult.LOCUS_SPAN_SOURCES) == LOCUS_MAP["span_order"]


def test_nonproduct_tier_fires_only_on_the_primary_subject():
    """cross_sector anywhere in the list made the block ORGANISATION; authors use it as a
    sector tag, so 90 EDR and auth-log device events printed 'an inventory or advice
    question'. The tier now fires on the first-listed class, or when every class is one."""
    fired = 0
    for record, how in BLOCKS:
        _, _, basis = consult.locus_for(record, how, None, LOCUS_MAP)
        if tier(basis) == "class_nonproduct":
            fired += 1
            classes = record["who"]["product_class"]
            assert classes[0] in NONPRODUCT or set(classes) <= NONPRODUCT, (record["id"], classes)
    for pattern in PATTERNS.values():
        _, _, basis = consult.locus_for(None, None, pattern, LOCUS_MAP)
        if tier(basis) == "class_nonproduct":
            classes = pattern["applies_to_classes"]
            assert classes[0] in NONPRODUCT or set(classes) <= NONPRODUCT, (pattern["id"], classes)
    assert fired, "no block is placed by a first-listed non-product class any more"

    first = consult.locus_for(*synthetic(["cross_sector", "network.firewall"]), None, LOCUS_MAP)
    assert first[0] == "ORGANISATION" and tier(first[2]) == "class_nonproduct"
    trailing = consult.locus_for(*synthetic(["network.firewall", "cross_sector"]), None, LOCUS_MAP)
    assert trailing[:2] == ("CONTROL", "ORGANISATION"), trailing
    assert "nonproduct-signal=ORGANISATION (cross_sector listed, not primary)" in trailing[2]
    assert "span-source=nonproduct" in trailing[2]


def test_a_trailing_sector_tag_does_not_make_a_device_event_organisation():
    record, how = block("obs-generic-hive-ransomware-as-a-service-with-log-and-recovery-destruction",
                        "pat-shadow-copy-deletion")
    locus, span, basis = consult.locus_for(record, how, None, LOCUS_MAP)
    assert locus == "ENDPOINT", basis
    assert "nonproduct-signal=ORGANISATION (cross_sector listed, not primary)" in basis


def test_library_pattern_with_trailing_cross_sector():
    locus, span, basis = consult.locus_for(
        None, None, PATTERNS["pat-browser-api-hooking-for-transaction-fraud"], LOCUS_MAP)
    assert locus == "ENDPOINT", basis
    assert span == "ORGANISATION"


def test_a_delivery_vector_does_not_decide_the_plane():
    """email_flow placed a Chrome renderer breakout read from EDR on DATA, and both Okta
    records on DATA while the gate they abuse is CONTROL. remote_access_service did the same
    for host events, into MANAGEMENT. Both now travel as a span and decide nothing."""
    chrome = BY_ID["obs-google-chrome-patch-gap-chain-to-browser-process-injection"]
    locus, span, basis = consult.locus_for(chrome, chrome["how"][0], None, LOCUS_MAP)
    assert (locus, span) == ("ENDPOINT", "DATA"), basis
    assert "span only" in basis and "span-source=surface_span_only" in basis

    record, how = block("obs-okta-single-sign-on-flow-proxied-by-a-lookalike-tenant",
                        "pat-session-token-replay")
    assert consult.locus_for(record, how, None, LOCUS_MAP)[0] == "CONTROL"

    for value in LOCUS_MAP["surface_span_only"]:
        decided = [r["id"] for r, h in BLOCKS
                   if consult.locus_for(r, h, None, LOCUS_MAP)[2].startswith(
                       "tier=surface; input=what.attack_surface={}".format(value))]
        assert not decided, "{} still decides {}".format(value, decided[:3])
        carried = [r for r, h in BLOCKS if r["what"].get("attack_surface") == value]
        assert carried, "no block carries {} any more; the rule is untested".format(value)


def test_a_delivery_vector_still_reaches_the_answer_as_a_span():
    code = subprocess.run(
        [sys.executable, str(SCRIPTS / "consult.py"), "Google Chrome", "--today", "2026-09-25",
         "--limit", "12"], capture_output=True, text=True, timeout=180)
    assert code.returncode == 0, code.stderr
    lines = code.stdout.splitlines()
    record_id = None
    for line in lines:
        if line.startswith("RECORD_ID: "):
            record_id = line.split(": ", 1)[1]
        if line == "LOCUS: ENDPOINT":
            assert record_id.startswith("obs-google-chrome"), record_id
            break
    else:
        pytest.fail("no ENDPOINT finding shown for Google Chrome")


def test_span_source_order():
    """The first source whose locus differs from the primary wins, and there is one order.

    The hive block carries remote_access_service, span only, and a trailing cross_sector:
    the surface is tried first, so it spans MANAGEMENT, not ORGANISATION."""
    record, how = block("obs-generic-hive-ransomware-as-a-service-with-log-and-recovery-destruction",
                        "pat-shadow-copy-deletion")
    locus, span, basis = consult.locus_for(record, how, None, LOCUS_MAP)
    assert (locus, span) == ("ENDPOINT", "MANAGEMENT"), basis
    assert "span-source=surface_span_only" in basis

    # A question's class is appended after the record's own span. It used to outrank every
    # other source and replace the span: this block printed ENDPOINT, CONTROL on a firewall
    # question and ENDPOINT, DATA in emit_xql.py, two answers to where one block sits.
    record, how = synthetic(["endpoint.os", "network.firewall", "cross_sector"], surface="email_flow")
    plain = consult.locus_for(record, how, None, LOCUS_MAP)
    asked = consult.locus_for(record, how, None, LOCUS_MAP, {"network.firewall"})
    assert plain[:2] == ("ENDPOINT", "DATA") and asked[:2] == ("ENDPOINT", "DATA"), (plain, asked)
    assert "span-source=surface_span_only, then class_matched span: network.firewall" in asked[2]
    assert consult.placed(record, how, None, LOCUS_MAP, {"network.firewall"})[:2] == (
        "ENDPOINT", ("DATA", "CONTROL"))
    # A question class on the record's own span or primary adds nothing.
    assert consult.placed(record, how, None, LOCUS_MAP, {"endpoint.os"})[1] == ("DATA",)


def test_evidence_signal_is_printed_and_spans_when_unanimous():
    """The evidence tier could never fire and its signal was never printed, although the
    docs said LOCUS_BASIS printed every signal. Evidence is now the last span source."""
    record, how = block("obs-generic-hive-ransomware-as-a-service-with-log-and-recovery-destruction",
                        "pat-shadow-copy-deletion")
    assert "evidence-signal=ENDPOINT (unanimous)" in consult.locus_for(record, how, None, LOCUS_MAP)[2]

    # The KEV-harvest join was this fixture until the 2026-10-01 third validation placed it
    # on ORGANISATION by the posture tier, where its posture evidence is the primary.
    overlay = BY_ID["obs-generic-anonymising-overlay-network-as-attack-infrastructure"]
    locus, span, basis = consult.locus_for(overlay, overlay["how"][0], None, LOCUS_MAP)
    assert (locus, span) == ("CONTROL", "DATA") and "span-source=evidence" in basis, basis

    deferred = set(LOCUS_MAP["defer_evidence"])
    spanned = 0
    for record, how in BLOCKS:
        locus, span, basis = consult.locus_for(record, how, None, LOCUS_MAP)
        assert "evidence-signal=" in basis, basis
        assert tier(basis) != "evidence", basis
        if "span-source=evidence" in basis:
            spanned += 1
            values = {LOCUS_MAP["by_evidence"][e] for e in how["evidence_type"] if e not in deferred}
            assert values == {span}, (record["id"], how.get("pattern_id"), values, span)
    assert spanned, "no block takes its span from evidence"


def test_split_class_signal_names_the_first_listed_class():
    harvest = BY_ID["obs-generic-broad-known-vulnerability-harvesting"]
    basis = consult.locus_for(harvest, harvest["how"][0], None, LOCUS_MAP)[2]
    assert "class-signal=split(first=server.web:DATA; also CONTROL, MANAGEMENT)" in basis, basis


def test_question_never_changes_the_primary():
    """The class a question matched may add a span; it never moves LOCUS. Placing a
    multi-product record by the product asked about would have printed an EPMM record as
    CONTROL for an Okta question, against app.mdm deriving MANAGEMENT, and made
    emit_xql.py and advise.py disagree with a consultation about the same block."""
    everything = set(LOCUS_MAP["by_class"])
    for record, how in BLOCKS:
        plain = consult.locus_for(record, how, None, LOCUS_MAP)
        for asked in (everything, set(record["who"]["product_class"][1:])):
            locus, span, basis = consult.locus_for(record, how, None, LOCUS_MAP, asked)
            assert locus == plain[0], (record["id"], asked, basis)
            assert span == plain[1], (record["id"], asked, basis)
            spans = consult.placed(record, how, None, LOCUS_MAP, asked)[1]
            assert list(spans[:1]) == ([plain[1]] if plain[1] else list(spans[:1])), spans
            assert len(set(spans)) == len(spans) and locus not in spans


def _consult(question):
    done = subprocess.run([sys.executable, str(SCRIPTS / "consult.py"), question, "--today",
                           "2026-09-25", "--limit", "500"], capture_output=True, text=True, timeout=180)
    assert done.returncode == 0, done.stderr
    findings, current = [], {}
    for line in done.stdout.splitlines():
        if line.startswith("=== FINDING "):
            current = {}
        elif line.startswith("=== END FINDING "):
            findings.append(current)
        else:
            key = re.match(r"^([A-Z_]+): (.*)$", line)
            if key:
                current[key.group(1)] = key.group(2)
    return findings


def test_question_never_changes_the_primary_on_screen():
    harvest = [f for f in _consult("I have a Palo Alto firewall")
               if f["RECORD_ID"] == "obs-generic-broad-known-vulnerability-harvesting"]
    assert harvest, "fixture record no longer reached"
    for finding in harvest:
        # An inventory question since the 2026-10-01 third validation, with no span of its
        # own: the second value is the question's class, appended.
        assert finding["LOCUS"] == "ORGANISATION"
        assert finding["LOCUS_SPAN"] == "ORGANISATION, CONTROL"
        assert "span-source=class_matched span: network.firewall" in finding["LOCUS_BASIS"]
    epmm = [f for f in _consult("Okta")
            if f["RECORD_ID"] == "obs-ivanti-epmm-authentication-bypass-and-arbitrary-file-write-chain"]
    assert epmm, "fixture record no longer reached"
    # app.mdm is MANAGEMENT: every detection block of the EPMM record sits there, and none
    # reaches the handset plane. Its patch-posture block is an inventory question, which the
    # posture tier puts on ORGANISATION whatever class is listed first.
    for finding in epmm:
        if finding["LOCUS_BASIS"].startswith("tier=posture;"):
            assert finding["LOCUS"] == "ORGANISATION", finding["LOCUS_BASIS"]
        else:
            assert finding["LOCUS"] == "MANAGEMENT", finding["LOCUS_BASIS"]
    assert "MANAGEMENT" in {f["LOCUS"] for f in epmm}
    assert "ENDPOINT" not in {f["LOCUS"] for f in epmm}


def test_generated_exposure_surface_is_ignored_and_authored_is_kept():
    """A generator writes an exposure's surface from a class table, so the surface tier was
    re-encoding the class through a remap that sends firewalls and hypervisors to
    MANAGEMENT. A hand-written exposure's surface was read from its advisory and is kept."""
    got = {rid: consult.locus_for(BY_ID[rid], None, None, LOCUS_MAP)
           for rid in ("exp-zdi-linux-kernel", "exp-kev-check-point-security-gateway",
                       "exp-kev-ivanti-endpoint-manager-mobile-epmm")}
    assert {rid: v[0] for rid, v in got.items()} == {
        "exp-zdi-linux-kernel": "ENDPOINT", "exp-kev-check-point-security-gateway": "CONTROL",
        "exp-kev-ivanti-endpoint-manager-mobile-epmm": "MANAGEMENT"}
    assert "internet_facing_management is generator-assigned" in \
        got["exp-kev-check-point-security-gateway"][2]

    vcenter = consult.locus_for(BY_ID["exp-broadcom-vmware-vcenter-arbitrary-file-upload"],
                                None, None, LOCUS_MAP)
    assert vcenter[0] == "MANAGEMENT" and tier(vcenter[2]) == "surface", vcenter

    generated = 0
    for record in EXPOSURES:
        locus, span, basis = consult.locus_for(record, None, None, LOCUS_MAP)
        if not GENERATOR_TAGS & set(record.get("tags") or []):
            continue
        generated += 1
        assert not basis.startswith("tier=surface"), (record["id"], basis)
        assert "not read" in basis, basis
        classes = record["who"]["product_class"]
        if basis.startswith("tier=identifier;"):
            # 0.44.0: every identifier's own text reads one locus (what.identifier_signals),
            # and that, not the surface, is what moved it off its class.
            read = {e["locus"] for e in record["what"]["identifier_signals"] if e.get("locus")}
            assert read == {locus}, (record["id"], locus, basis)
        elif not set(classes) & NONPRODUCT:
            first = next(c for c in classes if c in LOCUS_MAP["by_class"])
            assert locus == LOCUS_MAP["by_class"][first], (record["id"], locus, basis)
    assert generated > 800, generated


def test_consult_and_validate_place_exposures_identically():
    counts, generated = collections.Counter(), 0
    for record in EXPOSURES:
        counts[consult.locus_for(record, None, None, LOCUS_MAP)[0]] += 1
        generated += bool(GENERATOR_TAGS & set(record.get("tags") or []))
    done = subprocess.run([sys.executable, str(SCRIPTS / "validate.py")],
                          capture_output=True, text=True, timeout=180)
    line = [l for l in done.stdout.splitlines() if l.startswith("locus derivation (exposures):")]
    assert len(line) == 1, done.stdout[-800:]
    found = re.match(r"^locus derivation \(exposures\): (\d+) records -> (.*); (\d+) generator-tagged", line[0])
    assert found, line[0]
    printed = {k: int(v) for k, v in (part.split("=") for part in found.group(2).split())}
    assert int(found.group(1)) == len(EXPOSURES)
    assert printed == {k: counts.get(k, 0) for k in LOCUS_MAP["locus_order"]}
    assert int(found.group(3)) == generated


def test_the_reference_states_the_distribution_the_ladder_gives():
    """references/locus-and-coverage.md prints both tallies, and a count written into prose
    goes stale unseen: the 115 in test_locus_axis.py's docstring and the figures in the
    locus map's comments had. Held to the derivation, so a ladder change fails here until
    the reference says what it now does."""
    text = " ".join((BUNDLE / "references" / "locus-and-coverage.md").read_text(encoding="utf-8").split())

    def parse(body):
        return {k: int(v) for k, v in re.findall(r"`([A-Z]+)` (\d+)", body)}

    blocks = re.search(r"Distribution over all (\d+) how-blocks: (.*?), with (\d+) carrying a span\.", text)
    assert blocks, "the reference no longer states the block distribution"
    counts, spans = collections.Counter(), 0
    for record, how in BLOCKS:
        locus, span, _ = consult.locus_for(record, how, None, LOCUS_MAP)
        counts[locus] += 1
        spans += bool(span)
    assert int(blocks.group(1)) == len(BLOCKS)
    assert parse(blocks.group(2)) == dict(counts)
    assert int(blocks.group(3)) == spans

    exposures = re.search(r"The (\d+) exposure records place as (.*?)\. ", text)
    assert exposures, "the reference no longer states the exposure distribution"
    placed = collections.Counter(consult.locus_for(r, None, None, LOCUS_MAP)[0] for r in EXPOSURES)
    assert int(exposures.group(1)) == len(EXPOSURES)
    assert parse(exposures.group(2)) == dict(placed)


# ------------------------------------------------ 2026-09-30 validation: what reaches a block

sys.path.insert(0, str(SCRIPTS))
import validate  # noqa: E402

ATTACK = json.loads((CORPUS / "reference" / "attack-techniques.json").read_text(
    encoding="utf-8"))["techniques"]


def block_at(record_id, index):
    return BY_ID[record_id], BY_ID[record_id]["how"][index]


def one_block(classes, surface, evidence=("syslog",), technique=(), markers=(), kind="observation"):
    record, how = synthetic(classes, surface=surface, evidence=evidence, kind=kind)
    how["technique"] = list(technique)
    how["markers"] = [dict(m) for m in markers]
    return record, how


def test_a_surface_does_not_place_a_block_past_the_way_in():
    """A record's surface is per record, and it put every block of a Siemens PLC record on
    MANAGEMENT with the internet-facing management interface the controllers were reached
    through, operator-display manipulation and S7 data-block writes included, so no Siemens
    finding reached CONTROL. A block past the way in is placed by its class now."""
    cases = {
        # read from industrial protocol and process telemetry: the PLC's own plane
        ("obs-generic-internet-exposed-plc-disruption-and-display-manipulation", 0): "CONTROL",
        ("obs-siemens-s7-plc-commodity-library-tooling", 3): "CONTROL",
        # posture only: an inventory question, not the management interface. It sat on CONTROL
        # by its class until the 2026-10-01 third validation; the posture tier now places it.
        ("obs-siemens-s7-plc-commodity-library-tooling", 5): "ORGANISATION",
        # a configuration change and a default administrative account stay administration
        ("obs-siemens-s7-plc-commodity-library-tooling", 4): "MANAGEMENT",
        ("obs-generic-internet-exposed-plc-disruption-and-display-manipulation", 1): "MANAGEMENT",
        # an administrative login read from auth_log cites the way in and keeps the surface
        ("obs-cisco-ios-xe-router-pivot-and-container-evasion", 2): "MANAGEMENT",
        ("obs-cisco-ios-snmp-router-implant", 0): "MANAGEMENT",
    }
    for (rid, index), want in cases.items():
        locus, span, basis = consult.locus_for(*block_at(rid, index), None, LOCUS_MAP)
        assert locus == want, (rid, index, basis)
        if want == "CONTROL":
            assert span == "MANAGEMENT" and "set aside for this block" in basis, basis
            assert tier(basis) == "class_first", basis
        if want == "ORGANISATION":
            assert span == "MANAGEMENT" and "span-source=surface" in basis, basis
            assert tier(basis) == "posture", basis

    # Each rule on a block carrying only what the ladder reads.
    plc = ["ot.plc", "ot.hmi"]
    past = consult.locus_for(*one_block(plc, "internet_facing_management", ("ics_protocol",)),
                             None, LOCUS_MAP)
    assert past[:2] == ("CONTROL", "MANAGEMENT") and "span-source=surface" in past[2], past
    assert consult.locus_for(*one_block(plc, "internet_facing_management", ("ics_protocol",),
                                        ("T0883",)), None, LOCUS_MAP)[0] == "MANAGEMENT"
    assert consult.locus_for(*one_block(plc, "internet_facing_management",
                                        ("ics_protocol", "config_diff")), None, LOCUS_MAP)[0] \
        == "MANAGEMENT"
    assert consult.locus_for(*one_block(plc, "internet_facing_management", ("asset_inventory",)),
                             None, LOCUS_MAP)[0] == "CONTROL"
    # Evidence that reads neither the class's plane nor only posture leaves the surface deciding.
    assert consult.locus_for(*one_block(plc, "internet_facing_management", ("netflow",)),
                             None, LOCUS_MAP)[0] == "MANAGEMENT"
    # A sub-technique counts as its parent.
    router = ["network.router"]
    assert consult.locus_for(*one_block(router, "internet_facing_management", ("auth_log",),
                                        ("T1078.001",)), None, LOCUS_MAP)[0] == "MANAGEMENT"
    assert consult.locus_for(*one_block(router, "internet_facing_management", ("auth_log",)),
                             None, LOCUS_MAP)[0] == "CONTROL"
    # An exposure has no block: its authored surface still decides for the record.
    record, _ = one_block(plc, "internet_facing_management", kind="exposure")
    assert consult.locus_for(record, None, None, LOCUS_MAP)[0] == "MANAGEMENT"


def test_a_vendor_only_plc_question_reaches_control_with_the_vendors_own_records():
    """The planes-ot probe: every Siemens-naming finding was MANAGEMENT, and CONTROL held one
    reserved slot from another vendor's record."""
    findings = [f for f in _consult("Siemens") if f["MATCH_TIER"] in ("product", "vendor")]
    assert findings, "no finding names Siemens"
    control = [f for f in findings if f["LOCUS"] == "CONTROL"]
    assert control, "no Siemens-naming finding sits on CONTROL"
    assert {"CONTROL", "MANAGEMENT", "ENDPOINT"} <= {f["LOCUS"] for f in findings}
    # The other loci are the posture question about exploit development, an inventory
    # question since the 2026-10-01 third validation, and the library artefact read from EDR
    # alone, which sat on the management interface until the fourth.
    for finding in findings:
        if finding["LOCUS"] == "ENDPOINT":
            assert finding["LOCUS_BASIS"].startswith("tier=host_evidence;"), finding["LOCUS_BASIS"]
        elif finding["LOCUS"] not in ("CONTROL", "MANAGEMENT"):
            assert finding["LOCUS"] == "ORGANISATION", finding["LOCUS_BASIS"]
            assert finding["LOCUS_BASIS"].startswith("tier=posture;"), finding["LOCUS_BASIS"]


def test_a_supply_surface_places_only_the_supply_path():
    """supply_chain_update put the AWS miner's pool traffic and its IAM workload creation on
    SUPPLY, and every SolarWinds block, Golden SAML included. It now places a block citing
    Supply Chain Compromise or Trusted Relationship, or reading integrity_check."""
    miner = "obs-amazon-cryptojacking-spread-across-uncommon-services"
    for index in range(2):
        locus, span, basis = consult.locus_for(*block_at(miner, index), None, LOCUS_MAP)
        assert (locus, span) == ("MANAGEMENT", "SUPPLY"), basis
    # The pool traffic reads flow and DNS records, never the provider's API, so since the
    # 2026-10-01 third validation cloud.iaas does not place it (admin_api_unread).
    locus, span, basis = consult.locus_for(*block_at(miner, 2), None, LOCUS_MAP)
    assert (locus, span) == ("DATA", "SUPPLY") and "set aside for this block" in basis, basis
    orion = "obs-solarwinds-orion-supply-chain-compromise-and-federated-identity-abuse"
    assert consult.locus_for(*block_at(orion, 0), None, LOCUS_MAP)[0] == "SUPPLY"
    golden = [consult.locus_for(r, h, None, LOCUS_MAP) for r, h in [
        block("obs-solarwinds-orion-supply-chain-compromise-and-federated-identity-abuse",
              "pat-forged-saml-token")]]
    assert golden[0][:2] == ("MANAGEMENT", "SUPPLY"), golden
    codebuild = block("obs-amazon-codebuild-webhook-actor-filter-matched-on-substring",
                      "pat-authorisation-filter-matches-on-substring")
    assert consult.locus_for(*codebuild, None, LOCUS_MAP)[0] == "SUPPLY"

    iaas = ["cloud.iaas", "app.cicd"]
    after = consult.locus_for(*one_block(iaas, "supply_chain_update", ("netflow", "cloud_audit")),
                              None, LOCUS_MAP)
    assert after[:2] == ("MANAGEMENT", "SUPPLY") and "set aside for this block" in after[2], after
    after = consult.locus_for(*one_block(iaas, "supply_chain_update", ("netflow", "dns")),
                              None, LOCUS_MAP)
    assert after[:2] == ("DATA", "SUPPLY") and "set aside for this block" in after[2], after
    for technique, evidence in ((("T1195.002",), ("netflow",)), ((), ("integrity_check",))):
        got = consult.locus_for(*one_block(iaas, "supply_chain_update", evidence, technique),
                                None, LOCUS_MAP)
        assert got[0] == "SUPPLY" and tier(got[2]) == "surface_supply", got
    assert consult.locus_for(*one_block(["identity.directory"], "third_party_access",
                                        ("auth_log",), ("T1199",)), None, LOCUS_MAP)[0] == "SUPPLY"
    # The vector is the surface's own: Trusted Relationship does not place a supply-chain update.
    assert consult.locus_for(*one_block(["identity.directory"], "supply_chain_update",
                                        ("auth_log",), ("T1199",)), None, LOCUS_MAP)[0] == "CONTROL"
    # A class on SUPPLY keeps its tier: nothing is set aside that would not move.
    kept = consult.locus_for(*one_block(["app.cicd"], "supply_chain_update", ("netflow",)),
                             None, LOCUS_MAP)
    assert kept[0] == "SUPPLY" and tier(kept[2]) == "surface_supply", kept


def test_a_cloud_administrative_api_block_is_management():
    """The emit-xql probe: blocks whose only live test is a cloud provider's or tenant's
    administrative API printed CONTROL or ENDPOINT from a container, AI-platform, directory or
    host class listed first, against the standing decision that such an API is MANAGEMENT."""
    keys = ["obs-generic-container-and-cloud-control-conditions-from-restricted-library#how1",
            "obs-generic-container-and-cloud-control-conditions-from-restricted-library#how2",
            "obs-amazon-bedrock-model-access-obtained-by-minting-iam-users#how1",
            "obs-generic-remaining-gap-conditions-from-restricted-library#how0",
            "obs-generic-impacket-toolkit-and-long-term-multi-actor-access#how2"]
    for key in keys:
        done = subprocess.run([sys.executable, str(SCRIPTS / "emit_xql.py"), key],
                              capture_output=True, text=True, timeout=180)
        assert done.returncode == 0, done.stderr
        header = [l for l in done.stdout.splitlines() if l.startswith("// obs-")]
        assert len(header) == 1 and "  locus=MANAGEMENT  " in header[0], (key, header)
    # A use of the service in the same audit trail is not its administration.
    exchange = block_at("obs-microsoft-exchange-online-forged-token-mailbox-access", 0)
    assert consult.locus_for(*exchange, None, LOCUS_MAP)[0] == "DATA"
    # 0.43.0 kept the Bedrock model-access block on CONTROL for the user name and agent beside
    # its operations; the fourth validation read them as fields of the same CloudTrail event,
    # and a block reading nothing but that trail is now placed by its administrative operations.
    bedrock = block_at("obs-amazon-bedrock-model-access-obtained-by-minting-iam-users", 0)
    assert consult.locus_for(*bedrock, None, LOCUS_MAP)[0] == "MANAGEMENT"

    host = ["endpoint.os", "server.mail"]
    admin = consult.locus_for(*one_block(host, "local_network", ("cloud_audit",), markers=[
        {"type": "cloud_operation", "match": "in", "value": ["CreateUser", "GetObject"]},
        {"type": "computed", "match": "equals", "value": True, "expr": "x"}]), None, LOCUS_MAP)
    assert admin[0] == "MANAGEMENT" and tier(admin[2]) == "operation", admin
    assert "CreateUser, GetObject" in admin[2]
    # A block reading more than the audit trail is not placed by an operation beside other
    # markers: the process name is read from the host evidence, not from the audit event.
    for evidence, markers in (
            (("cloud_audit",),
             [{"type": "cloud_operation", "match": "equals", "value": "MailItemsAccessed"}]),
            (("cloud_audit", "edr_process"),
             [{"type": "cloud_operation", "match": "in", "value": ["CreateUser"]},
              {"type": "process_name", "match": "equals", "value": "sh"}]),
            (("cloud_audit",), [])):
        got = consult.locus_for(*one_block(host, "local_network", evidence, markers=markers),
                                None, LOCUS_MAP)
        assert got[0] == "ENDPOINT", (markers, got)
    regex = consult.locus_for(*one_block(host, "local_network", markers=[
        {"type": "cloud_operation", "match": "regex", "value": "(?i)get.*object"}]),
        None, LOCUS_MAP)
    assert regex[0] == "MANAGEMENT", regex


def test_consult_and_emit_agree_on_the_records_span():
    """The locus-consistency probe: on "Fortinet FortiGate" 11 of 78 findings printed a span
    whose record-derived second value the question's class had replaced. Every finding's
    LOCUS_SPAN now begins with the span emit_xql.py prints for the same block."""
    done = subprocess.run([sys.executable, str(SCRIPTS / "consult.py"), "Fortinet FortiGate",
                           "--today", "2026-09-30", "--limit", "500", "--no-locus-spread"],
                          capture_output=True, text=True, timeout=180)
    assert done.returncode == 0, done.stderr
    keyed = {}
    for line in done.stdout.splitlines():
        if line.startswith("FINDING_KEY: "):
            key = line.split(": ", 1)[1]
        elif line.startswith("LOCUS_SPAN: "):
            keyed[key] = line.split(": ", 1)[1].split(", ")
    assert len(keyed) > 70, len(keyed)
    appended = 0
    for key, printed in keyed.items():
        rid, index = key.rsplit("#how", 1)
        record = BY_ID[rid]
        how = record["how"][int(index)]
        locus, span, _ = consult.locus_for(record, how, PATTERNS.get(how.get("pattern_id")),
                                           LOCUS_MAP)
        emitted = [locus] + ([span] if span else [])
        assert printed[:len(emitted)] == emitted, (key, printed, emitted)
        appended += len(printed) > len(emitted)
    assert appended, "no finding carries a question class after its own span; untested"
    ransomware = keyed["obs-generic-ransomware-repeated-deployment-and-enclave-mapping#how1"]
    assert ransomware == ["ENDPOINT", "MANAGEMENT", "CONTROL"], ransomware


MANAGEMENT_PATTERNS = ("pat-snmp-from-unexpected-source",
                       "pat-management-channel-usable-before-authentication-completes",
                       "pat-unsanitised-input-executed-via-log-write",
                       "pat-scripted-device-config-harvesting")


def test_patterns_about_administering_a_device_derive_management():
    """The advise-attack-id probe: SNMP, management-interface and admin-login patterns printed
    CONTROL, from the network class listed first, because a device's administration has no
    class of its own. Each now declares MANAGEMENT with its reason."""
    for pid in MANAGEMENT_PATTERNS:
        locus, span, basis = consult.locus_for(None, None, PATTERNS[pid], LOCUS_MAP)
        assert locus == "MANAGEMENT" and tier(basis) == "declared", (pid, basis)
        assert PATTERNS[pid]["locus_reason"] in basis
    done = subprocess.run([sys.executable, str(SCRIPTS / "advise.py"), "--attack", "T1190",
                           "--no-verify"], capture_output=True, text=True, timeout=300)
    assert done.returncode == 0, done.stderr
    current, placed = None, {}
    for line in done.stdout.splitlines():
        if line.startswith("--- PATTERN_ID: "):
            current = line.split(": ", 1)[1]
        elif line.startswith("LOCUS: ") and current:
            placed.setdefault(current, line.split(": ", 1)[1])
    for pid in MANAGEMENT_PATTERNS[:3]:
        assert placed.get(pid) == "MANAGEMENT", (pid, placed.get(pid))

    # A declared pattern locus never reaches a block, so validate.py and consult.py agree.
    record, how = block("obs-cisco-ios-snmp-router-implant", "pat-snmp-from-unexpected-source")
    assert consult.locus_for(record, how, PATTERNS["pat-snmp-from-unexpected-source"],
                             LOCUS_MAP) == consult.locus_for(record, how, None, LOCUS_MAP)


def test_validate_holds_a_declared_pattern_locus_to_its_reason():
    vocab = json.loads((CORPUS / "schema" / "vocab.json").read_text(encoding="utf-8"))
    base = {k: v for k, v in PATTERNS["pat-snmp-from-unexpected-source"].items()
            if k not in ("locus", "locus_reason")}

    def problems(**extra):
        found = []
        validate.check_declared_pattern_locus(dict(base, **extra), vocab, LOCUS_MAP, "p", found)
        return [p.message if hasattr(p, "message") else str(p) for p in found]

    assert problems() == []
    assert problems(locus="MANAGEMENT", locus_reason="SNMP") == []
    assert any("no locus_reason" in p for p in problems(locus="MANAGEMENT"))
    assert any("already gives" in p for p in problems(locus="CONTROL", locus_reason="x"))
    assert any("semicolon" in p for p in problems(locus="MANAGEMENT", locus_reason="a; b"))
    assert any("not in vocab.locus" in p for p in problems(locus="PLANE", locus_reason="x"))
    assert any("no locus is declared" in p for p in problems(locus_reason="x"))


def test_validate_holds_the_technique_lists_to_the_reference():
    vocab = json.loads((CORPUS / "schema" / "vocab.json").read_text(encoding="utf-8"))
    schema = json.loads((CORPUS / "schema" / "observation.schema.json").read_text(encoding="utf-8"))

    def problems(**changes):
        found = []
        validate.check_locus_map(vocab, schema, dict(LOCUS_MAP, **changes), found, ATTACK)
        return [str(p) for p in found]

    assert problems() == []
    assert any("omits T1190" in p for p in problems(
        way_in_techniques=[t for t in LOCUS_MAP["way_in_techniques"] if t != "T1190"]))
    assert any("lists T1059" in p for p in problems(
        way_in_techniques=LOCUS_MAP["way_in_techniques"] + ["T1059"]))
    assert any("not a supply surface" in p for p in problems(
        surface_vector_techniques=dict(LOCUS_MAP["surface_vector_techniques"],
                                       internet_facing_management=["T1190"])))
    assert any("no surface_vector_techniques entry" in p for p in problems(
        surface_vector_techniques={"supply_chain_update": ["T1195"]}))
    assert any("not in way_in_techniques" in p for p in problems(
        surface_vector_techniques=dict(LOCUS_MAP["surface_vector_techniques"],
                                       third_party_access=["T1059"])))
    assert any("list of operation names" in p for p in problems(
        non_administrative_operations="MailItemsAccessed"))


def test_validate_counts_what_each_per_block_rule_placed():
    """The distribution is the number that says the axis has broken, and a per-block rule that
    fired everywhere or nowhere would not move it much. validate.py prints what each placed."""
    set_aside, supply = 0, 0
    placed = collections.Counter()
    for record, how in BLOCKS:
        basis = consult.locus_for(record, how, None, LOCUS_MAP)[2]
        if "set aside for this block" in basis:
            set_aside += 1
            supply += record["what"].get("attack_surface") in LOCUS_MAP["surface_supply"]
        placed[tier(basis)] += 1
    operation, posture, unread = placed["operation"], placed["posture"], placed["admin_api_unread"]
    host, listed, host_listed = (placed["host_evidence"], placed["admin_api_listed"],
                                 placed["host_listed"])
    declared = sum(bool(p.get("locus")) for p in PATTERNS.values())
    assert set_aside and supply and set_aside > supply and operation and declared
    assert posture and unread and host and listed and host_listed
    done = subprocess.run([sys.executable, str(SCRIPTS / "validate.py")],
                          capture_output=True, text=True, timeout=180)
    line = [l for l in done.stdout.splitlines() if l.startswith("locus derivation (per block):")]
    assert len(line) == 1, done.stdout[-800:]
    assert line[0] == (
        "locus derivation (per block): {} block(s) past their record's surface placed without it, "
        "{} of them on a supply surface and {} by their host evidence; {} placed by a cloud "
        "administrative operation; {} placed as a posture question; {} placed off an "
        "administrative API class they never read; {} placed by an administrative API class "
        "listed after the first; {} placed by an endpoint class listed after the first; {} "
        "pattern(s) declaring a locus".format(set_aside, supply, host, operation, posture, unread,
                                              listed, host_listed, declared))


def test_the_reference_states_what_each_per_block_rule_placed():
    text = " ".join((BUNDLE / "references" / "locus-and-coverage.md").read_text(encoding="utf-8").split())
    found = re.search(r"(\d+) blocks placed without their record's surface, (\d+) of them on a "
                      r"supply surface and (\d+) by their host evidence; (\d+) placed by a cloud "
                      r"administrative operation; (\d+) placed as a posture question; (\d+) placed "
                      r"off an administrative API class they never read; (\d+) placed by an "
                      r"administrative API class listed after the first; (\d+) placed by an "
                      r"endpoint class listed after the first; (\d+) patterns declaring a locus",
                      text)
    assert found, "the reference no longer states what the per-block rules placed"
    bases = [(record, consult.locus_for(record, how, None, LOCUS_MAP)[2]) for record, how in BLOCKS]
    aside = [record for record, basis in bases if "set aside for this block" in basis]
    assert [int(v) for v in found.groups()] == [
        len(aside), sum(r["what"].get("attack_surface") in LOCUS_MAP["surface_supply"] for r in aside),
        sum(tier(basis) == "host_evidence" for _, basis in bases),
        sum(tier(basis) == "operation" for _, basis in bases),
        sum(tier(basis) == "posture" for _, basis in bases),
        sum(tier(basis) == "admin_api_unread" for _, basis in bases),
        sum(tier(basis) == "admin_api_listed" for _, basis in bases),
        sum(tier(basis) == "host_listed" for _, basis in bases),
        sum(bool(p.get("locus")) for p in PATTERNS.values())]
