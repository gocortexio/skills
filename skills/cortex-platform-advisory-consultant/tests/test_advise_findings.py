# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""What advise.py prints on each pattern, checked against the corpus it was printed from.

No test read an advise.py finding block, which is how each of these shipped:

- RESPONSE_DOCTRINE read `product_class`, a key no pattern has, so every block printed
  "0 matched" and the appliance and OT rules never fired.
- COUNTERMEASURES concatenated each technique's list and cut the head: six Isolate controls
  for LSASS dumping, every Evict and Detect control dropped, under a header naming techniques
  none of whose controls was shown. T1685, which ATT&CK 19.2 gave the revoked T1562.001's
  work, joined to nothing while D3FEND mapped the predecessor.
- OBSERVED counted how-blocks as records, printed four in file order with no record id and
  no word about the rest, and cut every title at 74 characters, restricted ones included.
- LOCUS printed its basis on the same line, so the one machine-parsed plane key was
  unparseable, and it never mentioned where a pattern's citing records actually sit.
- `--have T1486` turned every DATA_GAP into a confident MISSING list.

Most tests read one advise.py run over every pattern, so each property is held on all of
them and not on a hand-picked example.

Run with PYTHONDONTWRITEBYTECODE=1 (LAW A26).
"""
import collections
import json
import pathlib
import re
import subprocess
import sys

import pytest

BUNDLE = pathlib.Path(__file__).resolve().parents[1]
ADVISE = BUNDLE / "scripts" / "advise.py"
CONSULT = BUNDLE / "scripts" / "consult.py"
CORPUS = BUNDLE / "corpus"

sys.dont_write_bytecode = True
sys.path.insert(0, str(BUNDLE / "scripts"))
import advise as A  # noqa: E402
import consult as C  # noqa: E402

RECORDS, PATTERNS, _, CITING = A.load(str(CORPUS))
LOCUS_MAP = C.load_locus_map(str(CORPUS))
ORDER = LOCUS_MAP["locus_order"]
D3FEND = C.load_d3fend(str(CORPUS))
DOCTRINE = C.load_doctrine(str(CORPUS))
ATTACK = C.load_attack(str(CORPUS))
VOCAB = C.load_vocab(str(CORPUS))
LOCI = set(VOCAB["locus"])


def run(script, *argv):
    extra = ["--no-verify"] if script == ADVISE else []
    done = subprocess.run([sys.executable, str(script), *extra, *argv],
                          capture_output=True, text=True, timeout=600, cwd=str(BUNDLE))
    return done.returncode, done.stdout, done.stderr


def blocks_of(stdout):
    """{pattern id: [lines of its block]}, a block running to the next block or banner."""
    out, current = {}, None
    for line in stdout.splitlines():
        m = re.match(r"^--- PATTERN_ID: (\S+)$", line)
        if m:
            current = out.setdefault(m.group(1), [])
        elif line.startswith("#####"):
            current = None
        elif current is not None:
            current.append(line)
    return out


def value(block, key):
    for line in block:
        if line.startswith(key + ": "):
            return line[len(key) + 2:]
    return None


def section(block, key):
    """The key's line and the indented lines under it, to the next column-zero key."""
    lines, inside = [], False
    for line in block:
        if re.match(r"^[A-Z][A-Z0-9_]*:", line):
            if inside:
                break
            inside = line.startswith(key + ":")
        if inside:
            lines.append(line)
    return lines


@pytest.fixture(scope="module")
def every_pattern():
    code, out, _ = run(ADVISE, "--patterns", ",".join(sorted(PATTERNS)))
    assert code == 0, out[-400:]
    blocks = blocks_of(out)
    assert len(blocks) == len(PATTERNS)
    return out, blocks


# --- response doctrine ----------------------------------------------------------------------

def doctrine_ids(block):
    return re.findall(r"^   - (doc-[a-z0-9-]+) \|", "\n".join(section(block, "RESPONSE_DOCTRINE")),
                      re.M)


def test_class_keyed_doctrine_fires_on_an_appliance_pattern(every_pattern):
    block = every_pattern[1]["pat-edge-appliance-integrity-mismatch"]
    assert "doc-appliance-rebuild-not-factory-reset" in doctrine_ids(block)
    m = re.match(r"(\d+) shown of (\d+), (\d+) matched", value(block, "RESPONSE_DOCTRINE"))
    assert int(m.group(3)) >= 1


def test_ot_pattern_is_told_to_name_degraded_states(every_pattern):
    block = every_pattern[1]["pat-affiliate-model-detection-strategy"]
    assert "ot.hmi" in value(block, "CLASSES")
    assert "doc-emergency-plan-names-degraded-states" in doctrine_ids(block)


def test_advise_doctrine_equals_a_direct_call(every_pattern):
    """Pins both the class key and the impact source: applies_to_classes, and the impact of
    the distinct non-seed records citing the pattern."""
    for pid, block in every_pattern[1].items():
        impacts, counted, seed = A.citing_impacts(CITING[pid])
        expected = C.doctrine_for(PATTERNS[pid].get("applies_to_classes"), impacts, DOCTRINE,
                                  indent="   ", basis=A.doctrine_basis(counted, seed))
        assert [x for x in section(block, "RESPONSE_DOCTRINE") if x] == expected, pid


def test_doctrine_header_says_where_class_and_impact_came_from(every_pattern):
    for pid, block in every_pattern[1].items():
        header = value(block, "RESPONSE_DOCTRINE")
        assert "this pattern's applies_to_classes" in header, pid
        if not CITING[pid]:
            assert "no citing record, so impact is not assessed" in header, pid


def test_collect_and_contain_survive_truncation():
    lines = C.doctrine_for(["network.firewall", "ot.hmi", "security.email_gateway"],
                           ["ransomware_deployment", "data_exfiltration", "dos"], DOCTRINE)
    shown = re.findall(r"^  - (doc-[a-z0-9-]+) \|", "\n".join(lines), re.M)
    assert "doc-collect-before-mitigate" in shown
    assert "doc-containment-assumes-adversary-watching" in shown
    m = re.match(r"RESPONSE_DOCTRINE: (\d+) shown of (\d+)", lines[0])
    assert int(m.group(1)) == len(shown)
    not_shown = [x for x in lines if x.strip().startswith("NOT_SHOWN:")]
    cut = not_shown[0].split(":", 1)[1].strip().split(", ") if not_shown else []
    assert len(shown) + len(cut) == int(m.group(2))


def test_every_pattern_keeps_collect_and_contain_and_accounts_for_the_rest(every_pattern):
    for pid, block in every_pattern[1].items():
        ids = doctrine_ids(block)
        assert "doc-collect-before-mitigate" in ids and \
            "doc-containment-assumes-adversary-watching" in ids, pid
        shown, total = map(int, re.match(r"(\d+) shown of (\d+)",
                                         value(block, "RESPONSE_DOCTRINE")).groups())
        cut = [x for x in section(block, "RESPONSE_DOCTRINE") if x.strip().startswith("NOT_SHOWN:")]
        cut_ids = cut[0].split(":", 1)[1].strip().split(", ") if cut else []
        assert shown == len(ids) and shown + len(cut_ids) == total, pid


# --- countermeasures ------------------------------------------------------------------------

def countermeasure_rows(block):
    return re.findall(r"^   - (D3-[A-Z0-9-]+) \| ([A-Za-z-]+) \|",
                      "\n".join(section(block, "COUNTERMEASURES")), re.M)


def test_countermeasures_span_every_available_stage():
    code, out, _ = run(ADVISE, "--patterns", "pat-credential-dump-lsass-access")
    block = blocks_of(out)["pat-credential-dump-lsass-access"]
    tactics = {t for _, t in countermeasure_rows(block)}
    assert {"Isolate", "Evict", "Detect"} <= tactics


def test_countermeasures_print_in_declared_tactic_order_and_miss_no_early_stage(every_pattern):
    rank = {name: i for i, name in enumerate(D3FEND["tactic_order"])}
    for pid, block in every_pattern[1].items():
        rows = countermeasure_rows(block)
        indices = [rank.get(t, len(rank)) for _, t in rows]
        assert indices == sorted(indices), pid
        header = value(block, "COUNTERMEASURES")
        available = re.findall(r"([A-Za-z]+) (\d+)/(\d+)", header.split("), ordered")[0])
        # One per tactic per pass: every tactic up to the limit gets a control.
        for position, (name, shown, _) in enumerate(available):
            if position < 6:
                assert int(shown) >= 1, (pid, header)


def source_parts(header):
    """{part: [technique ids]} for the text after ", from " on a COUNTERMEASURES header. A
    revoked-predecessor label is parenthesised and names ids that are not cited; it is cut."""
    parts = re.sub(r" \([^)]*\)", "", header.split(", from ", 1)[1]).split("; ")
    out = {"from": re.findall(r"(?:^|, )(T[0-9.]+)", parts[0])}
    for part in parts[1:]:
        name, _, ids = part.partition(": ")
        out[name] = re.findall(r"(?:^|, )(T[0-9.]+)", ids)
    return out


def test_countermeasure_source_names_only_contributors(every_pattern):
    by_attack = D3FEND["by_attack"]
    for pid, block in every_pattern[1].items():
        header = value(block, "COUNTERMEASURES")
        if header.startswith("none") or header.startswith("UNASSESSED"):
            continue
        shown = {cid for cid, _ in countermeasure_rows(block)}
        for tid in source_parts(header)["from"]:
            assert set(by_attack.get(tid) or []) & shown, (pid, tid)


def test_countermeasure_header_names_every_cited_technique_once(every_pattern):
    """A technique D3FEND does not map, and one whose every control an earlier technique
    reached, vanished from the line: pat-network-device-cli-output-manipulation showed host
    controls for T1685 over a router firmware implant, with nothing saying T1601 has none."""
    by_attack = D3FEND["by_attack"]
    for pid, block in every_pattern[1].items():
        header = value(block, "COUNTERMEASURES")
        if not re.match(r"\d+ shown of", header):
            continue
        parts = source_parts(header)
        named = [t for ids in parts.values() for t in ids]
        cited = list(dict.fromkeys(t.upper() for t in PATTERNS[pid].get("technique") or []))
        assert sorted(named) == sorted(cited), (pid, header)
        unmapped = next((ids for name, ids in parts.items() if name.startswith("not mapped")), [])
        assert all(not by_attack.get(t) for t in unmapped), pid
        assert all(by_attack.get(t) for name, ids in parts.items()
                   if not name.startswith("not mapped") for t in ids), pid
    block = every_pattern[1]["pat-network-device-cli-output-manipulation"]
    assert "; not mapped by D3FEND 1.6.0: " in value(block, "COUNTERMEASURES")
    assert "T1601" in value(block, "COUNTERMEASURES").split("; not mapped by D3FEND 1.6.0: ")[1]


def graded_rows(block):
    return re.findall(r"^   - (D3-[A-Z0-9-]+) \| ([A-Za-z-]+) \| [^|]+ \| (\S+)$",
                      "\n".join(section(block, "COUNTERMEASURES")), re.M)


def test_a_direct_mapping_is_never_cut_for_an_inferred_one_in_its_tactic(every_pattern):
    """The lists hold D3FEND's direct mappings and the classes above and below them, and were
    taken in name order, so a superclass filled the visible slots: Access Mediation, whose
    definition is about buildings and border crossings, headed 21 of the 28 T1685 answers
    while System Daemon Monitoring, its direct Detect mapping, was cut. Over the 415
    patterns with a control, 389 showed an inferred control while a direct one in the same
    tactic was cut."""
    inferred = D3FEND["by_attack_inferred"]
    table = D3FEND["countermeasures"]
    checked = 0
    for pid, block in every_pattern[1].items():
        rows = graded_rows(block)
        if not rows:
            continue
        cited = [t.upper() for t in PATTERNS[pid].get("technique") or []]

        def best(cid):
            grades = [(inferred.get(t) or {}).get(cid, "direct") for t in cited
                      if cid in (D3FEND["by_attack"].get(t) or [])]
            return min(grades, key=C.D3FEND_GRADES.index)
        for cid, _, printed in rows:
            assert printed == ("direct" if best(cid) == "direct" else "inferred-" + best(cid)), \
                (pid, cid, printed)
        cut = [x for x in section(block, "COUNTERMEASURES") if x.strip().startswith("NOT_SHOWN:")]
        cut_ids = cut[0].split(":", 1)[1].strip().split(", ") if cut else []
        for cid, tactic, printed in rows:
            if printed != "direct":
                assert not [c for c in cut_ids if table[c]["tactic"] == tactic
                            and best(c) == "direct"], (pid, cid)
        checked += 1
    assert checked > 400


def test_access_mediation_no_longer_heads_the_t1685_answer():
    code, out, _ = run(ADVISE, "--attack", "T1685")
    assert code == 0
    blocks = blocks_of(out)
    assert len(blocks) >= 20
    for pid, block in blocks.items():
        rows = graded_rows(block)
        assert "D3-AMED" not in {cid for cid, _, _ in rows}, pid
        assert rows and rows[0][2] == "direct", (pid, rows)


def test_a_host_wide_control_is_never_shown_over_a_targeted_one_it_ties(every_pattern):
    """Within a tactic and grade the order was the name, so Host Reboot and Host Shutdown were
    the eviction advice on 17 and 8 of 29 findings, and Process Termination and Process
    Suspension, which D3FEND maps to the same techniques through the same relation, on none.
    The LSASS answer was to reboot or shut the host down, which loses the memory a responder
    collects first. A control the file lists as host-wide is now shown only when no control of
    its tactic and grade that more or as many of the finding's techniques reach was cut."""
    host_wide = set(D3FEND["host_wide"])
    inferred = D3FEND["by_attack_inferred"]
    table = D3FEND["countermeasures"]
    shown_host_wide = checked = 0
    for pid, block in every_pattern[1].items():
        rows = graded_rows(block)
        if not rows:
            continue
        cited = list(dict.fromkeys(t.upper() for t in PATTERNS[pid].get("technique") or []))

        def fit(cid):
            reached = [t for t in cited if cid in (D3FEND["by_attack"].get(t) or [])]
            best = min(((inferred.get(t) or {}).get(cid, "direct") for t in reached),
                       key=C.D3FEND_GRADES.index)
            return C.D3FEND_GRADES.index(best), -len(reached)
        cut = [x for x in section(block, "COUNTERMEASURES") if x.strip().startswith("NOT_SHOWN:")]
        cut_ids = cut[0].split(":", 1)[1].strip().split(", ") if cut else []
        for cid, tactic, _ in rows:
            if cid not in host_wide:
                continue
            shown_host_wide += 1
            assert not [c for c in cut_ids if c not in host_wide and table[c]["tactic"] == tactic
                        and fit(c) <= fit(cid)], (pid, cid, cut_ids)
        checked += 1
    assert checked > 400
    # No finding cites a technique reaching Host Reboot without Process Termination.
    assert shown_host_wide == 0


def test_lsass_eviction_advice_is_the_process_not_the_host():
    code, out, _ = run(ADVISE, "--attack", "T1003.001")
    assert code == 0
    block = blocks_of(out)["pat-credential-dump-lsass-access"]
    evict = [cid for cid, tactic, _ in graded_rows(block) if tactic == "Evict"]
    assert sorted(evict) == ["D3-PS", "D3-PT"], evict
    cut = [x for x in section(block, "COUNTERMEASURES") if x.strip().startswith("NOT_SHOWN:")][0]
    assert "D3-HR" in cut and "D3-HS" in cut


def test_a_control_more_of_the_finding_reaches_is_taken_first():
    """Within a tactic and grade, a control two cited techniques reach outranks one only the
    first reaches, whatever the first technique's list order says."""
    table = {cid: {"tactic": "Evict", "name": cid} for cid in ("D3-A", "D3-B", "D3-C")}
    d3fend = {"countermeasures": table, "tactic_order": ["Evict"], "host_wide": {"D3-A": "x"},
              "by_attack": {"T0001": ["D3-A", "D3-B", "D3-C"], "T0002": ["D3-C"]},
              "by_attack_inferred": {}}
    chosen = C.select_countermeasures({"technique": ["T0001", "T0002"]}, None, d3fend,
                                      limit=3).chosen
    assert chosen == ["D3-C", "D3-B", "D3-A"]
    d3fend["host_wide"] = {}
    assert C.select_countermeasures({"technique": ["T0001", "T0002"]}, None, d3fend,
                                    limit=3).chosen == ["D3-C", "D3-A", "D3-B"]


def test_a_partial_date_is_read_at_its_precision_not_as_undated():
    """Only a full ISO date parsed, so ten records dated to the year or the month printed
    "undated" and age_days() ranked them as 3,650 days old, while query.py read them."""
    partial = [r for r in RECORDS if re.match(r"^\d{4}(-\d{2})?$",
                                              str((r.get("when") or {}).get("published") or ""))]
    assert len(partial) >= 10
    for r in partial:
        assert C.published(r) is not None, r["id"]
        assert C.published_text(r) == r["when"]["published"], r["id"]
        assert C.age_days(r, C.published(r)) == 0
    code, out, _ = run(ADVISE, "--attack", "T1003")
    assert code == 0
    assert "obs-generic-remaining-gap-conditions-from-restricted-library | 2026-08 |" in out


def test_an_unstated_rule_shape_says_what_its_citing_blocks_state(every_pattern):
    """RULE_SHAPE printed "unstated" where every block citing the pattern states one: seven of
    seven say inventory for the logging-retention audit."""
    said = 0
    for pid, block in every_pattern[1].items():
        shape = value(block, "RULE_SHAPE")
        pattern = PATTERNS[pid]
        if pattern.get("rule_shape"):
            assert shape == pattern["rule_shape"], pid
            continue
        stated = collections.Counter(h.get("rule_shape") for _, h in CITING[pid]
                                     if h.get("rule_shape"))
        if not stated:
            assert shape == "unstated", pid
            continue
        said += 1
        assert shape == "unstated (its citing how-blocks state {} of {})".format(
            ", ".join("{} {}".format(s, n) for s, n in stated.most_common()),
            len(CITING[pid])), (pid, shape)
    assert said >= 5


def test_revoked_bridge_states_what_d3fend_maps_not_a_wrong_date(every_pattern):
    """ATT&CK 19.1 already carried T1685; 19.2 revoked nothing. The label said D3FEND
    1.6.0 "predates ATT&CK 19.2", which was never the reason."""
    header = value(every_pattern[1]["pat-audit-policy-tampering"], "COUNTERMEASURES")
    assert "maps the revoked id, not its replacement" in header
    assert "predates" not in "\n".join(every_pattern[0].splitlines())


def test_countermeasures_account_for_every_mapped_id(every_pattern):
    for pid, block in every_pattern[1].items():
        header = value(block, "COUNTERMEASURES")
        m = re.match(r"(\d+) shown of (\d+)", header)
        if not m:
            continue
        rows = countermeasure_rows(block)
        cut = [x for x in section(block, "COUNTERMEASURES") if x.strip().startswith("NOT_SHOWN:")]
        cut_ids = cut[0].split(":", 1)[1].strip().split(", ") if cut else []
        assert int(m.group(1)) == len(rows), pid
        assert len(rows) + len(cut_ids) == int(m.group(2)), pid
        assert not ({c for c, _ in rows} & set(cut_ids)), pid


def test_migrated_technique_keeps_its_countermeasures(every_pattern):
    header = value(every_pattern[1]["pat-audit-policy-tampering"], "COUNTERMEASURES")
    assert not header.startswith("none"), header
    assert "via revoked" in header


def test_no_d3fend_gap_claim_that_a_predecessor_fills(every_pattern):
    predecessors = collections.defaultdict(set)
    for tid, entry in ATTACK.items():
        if entry.get("revoked") and entry.get("replaced_by"):
            predecessors[entry["replaced_by"]].add(tid)
    for pid, block in every_pattern[1].items():
        if "gap in D3FEND coverage" not in (value(block, "COUNTERMEASURES") or ""):
            continue
        for tid in PATTERNS[pid].get("technique") or []:
            filled = [old for old in predecessors[tid.upper()] if old in D3FEND["by_attack"]]
            assert not filled, (pid, tid, filled)


# --- OBSERVED -------------------------------------------------------------------------------

def record_lines(block):
    return [line for line in section(block, "OBSERVED")[1:] if line.startswith("   [")]


def test_observed_counts_distinct_records():
    _, out, _ = run(ADVISE, "--patterns", "pat-kernel-performs-the-change-so-no-process-owns-it")
    block = blocks_of(out)["pat-kernel-performs-the-change-so-no-process-owns-it"]
    assert value(block, "OBSERVED") == "yes, 1 record(s), 3 how-block(s)"
    assert len(record_lines(block)) == 1


def test_observed_counts_match_the_corpus_on_every_pattern(every_pattern):
    for pid, block in every_pattern[1].items():
        cited = CITING[pid]
        if not cited:
            # An uncited pattern says where it came from: its caveat can point at reports the
            # answer otherwise never names.
            assert value(block, "OBSERVED") == "no citing record in the corpus; derived from " \
                + "; ".join(C.library_origins(PATTERNS[pid])), pid
            continue
        distinct = {r["id"] for r, _ in cited}
        # A seed-only pattern read "yes, 1 record(s)" as though observed, while its
        # RESPONSE_DOCTRINE called the same record unassessable. The seed clause counts the
        # citing blocks by which seed meaning applies, as consult.py's STATUS line decides it.
        seeds = {r["id"] for r, _ in cited if (r.get("status") or "").lower() == "seed"}
        parts = collections.Counter(C.seed_support(r, r["how"].index(how)) for r, how in cited
                                    if r["id"] in seeds)
        assert value(block, "OBSERVED") == "yes, {} record(s), {} how-block(s){}".format(
            len(distinct), len(cited),
            "; {} of the records seed: {} citing how-block(s) unconfirmed, {} supported by a "
            "re-read source".format(len(seeds), parts["unread"] + parts["unconfirmed"],
                                    parts["supported"]) if seeds else ""), pid
        doctrine = value(block, "RESPONSE_DOCTRINE")
        if seeds and len(seeds) < len(distinct):
            assert "(and not of its {} seed record(s))".format(len(seeds)) in doctrine, pid


def test_observed_says_which_seed_blocks_a_re_read_source_supports():
    """The Fortinet family record was re-read and supports the block citing this pattern, and
    OBSERVED called it "1 of the records seed, unconfirmed" all the same."""
    _, out, _ = run(ADVISE, "--attack", "T1190")
    block = blocks_of(out)["pat-management-channel-usable-before-authentication-completes"]
    assert value(block, "OBSERVED").endswith(
        "1 of the records seed: 0 citing how-block(s) unconfirmed, 1 supported by a re-read "
        "source"), value(block, "OBSERVED")


def test_every_citing_record_is_accounted_for(every_pattern):
    for pid, block in every_pattern[1].items():
        lines = section(block, "OBSERVED")
        named = [re.match(r"^   \[[A-Z?]+\] (obs-\S+) \|", x).group(1) for x in record_lines(block)]
        more = [x for x in lines if x.startswith("   ... ")]
        if more:
            m = re.match(r"^   \.\.\. (\d+) more record\(s\) not shown: (.*)$", more[0])
            rest = m.group(2).split(", ")
            assert int(m.group(1)) == len(rest)
            named += rest
        assert len(record_lines(block)) <= A.OBSERVED_LINES
        assert sorted(named) == sorted({r["id"] for r, _ in CITING[pid]}), pid


def test_record_lines_carry_record_ids_and_run_newest_first(every_pattern):
    for pid, block in every_pattern[1].items():
        dates = []
        for line in record_lines(block):
            # A date held to the month or the year prints at that precision (0.43.0 R4).
            m = re.match(r"^   \[[A-Z?]+\] obs-\S+ \| (\d{4}(?:-\d{2}){0,2}|undated) \| LOCUS "
                         r"\S+ \| ", line)
            assert m, (pid, line)
            dates.append(m.group(1))
        # Ordered as the parsed date: a partial date reads as the first day it names.
        dated = [(d + "-01-01")[:10] if len(d) == 4 else (d + "-01")[:10] if len(d) == 7 else d
                 for d in dates if d != "undated"]
        assert dated == sorted(dated, reverse=True), pid
        assert all(d != "undated" for d in dates[:len(dated)]), \
            "undated records sort last: {}".format(pid)


def restricted_citations():
    out = []
    for pid, cited in sorted(CITING.items()):
        for record, _ in cited:
            if record["where"].get("disclosure") != "public":
                out.append((pid, record["where"]["title"]))
    return sorted(set(out))


@pytest.mark.parametrize("pid,title", restricted_citations())
def test_restricted_title_is_cited_whole(every_pattern, pid, title):
    """The line says to cite the title as given; it was cut at 74 characters."""
    newest = sorted({r["id"]: r for r, _ in CITING[pid]}.values(),
                    key=lambda r: (-(C.published(r) or A.datetime.date.min).toordinal(), r["id"]))
    if not any(r["where"]["title"] == title for r in newest[:A.OBSERVED_LINES]):
        pytest.skip("the record is listed by id past the line cap")
    text = "\n".join(every_pattern[1][pid])
    assert "| {} | RESTRICTED - cite the title as given".format(title) in text


def test_at_least_the_three_known_restricted_titles_are_checked():
    pids = {pid for pid, _ in restricted_citations()}
    assert {"pat-process-ancestry-does-not-match-reality", "pat-container-escape-to-host",
            "pat-mailbox-delegation-or-role-granted"} <= pids


# --- LOCUS ----------------------------------------------------------------------------------

def keys_of(block):
    return frozenset(m.group(1) for m in (re.match(r"^([A-Z][A-Z0-9_]*):", x) for x in block) if m)


def test_advise_locus_keys_match_the_consult_contract(every_pattern):
    keysets = {pid: keys_of(block) for pid, block in every_pattern[1].items()}
    assert len(set(keysets.values())) == 1, "key set varies between patterns"
    assert {"LOCUS", "LOCUS_SPAN", "LOCUS_BASIS", "LOCUS_OBSERVED", "FIDELITY",
            "RULE_SHAPE"} <= next(iter(keysets.values()))
    for pid, block in every_pattern[1].items():
        locus = value(block, "LOCUS")
        assert locus in LOCI, (pid, locus)
        span = value(block, "LOCUS_SPAN").split(", ")
        assert span[0] == locus and 1 <= len(span) <= 2 and set(span) <= LOCI, pid
        assert value(block, "LOCUS_BASIS").startswith("tier="), pid


def test_advise_locus_is_the_pattern_derivation(every_pattern):
    """The primary stays where the pattern applies, whatever its records say: its class list,
    what its own markers, shape and evidence say where a block's would decide, or the locus
    the pattern declares, with its reason. Until the 2026-10-01 third validation only the
    class list was read, and a pattern testing only a tenant role grant derived DATA."""
    declared, own = 0, 0
    for pid, block in every_pattern[1].items():
        assert value(block, "LOCUS") == C.locus_for(None, None, PATTERNS[pid], LOCUS_MAP)[0], pid
        basis = value(block, "LOCUS_BASIS")
        if PATTERNS[pid].get("locus"):
            declared += 1
            assert basis.startswith(
                "tier=declared; input=locus declared on the pattern, {};".format(
                    PATTERNS[pid]["locus_reason"])), pid
        elif re.match(r"tier=(host_evidence|operation|posture|admin_api_unread|admin_api_listed|"
                      r"host_listed);", basis):
            own += 1
            # The two *_listed tiers read a record's class list, never a pattern's.
            assert not re.match(r"tier=(admin_api_listed|host_listed);", basis), (pid, basis)
            assert re.match(r"tier=[a-z_]+; input=(pattern |applies_to_classes first-listed=)",
                            basis), (pid, basis)
        else:
            assert "input=applies_to_classes" in basis, pid
    assert declared, "no declared pattern locus reached; the branch is untested"
    assert own, "no pattern placed by its own markers, shape or evidence; the branch is untested"


def test_observed_plane_is_not_hidden(every_pattern):
    block = every_pattern[1]["pat-audit-policy-tampering"]
    assert value(block, "LOCUS") == "ENDPOINT"
    assert value(block, "LOCUS_SPAN") == "ENDPOINT, MANAGEMENT"
    assert "MANAGEMENT=1" in value(block, "LOCUS_OBSERVED")
    assert "span-source=observed span" in value(block, "LOCUS_BASIS")


def test_locus_observed_matches_consult_derivation(every_pattern):
    for pid, block in every_pattern[1].items():
        observed = value(block, "LOCUS_OBSERVED")
        cited = CITING[pid]
        if not cited:
            assert observed == "none - no citing record", pid
            continue
        counts = collections.Counter(C.locus_for(r, h, PATTERNS[pid], LOCUS_MAP)[0]
                                     for r, h in cited)
        printed = dict((k, int(v)) for k, v in re.findall(r"([A-Z]+)=(\d+)", observed.split(" (")[0]))
        assert printed == dict(counts), pid
        assert sum(printed.values()) == len(cited), pid
        span = value(block, "LOCUS_SPAN").split(", ")
        primary = span[0]
        if len(counts) == 1 and next(iter(counts)) != primary:
            assert span == [primary, next(iter(counts))], pid


def test_locus_returned_sums_to_findings():
    _, out, _ = run(ADVISE, "--attack", "T1190")
    m = re.search(r"^LOCUS_RETURNED: (.*?)  \(", out, re.M)
    counts = {k: int(v) for k, v in re.findall(r"([A-Z]+)=(\d+)", m.group(1))}
    assert list(counts) == ORDER
    findings = int(re.search(r"^FINDINGS: (\d+)", out, re.M).group(1))
    assert sum(counts.values()) == findings
    printed = collections.Counter(value(b, "LOCUS") for b in blocks_of(out).values())
    assert {k: v for k, v in counts.items() if v} == dict(printed)
    absent = re.search(r"^LOCUS_ABSENT: (.*)$", out, re.M).group(1)
    for locus in ORDER:
        assert (locus in absent.split(" - ")[0]) == (counts[locus] == 0)


def test_uncited_pattern_says_none(every_pattern):
    uncited = sorted(pid for pid in PATTERNS if not CITING[pid])
    assert uncited
    for pid in uncited:
        assert value(every_pattern[1][pid], "LOCUS_OBSERVED") == "none - no citing record"


def test_fidelity_and_rule_shape_are_separate_lines(every_pattern):
    for pid, block in every_pattern[1].items():
        assert "RULE_SHAPE" not in value(block, "FIDELITY"), pid
        assert "LOCUS_BASIS" not in value(block, "LOCUS"), pid


# --- --have ---------------------------------------------------------------------------------

MISSING_LINE = re.compile(r"^\s*(- )?MISSING[: ]", re.M)


@pytest.mark.parametrize("script,argv", [
    pytest.param(ADVISE, ["--patterns", "pat-webserver-spawns-shell"], id="advise"),
    pytest.param(CONSULT, ["Apache Tomcat", "--limit", "3"], id="consult"),
])
def test_have_rejects_a_technique_id(script, argv):
    code, out, err = run(script, *argv, "--have", "T1486")
    assert not MISSING_LINE.search(out), out
    assert "DATA_GAP: UNASSESSED" in out
    assert "DECLARED_TELEMETRY_REJECTED: T1486 (an ATT&CK id - use " in out
    assert "T1486" in err


def test_have_is_normalised():
    _, out, _ = run(ADVISE, "--patterns", "pat-webserver-spawns-shell", "--have",
                    "WEB_SERVER, edr-process")
    assert "DATA_GAP: 0" in out
    assert "DECLARED_TELEMETRY: edr_process, web_server" in out
    assert "DECLARED_TELEMETRY_REJECTED: none" in out


def test_every_vocab_evidence_type_is_accepted():
    _, out, _ = run(ADVISE, "--attack", "T1190", "--have", ",".join(sorted(VOCAB["evidence_type"])))
    assert "DECLARED_TELEMETRY_REJECTED: none" in out
    gaps = re.findall(r"^DATA_GAP: (.*)$", out, re.M)
    assert gaps and set(gaps) == {"0"}


@pytest.mark.parametrize("script,argv", [
    pytest.param(ADVISE, ["--patterns", "pat-webserver-spawns-shell"], id="advise"),
    pytest.param(CONSULT, ["Apache Tomcat", "--limit", "3"], id="consult"),
])
@pytest.mark.parametrize("have", ["", ","])
def test_empty_have_is_unassessed_in_both_scripts(script, argv, have):
    _, out, _ = run(script, *argv, "--have", have)
    assert "DATA_GAP: UNASSESSED - caller declared no inventory" in out
    assert "DECLARED_TELEMETRY: NONE DECLARED - all DATA_GAP fields unassessed" in out
    assert not MISSING_LINE.search(out)


def test_parse_have_refuses_by_name():
    have, rejected = C.parse_have("syslog, T1486, dns netflow, licel_alice_raw", VOCAB, "--attack")
    assert have == {"syslog"}
    reasons = dict(rejected)
    assert reasons["T1486"] == "an ATT&CK id - use --attack"
    assert "separate values with commas" in reasons["dns netflow"]
    assert "evidence types in corpus/schema/vocab.json" in reasons["licel_alice_raw"]
    assert C.parse_have(None, VOCAB) == (None, [])
    assert C.parse_have(" , ", VOCAB) == (None, [])
    assert C.parse_have("T1486", VOCAB)[0] is None


def test_evidence_vocabulary_and_the_connector_table_agree():
    """parse_have accepts vocab.json's list and DATA_GAP names a connector for each."""
    assert set(VOCAB["evidence_type"]) == set(C.CONNECTOR)


def test_reference_version_is_read_from_the_file():
    reference = json.loads((CORPUS / "reference" / "attack-techniques.json").read_text(encoding="utf-8"))
    _, out, _ = run(ADVISE, "--attack", "T9999")
    assert "shipped ATT&CK {} reference".format(reference["version"]) in out


def test_advise_have_refusal_names_where_coverage_is_declared():
    """advise.py refused an ATT&CK id in --have with "use --attack", which selects every pattern
    citing the id: the opposite of declaring it covered, which only consult.py --covered does."""
    code, out, _ = run(ADVISE, "ransomware pre-encryption activity", "--have", "T1486")
    assert code == 0
    assert "DECLARED_TELEMETRY_REJECTED: T1486 (an ATT&CK id - use --attack to select by it, " \
           "or consult.py --covered to declare it covered)" in out


def test_an_unmapped_parent_names_the_sub_techniques_d3fend_maps(every_pattern):
    """pat-edge-appliance-unexplained-reboot printed a gap in D3FEND for T1542 while D3FEND maps
    T1542.001 to .005, ROMMONkit and TFTP Boot among them: the boot persistence the pattern is
    about. 24 patterns printed the gap over a mapped child."""
    index = D3FEND["by_attack"]
    named = 0
    for pid, block in every_pattern[1].items():
        header = value(block, "COUNTERMEASURES") or ""
        for tid in {t.upper() for t in PATTERNS[pid].get("technique") or []}:
            if index.get(tid) or "." in tid:
                continue
            subs = sorted(t for t in index if t.startswith(tid + ".") and index[t])
            if subs:
                named += 1
                assert "{} ({})".format(tid, ", ".join(subs)) in header \
                    or "{} (its sub-techniques {} are mapped".format(tid, ", ".join(subs)) \
                    in header, (pid, tid, header)
    assert named >= 10
    block = every_pattern[1]["pat-edge-appliance-unexplained-reboot"]
    assert "T1542.004" in value(block, "COUNTERMEASURES")
