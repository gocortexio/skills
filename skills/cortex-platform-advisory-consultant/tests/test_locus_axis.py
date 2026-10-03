# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The spread must be what the header says it is, and the key set must not move.

Two invariants, and they fail in opposite directions.

The first is the house one: a printed count describes what was emitted. LOCUS_MATCHED,
LOCUS_ELIGIBLE, LOCUS_SHOWN, LOCUS_DISPLACED, LOCUS_RESERVED and RECORD_CAP are counts over
the same set, and a quota that silently dropped a finding it never accounted for would leave
every one of them looking authoritative. So the displacement is checked by differencing the
spread run against --no-locus-spread, rather than by trusting the number, and every count
an absent locus's bullet states is recounted from the whole match set.

The second is new to this bundle. consult.py's contract says the key set does not vary
between findings even when a field is empty, because an absent key would have to be
distinguished from an empty one. Nothing tested it. RESPONSE_DOCTRINE was conditional in
code and only ever non-empty by accident of six always-on doctrine rules; it is now
unconditional, and this file is what stops the next block going the same way.

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
SCRIPTS = BUNDLE / "scripts"
SCHEMA = BUNDLE / "corpus" / "schema"

sys.dont_write_bytecode = True
sys.path.insert(0, str(SCRIPTS))
import consult as C  # noqa: E402
import query  # noqa: E402

ROLES = {r["id"]: (r.get("what") or {}).get("role")
         for r in query.load_corpus(str(BUNDLE / "corpus"))[0]}

# Fixed so ranking is reproducible: recency is an input to the score, and the score is
# what the quota reserves against.
TODAY = "2026-08-08"

# Cisco ASA populates most of the six loci and leaves at least one absent, which exercises
# every branch: displacement, reservation, an absent locus and underservice. No count is
# written here, because the one that was (115 findings) had gone stale unseen; the tests
# below assert the shape instead.
# The other two are a broad endpoint question and an OT one, so the key-set assertion is
# not made against a single product class.
QUESTIONS = ["I have a Cisco ASA", "Microsoft Windows", "SCADA"]

LOCI = sorted(json.loads((SCHEMA / "vocab.json").read_text(encoding="utf-8"))["locus"])


def run(*argv):
    done = subprocess.run(
        [sys.executable, str(SCRIPTS / "consult.py"), *argv],
        capture_output=True, text=True, timeout=180)
    return done.returncode, done.stdout, done.stderr


def consult(question, *extra, today=TODAY):
    code, out, err = run(question, "--today", today, *extra)
    assert code == 0, "consult.py exited {}: {}".format(code, err)
    return out


# The quota's own fixtures are read at one later date, after the locus ladder, the tiers and
# the resolver changes of 0.43.0 had all landed, because each of those moved them: "I have a
# Cisco ASA" lost the ORGANISATION filler it used to reserve, and FortiGate's rank 78 is gone.
LATER = "2026-09-25"


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


def reserve_basis(stdout):
    """The per-locus counts a reserved slot is filled from: LOCUS_SUBJECT where the question
    named a product or vendor and a finding names it, LOCUS_ELIGIBLE otherwise. Until the
    2026-09-30 validation it was always LOCUS_ELIGIBLE, and a class analogue filled the
    reserve of a plane nothing naming the product sat on."""
    line = [l for l in stdout.splitlines() if l.startswith("LOCUS_SUBJECT:")][0]
    if "what a reserved slot is filled from)" in line:
        return dist(stdout, "LOCUS_SUBJECT")
    return dist(stdout, "LOCUS_ELIGIBLE")


def shown_loci(stdout):
    return [l.split(":", 1)[1].strip() for l in stdout.splitlines()
            if l.startswith("LOCUS: ")]


def identities(stdout):
    """FINDING_KEY for each finding, in printed order.

    This was (RECORD_ID, PATTERN_ID), and that pair is not unique: one record can cite one
    pattern from two blocks. The displacement test below then counted a displaced block as
    still shown because its sibling was, and passed only because none of its three
    questions happened to displace one. 'Microsoft SharePoint' does.
    """
    keys = [l.split(":", 1)[1].strip() for l in stdout.splitlines() if l.startswith("FINDING_KEY: ")]
    assert len(keys) == stdout.count("=== FINDING "), "a finding printed no FINDING_KEY"
    return keys


def bullet_key(line):
    """The FINDING_KEY a LOCUS_DISPLACED or LOCUS_RESERVED bullet names."""
    found = re.search(r"(\S+#how\d+) / ", line)
    assert found, "bullet names no FINDING_KEY: {}".format(line)
    return found.group(1)


def stated(stdout, key):
    """The count of bullets a LOCUS_DISPLACED, LOCUS_RESERVED or RECORD_CAP line states."""
    line = [l for l in stdout.splitlines() if l.startswith(key + ":")][0]
    if key == "RECORD_CAP":
        listed = re.search(r": (\d+) listed below", line)
        if listed is None:
            assert "; 0 finding(s) passed over in the top " in line, line
            return 0
        return int(listed.group(1))
    return int(line.split(":")[1].strip().split()[0])


def capped_total(stdout):
    """What RECORD_CAP says the cap cost in all: its own bullets, and the LOCUS_DISPLACED
    bullets it chose. Counting its own bullets alone, the line told "Check Point firewall"
    that nothing was passed over while LOCUS_DISPLACED named a block the cap had chosen."""
    line = [l for l in stdout.splitlines() if l.startswith("RECORD_CAP:")][0]
    total = re.search(r"; (\d+) finding\(s\)(?: from \d+ record\(s\))? passed over", line)
    assert total, line
    under = re.search(r", and (\d+) listed under LOCUS_DISPLACED", line)
    chose = [l for l in bullets(stdout, "LOCUS_DISPLACED") if "; RECORD_CAP chose it" in l]
    assert int(under.group(1) if under else 0) == len(chose), line
    assert int(total.group(1)) == stated(stdout, "RECORD_CAP") + len(chose), line
    return int(total.group(1))


def absent_loci(stdout):
    line = [l for l in stdout.splitlines() if l.startswith("LOCUS_ABSENT:")][0]
    body = line.split(":", 1)[1].split(" - ")[0].strip()
    return [] if body.startswith("none") else [x.strip() for x in body.split(",")]


def blocks(stdout):
    """Each finding block as {KEY: value}, column-zero keys only."""
    out, current = [], None
    for line in stdout.splitlines():
        if line.startswith("=== FINDING "):
            current = {}
        elif line.startswith("=== END FINDING "):
            out.append(current)
            current = None
        elif current is not None:
            found = re.match(r"^([A-Z][A-Z0-9_]*): ?(.*)$", line)
            if found and found.group(1) not in current:
                current[found.group(1)] = found.group(2)
    return out


def bullets(stdout, key):
    """The indented body lines that follow a LOCUS_DISPLACED / LOCUS_RESERVED / RECORD_CAP /
    LOCUS_ABSENT header."""
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
        totals.add((tuple(sorted(dist(out, "LOCUS_MATCHED").items())),
                    tuple(sorted(dist(out, "LOCUS_ELIGIBLE").items()))))
        stated = re.search(r"FINDINGS: \d+ shown of (\d+) matched", out)
        assert stated, "FINDINGS line missing"
        assert sum(dist(out, "LOCUS_MATCHED").values()) == int(stated.group(1))
    assert len(totals) == 1, "LOCUS_MATCHED moved when --limit changed"


@pytest.mark.parametrize("question", QUESTIONS)
def test_locus_absent_names_every_locus_with_no_eligible_finding(question):
    """Reads the vocabulary rather than hard-coding six, so a seventh cannot pass.

    Absent means no ELIGIBLE finding, not no match: a locus reached only by prose, or only
    below the floor, was reported represented and then guaranteed a reserved slot.
    """
    out = consult(question, "--limit", "12")
    matched, eligible = dist(out, "LOCUS_MATCHED"), dist(out, "LOCUS_ELIGIBLE")
    assert set(absent_loci(out)) == {l for l in LOCI if not eligible.get(l, 0)}
    assert set(matched) == set(LOCI), "LOCUS_MATCHED must list every locus, zeros included"
    assert set(eligible) == set(LOCI), "LOCUS_ELIGIBLE must list every locus, zeros included"
    for locus in LOCI:
        assert eligible[locus] <= matched[locus]
    # One bullet per absent locus, in the order the line names them.
    named = [b.split(":")[0].strip("- ") for b in bullets(out, "LOCUS_ABSENT")]
    assert named == absent_loci(out)


@pytest.mark.parametrize("question", QUESTIONS)
def test_displacement_count_matches_the_diff_against_no_spread(question):
    """The one that catches a quota dropping a finding it never accounted for."""
    limit = 12
    spread = consult(question, "--limit", str(limit))
    pure = consult(question, "--limit", str(limit), "--no-locus-spread")

    lost = [x for x in identities(pure) if x not in identities(spread)]
    # Two things take a slot from the natural top N, and each names what it took: a reserved
    # slot (LOCUS_DISPLACED) and the record cap (RECORD_CAP).
    reported = bullets(spread, "LOCUS_DISPLACED") + bullets(spread, "RECORD_CAP")
    assert len(lost) == len(reported), \
        "{} finding(s) vanished against pure order, {} reported".format(len(lost), len(reported))
    assert sorted(lost) == sorted(bullet_key(line) for line in reported), \
        "the findings named are not the ones that vanished"

    # Every slot taken from below the cut costs exactly one above it.
    assert len(bullets(spread, "LOCUS_RESERVED")) == len(bullets(spread, "LOCUS_DISPLACED"))
    for key in ("LOCUS_DISPLACED", "LOCUS_RESERVED", "RECORD_CAP"):
        assert stated(spread, key) == len(bullets(spread, key))
    capped_total(spread)


@pytest.mark.parametrize("limit", [12, 500])
@pytest.mark.parametrize("question", QUESTIONS + ["Microsoft SharePoint"])
def test_every_finding_key_is_unique_and_bullets_resolve(question, limit):
    """FINDING_KEY is the finding's identity, so it has to be one, and the header has to use it.

    SharePoint is here because its top twelve displace two blocks of one record that cite
    the same pattern: keyed on (RECORD_ID, PATTERN_ID), three findings were lost against
    pure order while LOCUS_DISPLACED reported four, and the bullets were right.
    """
    spread = consult(question, "--limit", str(limit))
    pure = consult(question, "--limit", str(limit), "--no-locus-spread")
    everything = consult(question, "--limit", "500", "--no-locus-spread")

    for out in (spread, pure, everything):
        keys = identities(out)
        assert len(keys) == len(set(keys)), "a FINDING_KEY repeats"
    rec = [l.split(":", 1)[1].strip() for l in spread.splitlines() if l.startswith("RECORD_ID: ")]
    for record_id, key in zip(rec, identities(spread)):
        assert key.startswith(record_id + "#how"), "{} does not belong to {}".format(key, record_id)

    displaced = [bullet_key(l) for l in bullets(spread, "LOCUS_DISPLACED")]
    capped = [bullet_key(l) for l in bullets(spread, "RECORD_CAP")]
    reserved = [bullet_key(l) for l in bullets(spread, "LOCUS_RESERVED")]
    # A displaced or capped finding sits in the pure top N and is missing from the spread
    # one; a reserved one is shown, and exists somewhere in the whole match set.
    assert set(displaced + capped) <= set(identities(pure))
    assert not set(displaced + capped) & set(identities(spread))
    assert not set(displaced) & set(capped)
    assert set(reserved) <= set(identities(spread))
    assert set(reserved) <= set(identities(everything))
    lost = [k for k in identities(pure) if k not in identities(spread)]
    assert sorted(lost) == sorted(displaced + capped)


def test_a_finding_key_asks_emit_xql_for_that_block():
    """The key a consultation prints is the handle emit_xql.py takes back, block for block."""
    out = consult("Microsoft SharePoint", "--limit", "500", "--no-locus-spread")
    keys = [k for k in identities(out) if k.startswith("obs-sangoma-switchvox-pa-sql-injection-exploited#")]
    assert len(keys) >= 2, "fixture record no longer reached"
    for key in keys:
        done = subprocess.run([sys.executable, str(SCRIPTS / "emit_xql.py"), key, "--json"],
                              capture_output=True, text=True, timeout=180)
        assert done.returncode == 0, done.stderr
        handed = json.loads(done.stdout)
        skipped = int(re.search(r"(\d+) skipped", done.stderr).group(1))
        assert len(handed) + skipped == 1, "a key must select exactly one block"
        for block in handed:
            assert block["finding_key"] == key
            assert "{}#how{}".format(block["record_id"], block["how_index"]) == key


def ordering_keys(stdout):
    """The ORDERING key of each printed finding, read back from its PRIORITY_BASIS.

    Group first, then a sector the question named, then the question's leftover words the
    record carries, then the platform fit, then the score. Descending score over the whole list
    stopped being the order in 0.43.0, when records naming the product began to lead regardless
    of age, and the fit joined the key when "Linux kernel" was found leading with Windows blocks.
    """
    keys = []
    for basis in re.findall(r"^PRIORITY_BASIS: (.*)$", stdout, re.M):
        score = float(re.search(r"score=([0-9.]+)/", basis).group(1))
        group = int(re.search(r"\(group (\d+)", basis).group(1))
        sector = re.search(r"; sector=([^;]+);", basis).group(1)
        fit = int(re.search(r"; platform_fit=([+-]?\d+) \(", basis).group(1))
        refined = re.search(r"; refined_by=(\S+)$", basis).group(1)
        # Inside group 0, another product of a named product's vendor follows (0.44.0).
        after = ", after what was asked)" in basis
        keys.append((group, after, sector == "-",
                     -(0 if refined == "-" else len(refined.split(","))), -fit, -score))
    return keys


@pytest.mark.parametrize("question", QUESTIONS)
def test_no_locus_spread_restores_pure_criticality_order(question):
    out = consult(question, "--limit", "12", "--no-locus-spread")
    keys = ordering_keys(out)
    assert keys and keys == sorted(keys), "pure order does not follow the stated ORDERING"
    assert bullets(out, "LOCUS_DISPLACED") == []
    assert out.count("LOCUS_UNDERSERVED:") == 0
    # Pure means the record cap is off too, and the positional index is the rank.
    assert "RECORD_CAP: off" in out
    found = blocks(out)
    assert [b["RANK"] for b in found] == [str(i) for i in range(1, len(found) + 1)]
    assert {b["SLOT"] for b in found} == {"natural"}
    # The distribution is still reported, which is the point of the flag.
    assert dist(out, "LOCUS_MATCHED") and dist(out, "LOCUS_SHOWN")


@pytest.mark.parametrize("question,limit", [("Fortinet FortiGate", 1), ("network firewall", 3)])
def test_underserved_appears_only_when_the_limit_is_below_the_eligible_count(question, limit):
    """Rebuilt over LOCUS_ELIGIBLE once the loci and tiers of 0.43.0 had landed: a locus
    holding only loose or sub-floor findings is owed no slot, so it cannot be underserved. And
    over reserve_basis() once the reserve was narrowed to findings naming what was asked:
    FortiGate's two such loci are what a limit of 1 underserves, not the ones holding
    analogues. The ASA held two until the 2026-10-01 fourth validation; its second, MANAGEMENT,
    was the management centre's, which names Cisco and not the ASA."""
    tight = consult(question, "--limit", str(limit), today=LATER)
    basis = reserve_basis(tight)
    populated = sum(1 for v in basis.values() if v)
    assert populated > limit, "fixture no longer exercises underservice"
    line = [l for l in tight.splitlines() if l.startswith("LOCUS_UNDERSERVED:")]
    assert len(line) == 1
    shown = dist(tight, "LOCUS_SHOWN")
    for locus in LOCI:
        if basis.get(locus, 0) and not shown.get(locus, 0):
            assert locus in line[0], "{} got no slot and was not named".format(locus)

    roomy = consult(question, "--limit", str(populated), today=LATER)
    assert "LOCUS_UNDERSERVED:" not in roomy


def test_spread_reserves_a_slot_for_every_eligible_locus_when_the_limit_allows():
    for question in QUESTIONS:
        out = consult(question, "--limit", "12")
        eligible, shown = reserve_basis(out), dist(out, "LOCUS_SHOWN")
        populated = [l for l in LOCI if eligible.get(l, 0)]
        if len(populated) > 12:
            continue
        for locus in populated:
            assert shown.get(locus, 0) >= 1, \
                "{} has {} eligible and no slot in {}".format(locus, eligible[locus], question)


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
    assert {"LOCUS", "LOCUS_SPAN", "LOCUS_BASIS", "SLOT"} <= blocks[0]
    assert "RESPONSE_DOCTRINE" in blocks[0], "the block that used to be conditional"


@pytest.mark.parametrize("question", QUESTIONS)
def test_locus_span_always_leads_with_the_primary(question):
    """One code path for the consumer: split on ', ' and get one to three, never '-'. The
    third is the locus a class the question resolved appends after the record's own span."""
    out = consult(question, "--limit", "12")
    primary = shown_loci(out)
    spans = [l.split(":", 1)[1].strip() for l in out.splitlines() if l.startswith("LOCUS_SPAN: ")]
    assert len(spans) == len(primary)
    for locus, span in zip(primary, spans):
        parts = [p.strip() for p in span.split(",")]
        assert 1 <= len(parts) <= 3
        assert parts[0] == locus
        assert len(set(parts)) == len(parts), "span repeats the primary"
        assert all(p in LOCI for p in parts)


# --- what may fill a reserved slot -----------------------------------------------------------

def reserved_bullets(stdout):
    """(locus, rank, score, tier, key) for each LOCUS_RESERVED bullet."""
    out = []
    for line in bullets(stdout, "LOCUS_RESERVED"):
        found = re.match(r"^  - ([A-Z]+), rank (\d+), score ([0-9.]+).*?, tier ([a-z-]+), "
                         r"(\S+#how\d+) / ", line)
        assert found, "unparseable LOCUS_RESERVED bullet: {}".format(line)
        out.append((found.group(1), int(found.group(2)), float(found.group(3)),
                    found.group(4), found.group(5)))
    return out


@pytest.mark.parametrize("question", QUESTIONS + [
    "Fortinet FortiGate", "Check Point firewall", "Zorblax Edge Gateway 9000"])
def test_a_reserved_slot_is_never_filled_below_the_floor_or_off_subject(question):
    """"Fortinet FortiGate" reserved ORGANISATION at score 1.50 for a geolocation-limits record
    and pushed out a record naming FortiGate; "Zorblax Edge Gateway 9000" reserved ORGANISATION
    for a phishing kit reached by the word "gateway". A reserved slot is filled only from a
    subject or tag match at or above the MODERATE floor."""
    out = consult(question, "--limit", "12", today=LATER)
    for locus, rank, score, tier, key in reserved_bullets(out):
        assert score >= C.RESERVE_FLOOR, "{} reserved at score {}".format(locus, score)
        assert tier in C.ELIGIBLE_TIERS, "{} reserved from tier {}".format(locus, tier)
        block = [b for b in blocks(out) if b["FINDING_KEY"] == key][0]
        assert block["MATCH_TIER"] == tier and block["LOCUS"] == locus


def absent_bullet(stdout, locus):
    for line in bullets(stdout, "LOCUS_ABSENT"):
        if line.startswith("  - {}:".format(locus)):
            return line
    raise AssertionError("no LOCUS_ABSENT bullet for {}".format(locus))


def test_a_locus_reached_only_by_filler_is_reported_absent():
    """A locus with matches and no eligible finding is absent, and its bullet says what did
    reach it. "Zorblax Edge Gateway 9000" is a mechanism answer whose ENDPOINT and SUPPLY are
    reached only by name fragments and pattern wording; "SolarWinds Orion" reaches SUPPLY only
    through the one block that detects the signed update itself, which scores under the floor.
    "npm" was the second fixture until the supply surface stopped placing every block of a
    supply-chain record: a model-namespace record's non-supply block now reaches CONTROL.
    ORGANISATION was the Zorblax fixture's other locus until the 2026-10-01 third validation
    placed posture questions there, and a tag match on an edge appliance's patch-speed
    question now holds it."""
    out = consult("Zorblax Edge Gateway 9000", "--limit", "12", today=LATER)
    matched = dist(out, "LOCUS_MATCHED")
    for locus in ("ENDPOINT", "SUPPLY"):
        assert locus in absent_loci(out)
        assert matched[locus] > 0, "fixture no longer reaches {} at all".format(locus)
        line = absent_bullet(out, locus)
        assert "matched {} (loose {}, below floor 0)".format(
            matched[locus], matched[locus]) in line, line
    printed = re.findall(r"^RECORD_ID: (.*)$", out, re.M)
    assert "obs-npm-registry-worm-propagates-through-maintainer-publish-rights" not in printed
    assert "obs-npm-registry-worm-propagates-through-maintainer-publish-rights#how2" in \
        absent_bullet(out, "SUPPLY")

    orion = consult("SolarWinds Orion", "--limit", "12", today=LATER)
    assert "SUPPLY" in absent_loci(orion)
    below = re.search(r"matched (\d+) \(loose 0, below floor (\d+)\)",
                      absent_bullet(orion, "SUPPLY"))
    assert below and int(below.group(1)) == int(below.group(2)) > 0


def test_a_named_mechanism_word_still_counts_as_on_topic():
    """A tag match is eligible in every mode. Once a resolved name's words are no longer
    searched, a tag hit on a named question comes from a word the caller wrote beyond the
    name; leaving tags out left "helpdesk social engineering" with four loci absent."""
    out = consult("helpdesk social engineering", "--limit", "12", today=LATER)
    assert "ORGANISATION" not in absent_loci(out)
    assert dist(out, "LOCUS_SHOWN")["ORGANISATION"] >= 1


ABSENT_BULLET = re.compile(
    r"^  - ([A-Z]+): matched (\d+)(?: \(loose (\d+), below floor (\d+)\))?; span-only (\d+)"
    r"; exposures (\d+); library (\d+)"
    r"(?:; best ineligible rank (\d+), score ([0-9.]+), tier ([a-z-]+), (\S+#how\d+) / \S+)?$")


@pytest.mark.parametrize("question,today", [(q, TODAY) for q in QUESTIONS] + [
    ("Zorblax Edge Gateway 9000", LATER), ("npm", LATER), ("Google Chrome", LATER),
    ("I have a Cisco ASA", LATER)])
def test_every_absent_locus_bullet_recounts_from_the_whole_match_set(question, today):
    """Every count an absent locus's bullet states is recounted from the whole match set,
    printed in pure order. The span-only count is how a locus that is another finding's second
    home, a class the question matched included, stops reading as holding nothing. The
    exposure and library counts are recounted from those blocks printed whole: each is counted
    on the bullet and neither makes the locus represented."""
    out = consult(question, "--limit", "12", today=today)
    full_out = consult(question, "--limit", "2000", "--no-locus-spread", "--exposure-limit",
                       "2000", "--pattern-limit", "2000", today=today)
    full = blocks(full_out)
    assert len(full) == sum(dist(out, "LOCUS_MATCHED").values()), "--limit 2000 truncated"
    # The exposure and library counts are recounted from the blocks themselves, printed whole.
    exposures = re.findall(r"^EXPOSURE_LOCUS: ([A-Z]+)$", full_out, re.M)
    library = re.findall(r"^LIBRARY_LOCUS: ([A-Z]+)$", full_out, re.M)
    for line in bullets(out, "LOCUS_ABSENT"):
        found = ABSENT_BULLET.match(line)
        assert found, "unparseable LOCUS_ABSENT bullet: {}".format(line)
        locus, matched = found.group(1), int(found.group(2))
        here = [b for b in full if b["LOCUS"] == locus]
        assert matched == len(here)
        loose = [b for b in here if b["MATCH_TIER"] not in C.ELIGIBLE_TIERS]
        spans = [b for b in full if locus in b["LOCUS_SPAN"].split(", ")[1:]]
        assert int(found.group(5)) == len(spans), "span-only count for {}".format(locus)
        assert int(found.group(6)) == exposures.count(locus), "exposures for {}".format(locus)
        assert int(found.group(7)) == library.count(locus), "library for {}".format(locus)
        if not matched:
            assert found.group(3) is None and found.group(8) is None
            continue
        assert int(found.group(3)) == len(loose)
        assert int(found.group(4)) == matched - len(loose)
        for b in here:
            if b["MATCH_TIER"] in C.ELIGIBLE_TIERS:
                score = float(re.search(r"score=([0-9.]+)/", b["PRIORITY_BASIS"]).group(1))
                assert score <= C.RESERVE_FLOOR + 0.05, \
                    "eligible finding in absent {}".format(locus)
        best = here[0]
        assert (found.group(8), found.group(10), found.group(11)) == (
            best["RANK"], best["MATCH_TIER"], best["FINDING_KEY"])


def test_an_absent_locus_carried_as_a_span_is_named():
    """SCADA printed "LOCUS_ABSENT: DATA ... no finding in this match set sits there" over a
    finding whose LOCUS_SPAN named DATA as its second home. The bullet now counts it."""
    out = consult("SCADA", "--limit", "500")
    assert "DATA" in absent_loci(out), "fixture no longer leaves DATA absent"
    spans = [l for l in out.splitlines() if l.startswith("LOCUS_SPAN: ")
             and "DATA" in l.split(": ", 1)[1].split(", ")[1:]]
    assert spans, "fixture no longer carries DATA as a span"
    found = ABSENT_BULLET.match(absent_bullet(out, "DATA"))
    assert found and int(found.group(5)) == len(spans)


# --- what each block says about its own slot -------------------------------------------------

@pytest.mark.parametrize("question", QUESTIONS + ["Fortinet FortiGate", "Atlassian Confluence"])
def test_reserved_blocks_print_the_rank_the_header_cites(question):
    """A reserved block printed "RANK: 12" under a header that called it rank 78, and nothing
    in it said it had been reserved. RANK is now the position in the whole ORDERING order and
    SLOT says why the block is shown."""
    out = consult(question, "--limit", "12", today=LATER)
    found = blocks(out)
    ranks = [int(b["RANK"]) for b in found]
    assert ranks == sorted(ranks) and len(set(ranks)) == len(ranks), "RANK is not increasing"
    reserved = reserved_bullets(out)
    for locus, rank, _, _, key in reserved:
        hits = [b for b in found if b["RANK"] == str(rank)]
        assert len(hits) == 1
        assert hits[0]["SLOT"].startswith("reserved - taken from rank {} ".format(rank))
        assert hits[0]["FINDING_KEY"] == key and hits[0]["LOCUS"] == locus
        assert rank > 12
    assert sum(b["SLOT"].startswith("reserved") for b in found) == len(reserved)
    for b in found:
        kind = b["SLOT"].split(" ")[0]
        assert kind in ("natural", "replacement", "reserved", "backfill"), b["SLOT"]
        # "natural - rank 13 is below the natural top 12" contradicted itself, and a consumer
        # counting by the first word counted it as natural.
        if kind == "natural":
            assert int(b["RANK"]) <= 12, "a natural slot is inside the natural top N"
        if kind == "replacement":
            assert int(b["RANK"]) > 12
    # A finding shown from below the cut in the natural fill took a capped finding's place.
    swapped = [b for b in found if b["SLOT"].startswith("replacement - ")]
    assert len(swapped) == stated(out, "RECORD_CAP")
    for line in bullets(out, "LOCUS_DISPLACED") + bullets(out, "RECORD_CAP"):
        assert int(re.search(r"rank (\d+)", line).group(1)) <= 12


# --- the record cap ----------------------------------------------------------------------------

def group_of(block):
    return int(re.search(r"\(group (\d+)", block["PRIORITY_BASIS"]).group(1))


def test_no_record_takes_more_than_the_cap_while_others_remain():
    """"Atlassian Confluence" showed 6 blocks of one PBX record in twelve, 8 in pure order.
    A record takes at most RECORD_CAP slots while another record's finding in its own match
    group is waiting; past the cap it is shown only as backfill, once its group has no such
    finding left."""
    out = consult("Atlassian Confluence", "--limit", "12", today=LATER)
    found = blocks(out)
    shown = collections.Counter(b["RECORD_ID"] for b in found)
    assert shown["obs-sangoma-switchvox-pa-sql-injection-exploited"] == C.RECORD_CAP, shown
    assert capped_total(out) > 0, "fixture no longer exercises the cap"
    everything = blocks(consult("Atlassian Confluence", "--limit", "2000", "--no-locus-spread",
                                today=LATER))
    keys = {b["FINDING_KEY"] for b in found}
    for b in found:
        if not b["SLOT"].startswith("backfill"):
            continue
        waiting = [w for w in everything
                   if group_of(w) == group_of(b) and w["FINDING_KEY"] not in keys
                   and shown[w["RECORD_ID"]] < C.RECORD_CAP]
        assert not waiting, "{} backfilled while {} waited".format(
            b["FINDING_KEY"], waiting[0]["FINDING_KEY"])
    pure = consult("Atlassian Confluence", "--limit", "12", "--no-locus-spread", today=LATER)
    assert max(collections.Counter(re.findall(r"^RECORD_ID: (.*)$", pure, re.M)).values()) \
        > C.RECORD_CAP, "pure order must stay uncapped"


# Each lost, across groups, a finding naming what was asked to another vendor's analogue: the
# review measured 178 of 848 product questions losing 566 such findings, these among them.
CAP_ACROSS_GROUPS = [
    ("Check Point firewall", ()), ("Atlassian Confluence", ()), ("Ivanti EPMM", ()),
    ("Apache Log4j", ()), ("Broadcom VMware Horizon", ()), ("PAN-OS", ()), ("Okta", ()),
    ("Fortinet FortiGate", ("--per-locus", "3"))]


@pytest.mark.parametrize("question,extra", CAP_ACROSS_GROUPS)
def test_the_cap_never_hands_a_tighter_groups_slot_to_a_looser_group(question, extra):
    """A finding the cap passed over leaves only for a finding of its own match group. Applied
    across groups, "Check Point firewall" lost its rank-3 Check Point block and kept a Cisco VPN
    analogue at rank 10, which is the opposite of what ORDERING's groups promise."""
    out = consult(question, "--limit", "12", *extra, today=LATER)
    found = blocks(out)
    capped = [l for l in bullets(out, "RECORD_CAP")] + [
        l for l in bullets(out, "LOCUS_DISPLACED") if "; RECORD_CAP chose it" in l]
    everything = {b["FINDING_KEY"]: b for b in blocks(
        consult(question, "--limit", "2000", "--no-locus-spread", *extra, today=LATER))}
    for line in capped:
        lost = everything[bullet_key(line)]
        # A reserve may outrank a lost finding, and says so: from below the cut, or held in
        # place inside it.
        looser = [b for b in found if "reserve of" not in b["SLOT"]
                  and group_of(b) > group_of(lost) and int(b["RANK"]) > int(lost["RANK"])]
        assert not looser, "{} (group {}) passed over for {} (group {})".format(
            bullet_key(line), group_of(lost), looser[0]["FINDING_KEY"], group_of(looser[0]))
    if question == "Check Point firewall":
        assert "obs-checkpoint-security-gateway-information-disclosure#how0" in \
            {b["FINDING_KEY"] for b in found}


@pytest.mark.parametrize("question,limit", [(q, "12") for q in QUESTIONS + [
    "SolarWinds Orion", "Atlassian Confluence"]] + [
    ("pradeo", "12"), ("pradeo", "25"), ("dexprotector", "12"), ("licel", "25")])
@pytest.mark.parametrize("per_locus", ["1", "3"])
def test_a_record_past_the_cap_says_why(question, limit, per_locus):
    """The cap bows only to a reserve whose locus holds no other record's eligible finding in
    its group, and to a group with no other record's finding left; each block a record holds
    past the cap, counted in RANK order, says so in SLOT, and no other block does.

    "pradeo" --per-locus 3 showed one record at ranks 28, 29 and 42: the reason sat on rank 29,
    the reserve round's last pick, saying its record already held 2 with only rank 28 before
    it, and rank 42 said nothing."""
    out = consult(question, "--limit", limit, "--per-locus", per_locus, today=LATER)
    found = blocks(out)
    total = collections.Counter(b["RECORD_ID"] for b in found)
    held = collections.Counter()
    for b in found:
        record = b["RECORD_ID"]
        held[record] += 1
        if b["SLOT"].startswith("backfill"):
            assert "its record holds {} slots in this answer".format(total[record]) in b["SLOT"]
        elif held[record] > C.RECORD_CAP:
            assert "; its record holds {} slots in this answer, past RECORD_CAP".format(
                total[record]) in b["SLOT"], b["SLOT"]
        else:
            assert "past RECORD_CAP" not in b["SLOT"], b["SLOT"]


# --- depth per plane, and the relationships other than victim ----------------------------------

@pytest.mark.parametrize("question", ["Fortinet FortiGate", "Microsoft Exchange", "SCADA"])
def test_per_locus_reserves_n_per_eligible_locus(question):
    """Rule 9 asks for several findings under each plane, and the quota reserved exactly one.
    Read over reserve_basis(): Exchange's CONTROL holds one finding naming Exchange Server."""
    out = consult(question, "--per-locus", "3", "--limit", "18", today=LATER)
    eligible, shown = reserve_basis(out), dist(out, "LOCUS_SHOWN")
    # A reserved block states its locus's own reserve, which is --per-locus only where the
    # locus holds that many: DATA holds one eligible finding and printed "reserve of 3".
    for b in blocks(out):
        if "reserve of" in b["SLOT"]:
            want = int(re.search(r"reserve of (\d+)", b["SLOT"]).group(1))
            assert want == min(3, eligible[b["LOCUS"]]), b["SLOT"]
    if question == "Microsoft Exchange":
        assert any(eligible[l] and eligible[l] < 3 for l in LOCI), "fixture no longer exercises it"
    asked = sum(min(3, n) for n in eligible.values())
    assert asked <= 18, "fixture asks more than the limit gives"
    assert "LOCUS_SPREAD: quota - 3 slot(s) reserved per locus" in out
    for locus in LOCI:
        assert shown[locus] >= min(3, eligible[locus]), "{} got {} of {}".format(
            locus, shown[locus], min(3, eligible[locus]))
    assert len(bullets(out, "LOCUS_DISPLACED")) == len(bullets(out, "LOCUS_RESERVED"))


def test_per_locus_changes_the_spread_and_underserves_below_its_reserve():
    # FortiGate's natural 18 already holds three of each locus with two or more eligible, since
    # the resolver-bypass block it reserved SUPPLY for sits on its firewall's CONTROL. Windows did
    # the work here until the 2026-10-01 fourth validation, through Windows Server, Netlogon and
    # Teams records in tier vendor; its subject is now ENDPOINT and ORGANISATION, which its
    # natural 18 already holds. A question naming nothing reserves from LOCUS_ELIGIBLE.
    windows = consult("network firewall", "--per-locus", "3", "--limit", "18", today=LATER)
    many, elig = dist(windows, "LOCUS_SHOWN"), reserve_basis(windows)
    one = dist(consult("network firewall", "--limit", "18", today=LATER), "LOCUS_SHOWN")
    assert any(many[l] > one[l] for l in LOCI if elig[l] >= 2), \
        "--per-locus 3 changed nothing"

    tight = consult("Fortinet FortiGate", "--per-locus", "3", "--limit", "4", today=LATER)
    asked = sum(min(3, n) for n in reserve_basis(tight).values())
    assert asked > 4, "fixture no longer exercises underservice"
    line = [l for l in tight.splitlines() if l.startswith("LOCUS_UNDERSERVED:")]
    assert len(line) == 1 and "below the {} slot(s) --per-locus 3".format(asked) in line[0]


def test_role_filter_keeps_only_that_role():
    """The relationships rule 9 asks for were reachable only through query.py's brief lines."""
    out = consult("Palo Alto firewall", "--role", "telemetry_source", "--limit", "500",
                  today=LATER)
    printed = re.findall(r"^RECORD_ID: (.*)$", out, re.M)
    assert printed, "fixture no longer holds a telemetry_source record"
    assert {ROLES[r] for r in printed} == {"telemetry_source"}
    line = [l for l in out.splitlines() if l.startswith("ROLE_FILTER:")][0]
    kept, matched = map(int, re.search(r"(\d+) of (\d+) matched observation records kept",
                                       line).groups())
    assert kept == len(set(printed)) and matched > kept
    # Exposure records are filtered too, and every one is a victim record: the RESOLUTION line
    # marked as over the kept records counted "4 exposure records" the filter never touched.
    exposures = re.search(r"(\d+) of (\d+) exposure records naming it kept", line)
    assert exposures and int(exposures.group(1)) == 0 < int(exposures.group(2)), line
    resolution = [l for l in out.splitlines() if l.startswith("RESOLUTION:")][0]
    assert "exposure record" not in resolution, resolution
    victim = consult("Palo Alto firewall", "--role", "victim", "--limit", "3", today=LATER)
    kept_exposures = re.search(r"(\d+) of (\d+) exposure records naming it kept", victim)
    assert kept_exposures.group(1) == kept_exposures.group(2)
    total = int(re.search(r"FINDINGS: \d+ shown of (\d+) matched", out).group(1))
    assert total == len(printed) == sum(dist(out, "LOCUS_MATCHED").values())
    tiers = re.search(r"^MATCH_TIERS: (.*?)  \(", out, re.M).group(1)
    assert sum(int(p.split("=")[1]) for p in tiers.split(", ")) == total
    assert "[--role telemetry_source: over the kept records only]" in \
        [l for l in out.splitlines() if l.startswith("RESOLUTION:")][0]

    both = consult("Palo Alto firewall", "--role", "control_bypassed,telemetry_source",
                   "--limit", "500", today=LATER)
    got = {ROLES[r] for r in re.findall(r"^RECORD_ID: (.*)$", both, re.M)}
    assert got == {"control_bypassed", "telemetry_source"}

    code, stdout, err = run("Palo Alto firewall", "--role", "bogus")
    assert code == 2 and stdout == "" and "--role 'bogus'" in err


def test_a_role_filter_that_keeps_nothing_says_so():
    """Filtered to nothing, the answer is not "the corpus holds nothing": the re-ask advice
    for an unknown name would send the caller to name a class for a product with records."""
    code, out, _ = run("Citrix ShareFile", "--role", "lateral_path", "--today", LATER)
    assert code == 1
    assert "0 of" in [l for l in out.splitlines() if l.startswith("ROLE_FILTER:")][0]
    assert "none from a record whose what.role is lateral_path" in out
    assert "NOTHING MATCHED" not in out and "=== FINDING " not in out
    # The two counts agree once each says what it is over: "0 shown of 0 matched" followed by
    # "27 finding(s) matched" read as a contradiction, and "the findings below" pointed at
    # nothing.
    findings = [l for l in out.splitlines() if l.startswith("FINDINGS:")][0]
    before = int(re.search(r"(\d+) matched before it\]$", findings).group(1))
    assert findings.startswith("FINDINGS: 0 shown of 0 matched [--role lateral_path")
    assert "NO_FINDINGS: {} finding(s) matched before --role".format(before) in out
    for key in ("RESOLUTION:", "CLASS_LEVEL_WARNING:"):
        line = [l for l in out.splitlines() if l.startswith(key)][0]
        assert "below" not in line and line.endswith("[before --role lateral_path, which "
                                                      "kept no finding]"), line

    # A name held only as exposures, whose exposures the filter drops, is emptied by the filter
    # too: it is not a name nothing in the corpus carries.
    code, out, _ = run("Craft CMS", "--role", "telemetry_source", "--today", LATER)
    assert "RESOLUTION: EXPOSURES_ONLY" in out, "fixture is no longer exposures-only"
    assert code == 1 and "NOTHING MATCHED" not in out
    assert "; 0 of 1 exposure records naming it kept;" in out
    assert "it kept 0 of the 1 exposure record(s) naming it" in out


def test_role_filter_says_the_role_is_the_records():
    """--role filters on the record's one what.role. The help, the reference and the
    CHANGELOG said it kept "records where the technology played the roles named", and two of
    the seven records "Palo Alto firewall" keeps as control_bypassed name a directory and a
    firewall, and say in their summaries that the perimeter held and that no actor was found."""
    out = consult("Palo Alto firewall", "--role", "telemetry_source,inline_tool,control_bypassed",
                  today=LATER)
    line = [l for l in out.splitlines() if l.startswith("ROLE_FILTER:")][0]
    assert "each record carries one what.role, not one per product or class it names" in line
    code, help_text, _ = run("--help")
    assert code == 0
    flat = " ".join(help_text.split())
    assert "technology played" not in flat
    assert "what.role is one value per record, not per product or class it names" in flat
    reference = (BUNDLE / "references" / "locus-and-coverage.md").read_text(encoding="utf-8")
    assert "where the technology played" not in reference
    assert "one value per record" in " ".join(reference.split())
    query_help = subprocess.run([sys.executable, str(SCRIPTS / "query.py"), "--help"],
                                capture_output=True, text=True, cwd=str(BUNDLE)).stdout
    assert "technology played" not in " ".join(query_help.split())


# --- a reserve names what was asked, and a plane only analogues hold says so -------------------
#
# The 2026-09-30 validation: "Fortinet FortiGate" reserved DATA and ENDPOINT for two other
# products' class analogues -- a known-vulnerability catalogue join and a Zeppelin share-
# enumeration block at score 3.71 -- pushed out two FortiGate findings, one at 3.92, and counted
# both planes as represented. "Cisco ASA" --per-locus 3 --limit 18 reserved the same two, and so
# did the other firewall questions.

VALIDATED = "2026-09-30"
ZEPPELIN = "obs-generic-ransomware-repeated-deployment-and-enclave-mapping"
NAMED = [("Fortinet FortiGate", ()), ("Cisco ASA", ("--per-locus", "3", "--limit", "18")),
         ("Palo Alto firewall", ("--per-locus", "3", "--limit", "18")),
         ("Check Point firewall", ()), ("Juniper SRX", ("--per-locus", "3", "--limit", "18")),
         ("Cisco Firepower Threat Defense", ("--per-locus", "3", "--limit", "18")),
         ("Microsoft Exchange", ()), ("Fortinet", ()), ("Microsoft Windows", ())]


def analogue_only(stdout):
    line = [l for l in stdout.splitlines() if l.startswith("LOCUS_ANALOGUE_ONLY:")]
    assert len(line) == 1, "LOCUS_ANALOGUE_ONLY must print exactly once"
    body = line[0].split(":", 1)[1].split(" - ")[0].strip()
    return [] if body in ("none", "not applicable") else [x.strip() for x in body.split(",")]


@pytest.mark.parametrize("question,extra", NAMED)
def test_a_reserve_is_filled_only_from_findings_naming_what_was_asked(question, extra):
    out = consult(question, "--limit", "12", *extra, today=VALIDATED)
    subject = [l for l in out.splitlines() if l.startswith("LOCUS_SUBJECT:")][0]
    assert "what a reserved slot is filled from)" in subject, subject
    for locus, rank, score, tier, key in reserved_bullets(out):
        assert tier in subject_tiers_stated(out), "{} reserved {} from tier {}".format(
            question, key, tier)
    # Never a finding naming what was asked given up for an analogue: whatever left the
    # natural top N left for a finding of its own group or a reserve naming what was asked.
    shown_tiers = {b["MATCH_TIER"] for b in blocks(out)}
    for line in bullets(out, "LOCUS_DISPLACED"):
        tier = re.search(r", tier ([a-z-]+), ", line).group(1)
        if tier in C.NAMING_TIERS:
            assert all(t in C.NAMING_TIERS for _, _, _, t, _ in reserved_bullets(out)), line
    # Every locus LOCUS_SUBJECT populates got its reserve, and no other locus was reserved for.
    basis = dist(out, "LOCUS_SUBJECT")
    reserved = {locus for locus, *_ in reserved_bullets(out)}
    assert reserved <= {l for l, n in basis.items() if n}
    assert shown_tiers, "no finding printed"


@pytest.mark.parametrize("question,extra", [NAMED[0], NAMED[1]])
def test_a_firewall_plane_held_only_by_analogues_is_named_and_not_reserved(question, extra):
    out = consult(question, "--limit", "12", *extra, today=VALIDATED)
    only = analogue_only(out)
    # ORGANISATION, not DATA, since the 2026-10-01 third validation: the analogue that held
    # DATA was the known-exploited catalogue join, an inventory question its web-server-first
    # record had placed there, and it now sits on ORGANISATION with every copy of itself.
    assert {"ORGANISATION", "ENDPOINT"} <= set(only), only
    assert "Do not report these loci as covered for what was asked" in out
    assert ZEPPELIN not in {b["RECORD_ID"] for b in blocks(out)}
    shown = dist(out, "LOCUS_SHOWN")
    assert shown["ORGANISATION"] == shown["ENDPOINT"] == shown["DATA"] == 0
    # The natural order is the product's and the vendor's, so nothing reserved displaced it.
    assert {b["MATCH_TIER"] for b in blocks(out)} <= set(C.NAMING_TIERS) | {"class",
                                                                           "vendor-other-class"}
    if question == "Fortinet FortiGate":
        assert {b["MATCH_TIER"] for b in blocks(out)} <= set(C.NAMING_TIERS)
        assert bullets(out, "LOCUS_DISPLACED") == []


ANALOGUE_BULLET = re.compile(
    r"^  - ([A-Z]+): eligible (\d+) \(([^)]*)\); first rank (\d+), score ([0-9.]+), "
    r"tier ([a-z-]+), (\S+#how\d+) / \S+; shown (\d+)$")


@pytest.mark.parametrize("question", ["Fortinet FortiGate", "Microsoft Exchange", "Fortinet",
                                      "Zyxel firewall"])
def test_every_analogue_only_bullet_recounts_from_the_whole_match_set(question):
    out = consult(question, "--limit", "12", today=VALIDATED)
    full = blocks(consult(question, "--limit", "2000", "--no-locus-spread", today=VALIDATED))
    assert len(full) == sum(dist(out, "LOCUS_MATCHED").values()), "--limit 2000 truncated"

    def eligible(b):
        # No --covered, so PRIORITY is the criticality's band and CONTEXT is below the floor.
        return b["MATCH_TIER"] in C.ELIGIBLE_TIERS and b["PRIORITY"] != "CONTEXT"

    # The tiers that name this question's subject (C.question_subject()): on these questions a
    # product question with a vendor-tier finding narrows to `product`, or to `vendor` where
    # nothing names the product; the per-vendor case has its own test below.
    held = {b["MATCH_TIER"] for b in full}
    named_product = "products=-" not in [l for l in out.splitlines()
                                         if l.startswith("RESOLVED_TO:")][0]
    tiers = (("product",) if "product" in held else ("vendor",)) \
        if named_product and "vendor" in held else C.NAMING_TIERS
    assert subject_tiers_stated(out) == tuple(tiers)
    naming = collections.Counter(b["LOCUS"] for b in full
                                 if eligible(b) and b["MATCH_TIER"] in tiers)
    assert dist(out, "LOCUS_SUBJECT") == {l: naming.get(l, 0) for l in LOCI}
    held = [l for l in LOCI if any(eligible(b) and b["LOCUS"] == l for b in full)]
    subject = [l for l in out.splitlines() if l.startswith("LOCUS_SUBJECT:")][0]
    expected = [l for l in held if not naming.get(l)] \
        if "what a reserved slot is filled from)" in subject else held
    assert sorted(analogue_only(out)) == sorted(expected)
    rows = bullets(out, "LOCUS_ANALOGUE_ONLY")
    assert len(rows) == len(expected)
    for line in rows:
        found = ANALOGUE_BULLET.match(line)
        assert found, "unparseable LOCUS_ANALOGUE_ONLY bullet: {}".format(line)
        locus = found.group(1)
        here = [b for b in full if b["LOCUS"] == locus and eligible(b)]
        assert int(found.group(2)) == len(here)
        tiers = collections.Counter(b["MATCH_TIER"] for b in here)
        assert found.group(3) == ", ".join("{} {}".format(t, tiers[t])
                                           for t in C.ELIGIBLE_TIERS if tiers.get(t))
        assert (found.group(4), found.group(6), found.group(7)) == (
            here[0]["RANK"], here[0]["MATCH_TIER"], here[0]["FINDING_KEY"])
        assert int(found.group(8)) == dist(out, "LOCUS_SHOWN")[locus]


def test_a_named_question_nothing_names_spreads_its_analogues():
    """Where no finding names what was asked, the answer is analogues throughout and says so,
    no finding naming it can be displaced, and the reserve spreads the analogues as before."""
    out = consult("Zyxel firewall", "--limit", "12", today=VALIDATED)
    assert "CLASS_LEVEL_WARNING:" in out
    subject = [l for l in out.splitlines() if l.startswith("LOCUS_SUBJECT:")][0]
    assert "none names it, so the answer is analogues throughout" in subject
    assert set(dist(out, "LOCUS_SUBJECT").values()) == {0}
    only = analogue_only(out)
    assert set(only) == {l for l, n in dist(out, "LOCUS_ELIGIBLE").items() if n}
    assert reserved_bullets(out), "fixture no longer exercises the analogue reserve"


@pytest.mark.parametrize("question", ["network firewall", "SCADA", "helpdesk social engineering"])
def test_a_question_naming_nothing_reserves_as_before(question):
    out = consult(question, "--limit", "12", "--no-locus-spread", today=VALIDATED)
    assert analogue_only(out) == []
    assert "LOCUS_ANALOGUE_ONLY: not applicable" in out
    assert "LOCUS_SUBJECT: not applicable" in out


def test_the_subject_lines_say_what_this_answer_did():
    """The 2026-10-01 review: under --no-locus-spread, LOCUS_ANALOGUE_ONLY said "the reserve
    spreads them" beside "LOCUS_SPREAD: off"; an answer with no finding said a reserved slot
    was filled from LOCUS_ELIGIBLE; and a vendor block read "names it (GitHub, github)"."""
    off = consult("Zyxel firewall", "--no-locus-spread", today=VALIDATED)
    line = [l for l in off.splitlines() if l.startswith("LOCUS_ANALOGUE_ONLY:")][0]
    assert "the reserve spreads them" not in line and "no slot is reserved" in line
    subject = [l for l in off.splitlines() if l.startswith("LOCUS_SUBJECT:")][0]
    assert "filled from LOCUS_ELIGIBLE" not in subject
    on = consult("Zyxel firewall", today=VALIDATED)
    assert "the reserve spreads them" in [l for l in on.splitlines()
                                          if l.startswith("LOCUS_ANALOGUE_ONLY:")][0]
    empty = consult("Apple iOS", today=VALIDATED)
    assert "FINDINGS: 0" in empty or not blocks(empty)
    subject = [l for l in empty.splitlines() if l.startswith("LOCUS_SUBJECT:")][0]
    assert "no finding matched, so there is nothing to reserve" in subject, subject
    github = consult("GitHub", "--limit", "2000", "--no-locus-spread", today=VALIDATED)
    assert "names it (GitHub, github)" not in github
    assert "names it (GitHub)" in github



@pytest.mark.parametrize("question", ["Fortinet FortiGate", "network firewall"])
def test_the_subject_line_reserves_nothing_with_the_spread_off(question):
    """The second review: with --no-locus-spread, a question naming a product still printed
    LOCUS_SUBJECT as "what a reserved slot is filled from", and one naming nothing that "a
    reserved slot is filled from LOCUS_ELIGIBLE", beside "LOCUS_SPREAD: off"."""
    def subject(out):
        return [l for l in out.splitlines() if l.startswith("LOCUS_SUBJECT:")][0]

    off = consult(question, "--no-locus-spread", today=VALIDATED)
    assert "LOCUS_SPREAD: off" in off
    line = subject(off)
    assert "is filled from" not in line, line
    assert "LOCUS_SPREAD is off, so no slot is reserved" in line, line
    on = subject(consult(question, today=VALIDATED))
    assert "is filled from" in on and "no slot is reserved" not in on, on


# --- a product question's subject is the product, not the vendor's other products ---------------
#
# The 2026-10-01 fourth validation: "Cisco ASA" --per-locus 3 --limit 18 counted three Secure
# Firewall Management Center blocks as LOCUS_SUBJECT MANAGEMENT=3, reserved MANAGEMENT for them
# and left it out of LOCUS_ANALOGUE_ONLY, though FMC administers Firepower Threat Defense and not
# ASA software and each block printed MATCH_BASIS "but not the product asked about". RESOLUTION,
# MATCH_BASIS and the exposure tiers already read `vendor` that way on a product question.

FOURTH = "2026-10-01"
FMC = "obs-cisco-secure-firewall-management-center-static-credential-login"


def subject_line(stdout):
    return [l for l in stdout.splitlines() if l.startswith("LOCUS_SUBJECT:")][0]


def subject_tiers_stated(stdout):
    """The tiers LOCUS_SUBJECT says it counted, read from its own parenthesis."""
    found = re.search(r"\(the eligible findings in tier ([a-z -]+?), naming ", subject_line(stdout))
    assert found, subject_line(stdout)
    return tuple(found.group(1).split(" or "))


def test_a_vendor_finding_does_not_hold_a_named_products_plane():
    """The ASA's MANAGEMENT was three management centre blocks, each tier vendor: it is now
    counted nowhere in LOCUS_SUBJECT, listed in LOCUS_ANALOGUE_ONLY with the management centre
    named in its bullet, and reserved for nothing, while the same blocks still show."""
    out = consult("Cisco ASA", "--per-locus", "3", "--limit", "18", today=FOURTH)
    assert dist(out, "LOCUS_SUBJECT") == dict(CONTROL=3, MANAGEMENT=0, DATA=0, ENDPOINT=0,
                                              SUPPLY=0, ORGANISATION=0)
    assert subject_tiers_stated(out) == ("product",)
    assert "naming Adaptive Security Appliance, and not tier vendor" in subject_line(out)
    assert "MANAGEMENT" in analogue_only(out)
    row = [l for l in bullets(out, "LOCUS_ANALOGUE_ONLY") if l.startswith("  - MANAGEMENT:")]
    assert row and "(vendor 3, " in row[0] and ", tier vendor, {}#how".format(FMC) in row[0], row
    assert {tier for _, _, _, tier, _ in reserved_bullets(out)} <= {"product"}
    assert "the reserve for LOCUS MANAGEMENT" not in out
    # Nothing is taken away: the three FMC blocks still show, on rank alone, as MATCH_TIER vendor.
    fmc = [b for b in blocks(out) if b["RECORD_ID"] == FMC]
    assert len(fmc) == 3 and {b["MATCH_TIER"] for b in fmc} == {"vendor"}


def test_a_vendor_question_keeps_the_vendors_products_as_its_subject():
    """The vendor is the subject when no product was named, so FMC is Cisco's own MANAGEMENT."""
    out = consult("Cisco", "--per-locus", "3", "--limit", "18", today=FOURTH)
    assert subject_tiers_stated(out) == tuple(C.NAMING_TIERS)
    assert "naming Cisco: what a reserved slot is filled from)" in subject_line(out)
    assert dist(out, "LOCUS_SUBJECT")["MANAGEMENT"] >= 3
    assert "MANAGEMENT" not in analogue_only(out)


def test_a_product_nothing_names_keeps_the_vendors_reserve_and_says_whose_it_is():
    """No finding names IOS XR and seventeen name Cisco in network.router: the reserve is filled
    from them as before, and the lines name Cisco, not the product."""
    out = consult("Cisco IOS XR", today=FOURTH)
    assert "RESOLUTION: VENDOR-LEVEL" in out
    assert subject_tiers_stated(out) == ("vendor",)
    assert "naming Cisco, because no finding names IOS XR:" in subject_line(out)
    assert reserved_bullets(out) == [] or \
        {tier for _, _, _, tier, _ in reserved_bullets(out)} == {"vendor"}
    full = blocks(consult("Cisco IOS XR", "--limit", "2000", "--no-locus-spread", today=FOURTH))
    vendor = collections.Counter(b["LOCUS"] for b in full
                                 if b["MATCH_TIER"] == "vendor" and b["PRIORITY"] != "CONTEXT")
    assert dist(out, "LOCUS_SUBJECT") == {l: vendor.get(l, 0) for l in LOCI}
    line = [l for l in out.splitlines() if l.startswith("LOCUS_ANALOGUE_ONLY:")][0]
    assert "none names Cisco in a class asked about:" in line, line


def test_the_analogue_line_names_the_product_not_the_vendor():
    """Exchange's LOCUS_ANALOGUE_ONLY said "none names Exchange Server, Microsoft" over findings
    naming Microsoft. Outlook and Exchange Online are other products (product_families)."""
    out = consult("Microsoft Exchange", today=FOURTH)
    line = [l for l in out.splitlines() if l.startswith("LOCUS_ANALOGUE_ONLY:")][0]
    assert "none names Exchange Server:" in line and "Exchange Server, Microsoft" not in line
    assert "DATA" in analogue_only(out)


# --- what was asked is decided per vendor ------------------------------------------------------
#
# The subject narrows only for a vendor the question named a product of. "Cisco ASA and Fortinet
# firewall" named Fortinet without one, so Fortinet's vendor-tier findings are still what was
# asked while the management centre is not; and a product whose name is its vendor's names
# nothing narrower than the vendor.

MIXED = "Cisco ASA and Fortinet firewall"


def test_reason_vendor_reads_every_vendor_reason_shape():
    """The four shapes query.vendor_reason() writes, each read as the resolved vendor it stands
    for: the per-vendor subject compares this against the question's makers."""
    assert C.reason_vendor(["vendor Cisco", "class network.firewall"]) == "Cisco"
    assert C.reason_vendor(["vendor VMware (as Broadcom)"]) == "Broadcom"
    assert C.reason_vendor(["vendor GitHub (named in product GitHub Actions)"]) == "GitHub"
    assert C.reason_vendor(["vendor Symantec (filed under Broadcom)"]) == "Symantec"
    assert C.reason_vendor(["class network.firewall"]) is None


def test_a_vendor_named_without_a_product_stays_what_was_asked():
    """Narrowing every vendor-tier finding on a product question told this one that nothing
    named Fortinet on MANAGEMENT, though the question named Fortinet and its FortiManager and
    boot-image blocks sit there. Only the management centre, another product of the ASA's
    vendor, is left out, and the counts recount from the whole match set."""
    out = consult(MIXED, today=FOURTH)
    line = subject_line(out)
    assert ("in tier product or vendor, naming Adaptive Security Appliance, Fortinet, and not "
            "tier vendor for Cisco, ") in line, line
    full = blocks(consult(MIXED, "--limit", "2000", "--no-locus-spread", today=FOURTH))

    def asked(b):
        return b["MATCH_TIER"] == "product" or (
            b["MATCH_TIER"] == "vendor" and b["TECHNOLOGY"].startswith("Fortinet /"))
    want = collections.Counter(b["LOCUS"] for b in full
                               if b["PRIORITY"] != "CONTEXT" and asked(b))
    assert dist(out, "LOCUS_SUBJECT") == {l: want.get(l, 0) for l in LOCI}
    assert want["MANAGEMENT"] and "MANAGEMENT" not in analogue_only(out)
    assert all(FMC not in key for _, _, _, _, key in reserved_bullets(out))


def test_a_product_named_by_its_vendors_own_name_keeps_the_vendor_as_what_was_asked():
    """SimpleHelp is the vendor's own name, so its vendor-tier records are SimpleHelp's."""
    out = consult("SimpleHelp", today=FOURTH)
    assert subject_tiers_stated(out) == tuple(C.NAMING_TIERS)
    assert dist(out, "LOCUS_SUBJECT") == dict(CONTROL=0, MANAGEMENT=4, DATA=0, ENDPOINT=0,
                                              SUPPLY=0, ORGANISATION=1)


# --- inside group 0, the product before the vendor's other products ------------------------------

@pytest.mark.parametrize("question", ["Cisco ASA", "Fortinet FortiGate", "Microsoft Exchange",
                                      "Cisco Firepower Threat Defense"])
def test_a_named_product_leads_the_vendors_other_products(question):
    """Product and vendor shared group 0 unordered, so the management centre led the ASA at
    ranks 1 and 2, FortiManager took ranks 2 and 3 of FortiGate and Outlook ranks 1 and 2 of
    Exchange. A named product now leads, and every block that follows it in group 0 says so
    in PRIORITY_BASIS and is tier vendor."""
    out = consult(question, "--no-locus-spread", "--limit", "400", today=FOURTH)
    found = blocks(out)
    assert found[0]["MATCH_TIER"] == "product", found[0]["FINDING_KEY"]
    zero = [b for b in found if "(group 0" in b["PRIORITY_BASIS"]]
    after = ["after what was asked" in b["PRIORITY_BASIS"] for b in zero]
    assert any(after) and after == sorted(after), question
    assert all(b["MATCH_TIER"] == "vendor" for b, late in zip(zero, after) if late)
    ordering = [l for l in out.splitlines() if l.startswith("ORDERING:")][0]
    assert "In group 0 a record naming only another of that vendor's products follows" in ordering


@pytest.mark.parametrize("question", ["Cisco", "Palo Alto Networks Panorama", "Okta",
                                      "Cisco IOS XR", MIXED])
def test_the_order_moves_only_for_another_product_of_a_named_products_vendor(question):
    """A vendor question, a product nothing names and a product named by its vendor's own name
    keep the 0.43.0 order: the vendor tier still precedes every class analogue, so "Palo Alto
    Networks Panorama" keeps the GlobalProtect record first. On the mixed question only the
    management centre follows, since Fortinet was named without a product."""
    out = consult(question, "--no-locus-spread", "--limit", "400", today=FOURTH)
    late = [b for b in blocks(out) if "after what was asked" in b["PRIORITY_BASIS"]]
    if question == MIXED:
        # Cisco's management centre follows; Fortinet, named without a product, does not.
        assert late and all(b["RECORD_ID"] == FMC for b in late)
        return
    assert not late and "after what was asked" not in out
    if question == "Palo Alto Networks Panorama":
        # The vendor tier still leads a product nothing names: no class analogue overtakes it.
        assert [b["RECORD_ID"] for b in blocks(out)[:3]] == [
            "obs-paloaltonetworks-globalprotect-command-injection"] * 3


# --- an absent locus that is shown, and --role's claims -------------------------------------------

ROLE_Q = ("Palo Alto firewall", "--role", "telemetry_source,inline_tool,control_bypassed")


def test_an_absent_locus_that_is_shown_says_so():
    """LOCUS_SHOWN counts every shown finding, eligible or not, so a locus could be counted
    there and named in LOCUS_ABSENT with nothing to reconcile the two (planes-role cosmetic 3).
    Its bullet now says how many are shown, and only where any is."""
    out = consult(*ROLE_Q, today=FOURTH)
    shown = dist(out, "LOCUS_SHOWN")
    assert any(shown.get(l) for l in absent_loci(out)), "fixture no longer shows an absent locus"
    for locus in absent_loci(out):
        bullet = absent_bullet(out, locus)
        if shown.get(locus):
            assert bullet.endswith("; shown {}, none eligible".format(shown[locus])), bullet
        else:
            assert "; shown " not in bullet, bullet


def test_a_role_filter_scopes_its_claim_that_nothing_names_it():
    """Under --role, RESOLUTION and CLASS_LEVEL_WARNING describe the kept records, and both said
    the corpus held no observation naming Palo Alto Networks while the filter had dropped one
    that does (planes-role minor 0). Each claim is now scoped and the dropped record counted;
    the unfiltered answer is unchanged."""
    out = consult(*ROLE_Q, today=FOURTH)
    res = [l for l in out.splitlines() if l.startswith("RESOLUTION:")][0]
    warn = [l for l in out.splitlines() if l.startswith("CLASS_LEVEL_WARNING:")][0]
    assert "no observation --role kept is about Palo Alto Networks" in res, res
    assert "1 observation record(s) naming it were dropped by --role" in res, res
    assert "No observation --role kept names it" in warn, warn
    for old, _ in C.ROLE_SCOPED:
        assert old not in res and old not in warn, old
    plain = consult("Palo Alto firewall", today=FOURTH)
    assert "--role kept" not in plain and "dropped by --role" not in plain


@pytest.mark.parametrize("mode", ["vendor-level", "class-level-inferred", "class-level-declared",
                                  "name-without-observations", "exposures-only"])
def test_every_claim_a_role_filter_can_falsify_is_scoped(mode):
    """Every mode main() can pass `dropped` to: not `product`, whose line makes no such claim,
    nor `unresolved`, which a --role answer reaches only once the filter has emptied it. None
    may still say that no observation names what was asked."""
    resolved = {"vendors": {"Acme"}, "products": {"Widget"}, "classes": {"app.rmm"},
                "product_pairs": {("Acme", "Widget")}}
    line, warning = C.resolution_text(mode, resolved, ["app.rmm"], [], dropped=2)
    text = "{} {}".format(line, warning or "")
    assert not re.search(r"(?i)\bno observation\b(?! --role kept)", text), text
    assert "holds no observation" not in text.lower(), text
    assert line.endswith("; 2 observation record(s) naming it were dropped by --role"), line
    plain = " ".join(filter(None, C.resolution_text(mode, resolved, ["app.rmm"], [])))
    assert "--role" not in plain, plain
