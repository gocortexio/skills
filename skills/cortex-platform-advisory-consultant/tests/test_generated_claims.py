# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A sentence a generator writes about the rest of the corpus must still be true of it.

The KEV generator tells a reader when an exposure's identifiers are "already carried by an
observation record in this corpus, which holds the detection logic", and tags the record
`also-in-observation-record`. It counts that overlap once, at generation time, against the
observations as they then stood. When an observation is corrected the count goes stale and
nothing says so. Six watchTowr syntheses carried identifiers their sources did not name, and
seven exposure records owed the sentence to those identifiers alone: the EPMM record said four
identifiers were covered when two were, and the Sentry record sent its reader to
X-Forwarded-For logic for an OS command injection.

The test recomputes the overlap from the corpus the bundle ships, so it fails whenever an
observation changes without the KEV generator being re-run, which is the point.

Run with PYTHONDONTWRITEBYTECODE=1 (LAW A26).
"""
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RECORDS = []
with open(os.path.join(ROOT, "corpus", "observations", "observations.jsonl"), encoding="utf-8") as h:
    for line in h:
        if line.strip():
            RECORDS.append(json.loads(line))

OBSERVED = set()
CARRIERS = {}
for _r in RECORDS:
    if _r.get("record_type") == "observation":
        OBSERVED |= set((_r.get("what") or {}).get("vulnerabilities") or [])
        for _v in (_r.get("what") or {}).get("vulnerabilities") or []:
            CARRIERS.setdefault(_v, set()).add(_r["id"])
KEV = [r for r in RECORDS if r["id"].startswith("exp-kev-")]
OVERLAP = re.compile(r"(\d+) of these identifiers (?:is|are) already carried by (?:an observation "
                     r"record|observation records) in this corpus: ([a-z0-9-]+(?:, [a-z0-9-]+)*)\.")


def test_kev_overlap_sentence_counts_what_the_observations_carry():
    bad = []
    for record in KEV:
        covered = len(set(record["what"]["vulnerabilities"]) & OBSERVED)
        stated = OVERLAP.search(record["what"]["summary"])
        said = int(stated.group(1)) if stated else 0
        tagged = "also-in-observation-record" in (record.get("tags") or [])
        if said != covered or tagged != bool(covered):
            bad.append("{} says {} covered{}; the observations carry {}".format(
                record["id"], said, " and is tagged" if tagged else "", covered))
    assert not bad, "re-run the KEV generator against this corpus:\n" + "\n".join(bad)


def test_kev_overlap_sentence_names_the_observations_that_carry_them():
    """0.43.0: the sentence said an identifier was "already carried by an observation record"
    and named none, so the Linux kernel's one exploited-kernel observation could not be found
    from its own catalogue record. It names every carrier now, and no longer claims the
    carrier "holds the detection logic": the kernel step of that record has no markers."""
    bad = []
    for record in KEV:
        stated = OVERLAP.search(record["what"]["summary"])
        if not stated:
            continue
        named = set(stated.group(2).split(", "))
        carriers = {rid for v in record["what"]["vulnerabilities"] for rid in CARRIERS.get(v, ())}
        if named != carriers:
            bad.append("{} names {}; the carriers are {}".format(
                record["id"], sorted(named), sorted(carriers)))
        if "holds the detection logic" in record["what"]["summary"]:
            bad.append("{} still says the carrier holds the detection logic".format(record["id"]))
    assert not bad, "re-run the KEV generator against this corpus:\n" + "\n".join(bad)
    kernel = BY_ID_ALL["exp-kev-linux-kernel"]["what"]["summary"]
    assert "obs-osgeo-geoserver-remote-code-execution" in kernel, kernel


BY_ID_ALL = {r["id"]: r for r in RECORDS}


def test_the_epmm_and_sentry_records_no_longer_borrow_the_x_forwarded_for_record():
    """The two records the Ivanti synthesis inflated, pinned by name."""
    by_id = {r["id"]: r for r in KEV}
    epmm = by_id["exp-kev-ivanti-endpoint-manager-mobile-epmm"]
    sentry = by_id["exp-kev-ivanti-sentry"]
    assert "2 of these identifiers are already carried" in epmm["what"]["summary"]
    assert "already carried" not in sentry["what"]["summary"]
    assert "also-in-observation-record" not in sentry["tags"]


# ---------------------------------------------------------------- 0.43.0: the other families

BY_ID = {r["id"]: r for r in RECORDS}
ZDI = [r for r in RECORDS if r["id"].startswith("exp-zdi-")]
PSIRT = [r for r in RECORDS if r["id"].startswith("exp-psirt-")]
NVD = [r for r in RECORDS if r["id"].startswith("exp-nvd-")]
KEV_IDS = set()
for _r in KEV:
    KEV_IDS |= set(_r["what"]["vulnerabilities"])


def test_a_kev_year_span_is_not_claimed_across_a_gap():
    """The generator wrote "each year from A to B" for any three years or more, so 32 of the
    49 records using it named a year with no identifier added. kev.json does not ship, so the
    two worst are pinned by their own years and every span is held to the one bound the
    corpus can check: a span of Y years needs at least Y identifiers."""
    epmm = BY_ID["exp-kev-ivanti-endpoint-manager-mobile-epmm"]["what"]["summary"]
    f5 = BY_ID["exp-kev-f5-big-ip"]["what"]["summary"]
    assert "added to it in 2023, 2025 and 2026." in epmm, epmm
    assert "added to it in 2021, 2022 and 2026." in f5, f5
    bad = []
    for record in KEV:
        span = re.search(r"each year from (\d{4}) to (\d{4})", record["what"]["summary"])
        if span and int(span.group(2)) - int(span.group(1)) + 1 > len(record["what"]["vulnerabilities"]):
            bad.append("{} claims {} years from {} identifiers".format(
                record["id"], int(span.group(2)) - int(span.group(1)) + 1,
                len(record["what"]["vulnerabilities"])))
    assert not bad, "\n".join(bad)


LEAD = re.compile(r"^(\d+) advisor(?:y|ies) published by a coordinated disclosure programme "
                  r"against .+?, carrying (no CVE identifier, so (?:it|each) is listed by programme identifier"
                  r"|(\d+) distinct CVE identifiers?)"
                  r"(?:; (\d+) carr(?:y|ies) no CVE and (?:is|are) listed by programme identifier)?"
                  r"(?:; (\d+) repeats? a CVE another of these advisories already carries)?\.")
PROGRAMME_ID = re.compile(r"^ZDI-\d{2}-\d{3,}$")


def test_a_zdi_advisory_count_reconciles_with_its_identifiers():
    """14 of 67 records did not reconcile: the lead counted advisories, the record carried
    distinct CVEs, and advisories with no CVE, or sharing one, fell between the two. Four
    records carried no identifier at all and passed validation only on a boilerplate
    versions_affected. Now n = m + k + j, and what the record lists is the m CVEs plus the
    k programme identifiers."""
    bad = []
    for record in ZDI:
        lead = LEAD.match(record["what"]["summary"])
        if not lead:
            bad.append("{}: lead sentence not in the reconciled form".format(record["id"]))
            continue
        n = int(lead.group(1))
        if lead.group(3) is None:  # no CVE at all, so every advisory is a programme identifier
            m, k, j = 0, n, 0
        else:
            m, k, j = int(lead.group(3)), int(lead.group(4) or 0), int(lead.group(5) or 0)
        vulns = record["what"]["vulnerabilities"]
        programme = [v for v in vulns if not v.startswith("CVE-")]
        if n != m + k + j or len(vulns) != m + k or len(programme) != k:
            bad.append("{}: n={} m={} k={} j={} but carries {} ({} programme)".format(
                record["id"], n, m, k, j, len(vulns), len(programme)))
        bad += ["{}: {!r} is not a programme identifier".format(record["id"], v)
                for v in programme if not PROGRAMME_ID.match(v)]
    assert not bad, "\n".join(bad)
    assert BY_ID["exp-zdi-microsoft-azure"]["what"]["vulnerabilities"] == ["ZDI-26-226", "ZDI-26-629"]


REACH = re.compile(r"(\d+) (?:is|are) reachable by a remote or network-adjacent attacker"
                   r"(?:, (\d+) needs? local access first)?(?:,? and (\d+) needs? local access first)?"
                   r"(?:,? and (\d+) needs? physical presence)?\.")
INTERNET = {"internet_facing_management", "internet_facing_service", "api_endpoint"}


def _kev_surface_by_class():
    """The class-to-surface table the KEV generator applies, read back from its records."""
    table = {}
    for record in KEV:
        table.setdefault(record["who"]["product_class"][0], set()).add(record["what"]["attack_surface"])
    return table


def test_a_generated_surface_follows_the_majority_attacker_position():
    """ZDI put every product on internet_facing_management if ANY advisory was remote: two
    remote advisories out of forty put the Linux kernel there, and the locus map commits that
    value to MANAGEMENT. A local or physical majority must not read as internet-facing, and a
    remote majority takes the same surface a KEV record of the class carries."""
    kev_surface = _kev_surface_by_class()
    bad = []
    for record in ZDI:
        reach = REACH.search(record["what"]["summary"])
        assert reach, "{}: no attacker-position sentence".format(record["id"])
        remote = int(reach.group(1))
        local = int(reach.group(2) or reach.group(3) or 0)
        physical = int(reach.group(4) or 0)
        stated = remote + local + physical
        surface = record["what"]["attack_surface"]
        first = record["who"]["product_class"][0]
        if 2 * remote < stated and surface in INTERNET:
            bad.append("{}: {} of {} reachable remotely, surface {}".format(
                record["id"], remote, stated, surface))
        if 2 * remote >= stated and first in kev_surface and {surface} != kev_surface[first]:
            bad.append("{}: remote majority on {} carries {}, the KEV records carry {}".format(
                record["id"], first, surface, sorted(kev_surface[first])))
    assert not bad, "\n".join(bad)


def test_psirt_and_database_surfaces_come_from_the_class_table_not_a_constant():
    """All 99 carried internet_facing_management, a constant, which made FortiClient and the
    Nokia base stations management-plane findings by default."""
    kev_surface = _kev_surface_by_class()
    bad = []
    for record in PSIRT + NVD:
        first = record["who"]["product_class"][0]
        if first in kev_surface and {record["what"]["attack_surface"]} != kev_surface[first]:
            bad.append("{}: {} carries {}, the KEV records carry {}".format(
                record["id"], first, record["what"]["attack_surface"], sorted(kev_surface[first])))
    assert not bad, "\n".join(bad)
    surfaces = {r["what"]["attack_surface"] for r in PSIRT + NVD}
    assert len(surfaces) > 1, "every PSIRT and database record carries one surface again: {}".format(surfaces)


def test_generated_exposures_land_on_the_plane_their_class_names():
    """The three records the surface constant misplaced, derived as consult.py derives them."""
    import sys
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    import consult
    locus_map = consult.load_locus_map(os.path.join(ROOT, "corpus"))
    got = {rid: consult.locus_for(BY_ID[rid], None, None, locus_map)[0]
           for rid in ("exp-zdi-linux-kernel", "exp-zdi-microsoft-windows", "exp-zdi-microsoft-exchange")}
    assert got == {"exp-zdi-linux-kernel": "ENDPOINT", "exp-zdi-microsoft-windows": "ENDPOINT",
                   "exp-zdi-microsoft-exchange": "DATA"}, got


def test_no_record_that_denies_kev_membership_carries_a_kev_identifier():
    """Five ZDI records and one database record said their identifiers were not in the
    catalogue while the KEV records beside them listed one each. The ZDI generator never read
    the catalogue; the database generator read it once, at collection. Read from the corpus
    alone, so a KEV refresh that overtakes an older record fails here too."""
    bad, denied = [], 0
    for record in ZDI + PSIRT + NVD:
        tags = record.get("tags") or []
        vulns = set(record["what"]["vulnerabilities"])
        held = sorted(vulns & KEV_IDS)
        summary = record["what"]["summary"]
        if "not-in-kev" in tags:
            denied += 1
            if held:
                bad.append("{} is tagged not-in-kev and carries {}".format(record["id"], held))
        elif "in-kev" in tags:
            if not held or any(c not in summary for c in held):
                bad.append("{} is tagged in-kev and its summary does not name {}".format(record["id"], held))
            if re.search(r"none of them|not present in the authoritative catalogue", summary, re.I):
                bad.append("{} is tagged in-kev and its summary still denies it".format(record["id"]))
        else:
            bad.append("{} carries neither in-kev nor not-in-kev".format(record["id"]))
    assert not bad, "\n".join(bad)
    assert denied > 150, "the denial check is reading {} records".format(denied)
    for rid in ("exp-zdi-progress-kemp-loadmaster", "exp-nvd-citrix-citrix-netscaler"):
        assert "in-kev" in BY_ID[rid]["tags"], rid


def test_every_generated_where_block_records_when_it_was_read():
    """KEV carried source_id, retrieved and verified; all 166 ZDI, PSIRT and database
    records carried none of the three."""
    bad = ["{}: {}".format(r["id"], k) for r in ZDI + PSIRT + NVD
           for k in ("source_id", "retrieved", "verified") if k not in r["where"]]
    assert not bad, "\n".join(bad[:20])
    assert all(r["where"]["verified"] is True for r in ZDI + PSIRT + NVD)


def test_zdi_is_not_labelled_as_the_affected_vendors_advisory():
    """vocab.json defines vendor_advisory as the affected vendor's own advisory. ZDI is a
    third-party programme, and each record cited one advisory of up to forty under a title
    the generator wrote."""
    assert ZDI
    for record in ZDI:
        where = record["where"]
        assert where["publisher"] == "Zero Day Initiative"
        assert where["source_type"] != "vendor_advisory", record["id"]
        assert where["title"] == "Published Advisories", (record["id"], where["title"])
        assert "/advisories/published/" in where["url"], (record["id"], where["url"])


def test_the_validator_refuses_a_kev_tag_the_corpus_contradicts():
    """EXP-7. The shipped corpus has none, and the check fires both ways on a record built to."""
    import subprocess
    import sys
    done = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "validate.py")],
                          capture_output=True, text=True, cwd=ROOT)
    assert "in-kev" not in done.stdout, done.stdout
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    import validate
    problems = []
    validate.check_kev_membership([("a", ["not-in-kev"], ["CVE-2026-0001"]),
                                   ("b", ["in-kev"], ["CVE-2026-0002"]),
                                   ("c", ["not-in-kev"], ["CVE-2026-0002"])],
                                  {"CVE-2026-0001"}, problems)
    assert [p.where for p in problems] == ["a", "b"], [str(p) for p in problems]
