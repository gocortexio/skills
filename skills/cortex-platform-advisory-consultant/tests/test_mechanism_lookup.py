# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Asking by mechanism rather than by technology.

Until 0.22.0 the free-text fallback searched vendor, products and class suffixes only, so
a word that is not a technology matched nothing anywhere: `phishing` returned 0 of 1,209
records. The haystack now includes tags, the cited pattern's wording and the record
summary, which the 2026-08-19 measurement showed takes thirty mechanism terms from 33
record-hits to 1,124 -- and brings 31 records that answer a vendor query they are not
about. That cost was accepted deliberately in exchange for the reach, so these tests hold
the mitigations rather than the reach: tiers must stay ordered, loose matches must be
demoted below tight ones, and every finding must say which tier it arrived on.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import consult as C  # noqa: E402
import query as Q  # noqa: E402


def run(*args):
    return subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "consult.py")]
                          + list(args) + ["--today", "2026-08-19"],
                          capture_output=True, text=True, cwd=ROOT)


def test_a_mechanism_word_now_reaches_records():
    """The defect this was built for: 'phishing' returned nothing from 1,209 records."""
    out = run("phishing", "--limit", "5").stdout
    line = [l for l in out.splitlines() if l.startswith("FINDINGS:")][0]
    assert " 0 shown of 0 matched" not in line, line


def test_a_mechanism_question_is_not_reported_as_unresolved():
    """It resolves to no vendor, but it is an answer, not a dead end."""
    out = run("phishing", "--limit", "3").stdout
    assert "RESOLUTION: mechanism" in out
    assert "NOTHING MATCHED" not in out


def test_a_word_in_nothing_at_all_is_still_unresolved():
    out = run("quimbleflopsy")
    assert "RESOLUTION: UNRESOLVED" in out.stdout
    assert out.returncode == 1


def test_every_finding_declares_which_tier_it_matched_on():
    out = run("phishing", "--limit", "6").stdout
    blocks = out.split("=== FINDING ")[1:]
    assert blocks and all("MATCH_BASIS:" in b for b in blocks)


def test_loose_matches_are_demoted_below_tight_ones():
    """The whole mitigation: prose hits may be wrong, so they must not outrank identity."""
    assert C.MATCH_WEIGHT["identity"] == C.MATCH_WEIGHT["tag"] == 1.0
    assert C.MATCH_WEIGHT["pattern"] < 1.0
    assert C.MATCH_WEIGHT["summary"] < C.MATCH_WEIGHT["pattern"]
    # A word inside an unresolved name is better evidence than prose and worse than a
    # curated tag. It sits between them, and the ordering is the point.
    assert C.MATCH_WEIGHT["pattern"] < C.MATCH_WEIGHT["name-fragment"] < C.MATCH_WEIGHT["tag"]


def test_every_tier_query_knows_has_a_weight_here():
    """A tier added in query.py must not reach emit() without a weight to rank it by."""
    assert set(C.MATCH_WEIGHT) == set(Q.TIER_ORDER)


def test_match_basis_reads_the_tightest_tier_present():
    assert C.match_basis(["vendor Cisco"])[0] == "identity"
    assert C.match_basis(["term phishing (tag)"])[0] == "tag"
    assert C.match_basis(["term x (summary)", "term y (tag)"])[0] == "tag", "tightest wins"
    assert C.match_basis(["term x (summary)"])[0] == "summary"


def test_a_word_inside_a_name_is_not_reported_as_naming_the_technology():
    """The 2026-08-27 defect. "mobile" sits inside "Endpoint Manager Mobile", so an
    Ivanti VPN gateway answered "mobile app hardening" claiming the caller had named it.
    The tier must be its own, and it must be worth less than naming the thing."""
    tier, weight = C.match_basis(["term mobile (name-fragment)"])
    assert tier == "name-fragment"
    assert weight < C.MATCH_WEIGHT["identity"]


def test_an_unrecognised_reason_shape_gets_the_weakest_tier_not_the_tightest():
    """Failing open here is what made a coincidence read like an answer."""
    assert C.match_basis(["something nobody wrote"])[0] == "summary"
    assert C.match_basis(["term x (a tier that does not exist)"])[0] == "summary"


def test_a_term_scores_once_at_its_tightest_tier():
    """A word present as both tag and prose must not be paid for twice."""
    record = {"who": {"vendor": "Acme", "products": [], "product_class": []},
              "tags": ["phishing"], "what": {"summary": "a phishing campaign"}, "how": []}
    resolved = {"vendors": set(), "products": set(), "classes": set(), "sectors": set(),
                "terms": {"phishing"}}
    points, reasons = Q.score(record, resolved)
    assert points == 2, (points, reasons)
    assert reasons == ["term phishing (tag)"], reasons


def test_a_vendor_query_still_leads_with_records_about_that_vendor():
    """Reach must not have cost the primary use case."""
    out = run("Cisco", "--limit", "10").stdout
    blocks = out.split("=== FINDING ")[1:]
    assert blocks
    first_five = " ".join(blocks[:5])
    assert "LOOSE" not in first_five, "loose matches reached the top five of a vendor query"


def test_a_mechanism_query_does_not_claim_the_technology_was_named():
    """The acceptance test for the 2026-08-27 defect, and the reason MATCH_TIERS exists.

    Asserted against the tally rather than against a record id, so that a corpus which
    grows past the Ivanti VPN still holds the invariant: if the header says nothing
    resolved by name, no finding may say the caller named it.
    """
    out = run("mobile app hardening", "--limit", "40").stdout
    assert "RESOLVED_TO: vendors=- | products=- | classes=-" in out
    assert "MATCH_TIERS: identity=0," in out, "nothing resolved, so nothing may claim identity"
    assert "named this technology" not in out
    assert "match=identityx" not in out


def test_a_class_alias_may_name_more_than_one_class():
    """"mdm" is a mobile enrolment console and fleet-management tooling both.

    Retargeting it to app.mdm alone took the question from 63 findings to 4 -- a thinner
    answer that reads as a safer one, which is the failure this corpus is built to catch.
    SKILL.md tells a caller to name every class the technology behaves as; the alias table
    can do the same.
    """
    aliases = {"vendor_aliases": {}, "product_aliases": {},
               "class_aliases": {"mdm": ["app.mdm", "app.rmm"], "firewall": "network.firewall"},
               "sector_aliases": {}}
    resolved = Q.resolve("mdm", Q.normalise_alias_keys(aliases))
    assert resolved["classes"] == {"app.mdm", "app.rmm"}
    # A scalar value must still resolve, or every other alias in the table breaks.
    assert Q.resolve("firewall", Q.normalise_alias_keys(aliases))["classes"] == {"network.firewall"}


def test_a_product_alias_may_name_more_than_one_class():
    """Same failure as the class alias, one level down.

    Moving EPMM's alias from app.rmm to app.mdm alone took that question from 74 findings
    to 17: the MDM records arrived and the fleet-management context that had been carrying
    it left. A product belongs to every class it behaves as.
    """
    aliases = {"vendor_aliases": {}, "sector_aliases": {}, "class_aliases": {},
               "product_aliases": {
                   "epmm": {"vendor": "Ivanti", "product": "Endpoint Manager Mobile",
                            "product_class": ["app.mdm", "app.rmm"]},
                   "asa": {"vendor": "Cisco", "product": "ASA",
                           "product_class": "network.firewall"}}}
    resolved = Q.resolve("epmm", Q.normalise_alias_keys(aliases))
    assert resolved["classes"] == {"app.mdm", "app.rmm"}
    assert resolved["products"] == {"Endpoint Manager Mobile"}
    # A scalar must still resolve, or every other product in the table breaks.
    assert Q.resolve("asa", Q.normalise_alias_keys(aliases))["classes"] == {"network.firewall"}
