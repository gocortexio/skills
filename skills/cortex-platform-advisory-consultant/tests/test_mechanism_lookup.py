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
import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import consult as C  # noqa: E402
import query as Q  # noqa: E402

ALIASES = Q.normalise_alias_keys(json.load(open(os.path.join(ROOT, "corpus", "schema",
                                                             "aliases.json"), encoding="utf-8")))
RECORDS, PATTERNS = Q.load_corpus(os.path.join(ROOT, "corpus"))
BY_ID = {r["id"]: r for r in RECORDS}


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
    """The whole mitigation: prose hits may be wrong, so they must not outrank a subject match."""
    for tier in Q.SUBJECT_TIERS:
        assert C.MATCH_WEIGHT[tier] == C.MATCH_WEIGHT["tag"] == 1.0, tier
    assert C.MATCH_WEIGHT["pattern"] < 1.0
    assert C.MATCH_WEIGHT["summary"] < C.MATCH_WEIGHT["pattern"]
    # A word inside an unresolved name is better evidence than prose and worse than a
    # curated tag. It sits between them, and the ordering is the point.
    assert C.MATCH_WEIGHT["pattern"] < C.MATCH_WEIGHT["name-fragment"] < C.MATCH_WEIGHT["tag"]


def test_every_tier_query_knows_has_a_weight_here():
    """A tier added in query.py must not reach emit() without a weight to rank it by."""
    assert set(C.MATCH_WEIGHT) == set(Q.TIER_ORDER)


def test_match_basis_reads_the_tightest_tier_present():
    assert C.match_basis(["vendor Cisco"])[0] == "vendor"
    assert C.match_basis(["term phishing (tag)"])[0] == "tag"
    assert C.match_basis(["term x (summary)", "term y (tag)"])[0] == "tag", "tightest wins"
    assert C.match_basis(["term x (summary)"])[0] == "summary"


def test_a_word_inside_a_name_is_not_reported_as_naming_the_technology():
    """The 2026-08-27 defect. "mobile" sits inside "Endpoint Manager Mobile", so an
    Ivanti VPN gateway answered "mobile app hardening" claiming the caller had named it.
    The tier must be its own, and it must be worth less than naming the thing."""
    tier, weight = C.match_basis(["term mobile (name-fragment)"])
    assert tier == "name-fragment"
    assert weight < C.MATCH_WEIGHT["product"]


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
    assert "MATCH_TIERS: product=0, vendor=0, class=0, vendor-other-class=0," in out, \
        "nothing resolved, so nothing may claim a subject tier"
    assert "named this technology" not in out
    assert "match=productx" not in out and "match=vendorx" not in out
    assert not {l.split(": ", 1)[1] for l in out.splitlines() if l.startswith("MATCH_TIER: ")} \
        & set(Q.SUBJECT_TIERS)


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


# --- 0.43.0 ------------------------------------------------------------------------------

def test_whitespace_runs_do_not_hide_an_alias():
    """Punctuation became a space beside a space, so 110 alias keys held a run of spaces and
    matched only text punctuated exactly as the key was."""
    assert Q.normalise("Backup & Replication") == "backup replication"
    assert Q.normalise("  Check   Point \t firewall ") == "check point firewall"
    assert "Backup & Replication" in Q.resolve("Veeam Backup&Replication", ALIASES)["products"]
    assert "Check Point" in Q.resolve("Check  Point firewall", ALIASES)["vendors"]
    assert "PAN-OS" in Q.resolve("Palo Alto Networks PAN - OS", ALIASES)["products"]


def test_a_vendor_name_word_is_not_a_free_text_term():
    """"check" and "point" were searched through every record's prose once Check Point had
    resolved, and matched "integrity check" and "entry point" 188 times."""
    resolved = Q.resolve("Check Point firewall", ALIASES)
    assert not {"check", "point", "firewall"} & resolved["terms"], resolved["terms"]
    for record in RECORDS:
        reasons = Q.score(record, resolved, PATTERNS)[1]
        assert not any(r.startswith(("term check ", "term point ")) for r in reasons), record["id"]


def test_two_spellings_of_one_vendor_answer_the_same_planes():
    """The plane answer depended on how the vendor was spelt: "Palo Alto Networks firewall"
    matched 220 findings, 146 of them on the words of the vendor's own name, and reported no
    locus absent, while "PAN-OS firewall" matched 97."""
    def matched(question):
        out = run(question, "--limit", "3").stdout
        return [l for l in out.splitlines() if l.startswith("LOCUS_MATCHED:")][0]
    assert matched("Palo Alto Networks firewall") == matched("PAN-OS firewall")


def test_a_mechanism_question_consumes_nothing():
    """Nothing resolves, so every word is still searched: the mechanism reach is unchanged."""
    question = "phishing kit capturing one-time codes"
    resolved = Q.resolve(question, ALIASES)
    assert not resolved["vendors"] | resolved["products"] | resolved["classes"]
    assert resolved["terms"] == {w for w in Q.normalise(question).split()
                                 if w not in Q.NOISE and len(w) > 2}


@pytest.mark.parametrize("record_id,question,product", [
    ("exp-kev-teamviewer-desktop", "Docker Desktop", "Desktop"),
    ("exp-kev-check-point-multiple-products", "Apple multiple products", "Multiple Products"),
])
def test_a_product_string_shared_across_vendors_scores_only_for_the_named_vendor(
        record_id, question, product):
    """"Desktop" is Docker's and TeamViewer's, and "Multiple Products" eighteen vendors'. The
    string alone gave another vendor's record product weight."""
    reasons = Q.score(BY_ID[record_id], Q.resolve(question, ALIASES), PATTERNS)[1]
    assert "product {}".format(product) not in reasons, reasons



# --- a name the corpus does not know, padded with ordinary words ----------------------------

def header(out, key):
    found = [l for l in out.splitlines() if l.startswith(key + ":")]
    return found[0] if found else None


def test_an_unknown_name_in_a_mechanism_answer_is_called_out():
    """"Zorblax Edge Gateway 9000" was answered as a confident mechanism answer: 247 findings
    about other vendors' edge devices, reached by "edge" and "gateway", while the two words
    naming the product reached nothing and nothing said so."""
    out = run("Zorblax Edge Gateway 9000", "--limit", "3").stdout
    assert "RESOLUTION: mechanism" in out
    assert header(out, "UNMATCHED_TERMS") == "UNMATCHED_TERMS: 9000, zorblax"
    warning = header(out, "MECHANISM_WARNING")
    assert warning and warning.startswith("MECHANISM_WARNING: 9000, zorblax reached no record")
    assert "network.vpn_gateway" in header(out, "CANDIDATE_CLASSES")


@pytest.mark.parametrize("question", ["phishing", "prompt injection", "mobile app hardening",
                                      "ransomware against hospitals",
                                      "runtime application self-protection"])
def test_an_ordinary_mechanism_question_has_nothing_to_warn_about(question):
    out = run(question, "--limit", "3").stdout
    assert header(out, "UNMATCHED_TERMS") == "UNMATCHED_TERMS: none", question
    assert "MECHANISM_WARNING:" not in out


def test_an_ordinary_word_that_reached_nothing_is_listed_and_not_warned_about():
    """The warning names only words written with a capital or a digit, since an ordinary word
    that reached nothing says nothing about the question."""
    assert C.proper_terms("Zorblax edge gateway 9000", {"zorblax", "9000", "edge"}) \
        == {"zorblax", "9000"}
    assert C.proper_terms("quimbleflopsy phishing", {"quimbleflopsy"}) == set()


def test_a_refining_word_is_not_reported_unmatched():
    """The leftover words of a named answer reorder it; listing them as unmatched would say
    they reached nothing."""
    out = run("Fortinet FortiGate boot image implant", "--limit", "3").stdout
    assert header(out, "UNMATCHED_TERMS") == "UNMATCHED_TERMS: none"
    assert C.reached_terms(["refine term boot (pattern)", "term phishing (tag)",
                            "term check point (name-fragment)", "vendor Cisco"]) \
        == {"boot", "phishing", "check point"}
