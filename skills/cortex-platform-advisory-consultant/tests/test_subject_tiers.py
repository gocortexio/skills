# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""What the ranking puts first, for each of the questions consult.py says it answers.

The coverage question -- "what should I build that I have not got" -- is answered by
`--rank-by gap`, which multiplies a covered finding's weight down so that it sinks. Nothing
tested that it sinks. The only gap-mode assertion anywhere was the key-set test, so an
ordering change that put covered findings back at the top would have inverted one of the
three advertised questions with the suite green. A proposed grouping of the sort key by
match tier, ahead of the weight, does exactly that: the covered vendor findings form the
first group and the multiplier can only reorder them inside it.

This test passes against the ranking as it stands and exists to keep passing through any
change to the sort key.

Run with PYTHONDONTWRITEBYTECODE=1 (LAW A26).
"""
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
import query  # noqa: E402

TODAY = "2026-09-25"
ALIASES = query.normalise_alias_keys(json.loads((CORPUS / "schema" / "aliases.json").read_text(
    encoding="utf-8")))
RECORDS, PATTERNS = query.load_corpus(str(CORPUS))
BY_ID = {r["id"]: r for r in RECORDS}


def reasons(record_id, question):
    return query.score(BY_ID[record_id], query.resolve(question, ALIASES), PATTERNS)[1]


def covered_inventory(vendor, items=12):
    """A caller's coverage list naming what they have built for one vendor's own findings.

    The rich 'Name: what it produces' form, built from the names and descriptions of the
    patterns that vendor's records cite, so the heuristic has something to say yes to.
    Derived from the corpus rather than written out, so a re-worded pattern cannot leave the
    fixture matching nothing.
    """
    records, patterns = query.load_corpus(str(CORPUS))
    out = []
    for record in records:
        if (record.get("who") or {}).get("vendor") != vendor:
            continue
        for how in record.get("how") or []:
            pattern = patterns.get(how.get("pattern_id"))
            if pattern:
                out.append("{}: {}".format(
                    re.sub(r"[^A-Za-z]", "", pattern["name"].title())[:40],
                    pattern["description"][:160].replace(",", " ")))
    return out[:items]


def consult(*argv):
    done = subprocess.run([sys.executable, str(SCRIPTS / "consult.py"), *argv],
                          capture_output=True, text=True, timeout=180)
    assert done.returncode == 0, done.stderr
    return done


def test_gap_ranking_still_sinks_what_is_covered(tmp_path):
    inventory = tmp_path / "covered.txt"
    inventory.write_text("\n".join(covered_inventory("Fortinet")) + "\n", encoding="utf-8")
    common = ["Fortinet FortiGate", "--covered", str(inventory), "--no-locus-spread",
              "--limit", "12", "--today", TODAY]

    # Without the demotion the covered findings are in the top twelve, so it is gap mode,
    # and nothing else, that has to move them out.
    ranked = consult(*common, "--rank-by", "criticality")
    assert "YES" in re.findall(r"^COVERAGE: (\w+)$", ranked.stdout, re.M), \
        "fixture's covered findings no longer rank in the top 12 on criticality"

    done = consult(*common, "--rank-by", "gap")

    tally = re.search(r"^COVERAGE_TALLY: (.*?)  \(", done.stdout, re.M)
    assert tally, done.stdout[:800]
    counts = {k: int(v) for k, v in (part.split("=") for part in tally.group(1).split(", "))}
    # The fixture has to put covered findings in the match set and leave at least a page
    # of uncovered ones, or the assertion below holds for no reason.
    assert counts.get("yes", 0) >= 1, "fixture no longer produces a covered finding: {}".format(counts)
    assert counts.get("no", 0) + counts.get("partial", 0) >= 12, \
        "fixture no longer leaves twelve uncovered findings: {}".format(counts)

    shown = re.findall(r"^COVERAGE: (\w+)$", done.stdout, re.M)
    assert len(shown) == 12
    assert "YES" not in shown, \
        "gap ranking put {} covered finding(s) in the top 12 while {} uncovered ones were " \
        "available".format(shown.count("YES"), counts.get("no", 0) + counts.get("partial", 0))


# --- one product matcher, for observations and exposures alike ----------------------------

@pytest.mark.parametrize("record_id,question,reason", [
    ("obs-broadcom-vmware-esxi-configuration-file-encryption-and-recovery", "Broadcom ESXi",
     "product VMware ESXi"),
    # The record lists the old name too, which product_families names as the same product.
    ("obs-cisco-secure-firewall-management-center-static-credential-login",
     "Cisco secure firewall management center (fmc)",
     "product Firepower Management Center (as Secure Firewall Management Center (FMC)), "
     "Secure Firewall Management Center"),
    ("exp-kev-ivanti-endpoint-manager-mobile-epmm", "Ivanti EPMM",
     "product Endpoint Manager Mobile (EPMM)"),
    ("exp-kev-check-point-quantum-security-gateways", "Check Point Quantum Security Gateway",
     "product Quantum Security Gateways"),
])
def test_a_product_spelt_differently_still_names_it(record_id, question, reason):
    """Exact string equality missed twelve products that have observations: the alias table
    spells them as the catalogue does ("ESXi"), the records as the vendor does ("VMware
    ESXi"), with an abbreviation in brackets or a plural."""
    assert reason in reasons(record_id, question)
    assert query.exposure_tier(BY_ID[record_id], query.resolve(question, ALIASES)) == "product" \
        or not record_id.startswith("exp-")


@pytest.mark.parametrize("record_id,question", [
    ("obs-ivanti-epmm-authentication-bypass-and-arbitrary-file-write-chain",
     "Ivanti endpoint manager"),
    ("exp-kev-check-point-quantum-security-gateways", "Check Point security gateway"),
])
def test_a_shorter_product_name_is_not_the_longer_product(record_id, question):
    """Token containment was measured as the alternative and matched Endpoint Manager (EPM) to
    Endpoint Manager Mobile. Canonical equality does not, and neither does "Security Gateway"
    to Quantum Security Gateways."""
    assert not any(r.startswith("product ") for r in reasons(record_id, question))


def test_one_matcher_serves_both_callers():
    """score() and exposure_tier() both read product_matches(), so they cannot disagree."""
    resolved = query.resolve("Apple multiple products", ALIASES)
    other = BY_ID["exp-kev-check-point-multiple-products"]
    assert not query.product_matches(resolved, other)
    assert query.product_matches(resolved, other, any_vendor=True) == {"Multiple Products"}
    assert query.exposure_tier(other, resolved) == "product-name-other-vendor"


# --- the words a resolved alias already accounted for -------------------------------------

def test_resolved_words_are_not_searched_again():
    resolved = query.resolve("Check Point firewall", ALIASES)
    assert resolved["terms"] == set()
    assert "check point" in resolved["name_phrases"]
    out = consult("Check Point firewall", "--today", TODAY, "--limit", "3").stdout
    tiers = [l for l in out.splitlines() if l.startswith("MATCH_TIERS:")][0]
    assert "pattern=0, summary=0" in tiers, tiers


def test_a_vendor_phrase_still_reaches_a_name_it_sits_in():
    """The whole phrase is searched in names, so a record naming "Fortinet appliances" under
    vendor any is still reached -- now as the vendor it names, not as a word fragment."""
    got = reasons("obs-generic-state-affiliated-ransom-operations-from-known-vulnerabilities",
                  "Fortinet FortiGate")
    assert "vendor Fortinet (named in product Fortinet appliances)" in got, got


def test_a_phrase_is_searched_whole_and_only_in_names():
    """"point" alone hit "Access Point" and "point of sale"; "check point" hits neither."""
    resolved = query.resolve("Check Point firewall", ALIASES)
    hay_hits = [r["id"] for r in RECORDS
                if any(x.startswith("term check point ")
                       for x in query.score(r, resolved, PATTERNS)[1])]
    for record_id in hay_hits:
        names = query.free_text_haystacks(BY_ID[record_id], PATTERNS)["name-fragment"]
        assert re.search(r"\bcheck point\b", names), record_id


# --- words left over once the technology resolved -----------------------------------------

def test_qualifying_words_refine_a_named_answer_without_changing_its_score():
    record = "obs-fortinet-appliance-implant-persisting-in-the-boot-image"
    question = "Fortinet FortiGate boot image implant"
    points, why = query.score(BY_ID[record], query.resolve(question, ALIASES), PATTERNS)
    assert points == query.score(BY_ID[record], query.resolve("Fortinet FortiGate", ALIASES),
                                 PATTERNS)[0] == 13
    assert {"refine term boot (pattern)", "refine term image (pattern)",
            "refine term implant (pattern)"} <= set(why), why


def test_a_refining_word_decides_a_tie_and_is_printed():
    """Two Fortinet records score 13. The one carrying all three of the question's leftover
    words now comes first in query.py, and consult.py prints the words on PRIORITY_BASIS."""
    done = subprocess.run([sys.executable, str(SCRIPTS / "query.py"),
                           "Fortinet FortiGate boot image implant", "--json", "--limit", "2"],
                          capture_output=True, text=True, timeout=180)
    first = json.loads(done.stdout)["records"][0]
    assert first["record"]["id"] == "obs-fortinet-appliance-implant-persisting-in-the-boot-image"
    assert first["tiebreak"]["refined_by"] == ["boot", "image", "implant"]
    out = consult("Fortinet FortiGate boot image implant", "--today", TODAY,
                  "--no-locus-spread", "--limit", "400").stdout
    block = out.split("RECORD_ID: obs-fortinet-appliance-implant-persisting-in-the-boot-image")[0]
    basis = [l for l in block.splitlines() if l.startswith("PRIORITY_BASIS:")][-1]
    assert basis.endswith("refined_by=boot,image,implant"), basis


def test_a_refining_word_never_decides_the_match_tier():
    import consult as C
    assert C.match_basis(["class network.firewall", "refine term boot (pattern)"])[0] == "class"
    assert C.match_basis(["refine term boot (pattern)"])[0] == "summary", \
        "a refine reason alone is not a match, and must fail to the weakest tier"


# --- a vendor named inside a generic record's products ------------------------------------

def test_a_vendor_named_inside_a_generic_records_products_is_a_vendor_match():
    """Eleven observations list GitHub under vendor any, and "GitHub" was told no record is
    about it."""
    got = reasons("obs-generic-stolen-forge-token-drives-mass-repository-exfiltration", "GitHub")
    assert any(r.startswith("vendor GitHub") for r in got), got
    out = consult("GitHub", "--today", TODAY).stdout
    assert "NAME_WITHOUT" not in [l for l in out.splitlines() if l.startswith("RESOLUTION:")][0]
    vendor = int(re.search(r"^MATCH_TIERS: product=\d+, vendor=(\d+),", out, re.M).group(1))
    assert vendor >= 11, vendor
    absent = [l for l in out.splitlines() if l.startswith("LOCUS_ABSENT:")][0]
    assert "SUPPLY" not in absent, absent


def test_a_vendor_named_in_another_class_does_not_make_the_answer_product_level():
    """"Guardsquare ... Android and iOS apps" resolves the Android vendor and two pipeline
    classes. A botnet record listing "Android TV boxes" names Android in neither class, which
    is the vendor's other history, and must not turn the class-level answer into a product one."""
    import consult as C
    question = "Guardsquare mobile application runtime protection, protected Android and iOS apps"
    resolved = query.resolve(question, ALIASES)
    why = reasons("obs-generic-consumer-media-device-botnet-hardens-c2-through-name-service",
                  question)
    assert any(r.startswith("vendor Android (named in product") for r in why), why
    assert not C.names_what_was_asked(why, resolved)



def test_a_vendor_named_in_another_class_is_weighed_as_a_name_fragment():
    """Counted or not, the botnet record was weighed as a subject match, at full weight and
    labelled as naming the technology, and it reached the Guardsquare top 12. Where the question
    resolved a class the record does not carry, the match is the name fragment it is; where
    the question resolved no class ("GitHub") it is the vendor."""
    import consult as C
    question = "Guardsquare mobile application runtime protection, protected Android and iOS apps"
    why = reasons("obs-generic-consumer-media-device-botnet-hardens-c2-through-name-service",
                  question)
    assert C.match_basis(why, query.resolve(question, ALIASES))[0] == "name-fragment"
    github = reasons("obs-generic-stolen-forge-token-drives-mass-repository-exfiltration",
                     "GitHub")
    assert C.match_basis(github, query.resolve("GitHub", ALIASES))[0] == "vendor"
    out = consult(question, "--today", TODAY).stdout
    assert "obs-generic-consumer-media-device-botnet-hardens-c2-through-name-service" \
        not in out, "the TV-box botnet is back in the Guardsquare top 12"


@pytest.mark.parametrize("question,sector", [
    ("Fortinet FortiManager in healthcare", "sector healthcare"),
    ("Fortinet FortiManager in a water utility", "cross-sector"),
])
def test_a_sector_does_not_undo_the_name_fragment_demotion(question, sector):
    """A sector reason is structured, and match_basis() took the tightest tier, so naming a
    sector re-promoted the demoted match: the same record was name-fragment for "Fortinet
    FortiGate" and a subject match with a sector added. A sector says where the victims were, and
    decides no tier; the tally does not move with it."""
    import consult as C
    record_id = "obs-generic-state-affiliated-ransom-operations-from-known-vulnerabilities"
    plain = reasons(record_id, "Fortinet FortiManager")
    why = reasons(record_id, question)
    assert sector in why, why
    assert C.match_basis(plain, query.resolve("Fortinet FortiManager", ALIASES))[0] \
        == C.match_basis(why, query.resolve(question, ALIASES))[0] == "name-fragment"
    assert C.match_basis(["class network.firewall", sector])[0] == "class"

    def tiers(q):
        out = consult(q, "--today", TODAY, "--limit", "1").stdout
        return [line.split("  (")[0] for line in out.splitlines()
                if line.startswith("MATCH_TIERS:")]
    assert tiers(question) == tiers("Fortinet FortiManager"), question


def test_a_generic_record_naming_the_vendor_does_not_answer_a_product_question():
    """"Linux kernel" was answered RESOLUTION: product, without CLASS_LEVEL_WARNING, because
    five endpoint records list "Linux servers" or "Linux endpoints". None is about the kernel,
    and none of the twelve findings shown named Linux. Where the question named a product, a
    vendor named inside a generic record's products does not count as naming it."""
    import consult as C
    resolved = query.resolve("Linux kernel", ALIASES)
    why = reasons("obs-generic-hive-ransomware-as-a-service-with-log-and-recovery-destruction",
                  "Linux kernel")
    assert any(query.named_in_product(r) for r in why), why
    assert not C.names_what_was_asked(why, resolved)
    out = consult("Linux kernel", "--today", TODAY).stdout
    mode = [l for l in out.splitlines() if l.startswith("RESOLUTION:")][0]
    assert mode.startswith("RESOLUTION: CLASS-LEVEL"), mode
    assert "\nCLASS_LEVEL_WARNING:" in out
    # A vendor question with no product still counts it: "Linux" alone names Linux.
    assert C.names_what_was_asked(
        reasons("obs-generic-hive-ransomware-as-a-service-with-log-and-recovery-destruction",
                "Linux"), query.resolve("Linux", ALIASES))


# --- the subject tiers, and the order they are grouped in -----------------------------------

def blocks(stdout):
    """Each finding block's column-zero keys, as a dict."""
    out = []
    for chunk in stdout.split("=== FINDING ")[1:]:
        found = {}
        for line in chunk.splitlines():
            match = re.match(r"^([A-Z][A-Z0-9_]*): (.*)$", line)
            if match and match.group(1) not in found:
                found[match.group(1)] = match.group(2)
        out.append(found)
    return out


def tier_counts(stdout):
    line = re.search(r"^MATCH_TIERS: (.*?)  \(over all (\d+) matched", stdout, re.M)
    counts = {k: int(v) for k, v in (part.split("=") for part in line.group(1).split(", "))}
    return counts, int(line.group(2))


def test_match_basis_separates_product_vendor_class():
    import consult as C
    firewall = {"classes": {"network.firewall"}, "products": {"FortiGate"}}
    assert C.match_basis(["vendor Fortinet", "product FortiGate", "class network.firewall"],
                         firewall)[0] == "product"
    assert C.match_basis(["vendor Ivanti"], {"classes": {"app.mdm"}})[0] == "vendor-other-class"
    assert C.match_basis(["vendor Cisco"], {"classes": set()})[0] == "vendor"
    assert C.match_basis(["vendor Fortinet", "class network.firewall"], firewall)[0] == "vendor"
    assert C.match_basis(["class network.firewall"], firewall)[0] == "class"
    assert set(C.MATCH_GROUP) == set(query.TIER_ORDER)
    assert C.MATCH_GROUP["product"] == C.MATCH_GROUP["vendor"] \
        < C.MATCH_GROUP["class"] == C.MATCH_GROUP["vendor-other-class"] \
        < min(C.MATCH_GROUP[t] for t in query.TIER_ORDER if t not in query.SUBJECT_TIERS)


@pytest.mark.parametrize("question", ["Fortinet FortiGate", "PAN-OS", "Ivanti EPMM",
                                      "Microsoft Windows"])
def test_named_findings_lead_the_natural_order(question):
    """A fresh class analogue always beat an older record naming the product: "Fortinet
    FortiGate" put Cisco FMC at rank 1 and Fortinet at 7 and 9, "PAN-OS" led with the same
    Cisco record, and "Microsoft Windows" showed no Microsoft record in twelve. The group is
    a strict key ahead of the weight, and scores descend within a group."""
    import consult as C
    out = consult(question, "--today", TODAY, "--no-locus-spread", "--limit", "400").stdout
    found = blocks(out)
    groups = [C.MATCH_GROUP[b["MATCH_TIER"]] for b in found]
    assert groups == sorted(groups), question
    runs = {}
    for b in found:
        basis = b["PRIORITY_BASIS"]
        # The platform fit orders a run before the score does ("Microsoft Windows" names one),
        # and inside group 0 another product of a named product's vendor follows (0.44.0).
        key = (C.MATCH_GROUP[b["MATCH_TIER"]], ", after what was asked)" in basis,
               re.search(r"; sector=([^;]+);", basis).group(1),
               re.search(r"; refined_by=(\S+)$", basis).group(1),
               re.search(r"; platform_fit=([+-]?\d+) \(", basis).group(1))
        runs.setdefault(key, []).append(float(re.search(r"score=([0-9.]+)/", basis).group(1)))
    for key, scores in runs.items():
        assert scores == sorted(scores, reverse=True), (question, key)
    ids = [b["RECORD_ID"] for b in found]
    if question == "PAN-OS":
        assert ids[0].startswith("obs-paloaltonetworks"), ids[:3]
    if question == "Ivanti EPMM":
        assert "obs-ivanti-epmm-authentication-bypass-and-arbitrary-file-write-chain" in ids[:6]
    if question == "Fortinet FortiGate":
        assert sum(i.startswith("obs-fortinet") for i in ids[:12]) >= 8, ids[:12]
    if question == "Microsoft Windows":
        assert sum(b["TECHNOLOGY"].startswith("Microsoft /") for b in found[:12]) >= 6


def test_a_class_match_never_claims_the_product_was_named():
    """"PAN-OS" printed identity=74 over 3 findings naming PAN-OS and 71 other vendors'
    firewalls, every one labelled "named this technology". MATCH_TIER separates them and the
    tally counts them apart."""
    out = consult("PAN-OS", "--today", TODAY, "--limit", "400", "--no-locus-spread").stdout
    counts, matched = tier_counts(out)
    assert list(counts) == list(query.TIER_ORDER)
    assert sum(counts.values()) == matched
    assert counts["product"] == 3 and counts["vendor"] == 0, counts
    assert counts["class"] == matched - 3, counts
    assert "named this technology" not in out
    found = blocks(out)
    assert len(found) == matched
    for b in found:
        assert b["MATCH_TIER"] in query.TIER_ORDER
        if b["MATCH_TIER"] == "class":
            assert b["MATCH_BASIS"].startswith("CLASS-LEVEL"), b["MATCH_BASIS"]
        if b["MATCH_TIER"] == "product":
            assert b["MATCH_BASIS"].startswith("PRODUCT - names the product asked about (PAN-OS")
            assert b["RECORD_ID"].startswith("obs-paloaltonetworks")
    assert "\nCLASS_LEVEL_WARNING:" not in out


def test_the_vendors_other_lines_are_named_as_such():
    out = consult("Fortinet FortiMail", "--today", TODAY, "--limit", "400").stdout
    others = [b for b in blocks(out) if b["MATCH_TIER"] == "vendor-other-class"]
    assert others and all(b["TECHNOLOGY"].startswith("Fortinet /") for b in others)
    assert all(b["MATCH_BASIS"].startswith("VENDOR, OTHER PRODUCT LINE - names Fortinet")
               for b in others)


def test_a_named_sector_lifts_within_its_group():
    """The sector resolved, scored +4 in query.py, and moved nothing in consult.py, which
    discarded the points and never printed the sector."""
    out = consult("Fortinet FortiGate in a water utility", "--today", TODAY,
                  "--no-locus-spread", "--limit", "400").stdout
    resolved = [l for l in out.splitlines() if l.startswith("RESOLVED_TO:")][0]
    assert resolved.endswith("| sectors=water"), resolved
    first_class = next(b for b in blocks(out) if b["MATCH_TIER"] == "class")
    assert "; sector=sector water;" in first_class["PRIORITY_BASIS"], first_class
    plain = consult("Fortinet FortiGate", "--today", TODAY, "--limit", "1").stdout
    assert [l for l in plain.splitlines() if l.startswith("RESOLVED_TO:")][0].endswith(
        "| sectors=-")


def test_qualifying_words_lift_a_record_within_its_group():
    """The boot-image implant record carries all three leftover words and scores below the
    SSL-VPN records; within the named group it now comes first, where the design put it."""
    out = consult("Fortinet FortiGate boot image implant", "--today", TODAY,
                  "--no-locus-spread", "--limit", "3").stdout
    assert blocks(out)[0]["RECORD_ID"] == \
        "obs-fortinet-appliance-implant-persisting-in-the-boot-image"


def test_a_covered_finding_drops_one_group_under_gap_ranking_only():
    import consult as C
    assert C.match_group("product", "yes", "gap") == (1, "group 1 after coverage=yes")
    assert C.match_group("class", "yes", "gap")[0] == 2
    assert C.match_group("summary", "yes", "gap")[0] == 2, "the last group has nowhere to go"
    assert C.match_group("product", "partial", "gap")[0] == 0
    assert C.match_group("product", "yes", "criticality")[0] == 0


def test_gap_ranking_prints_the_demotion(tmp_path):
    inventory = tmp_path / "covered.txt"
    inventory.write_text("\n".join(covered_inventory("Fortinet")) + "\n", encoding="utf-8")
    out = consult("Fortinet FortiGate", "--covered", str(inventory), "--rank-by", "gap",
                  "--no-locus-spread", "--limit", "400", "--today", TODAY).stdout
    ordering = [l for l in out.splitlines() if l.startswith("ORDERING:")][0]
    assert "drops one group" in ordering
    covered = [b for b in blocks(out) if b["COVERAGE"] == "YES"
               and b["MATCH_TIER"] in ("product", "vendor")]
    assert covered, "fixture no longer covers a named finding"
    assert all("(group 1 after coverage=yes)" in b["PRIORITY_BASIS"] for b in covered)


# --- a campaign record's blocks are tiered by what each concerns -----------------------------
#
# The 2026-09-30 validation: "Microsoft Exchange" drew its whole product tier from one record
# filed under vendor `any` listing Fortinet appliances, Exchange and VMware Horizon, and two of
# the four blocks shown from it detect another product -- the outbound lookup for the
# logging-library flaw and the FortiOS username-case MFA bypass -- each printed as "names the
# product asked about". A consumer gating on MATCH_TIER product passed on an appliance bypass.

CAMPAIGN = "obs-generic-state-affiliated-ransom-operations-from-known-vulnerabilities"


def keyed(stdout):
    return {b["FINDING_KEY"]: b for b in blocks(stdout)}


def test_a_campaign_records_block_about_another_product_is_not_the_product_tier():
    out = consult("Microsoft Exchange", "--today", "2026-09-30", "--no-locus-spread",
                  "--limit", "500").stdout
    found = keyed(out)
    record = BY_ID[CAMPAIGN]
    # The fixture's shape: four blocks, the bypass carrying only CVE-2020-12812 and the
    # outbound-lookup block naming Log4j, so a re-cut record fails here rather than passing.
    assert "CVE-2020-12812" in json.dumps(record["how"][2]["markers"])
    assert "Log4j" in record["how"][3]["caveat"]
    for index in (2, 3):
        block = found["{}#how{}".format(CAMPAIGN, index)]
        assert block["MATCH_TIER"] != "product", block["MATCH_BASIS"]
        assert "but this block concerns another" in block["MATCH_BASIS"]
        assert block["MATCH_BASIS"].endswith("analogy, not intelligence about yours")
    assert "CVE-2020-12812 (held here under Fortinet FortiOS)" in \
        found[CAMPAIGN + "#how2"]["MATCH_BASIS"]
    assert "it names Log4j" in found[CAMPAIGN + "#how3"]["MATCH_BASIS"]
    # The block carrying Exchange's own identifiers keeps the tier and says why.
    join = found[CAMPAIGN + "#how1"]
    assert join["MATCH_TIER"] == "product"
    assert "this block concerns it: it carries CVE-2021-31207, CVE-2021-34473, CVE-2021-34523" \
        in join["MATCH_BASIS"]
    # A block naming no product and carrying no identifier, citing a pattern written for no
    # class of Exchange's, no longer keeps it by default: it says it concerns the campaign.
    general = found[CAMPAIGN + "#how0"]
    assert general["MATCH_TIER"] != "product", general["MATCH_BASIS"]
    assert "this block concerns the campaign, not it: it names none of the record's products " \
           "and carries no identifier" in general["MATCH_BASIS"]
    # MATCH_TIERS counts blocks, so it moves with them, and the answer is still a product one.
    counts, matched = tier_counts(out)
    assert matched == len(blocks(out)), "--limit 500 truncated"
    assert counts["product"] == sum(1 for b in blocks(out) if b["MATCH_TIER"] == "product")
    assert "RESOLUTION: product" in out


def test_a_vendor_named_in_a_campaign_record_is_tiered_by_block_too():
    """The same record answers "Fortinet" through the entry "Fortinet appliances", and its
    logging-library block is no more Fortinet's than it is Exchange's."""
    out = consult("Fortinet", "--today", "2026-09-30", "--no-locus-spread",
                  "--limit", "500").stdout
    found = keyed(out)
    assert found[CAMPAIGN + "#how3"]["MATCH_TIER"] not in ("product", "vendor")
    assert "the record names the vendor asked about (Fortinet (named in product Fortinet " \
           "appliances))" in found[CAMPAIGN + "#how3"]["MATCH_BASIS"]
    bypass = found[CAMPAIGN + "#how2"]
    assert bypass["MATCH_TIER"] == "vendor"
    assert "carries CVE-2020-12812, which an exposure record here files under Fortinet" \
        in bypass["MATCH_BASIS"]


def test_block_scope_reads_the_block_and_leaves_other_records_alone():
    import consult as C
    resolved = query.resolve("Microsoft Exchange", ALIASES)
    owners = C.identifier_owners(RECORDS, resolved)
    assert "CVE-2021-34473" in owners.product and "CVE-2020-12812" not in owners.product

    def record(vendor, products, *blocks_):
        return {"id": "obs-test", "who": {"vendor": vendor, "products": list(products)},
                "how": list(blocks_)}

    def block(logic, *cves):
        return {"logic": logic, "caveat": "",
                "markers": [{"type": "cve", "match": "equals", "value": c} for c in cves]}

    campaign = ("any", ["Microsoft Exchange", "VMware Horizon"])
    named = C.block_scope(record(*campaign), block("Requests to the Exchange Server front end "
                                                   "from 192.0.2.10"), resolved, ALIASES, owners)
    assert named.concerns and "names it" in named.text
    carried = C.block_scope(record(*campaign), block("A chain against the mail tier.",
                                                     "CVE-2021-34473"), resolved, ALIASES, owners)
    assert carried.concerns and "CVE-2021-34473" in carried.text
    other = C.block_scope(record(*campaign), block("The appliance bypass.", "CVE-2020-12812"),
                          resolved, ALIASES, owners)
    assert not other.concerns and "Fortinet FortiOS" in other.text
    # A name takes the block away where the pattern it cites is written for none of the asked
    # product's classes: Log4j's lookup is a web and library pattern, Exchange a mail one.
    web = {"id": "pat-test-web", "applies_to_classes": ["server.web", "dev.library"]}
    mail = {"id": "pat-test-mail", "applies_to_classes": ["server.mail"]}
    shared = {"id": "pat-test-shared", "applies_to_classes": ["server.mail",
                                                              "network.remote_access"]}
    lookup = block("An outbound lookup after the Log4j flaw fires.")
    library = C.block_scope(record(*campaign), lookup, resolved, ALIASES, owners, "product", web)
    assert not library.concerns and "names Log4j" in library.text
    assert library.rule == "other-kind"
    # Under a pattern written for the mail tier alone, and for no kind Horizon holds, the
    # block is Exchange's by kind, and still says what it names.
    passing = C.block_scope(record(*campaign), lookup, resolved, ALIASES, owners, "product",
                            mail)
    assert (passing.concerns, passing.rule) == (True, "kind"), passing.text
    assert "names Log4j" in passing.text
    # Under one written for Horizon's kind as well, nothing singles Exchange out.
    either = C.block_scope(record(*campaign), lookup, resolved, ALIASES, owners, "product",
                           shared)
    assert (either.concerns, either.rule) == (False, "silent"), either.text
    assert "does not single it out" in either.text and "held by VMware Horizon" in either.text
    # A block with no reading either way no longer keeps the tier by default.
    silent = C.block_scope(record(*campaign), block("Tools left on the host."), resolved,
                           ALIASES, owners)
    assert (silent.concerns, silent.rule) == (False, "silent"), silent.text
    assert "cites no pattern to read its kind by" in silent.text
    # Another entry named by its own name takes the block; a class word of Exchange's in its
    # own sentences keeps it.
    horizon = C.block_scope(record(*campaign), block("Sessions on the VMware Horizon "
                                                     "connection server."), resolved, ALIASES,
                            owners)
    assert (horizon.concerns, horizon.rule) == (False, "other-entry"), horizon.text
    mailbox = C.block_scope(record(*campaign), block("Rules written on the mail server."),
                            resolved, ALIASES, owners)
    assert (mailbox.concerns, mailbox.rule) == (True, "class"), mailbox.text
    # The record's only block keeps the tier under a pattern written for Exchange's kind, and
    # not under one written for none of its classes.
    tools = block("Tools left on the host.")
    alone = record(*campaign, tools)
    assert C.block_scope(alone, tools, resolved, ALIASES, owners, "product", mail).rule == \
        "only-block"
    assert not C.block_scope(alone, tools, resolved, ALIASES, owners, "product", web).concerns
    # Beside an entry the resolver reads nothing in there is no other product to be about.
    sole = C.block_scope(record("any", ["Microsoft Exchange", "example estates"]), tools,
                         resolved, ALIASES, owners)
    assert (sole.concerns, sole.rule) == (True, "sole-product"), sole.text
    # Only a campaign record is read this way: one filed under a vendor, and one whose every
    # entry names the product, keep their tier for every block.
    assert C.block_scope(record("Microsoft", ["Exchange Server", "Outlook"]),
                         block("The appliance bypass.", "CVE-2020-12812"), resolved, ALIASES,
                         owners) is None
    assert C.block_scope(record("any", ["Microsoft Exchange"]),
                         block("The appliance bypass.", "CVE-2020-12812"), resolved, ALIASES,
                         owners) is None
    # And block_tier() gives the demoted block the record's other reasons' tier.
    why = ["product Microsoft Exchange (as Exchange Server)", "class server.mail"]
    tier, weight, scope = C.block_tier("product", 1.0, why, record(*campaign),
                                       block("The appliance bypass.", "CVE-2020-12812"),
                                       resolved, ALIASES, owners)
    assert (tier, scope.concerns, scope.rule) == ("class", False, "other-identifier")
    tier = C.block_tier("product", 1.0, why[:1], record(*campaign),
                        block("The appliance bypass.", "CVE-2020-12812"), resolved, ALIASES,
                        owners)[0]
    assert tier == "name-fragment", "reached by name, never below a name fragment"


# --- a block about what was asked is not taken away by a name it mentions -------------------
#
# The 2026-10-01 review of the fix above: block_scope() demoted a block whenever the resolver
# found any other product in its text, and about a dozen blocks that are about what was asked
# lost the tier that way, each labelled "this block concerns another". These are the review's
# cases; each was demoted at 668299e.

REMOTE_ENCRYPTION = "obs-generic-ransomware-remote-encryption-of-shares-from-single-host"
WORM = "obs-generic-self-replicating-package-worm-via-install-hook"
RUNNER = "obs-generic-rogue-self-hosted-ci-runner-as-c2"
FORGE = "obs-generic-stolen-forge-token-drives-mass-repository-exfiltration"
WEB = "obs-generic-ai-orchestrated-intrusion-of-internet-facing-web-servers"
GIT_CONFIG = "obs-generic-exposed-git-config-harvested-for-cloud-credentials"

KEPT = [
    # /vmfs/volumes/ and vmdk, beside "Windows hosts, Linux servers and the virtualisation layer".
    ("VMware ESXi", REMOTE_ENCRYPTION + "#how2", "product", "class",
     "server.hypervisor (hypervisor, virtual machine, virtualisation)"),
    # The install hook republishing to the registry, beside a passing "self-hosted runner".
    # "dependency" sits only in a computed marker's expression, so only "package" is read.
    ("npm registry", WORM + "#how0", "product", "class", "dev.library (package)"),
    # Runner.Listener and actions-runner: "actions runner" is a word the table files under the
    # record's own co-listed entry, not that entry's name.
    ("GitHub Actions", RUNNER + "#how0", "product", "class", "app.cicd (runner)"),
    ("GitHub", RUNNER + "#how0", "vendor", "class", "app.cicd (runner)"),
    # The forge API reconnaissance block names "git client", and Git is no product the record
    # lists; nothing else it lists ("personal access tokens", "private source repositories")
    # reads as a product at all.
    ("GitHub", FORGE + "#how1", "vendor", "sole-product",
     "names Git (which the record does not list)"),
    # appcmd, inetsrv and BadIIS: "badiis" is filed under the Telerik entry, and is not its name.
    # The pattern is a web server's, and no other entry the record lists is one by its own words.
    ("Microsoft IIS", WEB + "#how2", "vendor", "kind",
     "names badiis (a word the alias table files under Progress Telerik UI for ASP.NET AJAX, "
     "which the record lists)"),
    # The record's only block, naming its first entry through a "/.git/" path fragment.
    ("Laravel", GIT_CONFIG + "#how0", "product", "only-block", "it also names Git"),
]


@pytest.mark.parametrize("question,key,tier,rule,says", KEPT)
def test_a_block_about_what_was_asked_keeps_its_tier_whatever_else_it_names(
        question, key, tier, rule, says):
    out = consult(question, "--today", "2026-09-30", "--no-locus-spread", "--limit", "2000").stdout
    found = keyed(out)
    assert key in found, "fixture no longer reaches {}".format(key)
    basis = found[key]["MATCH_BASIS"]
    assert found[key]["MATCH_TIER"] == tier, basis
    assert "concerns another" not in basis
    assert says in basis, basis
    import consult as C
    resolved = query.resolve(question, ALIASES)
    record_id, index = key.rsplit("#how", 1)
    how = BY_ID[record_id]["how"][int(index)]
    kind = "product" if tier == "product" else "vendor"
    scope = C.block_scope(BY_ID[record_id], how, resolved, ALIASES,
                          C.identifier_owners(RECORDS, resolved), kind,
                          PATTERNS.get(how.get("pattern_id")))
    assert scope.rule == rule, scope.text
    if question == "Laravel":
        assert [l for l in out.splitlines() if l.startswith("RESOLUTION:")][0].startswith(
            "RESOLUTION: product")


def test_the_esxi_answer_keeps_its_hypervisor_block_not_the_directory_one_in_its_place():
    """The demoted hypervisor block left the slot to the same record's directory enumeration,
    at product tier. The hypervisor block is back in the product tier, and the directory
    block, which names none of the record's products and cites a pattern written for no class
    of ESXi's, is not: it says it concerns the campaign."""
    out = consult("VMware ESXi", "--today", "2026-09-30", "--no-locus-spread",
                  "--limit", "2000").stdout
    found = keyed(out)
    assert found[REMOTE_ENCRYPTION + "#how2"]["MATCH_TIER"] == "product"
    directory = found[REMOTE_ENCRYPTION + "#how1"]
    assert directory["MATCH_TIER"] != "product", directory["MATCH_BASIS"]
    assert "this block concerns the campaign, not it: it names none of the record's products" \
        in directory["MATCH_BASIS"]
    # The blocks that are another product's still are: the Windows share encryption (Netlogon)
    # and the FortiOS bypass in the Hive record.
    assert found[REMOTE_ENCRYPTION + "#how0"]["MATCH_TIER"] != "product"
    hive = "obs-generic-hive-ransomware-as-a-service-with-log-and-recovery-destruction#how0"
    assert found[hive]["MATCH_TIER"] != "product"
    assert "CVE-2020-12812 (held here under Fortinet FortiOS)" in found[hive]["MATCH_BASIS"]


def test_a_block_naming_the_product_asked_is_never_called_another_products():
    out = consult("Progress Telerik UI for ASP.NET AJAX", "--today", "2026-09-30",
                  "--no-locus-spread", "--limit", "2000").stdout
    web = [b for b in blocks(out) if b["FINDING_KEY"].startswith(WEB + "#how")]
    assert len(web) == len(BY_ID[WEB]["how"]), "fixture no longer reaches the web-server record"
    for b in web:
        assert "names Progress Telerik UI for ASP.NET AJAX" not in b["MATCH_BASIS"], \
            b["MATCH_BASIS"]
    # Its ViewState block names nothing of Telerik and cites a pattern written for web servers,
    # middleware and collaboration suites, which IIS, Nacos and Zimbra are and the Telerik
    # library is not: it is the campaign's, and says whose kind the pattern is.
    viewstate = keyed(out)[WEB + "#how0"]
    assert viewstate["MATCH_TIER"] != "product", viewstate["MATCH_BASIS"]
    assert "Microsoft IIS" in viewstate["MATCH_BASIS"]


def campaign_questions():
    """(entry, record) for every entry of a campaign record that resolves, as a question, to a
    product: the questions a campaign record answers by name."""
    out = []
    for record in RECORDS:
        who = record.get("who") or {}
        if who.get("vendor") not in query.SENTINEL_VENDORS or len(who.get("products") or []) < 2:
            continue
        for entry in who["products"]:
            if query.resolve(entry, ALIASES).get("product_pairs"):
                out.append((entry, record))
    return out


def test_no_block_is_said_to_concern_another_by_naming_what_was_asked():
    """"Progress Telerik UI for ASP.NET AJAX" read a block as naming the product it asked
    about and called it another's: "it names Progress Telerik UI for ASP.NET AJAX, and neither
    names Telerik UI for ASP.NET AJAX". Over every campaign entry that resolves to a product, a
    block taken away never names, in its reason, the product asked or the entry naming it."""
    import consult as C
    pairs = campaign_questions()
    assert len(pairs) > 40, "fixture no longer exercises the campaign records"
    owners_of = {}
    taken = 0
    for entry, record in pairs:
        resolved = query.resolve(entry, ALIASES)
        owners = owners_of.setdefault(entry, C.identifier_owners(RECORDS, resolved))
        asked = {query.normalise(p) for _, p in resolved["product_pairs"]} | {
            query.normalise(entry)}
        for how in record.get("how") or []:
            scope = C.block_scope(record, how, resolved, ALIASES, owners, "product",
                                  PATTERNS.get(how.get("pattern_id")))
            if scope is None or scope.concerns:
                continue
            taken += 1
            assert scope.rule in ("other-identifier", "other-entry", "other-kind", "silent"), \
                scope
            if scope.rule == "silent":
                # The products said to hold the pattern's kind are never the one asked.
                held = re.search(r"held by (.*?), which the record also lists", scope.text)
                said = {query.normalise(n) for n in re.split(r", | and ", held.group(1))} \
                    if held else set()
                assert not said & asked, "{} on {!r}: {}".format(record["id"], entry,
                                                                 scope.text)
                continue
            named = re.search(r"it names (.*?)(, which the record also lists|, and the pattern)",
                              scope.text)
            if named:
                said = {query.normalise(re.sub(r" \([^)]*\)", "", n))
                        for n in re.split(r", | and ", named.group(1))}
                assert not said & asked, "{} on {!r}: {}".format(record["id"], entry, scope.text)
    assert taken, "fixture no longer takes a block away"


# --- a class word inside a matched string keeps nothing ----------------------------------------
#
# The second review of the fix above found a false keep, which none of the tests above could
# see: each held a block to not being taken away. The access-resale record's integrity block
# matches three NetScaler paths, and the class alias "vpn" read "/var/vpn/themes/imgs/" as a VPN
# gateway, Connect Secure's class, so on seven Ivanti and Pulse questions the block printed at
# product or vendor tier as "this block concerns it". CISA's advisory gives all three paths for
# the NetScaler flaw and none for Pulse Secure or F5.

ACCESS_RESALE = "obs-generic-remote-access-appliance-compromise-for-access-resale"
C_NAMING_TIERS = ("product", "vendor")


@pytest.mark.parametrize("question,kind", [("Ivanti Connect Secure", "product"),
                                           ("Pulse Connect Secure", "product"),
                                           ("Ivanti", "vendor")])
def test_a_netscaler_path_block_is_not_ivantis(question, kind):
    out = consult(question, "--today", "2026-09-30", "--no-locus-spread", "--limit", "2000").stdout
    found = keyed(out)
    key = ACCESS_RESALE + "#how0"
    assert key in found, "fixture no longer reaches the access-resale record"
    basis = found[key]["MATCH_BASIS"]
    assert found[key]["MATCH_TIER"] not in C_NAMING_TIERS, basis
    assert "this block concerns another: it names Citrix Application Delivery Controller and " \
           "NetScaler Gateway, which the record also lists" in basis, basis
    assert "concerns it" not in basis
    import consult as C
    resolved = query.resolve(question, ALIASES)
    how = BY_ID[ACCESS_RESALE]["how"][0]
    scope = C.block_scope(BY_ID[ACCESS_RESALE], how, resolved, ALIASES,
                          C.identifier_owners(RECORDS, resolved), kind,
                          PATTERNS.get(how.get("pattern_id")))
    assert (scope.concerns, scope.rule) == (False, "other-entry"), scope.text
    # The access-resale block cites a pattern written for VPN gateways, Connect Secure's kind and
    # neither NetScaler's nor BIG-IP's, and keeps the tier by kind. The tunnel client, whose
    # markers are Windows binaries and whose pattern is written for no class of Connect
    # Secure's, no longer keeps it by default.
    assert found[ACCESS_RESALE + "#how5"]["MATCH_TIER"] in C_NAMING_TIERS
    assert "this block concerns it by kind" in found[ACCESS_RESALE + "#how5"]["MATCH_BASIS"]
    assert found[ACCESS_RESALE + "#how3"]["MATCH_TIER"] not in C_NAMING_TIERS


def test_a_class_is_read_in_the_blocks_sentences_not_its_matched_strings():
    """The same word, read in the block's logic, is a class reading of its own; read only in
    the path it matches, it is not, and the name in that path decides."""
    import consult as C
    resolved = query.resolve("Ivanti Connect Secure", ALIASES)
    owners = C.identifier_owners(RECORDS, resolved)
    campaign = {"id": "obs-test", "who": {"vendor": "any", "products": [
        "Pulse Connect Secure", "Citrix Application Delivery Controller and NetScaler Gateway"]},
        "how": [{}, {}]}

    def block(logic, path):
        return {"logic": logic, "caveat": "",
                "markers": [{"type": "file_path", "match": "regex", "value": path}]}

    in_path = C.block_scope(campaign, block("Tools were left in the theme image directory.",
                                            "(?i)(/netscaler/ns_gui/|/var/vpn/themes/imgs/)"),
                            resolved, ALIASES, owners)
    assert (in_path.concerns, in_path.rule) == (False, "other-entry"), in_path.text
    in_logic = C.block_scope(campaign, block("Tools were left on the VPN gateway's theme "
                                             "directory.", "(?i)/netscaler/ns_gui/"),
                             resolved, ALIASES, owners)
    assert (in_logic.concerns, in_logic.rule) == (True, "class"), in_logic.text
    assert C.block_prose({"logic": "a", "caveat": "b", "markers": [{"value": "c"}]}) == "a b"


def test_every_class_reading_is_in_the_blocks_own_sentences():
    """Over every campaign entry that resolves to a product, a block kept on its class words
    cites only words its logic and caveat carry. At the commit this test follows, the
    integrity block's "vpn" and the outbound-lookup block's "ldap" came from matched strings."""
    import consult as C
    kept = 0
    owners_of = {}
    for entry, record in campaign_questions():
        resolved = query.resolve(entry, ALIASES)
        owners = owners_of.setdefault(entry, C.identifier_owners(RECORDS, resolved))
        for how in record.get("how") or []:
            scope = C.block_scope(record, how, resolved, ALIASES, owners, "product",
                                  PATTERNS.get(how.get("pattern_id")))
            if scope is None or scope.rule not in ("class", "shared-class"):
                continue
            kept += 1
            prose = C.own_word_classes(query.resolve(C.block_prose(how), ALIASES))
            read = re.search(r"read for (.*?), (a class of what was asked|their class)",
                             scope.text)
            assert read, scope.text
            for klass, words in re.findall(r"([a-z]+\.[a-z_]+) \(([^)]*)\)", read.group(1)):
                if klass in prose:
                    assert set(words.split(", ")) <= prose[klass], (record["id"], entry,
                                                                    scope.text)
                else:
                    assert False, "{} on {!r} read {} outside its sentences: {}".format(
                        record["id"], entry, klass, scope.text)
    assert kept, "fixture no longer keeps a block on its class words"


def test_an_exposure_points_at_the_block_carrying_its_identifier():
    """The ProxyShell exposure pointed at "FINDING 3 above", the first block shown from the
    campaign record, and that was the Log4j block."""
    out = consult("Microsoft Exchange", "--today", "2026-09-30").stdout
    shown = [b["FINDING_KEY"] for b in blocks(out)]
    held = [l for l in out.splitlines() if l.startswith("EXPOSURE_DETECTION_HELD:")
            and CAMPAIGN in l]
    assert held, "fixture no longer cross-references the campaign record"
    for line in held:
        pointer = re.search(CAMPAIGN + r" \(any\) carries ([^;]+?)( - FINDING (\d+) above"
                            r"| - its record is shown above \(([^)]*)\)[^;]*)?(;|$)", line)
        assert pointer, line
        if pointer.group(3):
            key = shown[int(pointer.group(3)) - 1]
            ids = set(pointer.group(1).split(", "))
            assert key.startswith(CAMPAIGN + "#how")
            index = int(key.rsplit("#how", 1)[1])
            text = json.dumps(BY_ID[CAMPAIGN]["how"][index])
            assert any(i in text for i in ids), "{} points at a block not carrying {}".format(
                key, ids)


def test_a_record_naming_only_the_vendor_says_so_rather_than_another_product():
    """With a product asked, a generic record naming the vendor inside an entry is a class
    analogue or a name fragment. It printed "is about another product than yours" beside
    "Fortinet appliances", and "the record was not reached as the technology you named" for a
    record reached by the vendor's name."""
    out = consult("Fortinet FortiManager", "--today", "2026-09-30", "--no-locus-spread",
                  "--limit", "500").stdout
    inside = [b for b in blocks(out)
              if "(named in product Fortinet appliances)" in b["MATCH_BASIS"]]
    assert {b["MATCH_TIER"] for b in inside} == {"class", "name-fragment"}, \
        "fixture no longer reaches both tiers"
    for b in inside:
        assert "the record names the vendor asked about (Fortinet (named in product Fortinet " \
               "appliances)) among what it lists" in b["MATCH_BASIS"], b["MATCH_BASIS"]
        assert "about another product than yours" not in b["MATCH_BASIS"]
        assert "not reached as the technology you named" not in b["MATCH_BASIS"]


def test_an_exposures_only_answer_carries_its_handset_refusal():
    """"Apple iOS" refused three handset records and said so only in EXPOSURES_NOT_LISTED:
    its RESOLUTION carried no refusal, and every EXPOSURE_MATCH said every exposure filed under
    the vendor was listed."""
    out = consult("Apple iOS", "--today", "2026-09-30").stdout
    resolution = [l for l in out.splitlines() if l.startswith("RESOLUTION:")][0]
    refused = int(re.search(r"handset=(\d+)", out).group(1))
    assert refused, "fixture no longer refuses a handset record"
    assert resolution.startswith("RESOLUTION: EXPOSURES_ONLY - ")
    assert "; {} handset exposure record(s) naming it are held and not listed".format(
        refused) in resolution
    matches = [l for l in out.splitlines() if l.startswith("EXPOSURE_MATCH: vendor - ")]
    assert matches and all("listed except {} handset record(s), which are refused".format(
        refused) in l for l in matches)


# --- no campaign block keeps a naming tier by default ------------------------------------------
#
# The third review of the campaign-block change failed it for the default: a block naming no
# listed product and carrying no identifier kept the product tier as "the campaign as it
# reached them all, yours among them", and for blocks tied to another entry's platform that was
# false. "Synacor Zimbra Collaboration Suite (ZCS)" drew its whole product tier from the
# web-server campaign: an antivirus exclusion for IIS's module directory, an ASP.NET ViewState
# block and a block that is not a detection. "VMware ESXi" took shadow-copy deletion, Windows
# domain account creation and LDAP share enumeration at product tier. Each held at 5b12154.

HIVE = "obs-generic-hive-ransomware-as-a-service-with-log-and-recovery-destruction"
HELPDESK = "obs-generic-helpdesk-impersonation-to-ransomware-deployment"
UNTRUSTED_FORK = "obs-generic-untrusted-fork-code-runs-with-repository-token"
REMOTE_TOOLS = "obs-generic-remote-access-tools-as-persistence-and-c2"
ENCLAVE = "obs-generic-ransomware-repeated-deployment-and-enclave-mapping"
KEEPING = ("named", "identifier", "class", "shared-class", "only-block", "sole-product", "kind")

TAKEN = [
    ("Synacor Zimbra Collaboration Suite (ZCS)", WEB + "#how1", "windows"),
    ("Synacor Zimbra Collaboration Suite (ZCS)", WEB + "#how0", None),
    ("Synacor Zimbra Collaboration Suite (ZCS)", WEB + "#how5", None),
    ("Alibaba Nacos", WEB + "#how1", "windows"),
    ("Alibaba Nacos", WEB + "#how0", None),
    ("VMware ESXi", HIVE + "#how2", "windows"),
    ("VMware ESXi", HELPDESK + "#how1", None),
    ("VMware ESXi", REMOTE_ENCRYPTION + "#how1", None),
]


@pytest.mark.parametrize("question,key,platform", TAKEN)
def test_a_campaign_block_with_no_reading_for_what_was_asked_is_not_its_tier(question, key,
                                                                             platform):
    out = consult(question, "--today", "2026-09-30", "--no-locus-spread", "--limit", "2000").stdout
    found = keyed(out)
    assert key in found, "fixture no longer reaches {}".format(key)
    basis = found[key]["MATCH_BASIS"]
    assert found[key]["MATCH_TIER"] not in C_NAMING_TIERS, basis
    assert "this block concerns the campaign" in basis, basis
    assert "yours among them" not in basis and "concerns it:" not in basis
    if platform:
        assert "its markers are written for {}".format(platform) in basis, basis


def test_an_answer_whose_campaign_blocks_all_fell_says_the_record_lists_it():
    """Zimbra's whole product tier was the web-server campaign's. With every block taken, the
    answer is class-level, and it must not say that no observation names Zimbra: one does."""
    out = consult("Synacor Zimbra Collaboration Suite (ZCS)", "--today", "2026-09-30").stdout
    counts, _ = tier_counts(out)
    assert counts["product"] == 0 and counts["vendor"] == 0
    resolution = [l for l in out.splitlines() if l.startswith("RESOLUTION:")][0]
    warning = [l for l in out.splitlines() if l.startswith("CLASS_LEVEL_WARNING:")][0]
    assert resolution.startswith("RESOLUTION: CLASS-LEVEL (inferred) - no observation is about "
                                 "Synacor Zimbra Collaboration Suite (ZCS) (1 campaign record(s) "
                                 "list it among what a campaign reached")
    assert "holds no observation naming it" not in warning
    assert "The corpus holds no observation about it (1 campaign record(s) list it" in warning


GENUINE = [
    # Domain account creation, under a pattern written for directories, on the one directory
    # the record lists beside Windows estates and ESXi.
    ("Microsoft Active Directory", HELPDESK + "#how1", "product", "kind"),
    # Secrets base64-encoded into the build log, on a record whose other entries are CI/CD
    # runners and pull_request_target workflows: GitHub Actions' own kind.
    ("GitHub Actions", UNTRUSTED_FORK + "#how1", "product", "kind"),
    # A tunnelling client, beside AnyDesk and three remote-access tools the table cannot read.
    ("Cloudflare Tunnel", REMOTE_TOOLS + "#how1", "product", "kind"),
]


@pytest.mark.parametrize("question,key,tier,rule", GENUINE)
def test_a_campaign_block_written_for_what_was_asked_keeps_its_tier(question, key, tier, rule):
    """The other direction: a block naming nothing that is about what was asked keeps the tier
    on a reading it states, not by default."""
    out = consult(question, "--today", "2026-09-30", "--no-locus-spread", "--limit", "2000").stdout
    found = keyed(out)
    assert key in found, "fixture no longer reaches {}".format(key)
    assert found[key]["MATCH_TIER"] == tier, found[key]["MATCH_BASIS"]
    assert "this block concerns it by kind" in found[key]["MATCH_BASIS"]
    import consult as C
    resolved = query.resolve(question, ALIASES)
    record_id, index = key.rsplit("#how", 1)
    how = BY_ID[record_id]["how"][int(index)]
    scope = C.block_scope(BY_ID[record_id], how, resolved, ALIASES,
                          C.identifier_owners(RECORDS, resolved), tier,
                          PATTERNS.get(how.get("pattern_id")))
    assert (scope.concerns, scope.rule) == (True, rule), scope.text


def test_a_block_written_for_another_platform_is_not_the_asked_products_by_kind():
    """On "Linux", the hive record's shadow-copy block (vssadmin.exe and the like) is
    endpoint.os, as Linux is, but its markers are Windows binaries and the record lists Windows
    endpoints: it is theirs."""
    out = consult("Linux", "--today", "2026-09-30", "--no-locus-spread", "--limit", "2000").stdout
    found = keyed(out)
    shadow = found[HIVE + "#how2"]
    assert shadow["MATCH_TIER"] not in C_NAMING_TIERS, shadow["MATCH_BASIS"]
    assert "its markers are written for windows, and Linux runs on linux" in shadow["MATCH_BASIS"]


def test_no_campaign_block_keeps_a_naming_tier_by_default():
    """Over every campaign entry that resolves to a product, and every vendor such an entry
    names, a block keeps the tier only on a stated reading, and a block kept on the pattern it
    cites is never one whose markers commit to another platform than the asked one's."""
    import consult as C
    kept = {}
    vendors = set()
    for entry, record in campaign_questions():
        vendors |= set(query.resolve(entry, ALIASES).get("vendors") or ())
    questions = [(entry, "product") for entry, _ in campaign_questions()] + \
        [(vendor, "vendor") for vendor in sorted(vendors)]
    camp = [r for r in RECORDS if (r.get("who") or {}).get("vendor") in query.SENTINEL_VENDORS]
    for question, kind in sorted(set(questions)):
        resolved = query.resolve(question, ALIASES)
        owners = C.identifier_owners(RECORDS, resolved)
        asked = query.question_platforms(resolved, ALIASES)
        for record in camp:
            for how in record.get("how") or []:
                pattern = PATTERNS.get(how.get("pattern_id"))
                scope = C.block_scope(record, how, resolved, ALIASES, owners, kind, pattern)
                if scope is None:
                    break
                assert scope.concerns == (scope.rule in KEEPING), (question, record["id"], scope)
                if scope.concerns:
                    kept[scope.rule] = kept.get(scope.rule, 0) + 1
                    assert "yours among them" not in scope.text or scope.rule in (
                        "shared-class", "only-block", "kind"), scope.text
                if scope.rule in ("kind", "only-block", "sole-product") and asked:
                    platforms = C.finding_platforms(how, pattern)
                    assert query.platform_fit(platforms, asked) >= 0, (question, record["id"],
                                                                       scope.text)
    assert kept.get("kind") and kept.get("class") and kept.get("named"), kept
    assert C.KEEPING_RULES == set(KEEPING) and set(KEEPING) < set(C.BLOCK_RULES)


def test_a_block_naming_entries_that_resolve_no_product_says_it_names_them():
    """The enclave-mapping block names "cloud storage and network backups", two of the record's
    four entries, and said it named none of them; on "SonicWall firewall" it kept the vendor
    tier and counted ENDPOINT as held by a finding naming SonicWall."""
    out = consult("SonicWall firewall", "--today", "2026-09-30", "--no-locus-spread",
                  "--limit", "2000").stdout
    block = keyed(out)[ENCLAVE + "#how1"]
    assert block["MATCH_TIER"] not in C_NAMING_TIERS, block["MATCH_BASIS"]
    assert "this block concerns another: it names cloud storage and network backups, which " \
           "the record also lists" in block["MATCH_BASIS"]
    for b in blocks(out):
        if "names none of" in b["MATCH_BASIS"]:
            record_id, index = b["FINDING_KEY"].rsplit("#how", 1)
            words = query.normalise(json.dumps(BY_ID[record_id]["how"][int(index)]))
            for entry in BY_ID[record_id]["who"]["products"]:
                assert query.normalise(entry) not in words, (b["FINDING_KEY"], entry)
