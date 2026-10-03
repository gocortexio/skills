# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""How an exposure relates to the question, decided once for every script that lists one.

An exposure is a vulnerability fact with no detection logic, so unlike an observation it
transfers nothing to another vendor's product: a CVE in Cisco's firewall says nothing about
Check Point's. `query.exposure_tier()` places each exposure in one of `EXPOSURE_TIERS`, closest
first, using the same product matcher as `score()`. Three defects shaped it:

- Product strings matched without their vendor. "Linux kernel" gave an Android handset record
  product weight, and "Apple multiple products" matched seventeen other vendors' "Multiple
  Products" catalogue entries.
- Vendor strings matched without the alias table. 18 exposures are filed under "VMware" while
  "VMware" resolves to Broadcom, so none of them was a vendor match for either name.
- Product strings matched exactly. "Endpoint Manager Mobile" missed "Endpoint Manager Mobile
  (EPMM)", so the EPMM catalogue record ranked third for "Ivanti EPMM", behind two EPM records
  that won the tie on their id.

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
import query as Q  # noqa: E402

ALIASES = Q.normalise_alias_keys(
    json.load(open(os.path.join(ROOT, "corpus", "schema", "aliases.json"), encoding="utf-8")))
RECORDS, PATTERNS = Q.load_corpus(os.path.join(ROOT, "corpus"))
BY_ID = {r["id"]: r for r in RECORDS}
EXPOSURES = [r for r in RECORDS if r.get("record_type") == "exposure"]


def tier(record_id, question):
    return Q.exposure_tier(BY_ID[record_id], Q.resolve(question, ALIASES))


def test_every_tier_is_one_the_listing_knows():
    resolved = Q.resolve("Check Point firewall", ALIASES)
    seen = {Q.exposure_tier(r, resolved) for r in EXPOSURES}
    assert seen - {None} <= set(Q.EXPOSURE_TIERS), seen


@pytest.mark.parametrize("record_id,question", [
    ("exp-kev-check-point-multiple-products", "Apple multiple products"),
    ("exp-kev-teamviewer-desktop", "Docker Desktop"),
])
def test_same_product_name_under_another_vendor_is_not_a_product_match(record_id, question):
    assert tier(record_id, question) == "product-name-other-vendor"


@pytest.mark.parametrize("record_id,question", [
    ("exp-kev-vmware-esxi", "VMware ESXi"),
    ("exp-kev-vmware-esxi", "Broadcom ESXi"),
    ("exp-kev-ivanti-endpoint-manager-mobile-epmm", "Ivanti EPMM"),
    ("exp-kev-check-point-quantum-security-gateways", "Check Point Quantum Security Gateway"),
    ("exp-kev-linux-kernel", "Linux kernel"),
])
def test_the_named_product_is_the_product_tier(record_id, question):
    """Through the vendor's alias ("VMware" is Broadcom's), a bracketed abbreviation, and a
    plural."""
    assert tier(record_id, question) == "product"


def test_the_vendors_other_lines_are_named_as_such_when_the_question_named_more():
    """A vendor match is the answer when the question named only the vendor, and the vendor's
    other product lines when it also named a product or a class."""
    assert tier("exp-kev-check-point-smartconsole", "Check Point") == "vendor"
    assert tier("exp-kev-ivanti-connect-secure-and-policy-secure", "Ivanti EPMM") == "other-products-of-vendor"


def test_a_handset_vendor_word_brings_no_handset_exposure_forward():
    """The Guardsquare question names Android and two build-pipeline classes. Android's handset
    catalogue records are that vendor's other lines, not an answer to it, and the handset stays
    out of scope."""
    question = "Guardsquare mobile application runtime protection, protected Android and iOS apps"
    resolved = Q.resolve(question, ALIASES)
    android = [r for r in EXPOSURES if r["who"]["vendor"] == "Android"]
    assert android
    for record in android:
        assert Q.exposure_tier(record, resolved) == "other-products-of-vendor", record["id"]


# --- a product whose alias names no vendor ------------------------------------------------

def _exposure(vendor, product):
    return {"id": "exp-test", "record_type": "exposure",
            "who": {"vendor": vendor, "products": [product], "product_class": ["app.version_control"]},
            "what": {"summary": "", "vulnerabilities": []}}


def test_a_vendorless_product_alias_matches_its_product_under_any_vendor():
    """"git" names a product and no vendor. Before the sentinel fix it put `any` into the
    resolved vendors, which the exposure tiers would have read as every vendor; after it, a
    product-tier match that requires the vendor could never fire for these products."""
    resolved = Q.resolve("git", ALIASES)
    assert "Git" in resolved["vendorless_products"]
    assert tier("exp-kev-git-git", "git") == "product"
    assert Q.exposure_tier(_exposure("Some Forge", "Git"), resolved) == "product"
    assert Q.exposure_tier(_exposure("Some Forge", "GitLab"), resolved) != "product"


def test_a_vendorless_product_reaches_no_vendor_tier():
    """No vendor resolved, so nothing can be the vendor's, or the vendor's other lines."""
    resolved = Q.resolve("npm registry", ALIASES)
    assert not resolved["vendors"] - {"npm"}
    for record in EXPOSURES:
        if record["who"]["vendor"] == "npm":
            continue
        assert Q.exposure_tier(record, resolved) not in (
            "vendor", "vendor-class", "other-products-of-vendor"), record["id"]


# --- query.py orders its exposure listing by the tier -------------------------------------

def query_json(question, *extra):
    done = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "query.py"), question,
                           "--json", *extra], capture_output=True, text=True, cwd=ROOT)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


@pytest.mark.parametrize("question", ["Check Point firewall", "Ivanti EPMM", "Linux kernel"])
def test_query_lists_named_exposures_before_class_only_ones(question):
    """Ranked on score, a Cisco firewall catalogue record tied a Check Point one at 3 on class
    alone and the id decided; six of the ten shown for "Check Point firewall" were Cisco's."""
    data = query_json(question, "--exposure-limit", "200")
    rows = [r for r in data["records"] if r["record"].get("record_type") == "exposure"]
    order = [Q.EXPOSURE_TIERS.index(r["exposure_tier"]) for r in rows]
    assert order == sorted(order), [r["exposure_tier"] for r in rows]
    named = [any(m.startswith("vendor ") for m in r["matched_on"]) for r in rows]
    assert named == sorted(named, reverse=True), "an unnamed exposure precedes a named one"
    assert sum(data["counts"]["exposures_by_tier"].values()) == data["counts"]["exposures_matched"]


def test_the_named_catalogue_record_leads_its_own_question():
    rows = [r for r in query_json("Ivanti EPMM")["records"]
            if r["record"].get("record_type") == "exposure"]
    assert rows[0]["record"]["id"] == "exp-kev-ivanti-endpoint-manager-mobile-epmm"
    assert rows[0]["exposure_tier"] == "product" and rows[0]["exposure_kind"] == "EXPLOITED"


def test_the_text_listing_labels_each_exposure_with_its_tier():
    done = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "query.py"),
                           "Check Point firewall"], capture_output=True, text=True, cwd=ROOT)
    lines = [l for l in done.stdout.splitlines() if l.startswith("exp ")]
    assert lines and all(any("  [{}]".format(t) in l for t in Q.EXPOSURE_TIERS) for l in lines)
    assert "exposures by relation to the question:" in done.stdout


# --- consult.py lists them, in blocks of their own ----------------------------------------
#
# consult.py built findings only from how-blocks, and 894 of the corpus's 1,142 records are
# exposures with none, so no question could return one: "Check Point firewall" never showed
# the two identifiers CISA added on 09-22, and corpus/README.md said the lookup returned
# exposures as a separate block when only query.py did.

import consult as C  # noqa: E402
import validate as V  # noqa: E402

TODAY = "2026-09-25"
SCOPE = C.load_scope(os.path.join(ROOT, "corpus"))
FINDING_KEYS = {"LOCUS", "LOCUS_SPAN", "LOCUS_BASIS", "RECORD_ID", "PATTERN_ID",
                "PRIORITY_BASIS", "FINDING_KEY", "RANK", "SLOT"}


def consult(question, *extra):
    done = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "consult.py"), question,
                           "--today", TODAY, *extra], capture_output=True, text=True, cwd=ROOT,
                          timeout=180)
    return done.returncode, done.stdout, done.stderr


def exposure_blocks(out):
    """Each EXPOSURE block as an ordered {KEY: value}, column-zero keys only."""
    found, current = [], None
    for line in out.splitlines():
        if line.startswith("=== EXPOSURE "):
            current = {}
        elif line.startswith("=== END EXPOSURE "):
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


def counts(line):
    """'KEY: a=1, b=2  (aside)' or 'KEY: n - a=1, b=2. prose' as {a: 1, b: 2}."""
    body = line.split(":", 1)[1]
    return {k: int(v) for k, v in re.findall(r"([A-Za-z-]+)=(\d+)", body.split("  (")[0])}


PROBES = ["Check Point firewall", "PAN-OS", "Ivanti EPMM", "Linux kernel", "Fortinet FortiGate"]


@pytest.mark.parametrize("question", PROBES)
def test_named_exposures_surface_for_every_probe(question):
    code, out, err = consult(question, "--limit", "3")
    assert code == 0, err
    assert "=== EXPOSURE 1 OF " in out
    ids = [b["EXPOSURE_ID"] for b in exposure_blocks(out)]
    if question == "Check Point firewall":
        block = [b for b in exposure_blocks(out)
                 if b["EXPOSURE_ID"] == "exp-kev-check-point-multiple-products"][0]
        assert "CVE-2026-85102" in block["EXPOSURE_IDENTIFIERS"]
        assert "CVE-2026-93616" in block["EXPOSURE_IDENTIFIERS"]
    if question == "Linux kernel":
        assert "exp-kev-linux-kernel" in ids
    if question == "Ivanti EPMM":
        assert ids[0] == "exp-kev-ivanti-endpoint-manager-mobile-epmm"
        assert exposure_blocks(out)[0]["EXPOSURE_RANK"] == "1"


@pytest.mark.parametrize("limit", ["0", "1", "10", "100"])
def test_exposure_header_counts_describe_what_was_emitted(limit):
    """`shown` is what was printed; every other count is over everything listed, before the cap,
    so it does not move with --exposure-limit."""
    code, out, _ = consult("Microsoft Windows", "--limit", "1", "--exposure-limit", limit)
    assert code == 0
    shown, total = map(int, re.search(r"^EXPOSURES: (\d+) shown of (\d+)", out, re.M).groups())
    assert shown == len(re.findall(r"^=== EXPOSURE ", out, re.M)) == min(int(limit), total)
    assert total > 10, "fixture no longer lists more than ten"
    by_tier = counts(header(out, "EXPOSURES"))
    assert sum(by_tier.values()) == total
    assert sum(counts(header(out, "EXPOSURE_KINDS")).values()) == total
    loci = counts(header(out, "EXPOSURE_LOCUS"))
    assert set(loci) == set(C.load_locus_map(C.CORPUS)["locus_order"]), "every locus, zeros too"
    assert sum(loci.values()) == total
    unlisted = header(out, "EXPOSURES_NOT_LISTED")
    parts = counts(unlisted)
    assert int(re.match(r"EXPOSURES_NOT_LISTED: (\d+) - ", unlisted).group(1)) == sum(parts.values())
    assert list(parts) == list(C.UNLISTED_EXPOSURE_TIERS)
    assert ("raise --exposure-limit" in header(out, "EXPOSURES")) == (total > shown)


def test_every_exposure_carries_the_same_key_set():
    _, out, _ = consult("Fortinet FortiGate", "--limit", "2", "--exposure-limit", "100")
    blocks = exposure_blocks(out)
    assert len(blocks) > 5
    keys = [tuple(b) for b in blocks]
    assert len(set(keys)) == 1, "an exposure block varies its key set"
    assert all(k.startswith("EXPOSURE_") for k in keys[0])
    assert not set(keys[0]) & FINDING_KEYS
    assert "EXPOSURE_ID" in keys[0] and "EXPOSURE_DETECTION_HELD" in keys[0]


@pytest.mark.parametrize("question", ["Check Point firewall", "Linux kernel"])
def test_exposures_never_move_the_findings(question):
    """The block sits beside the findings and never enters them, or the plane answer."""
    _, none, _ = consult(question, "--limit", "12", "--exposure-limit", "0")
    _, many, _ = consult(question, "--limit", "12", "--exposure-limit", "100")
    for key in ("FINDINGS", "MATCH_TIERS", "LOCUS_MATCHED", "LOCUS_ELIGIBLE", "LOCUS_SHOWN",
                "LOCUS_ABSENT", "RESOLUTION"):
        assert header(none, key) == header(many, key), key
    def findings(out):
        body = out.split("=== END HEADER ===")[1]
        return re.split(r"^=== (?:EXPOSURE|LIBRARY) ", body, flags=re.M)[0]
    assert findings(none) == findings(many)


def test_rank_by_gap_does_not_reorder_exposures():
    def order(*extra):
        return [b["EXPOSURE_ID"] for b in exposure_blocks(
            consult("Fortinet FortiGate", "--limit", "3", "--exposure-limit", "100", *extra)[1])]
    assert order("--rank-by", "gap", "--covered", "T1190") == order()


@pytest.mark.parametrize("question", PROBES + ["VMware ESXi", "Sitecore"])
def test_listed_exposures_name_what_was_asked(question):
    resolved = Q.resolve(question, ALIASES)
    _, out, _ = consult(question, "--limit", "1", "--exposure-limit", "200")
    for block in exposure_blocks(out):
        record = BY_ID[block["EXPOSURE_ID"]]
        assert Q.vendor_reason(record, resolved) or Q.product_matches(resolved, record), \
            block["EXPOSURE_ID"]
        assert block["EXPOSURE_MATCH"].split(" - ")[0] in C.NAMING_EXPOSURE_TIERS
        assert "named this technology" not in block["EXPOSURE_MATCH"]
    if question == "Linux kernel":
        assert "exp-kev-android-android-kernel" not in out


def test_the_listing_order_is_fixed_and_printed():
    kev = Q.kev_identifiers(RECORDS)
    _, out, _ = consult("Microsoft Windows", "--limit", "1", "--exposure-limit", "200")
    blocks = exposure_blocks(out)
    keys = [C.exposure_order(b["EXPOSURE_MATCH"].split(" - ")[0], BY_ID[b["EXPOSURE_ID"]], kev)
            for b in blocks]
    assert keys == sorted(keys)
    assert [b["EXPOSURE_RANK"] for b in blocks] == [str(i) for i in range(1, len(blocks) + 1)]
    for block in blocks:
        assert block["EXPOSURE_ORDER_BASIS"].startswith(
            "tier={}; kind={}; ".format(block["EXPOSURE_MATCH"].split(" - ")[0],
                                        block["EXPOSURE_KIND"].split(" - ")[0]))


def test_exposure_kind_comes_from_identifiers_not_tags():
    """Six records once denied membership of an identifier the catalogue records listed. The
    kind is read from the identifiers, so a stale tag cannot make an exploited CVE read as
    merely disclosed."""
    kev = Q.kev_identifiers(RECORDS)
    held = sorted(kev)[0]
    stale = {"id": "exp-zdi-test", "record_type": "exposure", "tags": ["not-in-kev"],
             "what": {"vulnerabilities": [held]}, "where": {"source_type": "vendor_research"}}
    assert Q.exposure_kind(stale, kev) == "EXPLOITED"
    assert Q.exposure_kind(dict(stale, what={"vulnerabilities": ["CVE-1999-0000"]}),
                           kev) == "DISCLOSED"
    _, out, _ = consult("Ivanti EPMM", "--limit", "1", "--exposure-limit", "100")
    for block in exposure_blocks(out):
        record = BY_ID[block["EXPOSURE_ID"]]
        assert block["EXPOSURE_KIND"].split(" - ")[0] == Q.exposure_kind(record, kev)
        ids = record["what"].get("vulnerabilities") or []
        assert block["EXPOSURE_KIND"].split(" - ")[1].startswith(
            "{} of {} ".format(len([v for v in ids if v in kev]), len(ids)))
    assert "KEV snapshot src-cisa-kev-" in header(out, "EXPOSURE_ORDERING")


def test_every_identifier_is_printed():
    _, out, _ = consult("Linux kernel", "--limit", "1")
    block = [b for b in exposure_blocks(out) if b["EXPOSURE_ID"] == "exp-kev-linux-kernel"][0]
    assert block["EXPOSURE_IDENTIFIERS"].split(", ") == \
        BY_ID["exp-kev-linux-kernel"]["what"]["vulnerabilities"]


def test_detection_held_points_at_the_finding_above():
    _, out, _ = consult("Check Point firewall", "--limit", "12")
    block = [b for b in exposure_blocks(out)
             if b["EXPOSURE_ID"] == "exp-kev-check-point-quantum-security-gateways"][0]
    held = block["EXPOSURE_DETECTION_HELD"]
    assert "obs-checkpoint-security-gateway-information-disclosure (Check Point)" in held
    shown = re.search(r"FINDING (\d+) above", held)
    if shown:
        finding = out.split("=== FINDING {} OF ".format(shown.group(1)))[1]
        assert re.search(r"^RECORD_ID: obs-checkpoint-security-gateway-information-disclosure$",
                         finding.split("=== END FINDING")[0], re.M)


def test_exposure_locus_follows_the_class_not_the_generator_surface():
    """A generated exposure's attack_surface restates a class default through a table that
    disagrees with by_class; the block places it by the class and says the surface was not
    read. The mobile management plane stays MANAGEMENT. The gateway pin was the Check Point
    "Multiple Products" record until 0.43.0 classed it by its management-server CVE; see
    test_a_firewall_manager_answers_management_with_control_beside_it."""
    for question, record_id, locus in [
            ("Check Point firewall", "exp-kev-check-point-security-gateway", "CONTROL"),
            ("Ivanti EPMM", "exp-kev-ivanti-endpoint-manager-mobile-epmm", "MANAGEMENT"),
            ("Linux kernel", "exp-kev-linux-kernel", "ENDPOINT")]:
        _, out, _ = consult(question, "--limit", "1")
        block = [b for b in exposure_blocks(out) if b["EXPOSURE_ID"] == record_id][0]
        assert block["EXPOSURE_LOCUS"] == locus, (question, block["EXPOSURE_LOCUS_BASIS"])
        assert block["EXPOSURE_LOCUS_SPAN"].split(", ")[0] == locus
        assert "not read" in block["EXPOSURE_LOCUS_BASIS"]


@pytest.mark.parametrize("question", ["Sitecore", "Zoho"])
def test_a_vendor_held_only_as_exposures_lists_them(question):
    code, out, _ = consult(question)
    assert code == 0
    assert header(out, "RESOLUTION").startswith("RESOLUTION: EXPOSURES_ONLY - ")
    assert "listed in the EXPOSURE blocks" in header(out, "RESOLUTION")
    shown = int(re.search(r"^EXPOSURES: (\d+) shown", out, re.M).group(1))
    assert shown > 0 and len(exposure_blocks(out)) == shown
    assert "=== FINDING " not in out
    assert "listed in the EXPOSURE blocks below" in header(out, "METHODOLOGY")


def test_a_handset_vendor_word_does_not_list_handset_exposures():
    """The Guardsquare question names Android beside two build-pipeline classes: its catalogue
    records are Android's other lines, and handsets stay out of scope in any case."""
    question = "Guardsquare mobile application runtime protection, protected Android and iOS apps"
    code, out, _ = consult(question, "--limit", "3")
    assert code == 0
    assert "=== EXPOSURE " not in out
    assert counts(header(out, "EXPOSURES_NOT_LISTED"))["other-products-of-vendor"] > 0


# --- the handset records are held, and refused with a count --------------------------------

# The exposures corpus/schema/scope.json keeps out of a consultation, pinned so a regeneration
# that adds or drops one is seen. "iOS and macOS" and its kin are macOS exposures as well and
# are not here.
HANDSET = {
    "exp-kev-android-android-kernel", "exp-kev-android-android-os", "exp-kev-android-framework",
    "exp-kev-android-pixel", "exp-kev-android-runtime", "exp-kev-apple-ios",
    "exp-kev-apple-ios-and-ipados", "exp-kev-apple-ios-ipados-and-watchos",
    "exp-kev-arm-mali-gpu-kernel-driver", "exp-kev-arm-mali-graphics-processing-unit-gpu",
    "exp-kev-code-aurora-acdb-audio-driver", "exp-kev-google-chrome-for-android-ui",
    "exp-kev-mediatek-multiple-chipsets", "exp-kev-qualcomm-multiple-chipsets",
    "exp-kev-qualcomm-snapdragon-auto-snapdragon-compute-snapdragon-connectivity-snapdragon-"
    "consumer-iot-snapdragon-industria",
    "exp-kev-samsung-mobile-devices",
}


def test_the_refused_handset_set_is_pinned():
    refused = {r["id"] for r in EXPOSURES if C.handset_record(r, SCOPE)}
    assert refused == HANDSET, (sorted(refused - HANDSET), sorted(HANDSET - refused))
    for record_id in ("exp-kev-apple-ios-and-macos", "exp-kev-apple-macos",
                      "exp-kev-samsung-magicinfo-9-server", "exp-kev-cisco-ios"):
        assert not C.handset_record(BY_ID[record_id], SCOPE), record_id


def test_a_handset_record_is_never_an_observation():
    """The refusal is of exposures only: an observation naming a handset vendor is a detection,
    and the decision keeps the handset plane out, not every record naming the vendor."""
    record = dict(BY_ID["exp-kev-apple-ios"], record_type="observation")
    assert not C.handset_record(record, SCOPE)


def test_a_vendor_question_counts_its_refused_handset_records():
    code, out, _ = consult("Android", "--limit", "3")
    assert code == 0, "Android observations still answer"
    assert "=== EXPOSURE " not in out
    assert counts(header(out, "EXPOSURES_NOT_LISTED"))["handset"] == 5

    code, out, _ = consult("Apple", "--exposure-limit", "100")
    listed = [b["EXPOSURE_ID"] for b in exposure_blocks(out)]
    assert listed and not set(listed) & HANDSET
    assert "exp-kev-apple-ios-and-macos" in listed
    assert counts(header(out, "EXPOSURES_NOT_LISTED"))["handset"] == 3


def test_a_name_held_only_as_handset_records_is_not_told_nothing_names_it():
    code, out, _ = consult("Qualcomm")
    assert code == 1, "nothing in scope names it"
    mode = header(out, "RESOLUTION")
    assert mode.startswith("RESOLUTION: UNRESOLVED - Qualcomm resolved")
    assert "no observation or exposure" not in mode
    assert "are handset records" in mode
    assert counts(header(out, "EXPOSURES_NOT_LISTED"))["handset"] == 2
    assert "THE ALIAS EXISTS AND WHAT CARRIES IT IS OUT OF SCOPE" in out
    assert "Report the name so a source can be found" not in out


# A bare handset name resolves nothing, so the vendor path above never saw it. "iOS" answered
# UNRESOLVED with handset=0, counted Apple's three handset records prose-only, said no record's
# prose carried its words over an EXPOSURES_NOT_LISTED counting nine, and advised adding the
# alias the scope decision forbids. "iPhone" reaches no record at all and got the same advice.
# (question, handset records its words name, other exposures they reach, or None when the
# question reaches none and EXPOSURES_NOT_LISTED is not printed)
BARE_HANDSET = [("iOS", 3, 6), ("iPadOS", 2, 2), ("watchOS", 1, 2), ("iPhone", 0, 1),
                ("iPad", 0, None), ("Mali", 2, 0), ("Snapdragon", 1, 0)]


@pytest.mark.parametrize("question,refused,prose", BARE_HANDSET)
def test_a_bare_handset_name_is_refused_with_a_count(question, refused, prose):
    code, out, _ = consult(question)
    assert code == 1, "nothing in scope names it"
    mode = header(out, "RESOLUTION")
    assert mode.startswith("RESOLUTION: UNRESOLVED - nothing in this question matched a vendor, "
                           "product or class; out of scope as a handset "
                           "(corpus/schema/scope.json): "), mode
    assert "no record's tags or prose" not in mode, mode
    if prose is not None:
        tally = counts(header(out, "EXPOSURES_NOT_LISTED"))
        assert (tally["handset"], tally["prose-only"]) == (refused, prose), tally
    assert ("=== THE ONLY NAME IN THE QUESTION IS ON THE HANDSET LIST, AND HANDSETS ARE OUT OF "
            "SCOPE ===") in out
    assert "A handset name is never an alias to add" in out
    assert "--as app.mdm" in out
    assert "add the vendor, product and product class to corpus/schema/aliases.json" not in out
    # The name is the table's word, not a claim about the product: the one Snapdragon record
    # also lists laptop, vehicle and module parts, and "snapdragon names a handset" overstated it.
    word = Q.normalise(question)
    assert "{} is listed there as a handset name".format(word) in mode, mode
    assert "names a handset" not in out
    # The generic re-ask offered every class, endpoint.os among them, and asked for every class
    # the technology behaves as, before the paragraph saying handsets are out of scope.
    assert "NOTHING MATCHED" not in out
    assert "CANDIDATE_CLASSES" not in out and "NAME EVERY CLASS IT BEHAVES AS" not in out


# A management product the alias table does not know, named beside a handset word, is the
# plane the scope keeps in. The bare refusal caught it, called the question out of scope and
# said no alias was missing: Kandji, Mosyle, Hexnode, MaaS360, Addigy and SOTI have no alias,
# and "jamf" is a word of the alias "jamf pro" only. The fix let any word that reached nothing
# stop the refusal, and a spyware family or a handset app written as a name ("Pegasus",
# "iMessage") was then offered as the product managing the devices. Nothing in the word tells
# the two apart, so both get one answer: the refusal stands, and names the word the plane turns
# on. (question, the names that reached nothing, the handset records its handset word names)
NAME_BESIDE_HANDSET = [("Kandji for iOS", "kandji", 3), ("Jamf iOS", "jamf", 3),
                       ("MaaS360 iOS", "maas360", 3), ("Mosyle iPad", "mosyle", 0),
                       ("Hexnode watchOS", "hexnode", 1),
                       ("SOTI MobiControl iPhone", "mobicontrol, soti", 0),
                       ("Pegasus iOS", "pegasus", 3), ("iOS iMessage", "imessage", 3),
                       ("Pegasus spyware on iPhone", "pegasus", 0)]


@pytest.mark.parametrize("question,unknown,refused", NAME_BESIDE_HANDSET)
def test_a_name_beside_a_handset_name_is_the_word_the_plane_turns_on(question, unknown, refused):
    code, out, _ = consult(question)
    assert code == 1
    names = unknown.split(", ")
    mode = header(out, "RESOLUTION")
    assert mode.startswith(
        "RESOLUTION: UNRESOLVED - nothing in this question matched a vendor, product or class; "
        "out of scope as a handset (corpus/schema/scope.json) unless {} names the product that "
        "manages these devices: ".format(" or ".join(names))), mode
    assert ("=== THE QUESTION NAMES A HANDSET, BESIDE A NAME THIS CORPUS DOES NOT KNOW ==="
            in out)
    assert "; {} reached no record.".format(unknown) in out
    assert "Which plane the question is on turns on {}".format(unknown) in out
    one = len(names) == 1
    assert ("if {} the product that enrols and manages these devices, the question is on the "
            "mobile management plane, which is in scope, and the name is a gap in "
            "corpus/schema/aliases.json: add its vendor and product with class app.mdm"
            .format("it names" if one else "they name")) in out
    assert ("If {} something on the handset, an app, a feature or spyware, the question is a "
            "handset question, and nothing is to be added.".format(
                "it names" if one else "they name")) in out
    assert "A handset name is never an alias to add" in out
    # Never the headline that calls the question a gap in the alias table, and never the
    # sentence reading the name as the managing product: "Pegasus" is spyware.
    assert "IF THIS IS A TECHNOLOGY THE CORPUS SHOULD KNOW BY NAME" not in out
    assert "its class is app.mdm" not in out
    assert "THE ONLY NAME IN THE QUESTION" not in out
    assert "CANDIDATE_CLASSES" not in out
    if refused:
        assert counts(header(out, "EXPOSURES_NOT_LISTED"))["handset"] == refused


# An ordinary word is no name. "iOS spyware", "iPhone spyware" and "stalkerware on iPhone" were
# refused, and became alias gaps once any word that reached nothing stopped the refusal: the
# answer named spyware as the term to add to aliases.json.
ORDINARY_BESIDE_HANDSET = ["iOS spyware", "iPhone spyware", "stalkerware on iPhone",
                           "iOS jailbroken", "iOS imessage", "iOS pegasus", "kandji ios",
                           "iOS byod", "iOS 18.1"]


@pytest.mark.parametrize("question", ORDINARY_BESIDE_HANDSET)
def test_an_ordinary_word_beside_a_handset_name_never_stops_the_refusal(question):
    code, out, _ = consult(question)
    assert code == 1
    mode = header(out, "RESOLUTION")
    assert ("; out of scope as a handset (corpus/schema/scope.json): " in mode
            and " unless " not in mode), mode
    assert ("=== THE ONLY NAME IN THE QUESTION IS ON THE HANDSET LIST, AND HANDSETS ARE OUT OF "
            "SCOPE ===") in out
    assert "reached no record" not in out
    assert "add the vendor, product and product class to corpus/schema/aliases.json" not in out
    assert "IF THIS IS A TECHNOLOGY THE CORPUS SHOULD KNOW BY NAME" not in out


def test_a_word_is_a_name_only_written_as_one():
    """unknown_names() reads the question's own spelling: a lower-case word and a version
    number are no name, and a refused alias's word and a handset name never are one."""
    def names(question):
        resolved = Q.resolve(question, ALIASES)
        return C.unknown_names(resolved, resolved["terms"], SCOPE, question)
    assert names("Kandji for iOS") == ["kandji"]
    assert names("kandji for iOS") == []
    assert names("iOS 18.1 MaaS360") == ["maas360"]
    assert names("iOS 18.1") == []
    assert names("Arm Mali") == []


@pytest.mark.parametrize("question,word", [("banks in Mali", "mali"),
                                           ("Mali government ministries", "mali")])
def test_a_place_beside_a_sector_is_not_refused(question, word):
    """A sector is something that resolved: "Mali" beside one is a country, and was refused as
    Arm's GPU with its two driver records. The word is still never an alias to add, and the
    management plane is offered on the condition that it names a handset; "ministries" reached
    nothing and is written as no name, so it is neither the word to add nor the product
    managing the devices."""
    code, out, _ = consult(question)
    assert code == 1
    assert Q.resolve(question, ALIASES)["sectors"], "the sector resolves"
    assert word in SCOPE["handset_names_also_places"]
    assert "handset" not in header(out, "RESOLUTION")
    assert counts(header(out, "EXPOSURES_NOT_LISTED"))["handset"] == 0
    assert "THE ONLY NAME IN THE QUESTION" not in out
    assert ("Never add {}: it is listed in corpus/schema/scope.json as a handset name. If it "
            "names a handset, the mobile management plane is in scope: re-ask with --as "
            "app.mdm.".format(word)) in out
    assert "enrols and manages" not in out and "reached no record" not in out


@pytest.mark.parametrize("question,refused", [("iOS in government", 3), ("iOS banking apps", 3),
                                              ("iOS devices in hospitals", 3),
                                              ("iPhone healthcare", 0)])
def test_a_handset_name_beside_a_sector_is_refused(question, refused):
    """Any sector once stopped the refusal, to answer "banks in Mali": "iOS in government" then
    counted Apple's three handset records prose-only, handset=0, and was told to add an alias.
    Only a word scope.json also lists as a place is read as one."""
    code, out, _ = consult(question)
    assert code == 1
    assert Q.resolve(question, ALIASES)["sectors"], "the sector resolves"
    mode = header(out, "RESOLUTION")
    assert "; out of scope as a handset (corpus/schema/scope.json): " in mode, mode
    assert counts(header(out, "EXPOSURES_NOT_LISTED"))["handset"] == refused
    assert ("=== THE ONLY NAME IN THE QUESTION IS ON THE HANDSET LIST, AND HANDSETS ARE OUT OF "
            "SCOPE ===") in out
    assert "IF THIS IS A TECHNOLOGY THE CORPUS SHOULD KNOW BY NAME" not in out


def test_several_handset_names_agree_in_number():
    code, out, _ = consult("iPhone and iPad")
    assert code == 1
    mode = header(out, "RESOLUTION")
    assert ("ipad, iphone are listed there as handset names, and no exposure record names them;"
            in mode), mode


def test_a_refused_alias_beside_a_handset_name_is_not_an_unknown_name():
    """The guard: "arm" in "Arm Mali" reached nothing, and is Arm's vendor alias, refused as
    GATED says; adding it would change nothing, so the question is still refused."""
    code, out, _ = consult("Arm Mali")
    assert code == 1
    assert "arm (vendor Arm" in header(out, "GATED")
    assert "out of scope as a handset" in header(out, "RESOLUTION")
    assert "add the vendor, product and product class to corpus/schema/aliases.json" not in out


def test_a_handset_name_that_is_also_a_refused_alias_names_both_meanings():
    """Bare "IOS" is Cisco's spelling as well. GATED offered Cisco IOS, and the refusal below it
    named only the handset."""
    code, out, _ = consult("IOS")
    assert code == 1
    assert "ios (product Cisco / IOS" in header(out, "GATED")
    assert ('ios is also the alias of Cisco IOS, refused as GATED says: if that is what you '
            'meant, ask "Cisco IOS".') in out
    assert "is also the alias of" not in consult("iPadOS")[1]


@pytest.mark.parametrize("question,refused,prose", [q for q in BARE_HANDSET if q[2] is not None])
def test_the_bare_refusal_counts_what_the_listing_counts(question, refused, prose):
    """The records refused are scope.json's handset records, reached by a word in their own
    product name: "iOS and macOS" is a macOS exposure as well and stays counted prose-only."""
    resolved = Q.resolve(question, ALIASES)
    reasons = {r["id"]: Q.score(r, resolved, PATTERNS)[1] for r in EXPOSURES}
    listing = C.exposure_listing(RECORDS, resolved, SCOPE, None, reasons)
    held = {r["id"] for _, r in listing.handset}
    assert held <= HANDSET and len(held) == refused, sorted(held)
    assert not listing.listed


@pytest.mark.parametrize("question", [
    "Cisco ASA VPN users on iOS and Android phones",
    "Guardsquare mobile application runtime protection, protected Android and iOS apps",
    "iOS MDM", "Cisco IOS", "Apple iOS", "Qualcomm", "Android",
])
def test_a_handset_word_beside_what_resolved_is_not_a_bare_refusal(question):
    """Beside anything that resolved, the question is answered for that: the management plane
    is in scope, and so is an app-shielding product protecting handset apps."""
    _, out, _ = consult(question, "--limit", "1")
    assert "out of scope as a handset" not in header(out, "RESOLUTION")
    assert "THE ONLY NAME IN THE QUESTION IS ON THE HANDSET LIST" not in out
    assert "THE QUESTION NAMES A HANDSET" not in out


@pytest.mark.parametrize("question", ["gpu", "audio", "chipsets", "wearables"])
def test_a_word_of_a_handset_products_name_is_not_a_handset_name(question):
    """Counting any word that stands in a handset record's product name was measured and
    refused: "gpu", "audio" and "chipsets" were answered as handset questions. Only scope.json's
    handset_names refuse."""
    code, out, _ = consult(question)
    assert code == 1
    assert "out of scope as a handset" not in header(out, "RESOLUTION")
    assert counts(header(out, "EXPOSURES_NOT_LISTED"))["handset"] == 0
    assert "IF THIS IS A TECHNOLOGY THE CORPUS SHOULD KNOW BY NAME" in out


def test_an_unknown_name_still_reads_as_a_gap_in_the_alias_table():
    code, out, _ = consult("Zorblax")
    assert code == 1
    assert header(out, "RESOLUTION") == ("RESOLUTION: UNRESOLVED - nothing in this question "
                                         "matched a vendor, product or class, and no record's "
                                         "tags or prose carried its words either")
    assert "IF THIS IS A TECHNOLOGY THE CORPUS SHOULD KNOW BY NAME" in out


def test_an_unresolved_line_never_denies_the_exposures_it_counts():
    """"tvOS" reaches one exposure by its prose and is no handset: the line said no record's
    prose carried its words."""
    code, out, _ = consult("tvOS")
    assert code == 1
    mode = header(out, "RESOLUTION")
    assert "no record's tags or prose" not in mode
    assert "no observation's tags or prose carried its words; 1 exposure record(s) did" in mode
    assert counts(header(out, "EXPOSURES_NOT_LISTED"))["prose-only"] == 1
    assert "IF THIS IS A TECHNOLOGY THE CORPUS SHOULD KNOW BY NAME" in out


def test_query_never_advises_an_alias_for_a_handset_name():
    """query.py lists handset records, labelled; where nothing matched it advised an alias."""
    def query(question):
        return subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "query.py"),
                               question], capture_output=True, text=True, cwd=ROOT,
                              timeout=180).stdout
    out = query("iPad")
    assert ("Nothing matched. ipad is listed in corpus/schema/scope.json as a handset name, "
            "which this corpus does not advise on; no alias is to be added.") in out
    assert "needs an entry in corpus/schema/aliases.json" not in out
    assert "needs an entry in corpus/schema/aliases.json" in query("Zorblax")
    # A name beside the handset name may be the product managing the devices, or something on
    # the handset, as consult.py says; an ordinary word is no name and refuses as before.
    out = query("Kandji iPad")
    assert ("Nothing matched. ipad is listed in corpus/schema/scope.json as a handset name, "
            "which this corpus does not advise on; a handset name is never an alias to add. "
            "kandji reached no record: if it names the product that enrols and manages these "
            "devices, it needs an entry in corpus/schema/aliases.json with class app.mdm; if it "
            "names something on the handset, nothing is to be added.") in out
    out = query("iPad jailbroken")
    assert ("Nothing matched. ipad is listed in corpus/schema/scope.json as a handset name, "
            "which this corpus does not advise on; no alias is to be added.") in out
    assert "jailbroken" not in out.split("Nothing matched.")[1]


def test_validate_refuses_a_handset_name_that_can_never_be_refused():
    aliases = json.load(open(os.path.join(ROOT, "corpus", "schema", "aliases.json"),
                             encoding="utf-8"))
    problems = []
    V.check_handset_names(SCOPE, aliases, problems)
    assert problems == []
    V.check_handset_names({"handset_names": ["android", "ios", "ip", "iPhone"]}, aliases,
                          problems)
    text = " ".join(p.message for p in problems)
    assert "'android'" in text and "'ip'" in text and "'iPhone'" in text, text
    assert "'ios'" not in text, "an ambiguous alias is gated, and stays a word"
    # A place is read as one only for a handset name; listed alone it would excuse nothing.
    problems = []
    V.check_handset_names({"handset_names": ["ios", "mali"],
                           "handset_names_also_places": ["mali", "chad"]}, aliases, problems)
    assert [p.message for p in problems] == [
        "handset_names_also_places entry 'chad' is not in handset_names, so it is never read"]


@pytest.mark.parametrize("question", ["Apple iOS", "Apple iPhone"])
def test_a_handset_name_beside_its_vendor_points_at_the_management_plane(question):
    """"Apple iOS" resolves the vendor and lists its six exposures, and was then sent to
    --as endpoint.os, the classes those exposures carry, without saying iOS is a handset: the
    plane the scope decision keeps out, never the management plane it keeps in."""
    code, out, _ = consult(question)
    assert code == 0, "the vendor's exposures are an answer"
    mode = header(out, "RESOLUTION")
    assert mode.startswith("RESOLUTION: EXPOSURES_ONLY - "), mode
    assert "names a handset, which this corpus does not advise on" in mode, mode
    assert "--as app.mdm" in mode and "the classes these exposures carry" not in mode, mode
    assert "; 3 handset exposure record(s) naming it are held" in mode, mode
    method = header(out, "METHODOLOGY")
    assert "--as app.mdm" in method and "naming every class it behaves as" not in method, method
    # "so" made the missing observation read as the reason iOS is a handset.
    assert "There is no observation to build a detection from, and {} names a handset".format(
        Q.normalise(question.split()[-1])) in method, method


def test_a_vendor_alone_is_still_pointed_at_its_exposures_classes():
    """The guard: "Apple" names no handset, and keeps the class-level --as pointer."""
    code, out, _ = consult("Apple")
    assert code == 0
    assert "the classes these exposures carry: endpoint.os (6)" in header(out, "RESOLUTION")
    assert "the classes these exposures carry are endpoint.os (6)" in header(out, "METHODOLOGY")
    assert "names a handset" not in out


def test_validate_refuses_a_stale_scope_entry():
    names = [(r["who"]["vendor"], r["who"]["products"]) for r in EXPOSURES]
    problems = []
    V.check_scope(SCOPE, names, problems)
    assert problems == []
    V.check_scope({"handset_exposures": {"Nokia Mobile": ["*"], "Apple": ["ipodos"]}}, names,
                  problems)
    text = " ".join(p.message for p in problems)
    assert "'Nokia Mobile'" in text and "'ipodos'" in text, text


# --- --role keeps exposures as it keeps findings ------------------------------------------

def test_a_role_filter_that_keeps_exposures_lists_them():
    """Every exposure is a victim record. Filtered to victim, an exposure-only name keeps its
    exposures and answers; filtered to another role it keeps none and is emptied."""
    code, out, _ = consult("Sitecore", "--role", "victim")
    assert code == 0 and exposure_blocks(out)
    assert "4 of 4 exposure records naming it kept" in header(out, "ROLE_FILTER")
    code, out, _ = consult("Sitecore", "--role", "telemetry_source")
    assert code == 1 and "=== EXPOSURE " not in out
    assert "0 of 4 exposure records naming it kept" in header(out, "ROLE_FILTER")


def test_a_handset_product_answered_at_class_level_says_its_records_were_held_back():
    """"Android kernel" resolves the Android vendor, its kernel and endpoint.os, and is answered
    from desktop and server records at class level; the line must not read as though nothing
    names it."""
    code, out, _ = consult("Android kernel", "--limit", "1")
    assert code == 0
    mode = header(out, "RESOLUTION")
    assert mode.startswith("RESOLUTION: CLASS-LEVEL (inferred)"), mode
    assert "5 handset exposure record(s) naming it are held and not listed" in mode, mode
    assert header(out, "CLASS_LEVEL_WARNING")


def test_a_declared_class_alone_lists_no_exposure():
    """--as names a class, and a class match alone never lists an exposure: the class-only ones
    are counted."""
    code, out, _ = consult("Portkey", "--as", "app.ai_platform", "--limit", "1")
    assert code == 0
    assert "=== EXPOSURE " not in out
    assert header(out, "EXPOSURES").startswith("EXPOSURES: 0 shown of 0 ")
    assert counts(header(out, "EXPOSURES_NOT_LISTED"))["class-only"] > 0


# --- a catch-all catalogue entry, read by its descriptions ---------------------------------
#
# The catalogue files some identifiers under "Multiple Products" (or "Multiple Routers",
# "MobileIron Multiple Products"), and its description of each names the products. The tier
# read who.products alone, so "Fortinet Multiple Products", naming FortiOS for five of its six
# exploited identifiers, was "not the product asked about" for FortiGate and sat seventh, below a
# PSIRT record none of whose fifteen identifiers is exploited.

KEV_EXPOSURES = [r for r in EXPOSURES if Q.KEV_TAG in (r.get("tags") or [])]
FORTIOS_FIVE = ["CVE-2025-25249", "CVE-2026-24858", "CVE-2025-59718", "CVE-2024-23113",
                "CVE-2022-40684"]


def test_every_catalogue_summary_reads_back_as_its_descriptions():
    """The descriptions are read back from the generator's summary, in its two fixed forms. A
    change of wording there would silently read nothing; this fails instead."""
    bad = []
    for record in KEV_EXPOSURES:
        ids = record["what"]["vulnerabilities"]
        read = Q.catalogue_descriptions(record)
        if len(read) != min(len(ids), 6) or not set(read) <= set(ids) or not all(read.values()):
            bad.append("{}: {} of {} read".format(record["id"], len(read), len(ids)))
    assert not bad, "\n".join(bad)
    assert Q.catalogue_descriptions(BY_ID["exp-fortinet-fortios-mfa-bypass-username-case"]) == {}


@pytest.mark.parametrize("question,record_id,own", [
    ("Fortinet FortiGate", "exp-kev-fortinet-multiple-products", FORTIOS_FIVE),
    ("Fortinet FortiMail", "exp-kev-fortinet-multiple-products", ["CVE-2025-32756"]),
    ("Check Point Security Gateway", "exp-kev-check-point-multiple-products", ["CVE-2026-85102"]),
    ("Mozilla Firefox", "exp-kev-mozilla-multiple-products", ["CVE-2010-3765"]),
    ("VMware vRealize Automation", "exp-kev-vmware-multiple-products", ["CVE-2022-22960"]),
    # "Ivanti MobileIron's Core & Connector, Sentry, and ...": MobileIron Core is EPMM's former
    # name, and the EPMM answer carried the same identifier at product tier from a hand-written
    # record while calling this one "not the product asked about".
    ("Ivanti EPMM", "exp-kev-ivanti-mobileiron-multiple-products", ["CVE-2020-15505"]),
])
def test_a_catch_all_entry_is_the_product_its_description_names(question, record_id, own):
    resolved = Q.resolve(question, ALIASES)
    record = BY_ID[record_id]
    assert not Q.product_matches(resolved, record), "the product field names nothing"
    assert Q.exposure_tier(record, resolved) == "product"
    assert Q.product_identifiers(resolved, record) == sorted(own)


@pytest.mark.parametrize("text,subject", [
    ("Ivanti MobileIron's Core & Connector, Sentry, and Monitor",
     "Ivanti MobileIron Core, Ivanti MobileIron Connector, Sentry, and Monitor"),
    ("WSO2 API Manager, Traffic Manager & Universal Gateway",
     "WSO2 API Manager, Traffic Manager, Universal Gateway"),
    ("Fortinet FortiOS, FortiProxy, and FortiSwitchManager",
     "Fortinet FortiOS, FortiProxy, and FortiSwitchManager"),
])
def test_a_description_subject_is_read_as_a_product_list(text, subject):
    assert Q.description_subject(text) == subject


@pytest.mark.parametrize("question,record_id", [
    ("Fortinet FortiSandbox", "exp-kev-fortinet-multiple-products"),
    ("Check Point SmartConsole", "exp-kev-check-point-multiple-products"),
    ("Cisco ASA", "exp-kev-cisco-multiple-products"),
])
def test_a_catch_all_entry_naming_other_products_stays_the_vendors_other_line(question,
                                                                            record_id):
    resolved = Q.resolve(question, ALIASES)
    assert Q.exposure_tier(BY_ID[record_id], resolved) != "product"
    assert Q.product_identifiers(resolved, BY_ID[record_id]) == []


def test_the_catch_all_match_says_which_identifiers_name_the_product():
    code, out, err = consult("Fortinet FortiGate", "--limit", "1", "--exposure-limit", "20")
    assert code == 0, err
    blocks = exposure_blocks(out)
    ids = [b["EXPOSURE_ID"] for b in blocks]
    block = blocks[ids.index("exp-kev-fortinet-multiple-products")]
    assert block["EXPOSURE_MATCH"] == (
        "product - PRODUCT - filed under Multiple Products, which names no product; the "
        "catalogue's own description names the product asked about for 5 of its 6 "
        "identifier(s): FortiOS (as FortiGate) in {}; its description of CVE-2025-32756 does "
        "not name it".format(", ".join(FORTIOS_FIVE)))
    assert ids.index("exp-kev-fortinet-multiple-products") < ids.index("exp-psirt-fortinet-fortios")
    assert counts(header(out, "EXPOSURES"))["product"] == 7
    listing = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "query.py"),
                              "Fortinet FortiGate", "--exposure-limit", "20"],
                             capture_output=True, text=True, cwd=ROOT, timeout=180).stdout
    assert "catalogue description names the product: FortiOS (as FortiGate) in {}".format(
        ", ".join(FORTIOS_FIVE)) in listing


def test_a_catch_all_match_counts_the_identifiers_its_record_does_not_describe():
    """Apple's catch-all record carries 53 identifiers and its summary describes six."""
    resolved = Q.resolve("Apple macOS", ALIASES)
    record = BY_ID["exp-kev-apple-multiple-products"]
    assert Q.exposure_tier(record, resolved) == "product"
    text = C.exposure_match_text("product", record, resolved)
    unread = len(record["what"]["vulnerabilities"]) - 6
    assert text.endswith("; {} are not described in this record, so whether the catalogue "
                         "names the product for them is not read here".format(unread)), text


def test_the_identifier_join_takes_only_the_identifiers_naming_the_product():
    """An observation carrying an identifier of a product-tier exposure is reached through it.
    For a catch-all entry that is only an identifier whose description names the product:
    CVE-2020-4006's names Workspace ONE Access and not vRealize Automation, so the two
    state-actor lists carrying it are reached for the one and not for the other."""
    lists = {"obs-generic-russian-state-broad-known-vulnerability-set",
             "obs-generic-russian-state-initial-access-vulnerability-set"}
    data = query_json("VMware Workspace ONE Access", "--limit", "200")
    reasons = {r["record"]["id"]: r["matched_on"] for r in data["records"]}
    for rid in lists:
        assert any(r.startswith("identifier CVE-2020-4006 (in ") and
                   "exp-kev-vmware-multiple-products" in r for r in reasons.get(rid, ())), rid
    data = query_json("VMware vRealize Automation", "--limit", "200")
    reasons = {r["record"]["id"]: r["matched_on"] for r in data["records"]}
    assert not [rid for rid, why in reasons.items() if any("CVE-2020-4006" in r for r in why)]
    row = next(r for r in data["records"] if r["record"]["id"] == "exp-kev-vmware-multiple-products")
    assert row["exposure_tier"] == "product"
    assert row["catalogue_names"] == {"CVE-2022-22960": "vRealize Automation"}


# --- which identifiers each carrier holds -------------------------------------------------

def held_map():
    vendor_of = {r["id"]: r["who"]["vendor"] for r in RECORDS}
    return {i: {(rid, vendor_of[rid]) for rid in rids}
            for i, rids in Q.identifier_carriers(RECORDS).items()}


def test_detection_held_says_which_identifiers_each_carrier_holds():
    """The field listed a carrier if it held any identifier. The EPMM catalogue record named the
    2023 chain's observation, which carries two of its seven exploited identifiers; the 2025 and
    2026 five are carried by nothing, and only a sentence in the prose summary said so."""
    code, out, err = consult("Ivanti EPMM", "--limit", "4")
    assert code == 0, err
    block = next(b for b in exposure_blocks(out)
                 if b["EXPOSURE_ID"] == "exp-kev-ivanti-endpoint-manager-mobile-epmm")
    assert block["EXPOSURE_DETECTION_HELD"] == (
        "2 of 7 identifier(s) carried; "
        "obs-ivanti-epmm-authentication-bypass-and-arbitrary-file-write-chain (Ivanti) carries "
        "CVE-2023-35078, CVE-2023-35081 - FINDING 1 above; no observation carries CVE-2025-4427, "
        "CVE-2025-4428, CVE-2026-1281, CVE-2026-1340, CVE-2026-6973")


def test_detection_held_reads_back_as_the_carrier_map_for_every_exposure():
    """Parsed back, every exposure's line names exactly query.py's carriers with exactly the
    identifiers each carries, and the rest as carried by none."""
    held, carriers = held_map(), Q.identifier_carriers(RECORDS)
    part = re.compile(r"^(\S+) \([^)]*\) carries ((?:CVE-\d{4}-\d+(?:, )?)+)$")
    for record in EXPOSURES:
        ids = record["what"].get("vulnerabilities") or []
        text = C.detection_held_text(ids, held, {})
        expect = Q.carried_by(record, carriers)
        if not expect:
            assert text.startswith("none - "), (record["id"], text)
            continue
        parts = text.split("; ")
        count = re.match(r"^(\d+) of (\d+) identifier\(s\) carried$", parts[0])
        got = {m.group(1): sorted(m.group(2).split(", "))
               for m in map(part.match, parts[1:-1])}
        carried = set().union(*map(set, expect.values()))
        assert got == expect, record["id"]
        assert count and (int(count.group(1)), int(count.group(2))) == (len(carried), len(ids))
        rest = [i for i in ids if i not in carried]
        assert parts[-1] == ("no observation carries " + ", ".join(rest) if rest
                             else "every identifier is carried"), record["id"]
