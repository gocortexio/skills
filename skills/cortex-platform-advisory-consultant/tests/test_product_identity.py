# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Which records name the product asked about, and which words may reach a record at all.

The 0.43.0 validation found the resolver's idea of "the same product" too narrow in three ways
and too wide in one:

- One product under several names. FortiOS is the operating system every FortiGate runs, and
  a FortiGate question tiered 9 of its 10 exposures and 5 of its own findings as the vendor's
  other lines, saying of records whose technology line read "FortiGate SSL VPN" that they did
  not name FortiGate. A catalogued, ransomware-linked SSL-VPN flaw was left out of the answer
  altogether. EPMM and MobileIron Core, its former name, were the same.
  `product_families` in corpus/schema/aliases.json records these as data.
- One entry naming several products. The catalogue writes "Adaptive Security Appliance (ASA)
  and Firepower Threat Defense (FTD)" as one string, and it was compared whole, so three ASA
  records were "not the product asked about".
- An alias the resolver held and never consulted. "Exchange" resolves to Exchange Server, and
  the records spelt "Exchange" were still the vendor's other lines.
- Too wide: a word refused as a product ("quantum", "ios") stayed a free-text term and reached
  the very product it was refused as, by name.

Two more from the same probes: a Windows binary named like a Unix command, and an exposure
saying its identifier was carried by an observation without saying which, which the lookup
then could not reach.

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

TODAY = "2026-09-30"
RAW = json.load(open(os.path.join(ROOT, "corpus", "schema", "aliases.json"), encoding="utf-8"))
ALIASES = Q.normalise_alias_keys(RAW)
RECORDS, PATTERNS = Q.load_corpus(os.path.join(ROOT, "corpus"))
BY_ID = {r["id"]: r for r in RECORDS}


def tier(record_id, question):
    return Q.exposure_tier(BY_ID[record_id], Q.resolve(question, ALIASES))


def reasons(record_id, question):
    return Q.score(BY_ID[record_id], Q.resolve(question, ALIASES), PATTERNS)[1]


def consult(question, *extra):
    done = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "consult.py"), question,
                           "--today", TODAY, *extra],
                          capture_output=True, text=True, cwd=ROOT, timeout=180)
    assert done.returncode in (0, 1), done.stderr
    return done.stdout


def query(question, *extra):
    done = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "query.py"), question,
                           *extra], capture_output=True, text=True, cwd=ROOT, timeout=180)
    assert done.returncode == 0, done.stderr
    return done.stdout


def blocks(out, kind):
    """Each FINDING or EXPOSURE block of a consultation as {key: value}."""
    found = []
    for body in re.findall(r"^=== {} \d+ OF \d+ ===\n(.*?)^=== END {} \d+ ===".format(kind, kind),
                           out, re.M | re.S):
        found.append(dict(re.findall(r"^([A-Z_]+): ?(.*)$", body, re.M)))
    return found


def header(out, key):
    return next((l for l in out.splitlines() if l.startswith(key + ":")), "")


# --- one product under several names --------------------------------------------------------

@pytest.mark.parametrize("record_id", [
    "exp-kev-fortinet-fortios",
    "exp-kev-fortinet-fortios-and-fortiproxy-ssl-vpn",
    "exp-fortinet-fortios-mfa-bypass-username-case",
    "exp-psirt-fortinet-fortios",
])
def test_a_fortios_exposure_is_a_fortigate_exposure(record_id):
    assert tier(record_id, "Fortinet FortiGate") == "product"


def test_the_family_runs_both_ways():
    # A record naming FortiGate alone. The corpus held one, exp-psirt-fortinet-fortigate, until
    # the PSIRT attribution fix of the same release filed both its advisories under FortiOS,
    # the product their version tables name; the shape is kept as a fixture.
    fortigate_only = {"id": "exp-fixture-fortigate", "record_type": "exposure",
                      "who": {"vendor": "Fortinet", "products": ["FortiGate"],
                              "product_class": ["network.firewall"]},
                      "what": {"summary": "", "vulnerabilities": []}, "tags": []}
    assert Q.exposure_tier(fortigate_only, Q.resolve("Fortinet FortiOS", ALIASES)) == "product"
    assert tier("exp-kev-ivanti-endpoint-manager-mobile-epmm", "Ivanti MobileIron Core") == "product"


def test_a_record_naming_the_ssl_vpn_names_fortigate():
    """The component is FortiGate's: MATCH_BASIS said "not the product asked about (FortiGate)"
    beside TECHNOLOGY: Fortinet / FortiOS; FortiGate SSL VPN."""
    why = reasons("obs-fortinet-ssl-vpn-auth-bypass-with-two-factor-enabled", "Fortinet FortiGate")
    assert "product FortiGate SSL VPN (a component of FortiGate), FortiOS (as FortiGate)" in why, why


def test_the_fortigate_answer_lists_the_ssl_vpn_flaw_and_calls_nothing_it_names_another_line():
    out = consult("Fortinet FortiGate", "--limit", "12", "--exposure-limit", "100")
    listed = {b["EXPOSURE_ID"]: b for b in blocks(out, "EXPOSURE")}
    ssl = listed.get("exp-kev-fortinet-fortios-and-fortiproxy-ssl-vpn")
    assert ssl and ssl["EXPOSURE_MATCH"].startswith("product - PRODUCT"), sorted(listed)
    assert "CVE-2023-27997" in ssl["EXPOSURE_IDENTIFIERS"]
    for finding in blocks(out, "FINDING"):
        tech = finding["TECHNOLOGY"]
        if re.search(r"\bForti(Gate|OS)\b", tech) and tech.startswith("Fortinet"):
            assert finding["MATCH_TIER"] == "product", (finding["RECORD_ID"], tech)
            assert "not the product asked about" not in finding["MATCH_BASIS"]
    tally = header(out, "EXPOSURES")
    # 7 until the PSIRT record naming FortiGate alone was folded into FortiOS's, which carried
    # both its identifiers already (0.43.0, the attribution fix), and 7 again since the
    # catalogue's "Multiple Products" entry is read by its descriptions, five of which name
    # FortiOS (0.43.0, the catch-all entry).
    assert "product=7," in tally, tally


def test_a_component_asked_about_brings_only_itself():
    """KSMBD is the kernel's: a kernel question reaches it, a KSMBD question does not reach
    the kernel's other flaws."""
    kernel = Q.product_forms(RAW, "Linux", "Kernel", {("linux",)})
    ksmbd = Q.product_forms(RAW, "Linux", "Kernel KSMBD", {("linux",)})
    assert kernel.get(("kernel", "ksmbd")) == "component", kernel
    assert ("kernel",) not in ksmbd, ksmbd
    assert tier("exp-zdi-linux-kernel-ksmbd", "Linux kernel") == "product"


def test_epmm_and_mobileiron_core_are_one_product_and_epm_is_not_it():
    assert tier("exp-kev-ivanti-endpoint-manager-mobile-epmm-and-mobileiron-core",
                "Ivanti EPMM") == "product"
    assert tier("exp-mobileiron-core-connector-authentication-bypass-rce", "Ivanti EPMM") == "product"
    assert tier("exp-kev-ivanti-endpoint-manager-epm", "Ivanti EPMM") == "vendor-class"
    ids = [b["EXPOSURE_ID"] for b in blocks(consult("Ivanti EPMM", "--limit", "1",
                                                    "--exposure-limit", "100"), "EXPOSURE")]
    both = ids.index("exp-kev-ivanti-endpoint-manager-mobile-epmm-and-mobileiron-core")
    assert both < ids.index("exp-kev-ivanti-endpoint-manager-epm"), ids


CSA_CATALOGUE = ("exp-kev-ivanti-cloud-services-appliance-csa",
                 "exp-kev-ivanti-cloud-services-appliance",
                 "exp-kev-ivanti-endpoint-manager-cloud-service-appliance-epm-csa")


@pytest.mark.parametrize("question", ["Ivanti Cloud Service Appliance",
                                      "Ivanti Cloud Services Appliance", "Ivanti EPM CSA"])
def test_the_cloud_service_appliance_is_one_product_by_each_of_its_names(question):
    """AA25-022A calls the appliance Cloud Service Appliance, the catalogue Cloud Services
    Appliance (CSA), and for its 2021 flaw Endpoint Manager Cloud Service Appliance (EPM CSA):
    one 4.6 appliance, which NVD's own description of that flaw calls the EPM Cloud Services
    Appliance (CSA). "Service" and "Services" differ mid-name, so no canonical form joined them,
    and a question naming the appliance as the advisory does reached its two catalogue records
    only through the class its alias shared with them. Moving that alias to
    network.remote_access in the same release left the answer with no exposure at all."""
    for record_id in CSA_CATALOGUE:
        assert tier(record_id, question) == "product", (record_id, question)
    assert any(r.startswith("product ") for r in reasons(
        "obs-ivanti-cloud-service-appliance-chained-exploitation", question)), question


def test_the_cloud_service_appliance_answer_lists_its_catalogue_records():
    out = consult("Ivanti Cloud Service Appliance", "--limit", "1", "--exposure-limit", "100")
    listed = {b["EXPOSURE_ID"]: b for b in blocks(out, "EXPOSURE")}
    for record_id in CSA_CATALOGUE:
        assert record_id in listed, sorted(listed)
        assert listed[record_id]["EXPOSURE_MATCH"].startswith("product - PRODUCT"), \
            listed[record_id]["EXPOSURE_MATCH"]
    assert "product=3," in header(out, "EXPOSURES"), header(out, "EXPOSURES")
    # Endpoint Manager is the product the appliance serves, not the appliance: an EPM question
    # does not reach the appliance's flaws by name.
    assert tier("exp-kev-ivanti-cloud-services-appliance-csa", "Ivanti Endpoint Manager") \
        != "product"


@pytest.mark.parametrize("question", ["Ivanti EPMM", "Ivanti MobileIron Core"])
def test_another_vendors_record_is_matched_on_the_products_own_name_only(question):
    """Read with Ivanti's names stripped, "MobileIron Core" is "core", which is WordPress's
    product too. Another vendor's entry is compared with the product's own name, whole."""
    assert tier("exp-kev-wordpress-core", question) != "product-name-other-vendor"
    assert tier("exp-kev-teamviewer-desktop", "Docker Desktop") == "product-name-other-vendor"


def test_an_alias_the_resolver_holds_names_the_product():
    """"Exchange" resolves to Exchange Server; the records spelt "Exchange" were the vendor's
    other lines and the answer said no observation named the product."""
    assert tier("exp-kev-microsoft-exchange", "Microsoft Exchange") == "product"
    assert tier("exp-zdi-microsoft-exchange", "Microsoft Exchange") == "product"
    why = reasons("obs-generic-state-affiliated-ransom-operations-from-known-vulnerabilities",
                  "Microsoft Exchange")
    assert any(r.startswith("product Microsoft Exchange") for r in why), why
    assert not any(r.startswith("product ") for r in reasons(
        "obs-microsoft-exchange-online-forged-token-mailbox-access", "Microsoft Exchange"))
    out = consult("Microsoft Exchange", "--limit", "3")
    assert header(out, "RESOLUTION").startswith("RESOLUTION: product"), header(out, "RESOLUTION")


# --- one entry naming several products ------------------------------------------------------

@pytest.mark.parametrize("record_id", [
    "exp-kev-cisco-adaptive-security-appliance-asa-and-firepower-threat-defense-ftd",
    "exp-kev-cisco-adaptive-security-appliance-and-firepower-threat-defense",
    "exp-kev-cisco-secure-firewall-adaptive-security-appliance-and-secure-firewall-threat-defense",
])
def test_a_compound_catalogue_entry_names_each_of_its_products(record_id):
    assert tier(record_id, "Cisco ASA") == "product"


def test_a_compound_entry_names_nothing_it_does_not_list():
    assert tier("exp-kev-cisco-secure-firewall-management-center-fmc-and-security-cloud-control"
                "-scc-firewall-management", "Cisco ASA") == "vendor-class"


def test_a_record_about_a_class_is_read_whole():
    """"Windows and Linux estates" describes what a generic record covers; split, its first
    half read as the product Windows."""
    assert Q.product_parts("Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD)") \
        == ["Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD)",
            "Adaptive Security Appliance", "Firepower Threat Defense"]
    assert not any(r.startswith("product ") for r in reasons(
        "obs-generic-five-publicly-available-tool-categories", "Microsoft Windows"))


def test_every_family_says_why_and_moves_a_record():
    """A family is data a reviewer can check, so each entry states its reason, and each is
    load-bearing: the corpus files the vendor's records under at least two of its names."""
    assert RAW["product_families"]
    for entry in RAW["product_families"]:
        assert str(entry.get("reason") or "").strip(), entry
        members = list(entry["names"]) + list(entry.get("components") or [])
        assert len(members) >= 2, entry
        strip = {tuple(Q.normalise(entry["vendor"]).split())}
        canon = {Q.canonical_product(m, strip) for m in members}
        spelt = set()
        for record in RECORDS:
            if (record.get("who") or {}).get("vendor") != entry["vendor"]:
                continue
            for spelling in record["who"].get("products") or []:
                for part in Q.product_parts(spelling):
                    form = Q.canonical_product(part, strip)
                    spelt |= {c for c in canon if Q._same_product(form, c)}
        assert len(spelt) >= 2, (entry["names"], sorted(spelt))


def test_the_validator_refuses_a_family_it_cannot_check():
    """The tests read the shipped table; validate.py is what reads a corpus passed with
    --corpus."""
    import validate as V  # noqa: E402
    vocab = json.load(open(os.path.join(ROOT, "corpus", "schema", "vocab.json"), encoding="utf-8"))
    problems = []
    V.check_aliases(RAW, vocab, problems)
    assert not problems, problems
    bad = dict(RAW, product_families=[{"vendor": "Example", "names": ["Widget"]},
                                      {"names": ["Widget", "Gadget"], "reason": "renamed"}])
    problems = []
    V.check_aliases(bad, vocab, problems)
    text = " ".join(str(getattr(p, "message", p)) for p in problems)
    assert "does not list two or more" in text and "gives no reason" in text, text
    assert "names no vendor" in text, text


# --- a refused word stays refused -----------------------------------------------------------

def test_a_refused_word_does_not_reach_what_it_was_refused_as():
    """"quantum" was refused as Check Point's gateway and then ranked the gateway's record
    first of 70, on the refused word alone."""
    data = json.loads(query("Zorblax Quantum Edge Gateway 9000", "--json", "--limit", "200",
                            "--exposure-limit", "200"))
    hit = [r["record"]["id"] for r in data["records"]
           if any(m.startswith("term quantum") for m in r["matched_on"])]
    assert not hit, hit
    out = consult("Zorblax Quantum Edge Gateway 9000", "--limit", "12")
    assert "quantum" in header(out, "UNMATCHED_TERMS"), header(out, "UNMATCHED_TERMS")


def test_apple_ios_is_not_answered_with_cisco_ios():
    out = consult("Apple iOS", "--limit", "12")
    assert "ios (product Cisco / IOS" in header(out, "GATED")
    cisco = [f["RECORD_ID"] for f in blocks(out, "FINDING") if f["TECHNOLOGY"].startswith("Cisco")]
    assert not cisco, cisco
    data = json.loads(query("Apple iOS", "--json", "--limit", "200", "--exposure-limit", "0"))
    assert not [r["record"]["id"] for r in data["records"]
                if r["record"]["who"]["vendor"] == "Cisco"]


def test_a_refused_word_still_reaches_everything_else_and_says_it_did():
    """"edge" is refused as Microsoft Edge and still finds the records tagged about edge
    devices; each such finding now says which word its tag matched."""
    out = consult("Zorblax Quantum Edge Gateway 9000", "--limit", "12")
    assert re.search(r"\btag=[1-9]", header(out, "MATCH_TIERS")), header(out, "MATCH_TIERS")
    tagged = [f["MATCH_BASIS"] for f in blocks(out, "FINDING") if f["MATCH_TIER"] == "tag"]
    assert tagged and all(b == "tagged with a term from the question (edge)" for b in tagged), tagged
    microsoft = [f["RECORD_ID"] for f in blocks(out, "FINDING")
                 if f["TECHNOLOGY"].startswith("Microsoft")]
    assert not microsoft, microsoft


def test_a_class_refusal_blocks_only_that_class():
    resolved = Q.resolve("which ids fired", ALIASES)
    refused = [m for m in resolved["refused_meanings"] if m[0] == "class"]
    assert refused, resolved["refused_meanings"]
    ids_record = {"who": {"vendor": "any", "products": [], "product_class": list(refused[0][2])}}
    other = {"who": {"vendor": "any", "products": [], "product_class": ["server.web"]}}
    assert "ids" in Q.refused_terms(ids_record, resolved)
    assert not Q.refused_terms(other, resolved)


# --- the identifier join ----------------------------------------------------------------------

def test_the_kernel_lookup_reaches_the_observation_carrying_its_identifier():
    """The kernel's catalogue record said one identifier was "already carried by an observation
    record" and query.py neither said which nor reached it."""
    data = json.loads(query("Linux kernel", "--json", "--limit", "20", "--exposure-limit", "3"))
    rows = {r["record"]["id"]: r for r in data["records"]}
    geo = rows.get("obs-osgeo-geoserver-remote-code-execution")
    assert geo, sorted(rows)
    assert "identifier CVE-2016-5195 (in exp-kev-linux-kernel)" in geo["matched_on"]
    kev = rows["exp-kev-linux-kernel"]
    assert kev["carried_by"].get("obs-osgeo-geoserver-remote-code-execution") == ["CVE-2016-5195"]
    text = query("Linux kernel")
    assert re.search(r"identifiers also carried by: .*obs-osgeo-geoserver-remote-code-execution "
                     r"\(CVE-2016-5195\)", text), text[-3000:]


def test_the_join_obeys_the_role_filter():
    data = json.loads(query("Linux kernel", "--json", "--role", "inline_tool", "--limit", "200"))
    assert "obs-osgeo-geoserver-remote-code-execution" not in {
        r["record"]["id"] for r in data["records"]}


def test_query_and_consult_name_the_same_carriers():
    data = json.loads(query("Linux kernel", "--json", "--exposure-limit", "3"))
    carried = next(r["carried_by"] for r in data["records"]
                   if r["record"]["id"] == "exp-kev-linux-kernel")
    held = next(b["EXPOSURE_DETECTION_HELD"] for b in blocks(
        consult("Linux kernel", "--limit", "1"), "EXPOSURE")
        if b["EXPOSURE_ID"] == "exp-kev-linux-kernel")
    assert set(re.findall(r"(obs-[a-z0-9-]+) \(", held)) == set(carried), (held, carried)


def test_the_lookup_labels_a_handset_exposure_it_lists():
    """query.py is the path SKILL.md starts a caller on, and it listed a Pixel catalogue record
    fourth for "Linux kernel" with nothing saying handsets are out of scope."""
    text = query("Linux kernel")
    line = next(l for l in text.splitlines() if l.startswith("exp exp-kev-android-pixel"))
    assert "handset record, out of scope" in line, line
    data = json.loads(query("Linux kernel", "--json", "--exposure-limit", "100"))
    flags = {r["record"]["id"]: r["handset"] for r in data["records"] if "handset" in r}
    assert flags["exp-kev-android-pixel"] is True and flags["exp-kev-linux-kernel"] is False


# --- every name of a family resolves one class set (0.44.0) --------------------------------
#
# The fourth validation found the family table and the alias table disagreeing: "fortigate"
# resolved network.firewall and "fortios" network.vpn_gateway, so a FortiGate answer never
# reached the class four of the six Fortinet observations carry, and a FortiOS answer lost
# FortiManager from the vendor tier. Two names the table declared resolved no alias of their own:
# "Secure Firewall Threat Defense" resolved no product, and "Firepower Management Center" resolved
# Firepower Threat Defense.

# A family the gate does not yet hold, with the reason. Each is pinned to fail, so the pin has to
# be removed once the family holds.
FAMILY_CLASSES_OPEN = {
    "Cloud Service Appliance": "three classes by its three names (network.remote_access, "
                               "network.vpn_gateway, app.rmm); which one the appliance takes is "
                               "a plane decision across the KEV classifier and the aliases, left "
                               "to the maintainer at 0.43.0",
    "Policy Secure": "no alias resolves either name, and the vocabulary has no class for network "
                     "access control to give one",
}


def family_reading(entry):
    """{name: (family products resolved, other products resolved, classes)} for each name of
    `entry`, asked beside its vendor."""
    strip = {tuple(Q.normalise(entry["vendor"]).split())}
    canon = [Q.canonical_product(n, strip) for n in entry["names"]]
    out = {}
    for name in entry["names"]:
        resolved = Q.resolve("{} {}".format(entry["vendor"], name), ALIASES)
        mine = {p for p in resolved["products"]
                if any(Q._same_product(Q.canonical_product(p, strip), c) for c in canon)}
        out[name] = (mine, set(resolved["products"]) - mine, frozenset(resolved["classes"]))
    return out


def family_holds(entry):
    reading = family_reading(entry)
    return (all(mine and not other for mine, other, _ in reading.values())
            and len({classes for _, _, classes in reading.values()}) == 1)


@pytest.mark.parametrize("entry", RAW["product_families"],
                         ids=[e["names"][0] for e in RAW["product_families"]])
def test_every_name_of_a_family_resolves_its_product_and_one_class_set(entry):
    """A family says its names are one product, so a question naming any of them reaches the
    same classes, or what the answer reaches depends on which name the defender typed."""
    if entry["names"][0] in FAMILY_CLASSES_OPEN:
        assert not family_holds(entry), "{} holds now; remove its pin".format(entry["names"])
        return
    reading = family_reading(entry)
    for name, (mine, other, _) in reading.items():
        assert mine and not other, (name, sorted(mine), sorted(other))
    assert len({classes for _, _, classes in reading.values()}) == 1, {
        name: sorted(classes) for name, (_, _, classes) in reading.items()}


def test_fortigate_and_fortios_reach_the_same_answer():
    """78 findings on network.firewall for FortiGate and 116 on network.vpn_gateway for FortiOS,
    with DATA absent on one and analogue-only on the other; the family now resolves the union of
    what its two aliases carried, so neither name loses a class it had."""
    for question in ("Fortinet FortiGate", "Fortinet FortiOS", "FortiGate", "FortiOS"):
        assert Q.resolve(question, ALIASES)["classes"] == {
            "network.firewall", "network.vpn_gateway"}, question
    args = ("--limit", "500", "--no-locus-spread", "--exposure-limit", "100",
            "--pattern-limit", "100")
    gate, fos = consult("Fortinet FortiGate", *args), consult("Fortinet FortiOS", *args)
    for key in ("FINDINGS", "MATCH_TIERS", "LOCUS_MATCHED", "LOCUS_ELIGIBLE", "LOCUS_ABSENT",
                "EXPOSURES", "EXPOSURE_LOCUS", "LIBRARY_LOCUS"):
        assert header(gate, key) == header(fos, key), key
    assert header(gate, "FINDINGS") == "FINDINGS: 154 shown of 154 matched"
    for kind, key in (("FINDING", "FINDING_KEY"), ("EXPOSURE", "EXPOSURE_ID"),
                      ("LIBRARY", "LIBRARY_PATTERN_ID")):
        assert sorted(b[key] for b in blocks(gate, kind)) == \
            sorted(b[key] for b in blocks(fos, kind)), kind
    tiers = {b["FINDING_KEY"]: b["MATCH_TIER"] for b in blocks(fos, "FINDING")}
    assert tiers["obs-fortinet-fortimanager-unregistered-device-config-theft#how0"] == "vendor"
    gunra = {tiers[k] for k in tiers
             if k.startswith("obs-generic-gunra-ransomware-affiliate-tradecraft#")}
    assert gunra == {"class"}, gunra
    # The AA26-222A record carries FortiOS's own catalogue identifiers and was not among the 78
    # findings a FortiGate question matched.
    assert any(b["FINDING_KEY"].startswith("obs-generic-gunra-ransomware-affiliate-tradecraft#")
               for b in blocks(gate, "FINDING"))
    # "FortiGate SSL VPN" resolved both classes through the class alias all along.
    assert header(consult("FortiGate SSL VPN", "--limit", "1"), "MATCH_TIERS") == \
        header(consult("Fortinet FortiGate", "--limit", "1"), "MATCH_TIERS")


def test_what_the_fortigate_answer_already_reached_does_not_move():
    """A class is added, never a tier: the product and vendor matches, the exposures naming the
    product, and FortiManager, which is no name of the family, stay as they were."""
    out = consult("Fortinet FortiGate", "--limit", "1")
    assert header(out, "MATCH_TIERS").startswith("MATCH_TIERS: product=11, vendor=2,")
    assert "(product=7," in header(out, "EXPOSURES"), header(out, "EXPOSURES")
    assert Q.resolve("Fortinet FortiManager", ALIASES)["classes"] == {
        "app.rmm", "network.firewall"}


def test_the_full_threat_defense_name_is_the_product_and_not_free_text():
    """"Cisco Firepower Threat Defense" resolved through "firepower" and searched "threat" as
    free text: 46 more findings by tag, pattern wording and summary, one of them a database
    extortion record in a reserved DATA slot. The current name resolved no product."""
    resolved = Q.resolve("Cisco Firepower Threat Defense", ALIASES)
    assert resolved["products"] == {"Firepower Threat Defense"} and not resolved["terms"]
    out = consult("Cisco Firepower Threat Defense", "--limit", "1")
    assert "tag=0, name-fragment=0, pattern=0, summary=0" in header(out, "MATCH_TIERS")
    assert header(out, "MATCH_TIERS") == header(consult("Cisco FTD", "--limit", "1"),
                                                "MATCH_TIERS")
    current = consult("Cisco Secure Firewall Threat Defense", "--limit", "1")
    assert "products=Secure Firewall Threat Defense" in header(current, "RESOLVED_TO")
    assert "(product=3," in header(current, "EXPOSURES"), header(current, "EXPOSURES")


def test_firepower_management_center_is_the_management_center():
    resolved = Q.resolve("Cisco Firepower Management Center", ALIASES)
    assert resolved["products"] == {"Secure Firewall Management Center (FMC)"}
    assert resolved["classes"] == {"app.rmm", "network.firewall"}
    assert Q.resolve("Cisco Firepower", ALIASES)["products"] == {"Firepower Threat Defense"}


# --- the SIMATIC S7 series ------------------------------------------------------------------

@pytest.mark.parametrize("question", ["Siemens S7", "SIMATIC S7", "Siemens S7 PLC", "S7comm"])
def test_the_s7_series_is_a_product(question):
    """"siemens s7" and "simatic s7" were class aliases only, so the S7 advisory, which lists
    every line, was a vendor match below a multi-vendor record and MATCH_TIERS read product=0
    beside RESOLUTION: product; S7comm, the series' protocol, resolved the S7-1500 alone."""
    assert Q.resolve(question, ALIASES)["products"] == {"SIMATIC S7"}, question


def test_the_s7_advisory_is_a_product_match_on_the_series_question():
    out = consult("Siemens S7", "--limit", "500", "--no-locus-spread")
    assert header(out, "MATCH_TIERS").startswith("MATCH_TIERS: product=6, vendor=0,")
    s7 = {b["MATCH_TIER"] for b in blocks(out, "FINDING")
          if b["RECORD_ID"] == "obs-siemens-s7-plc-commodity-library-tooling"}
    assert s7 == {"product"}, s7


@pytest.mark.parametrize("question,product", [("Siemens S7-1500", "SIMATIC S7-1500"),
                                              ("S7-300", "SIMATIC S7-300")])
def test_an_s7_line_asked_about_brings_only_itself(question, product):
    assert Q.resolve(question, ALIASES)["products"] == {product}, question


@pytest.mark.parametrize("question", ["Samsung Galaxy S7", "a Galaxy S7 edge handset", "S7"])
def test_a_bare_s7_names_no_controller(question):
    resolved = Q.resolve(question, ALIASES)
    assert "Siemens" not in resolved["vendors"] and "ot.plc" not in resolved["classes"], question


def test_a_vendor_only_siemens_question_does_not_move():
    assert header(consult("Siemens", "--limit", "1"), "MATCH_TIERS").startswith(
        "MATCH_TIERS: product=0, vendor=8, class=33,")


# --- one product, one class set, wherever the resolver joins two names (0.44.0) ---------------
#
# product_families is one way the bundle calls two names one product; canonical equality under
# the vendor's names is the other ("junos os" and "juniper junos os", "sentry" and "mobileiron
# sentry"). The family test above asks every family name; this one reads the alias table for
# every product the resolver joins, so an ingest pass that copies a generator's class into a
# new alias cannot split a product again unseen.

# A product whose aliases still disagree, with the reason it is not decided here. Each pin must
# still disagree, so it has to be removed once the product holds.
IDENTITY_CLASSES_OPEN = {
    "cloud service appliance": "the appliance's class is a plane decision across the KEV "
                               "classifier and the aliases, left to the maintainer at 0.43.0",
    "sentry": "network.vpn_gateway against app.mdm, app.rmm for MobileIron Sentry; the "
              "hand-written MobileIron record lists Sentry without the gateway class, so the "
              "record and the aliases are decided together",
    "virtual traffic manager": "network.vpn_gateway came from the KEV classifier's Ivanti "
                               "default and the record carries it; a load balancer needs the "
                               "generator corrected first",
    "junos os": "network.firewall against network.router; Junos OS runs both, and the four "
                "Junos observations split across the two",
    "identity services engine": "identity.sso against identity.directory; both CONTROL",
    "weblogic": "server.web against app.middleware; both DATA",
}


def product_identities(aliases):
    """{(vendor, canonical form): {alias: classes}}: product aliases query.py treats as one
    product, by canonical equality under the vendor's names or as names of one family."""
    spellings, _, _ = Q.vendor_relations(aliases)
    names = {}
    for key, vendor in (aliases.get("vendor_aliases") or {}).items():
        names.setdefault(vendor, set()).add(tuple(key.split()))

    def strip_of(vendor):
        out = set()
        for name in spellings.get(vendor) or {vendor}:
            out |= {tuple(Q.normalise(name).split())} | names.get(name, set())
        return out

    def head(vendor):
        return min(spellings.get(vendor) or {vendor})
    joined = {}
    for entry in aliases.get("product_families") or []:
        canon = [Q.canonical_product(n, strip_of(entry["vendor"])) for n in entry["names"]]
        for form in canon:
            joined[(head(entry["vendor"]), form)] = (head(entry["vendor"]), canon[0])
    groups = {}
    for alias, value in (aliases.get("product_aliases") or {}).items():
        if value["vendor"] in Q.SENTINEL_VENDORS:
            continue
        form = Q.canonical_product(value["product"], strip_of(value["vendor"]))
        if not form:
            continue
        key = (head(value["vendor"]), form)
        key = next((k for k in groups if k[0] == key[0] and Q._same_product(k[1], form)), key)
        key = joined.get(key, key)
        klass = value.get("product_class") or []
        groups.setdefault(key, {})[alias] = frozenset(
            klass if isinstance(klass, list) else [klass])
    return groups


def test_every_product_the_resolver_joins_carries_one_class_set():
    """FortiGate and FortiOS were one product with two class sets, so the answer depended on
    which name was typed. Measured at 0.44.0: 795 products, 194 with two or more aliases."""
    split = {}
    for key, members in product_identities(ALIASES).items():
        if len(set(members.values())) > 1:
            split[key] = members
    pinned = {pin for pin in IDENTITY_CLASSES_OPEN
              for members in split.values() if pin in members}
    assert pinned == set(IDENTITY_CLASSES_OPEN), \
        "holds now; remove the pin: {}".format(sorted(set(IDENTITY_CLASSES_OPEN) - pinned))
    unpinned = {key: {a: sorted(c) for a, c in members.items()}
                for key, members in split.items()
                if not any(pin in members for pin in IDENTITY_CLASSES_OPEN)}
    assert not unpinned, unpinned


def test_the_identity_gate_refuses_a_split_it_was_not_told_about():
    raw = json.loads(json.dumps(RAW))
    raw["product_aliases"]["fortios"]["product_class"] = "network.vpn_gateway"
    members = next(m for m in product_identities(Q.normalise_alias_keys(raw)).values()
                   if "fortios" in m)
    assert len(set(members.values())) == 2, members


# --- a product's own words name no sector (0.44.0) -------------------------------------------

@pytest.mark.parametrize("question", [
    "Cisco Firepower Threat Defense", "Cisco Secure Firewall Threat Defense", "Ruby on Rails",
    "Microsoft Kerberos Key Distribution Center", "Cisco Smart Licensing Utility",
    "Cisco Unified Communications Manager"])
def test_a_sector_word_inside_a_product_name_names_no_sector(question):
    """Sector aliases were matched on text product spans did not blank, so "defense" in
    Threat Defense made an FTD question a defence-sector one and reordered its findings."""
    resolved = Q.resolve(question, ALIASES)
    assert resolved["products"] and not resolved["sectors"], (question, resolved["sectors"])


@pytest.mark.parametrize("question,sector", [
    ("Fortinet FortiGate in a defense contractor", "defence"),
    ("Cisco ASA at a defense contractor", "defence"),
    ("Ruby on Rails at a rail operator", "transportation")])
def test_the_same_word_outside_the_product_name_still_names_the_sector(question, sector):
    assert sector in Q.resolve(question, ALIASES)["sectors"], question


def test_every_name_of_threat_defense_gives_the_ftd_answer():
    def body(out):
        return [l for l in out.splitlines() if not l.startswith(("QUESTION:", "RESOLVED_BY:"))]
    ftd = body(consult("Cisco FTD"))
    for question in ("Cisco Firepower Threat Defense", "Firepower Threat Defense"):
        assert body(consult(question)) == ftd, question


# --- AWS is the vendor's cloud, not one product of it (0.44.0) -------------------------------

@pytest.mark.parametrize("question", ["AWS", "Amazon Web Services"])
def test_aws_names_the_vendor_whose_services_its_records_are(question):
    """"aws" resolved the literal product Amazon Web Services, which two records spell, so an
    AWS answer told the reader that its IAM, EC2, EKS and Lambda findings were not about the
    product asked about. All twelve Amazon records are AWS services."""
    out = consult(question)
    assert header(out, "RESOLVED_TO") == \
        "RESOLVED_TO: vendors=Amazon | products=- | classes=cloud.iaas | sectors=-"
    assert "not the product asked about" not in out
    assert header(out, "MATCH_TIERS").startswith(
        "MATCH_TIERS: product=0, vendor=22, class=15, vendor-other-class=2,")


@pytest.mark.parametrize("question,product", [
    ("AWS IAM", "AWS IAM"), ("AWS Lambda", "AWS Lambda"), ("AWS CodeBuild", "AWS CodeBuild")])
def test_an_aws_service_is_still_its_own_product(question, product):
    resolved = Q.resolve(question, ALIASES)
    assert resolved["products"] == {product} and resolved["vendors"] == {"Amazon"}, resolved
