# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A class correction to a generated record must survive the next regeneration.

Exposure records are generated, not written, so a correction made to the corpus file alone
lasts only until the generator runs again. Twelve did exactly that. 0.26.0 moved the EPMM
records to app.mdm, and two later releases moved three endpoint managers to app.rmm and five
network and mail appliances out of security.edr. Every one was made to the corpus and the
alias table and none to the generator's classifier, so the 0.38.0 regeneration put all twelve
back, printed nothing, and passed every test -- because no test named any of them.

An EPMM question then pointed at the ENDPOINT plane again, the one plane the handset rule
declines to advise on. 0.41.0 moved the corrections into the classifier. This file is the
half that a maintainer-side fix cannot supply: it fails the next time a regeneration and a
correction disagree, whichever of the two was changed.

Run with PYTHONDONTWRITEBYTECODE=1 (LAW A26).
"""
import collections
import json
import os
import re
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import consult  # noqa: E402
RECORDS = {}
with open(os.path.join(ROOT, "corpus", "observations", "observations.jsonl"), encoding="utf-8") as h:
    for line in h:
        if line.strip():
            record = json.loads(line)
            RECORDS[record["id"]] = record

# Order matters where there are two: the first-listed class is primary.
CORRECTED = {
    # 0.26.0, the mobile management plane
    "exp-kev-ivanti-endpoint-manager-mobile-epmm": ["app.mdm"],
    "exp-kev-ivanti-endpoint-manager-mobile-epmm-and-mobileiron-core": ["app.mdm"],
    "exp-kev-ivanti-mobileiron-multiple-products": ["network.vpn_gateway", "app.mdm"],
    "exp-kev-omnissa-workspace-one-uem": ["app.mdm", "app.rmm"],
    # endpoint managers are not EDR
    "exp-kev-ivanti-endpoint-manager-epm": ["app.rmm"],
    "exp-kev-ivanti-endpoint-manager-cloud-service-appliance-epm-csa": ["app.rmm"],
    "exp-kev-motex-lanscope-endpoint-manager": ["app.rmm"],
    # a firewall operating system is not endpoint detection
    "exp-kev-sophos-sfos": ["network.firewall"],
    "exp-kev-sophos-cyberoamos": ["network.firewall"],
    "exp-kev-sophos-sg-utm": ["network.firewall"],
    "exp-kev-sophos-web-appliance": ["network.proxy"],
    "exp-kev-symantec-symantec-messaging-gateway": ["security.email_gateway"],
    # 0.43.0, the first-hit keyword ladder. Each was classed by the wrong word or by a vendor
    # default, and aliases.json copied the class, so a question's plane followed the error.
    "exp-kev-laravel-ignition": ["server.web"],
    "exp-kev-sonatype-nexus-repository": ["app.cicd"],
    "exp-kev-sonatype-nexus-repository-manager": ["app.cicd"],
    "exp-kev-arista-extensible-operating-system": ["network.switch"],
    "exp-kev-microsoft-forefront-threat-management-gateway-tmg": ["network.firewall", "network.proxy"],
    "exp-kev-microsoft-streaming-service-proxy": ["endpoint.os"],
    "exp-kev-microsoft-partner-center": ["cloud.saas"],
    "exp-kev-asus-live-update": ["endpoint.os"],
    "exp-kev-microsoft-internet-key-exchange-ike-service-extensions": ["endpoint.os"],
    "exp-kev-cisco-secure-access-control-system-acs": ["identity.directory"],
    "exp-kev-broadcom-brocade-fabric-os": ["network.switch"],
    # A handset, filed under Google and classed a browser by the Google vendor default. It
    # is now the Android Pixel record; handsets stay out of scope, this only places it.
    "exp-kev-android-pixel": ["endpoint.os"],
    # The PSIRT table put the radio access network on SD-WAN or branch edge.
    "exp-psirt-nokia-single-ran": ["telecom.ran"],
    "exp-psirt-nokia-bts": ["telecom.ran"],
    "exp-psirt-nokia-asika": ["telecom.ran"],
    # 0.43.0, the 2026-09-30 validation. Four Fortinet lines reached network.firewall through
    # the vendor default and aliases.json copied it, so a FortiGate question listed a sandbox,
    # an endpoint manager and a web application firewall as firewalls.
    "exp-kev-fortinet-fortisandbox": ["security.edr"],
    "exp-kev-fortinet-fortiweb": ["network.proxy"],
    "exp-kev-fortinet-forticlient-ems": ["app.rmm", "security.edr"],
    "exp-zdi-fortinet-fortiweb": ["network.proxy"],
    "exp-psirt-fortinet-fortiweb": ["network.proxy"],
    "exp-psirt-fortinet-forticlientems": ["app.rmm", "security.edr"],
    # A management platform leads with app.rmm and keeps what it manages second: the class is
    # all a generated record's locus reads, and FortiManager's KEV exposure printed CONTROL
    # beside the MANAGEMENT observation carrying the same CVE.
    "exp-kev-fortinet-fortimanager": ["app.rmm", "network.firewall"],
    "exp-psirt-fortinet-fortimanager": ["app.rmm", "network.firewall"],
    "exp-psirt-fortinet-fortiswitchmanager": ["app.rmm", "network.switch"],
    "exp-kev-check-point-smartconsole": ["app.rmm", "network.firewall"],
    "exp-kev-check-point-multiple-products": ["app.rmm", "network.firewall"],
    "exp-kev-cisco-secure-firewall-management-center-fmc": ["app.rmm", "network.firewall"],
    "exp-kev-cisco-secure-firewall-management-center-fmc-and-security-cloud-control-scc-"
    "firewall-management": ["app.rmm", "network.firewall"],
    "exp-zdi-cisco-secure-firewall-management-center": ["app.rmm", "network.firewall"],
    "exp-zdi-sonicwall-gms-virtual-appliance": ["app.rmm", "network.firewall"],
    "exp-kev-palo-alto-networks-expedition": ["app.rmm", "network.firewall"],
    "exp-kev-cisco-catalyst-sd-wan-manager": ["app.rmm", "network.router"],
    "exp-kev-cisco-catalyst-sd-wan-manger": ["app.rmm", "network.router"],
    "exp-kev-cisco-prime-data-center-network-manager-dcnm": ["app.rmm", "network.switch"],
    "exp-kev-arista-velocloud-orchestrator": ["app.rmm", "network.wan_edge"],
    "exp-kev-versa-director": ["app.rmm", "network.wan_edge"],
    # One product, one class, whichever generator wrote the record, and the class its alias and
    # the observation naming it carry.
    "exp-kev-connectwise-screenconnect": ["app.rmm"],
    "exp-kev-langflow-langflow": ["app.ai_platform"],
    "exp-kev-microsoft-outlook": ["app.office_suite"],
    "exp-kev-minio-minio": ["cloud.iaas"],
    "exp-kev-progress-kemp-loadmaster": ["network.load_balancer"],
    "exp-zdi-cisco-identity-services-engine": ["identity.sso"],
    "exp-zdi-fortinet-forticlient": ["security.edr"],
}


with open(os.path.join(ROOT, "corpus", "schema", "vocab.json"), encoding="utf-8") as h:
    CLASS_TAGS = {c.replace(".", "-") for c in json.load(h)["product_class"]}


@pytest.mark.parametrize("rid", sorted(CORRECTED))
def test_a_corrected_class_is_still_the_class_the_record_carries(rid):
    assert rid in RECORDS, "{} is gone; if it was merged or renamed, move the pin".format(rid)
    got = RECORDS[rid]["who"].get("product_class")
    assert got == CORRECTED[rid], "{} carries {}, corrected to {}".format(rid, got, CORRECTED[rid])


@pytest.mark.parametrize("rid", sorted(r for r in CORRECTED if r.startswith("exp-kev-")))
def test_the_generated_tag_follows_the_corrected_class(rid):
    """The hand fixes corrected the class and left the tag the generator had derived from the
    wrong one, so SFOS still carried `security-edr` for a tag lookup to find. The one class tag
    a KEV record carries is its primary class's; FortiSandbox is now correctly security.edr, so
    the check is on the class tags as a whole rather than on that one."""
    primary = CORRECTED[rid][0].replace(".", "-")
    tags = RECORDS[rid].get("tags", [])
    assert [t for t in tags if t in CLASS_TAGS] == [primary], (rid, tags)


# ---------------------------------------------------------------- one product, one record

with open(os.path.join(ROOT, "corpus", "schema", "aliases.json"), encoding="utf-8") as h:
    ALIASES = json.load(h)


def _slug(text):
    return re.sub(r"-{2,}", "-", re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-"))


def test_no_kev_product_is_split_across_two_records():
    """The catalogue sometimes repeats the vendor inside the product string and sometimes
    files a product under a former owner, and the generator's slug merge could see neither.
    Ten records held one product twice: "Android kernel" listed the record with the newest
    kernel identifier fourth, behind two other Android products. Grouped here the way the
    generator's split guard groups them, through the corpus's own vendor aliases."""
    vendor_aliases = {k.lower(): v for k, v in ALIASES["vendor_aliases"].items() if isinstance(v, str)}
    groups = {}
    for rid, record in RECORDS.items():
        if not rid.startswith("exp-kev-"):
            continue
        vendor = record["who"]["vendor"]
        canon = vendor_aliases.get(vendor.lower(), vendor)
        product = _slug(record["who"]["products"][0])
        for prefix in {_slug(vendor), _slug(canon)}:
            if product.startswith(prefix + "-"):
                product = product[len(prefix) + 1:]
                break
        groups.setdefault((canon, product), []).append(rid)
    split = {k: v for k, v in groups.items() if len(v) > 1}
    assert not split, "one product, several records: {}".format(split)


def test_the_merged_records_are_gone_and_their_survivors_carry_everything():
    for gone in ("exp-kev-google-pixel", "exp-kev-php-group-php", "exp-kev-android-kernel",
                 "exp-kev-drupal-core", "exp-kev-roundcube-webmail", "exp-kev-kentico-xperience",
                 "exp-kev-kentico-xperience-cms", "exp-kev-pulse-secure-pulse-connect-secure",
                 "exp-kev-cisco-cisco-ios-xe-web-ui", "exp-kev-qnap-qnap-network-attached-storage-nas"):
        assert gone not in RECORDS, gone
    kernel = RECORDS["exp-kev-android-android-kernel"]
    assert set(kernel["what"]["vulnerabilities"]) >= {
        "CVE-2019-2215", "CVE-2020-0041", "CVE-2021-0920", "CVE-2021-1048", "CVE-2024-36971"}
    assert kernel["who"]["product_class"] == ["endpoint.os"]
    assert RECORDS["exp-kev-android-pixel"]["who"]["vendor"] == "Android"
    assert "CVE-2024-4577" in RECORDS["exp-kev-php-php"]["what"]["vulnerabilities"]


def test_no_product_alias_names_a_product_no_record_carries_after_a_merge():
    """A merge removes a product string; an alias still naming it resolves to nothing."""
    carried = {(r["who"]["vendor"], p) for r in RECORDS.values() for p in r["who"].get("products") or []}
    for alias in ("webmail", "xperience", "xperience cms", "qnap network-attached storage",
                  "qnap network-attached storage (nas)", "cisco ios xe web ui"):
        entry = ALIASES["product_aliases"][alias]
        assert (entry["vendor"], entry["product"]) in carried, (alias, entry)
    assert ALIASES["vendor_aliases"]["php group"] == "PHP"


# Records naming a product among several, whose classes describe the incident rather than
# each product. The alias classes the product; the record is not wrong to omit it.
ALIAS_CLASS_EXEMPT = {
    "vrealize automation": "named with four other products on one template-injection chain record",
    "vmware cloud foundation": "named with four other products on one template-injection chain record",
    "aws codecommit": "named with four other services on one cryptojacking record",
    "codecommit": "named with four other services on one cryptojacking record",
}


def test_a_product_alias_carries_its_records_class():
    """The classifier's errors were copied into the alias table, so a question resolved the
    wrong class even where a record was later corrected: "firebox and xtm" said router over
    two firewall records, and the J-Web aliases still said router after the record they name
    stopped carrying it. The FIRST class is checked. 0.26.0 deliberately gave the EPMM
    aliases app.rmm as well, so a question keeps its fleet-management context while still
    resolving app.mdm first; a later class may be one no record carries."""
    classes = {}
    for record in RECORDS.values():
        for product in record["who"].get("products") or []:
            classes.setdefault((record["who"]["vendor"], product), set()).update(
                record["who"].get("product_class") or [])
    bad = []
    for alias, entry in ALIASES["product_aliases"].items():
        held = classes.get((entry["vendor"], entry["product"]))
        if held is None or alias in ALIAS_CLASS_EXEMPT:
            continue
        cls = entry["product_class"]
        first = cls[0] if isinstance(cls, list) else cls
        if first not in held:
            bad.append("{!r} resolves {} but the records naming {} carry {}".format(
                alias, first, entry["product"], sorted(held)))
    assert not bad, "\n".join(bad)
    assert all(a in ALIASES["product_aliases"] for a in ALIAS_CLASS_EXEMPT), "an exemption names a missing alias"


# ------------------------------------------------ one product, one class, one plane

GENERATED_FAMILIES = ("kev", "zdi", "psirt", "nvd")


def test_one_product_carries_one_class_whichever_generator_wrote_it():
    """FortiSandbox was a firewall in its KEV record and endpoint security in its PSIRT and ZDI
    records, so whether a FortiGate question listed it depended on which generator had written
    the record it met. Grouped by the vendor as the alias table resolves it and the product
    with case and punctuation dropped, so FortiClient EMS and FortiClientEMS are one."""
    vendor_aliases = {k.lower(): v for k, v in ALIASES["vendor_aliases"].items() if isinstance(v, str)}
    groups = collections.defaultdict(set)
    for rid, record in RECORDS.items():
        family = rid.split("-")[1]
        if record.get("record_type") != "exposure" or family not in GENERATED_FAMILIES:
            continue
        vendor = vendor_aliases.get(record["who"]["vendor"].lower(), record["who"]["vendor"])
        for product in record["who"].get("products") or []:
            key = (vendor, re.sub(r"[^a-z0-9]", "", product.lower()))
            groups[key].add((family, rid, tuple(record["who"].get("product_class") or [])))
    split = {k: sorted(v) for k, v in groups.items()
             if len({f for f, _, _ in v}) > 1 and len({c for _, _, c in v}) > 1}
    assert not split, "one product, several classes: {}".format(split)


def test_the_validator_refuses_two_generators_classing_one_product_apart():
    """The same property for any corpus validate.py is given, which these tests never see."""
    import validate  # noqa: E402

    def exposure(rid, product, classes):
        return {"id": rid, "record_type": "exposure",
                "who": {"vendor": "Fortinet", "products": [product], "product_class": classes}}
    problems = []
    validate.check_generated_classes([
        ("a", "known-exploited-catalogue", exposure("exp-kev-x", "FortiClient EMS", ["network.firewall"])),
        ("b", "psirt", exposure("exp-psirt-x", "FortiClientEMS", ["app.rmm", "security.edr"])),
        ("c", "psirt", exposure("exp-psirt-y", "FortiAP", ["network.remote_access"])),
    ], ALIASES, problems)
    assert len(problems) == 1, problems
    assert "Fortinet FortiClient EMS is classed differently" in str(problems[0]), problems
    problems = []
    validate.check_generated_classes([
        ("a", "known-exploited-catalogue", exposure("exp-kev-x", "FortiClient EMS", ["app.rmm", "security.edr"])),
        ("b", "psirt", exposure("exp-psirt-x", "FortiClientEMS", ["app.rmm", "security.edr"])),
    ], ALIASES, problems)
    assert not problems, problems


LOCUS_MAP = consult.load_locus_map(os.path.join(ROOT, "corpus"))


def _loci(record):
    """Every primary and span a record's blocks derive, or the exposure's own, with no question."""
    out = set()
    for how in record.get("how") or [None]:
        locus, span, _ = consult.locus_for(record, how, None, LOCUS_MAP)
        out |= {locus} | ({span} if span else set())
    return out


def test_a_management_platforms_exposure_sits_where_its_observation_does():
    """The FortiManager KEV exposure and the observation carrying the same CVE, CVE-2024-47575,
    placed on disjoint planes: EXPOSURE_LOCUS CONTROL beside FINDING LOCUS MANAGEMENT."""
    exposure = RECORDS["exp-kev-fortinet-fortimanager"]
    observation = RECORDS["obs-fortinet-fortimanager-unregistered-device-config-theft"]
    assert set(exposure["what"]["vulnerabilities"]) & set(observation["what"]["vulnerabilities"])
    assert consult.locus_for(exposure, None, None, LOCUS_MAP)[0] == "MANAGEMENT"
    assert "MANAGEMENT" in _loci(observation)
    for rid in ("exp-kev-fortinet-forticlient-ems", "exp-kev-check-point-smartconsole",
                "exp-kev-cisco-secure-firewall-management-center-fmc",
                "exp-zdi-cisco-secure-firewall-management-center",
                "exp-kev-connectwise-screenconnect"):
        assert consult.locus_for(RECORDS[rid], None, None, LOCUS_MAP)[0] == "MANAGEMENT", rid


def test_a_catalogue_record_shares_a_plane_with_the_observations_naming_its_product():
    """Of the 31 products a KEV record and an observation both name, five placed on disjoint
    planes with no question asked -- FortiManager and ScreenConnect CONTROL against MANAGEMENT,
    Langflow SUPPLY against CONTROL, Outlook ENDPOINT against DATA, MinIO DATA against
    MANAGEMENT -- each because a vendor default or the first keyword rule classed the catalogue
    record against the class its alias and its observation already carried. The primary a
    catalogue record derives is now among the planes its product's observations reach."""
    held = collections.defaultdict(lambda: {"kev": [], "obs": []})
    for rid, record in RECORDS.items():
        for product in record["who"].get("products") or []:
            key = (record["who"].get("vendor"), product)
            if rid.startswith("exp-kev-"):
                held[key]["kev"].append(record)
            elif record.get("record_type") == "observation":
                held[key]["obs"].append(record)
    apart = []
    for key, found in sorted(held.items(), key=lambda item: str(item[0])):
        if not (found["kev"] and found["obs"]):
            continue
        reached = set().union(*(_loci(r) for r in found["obs"]))
        for record in found["kev"]:
            primary = consult.locus_for(record, None, None, LOCUS_MAP)[0]
            if primary not in reached:
                apart.append("{} {} on {}, its observations on {}".format(
                    record["id"], key[1], primary, sorted(reached)))
    assert not apart, "\n".join(apart)


def consult_out(question, *extra):
    done = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "consult.py"), question,
                           "--today", "2026-09-30", *extra],
                          capture_output=True, text=True, cwd=ROOT, timeout=300)
    assert done.returncode == 0, done.stderr
    return done.stdout


def exposure_blocks(out):
    found = []
    for body in re.findall(r"^=== EXPOSURE \d+ OF \d+ ===\n(.*?)^=== END EXPOSURE \d+ ===",
                           out, re.M | re.S):
        found.append(dict(re.findall(r"^([A-Z_]+): ?(.*)$", body, re.M)))
    return {b["EXPOSURE_ID"]: b for b in found}


def test_a_fortigate_answer_lists_no_other_fortinet_line_as_a_firewall():
    """FortiSandbox, FortiClient EMS and FortiWeb took three of the ten exposure slots as
    "VENDOR IN A CLASS ASKED ABOUT ... in network.firewall", and EXPOSURE_LOCUS read
    CONTROL=11, MANAGEMENT=0 with FortiManager among them."""
    out = consult_out("Fortinet FortiGate", "--limit", "3", "--exposure-limit", "100")
    listed = exposure_blocks(out)
    for rid in ("exp-kev-fortinet-fortisandbox", "exp-kev-fortinet-forticlient-ems",
                "exp-kev-fortinet-fortiweb", "exp-zdi-fortinet-fortiweb"):
        assert rid not in listed, rid
    manager = listed["exp-kev-fortinet-fortimanager"]
    assert manager["EXPOSURE_LOCUS"] == "MANAGEMENT", manager["EXPOSURE_LOCUS_BASIS"]
    assert manager["EXPOSURE_LOCUS_SPAN"] == "MANAGEMENT, CONTROL"
    tally = re.search(r"^EXPOSURE_LOCUS: (.*)$", out, re.M).group(1)
    assert "MANAGEMENT=0," not in tally, tally


def test_a_firewall_manager_answers_management_with_control_beside_it():
    """Check Point's two newest catalogue entries, one in the Security Management Server, Log
    Server and SmartEvent, printed EXPOSURE_LOCUS CONTROL alone, as did SmartConsole's. Listed
    management first, a firewall question adds CONTROL as the span; listed firewall first, no
    question could ever have printed MANAGEMENT."""
    out = consult_out("Check Point firewall", "--limit", "3")
    listed = exposure_blocks(out)
    for rid in ("exp-kev-check-point-multiple-products", "exp-kev-check-point-smartconsole"):
        block = listed[rid]
        assert block["EXPOSURE_LOCUS"] == "MANAGEMENT", (rid, block["EXPOSURE_LOCUS_BASIS"])
        assert block["EXPOSURE_LOCUS_SPAN"] == "MANAGEMENT, CONTROL", rid
    # SmartConsole's CONTROL is the question's. Multiple Products' is its own since 0.44.0: the
    # catalogue text of CVE-2026-85102 names the gateway VPN, so the record carries CONTROL as
    # its span whatever the question asks.
    assert "class_matched span: network.firewall" in \
        listed["exp-kev-check-point-smartconsole"]["EXPOSURE_LOCUS_BASIS"]
    assert "span-source=identifier;" in \
        listed["exp-kev-check-point-multiple-products"]["EXPOSURE_LOCUS_BASIS"]
    assert listed["exp-kev-check-point-security-gateway"]["EXPOSURE_LOCUS"] == "CONTROL"
    # The catalogue's value for these is Unknown, which printed as a bare "no".
    assert listed["exp-kev-check-point-multiple-products"]["EXPOSURE_RANSOMWARE"].startswith(
        "unknown - ")


# ------------------------------------------------ what a generated summary says

DESCRIBED = 6


@pytest.mark.parametrize("rid", sorted(r for r in RECORDS if r.startswith("exp-kev-")
                                       and len(RECORDS[r]["what"]["vulnerabilities"]) > 1))
def test_every_kev_summary_says_what_its_identifiers_are(rid):
    """A record carrying two or more identifiers only counted them: 230 of 699, among them
    "Check Point Multiple Products", whose two are a management-server script upload and a
    gateway VPN flaw. Each is now described in the catalogue's words, newest first, and a
    record carrying more than six says how many it leaves undescribed."""
    ids = RECORDS[rid]["what"]["vulnerabilities"]
    summary = RECORDS[rid]["what"]["summary"]
    described = re.findall(r"\b((?:CVE|ZDI)-\d{2,4}-\d+): ", summary)
    assert len(described) == min(len(ids), DESCRIBED), (rid, described)
    assert set(described) <= set(ids), rid
    if len(ids) > DESCRIBED:
        assert "The other {} are described in the catalogue".format(len(ids) - DESCRIBED) in summary
    else:
        assert "The catalogue describes each of them: " in summary, rid


def test_the_check_point_placeholder_names_its_components():
    summary = RECORDS["exp-kev-check-point-multiple-products"]["what"]["summary"]
    for component in ("Security Management Server", "Log Server", "SmartEvent", "Security Gateway"):
        assert component in summary, component


# ------------------------------------------------ what a PSIRT record is attributed

def test_a_psirt_record_carries_only_advisories_the_vendor_marks_affected():
    """The collectors took every product an advisory mentioned. Palo Alto's status table lists
    Cloud NGFW on 14 PAN-OS advisories and reads "None" for it on 13; Panorama's and GlobalProtect
    UWP App's rows read "None" on every advisory that named them. A Fortinet capwap flaw was
    filed under the three devices an attacker would control, and "FortiClient EMS" under the
    endpoint agent."""
    vulns = {rid: set(r["what"].get("vulnerabilities") or []) for rid, r in RECORDS.items()}
    assert vulns["exp-psirt-palo-alto-networks-cloud-ngfw"] == {"CVE-2026-0287"}
    assert vulns["exp-psirt-palo-alto-networks-prisma-access"] == {
        "CVE-2026-0279", "CVE-2026-0280", "CVE-2026-0287", "CVE-2026-0288"}
    for gone in ("exp-psirt-palo-alto-networks-panorama",
                 "exp-psirt-palo-alto-networks-globalprotect-uwp-app",
                 "exp-psirt-palo-alto-networks-prisma-sd-wan-ion",
                 "exp-psirt-fortinet-fortiextender", "exp-psirt-fortinet-fortiswitch",
                 "exp-psirt-fortinet-fortigate", "exp-psirt-fortinet-fortisanbox"):
        assert gone not in RECORDS, gone
    assert "CVE-2026-59836" in vulns["exp-psirt-fortinet-forticlientems"]
    assert "CVE-2026-59836" not in vulns["exp-psirt-fortinet-forticlient"]
    assert "CVE-2025-53844" not in vulns["exp-psirt-fortinet-fortiap"]
    assert "CVE-2026-27316" in vulns["exp-psirt-fortinet-fortisandbox"]
    # Every identifier the removed records held is still carried by a record the vendor's own
    # table names, so the fix moved attribution and lost nothing.
    assert {"CVE-2025-53844", "CVE-2025-53847"} <= vulns["exp-psirt-fortinet-fortios"]


@pytest.mark.parametrize("rid", sorted(r for r in RECORDS if r.startswith("exp-psirt-")
                                       and RECORDS[r]["who"]["vendor"] != "Nokia"))
def test_a_psirt_record_is_dated_by_its_advisories_and_names_each(rid):
    """Every Fortinet and Palo Alto record carried the collection date, 2026-08-01, at month
    precision, and cited one advisory of up to fourteen with no way to reach the rest."""
    record = RECORDS[rid]
    assert record["when"]["precision"] == "day", rid
    assert record["when"]["published"] != "2026-08-01", rid
    count = int(re.match(r"(\d+) vendor security advis", record["what"]["summary"]).group(1))
    if count > 1:
        named = re.search(r"under its own identifier: (.*?); the reference below",
                          record["what"]["summary"]).group(1).split(", ")
        assert len(named) == count, (rid, named)
        assert record["where"]["url"].rstrip("/").endswith(named[0]), rid
