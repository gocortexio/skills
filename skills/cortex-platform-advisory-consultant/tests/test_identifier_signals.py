# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A generated exposure's identifiers are read by their own words, not only by the record's class.

A generated exposure's attack_surface is assigned from a class table and never read, so until
0.44.0 its class was the only plane it had, and a firewall's class is CONTROL. The fourth
validation found three answers that followed from that:

- scope-known: FortiOS's two super-admin authentication bypasses printed CONTROL in their
  exposure beside a finding placing the same CVE on MANAGEMENT, and the FortiGate header read
  as though the product had no management-plane exposure.
- scope-alias: both PAN-OS exposures printed CONTROL alone, though the catalogue text the KEV
  record quotes names the management web interface for four of its twelve identifiers, and
  asking about the management interface by name changed nothing.
- scope-new-record: "Check Point VPN" listed none of the three Check Point identifiers the
  catalogue describes as VPN flaws, because no record carried the VPN gateway class.

The generators now write what.identifier_signals from locus-map.json identifier_reading: for
each identifier whose own catalogue description or name, advisory title or database
description names an administrative component, a MANAGEMENT entry, and for a VPN feature on a
network device a network.vpn_gateway entry, each with its rule, words and field. A locus every
identifier reads decides the primary; otherwise it is the span. A class read this way widens
only the vendor-class exposure tier. validate.py holds every entry to the rule.

Run with PYTHONDONTWRITEBYTECODE=1 (LAW A26).
"""
import collections
import copy
import json
import pathlib
import re
import subprocess
import sys

BUNDLE = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = BUNDLE / "scripts"
CORPUS = BUNDLE / "corpus"
TODAY = "2026-10-01"

sys.dont_write_bytecode = True
sys.path.insert(0, str(SCRIPTS))
import consult  # noqa: E402
import query as Q  # noqa: E402
import validate  # noqa: E402

RECORDS, PATTERNS = Q.load_corpus(str(CORPUS))
BY_ID = {r["id"]: r for r in RECORDS}
LOCUS_MAP = consult.load_locus_map(str(CORPUS))
CARRIERS = [r for r in RECORDS if (r.get("what") or {}).get("identifier_signals")]

_OUT = {}


def run(script, *argv):
    key = (script,) + argv
    if key not in _OUT:
        done = subprocess.run([sys.executable, str(SCRIPTS / script), *argv],
                              capture_output=True, text=True, timeout=300)
        assert done.returncode == 0, done.stderr
        _OUT[key] = done.stdout
    return _OUT[key]


def consult_out(question, *extra):
    return run("consult.py", question, "--today", TODAY, *extra)


def exposure_blocks(out):
    found = {}
    for body in re.findall(r"^=== EXPOSURE \d+ OF \d+ ===\n(.*?)^=== END EXPOSURE \d+ ===",
                           out, re.M | re.S):
        block = dict(re.findall(r"^([A-Z_]+): ?(.*)$", body, re.M))
        found[block["EXPOSURE_ID"]] = block
    return found


def header(out, key):
    return re.search(r"^{}: (.*)$".format(key), out, re.M).group(1)


def placed(rid):
    return consult.locus_for(BY_ID[rid], None, None, LOCUS_MAP)


# ------------------------------------------------------------- the three majors, fixed

def test_fortios_super_admin_bypasses_carry_management_beside_control():
    """scope-known major 1 (and 0.43.0 coverage minor 3): CVE-2024-55591 was CONTROL in its
    exposure and MANAGEMENT in the finding carrying it. Two of the record's four identifiers
    are SSL-VPN flaws, so the primary stays CONTROL and MANAGEMENT is the span, with the
    catalogue's own words in the basis. The header now counts the span."""
    out = consult_out("Fortinet FortiGate", "--limit", "3")
    listed = exposure_blocks(out)
    block = listed["exp-kev-fortinet-fortios-and-fortiproxy"]
    assert block["EXPOSURE_LOCUS"] == "CONTROL"
    assert block["EXPOSURE_LOCUS_SPAN"] == "CONTROL, MANAGEMENT"
    assert "span-source=identifier" in block["EXPOSURE_LOCUS_BASIS"]
    assert 'CVE-2024-55591 MANAGEMENT ("super-admin")' in block["EXPOSURE_LOCUS_BASIS"]
    assert 'CVE-2025-24472 MANAGEMENT ("super-admin")' in block["EXPOSURE_LOCUS_BASIS"]
    multi = listed["exp-kev-fortinet-multiple-products"]
    assert multi["EXPOSURE_LOCUS_SPAN"] == "CONTROL, MANAGEMENT"
    assert 'CVE-2022-40684 MANAGEMENT ("administrative interface")' in multi["EXPOSURE_LOCUS_BASIS"]
    # 9 exposures until fortigate carried network.vpn_gateway as fortios does (0.44.0, B2);
    # the vendor's VPN-gateway exposures then joined the vendor-class tier: FortiProxy
    # (CONTROL), FortiSwitchManager (MANAGEMENT) and the FortiClient VPN (CONTROL).
    assert header(out, "EXPOSURE_LOCUS").startswith("CONTROL=9, MANAGEMENT=3,")
    assert header(out, "EXPOSURE_LOCUS_SPAN").startswith("CONTROL=3, MANAGEMENT=5, DATA=0,")


def test_pan_os_exposures_carry_the_management_web_interface():
    """scope-alias major 0 (and 0.43.0 scope-alias minor 3): both PAN-OS exposures printed
    CONTROL alone, and asking about the management interface by name changed nothing. The
    TODO counted five of twelve; CVE-2017-15944 is "multiple, unspecified vulnerabilities" in
    the catalogue and names no interface, so the source gives four."""
    for question in ("PAN-OS", "PAN-OS firewall management interface"):
        out = consult_out(question, "--limit", "3")
        listed = exposure_blocks(out)
        kev = listed["exp-kev-palo-alto-networks-pan-os"]
        psirt = listed["exp-psirt-palo-alto-networks-pan-os"]
        for block in (kev, psirt):
            assert block["EXPOSURE_LOCUS"] == "CONTROL", question
            assert block["EXPOSURE_LOCUS_SPAN"] == "CONTROL, MANAGEMENT", question
            assert "span-source=identifier" in block["EXPOSURE_LOCUS_BASIS"], question
        for cve in ("CVE-2024-0012", "CVE-2024-9474", "CVE-2025-0108", "CVE-2025-0111"):
            assert "{} MANAGEMENT".format(cve) in kev["EXPOSURE_LOCUS_BASIS"], cve
        assert "CVE-2017-15944 MANAGEMENT" not in kev["EXPOSURE_LOCUS_BASIS"]
        for cve in ("CVE-2026-0272", "CVE-2026-0281", "CVE-2026-0285", "CVE-2026-0286"):
            assert "{} MANAGEMENT".format(cve) in psirt["EXPOSURE_LOCUS_BASIS"], cve
        assert header(out, "EXPOSURE_LOCUS_SPAN").startswith("CONTROL=1, MANAGEMENT=2,"), question


def test_a_vpn_question_lists_the_vendors_own_vpn_flaws():
    """scope-new-record major 0 (and 0.43.0 scope-new-record minor 0): "Check Point VPN"
    listed no exposure. Three identifiers are VPN flaws by the catalogue's words; SmartConsole's
    is not, and stays unlisted. query.py agrees with the consultation."""
    out = consult_out("Check Point VPN", "--limit", "3")
    assert header(out, "EXPOSURES").startswith(
        "3 shown of 3 naming what was asked (product=0, vendor-class=3, vendor=0)")
    unlisted = header(out, "EXPOSURES_NOT_LISTED")
    assert "other-products-of-vendor=1," in unlisted and "class-only=30," in unlisted
    listed = exposure_blocks(out)
    assert set(listed) == {"exp-kev-check-point-multiple-products",
                           "exp-kev-check-point-security-gateway",
                           "exp-kev-check-point-quantum-security-gateways"}
    assert ("network.vpn_gateway (by the source's own text of CVE-2026-50751, not its product "
            "class)") in listed["exp-kev-check-point-security-gateway"]["EXPOSURE_MATCH"]
    # The management-server record keeps its class's MANAGEMENT; its gateway VPN identifier
    # now gives CONTROL as the record's own span, whatever the question asked.
    multi = listed["exp-kev-check-point-multiple-products"]
    assert multi["EXPOSURE_LOCUS"] == "MANAGEMENT"
    assert multi["EXPOSURE_LOCUS_SPAN"] == "MANAGEMENT, CONTROL"
    assert "span-source=identifier" in multi["EXPOSURE_LOCUS_BASIS"]
    listing = run("query.py", "Check Point VPN")
    assert "vendor-class=3," in listing and "class-only=30," in listing


def test_the_asa_snmp_and_cli_flaws_carry_management():
    """val043c planes-network minor 2: CVE-2016-6366 (SNMP) and CVE-2016-6367 (CLI) sat on
    CONTROL with the rest of the ASA's identifiers."""
    locus, span, basis = placed("exp-kev-cisco-adaptive-security-appliance-asa")
    assert (locus, span) == ("CONTROL", "MANAGEMENT"), basis
    assert "CVE-2016-6366 MANAGEMENT" in basis and "CVE-2016-6367 MANAGEMENT" in basis


def test_every_identifier_reading_one_other_plane_moves_the_primary():
    """Every identifier reads MANAGEMENT: the identifier tier decides and the class's plane
    is the span. Both Jenkins records are a judgement: their CLI is Jenkins's administration,
    and SUPPLY, the build server's plane, stays as the span."""
    expected = {"exp-kev-cisco-nx-os": ("MANAGEMENT", "CONTROL"),
                "exp-kev-f5-big-ip-configuration-utility": ("MANAGEMENT", "CONTROL"),
                "exp-kev-jenkins-jenkins": ("MANAGEMENT", "SUPPLY"),
                "exp-kev-jenkins-jenkins-command-line-interface-cli": ("MANAGEMENT", "SUPPLY")}
    for rid, want in expected.items():
        locus, span, basis = placed(rid)
        assert (locus, span) == want, (rid, basis)
        assert basis.startswith("tier=identifier;"), basis
        assert "span-source=identifier" in basis, basis


def test_a_cve_and_its_carrier_finding_share_a_plane():
    """The defect the validation named: one CVE on two disjoint planes in one answer. For each
    identifier an observation of the same vendor carries, the plane its exposure's own text
    reads is one that observation's blocks print, except five pinned below with why."""
    for cve in ("CVE-2024-55591", "CVE-2022-41328", "CVE-2017-6742", "CVE-2020-5902"):
        holders = [r for r in CARRIERS if cve in r["what"]["vulnerabilities"]]
        assert holders, cve
        for record in holders:
            locus, span, _ = consult.locus_for(record, None, None, LOCUS_MAP)
            assert "MANAGEMENT" in (locus, span), (cve, record["id"])
    # The observation sits on CONTROL; val043c scope-unknown minor 1 calls that wrong, and this
    # test says so when it is corrected. The Pulse Connect Secure observation is about
    # credentials reused after patching, and its blocks concern another identifier.
    pinned = {"CVE-2024-8190", "CVE-2024-9379", "CVE-2024-9380",
              "CVE-2019-11539", "CVE-2021-22900"}
    carriers = collections.defaultdict(list)
    for record in RECORDS:
        if record.get("record_type") != "exposure":
            for identifier in (record.get("what") or {}).get("vulnerabilities") or []:
                carriers[identifier].append(record)
    pairs, disagree = 0, set()
    for record in CARRIERS:
        own, _ = consult.identifier_loci(record, LOCUS_MAP["by_class"])
        for identifier, plane in own.items():
            for obs in carriers.get(identifier, ()):
                if obs["who"].get("vendor") != record["who"].get("vendor"):
                    continue
                pairs += 1
                if plane not in Q.record_loci(obs, PATTERNS, LOCUS_MAP, consult.locus_for):
                    disagree.add(identifier)
    assert disagree == pinned, disagree
    assert pairs == 20, pairs


# ------------------------------------------------------------- validate.py's checks

def _problems(record):
    found = []
    validate.check_identifier_signals(record, LOCUS_MAP, "t", found)
    return [str(p) for p in found]


def test_every_shipped_signal_is_one_the_rule_would_write():
    for record in RECORDS:
        assert not _problems(record), record["id"]
    assert len(CARRIERS) == 89
    by_family = collections.Counter(r["id"].split("-")[1] for r in CARRIERS)
    assert by_family == {"kev": 59, "nvd": 19, "psirt": 10, "zdi": 1}
    entries = [e for r in CARRIERS for e in r["what"]["identifier_signals"]]
    assert len(entries) == 191
    assert sum(1 for e in entries if e.get("locus")) == 139


def test_validate_refuses_a_signal_the_rule_cannot_have_written():
    base = BY_ID["exp-kev-fortinet-fortios-and-fortiproxy"]

    def with_entries(record, entries):
        record = copy.deepcopy(record)
        record["what"]["identifier_signals"] = entries
        return record

    def good(**changes):
        entry = {"id": "CVE-2024-55591", "rule": "super-admin", "locus": "MANAGEMENT",
                 "phrase": "super-admin", "field": "shortDescription"}
        entry.update(changes)
        return {k: v for k, v in entry.items() if v is not None}

    shipped = base["what"]["identifier_signals"]
    cases = {
        "not in what.vulnerabilities": [good(id="CVE-2099-0001")],
        "a second locus entry": shipped + [good()],
        "no rule of that name": [good(rule="websocket-admin")],
        "the rule reads MANAGEMENT, the entry says DATA": [good(locus="DATA")],
        "not what the rule's pattern matches": [good(phrase="websocket")],
        "is not one identifier_reading reads": [good(field="notes")],
        "out of what.vulnerabilities order": list(reversed(shipped)),
        # V6: the quoted description of CVE-2025-24472 reads super-admin, and the entry is gone.
        "and the record carries no locus entry": [e for e in shipped if e["id"] != "CVE-2025-24472"],
    }
    for words, entries in cases.items():
        found = _problems(with_entries(base, entries))
        assert any(words in p for p in found), (words, found)
        assert all("regenerate" in p for p in found), found
    # V6 the other way: a shortDescription entry the quotation does not yield.
    extra = shipped + [{"id": "CVE-2018-13382", "rule": "snmp", "locus": "MANAGEMENT",
                        "phrase": "SNMP", "field": "shortDescription"}]
    found = _problems(with_entries(base, sorted(extra, key=lambda e: (
        base["what"]["vulnerabilities"].index(e["id"]), "class" in e))))
    assert any("reads no locus here" in p for p in found), found
    # V5: a class reading on a record with no network. class, and one the record already holds.
    forti = BY_ID["exp-psirt-fortinet-fortipam"]
    vpn = [{"id": forti["what"]["vulnerabilities"][0], "rule": "vpn",
            "class": "network.vpn_gateway", "phrase": "VPN", "field": "title"}]
    assert any("carrying no class beginning" in p for p in _problems(with_entries(forti, vpn)))
    gateway = BY_ID["exp-kev-ivanti-connect-secure-policy-secure-and-zta-gateways"]
    assert "network.vpn_gateway" in gateway["who"]["product_class"]
    held = [{"id": gateway["what"]["vulnerabilities"][0], "rule": "vpn",
             "class": "network.vpn_gateway", "phrase": "VPN", "field": "vulnerabilityName"}]
    assert any("already carries network.vpn_gateway" in p
               for p in _problems(with_entries(gateway, held)))
    # V2: a record whose first product class is not read.
    client = BY_ID["exp-psirt-fortinet-forticlient"]
    assert any("undecomposed_classes" in p for p in _problems(with_entries(client, [
        {"id": client["what"]["vulnerabilities"][0], "rule": "management-interface",
         "locus": "MANAGEMENT", "phrase": "management interface", "field": "title"}])))
    # V1: an observation and a hand-written exposure.
    for rid in ("exp-fortinet-fortios-mfa-bypass-username-case",
                "obs-fortinet-product-family-breadth-and-management-reach"):
        record = BY_ID[rid]
        assert any("which no generator wrote" in p for p in _problems(with_entries(record, [
            {"id": "CVE-2020-12812", "rule": "command-line-interface", "locus": "MANAGEMENT",
             "phrase": "CLI", "field": "shortDescription"}]))), rid


def test_validate_reads_a_dropped_field_as_carrying_none(monkeypatch):
    """A review of 0.44.0: the re-read of quoted catalogue descriptions returned at once on a
    record with no what.identifier_signals key, so it ran on the 59 catalogue records carrying
    the field and on none of the other 640, and a record whose field was dropped passed while its
    exposure moved plane. A generated exposure with no key now reads as carrying no entries."""
    for rid in ("exp-kev-fortinet-fortios-and-fortiproxy", "exp-kev-palo-alto-networks-pan-os",
                "exp-kev-f5-big-ip-configuration-utility"):
        record = copy.deepcopy(BY_ID[rid])
        del record["what"]["identifier_signals"]
        found = _problems(record)
        assert any("and the record carries no locus entry" in p for p in found), (rid, found)
        assert all("regenerate" in p for p in found), found
    # Every carrier, its field dropped: each catalogue record whose quotation reads something is
    # caught. The two that are not read an identifier the summary does not quote (Junos OS) or
    # read the catalogue's name where its description says nothing (DrayTek); an advisory title
    # or database description is quoted by no identifier, so those records are held to the
    # table only, as the locus map says.
    missed = set()
    for record in CARRIERS:
        bare = copy.deepcopy(record)
        del bare["what"]["identifier_signals"]
        if not _problems(bare):
            missed.add(record["id"])
    unquoted = {r["id"] for r in CARRIERS if not r["id"].startswith("exp-kev-")}
    assert len(unquoted) == 30
    assert missed == unquoted | {"exp-kev-juniper-junos-os",
                                 "exp-kev-draytek-multiple-vigor-routers"}, missed - unquoted
    # Every description quoted by a catalogue record the rule reads is read again, whether or
    # not the record carries the key; a record listing an undecomposed class first, an
    # observation and a hand-written exposure, with no key, read nothing.
    calls = []
    real = validate._locus.Q.read_identifier
    monkeypatch.setattr(validate._locus.Q, "read_identifier",
                        lambda *a, **k: calls.append(1) or real(*a, **k))
    undecomposed = set(LOCUS_MAP["identifier_reading"]["undecomposed_classes"])
    nonproduct = set(LOCUS_MAP.get("nonproduct_class") or [])
    kev = [r for r in RECORDS if r.get("record_type") == "exposure"
           and Q.KEV_TAG in (r.get("tags") or [])]
    read = [r for r in kev if ([c for c in r["who"].get("product_class") or []
                                if c not in nonproduct] or [None])[0] not in undecomposed]
    for record in RECORDS:
        assert not _problems(record), record["id"]
    quoted = sum(len(Q.catalogue_descriptions(r)) for r in read)
    assert (len(kev), len(read), quoted, len(calls)) == (699, 515, 900, 900)
    note = LOCUS_MAP["_why_identifier_reading"]
    assert "({} across {} records)".format(quoted, len(read)) in note, note
    assert "the other {} list an undecomposed class first".format(len(kev) - len(read)) in note


def test_the_identifier_reading_table_is_well_formed():
    vocab = json.loads((CORPUS / "schema" / "vocab.json").read_text(encoding="utf-8"))
    schema = json.loads((CORPUS / "schema" / "observation.schema.json").read_text(encoding="utf-8"))
    attack = json.loads((CORPUS / "reference" / "attack-techniques.json").read_text(
        encoding="utf-8"))["techniques"]
    table = LOCUS_MAP["identifier_reading"]

    def problems(**changes):
        found = []
        changed = dict(table, **changes)
        count = validate.check_locus_map(vocab, schema, dict(LOCUS_MAP, identifier_reading=changed),
                                         found, attack)
        assert count == len(found), "a table problem must count as a map problem"
        return [str(p) for p in found]

    def rules(index, **changes):
        out = copy.deepcopy(table["rules"])
        out[index].update(changes)
        return [{k: v for k, v in r.items() if v is not None} for r in out]

    assert problems() == []
    found = []
    validate.check_locus_map(vocab, schema, {k: v for k, v in LOCUS_MAP.items()
                                             if k != "identifier_reading"}, found, attack)
    assert any("identifier_reading must be a table" in str(p) for p in found)
    assert any("exactly the generator tags" in p
               for p in problems(fields={"known-exploited-catalogue": ["shortDescription"]}))
    assert any("does not compile" in p for p in problems(rules=rules(0, pattern="(")))
    assert any("exactly one of locus or class" in p
               for p in problems(rules=rules(0, **{"class": "network.vpn_gateway"})))
    assert any("not in locus_order" in p for p in problems(rules=rules(0, locus="PLANE")))
    assert any("no entry in by_class" in p
               for p in problems(rules=rules(6, **{"class": "network.vpn"})))
    assert any("no other rule carries" in p for p in problems(rules=rules(1, rule="snmp")))
    assert any("leaves out 'security.edr'" in p for p in problems(
        undecomposed_classes=[c for c in table["undecomposed_classes"] if c != "security.edr"]))
    assert any("has no entry in by_class" in p for p in problems(
        undecomposed_classes=table["undecomposed_classes"] + ["endpoint.phone"]))
    assert any("class_requires_prefix" in p for p in problems(class_requires_prefix=""))
    assert any("unless does not compile" in p for p in problems(rules=rules(6, unless="(")))
    assert any("unless does not compile" in p for p in problems(rules=rules(6, unless="")))


def test_validate_prints_the_exposure_distribution_consult_derives():
    out = run("validate.py")
    line = next(l for l in out.splitlines() if l.startswith("locus derivation (exposures):"))
    counts = collections.Counter()
    decided = 0
    for record in RECORDS:
        if record.get("record_type") == "exposure":
            locus, _, basis = consult.locus_for(record, None, None, LOCUS_MAP)
            counts[locus] += 1
            decided += basis.startswith("tier=identifier;")
    printed = " ".join("{}={}".format(k, counts.get(k, 0)) for k in LOCUS_MAP["locus_order"])
    assert printed == "CONTROL=266 MANAGEMENT=131 DATA=264 ENDPOINT=148 SUPPLY=79 ORGANISATION=6"
    assert "-> {};".format(printed) in line, line
    assert line.endswith("; {} carrying what.identifier_signals, {} placed by every identifier's "
                         "own text".format(len(CARRIERS), decided)), line
    assert (len(CARRIERS), decided) == (89, 24)


# ----------------------------------------------------- what must not move (pass before and after)

def test_a_class_reading_alone_never_decides_the_primary():
    """CVE-2026-50751 reads network.vpn_gateway, CONTROL as the record's firewall class is: the
    class tier still decides."""
    locus, span, basis = placed("exp-kev-check-point-security-gateway")
    assert (locus, span) == ("CONTROL", None)
    assert basis.startswith("tier=class_first;"), basis


def test_text_that_names_no_component_moves_nothing():
    """An LDAP connectivity test, a "web UI", Catalyst SD-WAN's peering authentication (session
    establishment, the network-sense control plane), a kernel and a mobile management product:
    no field, no basis suffix, the placement 0.43.0 gave."""
    expected = {"exp-kev-fortinet-fortios-and-fortiadc": ("CONTROL", None),
                "exp-kev-cisco-ios-xe-web-ui": ("CONTROL", None),
                "exp-kev-cisco-catalyst-sd-wan-controller-and-manager": ("CONTROL", None),
                "exp-kev-linux-kernel": ("ENDPOINT", None),
                "exp-kev-ivanti-endpoint-manager-mobile-epmm": ("MANAGEMENT", None)}
    for rid, want in expected.items():
        assert "identifier_signals" not in BY_ID[rid]["what"], rid
        locus, span, basis = placed(rid)
        assert (locus, span) == want, (rid, basis)
        assert basis.startswith("tier=class_first;") and "identifier-signal" not in basis, rid


def test_an_undecomposed_record_is_not_read():
    """A record listing an ENDPOINT class or dev.library first is not read, whatever its text
    says: the Windows Management Console, Windows IKE, FortiClient's VPN, two EDR consoles, and
    React Native Community CLI, whose product name is "CLI"."""
    expected = {"exp-kev-microsoft-windows": "ENDPOINT",
                "exp-kev-microsoft-internet-key-exchange-ike-service-extensions": "ENDPOINT",
                "exp-psirt-fortinet-forticlient": "ENDPOINT",
                "exp-psirt-fortinet-fortideceptor": "ENDPOINT",
                "exp-kev-trend-micro-apex-one": "ENDPOINT",
                "exp-kev-react-native-community-cli": "SUPPLY"}
    for rid, want in expected.items():
        assert "identifier_signals" not in BY_ID[rid]["what"], rid
        assert placed(rid)[:2] == (want, None), rid


def test_the_rule_itself_refuses_an_undecomposed_record():
    """Not only their text: fed words every rule reads, those records still yield nothing, and
    a firewall fed the same words yields an entry per identifier."""
    words = "management interface SNMP CLI SSL-VPN"

    def texts(record):
        return {i: [(f, words) for f in ("shortDescription", "vulnerabilityName", "title",
                                         "description")]
                for i in record["what"]["vulnerabilities"]}

    for rid in ("exp-kev-microsoft-windows", "exp-psirt-fortinet-forticlient",
                "exp-psirt-fortinet-fortideceptor", "exp-kev-react-native-community-cli"):
        assert Q.identifier_signals(BY_ID[rid], texts(BY_ID[rid]), LOCUS_MAP) == [], rid
    firewall = BY_ID["exp-kev-fortinet-fortios-and-fortiadc"]
    got = Q.identifier_signals(firewall, texts(firewall), LOCUS_MAP)
    assert [(e["id"], e.get("locus") or e.get("class")) for e in got] == [
        (i, value) for i in firewall["what"]["vulnerabilities"]
        for value in ("MANAGEMENT", "network.vpn_gateway")]


def test_words_that_are_not_read():
    """Reach, yield and mechanism are not a component; "web UI", SSH and IKE are measured and
    left out (locus-map.json _why_identifier_reading)."""
    for text in ("an attacker residing in the management network",
                 "allows an attacker to obtain administrative privileges",
                 "The issue can be observed with the CLI command:",
                 "Internet Group Management Protocol (IGMP) packets",
                 "Device Management Server-Side Request Forgery",
                 "a command injection in the web UI",
                 "via the SSH server", "an IKEv2 flaw", "login.cgi cli parameter"):
        assert Q.read_identifier([("shortDescription", text)], True, LOCUS_MAP) == (None, None), text
    for text, rule in (("in the web-based management interface", "management-interface"),
                       ("in the Configuration utility", "configuration-utility"),
                       ("in the command-line interface (CLI) parser", "command-line-interface"),
                       ("an authentication bypass to super-admin", "super-admin"),
                       ("an administrative interface flaw", "administrative-interface"),
                       ("a crafted SNMP packet", "snmp")):
        locus, cls = Q.read_identifier([("shortDescription", text)], True, LOCUS_MAP)
        assert locus and locus["rule"] == rule and locus["locus"] == "MANAGEMENT", text
        assert cls is None, text
    locus, cls = Q.read_identifier([("title", "SSL-VPN heap overflow")], True, LOCUS_MAP)
    assert locus is None and cls["class"] == "network.vpn_gateway" and cls["phrase"] == "SSL-VPN"
    assert Q.read_identifier([("title", "SSL-VPN heap overflow")], False, LOCUS_MAP) == (None, None)


def test_a_provider_vpn_is_not_a_vpn_gateway():
    """A review of 0.44.0: the vpn rule read any VPN wording, so a router's MPLS VPN routing and
    forwarding (VRF) hopping flaw read network.vpn_gateway and "Huawei VPN" listed the NetEngine
    routers as a VPN gateway's flaw. A provider VPN carries its own words, and a text naming them
    is not read by the rule; over every row store the generators read, the only VPN text naming
    them is that one identifier."""
    for text in ("lets an attacker send packets into other VPNs through a crafted MPLS "
                 "forwarding packet, a VPN routing and forwarding (VRF) hopping flaw",
                 "a route leak between L3VPN instances", "an EVPN VPN flaw", "VPLS VPN traffic"):
        assert Q.read_identifier([("description", text)], True, LOCUS_MAP) == (None, None), text
    _, cls = Q.read_identifier([("description", "configured for remote-access VPN")], True,
                               LOCUS_MAP)
    assert cls["class"] == "network.vpn_gateway"
    # The rule's veto is its own: an MPLS text still reads a management component.
    locus, cls = Q.read_identifier([("description", "an SNMP flaw on an MPLS VPN router")],
                                   True, LOCUS_MAP)
    assert locus["rule"] == "snmp" and cls is None
    router = BY_ID["exp-nvd-huawei-netengine-routers"]
    assert [(e["id"], e.get("locus") or e.get("class"))
            for e in router["what"]["identifier_signals"]] == [("CVE-2012-3268", "MANAGEMENT")]
    out = consult_out("Huawei VPN")
    assert header(out, "EXPOSURES").startswith(
        "0 shown of 0 naming what was asked (product=0, vendor-class=0, vendor=0)"), out[:400]


def test_the_earliest_words_win_and_the_first_field_decides():
    """Within a text the earliest match wins, so adding a rule never re-keys text an earlier
    rule read; the name is read only where the description reads nothing."""
    locus, _ = Q.read_identifier([("shortDescription", "SNMP then the management interface")],
                                 True, LOCUS_MAP)
    assert (locus["rule"], locus["phrase"]) == ("snmp", "SNMP")
    locus, _ = Q.read_identifier([("shortDescription", "unspecified vulnerability"),
                                  ("vulnerabilityName", "Web Management Page Command Injection")],
                                 True, LOCUS_MAP)
    assert (locus["field"], locus["phrase"]) == ("vulnerabilityName", "Web Management Page")


def test_a_class_question_naming_no_vendor_is_not_widened():
    """A class read from an identifier's text reaches the vendor-class tier only: "VPN gateway"
    counts the same 30 class-only exposures it did before."""
    out = consult_out("VPN gateway", "--limit", "3")
    assert "class-only=30," in header(out, "EXPOSURES_NOT_LISTED")


def test_the_primary_is_question_independent():
    """X-07: a question's matched class only ever appends, so a carrier's primary and first span
    value are the same whatever is asked. The count is held first: before 0.44.0 no record
    carried the field, and a loop over none passes."""
    assert len(CARRIERS) == 89
    for record in CARRIERS:
        bare = consult.placed(record, None, None, LOCUS_MAP)
        for asked in (None, {"network.firewall"}, {"network.vpn_gateway"}, {"app.rmm"}):
            got = consult.placed(record, None, None, LOCUS_MAP, asked)
            assert got[0] == bare[0] and got[1][:len(bare[1])] == bare[1], (record["id"], asked)
