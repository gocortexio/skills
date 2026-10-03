# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Three places the ladder let a record's first-listed class outrank what the block says.

The 2026-10-01 third validation found each from a different probe, and each was the class
tier deciding where the block itself had already committed:

- contract: a library pattern placed with no record read only its applies_to_classes, so
  pat-mailbox-delegation-or-role-granted, whose one live test is an Exchange role or
  permission grant, derived DATA from server.mail while the block citing it sat on
  MANAGEMENT through the operation tier. advise.py then printed MANAGEMENT under
  LOCUS_ABSENT for a selection holding a role-grant detection.
- planes-cloud: cloud.iaas is defined as an administrative API and console, and a record
  listing it first put every block on MANAGEMENT, including a certificate-issuance alert read
  from DNS and TLS metadata and a host's mining-pool traffic. The AWS header then named DATA
  absent while two AWS-named findings read it.
- locus-consistency: the inventory-shape tier sat below class_first and could never fire, so
  a vulnerability-management join reading only posture took whatever plane its record listed
  first. Its 13 citing blocks sat on five loci, and the one on a web-server-first record
  filled the DATA slot on firewall and VPN questions.

Each is pinned on the corpus record or pattern the probe named, and on a synthetic input
carrying only what the ladder reads. Run with PYTHONDONTWRITEBYTECODE=1 (LAW A26).
"""
import pathlib
import re
import subprocess
import sys

BUNDLE = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = BUNDLE / "scripts"
CORPUS = BUNDLE / "corpus"

sys.dont_write_bytecode = True
sys.path.insert(0, str(SCRIPTS))
import consult  # noqa: E402
import query  # noqa: E402

RECORDS, PATTERNS = query.load_corpus(str(CORPUS))
LOCUS_MAP = consult.load_locus_map(str(CORPUS))
BY_ID = {r["id"]: r for r in RECORDS}
BLOCKS = [(record, how) for record in RECORDS for how in (record.get("how") or [])]
POSTURE = {e for e, locus in LOCUS_MAP["by_evidence"].items() if locus == "ORGANISATION"}


def tier(basis):
    found = re.match(r"^tier=([a-z_]+);", basis)
    assert found, basis
    return found.group(1)


def block(key):
    rid, index = key.rsplit("#how", 1)
    return BY_ID[rid], BY_ID[rid]["how"][int(index)]


def one_block(classes, evidence, shape="single_event", surface="local_network", technique=(),
              markers=()):
    record = {"id": "obs-synthetic", "record_type": "observation", "tags": [],
              "who": {"product_class": list(classes)}, "what": {"attack_surface": surface}}
    how = {"evidence_type": list(evidence), "rule_shape": shape, "technique": list(technique),
           "markers": [dict(m) for m in markers]}
    return record, how


def one_pattern(classes, evidence, shape="single_event", markers=()):
    return {"id": "pat-synthetic", "applies_to_classes": list(classes),
            "evidence_type": list(evidence), "rule_shape": shape,
            "markers": [dict(m) for m in markers]}


def run(*argv):
    done = subprocess.run([sys.executable] + [str(a) for a in argv], capture_output=True,
                          text=True, timeout=300)
    assert done.returncode == 0, done.stderr[-800:]
    return done.stdout


def findings(stdout):
    found, current = [], None
    for line in stdout.splitlines():
        if line.startswith("=== FINDING "):
            current = {}
        elif line.startswith("=== END FINDING ") and current is not None:
            found.append(current)
            current = None
        elif current is not None:
            key = re.match(r"^([A-Z_]+): (.*)$", line)
            if key:
                current.setdefault(key.group(1), key.group(2))
    return found


def absent(stdout, key="LOCUS_ABSENT"):
    line = [l for l in stdout.splitlines() if l.startswith(key + ": ")]
    assert len(line) == 1, key
    named = line[0].split(": ", 1)[1].split(" - ", 1)[0]
    return set() if named.startswith("none") else {v.strip() for v in named.split(",")}


# ------------------------------------------------------------------------------ contract

ROLE_GRANT = "pat-mailbox-delegation-or-role-granted"


def test_a_pattern_whose_only_test_is_an_administrative_operation_is_management():
    """The operation tier read a record's block and never a pattern's own markers, so a
    library pattern testing only a tenant administrative API took its first-listed class."""
    locus, span, basis = consult.locus_for(None, None, PATTERNS[ROLE_GRANT], LOCUS_MAP)
    assert locus == "MANAGEMENT" and tier(basis) == "operation", basis
    assert "Add-MailboxFolderPermission" in basis, basis
    assert "class-signal=split(first=server.mail:DATA" in basis, basis

    placed = 0
    for pid, pattern in PATTERNS.items():
        if not consult.administrative_operation(pattern, LOCUS_MAP):
            continue
        locus, _, basis = consult.locus_for(None, None, pattern, LOCUS_MAP)
        if tier(basis) in ("declared", "class_nonproduct"):
            continue
        placed += 1
        assert locus == "MANAGEMENT" and tier(basis) == "operation", (pid, basis)
    assert placed >= 15, placed


def test_a_pattern_is_placed_by_its_own_markers_only_where_they_are_administrative():
    mail = ["server.mail", "cloud.saas"]
    grant = consult.locus_for(None, None, one_pattern(mail, ("cloud_audit",), markers=[
        {"type": "cloud_operation", "match": "in", "value": ["New-ManagementRoleAssignment"]}]),
        LOCUS_MAP)
    assert grant[0] == "MANAGEMENT" and tier(grant[2]) == "operation", grant
    assert "input=pattern markers test only cloud administrative operations" in grant[2], grant
    # Since the fourth validation a pattern reading only the audit trail is placed by an
    # operation beside other fields of the same event, so the process name here is read beside
    # host evidence: the marker no audit event carries, which still keeps the class.
    for evidence, markers in (
            (("cloud_audit",),
             [{"type": "cloud_operation", "match": "equals", "value": "MailItemsAccessed"}]),
            (("cloud_audit", "edr_process"),
             [{"type": "cloud_operation", "match": "in", "value": ["Set-Mailbox"]},
              {"type": "process_name", "match": "equals", "value": "sh"}]),
            (("cloud_audit",), [])):
        got = consult.locus_for(None, None, one_pattern(mail, evidence, markers=markers),
                                LOCUS_MAP)
        assert got[0] == "DATA" and tier(got[2]) == "class_first", (markers, got)


def test_a_records_block_still_never_reads_its_patterns_markers():
    """The role-grant pattern's citing block is placed from its own markers; a block with none
    citing an administrative-operation pattern is not moved by the pattern's."""
    for record, how in BLOCKS:
        pattern = PATTERNS.get(how.get("pattern_id"))
        if pattern and consult.administrative_operation(pattern, LOCUS_MAP) \
                and not consult.administrative_operation(how, LOCUS_MAP):
            with_pattern = consult.locus_for(record, how, pattern, LOCUS_MAP)
            assert with_pattern == consult.locus_for(record, how, None, LOCUS_MAP)
            assert tier(with_pattern[2]) != "operation", (record["id"], with_pattern[2])


def test_a_message_property_sweep_declares_data_against_the_operation_tier():
    """Its markers are mailbox audit actions, Update and UpdateInboxRules beside
    MailItemsAccessed, which would place it on MANAGEMENT once a pattern's own markers are
    read; what it reads is properties of mail held, and it says so in its locus_reason."""
    pattern = PATTERNS["pat-mail-item-property-scan"]
    assert pattern["locus"] == "DATA" and "mail held is DATA" in pattern["locus_reason"]
    underived = {k: v for k, v in pattern.items() if k not in ("locus", "locus_reason")}
    assert consult.locus_for(None, None, underived, LOCUS_MAP)[0] == "MANAGEMENT"
    locus, _, basis = consult.locus_for(None, None, pattern, LOCUS_MAP)
    assert locus == "DATA" and tier(basis) == "declared", basis


def test_advise_reports_a_role_grant_selection_on_management():
    out = run(SCRIPTS / "advise.py", "--patterns",
              "pat-container-escape-to-host,pat-process-ancestry-does-not-match-reality,"
              + ROLE_GRANT, "--no-verify")
    blocks = out.split("--- PATTERN_ID: ")[1:]
    grant = [b for b in blocks if b.startswith(ROLE_GRANT + "\n")]
    assert len(grant) == 1
    assert "\nLOCUS: MANAGEMENT\n" in grant[0], grant[0][:600]
    assert "MANAGEMENT" not in absent(out), [l for l in out.splitlines() if "LOCUS_ABSENT" in l]
    assert re.search(r"^LOCUS_RETURNED: .*MANAGEMENT=1,", out, re.M), out[:2000]


# -------------------------------------------------------------------------- planes-cloud

CERTIFICATE = "obs-amazon-elastic-ip-released-while-dns-still-points-at-it#how1"
MINER = "obs-amazon-cryptojacking-spread-across-uncommon-services"


def test_an_administrative_api_class_does_not_place_a_block_that_never_reads_it():
    locus, span, basis = consult.locus_for(*block(CERTIFICATE), None, LOCUS_MAP)
    assert locus == "DATA" and tier(basis) == "admin_api_unread", basis
    assert "first-listed=cloud.iaas" in basis, basis

    # The pool traffic reads DNS and flow records; process_telemetry, whose reading is
    # contested, neither decides nor keeps the block on the class.
    locus, span, basis = consult.locus_for(*block(MINER + "#how2"), None, LOCUS_MAP)
    assert (locus, span) == ("DATA", "SUPPLY") and tier(basis) == "admin_api_unread", basis
    # The role-and-workload correlation tests the API; the image check reads its audit trail.
    assert consult.locus_for(*block(MINER + "#how0"), None, LOCUS_MAP)[0] == "MANAGEMENT"
    locus, _, basis = consult.locus_for(*block(MINER + "#how1"), None, LOCUS_MAP)
    assert locus == "MANAGEMENT" and tier(basis) == "class_first", basis


def test_the_administrative_api_rule_on_a_block_carrying_only_what_it_reads():
    iaas = ["cloud.iaas", "server.web"]
    got = consult.locus_for(*one_block(iaas, ("netflow", "dns")), None, LOCUS_MAP)
    assert got[0] == "DATA" and tier(got[2]) == "admin_api_unread", got
    got = consult.locus_for(*one_block(iaas, ("edr_process", "process_telemetry")), None, LOCUS_MAP)
    assert got[0] == "ENDPOINT" and tier(got[2]) == "admin_api_unread", got
    # Reading the API in any form keeps the class: its audit trail or configuration, an
    # operation marker beside other typed markers, or the provider's own inventory.
    for evidence, markers in ((("netflow", "cloud_audit"), ()), (("netflow", "config_diff"), ()),
                              (("netflow",), ({"type": "cloud_operation", "match": "equals",
                                               "value": "RunInstances"},
                                              {"type": "process_name", "match": "equals",
                                               "value": "xmrig"})),
                              (("asset_inventory",), ()), (("netflow", "edr_process"), ()),
                              (("process_telemetry",), ()), ((), ())):
        got = consult.locus_for(*one_block(iaas, evidence, markers=markers), None, LOCUS_MAP)
        assert got[0] == "MANAGEMENT" and tier(got[2]) == "class_first", (evidence, got)
    # Only a class the map lists: cloud.identity is not, and a class off MANAGEMENT never is.
    assert consult.locus_for(*one_block(["cloud.identity"], ("netflow",)), None, LOCUS_MAP)[0] \
        == "MANAGEMENT"
    assert consult.locus_for(*one_block(["network.firewall"], ("netflow",)), None, LOCUS_MAP)[0] \
        == "CONTROL"
    # A pattern reads its own evidence and markers the same way.
    got = consult.locus_for(None, None, one_pattern(iaas, ("dns", "tls_metadata")), LOCUS_MAP)
    assert got[0] == "DATA" and tier(got[2]) == "admin_api_unread", got


def test_validate_holds_the_two_evidence_lists_to_what_they_claim():
    import json
    import validate
    vocab = json.loads((CORPUS / "schema" / "vocab.json").read_text(encoding="utf-8"))
    schema = json.loads((CORPUS / "schema" / "observation.schema.json").read_text(encoding="utf-8"))
    attack = json.loads((CORPUS / "reference" / "attack-techniques.json").read_text(
        encoding="utf-8"))["techniques"]

    def problems(**changes):
        found = []
        validate.check_locus_map(vocab, schema, dict(LOCUS_MAP, **changes), found, attack)
        return [str(p) for p in found]

    assert problems() == []
    assert any("not placed on MANAGEMENT" in p
               for p in problems(administrative_api_classes=["cloud.iaas", "identity.sso"]))
    assert any("non-product class" in p
               for p in problems(administrative_api_classes=["cross_sector"]))
    assert any("must be a list" in p for p in problems(administrative_api_classes="cloud.iaas"))
    assert any("no entry in by_evidence" in p for p in problems(contested_evidence=["telemetry"]))
    assert any("also deferred" in p for p in problems(contested_evidence=["syslog"]))
    assert any("must be a list" in p for p in problems(contested_evidence="process_telemetry"))


def test_aws_reaches_data_with_its_own_findings():
    out = run(SCRIPTS / "consult.py", "AWS", "--today", "2026-09-30")
    assert "DATA" not in absent(out), [l for l in out.splitlines() if l.startswith("LOCUS_ABSENT")]
    every = findings(run(SCRIPTS / "consult.py", "AWS", "--today", "2026-09-30", "--limit", "500",
                         "--no-locus-spread"))
    data = {f["FINDING_KEY"] for f in every if f.get("LOCUS") == "DATA"}
    assert {CERTIFICATE, MINER + "#how2"} <= data, data


# --------------------------------------------------------------------- locus-consistency

HARVEST = "obs-generic-broad-known-vulnerability-harvesting#how0"
CATALOGUE = "pat-known-exploited-vulnerability-catalogue-join"


def test_a_posture_question_is_organisation_whatever_its_record_lists_first():
    locus, span, basis = consult.locus_for(*block(HARVEST), None, LOCUS_MAP)
    assert locus == "ORGANISATION" and tier(basis) == "posture", basis
    assert "class-signal=split(first=server.web:DATA" in basis, basis

    cited = [(r, h) for r, h in BLOCKS if h.get("pattern_id") == CATALOGUE]
    assert len(cited) >= 10, len(cited)
    assert {consult.locus_for(r, h, None, LOCUS_MAP)[0] for r, h in cited} == {"ORGANISATION"}
    assert consult.locus_for(None, None, PATTERNS[CATALOGUE], LOCUS_MAP)[0] == "ORGANISATION"

    contested = set(LOCUS_MAP["contested_evidence"]) | set(LOCUS_MAP["defer_evidence"])
    posture = 0
    for record, how in BLOCKS:
        read = {e for e in how.get("evidence_type") or [] if e not in contested}
        if how.get("rule_shape") != "inventory" or not read or not read <= POSTURE:
            continue
        posture += 1
        locus, _, basis = consult.locus_for(record, how, None, LOCUS_MAP)
        if tier(basis) not in ("declared", "surface_supply"):
            assert locus == "ORGANISATION", (record["id"], basis)
    assert posture > 60, posture


def test_the_posture_rule_on_a_block_carrying_only_what_it_reads():
    firewall = ["network.firewall", "server.web"]
    got = consult.locus_for(*one_block(firewall, ("vuln_scan", "asset_inventory"), "inventory"),
                            None, LOCUS_MAP)
    assert got[0] == "ORGANISATION" and tier(got[2]) == "posture", got
    # A posture question about the way in is still a posture question: the surface it would
    # have kept is carried as the span.
    got = consult.locus_for(*one_block(firewall, ("asset_inventory",), "inventory",
                                       surface="internet_facing_management", technique=("T1190",)),
                            None, LOCUS_MAP)
    assert got[:2] == ("ORGANISATION", "MANAGEMENT") and "span-source=surface" in got[2], got
    # Shape alone decides nothing, and posture evidence alone decides nothing.
    for evidence, shape in ((("asset_inventory", "netflow"), "inventory"),
                            (("asset_inventory",), "single_event")):
        got = consult.locus_for(*one_block(firewall, evidence, shape), None, LOCUS_MAP)
        assert got[0] == "CONTROL" and tier(got[2]) == "class_first", (evidence, shape, got)
    # A supply surface reaching the block, and a declaration, still outrank it.
    got = consult.locus_for(*one_block(["app.msp"], ("asset_inventory",), "inventory",
                                       surface="third_party_access", technique=("T1199",)),
                            None, LOCUS_MAP)
    assert got[0] == "SUPPLY" and tier(got[2]) == "surface_supply", got
    record, how = one_block(firewall, ("asset_inventory",), "inventory")
    how["locus"] = "CONTROL"
    assert consult.locus_for(record, how, None, LOCUS_MAP)[0] == "CONTROL"
    # A pattern reads its own shape and evidence the same way.
    got = consult.locus_for(None, None, one_pattern(firewall, ("vuln_scan",), "inventory"), LOCUS_MAP)
    assert got[0] == "ORGANISATION" and tier(got[2]) == "posture", got


def test_a_posture_pattern_states_the_shape_its_citing_blocks_state():
    """Ten posture patterns, the catalogue join among them, stated no rule_shape while every
    citing block that states one said inventory, so the posture tier could place each block
    and not the pattern: advise.py printed the join on DATA from server.web while all 13 of
    its citing blocks sat on ORGANISATION."""
    contested = set(LOCUS_MAP["contested_evidence"]) | set(LOCUS_MAP["defer_evidence"])
    checked = 0
    for pid, pattern in PATTERNS.items():
        read = {e for e in pattern.get("evidence_type") or [] if e not in contested}
        shapes = {h.get("rule_shape") for _, h in BLOCKS if h.get("pattern_id") == pid} - {None}
        if not read or not read <= POSTURE or shapes != {"inventory"}:
            continue
        checked += 1
        assert pattern.get("rule_shape") == "inventory", pid
        locus, _, basis = consult.locus_for(None, None, pattern, LOCUS_MAP)
        if tier(basis) != "declared":
            assert locus == "ORGANISATION", (pid, basis)
    assert checked >= 20, checked


def test_every_tier_the_map_advertises_decides_something():
    """`shape` was listed, documented and printed in the reference while no input could ever
    reach it, the condition that had the evidence tier deleted. Every tier but the floor must
    decide at least one block or pattern of the shipped corpus."""
    decided = {tier(consult.locus_for(r, h, None, LOCUS_MAP)[2]) for r, h in BLOCKS}
    decided |= {tier(consult.locus_for(None, None, p, LOCUS_MAP)[2]) for p in PATTERNS.values()}
    decided |= {tier(consult.locus_for(r, None, None, LOCUS_MAP)[2]) for r in RECORDS
                if r.get("record_type") == "exposure"}
    assert LOCUS_MAP["tier_order"][-1] == "default"
    unreached = [t for t in LOCUS_MAP["tier_order"][:-1] if t not in decided]
    assert not unreached, unreached


def test_fortigate_prints_the_harvest_join_on_organisation():
    every = findings(run(SCRIPTS / "consult.py", "Fortinet FortiGate", "--today", "2026-09-30",
                         "--limit", "500", "--no-locus-spread"))
    harvest = [f for f in every if f.get("FINDING_KEY") == HARVEST]
    assert len(harvest) == 1
    assert harvest[0]["LOCUS"] == "ORGANISATION", harvest[0]["LOCUS_BASIS"]
    assert harvest[0]["LOCUS_BASIS"].startswith("tier=posture;"), harvest[0]["LOCUS_BASIS"]
