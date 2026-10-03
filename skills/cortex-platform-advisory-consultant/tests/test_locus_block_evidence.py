# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Record-level planes that decided a block whose own evidence read none of them.

The 2026-10-01 fourth validation found two from different probes:

- planes-ot: the Siemens S7 record's library-artefact block reads only EDR and file evidence
  on a host that is not an engineering workstation, cites no initial-access technique, and
  reads nothing on the record's management-interface surface or its PLC classes' CONTROL.
  surface_reaches_block kept the surface for it, so it printed MANAGEMENT and both Siemens
  answers named ENDPOINT absent. host_evidence places it on ENDPOINT.
- planes-cloud: the AWS Kubernetes node-credentials record lists cloud.container first, and
  its metadata credential request paired with the node role's first cloud API call, read
  from flow records and the provider's audit trail, printed CONTROL, the only Amazon-named
  CONTROL finding. admin_api_listed places it on MANAGEMENT from cloud.iaas, listed second.
  The same major names the Bedrock model-access block, read from CloudTrail alone, on CONTROL
  because a user name and an agent sit beside its operations; the operation tier now reads a
  block that reads only the audit trail as the API's live test.

The same shape, a block on its record's first-listed class's plane while reading none of
it, closes three 0.43.0 minors through host_listed: an endpoint class listed after the
first places a block that reads only host evidence. A contested evidence type now takes no
part in the surface reach test either. Each rule is pinned on the corpus blocks the probes
named, on synthetic blocks carrying only what the ladder reads, in both directions, and on
the whole corpus: exactly eleven blocks move, and no pattern or exposure. Run with
PYTHONDONTWRITEBYTECODE=1 (LAW A26).
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
BLOCKS = [(record, i, how) for record in RECORDS for i, how in enumerate(record.get("how") or [])]

S7 = "obs-siemens-s7-plc-commodity-library-tooling"
NODE = "obs-amazon-kubernetes-node-credentials-to-cloud-account-takeover"
BEDROCK = "obs-amazon-bedrock-model-access-obtained-by-minting-iam-users"
STATE_FILE = "obs-amazon-s3-infrastructure-state-file-to-second-account"
EXCHANGE_ONLINE = "obs-microsoft-exchange-online-forged-token-mailbox-access"
SPIFFE = "obs-spiffe-spire-cgroup-spoofing-issues-co-located-workload-identities"
RESTRICTED = "obs-generic-remaining-gap-conditions-from-restricted-library"
MODEL_STORE = "obs-generic-ransomware-built-for-model-and-dataset-artefacts"
AI_CLIENTS = "obs-generic-adversary-use-of-ai-assistants-and-the-artefacts-left-behind"
VPN_APPLIANCE = "obs-generic-remote-access-appliance-compromise-for-access-resale"

# The seven blocks host_listed places, each host execution on a record that lists an
# operating system, browser or agent class after its first.
HOST_LISTED = {
    "obs-generic-email-thread-hijacking-loader-distribution#how2",
    RESTRICTED + "#how2",
    AI_CLIENTS + "#how0",
    MODEL_STORE + "#how0",
    "obs-google-sheets-visualization-api-browser-injected-crypto-skimmer#how3",
    "obs-microsoft-active-directory-ntds-shadow-copy-extraction#how1",
    "obs-anthropic-claude-code-session-parents-tunnel-and-persistence#how2",
}

# The operation tier's blocks before the fourth validation, every one with every typed marker
# a cloud_operation; the audit-trail case adds the Bedrock and S3 blocks.
OPERATION_BEFORE = {
    "obs-cisco-duo-default-mfa-configuration-enrolment-abuse#how1",
    "obs-generic-ransomware-ecosystem-behaviour-and-timing#how2",
    "obs-generic-container-and-cloud-control-conditions-from-restricted-library#how1",
    "obs-generic-container-and-cloud-control-conditions-from-restricted-library#how2",
    RESTRICTED + "#how0",
    "obs-ivanti-epmm-authentication-bypass-and-arbitrary-file-write-chain#how2",
    "obs-microsoft-cloud-initial-access-via-service-and-dormant-accounts#how0",
    "obs-microsoft-cloud-initial-access-via-service-and-dormant-accounts#how2",
    "obs-microsoft-cloud-post-compromise-federated-identity-and-api-persistence#how1",
    "obs-microsoft-office-365-rapid-deployment-configuration-gaps#how1",
    "obs-microsoft-entra-id-administrative-units-conceal-and-protect-privilege#how0",
    "obs-microsoft-azure-service-principal-secret-to-tenant-takeover#how0",
    "obs-amazon-cloudtrail-disabled-mid-intrusion#how0",
    "obs-amazon-lambda-code-and-environment-variables-harvested#how0",
    BEDROCK + "#how1",
    "obs-amazon-cryptojacking-spread-across-uncommon-services#how0",
    "obs-amazon-console-sign-in-cloned-with-live-second-factor-capture#how1",
    "obs-amazon-role-trust-policy-open-to-any-account#how0",
}


def tier(basis):
    found = re.match(r"^tier=([a-z_]+);", basis)
    assert found, basis
    return found.group(1)


def placed(rid, index):
    return consult.locus_for(BY_ID[rid], BY_ID[rid]["how"][index], None, LOCUS_MAP)


def one_block(classes, evidence, surface="local_network", technique=(), markers=()):
    record = {"id": "obs-synthetic", "record_type": "observation", "tags": [],
              "who": {"product_class": list(classes)}, "what": {"attack_surface": surface}}
    how = {"evidence_type": list(evidence), "rule_shape": "single_event",
           "technique": list(technique), "markers": [dict(m) for m in markers]}
    return record, how


def synthetic(classes, evidence, surface="local_network", technique=(), markers=()):
    got = consult.locus_for(*one_block(classes, evidence, surface, technique, markers), None,
                            LOCUS_MAP)
    return got[0], tier(got[2]), got


def operation(*names):
    return {"type": "cloud_operation", "match": "in", "value": list(names)}


def typed(kind, value):
    return {"type": kind, "match": "equals", "value": value}


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


def header(stdout, key):
    line = [l for l in stdout.splitlines() if l.startswith(key + ": ")]
    assert len(line) == 1, key
    return line[0].split(": ", 1)[1]


def absent(stdout):
    named = header(stdout, "LOCUS_ABSENT").split(" - ", 1)[0]
    return set() if named.startswith("none") else {v.strip() for v in named.split(",")}


# ------------------------------------------------------------------------------ planes-ot

def test_a_block_reading_only_host_evidence_past_its_surface_is_endpoint():
    locus, span, basis = placed(S7, 0)
    assert (locus, span) == ("ENDPOINT", "MANAGEMENT") and tier(basis) == "host_evidence", basis
    assert "reads only host evidence (edr_process, edr_file, file_artefact)" in basis, basis
    assert ("set aside for this block, which reads only host evidence, cites no initial-access "
            "technique and reads nothing on MANAGEMENT or on CONTROL, its first-listed class's "
            "plane: span only") in basis, basis


def test_the_s7_records_other_blocks_keep_their_placement():
    """A block reading its class's plane keeps the class, and DATA alone does not set the
    management interface aside: the controller sweep is read from flow and IDS records, the
    same shape as an SNMP sweep the vocabulary names MANAGEMENT."""
    expected = {1: ("CONTROL", "class_first"), 2: ("MANAGEMENT", "surface"),
                3: ("CONTROL", "class_first"), 4: ("MANAGEMENT", "surface"),
                5: ("ORGANISATION", "posture")}
    for index, (locus, rule) in expected.items():
        got = placed(S7, index)
        assert (got[0], tier(got[2])) == (locus, rule), (index, got)


def test_the_host_evidence_rule_on_a_block_carrying_only_what_it_reads():
    plc, management = ["ot.plc"], "internet_facing_management"
    host = ("edr_process", "edr_file")
    locus, rule, got = synthetic(plc, host, management)
    assert (locus, got[1], rule) == ("ENDPOINT", "MANAGEMENT", "host_evidence"), got
    # A contested type neither decides nor stops it.
    assert synthetic(["server.database"], ("edr_process", "process_telemetry"),
                     management)[:2] == ("ENDPOINT", "host_evidence")
    # The other direction. A block about the way in, or reading the surface's plane, keeps
    # the surface; one reading its class's plane keeps the class; DATA or SUPPLY alone set
    # nothing aside; a surface on the class's own plane always reaches, so an appliance whose
    # portal and class are both CONTROL keeps CONTROL for a host-only block.
    for classes, evidence, surface, technique, want in (
            (plc, host, management, ("T1190",), ("MANAGEMENT", "surface")),
            (plc, ("edr_process", "config_diff"), management, (), ("MANAGEMENT", "surface")),
            (plc, ("edr_process", "ics_protocol"), management, (), ("CONTROL", "class_first")),
            (plc, ("netflow", "network_ids"), management, (), ("MANAGEMENT", "surface")),
            (["server.database"], ("integrity_check", "syslog"), management, (),
             ("MANAGEMENT", "surface")),
            (["network.vpn_gateway"], ("edr_process",), "vpn_portal", (), ("CONTROL", "surface")),
            (["endpoint.os"], host, management, (), ("ENDPOINT", "class_first"))):
        got = synthetic(classes, evidence, surface, technique)
        assert got[:2] == want, (classes, evidence, surface, technique, got[2])
    # The corpus's VPN appliance record: three host-only blocks under a portal surface on its
    # class's own plane stay there.
    for index in (1, 2, 4):
        got = placed(VPN_APPLIANCE, index)
        assert (got[0], tier(got[2])) == ("CONTROL", "surface"), (index, got)


def test_contested_evidence_neither_decides_nor_stops_a_surface():
    """The reach test read process_telemetry as CONTROL while every tier left it out, so it
    could set a surface aside by reading a first-listed class's CONTROL, or keep one by reading
    a CONTROL surface. Both directions, and a block reading its class's plane uncontested."""
    management = "internet_facing_management"
    locus, rule, got = synthetic(["ot.plc"], ("process_telemetry",), management)
    assert (locus, rule) == ("MANAGEMENT", "surface"), got
    locus, rule, got = synthetic(["app.rmm"], ("edr_process", "process_telemetry"), "vpn_portal")
    assert (locus, rule) == ("ENDPOINT", "host_evidence"), got
    assert "process_telemetry contested and not read" in got[2], got
    # Must not move: the industrial protocol is the class's own plane, read uncontested.
    assert synthetic(["ot.plc"], ("ics_protocol", "process_telemetry"),
                     management)[:2] == ("CONTROL", "class_first")
    # One deciding set for every evidence test.
    assert consult.deciding_planes({"evidence_type": ["edr_process", "process_telemetry",
                                                      "syslog", "netflow"]},
                                   LOCUS_MAP) == {"ENDPOINT", "DATA"}


# --------------------------------------------------------------------------- planes-cloud

def test_an_administrative_api_class_listed_later_places_a_block_reading_its_api():
    for index in (0, 1):
        locus, span, basis = placed(NODE, index)
        assert locus == "MANAGEMENT" and tier(basis) == "admin_api_listed", (index, basis)
        assert ("lists cloud.iaas after first-listed=cloud.container, and the block reads that "
                "administrative API and nothing on CONTROL") in basis, basis
    assert "process_telemetry contested and not read" in placed(NODE, 0)[2]


def test_the_listed_administrative_api_rule_on_a_block_carrying_only_what_it_reads():
    container = ["cloud.container", "cloud.iaas"]
    assert synthetic(container, ("cloud_audit", "netflow"))[:2] == ("MANAGEMENT",
                                                                   "admin_api_listed")
    assert synthetic(container, ("cloud_audit", "process_telemetry"))[:2] == (
        "MANAGEMENT", "admin_api_listed")
    reading = {"type": "cloud_operation", "match": "equals", "value": "MailItemsAccessed"}
    # The other direction: evidence on the first class's plane keeps it, a block that never
    # reads the API is not moved, a class not listed in administrative_api_classes moves
    # nothing, a use of a service is not its administration, and a first-listed cloud.iaas
    # was never in question.
    for classes, evidence, markers, want in (
            (container, ("cloud_audit", "auth_log"), (), ("CONTROL", "class_first")),
            (container, ("netflow",), (), ("CONTROL", "class_first")),
            (["cloud.container", "cloud.identity"], ("cloud_audit",), (), ("CONTROL", "class_first")),
            (["cloud.saas", "cloud.iaas"], ("cloud_audit",), (reading,), ("DATA", "class_first")),
            (["cloud.iaas", "cloud.container"], ("cloud_audit",), (), ("MANAGEMENT", "class_first"))):
        got = synthetic(classes, evidence, markers=markers)
        assert got[:2] == want, (classes, evidence, got[2])
    # A pattern's applies_to_classes says where it applies, not which provider an incident
    # ran through, so a pattern placed with no block is never read this way.
    pattern = {"id": "pat-synthetic", "applies_to_classes": container,
               "evidence_type": ["cloud_audit", "netflow"], "rule_shape": "correlation",
               "markers": []}
    got = consult.locus_for(None, None, pattern, LOCUS_MAP)
    assert got[0] == "CONTROL" and tier(got[2]) == "class_first", got


def test_an_audit_trail_only_block_testing_an_administrative_operation_is_management():
    """0.43.0 kept the Bedrock model-access block on CONTROL because a user name and an agent
    sit beside its operations; every one of them is a field of the same CloudTrail event."""
    locus, span, basis = placed(BEDROCK, 0)
    assert locus == "MANAGEMENT" and tier(basis) == "operation", basis
    assert ("reads only the provider's audit trail (cloud_audit), and its markers test cloud "
            "administrative operations there") in basis, basis
    assert "beside other fields of the same event (username, user_agent)" in basis, basis
    # The S3 caller-identity block was MANAGEMENT by its first class and changes tier only.
    locus, _, basis = placed(STATE_FILE, 1)
    assert locus == "MANAGEMENT" and tier(basis) == "operation", basis
    ai = ["app.ai_platform", "cloud.identity"]
    got = synthetic(ai, ("cloud_audit",), markers=(operation("CreateUser"), typed("username", "x"),
                                                   typed("user_agent", "y")))
    assert got[:2] == ("MANAGEMENT", "operation"), got[2]
    # Must not move: a use of the service beside an actor field; an operation beside a process
    # name read from host evidence; the audit trail with no operation at all; a use of the
    # service on its own, on the corpus block that tests it.
    assert synthetic(ai, ("cloud_audit",), markers=(operation("InvokeModel"),
                                                    typed("username", "x")))[:2] == (
        "CONTROL", "class_first")
    assert synthetic(["endpoint.os", "server.mail"], ("cloud_audit", "edr_process"),
                     markers=(operation("CreateUser"), typed("process_name", "sh")))[:2] == (
        "ENDPOINT", "class_first")
    assert synthetic(ai, ("cloud_audit",))[:2] == ("CONTROL", "class_first")
    assert placed(EXCHANGE_ONLINE, 0)[0] == "DATA"
    # The every-marker form keeps its own words.
    got = synthetic(["endpoint.os", "server.mail"], ("cloud_audit",),
                    markers=(operation("CreateUser", "GetObject"),))
    assert got[:2] == ("MANAGEMENT", "operation"), got[2]
    assert "markers test only cloud administrative operations (CreateUser, GetObject)" in got[2][2]


# ------------------------------------------------------------- the same shape, by host class

def test_an_endpoint_class_listed_later_places_a_block_reading_only_host_evidence():
    for key in sorted(HOST_LISTED):
        rid, index = key.rsplit("#how", 1)
        locus, _, basis = placed(rid, int(index))
        assert locus == "ENDPOINT" and tier(basis) == "host_listed", (key, basis)
        assert "and the block reads only host evidence (" in basis, (key, basis)
    directory = ["identity.directory", "endpoint.os"]
    locus, rule, got = synthetic(directory, ("edr_file",))
    assert (locus, rule) == ("ENDPOINT", "host_listed"), got
    assert ("lists endpoint.os after first-listed=identity.directory, and the block reads only "
            "host evidence (edr_file) and nothing on CONTROL") in got[2], got
    # Neither a contested nor a deferred type decides or stops it.
    assert synthetic(["app.ai_platform", "endpoint.os"],
                     ("edr_process", "process_telemetry", "syslog"))[:2] == (
        "ENDPOINT", "host_listed")
    # Must not move: the first class's plane read, host and traffic split, no endpoint class
    # listed (the SPIFFE shape), an endpoint-first record, and a pattern with the same classes
    # and evidence.
    for classes, evidence, want in (
            (directory, ("edr_file", "auth_log"), ("CONTROL", "class_first")),
            (directory, ("edr_file", "netflow"), ("CONTROL", "class_first")),
            (["cloud.container", "cloud.identity"], ("edr_process",), ("CONTROL", "class_first")),
            (["endpoint.os", "identity.directory"], ("edr_file",), ("ENDPOINT", "class_first"))):
        assert synthetic(classes, evidence)[:2] == want, (classes, evidence)
    pattern = {"id": "pat-synthetic", "applies_to_classes": directory,
               "evidence_type": ["edr_file"], "rule_shape": "single_event", "markers": []}
    got = consult.locus_for(None, None, pattern, LOCUS_MAP)
    assert got[0] == "CONTROL" and tier(got[2]) == "class_first", got
    for index in range(4):
        got = placed(SPIFFE, index)
        assert (got[0], tier(got[2])) == ("CONTROL", "class_first"), (index, got)


# ---------------------------------------------------------------------- what else moved

def test_the_new_rules_place_exactly_these_blocks():
    """The narrow claim, held over the shipped corpus: no other block, no pattern placed with
    no block and no exposure is placed by any of the three new tiers, and the operation tier
    gains exactly the two audit-trail blocks. A corpus change adding a block of these shapes
    fails here, and the next ingest updates the sets on purpose."""
    new = ("host_evidence", "admin_api_listed", "host_listed")
    by_rule = {rule: set() for rule in new + ("operation",)}
    for record, index, how in BLOCKS:
        rule = tier(consult.locus_for(record, how, None, LOCUS_MAP)[2])
        if rule in by_rule:
            by_rule[rule].add(consult.finding_key(record, index))
    assert by_rule == {"host_evidence": {S7 + "#how0"},
                       "admin_api_listed": {NODE + "#how0", NODE + "#how1"},
                       "host_listed": HOST_LISTED,
                       "operation": OPERATION_BEFORE | {BEDROCK + "#how0",
                                                        STATE_FILE + "#how1"}}, by_rule
    for pattern in PATTERNS.values():
        assert tier(consult.locus_for(None, None, pattern, LOCUS_MAP)[2]) not in new, pattern["id"]
    for record in RECORDS:
        if record.get("record_type") == "exposure":
            assert tier(consult.locus_for(record, None, None, LOCUS_MAP)[2]) not in new, record["id"]


def test_aws_no_longer_claims_control_coverage_for_amazon():
    out = run(SCRIPTS / "consult.py", "AWS", "--today", "2026-10-01")
    assert header(out, "LOCUS_SUBJECT").startswith("CONTROL=0, "), header(out, "LOCUS_SUBJECT")
    assert header(out, "LOCUS_ANALOGUE_ONLY").startswith("CONTROL, ENDPOINT - "), \
        header(out, "LOCUS_ANALOGUE_ONLY")
    assert header(out, "LOCUS_ABSENT").startswith("ORGANISATION - "), header(out, "LOCUS_ABSENT")
    shown = {f["FINDING_KEY"]: f for f in findings(out)}
    assert shown[NODE + "#how0"]["LOCUS"] == "MANAGEMENT", shown[NODE + "#how0"]["LOCUS_BASIS"]
    # Must not move: the supply-path filter block, and DATA from the two blocks off cloud.iaas.
    assert shown["obs-amazon-codebuild-webhook-actor-filter-matched-on-substring#how0"]["LOCUS"] \
        == "SUPPLY"
    assert "DATA" not in absent(out)
    every = {f["FINDING_KEY"]: f for f in findings(
        run(SCRIPTS / "consult.py", "AWS", "--today", "2026-10-01", "--limit", "500",
            "--no-locus-spread"))}
    assert every[BEDROCK + "#how0"]["LOCUS"] == "MANAGEMENT", every[BEDROCK + "#how0"]["LOCUS_BASIS"]


def test_siemens_no_longer_reports_endpoint_absent():
    for question in ("Siemens", "Siemens S7"):
        out = run(SCRIPTS / "consult.py", question, "--today", "2026-10-01")
        assert "ENDPOINT" not in absent(out), (question, header(out, "LOCUS_ABSENT"))
        every = {f["FINDING_KEY"]: f for f in findings(
            run(SCRIPTS / "consult.py", question, "--today", "2026-10-01", "--limit", "500",
                "--no-locus-spread"))}
        artefact = every[S7 + "#how0"]
        assert artefact["LOCUS"] == "ENDPOINT", artefact["LOCUS_BASIS"]
        assert artefact["LOCUS_SPAN"].startswith("ENDPOINT, MANAGEMENT"), artefact["LOCUS_SPAN"]
        # Must not move: the data-block writes read on the PLC's own plane, and the sweep.
        assert every[S7 + "#how3"]["LOCUS"] == "CONTROL"
        assert every[S7 + "#how2"]["LOCUS"] == "MANAGEMENT"


def test_the_host_blocks_of_the_linux_kernel_listing_read_endpoint():
    """query-kev-growth: the restricted-library Unix credential-file block and two AI-platform
    host blocks sat on CONTROL, so the listing's loci for those records named no ENDPOINT."""
    out = run(SCRIPTS / "query.py", "Linux kernel")
    loci = {}
    for line in out.splitlines():
        found = re.match(r"^obs (\S+) .* loci=(\S+)\s*$", line)
        if found:
            loci[found.group(1)] = set(found.group(2).split(","))
    for rid in (RESTRICTED, MODEL_STORE, AI_CLIENTS):
        assert rid in loci, (rid, sorted(loci))
        assert "ENDPOINT" in loci[rid], (rid, loci[rid])


def test_the_credential_file_pattern_is_observed_on_endpoint():
    """revoked-and-family: the pattern's one citing block sat on CONTROL by its record's first
    class, so a credential file read at a shell spanned ENDPOINT, CONTROL."""
    out = run(SCRIPTS / "advise.py", "--patterns", "pat-credential-file-read-by-interactive-tool",
              "--no-verify")
    assert header(out, "LOCUS_SPAN") == "ENDPOINT", header(out, "LOCUS_SPAN")
    assert header(out, "LOCUS_OBSERVED").startswith("ENDPOINT=1 "), header(out, "LOCUS_OBSERVED")
