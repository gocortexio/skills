# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""An ordinary English word in a question must not set the answer's whole frame.

0.29.0 gated ambiguous *product* aliases. `class_aliases` is the third alias table and has
no gate, and a false class resolution is worse than a false product one: the product name
is one line of the header, while the class decides which plane the consultation is about.

The defect, reported by a consuming content-pack session on 2026-09-04. Asking about a
mobile in-app integrity sensor -- "an in-app sensor reporting rooted or jailbroken devices"
-- resolved `sensor` to `ot.field_device` and answered a question about consumer handsets
with industrial field instrumentation, six well-formed findings, none of them mobile.

0.30.0 deleted the two class aliases whose ordinary meaning is not the class they point at,
and left the general gate to be built. 0.43.0 builds it: `ambiguous_class_aliases` gates a
class alias by one of three modes -- `upper` (an acronym only in capitals), `refuse_near` (not
beside the words that make it something else) and `require_near` (only beside the words that
make it this class) -- and three more aliases that collide with a name are deleted. Both
halves are held here, with the tripwires for the two words still ungated.
"""
import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import query as Q  # noqa: E402

RAW = json.load(open(os.path.join(ROOT, "corpus", "schema", "aliases.json"), encoding="utf-8"))
ALIASES = Q.normalise_alias_keys(RAW)
CLASSES = RAW["class_aliases"]


def run(*args):
    return subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "consult.py")]
                          + list(args) + ["--today", "2026-08-19"],
                          capture_output=True, text=True, cwd=ROOT)


# --- the reported defect --------------------------------------------------------------

REPORTED = ("mobile application integrity: an in-app sensor reporting rooted or jailbroken "
            "devices, emulators, repackaged or tampered applications, sideloaded installs "
            "and certificate pinning failures")


def test_the_reported_question_no_longer_resolves_to_industrial_control():
    """Verbatim from the report. It resolved to ot.field_device on 0.29.0."""
    out = run(REPORTED, "--have", "licel_alice_raw", "--limit", "6").stdout
    resolved = out.split("RESOLVED_TO:")[1].split("\n")[0]
    assert "ot.field_device" not in resolved, resolved
    assert "classes=-" in resolved, resolved
    # Nothing resolving is the honest state here, and the header has to say so rather than
    # leave a reader to infer it from an empty field.
    assert "RESOLUTION: mechanism" in out, out[:400]
    assert "product=0, vendor=0, class=0," in out, out[:600]


@pytest.mark.parametrize("question,wrong_class", [
    ("an in-app sensor reporting rooted devices", "ot.field_device"),
    ("the EDR sensor stopped reporting", "ot.field_device"),
    ("instrumentation added to the binary at build time", "ot.field_device"),
])
def test_a_software_agent_is_not_a_field_instrument(question, wrong_class):
    """In a security question "sensor" is an agent and "instrumentation" is bytecode.

    Both pointed at OT, which is not a near miss: it is a different plane with a different
    threat surface, and the findings that come back are confident and irrelevant.
    """
    assert wrong_class not in Q.resolve(question, ALIASES)["classes"], question


@pytest.mark.parametrize("alias", ["sensor", "instrumentation"])
def test_the_two_removed_aliases_stay_removed(alias):
    assert alias not in CLASSES, alias


@pytest.mark.parametrize("alias", ["field device", "actuator"])
def test_the_class_they_pointed_at_is_still_reachable(alias):
    """Deletion, not gating, so the class has to keep its unambiguous ways in."""
    assert CLASSES.get(alias) == "ot.field_device", alias
    assert "ot.field_device" in Q.resolve(
        "a {} on the plant network".format(alias), ALIASES)["classes"]


# --- the registration gap underneath it -----------------------------------------------

def test_licel_routes_like_every_other_app_shielding_vendor():
    """The reported question returned nothing for Licel while Guardsquare answered.

    Both are RASP vendors and this corpus refuses both as sources on the same
    measurement. Only one of them was in the table, so the difference was a registration
    gap rather than anything about the corpus.
    """
    out = run("Licel Alice mobile in-app integrity", "--limit", "3").stdout
    assert "RESOLUTION: CLASS-LEVEL (inferred)" in out, out[:400]
    assert "CLASS_LEVEL_WARNING:" in out
    assert "classes=app.cicd, dev.library" in out, out[:400]


@pytest.mark.parametrize("question", ["licel", "dexprotector", "Licel DexProtector"])
def test_the_vendor_and_its_shielding_product_reach_the_class(question):
    assert Q.resolve(question, ALIASES)["classes"] == {"dev.library", "app.cicd"}, question


@pytest.mark.parametrize("question", [
    "alice in accounting clicked the link",
    "alice and bob exchanged keys",
    "the alice account was disabled",
])
def test_a_given_name_on_its_own_names_no_product(question):
    """Alice IS a Licel product, and it is also the commonest name in security writing.

    It is registered in product_aliases rather than beside its siblings in class_aliases,
    because product_aliases is the only table with a gate: it resolves within two tokens of
    licel and nowhere else. Putting it in class_aliases would have rebuilt the sensor defect
    in the same release that removes it.
    """
    resolved = Q.resolve(question, ALIASES)
    assert "Alice" not in resolved["products"], (question, resolved["products"])
    assert not resolved["classes"], (question, resolved["classes"])


def test_alice_resolves_when_its_vendor_is_named():
    resolved = Q.resolve("Licel Alice", ALIASES)
    assert resolved["products"] == {"Alice"}
    assert resolved["vendors"] == {"Licel"}
    assert resolved["classes"] == {"dev.library", "app.cicd"}


# --- the general case -----------------------------------------------------------------

@pytest.mark.parametrize("question,wrong_class", [
    ("a relay of phishing mail through the gateway", "ot.protection_relay"),
    ("switch off the service before patching", "network.switch"),
    ("the attacker switches to a second C2", "network.switch"),
    ("context switching between consoles", "network.switch"),
])
def test_known_ungated_class_aliases_are_recorded_as_still_failing(question, wrong_class):
    """These are NOT fixed, and the test says so rather than pretending otherwise.

    `relay` is a mail relay before it is a protective relay, and `switch` is a verb. The gate
    that landed in 0.43.0 covers `ran` and `ad`, which this test held until then and which are
    now asserted the other way below. `relay` and `switch` were left: `network.switch` has no
    route but variants of its own word, so gating it needs its context words chosen first, and
    `relay` was not in the measured set. When either is gated these fail, and the fix is to
    invert them, not to delete them.
    """
    assert wrong_class in Q.resolve(question, ALIASES)["classes"], (
        "{} no longer resolves {} -- if the class-alias gate landed, invert this test"
        .format(question, wrong_class))


GATES = RAW["ambiguous_class_aliases"]


@pytest.mark.parametrize("question,wrong_class", [
    ("the script ran overnight and logged nothing", "telecom.ran"),
    ("a malicious ad served through the network", "identity.directory"),
    ("which event IDs should I watch", "network.firewall"),
    ("block these IPs at the perimeter", "network.firewall"),
    ("limit the blast radius of a compromise", "identity.directory"),
    ("Kubernetes ingress controller exposed", "ot.plc"),
    ("baseboard management controller firmware", "ot.plc"),
    ("Aviatrix Controller", "ot.plc"),
    ("a domain controller was compromised", "ot.plc"),
    ("directory traversal on our web server", "identity.directory"),
    ("Spring Boot actuator heapdump exposed", "ot.field_device"),
    ("EWS mailbox access by a stolen token", "ot.engineering_workstation"),
    ("an exposed API endpoint returning secrets", "endpoint.os"),
    ("Ivanti Endpoint Manager Mobile", "endpoint.os"),
    ("deploy the content pack to our XSIAM tenant", "cloud.identity"),
    ("our detection library is thin", "dev.library"),
    ("log ingestion pipeline dropped events", "app.cicd"),
    ("SOAR workflow approval step", "app.cicd"),
    ("package delivery phishing lure", "dev.library"),
    ("red teams and SOC teams", "app.collaboration"),
    ("Linux PAM module backdoor", "security.pam"),
    ("UDM fields in Google SecOps", "telecom.subscriber"),
    ("routing rules in the mailbox", "network.router"),
    ("a sim of the incident for the tabletop", "telecom.subscriber"),
])
def test_ordinary_words_do_not_set_the_plane(question, wrong_class):
    """Each resolved the wrong class until 0.43.0, and a class decides the plane the whole
    consultation is about. 'Ivanti Endpoint Manager Mobile' reached endpoint.os and made
    ENDPOINT its largest locus, against the standing decision that the mobile management
    plane is MANAGEMENT."""
    assert wrong_class not in Q.resolve(question, ALIASES)["classes"], question


@pytest.mark.parametrize("question,right_class", [
    ("our IDS", "network.firewall"),
    ("Suricata IPS", "network.firewall"),
    ("the RADIUS server", "identity.directory"),
    ("our AD forest", "identity.directory"),
    ("RAN base station intrusion", "telecom.ran"),
    ("SIM swap fraud", "telecom.subscriber"),
    ("a poisoned CI job", "app.cicd"),
    ("an S7 controller on the plant network", "ot.plc"),
    ("PLC controller logic changed", "ot.plc"),
    ("an actuator on the plant network", "ot.field_device"),
    ("unmanaged endpoints on the guest network", "endpoint.os"),
    ("the LDAP directory", "identity.directory"),
    ("our CI/CD pipeline", "app.cicd"),
    ("a malicious npm package", "dev.library"),
])
def test_the_gated_word_still_resolves_where_it_means_the_class(question, right_class):
    """The gate is a refusal in context, not a deletion: in capitals, or beside the words
    that make it the class, the alias still works. `upper` depends on the caller's casing, so
    a consumer that lower-cases its questions loses these routes."""
    assert right_class in Q.resolve(question, ALIASES)["classes"], question


def test_the_mobile_management_plane_does_not_reach_endpoint():
    """The standing decision: app.mdm is MANAGEMENT, and handsets are out of scope."""
    for question in ("Ivanti Endpoint Manager Mobile", "Ivanti EPMM", "our MDM console"):
        assert "endpoint.os" not in Q.resolve(question, ALIASES)["classes"], question


def test_every_gated_class_alias_is_a_real_class_alias_with_a_reason_and_a_known_mode():
    for alias, rule in GATES.items():
        assert Q.normalise(alias) in ALIASES["class_aliases"], alias
        assert rule.get("reason", "").strip(), alias
        assert rule.get("mode") in ("upper", "refuse_near", "require_near"), alias
        if rule["mode"] != "upper":
            assert rule.get("near"), "{} needs its context words".format(alias)


@pytest.mark.parametrize("alias", ["ews", "directory", "teams"])
def test_the_class_aliases_that_collide_with_a_name_stay_removed(alias):
    """EWS is Exchange Web Services as often as an engineering workstation, bare "directory"
    is directory traversal, and "teams" is red teams; each class keeps other routes."""
    assert alias not in CLASSES, alias


def test_a_refused_class_word_is_reported():
    gated = Q.resolve("which event IDs should I watch", ALIASES)["gated"]
    assert any(g.startswith("ids (class network.firewall") for g in gated), gated


@pytest.mark.parametrize("question,wrong_class", [
    ("CIS benchmark hardening", "app.cicd"),
    ("malicious ads served to users", "identity.directory"),
])
def test_a_plural_that_is_another_word_does_not_resolve(question, wrong_class):
    """"ci" took an optional plural and matched CIS; "ad" matched "ads"."""
    assert wrong_class not in Q.resolve(question, ALIASES)["classes"], question


@pytest.mark.parametrize("question,right_class", [
    ("our HMIs", "ot.hmi"), ("the PLCs", "ot.plc"), ("guest VMs", "server.hypervisor"),
])
def test_other_plurals_still_resolve(question, right_class):
    assert right_class in Q.resolve(question, ALIASES)["classes"], question


@pytest.mark.parametrize("question,right_class", [
    ("ADs", "identity.directory"),
    ("the ADs in our forest", "identity.directory"),
    ("cloned SIMs", "telecom.subscriber"),
    ("both RANs", "telecom.ran"),
])
def test_an_acronym_plural_in_capitals_resolves(question, right_class):
    """RES-09 kept "ADs" in capitals as Active Directory, and singular_only took the plural
    away from it along with "ads". `acronym_plural` gives it back, capitals and a lower-case s
    only: "SIMs" and "RANs" had never resolved either."""
    assert right_class in Q.resolve(question, ALIASES)["classes"], question


@pytest.mark.parametrize("question,wrong_class", [
    ("malicious ads served to users", "identity.directory"),
    ("hidden in an NTFS ADS", "identity.directory"),
    ("CMDB CIs", "app.cicd"),
    ("which event IDs should I watch", "network.firewall"),
])
def test_the_plural_that_is_another_word_stays_refused(question, wrong_class):
    """"ads" is an advertisement, ADS an alternate data stream, and "CIs" configuration
    items; `ci` does not take the acronym plural."""
    assert wrong_class not in Q.resolve(question, ALIASES)["classes"], question


def test_the_other_word_is_not_reported_as_a_refusal():
    """"ads" is the word singular_only names, not an acronym written in lower case, so the
    GATED line does not report it."""
    assert not Q.resolve("malicious ads served to users", ALIASES)["gated"]


def test_capitals_are_read_at_the_word_that_matched():
    """The upper gate searched the whole question for the capitals, so one "RAN" admitted
    every lower-case "ran" as well. It now reads the span that matched."""
    raw = "RAN outage after the engineer ran a script"
    tokens = Q.normalise(raw).split()
    spans = Q.raw_token_spans(raw)
    rule = RAW["ambiguous_class_aliases"]["ran"]
    assert Q.class_gate(raw, tokens, (0, 1), "ran", rule, True, spans) is None
    assert Q.class_gate(raw, tokens, (5, 6), "ran", rule, True, spans)
    assert len(spans) == len(tokens)


# --- routes added in 0.43.0 -----------------------------------------------------------

@pytest.mark.parametrize("question", ["Fortinet SD-WAN", "our SD WAN edges", "Palo Alto Prisma SD-WAN"])
def test_sd_wan_reaches_the_wan_edge_class(question):
    """Only "sdwan" was a class alias, so the hyphenated spelling everyone writes reached
    network.router through Cisco's product alias and never the WAN-edge class."""
    assert "network.wan_edge" in Q.resolve(question, ALIASES)["classes"], question


@pytest.mark.parametrize("question", [
    "Siemens S7", "SIMATIC S7 controllers", "an S7 controller on the plant network", "S7 PLCs"])
def test_the_s7_family_reaches_the_plc_class(question):
    """"s7 200" and "simatic s7-200" were aliases and "s7" was not, so the commonest way of
    naming the family resolved the vendor alone and left the control plane absent. The
    last two reach the class through "controller" and "plc", not through an s7 alias."""
    assert "ot.plc" in Q.resolve(question, ALIASES)["classes"], question


@pytest.mark.parametrize("question", ["Samsung Galaxy S7", "a Galaxy S7 edge handset"])
def test_a_handset_model_named_s7_is_not_a_controller(question):
    """A bare "s7" class alias, added and reviewed in 0.43.0, sent "Samsung Galaxy S7" to
    ot.plc: a handset question, which this bundle keeps out of scope, answered from the
    industrial control plane. Class aliases have no gate, so the alias carries its vendor or
    family word instead, "siemens s7" and "simatic s7"."""
    assert "ot.plc" not in Q.resolve(question, ALIASES)["classes"], question
    assert "s7" not in CLASSES, "a bare s7 class alias fires on every product named S7"


def test_ss7_is_still_signalling_and_not_a_controller():
    classes = Q.resolve("SS7 signalling abuse", ALIASES)["classes"]
    assert "telecom.signalling" in classes
    assert "ot.plc" not in classes
