# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""An ordinary English word in a question must not resolve as a product name.

The defect, reported by a consuming content-pack session:
"Guardsquare mobile application runtime protection ... protected Android and iOS apps"
resolved `runtime` to Android Runtime and `ios` to Cisco IOS, reported
`RESOLUTION: product - the corpus holds records naming this technology`, and returned a
GeoServer Java deserialisation record at rank 1 of 860 matched findings. Every part of
that is wrong and none of it is visible to a consumer gating on the header.

tests/test_mechanism_lookup.py already pins one string, "mobile app hardening". These
tests hold the general case: the gate is corroboration, so the word resolves next to its
vendor and not otherwise, and nothing may claim a subject tier on a bare token match.
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
AMBIGUOUS = RAW["ambiguous_aliases"]
REVIEWED_KEEP = RAW["_ambiguous_reviewed_keep"]
AMBIGUOUS_VENDORS = RAW["ambiguous_vendor_aliases"]
RECORDS, PATTERNS = Q.load_corpus(os.path.join(ROOT, "corpus"))
BY_ID = {r["id"]: r for r in RECORDS}


def run(*args):
    return subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "consult.py")]
                          + list(args) + ["--today", "2026-08-19"],
                          capture_output=True, text=True, cwd=ROOT)


def test_the_reported_query_no_longer_claims_to_know_the_technology():
    """The verbatim string from the defect report. 860 matched, GeoServer at rank 1."""
    out = run("Guardsquare mobile application runtime protection, "
              "protected Android and iOS apps", "--limit", "5").stdout
    assert "products=-" in out, "no product may resolve from these words"
    assert "RESOLUTION: product" not in out, "must not report the tight case"
    # The class route added in 0.29.0 means Guardsquare resolves to app.cicd and
    # dev.library, so MATCH_TIERS class is legitimately non-zero. What
    # must never come back is a claim that a vendor or product the corpus knows was named.
    assert "RESOLUTION: CLASS-LEVEL (inferred)" in out, out[:400]
    assert "CLASS_LEVEL_WARNING:" in out
    assert "Cisco" not in out.split("RESOLVED_TO:")[1].split("\n")[0]


@pytest.mark.parametrize("question", [
    "runtime application self-protection",
    "a client certificate on the edge of the network",
    "our core platform runs behind a firewall",
    "the salt used to hash the password",
    "which tools does the framework ship",
    "a beacon on a desktop, seen by the defender",
])
def test_generic_words_resolve_to_no_product(question):
    """A sentence of ordinary words is not a product question, however it is phrased."""
    resolved = Q.resolve(question, ALIASES)
    assert not resolved["products"], (question, resolved["products"])


@pytest.mark.parametrize("alias", sorted(AMBIGUOUS))
def test_every_flagged_alias_still_resolves_beside_its_vendor(alias):
    """The gate is corroboration, not deletion. Naming the vendor must still work."""
    entry = ALIASES["product_aliases"][alias]
    resolved = Q.resolve("{} {}".format(entry["vendor"], alias), ALIASES)
    assert entry["product"] in resolved["products"], (alias, resolved["products"])


@pytest.mark.parametrize("alias", sorted(AMBIGUOUS))
def test_every_flagged_alias_is_inert_on_its_own(alias):
    """Bare, with no vendor anywhere, the word must not name a product."""
    resolved = Q.resolve("I have a {}".format(alias), ALIASES)
    entry = ALIASES["product_aliases"][alias]
    assert entry["product"] not in resolved["products"], (alias, resolved["products"])


@pytest.mark.parametrize("question,vendor,absent", [
    ("Apple iOS and iPadOS", "Apple", "Cisco"),
    ("Cisco Secure Firewall Management Center", "Cisco", "Sophos"),
    ("Cisco RV Series Routers", "Cisco", "D-Link"),
    ("Microsoft .NET Framework", "Microsoft", "Android"),
    ("Android Android Kernel", "Android", "Linux"),
])
def test_a_real_product_question_gains_no_second_vendor(question, vendor, absent):
    """The same defect, on questions that are not about mobile at all.

    Measured over the alias table: 90 vendor-qualified product questions were resolving a
    spurious second vendor off a single shared word, and none lost its own subject when
    the gate was added.
    """
    resolved = Q.resolve(question, ALIASES)
    assert vendor in resolved["vendors"], (question, resolved["vendors"])
    assert absent not in resolved["vendors"], (question, resolved["vendors"])


def test_every_flagged_alias_is_a_real_product_alias_with_a_reason():
    """A flag on a key that does not exist protects nothing and reads as though it does."""
    for alias in AMBIGUOUS:
        assert alias in ALIASES["product_aliases"], alias
        assert AMBIGUOUS[alias].strip(), "{} carries no reason".format(alias)


def test_the_gate_fails_closed_on_a_multi_token_alias():
    """The trap the first version fell into: no positions found, so it admitted everything.

    Indexing by single-token equality found nothing for "device management" and returned
    True, which is a gate that reads as though it protects a two-word alias and does not.
    """
    assert not Q.corroborated("mobile device management", "device management", "Yealink")
    assert Q.corroborated("yealink device management", "device management", "Yealink")


def test_a_generic_multi_word_alias_does_not_name_a_vendor():
    """"web server" pointed at a backup product, and "mobile device management" at a phone."""
    for question, absent in (("mobile device management", "Yealink"),
                             ("our web server is public", "Commvault"),
                             ("the advisory names multiple products", "Apple")):
        resolved = Q.resolve(question, ALIASES)
        assert absent not in resolved["vendors"], (question, resolved["vendors"])


# --- the technology the whole change started from -------------------------------------

RASP_VENDORS = ["Guardsquare", "DexGuard", "iXGuard", "ThreatCast", "AppSweep", "Appdome",
                "Promon", "Build38", "Approov", "NowSecure", "Verimatrix", "Arxan",
                "Digital.ai", "Pradeo", "Talsec", "Licel", "DexProtector"]


@pytest.mark.parametrize("vendor", RASP_VENDORS)
def test_an_app_shielding_vendor_gets_a_labelled_class_answer(vendor):
    """Not exit 1, and not a GeoServer record claiming to be about mobile app protection.

    This corpus refuses these as sources and that refusal stands. What they
    resolve to here is the class a build-integrated SDK behaves as, which is a different
    claim and has to be labelled as one.
    """
    out = run(vendor, "--limit", "3").stdout
    assert "RESOLUTION: CLASS-LEVEL (inferred)" in out, out[:400]
    assert "CLASS_LEVEL_WARNING:" in out
    assert "classes=app.cicd, dev.library" in out


def test_the_class_route_does_not_reach_the_excluded_plane():
    """security.edr fills two more loci and is deliberately not in the alias.

    It derives ENDPOINT, and the handset is the plane this corpus declines to advise on. This
    held ENDPOINT absent as its proxy until a supply surface stopped placing every block of its
    record: a poisoned-update record listing dev.library now reaches ENDPOINT through its
    Windows host's resolver bypass, a desktop block the class route is right to return. What
    must hold is the route itself: no class but the two build classes resolves, and every
    finding reached by class carries one of them.
    """
    out = run("Guardsquare", "--limit", "500", "--no-locus-spread").stdout
    resolved = [l for l in out.splitlines() if l.startswith("RESOLVED_TO:")][0]
    assert "classes=app.cicd, dev.library |" in resolved, resolved
    classes = [l.split(": ", 1)[1].split(", ") for l in out.splitlines()
               if l.startswith("PRODUCT_CLASS: ")]
    assert classes, "no finding reached"
    for listed in classes:
        assert {"app.cicd", "dev.library"} & set(listed), listed


# --- the longer names that keep a route open ------------------------------------------

@pytest.mark.parametrize("question,vendor,product", [
    ("quantum security gateway", "Check Point", "Quantum Security Gateway"),
    ("omnissa horizon", "Broadcom", "VMware Horizon"),
    ("cursor ide", "Anysphere", "Cursor"),
    ("cursor editor", "Anysphere", "Cursor"),
    ("ivanti epm", "Ivanti", "Endpoint Manager (EPM)"),
    ("ivanti endpoint manager mobile", "Ivanti", "Endpoint Manager Mobile"),
    ("exchange online", "Microsoft", "Microsoft 365"),
])
def test_a_longer_name_resolves_its_product_on_its_own(question, vendor, product):
    """quantum, horizon, cursor, epm, endpoint manager and exchange are ordinary words or
    names two vendors share, and are due to be gated. Each of these fuller names is how a
    caller writes the product without its vendor, so each needs its own entry before the
    bare word stops resolving, or the gate costs a route instead of closing a false one."""
    resolved = Q.resolve(question, ALIASES)
    assert product in resolved["products"], (question, resolved["products"])
    assert vendor in resolved["vendors"], (question, resolved["vendors"])


@pytest.mark.parametrize("question", ["Elastic Stack", "Elastic NV"])
def test_the_elastic_vendor_has_a_name_that_is_not_an_ordinary_word(question):
    """"elastic" is Elastic IP and elastic scaling as often as it is the vendor."""
    assert "Elastic" in Q.resolve(question, ALIASES)["vendors"], question


# --- 0.43.0: the ordinary-word product aliases the 0.29.0 list left out ------------------

@pytest.mark.parametrize("question", [
    "Zorblax Quantum Edge Gateway 9000",
    "key exchange appliance",
    "post-quantum cryptography migration",
    "OAuth token exchange abuse",
    "a crypto exchange was drained",
    "x-ray of our estate over a 90 day horizon",
    "cursor-based pagination in the collector",
    "attackers amplify DNS traffic",
    "our auditor asked for SIEM coverage",
    "how do I counteract credential theft",
    "beaconing at dawn every day",
    "Triton malware on our safety instrumented system",
    "tracking pixel in a phishing email",
    "a superset of the Sigma rules",
    "airflow sensors in the data centre",
    "car ignition immobiliser relay attack",
    "end of sale EOS hardware",
    "an EPM rollout",
])
def test_the_2026_09_25_ordinary_words_name_no_product(question):
    """Each resolved a product until 0.43.0: Check Point for "quantum", Exchange Server for
    "key exchange", VMware Horizon and Ray for "x-ray ... horizon", NVIDIA Triton for the
    safety-system malware, Android's Pixel for a tracking pixel."""
    resolved = Q.resolve(question, ALIASES)
    assert not resolved["products"], (question, resolved["products"])
    assert not resolved["vendors"], (question, resolved["vendors"])


def _dictionary():
    path = "/usr/share/dict/words"
    if not os.path.exists(path):
        pytest.skip("no system word list to check the alias table against")
    with open(path, encoding="utf-8", errors="ignore") as handle:
        return {w.strip() for w in handle if w.strip() and w.strip() == w.strip().lower()}


def _is_word(token, words):
    if token in words:
        return True
    return any(token.endswith(suf) and token[:-len(suf)] in words
               for suf in ("s", "es", "ed", "ing", "er"))


def test_every_dictionary_word_product_alias_is_decided():
    """A single-word product alias that is also an English word must be gated or kept on
    purpose, with the reason written down. 38 were neither when this was measured, and
    "quantum" and "exchange" were among them; a new one now fails here until somebody
    decides it rather than being inherited as a product name."""
    words = _dictionary()
    gated = {Q.normalise(k) for k in AMBIGUOUS}
    kept = {Q.normalise(k) for k in REVIEWED_KEEP}
    undecided = sorted(
        alias for alias in ALIASES["product_aliases"]
        if len(alias.split()) == 1 and _is_word(alias, words)
        and alias not in gated and alias not in kept)
    assert not undecided, "dictionary-word product aliases neither gated nor reviewed: {}".format(
        undecided)


def test_every_reviewed_keep_is_a_real_ungated_alias_with_a_reason():
    for alias, reason in REVIEWED_KEEP.items():
        assert Q.normalise(alias) in ALIASES["product_aliases"], alias
        assert alias not in AMBIGUOUS, "{} is both gated and kept".format(alias)
        assert reason.strip(), alias


def test_no_gated_alias_names_a_sentinel_vendor():
    """A sentinel has no name to sit beside, so a gated alias naming one could never resolve."""
    for alias in AMBIGUOUS:
        assert ALIASES["product_aliases"][Q.normalise(alias)]["vendor"] not in Q.SENTINEL_VENDORS, \
            alias


@pytest.mark.parametrize("question,product", [
    ("maintenance windows for patching", "Windows"),
    ("the 2026 threat outlook", "Outlook"),
])
def test_known_ungated_product_aliases_still_fail(question, product):
    """Kept on purpose, and pinned as still failing, so a gate landing on either is seen.

    Bare "Windows" and "Outlook" are how callers name the platform and the client, and
    gating them would lose the commonest way of asking. _ambiguous_reviewed_keep records the
    decision; when it changes, invert this test."""
    assert product in Q.resolve(question, ALIASES)["products"], question


# --- 0.43.0: what counts as a name for the vendor ------------------------------------------

def test_the_whole_vendor_name_corroborates_and_a_fragment_of_it_does_not():
    """Any single token of the vendor's name used to count, so "av" named Justice AV Solutions
    and "link" named D-Link."""
    assert not Q.corroborated("an av viewer on the desktop", "viewer", "Justice AV Solutions")
    assert Q.corroborated("justice av solutions viewer", "viewer", "Justice AV Solutions")
    assert not Q.corroborated("check the quantum readiness of tls", "quantum", "Check Point")
    assert Q.corroborated("check point quantum", "quantum", "Check Point")


@pytest.mark.parametrize("question,absent", [
    ("an AV viewer on the desktop", "Justice AV Solutions"),
    ("wan link routers", "D-Link"),
    ("check the quantum readiness of tls", "Check Point"),
    ("point to point quantum key distribution link", "Check Point"),
])
def test_a_fragment_of_a_vendor_name_names_no_vendor(question, absent):
    assert absent not in Q.resolve(question, ALIASES)["vendors"], question


def test_a_vendor_alias_corroborates():
    """"ms" is a registered Microsoft alias and never counted, so "MS Word" lost Word."""
    resolved = Q.resolve("MS Word macro", ALIASES)
    assert "Word" in resolved["products"], resolved["products"]
    assert "Microsoft" in resolved["vendors"]


@pytest.mark.parametrize("question,product", [
    ("Ivanti EPMM and Sentry", "Sentry"),
    ("Cisco ASA and IOS", "IOS"),
])
def test_an_unambiguous_sibling_anchors(question, product):
    """"Sentry" sat three words from its vendor and vanished silently. An unambiguous product
    of the same vendor within two words now anchors it; a vendor alias does not, which is
    what keeps the Guardsquare question above from meaning Android Runtime."""
    assert product in Q.resolve(question, ALIASES)["products"], question


@pytest.mark.parametrize("question,product,klass", [
    ("Cisco ASA VPN users on iOS and Android phones", "IOS", "network.router"),
    ("ransomware moved from edge devices to domain controllers", "Edge", "endpoint.browser"),
    ("Windows hosts behind an edge firewall", "Edge", "endpoint.browser"),
    ("Windows servers with Defender disabled at the network edge", "Edge", "endpoint.browser"),
    ("Windows servers with Defender disabled at the network edge", "Defender", None),
    ("Outlook phishing with a word document lure", "Word", None),
    ("Azure AD sign-ins from a new publisher app", "Publisher", None),
])
def test_a_sibling_further_off_does_not_anchor(question, product, klass):
    """The first anchor reached across the whole question, and Microsoft has over a hundred
    unambiguous aliases to anchor its eight gated ones: "Cisco ASA VPN users on iOS and
    Android phones" resolved Cisco IOS, the 0.29.0 defect again, and "edge devices" beside
    "domain controllers" resolved Microsoft Edge and the browser class, which sets a plane.
    The anchor now has the two-word window a vendor name has, and the refusal is reported."""
    resolved = Q.resolve(question, ALIASES)
    assert product not in resolved["products"], (question, resolved["resolved_by"])
    if klass:
        assert klass not in resolved["classes"], (question, resolved["classes"])
    word = Q.normalise(product)
    if not any(b.startswith(word) for b in resolved["resolved_by"]):
        # Reported, unless another alias accounted for the word ("edge devices" is a class).
        assert any(g.startswith(word + " (product ") for g in resolved["gated"]), \
            resolved["gated"]


@pytest.mark.parametrize("question,product", [
    ("SharePoint project sites", "Project"),
    ("Active Directory and edge VPN appliances", "Edge"),
])
def test_known_false_anchors_inside_the_window_are_pinned(question, product):
    """KNOWN FALSE POSITIVES, kept. Inside two words a sibling anchors as a vendor name
    corroborates, and the words cannot tell "SharePoint project sites" from "Ivanti EPMM and
    Sentry". When a rule separates them this test fails, and the fix is to invert it."""
    assert product in Q.resolve(question, ALIASES)["products"], question


# --- 0.43.0: vendor aliases that are ordinary words ---------------------------------------

@pytest.mark.parametrize("question,vendor", [
    ("beacon interval jitter of 500 ms", "Microsoft"),
    ("PAN data exfiltration from the cardholder environment", "Palo Alto Networks"),
    ("a pulse of outbound DNS", "Ivanti"),
    ("it would be nice to detect kerberoasting", "Nice"),
    ("attack in progress on the storage array", "Array Networks"),
    ("attack in progress on the storage array", "Progress"),
    ("a daemon listening on a high port", "Daemon"),
    ("Microsoft Sentinel analytics rules", "Thales"),
    ("backdoored AMI in the AWS account", "AMI"),
    ("ARM template deployment in Azure", "Arm"),
    ("elastic IP reassigned in AWS", "Elastic"),
    ("meta tags injected into the page", "Meta"),
    ("guard rails for our LLM agents", "Rails"),
    ("notepad exe spawning powershell", "Notepad++"),
    ("a checkbox in the admin console", "Checkbox"),
    ("hash algo downgrade", "ALGO"),
    ("Akira ransomware on ESXi hosts", "Akira"),
])
def test_an_ordinary_word_names_no_vendor(question, vendor):
    assert vendor not in Q.resolve(question, ALIASES)["vendors"], question


@pytest.mark.parametrize("question,vendor", [
    ("Progress MOVEit Transfer", "Progress"),
    ("PAN Panorama", "Palo Alto Networks"),
    ("Pulse Connect Secure", "Ivanti"),
    ("Elastic Stack", "Elastic"),
    ("Array Networks AG", "Array Networks"),
    ("Progress Software", "Progress"),
])
def test_the_vendor_still_resolves_with_its_product_or_full_name(question, vendor):
    assert vendor in Q.resolve(question, ALIASES)["vendors"], question


def test_every_flagged_vendor_alias_is_a_real_vendor_alias_with_a_reason():
    for alias, reason in AMBIGUOUS_VENDORS.items():
        assert Q.normalise(alias) in ALIASES["vendor_aliases"], alias
        assert reason.strip(), alias
    assert "akira" not in RAW["vendor_aliases"], "a ransomware operation is not a vendor"


def test_milliseconds_are_not_a_product_answer():
    out = run("beacon interval jitter of 500 ms", "--limit", "3").stdout
    assert "RESOLUTION: product" not in out
    assert "vendors=-" in out.split("RESOLVED_TO:")[1].split("\n")[0]


# --- 0.43.0: a longer alias claims its words ----------------------------------------------

@pytest.mark.parametrize("question,absent", [
    ("Palo Alto Prisma SD-WAN", "Cisco"),
    ("Citrix SD-WAN and NetScaler", "Cisco"),
    ("Barracuda email security gateway", "Check Point"),
    ("Barracuda email security gateway", "Libraesva"),
    ("Motex LANSCOPE Endpoint Manager", "Ivanti"),
    ("Microsoft Endpoint Manager", "Ivanti"),
    ("Zyxel multiple network attached storage devices", "QNAP"),
    ("JoomShaper SP Page Builder", "Joomlack"),
    ("Veeam Backup and Replication", "NAKIVO"),
    ("Hewlett Packard Enterprise", "Hewlett Packard (HP)"),
])
def test_a_longer_name_claims_its_words(question, absent):
    """A shorter alias inside a longer admitted one resolved as well, so "Fortinet SD-WAN"
    named Cisco and "Barracuda email security gateway" named Check Point and Libraesva."""
    assert absent not in Q.resolve(question, ALIASES)["vendors"], question


def test_a_gate_does_not_take_a_vendor_s_own_phrasing_of_its_product():
    """"Barracuda email security gateway" reached Barracuda's product only through
    Libraesva's alias. With that alias gated it resolved the vendor and the class alone, so the
    natural phrasing needs Barracuda's own alias, as Check Point's needed quantum security
    gateway."""
    resolved = Q.resolve("Barracuda email security gateway", ALIASES)
    assert resolved["products"] == {"Email Security Gateway (ESG) Appliance"}, resolved["products"]
    assert resolved["vendors"] == {"Barracuda Networks"}, resolved["vendors"]


@pytest.mark.parametrize("question,absent_product", [
    ("Ivanti Endpoint Manager Mobile", "Endpoint Manager (EPM)"),
    ("Azure Active Directory", "Active Directory"),
    ("Azure Active Directory", "Microsoft Azure"),
])
def test_a_longer_product_line_of_the_same_vendor_is_not_its_shorter_one(question, absent_product):
    """On-premises Active Directory sits on another plane from Entra ID, and EPM is not EPMM."""
    assert absent_product not in Q.resolve(question, ALIASES)["products"], question


@pytest.mark.parametrize("question,products", [
    ("Apex One and OfficeScan", {"Apex One", "OfficeScan"}),
    ("Citrix NetScaler", {"Citrix NetScaler",
                          "Citrix Application Delivery Controller and NetScaler Gateway"}),
    ("Veeam Backup and Replication", {"Backup & Replication"}),
])
def test_a_composite_or_the_same_product_keeps_its_components(question, products):
    assert products <= Q.resolve(question, ALIASES)["products"], question


def family_of(vendor):
    """Every name in the vendor's family and spellings, parent, lines and siblings alike.

    This is the set a RESOLUTION may land in, which is wider than what a record MATCHES
    through: "VMware" resolves Broadcom, while a Symantec question never matches VMware."""
    spellings, members, parent = Q.vendor_relations(RAW)
    head = parent.get(vendor, vendor)
    group = {head, vendor} | members.get(head, set())
    return set().union(*[spellings.get(name) or {name} for name in group])


def test_every_alias_asked_beside_its_vendor_keeps_its_product_and_no_other_vendor():
    """The whole table asked about itself, which is what would have caught the nesting defect.

    Every product alias whose vendor is named, asked as "<vendor> <alias>", resolves its own
    product and no vendor outside that vendor's family. Before 0.43.0, 75 of these questions
    resolved a second vendor, 39 of them through a shorter alias nested in the longer one."""
    lost, foreign = [], []
    for alias, entry in ALIASES["product_aliases"].items():
        if entry["vendor"] in Q.SENTINEL_VENDORS:
            continue
        question = "{} {}".format(entry["vendor"], alias)
        resolved = Q.resolve(question, ALIASES)
        if entry["product"] not in resolved["products"]:
            lost.append(question)
        kin = family_of(entry["vendor"])
        if resolved["vendors"] - kin:
            foreign.append((question, sorted(resolved["vendors"] - kin)))
    assert not lost, lost[:20]
    assert not foreign, foreign[:20]


# --- 0.43.0: saying what was refused and what produced the resolution ----------------------

def test_a_refused_alias_is_named_and_a_resolved_one_is_traced():
    out = run("key exchange appliance", "--limit", "3").stdout
    gated = [l for l in out.splitlines() if l.startswith("GATED:")]
    assert gated and "exchange (product Microsoft / Exchange Server" in gated[0], out[:600]
    clean = run("Cisco IOS", "--limit", "3").stdout
    assert "GATED:" not in clean
    traced = [l for l in clean.splitlines() if l.startswith("RESOLVED_BY:")][0]
    assert "ios -> product Cisco / IOS (beside cisco)" in traced, traced


def test_a_word_another_alias_accounted_for_is_not_reported_as_refused():
    """"firewall" is refused as Sophos's product and resolved as a class; saying it was not
    admitted on every firewall question would bury the refusals that matter."""
    assert not Q.resolve("Check Point firewall", ALIASES)["gated"]


def test_query_json_carries_the_resolution():
    done = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "query.py"),
                           "Zorblax Quantum Edge Gateway 9000", "--json"],
                          capture_output=True, text=True, cwd=ROOT)
    resolved = json.loads(done.stdout)["resolved"]
    assert resolved["products"] == [] and resolved["vendors"] == []
    assert any(g.startswith("quantum (product Check Point") for g in resolved["gated"])
    assert set(resolved) == {"vendors", "products", "classes", "sectors", "terms",
                             "resolved_by", "gated"}


# --- 0.43.0: a plural that is another word, and a renamed vendor ---------------------------

def test_a_gated_vendor_word_resolves_beside_its_product():
    """"quest" is gated as the ordinary noun, and KACE had no alias of its own, so "Quest
    KACE" resolved nothing at all."""
    resolved = Q.resolve("Quest KACE", ALIASES)
    assert "Quest" in resolved["vendors"], resolved["gated"]
    assert "KACE Systems Management Appliance (SMA)" in resolved["products"]
    assert not Q.resolve("a quest for better coverage", ALIASES)["vendors"]


def test_a_plural_that_is_another_acronym_names_no_vendor():
    """"hf" is Hugging Face and "HFS" is Rejetto's file server."""
    assert "Hugging Face" not in Q.resolve("Rejetto HFS", ALIASES)["vendors"]
    assert "Hugging Face" in Q.resolve("HF model hub token", ALIASES)["vendors"]


@pytest.mark.parametrize("record_id,question", [
    ("exp-kev-vmware-esxi", "VMware ESXi"),
    ("exp-kev-vmware-esxi", "Broadcom ESXi"),
    ("exp-kev-symantec-symantec-messaging-gateway", "Broadcom"),
    ("exp-kev-telerik-user-interface-ui-for-asp-net-ajax", "Progress Software"),
    ("exp-kev-qnap-systems-helpdesk", "QNAP"),
    ("exp-kev-hewlett-packard-hp-openview-network-node-manager", "Hewlett Packard Enterprise"),
])
def test_a_renamed_or_acquired_vendor_is_still_its_vendor(record_id, question):
    """18 exposures are filed under "VMware" while "VMware" resolves to Broadcom, so they were
    reached only on free text. A vendor's alias keys, its other spellings and the lines it
    acquired now match its records."""
    reasons = Q.score(BY_ID[record_id], Q.resolve(question, ALIASES), PATTERNS)[1]
    assert any(r.startswith("vendor ") for r in reasons), (record_id, question, reasons)


@pytest.mark.parametrize("record_id,question", [
    ("obs-broadcom-esxi-hypervisor-encryption", "Symantec"),
    ("obs-broadcom-esxi-hypervisor-encryption", "Symantec Endpoint Protection"),
    ("obs-generic-helpdesk-impersonation-to-ransomware-deployment", "Symantec"),
    ("exp-kev-vmware-esxi", "Symantec"),
    ("exp-kev-vmware-esxi", "VMware Tanzu"),
    ("exp-kev-symantec-symantec-messaging-gateway", "VMware Tanzu"),
    ("exp-kev-broadcom-brocade-fabric-os", "Symantec"),
])
def test_a_member_never_reaches_its_parent_or_a_sibling(record_id, question):
    """The family table was read as a flat set, so sibling acquisitions were each other's
    vendor: bare "Symantec" went from no answer to 41 VMware ESXi findings under RESOLUTION:
    product, reasoned "vendor Broadcom (as Symantec)". A family runs parent to member only."""
    reasons = Q.score(BY_ID[record_id], Q.resolve(question, ALIASES), PATTERNS)[1]
    assert not any(r.startswith("vendor ") for r in reasons), (record_id, question, reasons)


def test_a_record_filed_under_the_parent_is_the_members_where_it_names_it():
    """Broadcom files a Symantec Messaging Gateway record under its own name. For a Symantec
    question it is Symantec's, and a Broadcom record about Brocade is not."""
    resolved = Q.resolve("Symantec", ALIASES)
    record = BY_ID["exp-broadcom-symantec-messaging-gateway-rce"]
    assert "vendor Symantec (filed under Broadcom)" in Q.score(record, resolved, PATTERNS)[1]
    assert Q.exposure_tier(record, resolved) == "vendor"
    assert Q.exposure_tier(BY_ID["exp-kev-broadcom-brocade-fabric-os"], resolved) is None


def test_a_member_question_is_not_answered_from_its_siblings():
    out = run("Symantec", "--limit", "3").stdout
    assert "RESOLUTION: product" not in out, out[:600]
    assert "VMware" not in out, out[:600]



@pytest.mark.parametrize("families,spellings,complaint", [
    ([["Broadcom", "VMware", "Symantec"]], [], "not a map"),
    ({"Broadcom": ["VMware"], "Dell": ["VMware"]}, [], "two parents"),
    ({"Broadcom": ["VMware"], "VMware": ["VMware Tanzu"]}, [], "parent itself"),
    ({"Broadcom": []}, [], "one or more"),
    ({}, [["QNAP"]], "two or more names"),
])
def test_the_validator_refuses_a_family_table_read_both_ways(families, spellings, complaint):
    """The flat list is what made sibling acquisitions each other's vendor, so the validator
    holds the shape as well as the tests: a map from a parent to its lines, one parent each."""
    import validate as V
    table = dict(RAW, vendor_families=families, vendor_spellings=spellings)
    problems = []
    V.check_aliases(table, {}, problems)
    assert any(complaint in p.message for p in problems), [p.message for p in problems]
    clean = []
    V.check_aliases(RAW, {}, clean)
    assert not clean, [p.message for p in clean]
