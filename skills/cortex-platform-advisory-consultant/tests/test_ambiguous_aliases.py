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
vendor and not otherwise, and nothing may claim `identity` on a bare token match.
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

ALIASES = Q.normalise_alias_keys(
    json.load(open(os.path.join(ROOT, "corpus", "schema", "aliases.json"), encoding="utf-8")))
AMBIGUOUS = json.load(
    open(os.path.join(ROOT, "corpus", "schema", "aliases.json"), encoding="utf-8")
)["ambiguous_aliases"]


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
    # dev.library, so identity is legitimately non-zero -- it is reached by class. What
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

    It derives ENDPOINT, and the handset is the plane this corpus declines to advise on.
    ENDPOINT coming back absent is the honest answer, so it must keep coming back absent.
    """
    out = run("Guardsquare", "--limit", "3").stdout
    absent = [l for l in out.splitlines() if l.startswith("LOCUS_ABSENT:")][0]
    assert "ENDPOINT" in absent, absent
