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

The general gate is filed maintainer-side and deliberately not built here. What this release
does is narrower and is what these tests hold: the two class aliases whose ordinary meaning
is not the class they point at are gone, and the class route they were breaking works.
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
    assert "identity=0" in out, out[:600]


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


# --- the general case, held open ------------------------------------------------------

@pytest.mark.parametrize("question,wrong_class", [
    ("the script ran overnight and logged nothing", "telecom.ran"),
    ("a relay of phishing mail through the gateway", "ot.protection_relay"),
    ("a malicious ad served through the network", "identity.directory"),
    ("switch off the service before patching", "network.switch"),
])
def test_known_ungated_class_aliases_are_recorded_as_still_failing(question, wrong_class):
    """These are NOT fixed, and the test says so rather than pretending otherwise.

    `ran` is the past tense of "run", `relay` is a mail relay before it is a protective
    relay, `ad` is an advertisement before it is a directory, and `switch` is a verb.

    The reason they are kept is NOT that their class is otherwise unreachable, which is what
    this docstring claimed until it was measured on 2026-09-13. Inverting `class_aliases`:
    `identity.directory` keeps 13 other aliases, `telecom.ran` 7 and `ot.protection_relay` 3,
    every one of them unambiguous, and all three classes were confirmed reachable without the
    ambiguous alias. Only `network.switch` has no route but morphological variants of its own
    word. So deleting three of the four would cost no class coverage; keeping them is a
    decision nobody has made, and the gate is the fix on file.

    `ad` and `switch` carried no tripwire at all until this change, so a gate landing would
    have altered them with the suite green -- the exact outcome the tripwire exists to stop.
    When the gate lands these fail, and the fix is to invert them, not to delete them.
    """
    assert wrong_class in Q.resolve(question, ALIASES)["classes"], (
        "{} no longer resolves {} -- if the class-alias gate landed, invert this test"
        .format(question, wrong_class))
