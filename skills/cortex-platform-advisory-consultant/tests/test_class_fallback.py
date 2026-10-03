# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Answering for a product the corpus does not know by name.

73 per cent of a real integration library resolves to zero records here. Until 0.20.0 each
of those produced an empty consultation, which reads as "nothing to worry about" and is
instead a statement about what this corpus has been fed. These tests hold the three
resolution modes apart, and hold the class-level warning in place -- the failure that
matters is not an empty answer but a class-level answer mistaken for product intelligence.
"""
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONSULT = os.path.join(ROOT, "scripts", "consult.py")

UNKNOWN = "Portkey"          # a real product, deliberately absent from the corpus


def run(*args):
    return subprocess.run([sys.executable, CONSULT] + list(args),
                          capture_output=True, text=True, cwd=ROOT)


def test_unknown_product_is_unresolved_not_empty():
    result = run(UNKNOWN)
    out = result.stdout
    # SKILL.md contracts exit 1 for "nothing matched". A richer message must not quietly
    # promote that to success, or a caller branching on the exit code reads it as an answer.
    assert result.returncode == 1, result.returncode
    assert "RESOLUTION: UNRESOLVED" in out
    assert "NOTHING MATCHED, AND THAT IS USUALLY NOT AN ANSWER" in out
    # The whole point: it must argue against the reading it would otherwise invite.
    assert "DO NOT report this as 'no known threats'" in out


def test_declared_class_turns_a_dead_lookup_into_findings():
    out = run(UNKNOWN, "--as", "app.ai_platform", "--limit", "5").stdout
    assert "RESOLUTION: CLASS-LEVEL (declared" in out
    shown = [line for line in out.splitlines() if line.startswith("FINDINGS:")]
    assert shown and " 0 shown of 0 matched" not in shown[0], shown


@pytest.mark.parametrize("argv,expected", [
    ([UNKNOWN, "--as", "app.ai_platform"], "class-level-declared"),
    (["AI gateway"], "class-level-inferred"),
])
def test_class_level_answers_always_carry_the_warning(argv, expected):
    """A class-level answer read as product intelligence is worse than no answer."""
    out = run(*argv).stdout
    assert "CLASS_LEVEL_WARNING:" in out
    assert "not this product" in out


def test_a_product_the_corpus_does_know_is_not_labelled_class_level():
    out = run("Cisco ASA", "--limit", "3").stdout
    assert "RESOLUTION: product" in out
    assert "CLASS_LEVEL_WARNING:" not in out


def test_declared_class_is_validated_against_the_vocabulary():
    """A silently ignored typo would produce an empty answer indistinguishable from a real one."""
    result = run(UNKNOWN, "--as", "app.notreal")
    assert result.returncode == 2
    assert "is not a product_class" in result.stderr
    assert "app.ai_platform" in result.stderr, "should suggest by prefix"


def test_several_classes_compose_rather_than_replace():
    """A gateway is a proxy and a credential store at once; one class under-describes it."""
    one = run(UNKNOWN, "--as", "app.ai_platform", "--limit", "1").stdout
    many = run(UNKNOWN, "--as", "app.ai_platform,network.proxy,security.pam,cloud.saas",
               "--limit", "1").stdout
    def matched(text):
        line = [l for l in text.splitlines() if l.startswith("FINDINGS:")][0]
        return int(line.split(" of ")[1].split()[0])
    assert matched(many) > matched(one), (matched(one), matched(many))


@pytest.mark.parametrize("question", ["Nutanix", "Honeywell"])
def test_a_resolved_name_with_no_record_does_not_blame_the_alias_table(question):
    """The header said nothing matched a vendor under a RESOLVED_TO naming one, and then told
    the caller to add an alias that exists. The exit code and the UNRESOLVED prefix are
    unchanged. Hewlett Packard Enterprise, Red Hat and Trend Micro reached this path too until
    the resolution modes counted exposures; they are EXPOSURES_ONLY now, which
    tests/test_resolution_modes.py holds. These two have no record of any kind."""
    result = run(question)
    out = result.stdout
    assert result.returncode == 1, result.returncode
    assert "RESOLUTION: UNRESOLVED" in out
    assert "nothing in this question matched a vendor" not in out
    assert "add the vendor, product and product class to corpus/schema/aliases.json" not in out
    assert "THE ALIAS EXISTS AND NO OBSERVATION CARRIES IT" in out
    assert "IF THIS IS A TECHNOLOGY THE CORPUS SHOULD KNOW BY NAME" in run(UNKNOWN).stdout


def test_no_findings_under_a_resolved_class_does_not_say_nothing_resolved():
    """"ServiceNow" resolves a vendor and app.itsm and reaches no observation."""
    result = run("ServiceNow")
    assert result.returncode == 1, result.returncode
    assert "NO_FINDINGS: ServiceNow, app.itsm resolved" in result.stdout
    assert "the resolver matched nothing" not in result.stdout


def test_a_vendor_only_question_reaches_its_class():
    """A vendor alias carries no class, so "Fortinet" resolved nothing a class analogue could
    match and DATA, ENDPOINT, SUPPLY and ORGANISATION came back absent. The classes are now
    derived from the vendor's own records, printed, and used for scoring only: the vendor's
    own findings still lead, and RESOLVED_TO still says what the question named."""
    out = run("Fortinet", "--today", "2026-09-25", "--limit", "12").stdout
    derived = [l for l in out.splitlines() if l.startswith("CLASSES_FROM_VENDOR:")][0]
    assert "network.firewall" in derived, derived
    assert "classes=-" in [l for l in out.splitlines() if l.startswith("RESOLVED_TO:")][0]
    first = [l for l in out.splitlines() if l.startswith("TECHNOLOGY:")][0]
    assert first.startswith("TECHNOLOGY: Fortinet /"), first
    assert "RESOLUTION: product" in out
    absent = [l for l in out.splitlines() if l.startswith("LOCUS_ABSENT:")][0]
    assert len(absent.split(" - ")[0].split(":", 1)[1].split(",")) < 4 \
        or absent.startswith("LOCUS_ABSENT: none"), absent
    # The analogues reach the match set and the plane accounting. Since the 2026-09-30
    # validation they no longer take a reserved slot from the vendor's own findings, so the
    # top 12 is Fortinet's and LOCUS_ANALOGUE_ONLY names the planes only analogues hold.
    tally = [l for l in out.splitlines() if l.startswith("MATCH_TIERS:")][0]
    counts = dict(part.split("=") for part in tally.split(":", 1)[1].split("  (")[0].strip()
                  .split(", "))
    assert int(counts["class"]) > 0 and counts["vendor-other-class"] == "0", tally
    lines = out.splitlines()
    at = [i for i, l in enumerate(lines) if l.startswith("LOCUS_ANALOGUE_ONLY:")][0]
    only = []
    for line in lines[at + 1:]:
        if not line.startswith("  - "):
            break
        only.append(line)
    assert any(", tier class, " in l for l in only), lines[at:at + 4]
    wide = run("Fortinet", "--today", "2026-09-25", "--limit", "200").stdout
    tiers = [l for l in wide.splitlines() if l.startswith("MATCH_TIER: ")]
    assert "MATCH_TIER: class" in tiers and "MATCH_TIER: vendor-other-class" not in tiers
    assert "CLASS-LEVEL - shares class network.firewall which the vendor's own records " \
           "carry" in wide or "(CLASSES_FROM_VENDOR)" in wide


def test_the_vendor_class_fallback_needs_two_records_or_takes_the_top_three():
    import json
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    import consult as C
    import query as Q
    aliases = Q.normalise_alias_keys(json.load(open(os.path.join(
        ROOT, "corpus", "schema", "aliases.json"), encoding="utf-8")))
    records, patterns = Q.load_corpus(os.path.join(ROOT, "corpus"))
    nonproduct = ("cross_sector", "process.service_desk")

    def derive(vendor):
        return C.classes_from_vendor(records, Q.resolve(vendor, aliases), patterns, nonproduct)
    # Microsoft's records carry many classes; the two-record floor keeps the ones they share.
    microsoft = derive("Microsoft")
    assert microsoft and "cross_sector" not in microsoft
    # One Siemens observation: the fallback takes its class rather than nothing.
    assert derive("Siemens") == ["ot.plc"]
    # A vendor named only inside generic records' products derives nothing from them.
    assert derive("GitHub") == []
