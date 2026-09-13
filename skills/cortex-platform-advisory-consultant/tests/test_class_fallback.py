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
