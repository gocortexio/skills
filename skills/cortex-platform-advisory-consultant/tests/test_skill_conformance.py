# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The bundle must satisfy the published skill validator, with one declared divergence.

Adopted from the xdm-author bundle's own asset-integrity suite, which found the
enforcement code this repository had never run: `quick_validate.py`, shipped with the
skill-creator plugin, gating `package_skill.py`. Prose guidance is advisory; that script is
the only thing on the machine that enforces anything.

ONE constraint is deliberately not adopted. Its ALLOWED_PROPERTIES excludes `version`, so it
exits non-zero on all four bundles in this repository with the identical message. The key is
kept: the Claude Code runtime schema defines it, every bundle here declares it, and this
repository publishes through a plugin marketplace rather than as a `.skill` archive, so
`package_skill.py` is not on the path it ships by. Decision taken by the repository owner on
2026-09-05. The key-set test below fails on any OTHER unexpected key AND if `version` is
removed, so a session "fixing" the validator complaint has to read this first.

WHY THE YAML TEST EXISTS. A description rewritten at 0.33.0 read
`... MITRE ATT&CK: "I run this technology ...`. An unquoted colon-space inside a plain scalar
makes YAML read a mapping, so the frontmatter stopped parsing entirely -- and it shipped,
because every check in this bundle read the file as text. The description was also 1141
characters against a 1024 limit nothing measured. Both were found by running the validator
for the first time, not by review.
"""
import json
import os
import re
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

VALIDATOR_ALLOWED = {"name", "description", "license", "allowed-tools", "metadata", "compatibility"}
DELIBERATE_DIVERGENCE = {"version"}

VALIDATOR_CANDIDATES = [
    os.path.expanduser("~/.claude/plugins/marketplaces/claude-plugins-official/plugins/"
                       "skill-creator/skills/skill-creator/scripts/quick_validate.py"),
]


def frontmatter():
    # Skipped here rather than at import, so the tests below that read SKILL.md as text still
    # run on a machine with no YAML parser.
    yaml = pytest.importorskip("yaml")
    with open(os.path.join(ROOT, "SKILL.md"), encoding="utf-8") as handle:
        text = handle.read()
    assert text.startswith("---"), "SKILL.md must open with YAML frontmatter on line 1"
    return yaml.safe_load(text.split("---", 2)[1])


def test_the_frontmatter_parses_as_yaml():
    """The defect that shipped at 0.33.0. A colon-space in a plain scalar ends the parse."""
    mapping = frontmatter()
    assert isinstance(mapping, dict), "frontmatter did not parse to a mapping"
    assert set(mapping) >= {"name", "description"}, sorted(mapping)


def test_no_value_would_break_the_parse_the_way_0_33_0_did():
    """Restated as the shape rather than the instance, so the next near-miss also fails.

    A plain YAML scalar cannot carry ': ' -- it is read as a nested mapping. Quoting would
    also work, but every value here is currently plain and the failure is silent, so the
    cheaper rule is to keep them free of the sequence.
    """
    with open(os.path.join(ROOT, "SKILL.md"), encoding="utf-8") as handle:
        block = handle.read().split("---", 2)[1]
    for line in block.strip().splitlines():
        if not line or line.startswith((" ", "#")):
            continue
        key, _, value = line.partition(":")
        if value.strip().startswith(("'", '"', "|", ">")):
            continue  # explicitly quoted or a block scalar; the sequence is safe there
        assert not re.search(r":\s", value), (
            "frontmatter key {!r} carries a colon-followed-by-space in an unquoted value; "
            "YAML reads that as a mapping and the frontmatter stops parsing".format(key))


def test_name_is_kebab_case_and_matches_the_directory():
    name = frontmatter()["name"]
    assert re.fullmatch(r"[a-z0-9-]+", name), "name must be kebab-case"
    assert not (name.startswith("-") or name.endswith("-") or "--" in name)
    assert len(name) <= 64, "name is {} characters; the maximum is 64".format(len(name))
    assert name == os.path.basename(ROOT), \
        "the runtime derives the skill id from the directory, so they must agree"


def test_description_is_within_the_limit_and_free_of_angle_brackets():
    desc = frontmatter()["description"]
    assert len(desc) <= 1024, "description is {} characters; the maximum is 1024".format(len(desc))
    assert "<" not in desc and ">" not in desc


def test_licence_is_declared():
    assert frontmatter().get("license") == "AGPL-3.0-or-later"


def test_key_set_is_the_allowed_set_plus_one_declared_divergence():
    keys = set(frontmatter())
    unexpected = keys - VALIDATOR_ALLOWED - DELIBERATE_DIVERGENCE
    assert not unexpected, (
        "frontmatter key(s) {} are rejected by the published skill validator and are not a "
        "declared divergence".format(sorted(unexpected)))
    missing = DELIBERATE_DIVERGENCE - keys
    assert not missing, (
        "frontmatter no longer declares {}; it is kept on purpose despite the validator "
        "rejecting it -- read this module's docstring before removing it".format(sorted(missing)))


def test_against_the_real_validator_when_it_is_on_this_machine():
    """Restating rules drifts from them. Run the actual script where it exists.

    The only complaint it may make is the declared `version` divergence. Anything else is a
    real regression, and this is the assertion that would have caught the 0.33.0 YAML break
    on the day it was written.
    """
    path = next((p for p in VALIDATOR_CANDIDATES if os.path.exists(p)), None)
    if path is None:
        pytest.skip("quick_validate.py is not installed on this machine")
    done = subprocess.run([sys.executable, path, ROOT], capture_output=True, text=True)
    noise = [l for l in (done.stdout + done.stderr).splitlines()
             if l.strip() and "Unexpected key(s) in SKILL.md frontmatter: version" not in l]
    assert not noise, "the published validator reports more than the declared divergence:\n" \
        + "\n".join(noise)


def _rule(number):
    """One numbered rule under "Rules that are not negotiable", with its line breaks folded."""
    with open(os.path.join(ROOT, "SKILL.md"), encoding="utf-8") as handle:
        text = handle.read()
    start = text.index("\n{}. **".format(number))
    end = text.index("\n{}. **".format(number + 1), start)
    return " ".join(text[start:end].split())


def _vocab():
    with open(os.path.join(ROOT, "corpus", "schema", "vocab.json"), encoding="utf-8") as handle:
        return json.load(handle)


def test_rule_nine_heads_the_answer_by_the_locus_vocabulary():
    """Rule 9 once defined three planes by a technology's relationship to the attack.

    CONTROL was "the appliance as a reachable service", DATA "the thing that SEES", its
    telemetry. No telemetry-source block derives DATA and every finding prints one of six
    loci, so a model following the rule either re-bucketed findings against their printed
    LOCUS or dropped the ENDPOINT, SUPPLY and ORGANISATION findings with no heading to go
    under. The rule now heads by the vocabulary and quotes it; the relationship is a
    `what.role`, asked for with `--role`.
    """
    rule = _rule(9)
    vocab = _vocab()
    missing = [locus for locus in vocab["locus"] if locus not in rule]
    assert not missing, "rule 9 does not name the loci {}".format(missing)
    for phrase in ("thing that SEES", "thing that sees", "reachable service"):
        assert phrase not in rule, "rule 9 defines a plane by relationship again: " + phrase
    glosses = dict(re.findall(r"\b(CONTROL|MANAGEMENT|DATA) is \"([^\"]+)\"", rule))
    assert set(glosses) == {"CONTROL", "MANAGEMENT", "DATA"}, (
        "rule 9 must gloss CONTROL, MANAGEMENT and DATA in the vocabulary's words: " + str(glosses))
    for locus, gloss in glosses.items():
        assert gloss in vocab["locus"][locus], (
            "rule 9's {} gloss {!r} is not the vocabulary's wording".format(locus, gloss))
    # LOCUS_ANALOGUE_ONLY since the 2026-09-30 validation: a plane held only by other
    # products' analogues was headed as though the subject's evidence sat there.
    for line in ("LOCUS_ELIGIBLE", "LOCUS_ABSENT", "LOCUS_ANALOGUE_ONLY", "--per-locus"):
        assert line in rule, "rule 9 no longer cites " + line
    roles = re.search(r"--role ([a-z_,]+)", rule)
    assert roles, "rule 9 no longer says how to ask for the non-victim relationships"
    unknown = set(roles.group(1).split(",")) - set(vocab["role"])
    assert not unknown, "rule 9 passes --role values the vocabulary lacks: {}".format(unknown)


def test_the_locus_table_quotes_the_vocabulary():
    """A paraphrased table is how a second definition of the planes starts."""
    with open(os.path.join(ROOT, "references", "locus-and-coverage.md"), encoding="utf-8") as handle:
        rows = dict(re.findall(r"^\| `([A-Z]+)` \| (.+?) \|$", handle.read(), re.M))
    assert rows == _vocab()["locus"]

