# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The GoCortexIO bundle standard, enforced.

This file is IDENTICAL in every bundle and is copied, never imported: a skill is installed on
its own, so a shared import path does not exist at runtime. It is COMPLETE as it stands and
needs no sibling bundle present to run. The pack-building harness carries the canonical copy and
the written standard, and when the bundles are checked out together a test there refuses drift.

A standard with no check becomes a paragraph, which is the failure LAW A24 exists to close.

WHAT IS DELIBERATELY NOT HERE. A British English check was written, measured across all four
bundles and REJECTED before it shipped. The estate is already British -- behaviour 55, colour 3,
analyse 5, recognise 11, and no American spelling at all -- so an unrestricted match returns
`otherwise`, `size`, `premise`, `raise` and `noise`, and `license` is almost entirely the SPDX
identifier and the frontmatter key. Every finding would have been wrong advice, and a check like
that gets switched off, taking the true findings with it.
"""

import pathlib
import re
import unicodedata

import pytest

BUNDLE = pathlib.Path(__file__).resolve().parent.parent
SPDX = "SPDX-License-Identifier: AGPL-3.0-or-later"
FRONTMATTER_KEYS = ["name", "description", "version", "license"]

#: Written by a tool, not by an author, so not ours to check. Matched on path PARTS rather than
#: a prefix. Without this, `.pytest_cache/README.md` -- which pytest writes, with no SPDX header
#: and markdown emphasis in it -- made a bundle's integrity suite pass on a clean checkout and
#: fail on every SECOND run.
GENERATED = {".git", ".pytest_cache", "__pycache__", ".ruff_cache", ".mypy_cache", ".venv"}

#: The SKILL.md body ceiling, in words. This is the anti-scope-creep control and the reason the
#: standard is worth having: a card that cannot grow forces knowledge out to a reference, or out
#: to a new skill, instead of accumulating where every session pays to read it.
STANDARD_CEILING = 5000

#: A bundle over the ceiling must be DECLARED, with its current figure and why. The figure is a
#: HIGH-WATER MARK: the suite refuses growth past it, so the number can only be lowered, and
#: lowering it is a visible edit rather than a silent drift. An undeclared bundle over the
#: ceiling fails, which is what stops this list being a place to hide.
#: Bundles declared OVER the standard ceiling, with the mark and the argument for it.
#:
#: EMPTY, and that is the point. The harness sat here from the day this file was written, at
#: 25,000 words and then 14,800, with the note "target is the standard ceiling". It reached it at
#: 2.50.0: the law register, the ground rules, the banner templates, the instrument contract and
#: version discipline all moved to references, and the card came down to roughly 4,200 words --
#: an INDEX to a thirteen-phase method rather than the method itself.
#:
#: A bundle added here must carry a real argument, not a number. The entry is the argument.
OVER_STANDARD = {}


#: Every bundle in this project. Written out rather than globbed, because a skill is installed
#: ALONE and has no siblings to enumerate at runtime -- the very property the rule below defends.
PROJECT_BUNDLES = (
    "cortex-content-pack-go-again",
    "cortex-platform-advisory-consultant",
    "cortex-platform-correlation-author",
    "cortex-platform-playbook-author",
    "cortex-platform-xdm-author",
)

#: The harness. It may point AT an instrument, because dispatch is its job. An instrument may not
#: point back, and may not point sideways at another instrument.
HARNESS = "cortex-content-pack-go-again"

_CROSS_BUNDLE_PATH = re.compile(
    r"(" + "|".join(PROJECT_BUNDLES) + r")/([A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+)")

#: A citation shaped like a file reference: inside backticks, or a markdown link target.
_IN_BUNDLE_REF = re.compile(r"`([^`\s]+)`|\]\(([^)\s]+)\)")

#: The directories a bundle-relative citation starts with. Anything else -- a URL path, a
#: repository name, a ratio -- is not a claim about a file in this bundle.
_BUNDLE_DIRS = ("references/", "scripts/", "assets/", "tests/", "phases/", "corpus/")


def _text_files():
    """Every .md and .py an author wrote, LICENSE and generated output excluded."""
    for ext in ("*.md", "*.py"):
        for f in sorted(BUNDLE.rglob(ext)):
            if GENERATED & set(f.parts) or f.name == "LICENSE":
                continue
            yield f


def _frontmatter():
    t = (BUNDLE / "SKILL.md").read_text(encoding="utf-8")
    assert t.startswith("---\n"), "SKILL.md must open with a frontmatter fence"
    return t.split("---\n", 2)[1]


def _declared(key):
    m = re.search(rf"^{key}:\s*(.+)$", _frontmatter(), re.M)
    assert m, f"SKILL.md frontmatter declares no {key}"
    return m.group(1).strip()


def _body():
    return (BUNDLE / "SKILL.md").read_text(encoding="utf-8").split("---\n", 2)[2]


@pytest.mark.parametrize("name", ["SKILL.md", "README.md", "CHANGELOG.md", "LICENSE"])
def test_the_four_files_every_bundle_carries(name):
    assert (BUNDLE / name).is_file(), f"{BUNDLE.name} has no {name}"


def test_frontmatter_carries_exactly_the_standard_keys_in_order():
    """Order too, not just presence. The frontmatter is the most-read thing in a bundle and
    four cards that read differently are four bundles that feel different."""
    got = [l.split(":", 1)[0] for l in _frontmatter().splitlines()
           if l.strip() and not l.startswith((" ", "\t", "#"))]
    assert got == FRONTMATTER_KEYS, f"{BUNDLE.name} frontmatter keys are {got}"


def test_the_declared_name_is_the_directory_name():
    """A skill is addressed by its directory. A name that disagrees is a skill nobody can call."""
    assert _declared("name") == BUNDLE.name


def test_the_declared_licence_is_agpl():
    assert _declared("license") == "AGPL-3.0-or-later"


def test_the_licence_file_is_the_agpl_text():
    assert "GNU AFFERO GENERAL PUBLIC LICENSE" in (BUNDLE / "LICENSE").read_text(encoding="utf-8")


def test_the_changelog_has_an_entry_for_the_declared_version():
    """A release with no entry is a version nobody can find out anything about."""
    v = _declared("version")
    assert f"## {v}" in (BUNDLE / "CHANGELOG.md").read_text(encoding="utf-8"), \
        f"CHANGELOG.md has no '## {v}' entry"


def test_skill_md_names_its_version_in_prose():
    """Frontmatter is machine-read; a reader scanning the card should not have to parse it."""
    v = _declared("version")
    assert f"The current version is {v}" in _body(), \
        f"SKILL.md prose does not say 'The current version is {v}'"


def test_every_source_file_carries_the_spdx_identifier():
    bad = [str(f.relative_to(BUNDLE)) for f in _text_files()
           if SPDX not in "\n".join(f.read_text(encoding="utf-8", errors="replace")
                                    .splitlines()[:12])]
    assert not bad, f"{len(bad)} file(s) with no SPDX header in the first 12 lines: {bad[:8]}"


def test_the_bundle_is_ascii_only():
    """The house style bans the em dash, the curly quote and the ellipsis character. Everything
    it bans is non-ASCII, so this tests the general property rather than a list that can rot."""
    bad = []
    for f in _text_files():
        for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            for col, ch in enumerate(line, 1):
                if ord(ch) > 127:
                    bad.append(f"{f.relative_to(BUNDLE)}:{i}:{col} "
                               f"U+{ord(ch):04X} {unicodedata.name(ch, 'unnamed')}")
    assert not bad, f"{len(bad)} non-ASCII character(s): {bad[:8]}. Use ' -- ' for a dash."


def test_the_skill_card_is_within_its_ceiling():
    """The control this standard exists for. Everything else here is tidiness; this is the one
    that changes what gets built, because it makes 'put it in the card' stop being free."""
    words = len(_body().split())
    limit = OVER_STANDARD.get(BUNDLE.name, (STANDARD_CEILING, ""))[0]
    assert words <= limit, (
        f"SKILL.md body is {words} words against a {limit}-word limit. Move prose to a "
        "reference, or move the subject to its own skill. Raising the limit is not the fix."
    )


def test_no_instrument_cites_a_path_inside_another_bundle():
    """Every skill has to ship on its own.

    The harness may point AT an instrument, because dispatch is its job. An instrument may not
    point back, and may not point sideways: a path into a bundle the reader has not installed is
    a citation they cannot open, and following it is not optional when it is where the rule
    actually lives. This is the same defect phase 902 reports as "a claim resting on a source the
    reader cannot see", one layer down.

    NAMING another bundle in prose is fine and stays fine -- provenance, credit, and "that bundle
    owns this" are all things a standalone reader loses nothing by reading. It is the PATH that
    breaks, so only a path is matched.

    TWO ARMS, because the first one alone never matched anything. It looks for a path PREFIXED
    with a bundle's own directory name, and nobody writes those thirty characters before a
    filename. An author writes references/gotchas.md (unquoted here on purpose -- quoted, this
    very docstring trips the arm below, which is one way to see that it works), indistinguishable
    in shape from a path into their OWN bundle, so the regex read straight past twelve real citations in
    one instrument while reporting the estate clean. The second arm therefore RESOLVES: a path
    shaped like an in-bundle reference that does not exist in this bundle is a citation this
    reader cannot open, wherever it actually lives.

    The resolving arm is deliberately narrow, because a looser version of it was measured first
    and would have shipped noise: it flagged `394/396` (a ratio), `/public_api/v1/alerts` (a URL
    path), `demisto/content` (a repository) and eighty-odd `../` links that resolve perfectly well
    against their own directory. So only a bundle-relative prefix or an explicit `../` counts,
    globs are skipped, and a relative link is resolved against the FILE that cites it, which is
    how a reader follows it. CHANGELOG.md is exempt: it records what was true at the time, and
    this project does not rewrite history to keep a checker quiet.

    A THIRD ARM WAS MEASURED AND REFUSED. The worst citation this check was written after was a
    path into the estate's private content repository -- a `Packs/<name>/...` directory a public
    reader has no copy of. Neither arm above catches it, and a rule against `Packs/` paths cannot
    be written honestly: across the estate those citations are globs, angle-bracket placeholders,
    and references to packs in the PUBLIC upstream library, which are legitimate evidence. A
    private pack and a public one are the same seven characters followed by a name. The check
    would have flagged correct content to catch one line, which is the trade this project already
    refused once over British English. Do not rebuild it; a private-repo path is a judgement made
    at review, and this note is here so the next author knows it was considered.
    """
    if BUNDLE.name == HARNESS:
        pytest.skip("the harness dispatches to instruments; pointing at them is its job")
    bad = []
    for f in _text_files():
        for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            for m in _CROSS_BUNDLE_PATH.finditer(line):
                if m.group(1) != BUNDLE.name:
                    bad.append(f"{f.relative_to(BUNDLE)}:{i} cites {m.group(0)}")

    unresolved = []
    for f in _text_files():
        if f.name == "CHANGELOG.md":
            continue
        for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            for m in _IN_BUNDLE_REF.finditer(line):
                target = (m.group(1) or m.group(2) or "").split("#")[0].strip()
                if not target or "*" in target or target.startswith(("http://", "https://")):
                    continue
                if not (target.startswith(_BUNDLE_DIRS) or target.startswith("../")):
                    continue
                base = f.parent if target.startswith("../") else BUNDLE
                if not (base / target).exists():
                    unresolved.append(f"{f.relative_to(BUNDLE)}:{i} cites {target}")

    assert not bad, (
        f"{len(bad)} path(s) into another bundle: {bad[:6]}. Name the other bundle in prose if it "
        "helps, but state the FACT rather than citing a file this reader may not have installed."
    )
    assert not unresolved, (
        f"{len(unresolved)} path(s) that do not resolve inside this bundle: {unresolved[:6]}. "
        "A reader who installed this skill alone cannot open any of them. Name the owning bundle "
        "in prose, or point at the file in THIS bundle that carries the fact."
    )


def test_a_bundle_over_the_standard_ceiling_is_declared_with_a_reason():
    """An exception has to be argued for, not merely taken. Same shape as the gate's own
    SPLIT_VERDICT register: the list is the argument, and an entry with no reason is a bundle
    quietly opting out of the only control that constrains its size."""
    if BUNDLE.name not in OVER_STANDARD:
        assert len(_body().split()) <= STANDARD_CEILING
        return
    mark, why = OVER_STANDARD[BUNDLE.name]
    assert mark > STANDARD_CEILING, f"{BUNDLE.name} is declared over but its mark is not"
    assert len(why) > 60, f"{BUNDLE.name} is declared over the ceiling with no real reason"
