# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cross-reference consistency for the bundle's documentation.

Three classes of check:

  1. Every ``xdm.*`` path mentioned in any reference file, the SKILL.md
     body, or the MAPPED-header template is in the authoritative path
     list (built from ``references/xdm-schema.md``).
  2. Every ``XDM_CONST.*`` constant mentioned in any reference file or
     the template is in the authoritative constant list (built from
     ``references/xdm-const.md``).
  3. Every relative markdown link in the bundle resolves to an existing
     file inside the bundle.

Documented exceptions live in the ALLOW_KNOWN_BAD_* sets below -- these
are deliberate counter-examples (e.g. ``xdm.event.start_time`` appears
in pitfall-traps.md to illustrate the ERR-016 violation, NOT as a real
path). Adding to the allow-list must come with a written reason.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

# Make ``_helpers`` importable regardless of unittest invocation form.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _helpers import bundle_root, read_json, read_text  # noqa: E402


# ---------------------------------------------------------------------------
# Allow-known-bad: deliberate counter-examples that intentionally use
# non-existent paths or constants. Each entry gets a one-line reason so a
# future reader (or a tool sweep) can decide whether the exception is
# still warranted.
# ---------------------------------------------------------------------------

ALLOW_KNOWN_BAD_XDM_PATHS = {
    # ERR-016 examples -- these are documented as NON-EXISTENT to teach
    # the rule. They MUST appear in the reference text.
    "xdm.event.start_time": "ERR-016 counter-example (non-existent path)",
    "xdm.event.end_time": "ERR-016 counter-example (non-existent path)",
    # Pitfall trap examples -- invented paths used to demonstrate
    # ERR-011 (self-reference) and related anti-patterns.
    "xdm.x": "pitfall-traps.md anti-pattern placeholder",
    # SKILL.md / script-usage placeholder, e.g. "--reverse <xdm.path>".
    "xdm.path": "placeholder token in script CLI usage docs, not a real path",
    # pitfall-traps.md "Wrong | Right" table -- left-column wrong paths.
    "xdm.cloud.provider": "pitfall-traps Wrong column (right is xdm.source.cloud.provider)",
    "xdm.network.http.user_agent": "pitfall-traps Wrong column (right is xdm.source.user_agent)",
    "xdm.network.dns.response_code_text": "pitfall-traps OMIT-with-sink example (documented optional sink)",
    "xdm.source.cloud.account_id": "pitfall-traps Wrong column (right is xdm.source.cloud.project_id)",
    # syslog-envelope.md documents that this field does NOT exist: the
    # observer family carries no address, so the natural mapping of a
    # sending device's address is rejected by ERR-020. Named so the reader
    # recognises the failure, not recommended.
    "xdm.observer.ipv4": "syslog-envelope absent-field counter-example",
    "xdm.source.user.email": "pitfall-traps Wrong column (right is xdm.source.user.upn)",
    "xdm.target.user.email": "pitfall-traps Wrong column (right is xdm.target.user.upn)",
    # compatibility-notes.md documents this as a deprecated path.
    "xdm.network.direction": "compatibility-notes deprecated path (documented)",
    # network-mapping.md documents this as NON-EXISTENT: the pasted
    # network mandatory list named it, and the reference corrects it to
    # xdm.network.http.http_header.
    "xdm.network.http.response_headers": "network-mapping counter-example (corrected to http_header)",
    # parent_process.* family -- documented as NON-EXISTENT.
    "xdm.source.process.parent_process": "compatibility-notes/pitfall-traps anti-pattern (parent path)",
    "xdm.source.process.parent_process.command_line": "compatibility-notes anti-pattern",
    "xdm.source.process.parent_process.identifier": "compatibility-notes anti-pattern",
    "xdm.source.process.parent_process.name": "compatibility-notes anti-pattern",
    "xdm.source.process.parent_process.pid": "compatibility-notes anti-pattern",
    "xdm.target.process.parent_process": "compatibility-notes anti-pattern (parent path)",
    "xdm.target.process.parent_process.command_line": "compatibility-notes anti-pattern",
    "xdm.target.process.parent_process.identifier": "compatibility-notes anti-pattern",
    "xdm.target.process.parent_process.name": "compatibility-notes anti-pattern",
    "xdm.target.process.parent_process.pid": "compatibility-notes anti-pattern",
    # failure-modes.md schema-enumeration drift symptom -- illustrative
    # placeholders showing the BAD pattern the agent should stop doing.
    "xdm.alert.foo": "failure-modes.md placeholder in #1 symptom example",
    "xdm.alert.bar": "failure-modes.md placeholder in #1 symptom example",
    "xdm.alert.baz": "failure-modes.md placeholder in #1 symptom example",
}

ALLOW_KNOWN_BAD_XDM_CONSTS = {
    # XDM_CONST_PATHS / XDM_CONST.X is a placeholder/template, not a real
    # constant.
    "XDM_CONST.X": "placeholder in anti-pattern examples",
    # failure-modes.md #6 -- these are explicitly cited as INVENTED
    # constants the agent should NOT produce. They MUST appear in the
    # text as cautionary examples.
    "XDM_CONST.CLOUD_PROVIDER_ORACLE": "failure-modes.md #6 invented-constant counter-example",
    "XDM_CONST.OS_FAMILY_BSD": "failure-modes.md #6 invented-constant counter-example",
    "XDM_CONST.THREAT_CATEGORY_SECURITY": "failure-modes.md #6 invented-constant counter-example",
}

# Token-prefix excludes -- match starts-with so we can ignore whole
# families of "invented this to make a point" examples without listing
# each individually.
ALLOW_KNOWN_BAD_CONST_PREFIXES = (
    "XDM_CONST.SOME_",
    "XDM_CONST.<",  # "XDM_CONST.<TYPE>" template placeholder
    "XDM_CONST.NAME_",  # banded-scoring example uses NAME_1 / NAME_2
)

# Path-prefix excludes for the same reason.
ALLOW_KNOWN_BAD_PATH_PREFIXES = (
    "xdm.<",   # template placeholder "xdm.<category>.<field>"
    "xdm.alert.original_threat_name",  # legitimate path; appears in template only
)


# ---------------------------------------------------------------------------
# Token extractors
# ---------------------------------------------------------------------------

XDM_PATH_RE = re.compile(r"\bxdm(?:\.[a-z_][a-z0-9_]*){1,6}\b")
# XDM_CONST.* token -- must end in an uppercase letter or digit (so partial
# captures like `XDM_CONST.LOG_LEVEL_` from template placeholders are
# excluded). Trailing-underscore and angle-bracket continuations like
# `XDM_CONST.LOG_LEVEL_<NAME>` are templates, not real constants.
XDM_CONST_RE = re.compile(r"\bXDM_CONST\.[A-Z][A-Z0-9_]*[A-Z0-9]\b")
SCHEMA_LINE_RE = re.compile(r"^\s*(xdm\.[a-z_][a-z0-9_.]*)\s+--\s+")
# XDM_CONST.X in the schema can be followed by a parenthesised
# annotation (e.g. "XDM_CONST.HTTP_RSP_CODE_OK (200)"). Capture the
# bare constant; ignore trailing parens, comments, comma, etc.
SCHEMA_CONST_RE = re.compile(r"^\s*(XDM_CONST\.[A-Z_][A-Z0-9_]*)\b")
MARKDOWN_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


def authoritative_xdm_paths():
    """Parse references/xdm-schema.md; return the set of canonical
    ``xdm.*`` paths (each line of the form ``xdm.foo.bar -- TYPE``)."""
    paths = set()
    for ln in read_text("references/xdm-schema.md").splitlines():
        m = SCHEMA_LINE_RE.match(ln)
        if m:
            paths.add(m.group(1))
    return paths


def authoritative_xdm_consts():
    """Parse references/xdm-const.md; return the set of XDM_CONST.*
    tokens that appear as code-fenced bare lines."""
    consts = set()
    in_code_fence = False
    for ln in read_text("references/xdm-const.md").splitlines():
        if ln.startswith("```"):
            in_code_fence = not in_code_fence
            continue
        m = SCHEMA_CONST_RE.match(ln)
        if m:
            consts.add(m.group(1))
    return consts


def cited_xdm_paths():
    """Yield (file_rel, path) for every xdm.* token in non-schema files."""
    root = bundle_root()
    schema_md = "references/xdm-schema.md"
    for p in sorted(root.rglob("*.md")):
        rel = str(p.relative_to(root))
        if rel == schema_md or rel.startswith("tests/"):
            continue
        text = p.read_text(encoding="utf-8")
        for m in XDM_PATH_RE.finditer(text):
            yield rel, m.group(0)
    # Also walk the MAPPED-header template
    tmpl = root / "assets/modeling_header_template.xql"
    if tmpl.is_file():
        text = tmpl.read_text(encoding="utf-8")
        rel = str(tmpl.relative_to(root))
        for m in XDM_PATH_RE.finditer(text):
            yield rel, m.group(0)


def cited_xdm_consts():
    """Yield (file_rel, const) for every XDM_CONST.* token outside of
    xdm-const.md AND outside of xdm-schema.md.

    xdm-schema.md is a definition file -- it lists XDM field paths with
    their TYPE TAGS (e.g. ``xdm.event.log_level -- XDM_CONST.LOG_LEVEL``).
    Those type tags are NOT specific constants; they are the names of
    the closed-list constant groups. Walking them as "citations" would
    flag every type tag as unknown.
    """
    root = bundle_root()
    skip_md = {"references/xdm-const.md", "references/xdm-schema.md"}
    for p in sorted(root.rglob("*.md")):
        rel = str(p.relative_to(root))
        if rel in skip_md or rel.startswith("tests/"):
            continue
        text = p.read_text(encoding="utf-8")
        for m in XDM_CONST_RE.finditer(text):
            yield rel, m.group(0)
    tmpl = root / "assets/modeling_header_template.xql"
    if tmpl.is_file():
        text = tmpl.read_text(encoding="utf-8")
        rel = str(tmpl.relative_to(root))
        for m in XDM_CONST_RE.finditer(text):
            yield rel, m.group(0)


def banned_registry_paths():
    """Paths in assets/banned_fields.json. A banned field is a real Cortex
    path a MODEL rule must never assign (lint ERR-029); the references cite
    these as counter-examples, so citation is legitimate even though the
    path is deliberately absent from xdm-schema.md."""
    raw = read_json("assets/banned_fields.json")
    return {e["path"] for e in raw.get("banned", []) if e.get("path")}


def is_allowed_path(path: str) -> bool:
    if path in ALLOW_KNOWN_BAD_XDM_PATHS:
        return True
    if path in banned_registry_paths():
        return True
    return any(path.startswith(p) for p in ALLOW_KNOWN_BAD_PATH_PREFIXES)


def is_allowed_const(const: str) -> bool:
    if const in ALLOW_KNOWN_BAD_XDM_CONSTS:
        return True
    return any(const.startswith(p) for p in ALLOW_KNOWN_BAD_CONST_PREFIXES)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestXdmPathConsistency(unittest.TestCase):
    """Every xdm.* path cited in any reference file must exist in the
    authoritative path list, OR be on the allow-known-bad list."""

    @classmethod
    def setUpClass(cls):
        cls.known_paths = authoritative_xdm_paths()

    def test_authoritative_list_is_substantial(self):
        # Sanity check on the parse -- a parser that returned nothing would
        # make every "cited path exists" assertion below vacuously true.
        self.assertGreater(
            len(self.known_paths),
            400,
            f"authoritative xdm path list suspiciously small: {len(self.known_paths)}",
        )

    def test_documented_field_count_matches_the_list(self):
        """The count stated in prose must be the count on disk. It said
        645 in three places against an actual 628 -- a figure inherited
        from 1.5.2 and never re-measured, while the loose ">400" sanity
        check above happily passed throughout."""
        actual = len(self.known_paths)
        heading = read_text("references/xdm-schema.md").splitlines()[5]
        m = re.search(r"(\d{3,})\s+fields", heading)
        self.assertIsNotNone(
            m, f"xdm-schema.md heading states no field count: {heading!r}"
        )
        self.assertEqual(
            int(m.group(1)), actual,
            f"references/xdm-schema.md claims {m.group(1)} fields; the list "
            f"holds {actual}",
        )
        for rel in ("SKILL.md", "references/failure-modes.md"):
            for stated in re.findall(r"(\d{3,})[- ]field|has (\d{3,}) fields",
                                     read_text(rel)):
                n = next(s for s in stated if s)
                self.assertEqual(
                    int(n), actual,
                    f"{rel} states {n} XDM fields; the list holds {actual}",
                )

    def test_cited_paths_exist(self):
        unknown = {}
        for rel, path in cited_xdm_paths():
            # Trim trailing punctuation that may have slipped into the
            # token match (commas, periods at clause ends).
            cleaned = path.rstrip(".,;:)\"'")
            if cleaned in self.known_paths:
                continue
            # Many cited paths are PREFIXES of canonical paths, e.g.
            # "xdm.source" appears as a section header but the leaves
            # live deeper. Allow if the cited path is a prefix of any
            # known path (an "xdm.* tree" reference, not a specific
            # field).
            if any(known.startswith(cleaned + ".") for known in self.known_paths):
                continue
            if is_allowed_path(cleaned):
                continue
            unknown.setdefault(cleaned, set()).add(rel)
        if unknown:
            report = "\n".join(
                f"  {p}  (cited in: {', '.join(sorted(files))})"
                for p, files in sorted(unknown.items())
            )
            self.fail(
                f"{len(unknown)} cited xdm.* path(s) not in xdm-schema.md "
                f"and not on allow-known-bad list:\n{report}"
            )


class TestXdmConstConsistency(unittest.TestCase):
    """Every XDM_CONST.* constant cited in any reference file must
    exist in the authoritative const list, OR be on the allow-known-bad
    list."""

    @classmethod
    def setUpClass(cls):
        cls.known_consts = authoritative_xdm_consts()

    def test_authoritative_list_is_substantial(self):
        self.assertGreater(
            len(self.known_consts),
            50,
            f"authoritative XDM_CONST list suspiciously small: {len(self.known_consts)}",
        )

    def test_cited_consts_exist(self):
        unknown = {}
        for rel, const in cited_xdm_consts():
            cleaned = const.rstrip(".,;:)\"'")
            if cleaned in self.known_consts:
                continue
            if is_allowed_const(cleaned):
                continue
            unknown.setdefault(cleaned, set()).add(rel)
        if unknown:
            report = "\n".join(
                f"  {c}  (cited in: {', '.join(sorted(files))})"
                for c, files in sorted(unknown.items())
            )
            self.fail(
                f"{len(unknown)} cited XDM_CONST.* not in xdm-const.md "
                f"and not on allow-known-bad list:\n{report}"
            )


class TestMarkdownLinks(unittest.TestCase):
    """Every relative markdown link must resolve to an existing file
    inside the bundle. http(s):// and #fragment-only links are
    skipped."""

    def test_relative_links_resolve(self):
        root = bundle_root()
        broken = []
        for p in sorted(root.rglob("*.md")):
            rel = p.relative_to(root)
            if str(rel).startswith("tests/"):
                continue
            text = p.read_text(encoding="utf-8")
            for m in MARKDOWN_LINK_RE.finditer(text):
                target = m.group(1).strip()
                if target.startswith(("http://", "https://", "#", "mailto:")):
                    continue
                # Strip any fragment / query.
                clean = target.split("#", 1)[0].split("?", 1)[0]
                if not clean:
                    continue
                # Relative to the markdown file's directory.
                resolved = (p.parent / clean).resolve()
                # Allow links that escape the bundle root only if they
                # still resolve to a real file (no such cases expected,
                # but a future install layout might justify it).
                if not resolved.exists():
                    broken.append(f"{rel}: link target '{target}' does not resolve to a file")
        if broken:
            self.fail(
                f"{len(broken)} broken markdown link(s):\n"
                + "\n".join("  " + b for b in broken)
            )


class TestSyslogEnvelopeWiring(unittest.TestCase):
    """The syslog envelope reference must exist and be reachable from the
    two documents that route an author to it: the Pattern B section of
    extraction-patterns.md and the SKILL.md reference map."""

    def test_reference_exists(self):
        self.assertTrue(
            (bundle_root() / "references" / "syslog-envelope.md").is_file(),
            "references/syslog-envelope.md is missing",
        )

    def test_linked_from_extraction_patterns(self):
        self.assertIn(
            "syslog-envelope.md",
            read_text("references/extraction-patterns.md"),
            "extraction-patterns.md does not link to syslog-envelope.md",
        )

    def test_linked_from_skill_md(self):
        self.assertIn(
            "syslog-envelope.md",
            read_text("SKILL.md"),
            "SKILL.md does not link to syslog-envelope.md",
        )


class TestNetworkMappingWiring(unittest.TestCase):
    """The network mandatory-mapping reference must exist and be
    reachable from SKILL.md, mirroring the authentication reference."""

    def test_reference_exists(self):
        self.assertTrue(
            (bundle_root() / "references" / "network-mapping.md").is_file(),
            "references/network-mapping.md is missing",
        )

    def test_linked_from_skill_md(self):
        self.assertIn(
            "network-mapping.md",
            read_text("SKILL.md"),
            "SKILL.md does not link to network-mapping.md",
        )


def _codes_on(text: str) -> set:
    """Every check code in ``text``, expanding the slash-abbreviated
    run form the docs use.

    ``ERR-009/010/011`` is three codes, but a bare ``(?:ERR|WARN|INFO)-\\d+``
    match sees only ERR-009 -- the rest carry no prefix. That is not
    hypothetical: it is why the restated-list guard below scored
    SKILL.md's 34-code enumeration as 2 and let it fall eleven codes
    behind the linter."""
    found = set()
    for kind, run in re.findall(r"\b(ERR|WARN|INFO)-(\d+(?:/\d+)*)", text):
        for num in run.split("/"):
            found.add(f"{kind}-{num}")
    return found


class TestReadmeCodeListMatchesTheLinter(unittest.TestCase):
    """README.md enumerates the linter's codes in full, so unlike
    SKILL.md it is holding a copy on purpose. A copy is only safe if
    something compares it, and nothing did."""

    def setUp(self) -> None:
        sys.path.insert(0, str(bundle_root() / "scripts"))
        import lint_rule  # noqa: PLC0415

        self.registry = {e["code"] for e in lint_rule.code_table()}
        self.named = _codes_on(read_text("README.md"))

    def test_readme_names_no_code_the_linter_lacks(self):
        unknown = sorted(self.named - self.registry)
        self.assertEqual(
            unknown, [],
            f"README.md names codes lint_rule.py does not define: {unknown}",
        )

    def test_readme_names_every_code_the_linter_has(self):
        missing = sorted(self.registry - self.named)
        self.assertEqual(
            missing, [],
            f"README.md's code list is {len(missing)} behind the linter: "
            f"{missing}. Add them, or replace the enumeration with a pointer "
            "to `scripts/lint_rule.py --list-codes`.",
        )


class TestEveryReferenceIsReachable(unittest.TestCase):
    """A reference nothing links to is content the author will never
    load. virtualization-mapping.md sat in references/ for two releases
    absent from SKILL.md's index and from every other reference, so the
    only way to reach it was to list the directory -- and it was a
    provisional draft carrying open questions, which is the worst thing
    to find that way."""

    def test_no_orphan_reference_files(self):
        root = bundle_root()
        refs = sorted((root / "references").rglob("*.md"))
        corpus = read_text("SKILL.md") + read_text("README.md")
        for p in refs:
            corpus += p.read_text(encoding="utf-8")

        orphans = []
        for p in refs:
            rel = p.relative_to(root)
            # A file is reachable if any other document names it. Strip
            # its own text first, so a self-reference does not count.
            others = corpus.replace(p.read_text(encoding="utf-8"), "")
            if p.name not in others:
                orphans.append(str(rel))

        self.assertEqual(
            orphans, [],
            f"reference files nothing links to: {orphans}. Add them to "
            "SKILL.md's 'References (load on demand)' list, link them from "
            "a reference that does appear there, or take them out of the "
            "shipped bundle.",
        )


class TestReferenceFilesNameOnlyRealCodes(unittest.TestCase):
    """A reference that cites a code the linter does not have sends the
    author looking for a check that will never fire. modeling-rules.md
    carried three -- WARN-019, WARN-020 and WARN-010 -- whose real
    counterparts are ERR-019, WARN-035 and ERR-020."""

    # Parser-conformance codes from modeling-rules.md's own numbering;
    # INFO-006, which SKILL.md names in order to record that it is
    # deliberately not emitted; and WARN-023, which is a CORTEX IDE
    # validator code rather than one of ours -- compatibility-notes.md
    # cites it as the platform's own output and says so.
    _NON_LINTER_CODES = {
        "ERR-001", "ERR-002", "ERR-003", "ERR-004", "ERR-005",
        "ERR-006", "ERR-007", "ERR-008", "INFO-006",
        "WARN-023",
    }

    def setUp(self) -> None:
        sys.path.insert(0, str(bundle_root() / "scripts"))
        import lint_rule  # noqa: PLC0415

        self.registry = {e["code"] for e in lint_rule.code_table()}

    def test_no_reference_cites_a_missing_code(self):
        root = bundle_root()
        for path in sorted((root / "references").rglob("*.md")):
            rel = str(path.relative_to(root))
            named = _codes_on(path.read_text(encoding="utf-8"))
            unknown = sorted(named - self.registry - self._NON_LINTER_CODES)
            with self.subTest(file=rel):
                self.assertEqual(
                    unknown, [],
                    f"{rel} cites codes lint_rule.py does not define: "
                    f"{unknown}",
                )


class TestSkillMdLintCodesExist(unittest.TestCase):
    """SKILL.md names linter codes inline inside its hard rules. The
    linter's own module docstring is the single registry of those codes,
    so a code named in the always-loaded body must exist there.

    This is the guard that stops the two drifting apart again: SKILL.md
    previously carried a hand-maintained enumeration that fell 17 codes
    behind the linter before anyone noticed. It now points at
    `--list-codes` instead, and this test keeps the remaining inline
    mentions honest."""

    # ERR-001 / 002 / 003 / 005 are PARSER-conformance codes from
    # references/modeling-rules.md, cited in the Scope section to say
    # parsing rules are out of scope. They are not lint_rule.py codes and
    # must not be required to appear in its registry.
    #
    # INFO-006 is the opposite case: SKILL.md names it in order to record
    # that it is deliberately NOT emitted, so its absence from the
    # registry is the documented state rather than drift.
    _NON_LINTER_CODES = {
        "ERR-001",
        "ERR-002",
        "ERR-003",
        "ERR-005",
        "INFO-006",
    }

    def setUp(self) -> None:
        sys.path.insert(0, str(bundle_root() / "scripts"))
        import lint_rule  # noqa: PLC0415

        self.registry = {e["code"] for e in lint_rule.code_table()}

    def test_registry_is_populated(self):
        """A parser that silently returns nothing would make every other
        assertion here vacuously true."""
        self.assertGreater(len(self.registry), 35, self.registry)

    def test_every_code_named_in_skill_md_exists(self):
        named = set(re.findall(r"(?:ERR|WARN|INFO)-\d+", read_text("SKILL.md")))
        unknown = sorted(named - self.registry - self._NON_LINTER_CODES)
        self.assertEqual(
            unknown,
            [],
            "SKILL.md names linter codes that lint_rule.py does not define: "
            f"{unknown}. Either the check was renamed or removed, or the "
            "reference is a typo.",
        )

    def test_skill_md_does_not_restate_the_code_list(self):
        """One line carrying a dozen codes is an enumeration, and an
        enumeration is what drifted last time. Inline mentions inside a
        rule are fine; a restated list is not."""
        worst = max(
            (
                (len(_codes_on(line)), i + 1)
                for i, line in enumerate(read_text("SKILL.md").splitlines())
            ),
            default=(0, 0),
        )
        count, line_no = worst
        self.assertLessEqual(
            count,
            6,
            f"SKILL.md line {line_no} names {count} distinct check codes, "
            "which is a restated code list. Point at "
            "`scripts/lint_rule.py --list-codes` instead.",
        )

    def test_list_codes_flag_is_documented_in_skill_md(self):
        self.assertIn(
            "--list-codes",
            read_text("SKILL.md"),
            "SKILL.md must tell the author how to get the current code list",
        )


class TestDocumentedSeverityMatchesEmittedSeverity(unittest.TestCase):
    """A code's description must not contradict the severity it fires at.

    This exists because ERR-030 spent several releases documented as
    "(advisory)" while being emitted at error severity, which blocks. The
    description is not decoration: SKILL.md sends authors to
    `--list-codes` as the single source of truth for the code list, and
    `--list-codes` renders these descriptions verbatim. So the bundle was
    telling authors that a check which fails their pack would not fail
    their pack -- the most expensive direction for a doc bug to point,
    because it is discovered on a tenant.

    The rule enforced here: no code may call itself advisory while
    emitting at error severity, and every ERR- code must actually block.
    """

    # WARN-038 is emitted at "info" despite its WARN- prefix, deliberately:
    # it is an implication check ("if these two fields name the same host,
    # a companion array is useful"), and a confident wrong fix there
    # populates a field with a plausible but wrong address. Its description
    # says "Info-severity" in as many words, so it is self-consistent and
    # is NOT a defect. Do not "fix" it by raising the severity.
    _PREFIX_EXCEPTIONS = {"WARN-038": "info"}

    # INFO-006 (missing cleanup stage) is documented and deliberately never
    # emitted: a MODEL rule surfaces only xdm.* fields, so no cleanup stage
    # is needed and flagging its absence would be noise. SKILL.md records
    # the decision. It therefore has a description but no call site.
    _NEVER_EMITTED = {"INFO-006"}

    def _documented(self):
        src = (bundle_root() / "scripts" / "lint_rule.py").read_text(
            encoding="utf-8"
        )
        doc = src.split('"""')[1]
        entries, cur = {}, None
        for line in doc.split("\n"):
            m = re.match(r"\s*((?:ERR|WARN|INFO)-\d{3})\s+(.*)", line)
            if m:
                cur = m.group(1)
                entries[cur] = m.group(2)
            elif cur and line.startswith(" " * 13):
                entries[cur] += " " + line.strip()
            elif not line.strip():
                cur = None
        return entries

    def _emitted(self):
        src = (bundle_root() / "scripts" / "lint_rule.py").read_text(
            encoding="utf-8"
        )
        out = {}
        for m in re.finditer(
            r'_violation\(\s*\n?\s*"((?:ERR|WARN|INFO)-\d{3})"\s*,\s*\n?\s*"(\w+)"',
            src,
        ):
            out.setdefault(m.group(1), set()).add(m.group(2))
        return out

    def test_no_code_calls_itself_advisory_while_blocking(self):
        documented, emitted = self._documented(), self._emitted()
        offenders = []
        for code, desc in documented.items():
            if "error" not in emitted.get(code, set()):
                continue
            if re.search(r"\badvisor(?:y|ily)\b", desc, re.I):
                offenders.append(code)
        self.assertEqual(
            offenders,
            [],
            f"{offenders} describe themselves as advisory but are emitted at "
            "error severity, which returns exit 1 and fails a release gate. "
            "`--list-codes` renders these descriptions verbatim, so this "
            "tells an author a blocking check will not block.",
        )

    def test_every_err_code_actually_blocks(self):
        emitted = self._emitted()
        wrong = {
            code: sorted(sev)
            for code, sev in emitted.items()
            if code.startswith("ERR-") and sev != {"error"}
        }
        self.assertEqual(
            wrong, {}, f"ERR- codes not emitted at error severity: {wrong}"
        )

    def test_prefix_matches_severity_except_where_documented(self):
        expected = {"ERR": "error", "WARN": "warning", "INFO": "info"}
        documented, emitted = self._documented(), self._emitted()
        for code, sev in sorted(emitted.items()):
            want = self._PREFIX_EXCEPTIONS.get(
                code, expected[code.split("-")[0]]
            )
            with self.subTest(code=code):
                self.assertEqual(
                    sorted(sev), [want],
                    f"{code} emits {sorted(sev)}, expected {want}",
                )
                if code in self._PREFIX_EXCEPTIONS:
                    # An exception is only tolerable while the description
                    # says so out loud, so a reader of --list-codes is not
                    # misled by the prefix.
                    self.assertRegex(
                        documented.get(code, ""),
                        r"(?i)info-severity",
                        f"{code} deviates from its prefix without saying so "
                        "in its description",
                    )

    def test_every_documented_code_is_emitted_or_listed_as_deliberate(self):
        documented, emitted = self._documented(), self._emitted()
        missing = set(documented) - set(emitted) - self._NEVER_EMITTED
        self.assertEqual(
            missing, set(),
            f"documented but never emitted: {sorted(missing)}. Either wire "
            "the check up or record the decision not to.",
        )

    def test_err030_specifically_says_it_blocks(self):
        # The regression this class was written for.
        desc = self._documented()["ERR-030"]
        self.assertNotRegex(desc, r"(?i)\badvisor")
        self.assertRegex(desc, r"(?i)block")


_LINT_MENTION_RE = re.compile(r"\blint(?:er|ing|_rule)?\b", re.IGNORECASE)

# The claim shapes that disown a check. parser-idioms.md carried the first
# two of these about ERR-019 and ERR-025.
_DISOWN_RE = re.compile(
    r"out of scope|reviewed by eye|not enforced|does not enforce|"
    r"cannot be checked|beyond the linter|no linter check",
    re.IGNORECASE,
)

# A sentence asserting what the linter covers, as opposed to one naming a
# single code in passing ("the linter flags this as WARN-039").
_COVERAGE_RE = re.compile(r"\b(?:covers|enforces|enforced by)\b", re.IGNORECASE)


def _fenced_stripped(text: str) -> str:
    """Drop ``` fenced blocks: rule bodies carry periods and code names
    that would otherwise be read as prose claims."""
    out, fenced = [], False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if not fenced:
            out.append(line)
    return "\n".join(out)


def _sentences(text: str):
    """Sentence-split within each paragraph. The split needs a period
    FOLLOWED BY whitespace, so ``scripts/lint_rule.py`` survives intact."""
    for para in _fenced_stripped(text).split("\n\n"):
        flat = " ".join(para.split())
        for sentence in re.split(r"(?<=\.)\s+", flat):
            if sentence.strip():
                yield sentence.strip()


class TestReferencesDescribeTheLinterAccurately(unittest.TestCase):
    """The reference guard above asserts that a cited code EXISTS. That is
    one-directional, and it is why this drifted: "ERR-019, ERR-025 ... are
    out of scope for the standalone linter and must be reviewed by eye"
    names two real codes, so it passed cleanly while being false. ERR-019
    is dispatched at lint_rule.py:4493 and returns error severity.

    The cost was not theoretical. The release gate began running this
    linter and refused a pack on ERR-019 x2; an author sent to
    parser-idioms.md by SKILL.md's own reference map would have read that
    the check does not exist, and concluded the gate was wrong.

    README.md is compared against ``code_table()`` in BOTH directions by
    TestReadmeCodeListMatchesTheLinter. These two checks give the
    references the same protection for the two claim shapes they actually
    make: disowning a code, and enumerating coverage."""

    # A coverage sentence naming fewer than this is describing a related
    # group in passing, not holding a copy of the registry.
    _ENUMERATION_FLOOR = 3

    def setUp(self) -> None:
        sys.path.insert(0, str(bundle_root() / "scripts"))
        import lint_rule  # noqa: PLC0415

        self.registry = {e["code"] for e in lint_rule.code_table()}
        root = bundle_root()
        self.docs = [
            (str(path.relative_to(root)), path.read_text(encoding="utf-8"))
            for path in sorted((root / "references").rglob("*.md"))
        ]

    def test_no_reference_disowns_a_code_the_linter_enforces(self):
        for rel, text in self.docs:
            for sentence in _sentences(text):
                if not _DISOWN_RE.search(sentence):
                    continue
                if not _LINT_MENTION_RE.search(sentence):
                    continue
                disowned = sorted(_codes_on(sentence) & self.registry)
                with self.subTest(file=rel, sentence=sentence[:80]):
                    self.assertEqual(
                        disowned, [],
                        f"{rel} says the linter does not enforce "
                        f"{disowned}, but lint_rule.py dispatches them. "
                        "An author triaging a gate refusal against this "
                        "sentence concludes the gate is wrong. Fix the "
                        f"sentence: {sentence!r}",
                    )

    def test_no_reference_holds_a_partial_coverage_list(self):
        for rel, text in self.docs:
            for sentence in _sentences(text):
                if not (_COVERAGE_RE.search(sentence)
                        and _LINT_MENTION_RE.search(sentence)):
                    continue
                named = _codes_on(sentence)
                if len(named & self.registry) < self._ENUMERATION_FLOOR:
                    continue
                missing = sorted(self.registry - named)
                with self.subTest(file=rel, sentence=sentence[:80]):
                    self.assertEqual(
                        missing, [],
                        f"{rel} states the linter's coverage and then "
                        f"enumerates it, but the list is {len(missing)} "
                        f"codes behind: {missing}. An unguarded copy of the "
                        "registry is what drifted last time -- replace the "
                        "enumeration with a pointer to "
                        "`python3 scripts/lint_rule.py --list-codes`.",
                    )



if __name__ == "__main__":
    unittest.main()


class TestMandatorySetCountsInProse(unittest.TestCase):
    """Prose that advertises a mandatory-set size must match the set.

    The network set moved to 17 (+3 conditional) in 1.8.14 and five
    places across three files went on saying "20-field"; the
    authentication set is 15 and two places said "12-field". Nothing
    tested them, which is the only reason they survived. Counts are
    DERIVED from the canonical tables here, so this cannot drift again
    in either direction.
    """

    _ROW = re.compile(r"^\|\s*`(xdm\.[a-z0-9_.]+)`\s*\|")
    # The story word must sit close to the count, otherwise a row that
    # merely mentions both stories ("a dual authentication+network
    # branch. Mandatory 17-field network-story mapping") is scored twice
    # and fails against whichever set it was not talking about.
    _CLAIM = re.compile(
        r"\b(\d{1,2})[- ](?:field|item)\b[^.|]{0,30}?"
        r"\b(network|authentication)\b",
        re.IGNORECASE,
    )

    @classmethod
    def _mandatory_rows(cls, reference: str, start: str, stop_prefix: str) -> int:
        """Count the backtick-quoted xdm rows in one heading's table."""
        seen, inside = set(), False
        for ln in read_text(reference).splitlines():
            if ln.startswith(start):
                inside = True
                continue
            if inside and ln.startswith(stop_prefix):
                break
            if inside:
                m = cls._ROW.match(ln)
                if m:
                    seen.add(m.group(1))
        return len(seen)

    @classmethod
    def setUpClass(cls):
        cls.network = cls._mandatory_rows(
            "references/network-mapping.md", "## Mandatory fields", "## "
        )
        cls.auth = cls._mandatory_rows(
            "references/authentication-mapping.md", "## Mandatory fields", "## "
        )

    def test_the_canonical_tables_are_the_expected_size(self):
        # Pins the derivation itself: if these move, the story changed
        # and every prose claim below must be revisited deliberately.
        self.assertEqual(self.network, 17, "network mandatory table")
        self.assertEqual(self.auth, 15, "authentication mandatory table")

    def test_no_prose_advertises_a_stale_mandatory_count(self):
        root = bundle_root()
        expected = {"network": self.network, "authentication": self.auth}
        targets = sorted((root / "references").rglob("*.md")) + [root / "SKILL.md"]
        for p in targets:
            rel = str(p.relative_to(root))
            for line_no, line in enumerate(
                p.read_text(encoding="utf-8").splitlines(), start=1
            ):
                for m in self._CLAIM.finditer(line):
                    claimed = int(m.group(1))
                    story = m.group(2).lower()
                    # 3 is the conditional HTTP subset, not the set.
                    if claimed == 3:
                        continue
                    size = expected[story]
                    with self.subTest(file=rel, line=line_no, story=story):
                        self.assertEqual(
                            claimed,
                            size,
                            f"{rel}:{line_no} advertises a "
                            f"{claimed}-field {story} mandatory set; "
                            f"the canonical table has {size}",
                        )
