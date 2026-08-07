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
    # virtualization-mapping.md -- cited as one of the two possible forms
    # of the virtualization tag, in an explicitly unresolved TO CONFIRM
    # block. Whether this member exists is the open question; if a tenant
    # confirms it, add it to xdm-const.md and drop this entry.
    "XDM_CONST.EVENT_TAG_VIRTUALIZATION": "virtualization-mapping.md unresolved tag-form counter-example",
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
        # Sanity check on the parse; the schema reference covers ~645 fields.
        self.assertGreater(
            len(self.known_paths),
            400,
            f"authoritative xdm path list suspiciously small: {len(self.known_paths)}",
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
                (len(set(re.findall(r"(?:ERR|WARN|INFO)-\d+", line))), i + 1)
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


if __name__ == "__main__":
    unittest.main()
