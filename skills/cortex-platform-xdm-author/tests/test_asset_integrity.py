# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""File-level integrity guards for the bundle.

Catches the classes of regression that bit earlier sessions:
  - Required top-level files renamed or removed.
  - Encoding accidents (non-UTF-8 bytes in source files).
  - Missing SPDX licence header on source files.
  - SKILL.md frontmatter losing its leading ``---``.
  - LICENSE replaced with the wrong text.
  - Non-ASCII glyphs (em-dash, arrow, smart quote) leaking back into
    prose outside fenced code blocks.
  - Markdown bold / italic emphasis used in prose outside fenced
    code blocks (the engineering style forbids it).
  - The legacy "Built with the GoCortex XQL IDE" tagline reappearing
    anywhere in the bundle.
"""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _helpers import bundle_root, iter_source_files, read_text  # noqa: E402


REQUIRED_FILES = [
    "SKILL.md",
    "README.md",
    "LICENSE",
    "assets/field_anchors.json",
    "assets/modeling_header_template.xql",
    "scripts/lookup_anchor.py",
    "scripts/lint_rule.py",
]

SPDX_MARKER = "SPDX-License-Identifier: AGPL-3.0-or-later"
SPDX_HEADER_WINDOW = 10
SPDX_EXEMPT = {"LICENSE", "SKILL.md"}

AGPL_FIRST_LINE_MARKER = "GNU AFFERO GENERAL PUBLIC LICENSE"

LEGACY_TAGLINE = "Built with the GoCortex XQL IDE"


_FENCED = re.compile(r"^```.*?^```", re.MULTILINE | re.DOTALL)
_INLINE_CODE = re.compile(r"`[^`\n]*`")
_BOLD = re.compile(r"\*\*[^*\n]+?\*\*")
_ITALIC = re.compile(r"(?<![*\w])\*[^*\n]+?\*(?!\*)")


def _strip_code(text: str) -> str:
    """Remove fenced and inline code spans -- the engineering style
    only constrains prose, not code samples."""
    text = _FENCED.sub("", text)
    text = _INLINE_CODE.sub("", text)
    return text


class TestFilePresence(unittest.TestCase):
    def test_required_files_exist(self):
        root = bundle_root()
        for rel in REQUIRED_FILES:
            with self.subTest(file=rel):
                self.assertTrue(
                    (root / rel).is_file(),
                    f"required file missing: {rel}",
                )


class TestUtf8Decoding(unittest.TestCase):
    def test_utf8_decodes_cleanly(self):
        for p in iter_source_files():
            with self.subTest(file=str(p.relative_to(bundle_root()))):
                raw = p.read_bytes()
                try:
                    raw.decode("utf-8", errors="strict")
                except UnicodeDecodeError as e:
                    self.fail(f"{p}: not valid UTF-8: {e}")


class TestSpdxCoverage(unittest.TestCase):
    def test_spdx_header_in_first_lines(self):
        root = bundle_root()
        for p in iter_source_files():
            rel = str(p.relative_to(root))
            if rel in SPDX_EXEMPT:
                continue
            with self.subTest(file=rel):
                head = "\n".join(
                    p.read_text(encoding="utf-8").splitlines()[:SPDX_HEADER_WINDOW]
                )
                self.assertIn(
                    SPDX_MARKER,
                    head,
                    f"{rel}: missing '{SPDX_MARKER}' in first "
                    f"{SPDX_HEADER_WINDOW} lines",
                )


class TestSkillMdFrontmatter(unittest.TestCase):
    def setUp(self):
        self.lines = read_text("SKILL.md").splitlines()

    def test_first_line_is_frontmatter_marker(self):
        self.assertGreater(len(self.lines), 1)
        self.assertEqual(self.lines[0], "---")

    def test_frontmatter_closes(self):
        closes = [i for i, ln in enumerate(self.lines[1:20], start=1) if ln == "---"]
        self.assertTrue(closes, "SKILL.md frontmatter never closes")

    def test_frontmatter_has_name_and_description(self):
        closes = [i for i, ln in enumerate(self.lines[1:20], start=1) if ln == "---"]
        end = closes[0]
        body = self.lines[1:end]
        keys = {}
        for ln in body:
            if ":" not in ln:
                continue
            k, _, v = ln.partition(":")
            keys[k.strip()] = v.strip()
        for required in ("name", "description"):
            with self.subTest(field=required):
                self.assertIn(required, keys)
                self.assertTrue(keys[required])


class TestLicenseFile(unittest.TestCase):
    def test_license_first_line_is_agpl(self):
        first = read_text("LICENSE").splitlines()[0].strip()
        self.assertIn(AGPL_FIRST_LINE_MARKER, first)


class TestFieldAnchorsJsonParses(unittest.TestCase):
    def test_parses(self):
        try:
            json.loads(read_text("assets/field_anchors.json"))
        except json.JSONDecodeError as e:
            self.fail(f"assets/field_anchors.json failed to parse: {e}")


class TestAsciiOnlyOutsideCode(unittest.TestCase):
    """Every byte in every bundle source file must be pure ASCII.
    Em-dashes, arrows, smart quotes etc. are publish-blockers per the
    engineering spec. For markdown the check runs against prose outside
    fenced and inline code; for code files (.py, .xql) the check runs
    against the whole file."""

    def test_markdown_prose_is_ascii(self):
        root = bundle_root()
        for p in iter_source_files():
            if p.suffix != ".md":
                continue
            rel = str(p.relative_to(root))
            with self.subTest(file=rel):
                prose = _strip_code(p.read_text(encoding="utf-8"))
                offenders = []
                for line_no, line in enumerate(prose.splitlines(), start=1):
                    for ch in line:
                        if ord(ch) > 127:
                            offenders.append(
                                (line_no, repr(ch), hex(ord(ch)))
                            )
                            break
                self.assertFalse(
                    offenders,
                    f"{rel}: non-ASCII glyphs in prose: {offenders[:5]}",
                )

    def test_code_files_are_ascii(self):
        """The ASCII rule applies to .py and .xql in their entirety --
        comments and docstrings included. Fenced-code exemption only
        applies to markdown."""
        root = bundle_root()
        for p in iter_source_files():
            if p.suffix not in (".py", ".xql"):
                continue
            rel = str(p.relative_to(root))
            with self.subTest(file=rel):
                offenders = []
                for line_no, line in enumerate(
                    p.read_text(encoding="utf-8").splitlines(), start=1
                ):
                    for ch in line:
                        if ord(ch) > 127:
                            offenders.append(
                                (line_no, repr(ch), hex(ord(ch)))
                            )
                            break
                self.assertFalse(
                    offenders,
                    f"{rel}: non-ASCII glyphs in source: {offenders[:5]}",
                )


class TestNoBoldItalicInProse(unittest.TestCase):
    """Markdown emphasis markers must not appear in prose. The
    engineering style asks for plain text; emphasis is reserved for
    code samples (which sit inside fenced blocks and are excluded)."""

    def test_no_bold_outside_code(self):
        root = bundle_root()
        for p in iter_source_files():
            if p.suffix != ".md":
                continue
            rel = str(p.relative_to(root))
            with self.subTest(file=rel):
                prose = _strip_code(p.read_text(encoding="utf-8"))
                hits = _BOLD.findall(prose)
                self.assertFalse(
                    hits,
                    f"{rel}: bold emphasis in prose: {hits[:3]}",
                )

    def test_no_italic_outside_code(self):
        root = bundle_root()
        for p in iter_source_files():
            if p.suffix != ".md":
                continue
            rel = str(p.relative_to(root))
            with self.subTest(file=rel):
                prose = _strip_code(p.read_text(encoding="utf-8"))
                hits = _ITALIC.findall(prose)
                self.assertFalse(
                    hits,
                    f"{rel}: italic emphasis in prose: {hits[:3]}",
                )


class TestNoLegacyTagline(unittest.TestCase):
    """The "Built with the GoCortex XQL IDE" tagline is a publish-
    blocker for vendor-neutral skill bundles. It must not appear in
    any bundle file."""

    def test_tagline_absent(self):
        root = bundle_root()
        for p in iter_source_files():
            rel = str(p.relative_to(root))
            with self.subTest(file=rel):
                self.assertNotIn(
                    LEGACY_TAGLINE,
                    p.read_text(encoding="utf-8"),
                    f"{rel}: contains the legacy '{LEGACY_TAGLINE}' tagline",
                )


class TestSampleDataUsesDocumentationDomains(unittest.TestCase):
    """Log samples are synthesised, as references/worked-examples.md
    states, so every hostname in them belongs to a reserved
    documentation domain. A name under a registrable third-party domain
    does not, and asserting one in a public fixture is a claim about
    somebody else's estate. Scoped to the sample corpora, where the
    policy is unambiguous; prose elsewhere legitimately cites real
    URLs."""

    # RFC 2606 / RFC 6761 reserved names, plus the two synthesised
    # estates the worked examples declare, plus the cloud providers'
    # own API endpoints (which are the event data, not a host).
    ALLOWED_SUFFIXES = (
        ".example.com", ".example.net", ".example.org",
        ".example.local", ".example.test",
        ".acme.local", ".contoso.com",
        ".invalid", ".test", ".localdomain",
        ".amazonaws.com", ".googleapis.com", ".gserviceaccount.com",
    )
    ALLOWED_EXACT = {
        "example.com", "example.net", "example.org",
        "acme.local", "contoso.com",
    }

    # A Java / .NET fully-qualified class name has the same shape as a
    # hostname read backwards. Nokia NFMP logs them verbatim
    # (java.net.ConnectException), so they are matched and dropped
    # before the hostname rule sees them.
    _PACKAGE_PREFIXES = ("java.", "javax.", "org.", "com.sun.", "sun.")

    _HOST = re.compile(
        r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.){1,}"
        r"(?:com|net|org|local|internal|io|au|uk|test|invalid)\b",
        re.IGNORECASE,
    )

    def test_no_third_party_domains_in_sample_data(self):
        root = bundle_root()
        corpora = [root / "tests" / "fixtures", root / "tests" / "corpus"]
        for base in corpora:
            for p in sorted(base.rglob("*")):
                if not p.is_file():
                    continue
                rel = str(p.relative_to(root))
                try:
                    text = p.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    continue
                for host in {m.group(0).lower() for m in self._HOST.finditer(text)}:
                    if host in self.ALLOWED_EXACT:
                        continue
                    if host.startswith(self._PACKAGE_PREFIXES):
                        continue
                    if host.endswith(self.ALLOWED_SUFFIXES):
                        continue
                    self.fail(
                        f"{rel}: sample data carries '{host}', which is not a "
                        f"documentation domain. Log samples are synthesised -- "
                        f"re-sanitise it under example.com / example.net / "
                        f"example.local."
                    )


if __name__ == "__main__":
    unittest.main()
