#!/usr/bin/env python3
# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Verify a release tag against the bundle it names, and cut its release notes.

Called by .github/workflows/release-skill-bundle.yml with BUNDLE and VERSION in the
environment, both already parsed out of the tag. It refuses before anything is built, so a
tag that disagrees with its bundle costs a failed run and nothing else -- no archive, no
Release, no asset.

WHY THIS IS A FILE AND NOT A HEREDOC IN THE WORKFLOW. A heredoc cannot be run without a
tag, a runner and a push, so the only way to test it is to publish something. As a file it
runs anywhere:

    BUNDLE=cortex-platform-correlation-author VERSION=0.7.0 python3 .github/scripts/release_notes.py

ONE VERSION SITE IS CHECKED HERE, DELIBERATELY. The frontmatter is the canonical one. The
prose sentence, the CHANGELOG heading and each bundle's own fourth site -- xdm-author's
provenance template, advisory-consultant's README line -- follow no general rule, so there
is nothing for this script to check generally. They are proven instead by that bundle's own
suite, which the workflow runs against the EXTRACTED ARCHIVE a step later.

Standard library only, Python 3.9+, matching every bundle's own promise.
"""

import os
import pathlib
import re
import sys
import tempfile

# GitHub caps a release body at 125,000 characters. The largest section shipping today is
# 39 lines, so this is a guard against a future accident rather than a live constraint.
BODY_CEILING = 120000


def die(message):
    """Refuse, in the grammar Actions renders as an error annotation."""
    print("::error::{}".format(message))
    sys.exit(1)


def frontmatter(path):
    """The YAML frontmatter block of a SKILL.md, as text.

    Parsed by hand rather than with a YAML library because this runs on a bare runner before
    anything is installed, and because the block is four known keys rather than a document.
    """
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        die("{} does not open with a frontmatter fence".format(path))
    parts = text.split("---\n", 2)
    if len(parts) < 3:
        die("{} has no closing frontmatter fence".format(path))
    return parts[1]


def declared(block, key):
    match = re.search(r"^{}:\s*(.+)$".format(key), block, re.M)
    return match.group(1).strip() if match else None


def changelog_section(path, version):
    """The body of the '## <version>' section, matched as a WHOLE LINE.

    The whole-line match is load-bearing, not pedantry. advisory-consultant's CHANGELOG
    carries '## 0.40.2' at line 8 and '## 0.4.0' at line 1988; a prefix match on '## 0.4'
    hits four headings and picks the wrong one silently, which is the worse half.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    heading = "## {}".format(version)
    start = None
    for i, line in enumerate(lines):
        if line.strip() == heading:
            start = i
            break
    if start is None:
        die("{} has no '{}' section. A release with no notes is a version nobody can find "
            "out anything about.".format(path, heading))
    end = len(lines)
    for i in range(start + 1, len(lines)):
        if lines[i].startswith("## "):
            end = i
            break
    return "\n".join(lines[start + 1:end]).strip()


def main():
    bundle = os.environ.get("BUNDLE")
    version = os.environ.get("VERSION")
    if not bundle or not version:
        die("BUNDLE and VERSION must both be set in the environment")

    root = pathlib.Path("skills") / bundle
    skill = root / "SKILL.md"
    if not skill.is_file():
        die("{} does not exist at this commit".format(skill))

    block = frontmatter(skill)
    if declared(block, "name") != bundle:
        die("the tag names bundle {!r} but {} declares name: {!r}".format(
            bundle, skill, declared(block, "name")))
    if declared(block, "version") != version:
        die("the tag says v{} but {} declares version: {!r}. Bump the frontmatter or move "
            "the tag. Do not release a version the bundle does not claim.".format(
                version, skill, declared(block, "version")))

    changelog = root / "CHANGELOG.md"
    if not changelog.is_file():
        die("{} does not exist".format(changelog))
    body = changelog_section(changelog, version)
    if not body:
        die("the '## {}' section of {} is empty. A heading with nothing under it is a "
            "release that says nothing about itself.".format(version, changelog))
    if len(body) > BODY_CEILING:
        die("the '## {}' section is {} characters; GitHub caps a release body at "
            "125,000".format(version, len(body)))

    out_dir = pathlib.Path(os.environ.get("RUNNER_TEMP") or tempfile.gettempdir())
    out = out_dir / "release-notes.md"
    out.write_text(body + "\n", encoding="utf-8")

    print("::notice::{} lines of notes for {} {}".format(
        len(body.splitlines()), bundle, version))

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as handle:
            handle.write("path={}\n".format(out))
    else:
        # Local run. Print what CI would have passed on, so the script is useful by hand.
        print("notes written to {}".format(out))
        print("-" * 70)
        print(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
