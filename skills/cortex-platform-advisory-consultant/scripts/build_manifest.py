#!/usr/bin/env python3
# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Derive the shipped provenance manifest from the corpus itself.

    python3 scripts/build_manifest.py            # rewrite SOURCES.md
    python3 scripts/build_manifest.py --check    # exit 1 if it is out of date

WHY THIS IS DERIVED RATHER THAN WRITTEN. The full sync record -- routes, pass logs, refusal
rates, per-source backlogs, the quality verdicts this estate holds on other people's research
-- is maintainer material and does not ship. What a consumer of the corpus legitimately needs
is narrower and answerable from the corpus alone: who published the records I am holding, what
kind of source each is, and whether the citation is abstract because the source is licensed.

WHY IT IS BUILT FROM THE CORPUS AND NOT FROM THE PRIVATE RECORD. A manifest transcribed from a
document that does not ship cannot be checked by anyone who has the bundle, so it rots exactly
where nobody can see it. This bundle has been bitten by that: a comment in the release gate
carried hand-typed counts that went stale and then cost a real decision, and the fix recorded
there was to recompute rather than to re-type. Derived from `observations.jsonl`, the manifest
is falsifiable by the person holding it -- `--check` is the whole argument.

WHAT IT DELIBERATELY OMITS. No per-source licence column: the corpus does not carry licence as
a field, and inventing one row by row would be prose nothing compares. `disclosure` is carried
instead, because it IS structured, and it is the field that actually governs reuse -- a
`restricted` source is cited abstractly and has no URL to follow.

Standard library only.
"""

import argparse
import collections
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE_ROOT = os.path.dirname(HERE)

HEADER = """<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Sources

**Derived file. Do not hand-edit.** Regenerate with `python3 scripts/build_manifest.py`;
`--check` fails if it is out of date, and a test in `tests/` runs that check.

Every publisher whose material is represented in `corpus/observations/observations.jsonl`,
with the kind of source it is, how its records are cited, and how many there are. It is built
from the corpus rather than maintained beside it, so it cannot drift from what the bundle
actually holds.

The full sync record -- routes, pass logs, per-source backlogs and the decisions behind what
was taken and what was refused -- is maintainer-side and is not part of a shipped bundle.

**Citation and reuse.** A `public` source carries a real `where.url` a reader can open and its
own title. A `restricted` source is licensed intelligence: it carries no URL, its title is
abstracted to `<Publisher> commentary on <subject>`, its dates are month-precision at finest,
and no report identifier appears anywhere. `scripts/validate.py` enforces that on the records
and on this bundle's prose. Cite a restricted source as its title states it and no further.
"""


def load(corpus):
    path = os.path.join(corpus, "observations", "observations.jsonl")
    out = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def render(records):
    rows = collections.defaultdict(lambda: {"types": set(), "disclosure": set(), "n": 0})
    for record in records:
        where = record.get("where") or {}
        publisher = (where.get("publisher") or "").strip() or "(unattributed)"
        row = rows[publisher]
        row["n"] += 1
        if where.get("source_type"):
            row["types"].add(where["source_type"])
        row["disclosure"].add(where.get("disclosure") or "unstated")

    types = collections.Counter()
    disclosure = collections.Counter()
    for record in records:
        where = record.get("where") or {}
        types[where.get("source_type") or "unstated"] += 1
        disclosure[where.get("disclosure") or "unstated"] += 1

    lines = [HEADER, ""]
    lines.append("## Totals")
    lines.append("")
    lines.append("| | count |")
    lines.append("|---|---|")
    lines.append("| records | {} |".format(len(records)))
    lines.append("| distinct publishers | {} |".format(len(rows)))
    for key, count in sorted(types.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append("| -- source_type `{}` | {} |".format(key, count))
    for key, count in sorted(disclosure.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append("| -- disclosure `{}` | {} |".format(key, count))
    lines.append("")
    lines.append("## Publishers")
    lines.append("")
    lines.append("| publisher | source type | citation | records |")
    lines.append("|---|---|---|---|")
    # Ordered by weight then name: the reader's first question is who most of this came from,
    # and an alphabetical list answers that only by being read end to end.
    for publisher, row in sorted(rows.items(), key=lambda kv: (-kv[1]["n"], kv[0].lower())):
        lines.append("| {} | {} | {} | {} |".format(
            publisher,
            ", ".join(sorted(row["types"])) or "unstated",
            ", ".join(sorted(row["disclosure"])),
            row["n"]))
    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--corpus", default=os.path.join(BUNDLE_ROOT, "corpus"))
    parser.add_argument("--out", default=os.path.join(BUNDLE_ROOT, "SOURCES.md"))
    parser.add_argument("--check", action="store_true",
                        help="do not write; exit 1 if the file on disk is not what this would write")
    args = parser.parse_args()

    text = render(load(args.corpus))

    if args.check:
        try:
            with open(args.out, "r", encoding="utf-8") as handle:
                current = handle.read()
        except OSError:
            print("{} is missing; run without --check to write it".format(args.out))
            return 1
        if current != text:
            print("{} is out of date; run: python3 scripts/build_manifest.py".format(
                os.path.relpath(args.out, BUNDLE_ROOT)))
            return 1
        print("manifest is current")
        return 0

    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(text)
    print("wrote {}".format(os.path.relpath(args.out, BUNDLE_ROOT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
