#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: GoCortexIO
"""lookup_anchor.py <vendor_field_name> [vendor_field_name ...]
   lookup_anchor.py --reverse <xdm.path>     (vendor synonyms for a target)
   lookup_anchor.py --related <xdm.path>     (companion / mirror fields)

Default (forward) lookup: take vendor field names and return the ranked
``xdm.*`` paths historical rules mapped them to, from the shipped
field-anchor index (``assets/field_anchors.json``).

``--reverse`` drives the index the other way: given an XDM target, list
the vendor column names that tend to fill it -- useful when authoring
top-down ("which raw field feeds xdm.target.user.username?").

``--related`` lists the companion / mirror fields you normally map
alongside a given target (e.g. xdm.source.ipv4 -> xdm.target.ipv4).

JSON on stdout.

Forward result block:

    {
      "input": "<as-given>",
      "normalised": "<after normalisation>",
      "candidates": [
        { "xdm_path": "...", "frequency": int, "score": int,
          "synonym_count": int, "exampleVendors": [...] },
        ...
      ]
    }

Exit codes:
    0   success (even with no candidates found)
    1   argument error
    2   cannot locate or parse the anchor file

Python 3.9+ stdlib only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Shared helpers live in _anchor_index.py. Re-export them here so
# importers that already write ``from lookup_anchor import X`` keep
# working.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _anchor_index import (  # noqa: E402
    ANCHORS_PATH,
    build_reverse_index,
    forward_synonyms,
    load_anchors,
    normalise_synonym,
    related_fields,
)

__all__ = [
    "ANCHORS_PATH",
    "build_reverse_index",
    "forward_synonyms",
    "load_anchors",
    "main",
    "normalise_synonym",
    "related_fields",
]


def _forward(fields: list) -> list:
    data = load_anchors()
    reverse = build_reverse_index(data)
    results = []
    for inp in fields:
        normalised = normalise_synonym(inp)
        results.append(
            {
                "input": inp,
                "normalised": normalised,
                "candidates": reverse.get(normalised, []),
            }
        )
    return results


def main(argv: list) -> int:
    ap = argparse.ArgumentParser(
        prog="lookup_anchor.py",
        description="Query the field-anchor index forwards (vendor field "
        "-> xdm.*), in reverse (xdm.* -> vendor fields), or for companion "
        "fields.",
        add_help=True,
    )
    ap.add_argument("fields", nargs="*", help="vendor field name(s) to look up")
    ap.add_argument("--reverse", metavar="XDM_PATH",
                    help="list vendor synonyms historically mapped to this XDM path")
    ap.add_argument("--related", metavar="XDM_PATH",
                    help="list companion / mirror fields for this XDM path")

    # Preserve the original bare-usage error contract (exit 1, short message).
    if len(argv) <= 1:
        sys.stderr.write(
            "usage: python3 lookup_anchor.py <vendor_field_name> "
            "[vendor_field_name ...]\n"
            "       python3 lookup_anchor.py --reverse <xdm.path>\n"
            "       python3 lookup_anchor.py --related <xdm.path>\n"
        )
        return 1

    try:
        args = ap.parse_args(argv[1:])
    except SystemExit as exc:
        # argparse exits 0 for -h / --help and 2 for a usage error. The
        # blanket catch turned the help exit into a failure, so
        # `lookup_anchor.py --help` printed correct help and reported 1.
        if exc.code == 0:
            raise
        return 1

    if args.reverse:
        data = load_anchors()
        out = {"xdm_path": args.reverse, "synonyms": forward_synonyms(data, args.reverse)}
        sys.stdout.write(json.dumps(out, indent=2) + "\n")
        return 0

    if args.related:
        out = {"xdm_path": args.related, "related": related_fields(args.related)}
        sys.stdout.write(json.dumps(out, indent=2) + "\n")
        return 0

    if not args.fields:
        sys.stderr.write("error: provide a vendor field name, --reverse, or --related\n")
        return 1

    sys.stdout.write(json.dumps(_forward(args.fields), indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
