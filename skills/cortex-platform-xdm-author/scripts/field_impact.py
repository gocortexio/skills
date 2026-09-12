#!/usr/bin/env python3
# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Answer "did this bundle change the MEANING of field F between two
versions" from ``assets/field_impact.json``.

Written for a migration check that measures a field against a model
authored under a DIFFERENT version of this bundle. Such a measurement is
only valid if the field means the same thing at both ends; where it does
not, the number is not wrong so much as about something else -- it lints
clean, the field is emitted, and the gate is green.

Two things the registry does that a grep over the changelog cannot:

* It separates a MAPPING change from prose that merely MENTIONS the
  field. A grep reports every hit and stops the reader; this reports
  ``unchanged`` with the reason each mention was harmless.
* It unions across a RANGE. Entries are per-version deltas, so crossing
  1.8.1 -> 2.0.0 means reading every version between, and doing that by
  hand is where it goes wrong.

Exit codes: 0 no meaning change, 1 meaning changed, 2 cannot answer
(unknown field range or incomplete coverage), 3 argument error.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

REGISTRY = pathlib.Path(__file__).resolve().parent.parent / "assets" / "field_impact.json"

EXIT_UNCHANGED = 0
EXIT_CHANGED = 1
EXIT_CANNOT_ANSWER = 2
EXIT_USAGE = 3

BUCKETS = ("meaning_changed", "mandatory_changed", "banned", "mentioned_only")


def _key(version: str) -> tuple:
    try:
        return tuple(int(p) for p in version.split("."))
    except ValueError:
        raise SystemExit(f"not a version: {version}")


def _load() -> dict:
    return json.loads(REGISTRY.read_text(encoding="utf-8"))


def _matches(pattern: str, field: str) -> bool:
    """A registry entry matches a queried field exactly, or by prefix when
    it is written as a subtree (``xdm.target.*``). ``xdm.*`` matches any
    field, which is how the generic entries are recorded."""
    if pattern == field:
        return True
    if pattern.endswith(".*"):
        return field.startswith(pattern[:-1])
    return False


def _range(reg: dict, lo: str | None, hi: str | None) -> list:
    """Entries in (lo, hi]. Excludes lo because a delta is recorded
    against the version it landed in: a consumer already ON lo has its
    changes, and crossing to hi means everything after it."""
    out = []
    for entry in reg["versions"]:
        k = _key(entry["version"])
        if lo is not None and k <= _key(lo):
            continue
        if hi is not None and k > _key(hi):
            continue
        out.append(entry)
    return sorted(out, key=lambda e: _key(e["version"]))


def query(field: str, lo: str | None, hi: str | None) -> dict:
    reg = _load()
    entries = _range(reg, lo, hi)
    if not entries:
        return {
            "field": field, "from": lo, "to": hi, "verdict": "cannot_answer",
            "reason": "no released version falls in that range", "hits": [],
        }

    hits, incomplete = [], []
    for entry in entries:
        if not entry.get("complete"):
            incomplete.append(entry["version"])
        for bucket in BUCKETS:
            for item in entry[bucket]:
                if _matches(item["field"], field):
                    hits.append({"version": entry["version"], "impact": bucket, **item})

    if any(h["impact"] == "meaning_changed" for h in hits):
        verdict, reason = "meaning_changed", "do NOT compare values across this range"
    elif any(h["impact"] == "banned" for h in hits):
        verdict, reason = "banned", "the field must no longer be assigned"
    elif any(h["impact"] == "mandatory_changed" for h in hits):
        verdict = "mandatory_changed"
        reason = "values are comparable; the POPULATION may differ, so compare, do not count"
    elif incomplete:
        verdict = "cannot_answer"
        reason = f"coverage is not complete for {', '.join(incomplete)}"
    else:
        verdict, reason = "unchanged", "safe to measure across this range"

    return {"field": field, "from": lo, "to": hi, "verdict": verdict,
            "reason": reason, "versions_read": [e["version"] for e in entries],
            "hits": hits}


def _print_human(result: dict) -> None:
    tag = {"unchanged": "[OK]", "meaning_changed": "[CHANGED]", "banned": "[BANNED]",
           "mandatory_changed": "[MANDATORY]", "cannot_answer": "[UNKNOWN]"}[result["verdict"]]
    span = f"{result['from'] or 'the first release'} -> {result['to'] or 'the current release'}"
    print(f"{tag} {result['field']}  {span}")
    print(f"       {result['reason']}")
    if result.get("versions_read"):
        print(f"       read {len(result['versions_read'])} version(s): "
              f"{', '.join(result['versions_read'])}")
    for hit in result["hits"]:
        print()
        print(f"  {hit['version']}  {hit['impact']}")
        if hit["impact"] == "meaning_changed":
            print(f"       was: {hit['was']}")
            print(f"       now: {hit['now']}")
            print(f"       {hit['migration']}")
        elif hit["impact"] == "mandatory_changed":
            print(f"       {hit['change']}: {hit['detail']}")
        elif hit["impact"] == "banned":
            print(f"       {hit['reason']}")
        else:
            print(f"       mentioned, no impact: {hit['note']}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Did this bundle change the meaning of an XDM field between versions?"
    )
    ap.add_argument("--field", help="the xdm.* path to ask about")
    ap.add_argument("--from", dest="lo", metavar="VERSION",
                    help="the version already installed (exclusive)")
    ap.add_argument("--to", dest="hi", metavar="VERSION",
                    help="the version being migrated to (inclusive)")
    ap.add_argument("--version", metavar="VERSION",
                    help="print one version's whole entry instead of querying a field")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    if args.version:
        entry = next((e for e in _load()["versions"] if e["version"] == args.version), None)
        if entry is None:
            print(f"no entry for {args.version}", file=sys.stderr)
            return EXIT_CANNOT_ANSWER
        print(json.dumps(entry, indent=2))
        return EXIT_CHANGED if entry["meaning_changed"] else EXIT_UNCHANGED

    if not args.field:
        ap.error("give --field (optionally with --from / --to), or --version")
        return EXIT_USAGE

    result = query(args.field, args.lo, args.hi)
    print(json.dumps(result, indent=2)) if args.json else _print_human(result)
    return {"unchanged": EXIT_UNCHANGED, "meaning_changed": EXIT_CHANGED,
            "banned": EXIT_CHANGED, "mandatory_changed": EXIT_UNCHANGED,
            "cannot_answer": EXIT_CANNOT_ANSWER}[result["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
