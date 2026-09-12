#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: GoCortexIO
"""xdm_const_mapper.py --field <xdm.path> --values v1,v2,... [--temp _x]
   xdm_const_mapper.py --banded [--temp _score] [--thresholds 80,50,30]

Emit the if()-chain that maps a vendor categorical column to the right
XDM_CONST values, or the banded severity / log-level chains for a numeric
score column. This removes the most error-prone hand-written step in rule
authoring.

Categorical mode (--field):
    Resolves the field's XDM_CONST group from the bundle references,
    token-matches each observed value to a member of that closed list,
    and prints the assignment. Values with no deterministic match are
    OMITTED and listed in a trailing comment -- the tool never invents a
    constant.

Banded mode (--banded):
    Prints the paired xdm.alert.severity (string bands) and
    xdm.event.log_level (XDM_CONST.LOG_LEVEL_*) if-chains for a numeric
    score temp, highest threshold first.

The emitted snippet is plain XQL ready to paste into the drain stage.

Exit codes:
    0   snippet emitted
    1   argument error, or no value mapped to a constant

Python 3.9+ stdlib only.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _xdm_schema import load_xdm_consts, load_xdm_paths  # noqa: E402


_STOP_STEM_SUFFIXES = ("ies", "ing", "ure", "ed", "es", "s", "e")


def _tokens(s: str) -> set:
    return {t for t in re.split(r"[^a-z0-9]+", s.lower()) if t}


def _stem(t: str) -> str:
    for suf in _STOP_STEM_SUFFIXES:
        if t.endswith(suf) and len(t) - len(suf) >= 3:
            return t[: -len(suf)]
    return t


def _stem_set(s: str) -> set:
    return {_stem(t) for t in _tokens(s)}


def _member_suffix(member: str, group: str) -> str:
    """The distinguishing part of a constant: drop the XDM_CONST.GROUP_ prefix."""
    tail = member[len("XDM_CONST."):]
    if tail.startswith(group + "_"):
        return tail[len(group) + 1:]
    return tail


def best_match(value: str, group: str, members: List[str]) -> Optional[str]:
    """Pick the constant in ``members`` that best matches ``value`` by
    stemmed-token overlap. Returns None when nothing overlaps (never
    invents a constant)."""
    vstems = _stem_set(value)
    if not vstems:
        return None
    best: Optional[str] = None
    best_score = 0
    for m in sorted(members):  # deterministic tie-break
        mstems = _stem_set(_member_suffix(m, group))
        overlap = len(vstems & mstems)
        if overlap > best_score:
            best_score = overlap
            best = m
    return best if best_score > 0 else None


def map_categorical(
    field: str, values: List[str], temp: str
) -> Tuple[str, List[str]]:
    """Return (snippet, unmapped_values). Raises ValueError if the field
    is not an XDM_CONST-typed field in the schema."""
    paths = load_xdm_paths()
    meta = paths.get(field)
    if meta is None:
        raise ValueError(f"{field} is not a known XDM field")
    group = meta["const_group"]
    if not group:
        raise ValueError(
            f"{field} is type {meta['type']!r}, not an XDM_CONST field"
        )
    members = sorted(load_xdm_consts().get(group, set()))
    if not members:
        raise ValueError(f"no documented constants for group {group}")

    pairs: List[Tuple[str, str]] = []
    unmapped: List[str] = []
    seen_values: set = set()
    for v in values:
        if v in seen_values:
            continue
        seen_values.add(v)
        match = best_match(v, group, members)
        if match:
            pairs.append((v, match))
        else:
            unmapped.append(v)

    if not pairs:
        raise ValueError(
            f"none of the values mapped to a {group} constant; map by hand "
            "or use the String fallback field (see pitfall-traps.md)"
        )

    lines = [f"{field} = if("]
    for v, const in pairs:
        lines.append(f'    {temp} = "{v}", {const},')
    # Drop the trailing comma on the last branch (no default -> null-safe).
    lines[-1] = lines[-1].rstrip(",")
    lines.append(")")
    snippet = "\n".join(lines)
    if unmapped:
        snippet += "\n// unmapped (no " + group + " constant; map by hand or use the String fallback): " + ", ".join(unmapped)
    return snippet, unmapped


def banded(temp: str, thresholds: List[int]) -> str:
    """Return the paired severity + log_level banded if-chains."""
    if len(thresholds) != 3:
        raise ValueError("banded mode needs exactly 3 thresholds (high,med,low)")
    hi, md, lo = thresholds
    return (
        "xdm.alert.severity = if(\n"
        f'    {temp} >= {hi}, "Critical",\n'
        f'    {temp} >= {md}, "High",\n'
        f'    {temp} >= {lo}, "Medium",\n'
        f'    {temp} != null, "Low"),\n'
        "xdm.event.log_level = if(\n"
        f"    {temp} >= {hi}, XDM_CONST.LOG_LEVEL_CRITICAL,\n"
        f"    {temp} >= {md}, XDM_CONST.LOG_LEVEL_ERROR,\n"
        f"    {temp} >= {lo}, XDM_CONST.LOG_LEVEL_WARNING,\n"
        f"    {temp} != null, XDM_CONST.LOG_LEVEL_INFORMATIONAL)"
    )


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Emit XDM_CONST if-chains for a vendor categorical "
        "column, or banded severity / log-level chains for a score column."
    )
    ap.add_argument("--field", help="target XDM_CONST field, e.g. xdm.event.outcome")
    ap.add_argument("--values", help="comma-separated observed vendor values")
    ap.add_argument("--temp", default="_value", help="source temp name (default _value)")
    ap.add_argument("--banded", action="store_true", help="emit banded score chains")
    ap.add_argument(
        "--thresholds",
        default="80,50,30",
        help="banded thresholds high,med,low (default 80,50,30)",
    )
    args = ap.parse_args(argv[1:])

    if args.banded:
        try:
            thresholds = [int(x) for x in args.thresholds.split(",")]
            sys.stdout.write(banded(args.temp, thresholds) + "\n")
        except ValueError as exc:
            sys.stderr.write(f"error: {exc}\n")
            return 1
        return 0

    if not args.field or not args.values:
        sys.stderr.write(
            "error: categorical mode needs --field and --values (or use "
            "--banded)\n"
        )
        return 1
    values = [v.strip() for v in args.values.split(",") if v.strip()]
    try:
        snippet, _ = map_categorical(args.field, values, args.temp)
    except ValueError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1
    sys.stdout.write(snippet + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
