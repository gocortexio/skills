#!/usr/bin/env python3
# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Score generated MODEL rules against an author-curated mapping corpus.

The corpus (``tests/corpus/mapping_matrix.json``) is a list of cases, each a
raw sample event plus the CORRECT XDM output it should produce -- authored from
the provider's own documentation and the authoritative XDM schema, NOT copied
from any content pack. For each case this runs the matching worked-example rule
through ``verify_rule`` and compares the result field-for-field, then reports a
per-source and overall accuracy score.

This is the measurable "bang on" guard: a mapping regression drops the score
and fails ``tests/test_mapping_accuracy.py``. It is source-agnostic -- add a
case for any worked example, not just cloud.

Usage:
    python3 scripts/score_mappings.py --report

Python 3.9+ stdlib only.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple

SELF_DIR = Path(__file__).resolve().parent
BUNDLE = SELF_DIR.parent
CORPUS_PATH = BUNDLE / "tests" / "corpus" / "mapping_matrix.json"
WORKED = BUNDLE / "references" / "worked-examples"


def _load_verify():
    spec = importlib.util.spec_from_file_location(
        "verify_rule", SELF_DIR / "verify_rule.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


_verify = _load_verify()


def _model_rule(md_path: Path) -> str:
    """Extract the MODEL rule (``[MODEL:`` .. first closing fence) from a
    worked-example markdown file, matching the worked-example lint test."""
    lines = md_path.read_text(encoding="utf-8").splitlines()
    start = next(
        (i for i, ln in enumerate(lines) if ln.startswith("[MODEL:")), None
    )
    if start is None:
        raise ValueError(f"no MODEL rule in {md_path.name}")
    end = next(
        (j for j in range(start, len(lines)) if lines[j].strip() == "```"),
        len(lines),
    )
    return "\n".join(lines[start:end]) + "\n"


def load_corpus() -> dict:
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


def score(corpus: dict) -> Tuple[List[dict], Dict[str, Tuple[int, int]]]:
    """Run every case; return (mismatches, {source: (matched, total)})."""
    rule_cache: Dict[str, str] = {}
    mismatches: List[dict] = []
    totals: Dict[str, Tuple[int, int]] = {}

    for case in corpus.get("cases", []):
        source = case.get("source", "?")
        we = case["worked_example"]
        if we not in rule_cache:
            rule_cache[we] = _model_rule(WORKED / we)
        out = _verify.evaluate_rule(rule_cache[we], case["sample"])
        matched = 0
        expect = case.get("expect", {})
        for path, want in expect.items():
            got = out.get(path)
            if got == want:
                matched += 1
            else:
                mismatches.append({
                    "case": case.get("name", "?"),
                    "path": path,
                    "want": want,
                    "got": got,
                })
        m, t = totals.get(source, (0, 0))
        totals[source] = (m + matched, t + len(expect))
    return mismatches, totals


def _report(corpus: dict) -> int:
    mismatches, totals = score(corpus)
    print("Mapping accuracy (author-curated corpus):")
    grand_m = grand_t = 0
    for source in sorted(totals):
        m, t = totals[source]
        grand_m += m
        grand_t += t
        pct = 100.0 * m / t if t else 0.0
        print(f"  {source:22} {m}/{t}  {pct:5.1f}%")
    pct = 100.0 * grand_m / grand_t if grand_t else 0.0
    print(f"  {'OVERALL':22} {grand_m}/{grand_t}  {pct:5.1f}%")
    if mismatches:
        print("\nMismatches:")
        for mm in mismatches:
            print(f"  [{mm['case']}] {mm['path']}: want {mm['want']!r}, "
                  f"got {mm['got']!r}")
        return 1
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", action="store_true",
                    help="print the per-source accuracy report")
    args = ap.parse_args(argv)
    corpus = load_corpus()
    if args.report or True:
        return _report(corpus)


if __name__ == "__main__":
    sys.exit(main())
