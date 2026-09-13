#!/usr/bin/env python3
# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Validate the advisory corpus.

Checks every observation record against observation.schema.json, checks that
controlled-vocabulary values exist in vocab.json, checks that every pattern_id
resolves, and enforces the hygiene rules that keep restricted-source records
from leaking their origin.

Python 3.9+, standard library only. Run from the bundle root:

    python3 scripts/validate.py
    python3 scripts/validate.py --corpus path/to/corpus
"""

import argparse
import json
import os
import pathlib
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import consult as _locus
except ImportError:  # validator must still run if the consultation script is absent
    _locus = None

BUNDLE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Identifiers that betray a licensed report if they survive into a record.
# Restricted records are cited abstractly, so none of these may appear anywhere
# in the record text. Extend the list when a new source family is ingested.
# No TRAILING \b on any of these, and that is the whole point. A report identifier almost never
# appears on its own -- it appears inside the filename it was filed under, as
# TR-YYYY-NN_Subject_Words. "_" is a word character, so a trailing \b never fires after the
# digits and the identifier goes unseen exactly where it is most likely to be written down.
# That defect shipped: corpus/README.md carried a real licensed identifier in filename form for
# the life of this check, and the check could not have caught it even had it been looking.
REPORT_ID_PATTERNS = [
    re.compile(r"\bTR-\d{4}-\d+", re.I),
    re.compile(r"\bWV-\d+", re.I),
    re.compile(r"\bDRA-\d+", re.I),
    re.compile(r"\bIR-\d{4}-\d+", re.I),
    re.compile(r"\bRPT-\d+", re.I),
]

ABSTRACT_TITLE = re.compile(r"^.+ commentary on .+$")


class Problem:
    def __init__(self, where, message):
        self.where = where
        self.message = message

    def __str__(self):
        return "{}: {}".format(self.where, self.message)


# --------------------------------------------------------------------------
# Minimal JSON Schema subset validator.
# Supports the keywords this corpus actually uses: type, required, properties,
# additionalProperties, items, minItems, enum, pattern. Deliberately not a
# general implementation; a general one would mean a third-party dependency.
# --------------------------------------------------------------------------

TYPE_MAP = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "number": (int, float),
    "integer": int,
}


def check_schema(value, schema, path, problems):
    expected = schema.get("type")
    if expected:
        py = TYPE_MAP[expected]
        if expected == "boolean":
            ok = isinstance(value, bool)
        elif expected in ("number", "integer"):
            ok = isinstance(value, py) and not isinstance(value, bool)
        else:
            ok = isinstance(value, py)
        if not ok:
            problems.append(Problem(path, "expected {}, got {}".format(expected, type(value).__name__)))
            return

    if "enum" in schema and value not in schema["enum"]:
        problems.append(Problem(path, "{!r} is not one of {}".format(value, schema["enum"])))

    if "pattern" in schema and isinstance(value, str):
        if not re.search(schema["pattern"], value):
            problems.append(Problem(path, "{!r} does not match {}".format(value, schema["pattern"])))

    if isinstance(value, dict):
        props = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                problems.append(Problem(path, "missing required key {!r}".format(key)))
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in props and not key.startswith("_"):
                    problems.append(Problem(path, "unknown key {!r}".format(key)))
        for key, sub in props.items():
            if key in value:
                check_schema(value[key], sub, "{}.{}".format(path, key), problems)

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            problems.append(Problem(path, "needs at least {} item(s)".format(schema["minItems"])))
        item_schema = schema.get("items")
        if item_schema:
            for i, item in enumerate(value):
                check_schema(item, item_schema, "{}[{}]".format(path, i), problems)


# --------------------------------------------------------------------------
# Corpus checks
# --------------------------------------------------------------------------

def load_jsonl(path, problems):
    records = []
    with open(path, "r", encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, 1):
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            try:
                records.append((lineno, json.loads(line)))
            except json.JSONDecodeError as exc:
                problems.append(Problem("{}:{}".format(os.path.basename(path), lineno), "invalid JSON: {}".format(exc)))
    return records


def check_vocab(record, vocab, where, problems):
    checks = [
        ("who.product_class", record.get("who", {}).get("product_class", []), "product_class"),
        ("what.impact", record.get("what", {}).get("impact", []), "impact"),
    ]
    for path, values, vocab_key in checks:
        for value in values or []:
            if value not in vocab[vocab_key]:
                problems.append(Problem(where, "{} {!r} not in vocab.{}".format(path, value, vocab_key)))

    # source_type had drifted: the schema enum carried a value vocab.json did not,
    # and nothing compared them, so 95 records used a vocabulary entry that was not
    # in the vocabulary. A controlled list nobody checks is not controlled.
    source_type = record.get("where", {}).get("source_type")
    if source_type and source_type not in vocab["source_type"]:
        problems.append(Problem(where, "where.source_type {!r} not in vocab.source_type".format(source_type)))

    # The flat corroborating_publisher/corroborating_url pair became a list at 0.19.0,
    # because a third publisher on one mechanism had nowhere to go and got refused for a
    # schema reason rather than a judgement. additionalProperties already rejects the old
    # keys, but "unknown key" does not tell anyone what to do about it, and this file is
    # read by people migrating a draft they wrote last week.
    where_block = record.get("where") or {}
    for legacy in ("corroborating_publisher", "corroborating_url"):
        if legacy in where_block:
            problems.append(Problem(where, "where.{} was replaced at 0.19.0 by where.corroborations, "
                                           "a list of {{publisher, url}} objects. Move it there; a "
                                           "further publisher is an extra entry, never a new record."
                                    .format(legacy)))
    for i, entry in enumerate(where_block.get("corroborations") or []):
        if not isinstance(entry, dict):
            continue
        # A corroboration exists to be read by someone who cannot read the primary, so an
        # entry missing either half is worse than absent: it asserts corroboration and
        # supplies no way to check it.
        for key in ("publisher", "url"):
            if not (entry.get(key) or "").strip():
                problems.append(Problem(where, "where.corroborations[{}].{} is empty; an "
                                               "unverifiable corroboration claims more than it shows"
                                        .format(i, key)))

    role = record.get("what", {}).get("role")
    if role and role not in vocab["role"]:
        problems.append(Problem(where, "what.role {!r} not in vocab.role".format(role)))

    surface = record.get("what", {}).get("attack_surface")
    if surface and surface not in vocab["attack_surface"]:
        problems.append(Problem(where, "what.attack_surface {!r} not in vocab.attack_surface".format(surface)))

    for sector in record.get("who2", {}).get("target_sectors", []) or []:
        if sector not in vocab.get("target_sector", {}):
            problems.append(Problem(where, "who2.target_sectors {!r} not in vocab.target_sector".format(sector)))

    actor_type = record.get("who2", {}).get("actor_type")
    if actor_type and actor_type not in vocab["actor_type"]:
        problems.append(Problem(where, "who2.actor_type {!r} not in vocab.actor_type".format(actor_type)))

    for i, how in enumerate(record.get("how", [])):
        for value in how.get("evidence_type", []):
            if value not in vocab["evidence_type"]:
                problems.append(Problem(where, "how[{}].evidence_type {!r} not in vocab.evidence_type".format(i, value)))
        declared = how.get("locus")
        if declared and declared not in vocab.get("locus", {}):
            problems.append(Problem(where, "how[{}].locus {!r} not in vocab.locus".format(i, declared)))


def check_locus_map(vocab, schema, locus_map, problems):
    """Every vocabulary value must carry a locus or be explicitly deferred.

    This is the source_type lesson applied before the drift rather than after it. A
    product_class added without a locus entry fails nothing on its own: it lands in
    the tier-7 default and every finding about it is quietly labelled CONTROL. A label
    that is silently wrong is worse than one that is missing, so absence is a problem
    here and the fix is either a mapping or an entry in the matching defer_ list.
    """
    where = "corpus/schema/locus-map.json"
    if not locus_map:
        problems.append(Problem(where, "absent; LOCUS cannot be derived and every finding "
                                       "will print UNDERIVABLE"))
        return

    loci = set(vocab.get("locus") or {})
    pairs = [("by_class", "product_class", None),
             ("by_surface", "attack_surface", "defer_surface"),
             ("by_evidence", "evidence_type", "defer_evidence")]
    for table, vocab_key, defer_key in pairs:
        mapped = locus_map.get(table) or {}
        deferred = set(locus_map.get(defer_key) or []) if defer_key else set()
        for value in vocab.get(vocab_key) or {}:
            if value not in mapped and value not in deferred:
                problems.append(Problem(where, "{} {!r} is neither in {} nor deferred".format(
                    vocab_key, value, table)))
        for value, locus in mapped.items():
            if value not in (vocab.get(vocab_key) or {}):
                problems.append(Problem(where, "{}[{!r}] is not in vocab.{}".format(
                    table, value, vocab_key)))
            if locus not in loci:
                problems.append(Problem(where, "{}[{!r}] = {!r} is not in vocab.locus".format(
                    table, value, locus)))

    for key in ("default",):
        if locus_map.get(key) not in loci:
            problems.append(Problem(where, "{} {!r} is not in vocab.locus".format(
                key, locus_map.get(key))))
    if set(locus_map.get("locus_order") or []) != loci:
        problems.append(Problem(where, "locus_order does not match vocab.locus"))

    # The schema enum and the vocabulary are two copies of one list, which is exactly
    # how source_type drifted. Compare them rather than trusting they agree.
    enum = (((schema.get("properties") or {}).get("how") or {}).get("items") or {}) \
        .get("properties", {}).get("locus", {}).get("enum")
    if enum is not None and set(enum) != loci:
        problems.append(Problem("corpus/schema/observation.schema.json",
                                "how[].locus enum does not match vocab.locus"))

    # CONNECTOR is keyed on evidence_type and nothing compared them either. Free check
    # while the file is open; it passes today and stops the next addition drifting.
    if _locus is not None:
        for value in sorted(set(vocab.get("evidence_type") or {}) - set(_locus.CONNECTOR)):
            problems.append(Problem("scripts/consult.py",
                                    "CONNECTOR has no entry for evidence_type {!r}, so its "
                                    "DATA_GAP would name no feed to acquire".format(value)))
        for value in sorted(set(_locus.CONNECTOR) - set(vocab.get("evidence_type") or {})):
            problems.append(Problem("scripts/consult.py",
                                    "CONNECTOR[{!r}] is not in vocab.evidence_type".format(value)))


def check_disclosure(record, where, problems):
    """Restricted records must not carry anything that points back at the report."""
    source = record.get("where", {})
    if source.get("disclosure") != "restricted":
        return

    if source.get("url"):
        problems.append(Problem(where, "restricted source carries a url; remove it"))

    title = source.get("title", "")
    if not ABSTRACT_TITLE.match(title):
        problems.append(Problem(where, "restricted source title {!r} is not of the form '<Publisher> commentary on <subject>'".format(title)))

    blob = json.dumps(record)
    for pattern in REPORT_ID_PATTERNS:
        found = pattern.search(blob)
        if found:
            problems.append(Problem(where, "restricted record contains report identifier {!r}".format(found.group(0))))

    # Rule 4 of corpus/README.md "Restricted sources": YYYY-MM at finest. An exact
    # publication date plus a subject line is close enough to a fingerprint to
    # identify the report. Coarser than month is fine; finer is a disclosure leak.
    when = record.get("when", {}) or {}
    if when.get("precision") not in ("month", "year"):
        problems.append(Problem(where, "restricted record has when.precision {!r}; must be 'month' or coarser".format(
            when.get("precision"))))
    for key, value in sorted(when.items()):
        if key != "precision" and isinstance(value, str) and len(value) > 7:
            problems.append(Problem(where, "restricted record when.{} is {!r}; month precision at finest".format(key, value)))


def check_markdown_disclosure(root, problems):
    """The prose is held to the same rule as the records.

    `check_disclosure` runs per record, so every markdown file in the bundle was exempt from
    the rule those files themselves document. corpus/README.md stated "No report identifier
    anywhere in the record. validate.py fails the build if it finds one" and then printed a
    real licensed identifier two lines later as its worked example. Nothing failed, because
    nothing read it.

    Documentation that states a disclosure rule is exactly where a specimen of the forbidden
    thing ends up, because an example feels like an exception. It is not one.
    """
    for path in sorted(root.rglob("*.md")):
        if ".git" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            for pattern in REPORT_ID_PATTERNS:
                found = pattern.search(line)
                if found:
                    problems.append(Problem(
                        "{}:{}".format(path.name, number),
                        "shipped markdown carries report identifier {!r}. Restricted sources "
                        "are cited abstractly; use a placeholder such as TR-<year>-<n> in an "
                        "example rather than a real filing.".format(found.group(0))))


def check_record_type(record, where, problems):
    """The two record shapes have different obligations; the schema alone cannot express this."""
    kind = record.get("record_type")
    rid = record.get("id", "")

    if kind == "observation":
        if not record.get("how"):
            problems.append(Problem(where, "observation carries no how block; detection logic is what makes it an observation"))
        if not rid.startswith("obs-"):
            problems.append(Problem(where, "observation id {!r} should use the obs- prefix".format(rid)))

    elif kind == "exposure":
        if not rid.startswith("exp-"):
            problems.append(Problem(where, "exposure id {!r} should use the exp- prefix".format(rid)))
        has_vulns = bool(record.get("what", {}).get("vulnerabilities"))
        has_versions = bool(record.get("who", {}).get("versions_affected"))
        if not (has_vulns or has_versions):
            problems.append(Problem(where, "exposure asserts nothing; needs what.vulnerabilities or who.versions_affected"))
        if not record.get("where", {}).get("url"):
            problems.append(Problem(where, "exposure has no where.url; a generated record must be traceable to its advisory"))


# Twelve markers once carried response doctrine as prose inside a computed `expr`,
# where nothing could query it and it reached a caller at the lowest fidelity tier.
# The vocabulary below is what those assertions had in common and what a computation
# over telemetry never contains: they name a PLAN or a programme capability rather
# than a quantity. Deliberately narrow. `count_distinct(page) by session` and
# `now() - vendor_fix_release_date` are real computations and must keep passing, so
# this does not try to judge prose generally, only the plan-shaped kind.
# No \b anchors: underscore is a word character, so \bresponse_plan\b never matches
# inside response_plan_orders and the first version of this guard was inert.
PLAN_ASSERTION = re.compile(
    r"response_plan|containment_plan|remediation_plan|communications_plan"
    r"|emergency_response_plan|recovery_tooling|verify_eradication"
    r"|_plan_(?:orders|includes|assumes|covers)")


def check_markers(record, vocab, where, problems, coverage, pattern_markers=None):
    """Markers are what detection rules get built from, so they are held to a
    tighter standard than the prose: a controlled type, a literal value, and an
    explicit computation where the condition is derived rather than looked up."""
    marker_types = vocab.get("marker_type", {})
    rule_shapes = vocab.get("rule_shape", {})
    for i, how in enumerate(record.get("how", [])):
        base = "how[{}]".format(i)
        shape = how.get("rule_shape")
        if shape and shape not in rule_shapes:
            problems.append(Problem(where, "{}.rule_shape {!r} is not in vocab".format(base, shape)))
        markers = how.get("markers") or []
        # Generic markers live on the shared pattern; a record only needs to carry
        # the literals specific to its own source. Either satisfies the contract.
        inherited = bool((pattern_markers or {}).get(how.get("pattern_id")))
        fidelity = how.get("fidelity")
        coverage["how_total"] += 1
        if fidelity == "alert":
            coverage["alert_total"] += 1
        if markers:
            coverage["how_with_markers"] += 1
            if fidelity == "alert":
                coverage["alert_with_markers"] += 1
            if not shape:
                problems.append(Problem(where, "{} carries markers but no rule_shape; a generator cannot tell what query to build".format(base)))
        elif inherited:
            coverage["how_inherited"] += 1
            if fidelity == "alert":
                coverage["alert_with_markers"] += 1
        elif fidelity == "alert" and shape not in ("inventory", "absence"):
            coverage["alert_missing"].append("{} {}".format(where, base))
        for j, m in enumerate(markers):
            at = "{}.markers[{}]".format(base, j)
            mtype = m.get("type")
            if mtype not in marker_types:
                problems.append(Problem(where, "{}.type {!r} is not in vocab marker_type".format(at, mtype)))
            value = m.get("value")
            if value is None or value == "" or value == []:
                problems.append(Problem(where, "{}.value is empty; a marker must carry a literal observable".format(at)))
            if m.get("match") == "in" and not isinstance(value, list):
                problems.append(Problem(where, "{}.match is 'in' so value must be an array".format(at)))
            if mtype == "computed" and not m.get("expr"):
                problems.append(Problem(where, "{}.type is 'computed' so expr is mandatory, otherwise it is not buildable".format(at)))
            if mtype != "computed" and m.get("expr"):
                problems.append(Problem(where, "{}.expr is only valid on a computed marker".format(at)))
            if mtype == "computed":
                doctrine = PLAN_ASSERTION.search(m.get("expr") or "")
                if doctrine:
                    problems.append(Problem(where, "{}.expr asserts a response plan ({!r}) rather "
                                            "than computing over telemetry. Response doctrine "
                                            "belongs in corpus/reference/response-doctrine.json, "
                                            "where it can be cited and matched on class and "
                                            "impact.".format(at, doctrine.group(0))))


def check_dates(record, where, problems):
    date_re = re.compile(r"^\d{4}(-\d{2}(-\d{2})?)?$")
    for key, value in (record.get("when") or {}).items():
        if key == "precision":
            continue
        if not date_re.match(str(value)):
            problems.append(Problem(where, "when.{} {!r} is not YYYY, YYYY-MM or YYYY-MM-DD".format(key, value)))


def main():
    parser = argparse.ArgumentParser(description="Validate the advisory corpus.")
    parser.add_argument("--corpus", default=os.path.join(BUNDLE_ROOT, "corpus"))
    parser.add_argument("--gaps", action="store_true",
                        help="list the alert-fidelity blocks with no markers, and the cited "
                             "technique ids that resolve against nothing")
    args = parser.parse_args()

    schema_dir = os.path.join(args.corpus, "schema")
    with open(os.path.join(schema_dir, "observation.schema.json"), "r", encoding="utf-8") as handle:
        schema = json.load(handle)
    with open(os.path.join(schema_dir, "vocab.json"), "r", encoding="utf-8") as handle:
        vocab = json.load(handle)
    locus_map = {}
    locus_map_path = os.path.join(schema_dir, "locus-map.json")
    if os.path.exists(locus_map_path):
        with open(locus_map_path, "r", encoding="utf-8") as handle:
            locus_map = json.load(handle)

    problems = []
    # The prose ships too. Scanned from the bundle root rather than from --corpus, because the
    # file that leaked a licensed identifier was corpus/README.md's sibling documentation and
    # a corpus-scoped walk would have missed SKILL.md and README.md entirely.
    check_markdown_disclosure(pathlib.Path(BUNDLE_ROOT), problems)
    locus_counts = {}
    coverage = {"how_total": 0, "how_with_markers": 0, "alert_total": 0,
                "alert_with_markers": 0, "alert_missing": [], "how_inherited": 0}

    pattern_ids = set()
    pattern_markers = {}
    cited_techniques = {}
    patterns_path = os.path.join(args.corpus, "patterns", "patterns.jsonl")
    if os.path.exists(patterns_path):
        for lineno, pattern in load_jsonl(patterns_path, problems):
            pid = pattern.get("id")
            if not pid:
                problems.append(Problem("patterns.jsonl:{}".format(lineno), "pattern has no id"))
            elif pid in pattern_ids:
                problems.append(Problem("patterns.jsonl:{}".format(lineno), "duplicate pattern id {!r}".format(pid)))
            else:
                pattern_ids.add(pid)
                if pattern.get("markers"):
                    pattern_markers[pid] = pattern["markers"]
                for tid in pattern.get("technique") or []:
                    cited_techniques.setdefault(tid, set()).add(pid)

    obs_dir = os.path.join(args.corpus, "observations")
    seen_ids = {}
    count = 0

    files = sorted(f for f in os.listdir(obs_dir) if f.endswith(".jsonl")) if os.path.isdir(obs_dir) else []
    for filename in files:
        path = os.path.join(obs_dir, filename)
        for lineno, record in load_jsonl(path, problems):
            count += 1
            # The record id carries the vendor. It used to come from the filename,
            # back when observations were one file per vendor; a line number alone
            # in a 1,149-line file says nothing about what the record is.
            where = "{}:{}".format(filename, lineno)
            if record.get("id"):
                where = "{} ({})".format(where, record["id"])
            check_schema(record, schema, where, problems)
            check_vocab(record, vocab, where, problems)
            check_disclosure(record, where, problems)
            check_record_type(record, where, problems)
            check_dates(record, where, problems)
            check_markers(record, vocab, where, problems, coverage, pattern_markers)

            rid = record.get("id")
            if rid:
                if rid in seen_ids:
                    problems.append(Problem(where, "duplicate id {!r}, first seen at {}".format(rid, seen_ids[rid])))
                else:
                    seen_ids[rid] = where

            for i, how in enumerate(record.get("how", [])):
                # Tallied here rather than reported per record: the number that says
                # the axis has broken is the distribution, not any single label. A
                # locus that collapses to nothing, or swallows everything, shows up
                # in one line at the bottom and nowhere else.
                if locus_map:
                    locus, span, basis = _locus.locus_for(record, how, None, locus_map)
                    locus_counts[locus] = locus_counts.get(locus, 0) + 1
                    if span:
                        locus_counts["_span"] = locus_counts.get("_span", 0) + 1
                    if basis.startswith("tier=declared"):
                        locus_counts["_declared"] = locus_counts.get("_declared", 0) + 1
                pid = how.get("pattern_id")
                if pid and pid not in pattern_ids:
                    problems.append(Problem(where, "how[{}].pattern_id {!r} is not in patterns.jsonl".format(i, pid)))
                for tid in how.get("technique") or []:
                    cited_techniques.setdefault(tid, set()).add(rid or where)

    check_locus_map(vocab, schema, locus_map, problems)

    for problem in problems:
        print(problem)

    pct = lambda a, b: (100 * a // b) if b else 0
    print("\n{} record(s) across {} file(s), {} pattern(s), {} problem(s)".format(
        count, len(files), len(pattern_ids), len(problems)))
    print("marker coverage: {}/{} how-blocks ({}%), {}/{} alert-fidelity blocks ({}%)".format(
        coverage["how_with_markers"] + coverage["how_inherited"], coverage["how_total"],
        pct(coverage["how_with_markers"] + coverage["how_inherited"], coverage["how_total"]),
        coverage["alert_with_markers"], coverage["alert_total"], pct(coverage["alert_with_markers"], coverage["alert_total"])))
    if coverage["alert_missing"] and args.gaps:
        print("\nalert-fidelity blocks with no markers (these cannot become rules):")
        for g in coverage["alert_missing"]:
            print("  " + g)
    if coverage["alert_missing"]:
        print("{} alert-fidelity block(s) still have no markers; run with --gaps to list them".format(len(coverage["alert_missing"])))

    if locus_counts:
        order = locus_map.get("locus_order") or sorted(k for k in locus_counts if k[0] != "_")
        total = sum(v for k, v in locus_counts.items() if k[0] != "_")
        print("locus derivation: {} how-blocks -> {}; {} declared override(s), {} carrying a span".format(
            total, " ".join("{}={}".format(k, locus_counts.get(k, 0)) for k in order),
            locus_counts.get("_declared", 0), locus_counts.get("_span", 0)))

    # Technique resolution against the shipped reference. Counted because two of these
    # went unnoticed while the corpus-state table read 395 of 395.
    #
    # The reference carried Enterprise and ICS only until 2026-08-27, which made a
    # Mobile-domain id out of scope rather than wrong -- T1451 and T1430 were cited by
    # four pieces of content and resolved against nothing by design. It now carries all
    # three domains and the count is 410/410.
    #
    # Still reported and never fatal, but for a different reason now. ATT&CK renumbers
    # and revokes between releases, so an id that stops resolving is a signal to go and
    # look at the corpus, not a broken build. Making it fatal would turn a maintenance
    # signal into a blocked release on the day upstream publishes v20.
    ref_path = os.path.join(args.corpus, "reference", "attack-techniques.json")
    if cited_techniques and os.path.exists(ref_path):
        try:
            with open(ref_path, "r", encoding="utf-8") as handle:
                known = set((json.load(handle).get("techniques") or {}).keys())
        except (OSError, ValueError):
            known = None
        if known:
            unresolved = sorted(t for t in cited_techniques if t not in known)
            total = len(cited_techniques)
            print("technique ids resolving against the shipped reference: {}/{}".format(
                total - len(unresolved), total))
            if unresolved:
                print("{} cited technique id(s) resolve against nothing; run with --gaps to list them".format(
                    len(unresolved)))
                if args.gaps:
                    print("\ncited technique ids not in the shipped reference:")
                    for tid in unresolved:
                        print("  {} cited by {}".format(tid, ", ".join(sorted(cited_techniques[tid]))))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
