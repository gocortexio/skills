#!/usr/bin/env python3
# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Validate the advisory corpus.

Checks every observation record against observation.schema.json, checks that
controlled-vocabulary values exist in vocab.json, checks that every pattern_id
resolves, checks every marker's field against the bundled XDM snapshot and its
combination key against the marker contract, and enforces the hygiene rules that
keep restricted-source records from leaking their origin.

Python 3.9+, standard library only. Run from the bundle root:

    python3 scripts/validate.py
    python3 scripts/validate.py --corpus path/to/corpus
"""

import argparse
import collections
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
try:
    # The binding check asks the emitter itself, so the validator and the skeleton can never
    # disagree about whether a marker's field exists. The emitter imports consult.py, so this
    # is absent whenever that is, and the check says it was skipped rather than passing.
    import emit_xql as _emit
except ImportError:
    _emit = None

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


def check_locus_map(vocab, schema, locus_map, problems, attack=None):
    """Every vocabulary value must carry a locus or be explicitly deferred.

    This is the source_type lesson applied before the drift rather than after it. A
    product_class added without a locus entry fails nothing on its own: it lands in
    the tier-7 default and every finding about it is quietly labelled CONTROL. A label
    that is silently wrong is worse than one that is missing, so absence is a problem
    here and the fix is either a mapping or an entry in the matching defer_ list.

    Returns the number of problems found in the map itself, because the caller derives
    every block through the map afterwards and must not do so over one it knows is broken.
    """
    where = "corpus/schema/locus-map.json"
    if not locus_map:
        problems.append(Problem(where, "absent; LOCUS cannot be derived and every finding "
                                       "will print UNDERIVABLE"))
        return 1
    before = len(problems)

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
        # Only tests/test_header_counts.py checked this, so a corpus validated clean while
        # carrying a value the ladder would place and the file said it had set aside.
        for value in sorted(deferred & set(mapped)):
            problems.append(Problem(where, "{} {!r} is both in {} and in {}; a value is "
                                           "mapped or deferred, never both".format(
                                               vocab_key, value, table, defer_key)))
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

    # The two lists the ladder looks a value up in by name. Each was a KeyError inside
    # locus_for() rather than a problem here: a supply surface with no by_surface entry
    # crashed this script with a traceback, and a non-product class with no by_class entry
    # would do the same now that the tier reads its locus from the table.
    by_surface = locus_map.get("by_surface") or {}
    for value in locus_map.get("surface_supply") or []:
        if value not in by_surface:
            problems.append(Problem(where, "surface_supply {!r} has no entry in by_surface, so "
                                           "the ladder cannot place a record carrying it".format(value)))
    by_class = locus_map.get("by_class") or {}
    for value in locus_map.get("nonproduct_class") or []:
        if value not in by_class:
            problems.append(Problem(where, "nonproduct_class {!r} has no entry in by_class, so "
                                           "the ladder cannot place a record carrying it".format(value)))

    # A span-only surface still commits a locus, which is what the span carries, so it must
    # be mapped. Deferred as well, it would commit nothing and the list would be a comment;
    # in surface_supply as well, the supply tier would decide on it before the list is read.
    for value in locus_map.get("surface_span_only") or []:
        if value not in by_surface:
            problems.append(Problem(where, "surface_span_only {!r} has no entry in by_surface, so "
                                           "it has no locus to carry as a span".format(value)))
        for other in ("defer_surface", "surface_supply"):
            if value in (locus_map.get(other) or []):
                problems.append(Problem(where, "surface_span_only {!r} is also in {}; a span-only "
                                               "surface neither decides nor is deferred".format(value, other)))

    # Each generator tag names the source_type its generator writes, which is what the
    # per-record drift check below compares against. A value outside the vocabulary would
    # make that check refuse every record the tag is on.
    tags = locus_map.get("untrusted_surface_tags")
    if tags is not None and not isinstance(tags, dict):
        problems.append(Problem(where, "untrusted_surface_tags must map each generator tag to the "
                                       "where.source_type its generator writes"))
    for tag, source_type in (tags if isinstance(tags, dict) else {}).items():
        if source_type not in (vocab.get("source_type") or {}):
            problems.append(Problem(where, "untrusted_surface_tags[{!r}] = {!r} is not in "
                                           "vocab.source_type".format(tag, source_type)))

    # The per-block surface rule reads two technique lists and the operation tier one list of
    # operation names. A key naming a surface that is not a supply surface would be read by
    # nothing, and a technique the reference does not file under initial-access would decide
    # blocks on a claim ATT&CK does not make. way_in_techniques is the reference's own list,
    # held equal to it, so an ATT&CK upgrade that adds or withdraws one fails here until the
    # list follows. Skipped only when the reference is absent, which is itself reported below.
    vectors = locus_map.get("surface_vector_techniques")
    if vectors is not None and not isinstance(vectors, dict):
        problems.append(Problem(where, "surface_vector_techniques must map each supply surface to "
                                       "the technique ids its vector is filed under"))
        vectors = {}
    way_in = locus_map.get("way_in_techniques")
    if way_in is not None and not isinstance(way_in, list):
        problems.append(Problem(where, "way_in_techniques must be a list of technique ids"))
        way_in = []
    for surface, ids in (vectors or {}).items():
        if surface not in (locus_map.get("surface_supply") or []):
            problems.append(Problem(where, "surface_vector_techniques[{!r}] is not a supply surface, so "
                                           "nothing reads it".format(surface)))
        for tid in ids or []:
            if tid not in (way_in or []):
                problems.append(Problem(where, "surface_vector_techniques[{!r}] names {}, which is not in "
                                               "way_in_techniques".format(surface, tid)))
    for surface in locus_map.get("surface_supply") or []:
        if vectors is not None and not (vectors or {}).get(surface):
            problems.append(Problem(where, "supply surface {!r} has no surface_vector_techniques entry, "
                                           "so it can reach no block".format(surface)))
    if attack and way_in is not None:
        filed = {tid for tid, entry in attack.items()
                 if "." not in tid and "initial-access" in (entry.get("tactics") or [])
                 and not entry.get("revoked") and not entry.get("deprecated")}
        for tid in sorted(set(way_in) - filed):
            problems.append(Problem(where, "way_in_techniques lists {}, which the shipped ATT&CK reference "
                                           "does not file, live, under initial-access".format(tid)))
        for tid in sorted(filed - set(way_in)):
            problems.append(Problem(where, "way_in_techniques omits {}, which the shipped ATT&CK reference "
                                           "files under initial-access".format(tid)))
    operations = locus_map.get("non_administrative_operations")
    if operations is not None and (not isinstance(operations, list)
                                   or not all(isinstance(v, str) and v for v in operations)):
        problems.append(Problem(where, "non_administrative_operations must be a list of operation names"))

    # The two lists the evidence tests read. admin_api_unread places a block off a class
    # because the block never reads the administrative API the class is, and admin_api_listed
    # places one onto a class listed later because it reads nothing else; a class that is not
    # on MANAGEMENT is not one, and a non-product class never decides by class at all, so
    # either listed would be a rule that reads as applied and moves nothing, or moves the
    # wrong thing. A contested evidence type must be one the ladder maps: deferred, it already
    # commits nothing, and unmapped, the list would be a comment.
    api_classes = locus_map.get("administrative_api_classes")
    if api_classes is not None and not isinstance(api_classes, list):
        problems.append(Problem(where, "administrative_api_classes must be a list of product classes"))
        api_classes = []
    for value in api_classes or []:
        if by_class.get(value) != "MANAGEMENT":
            problems.append(Problem(where, "administrative_api_classes {!r} is not placed on MANAGEMENT "
                                           "in by_class, so it is not an administrative API class".format(value)))
        if value in (locus_map.get("nonproduct_class") or []):
            problems.append(Problem(where, "administrative_api_classes {!r} is a non-product class, "
                                           "which never decides by class".format(value)))
    contested = locus_map.get("contested_evidence")
    if contested is not None and not isinstance(contested, list):
        problems.append(Problem(where, "contested_evidence must be a list of evidence types"))
        contested = []
    for value in contested or []:
        if value not in (locus_map.get("by_evidence") or {}):
            problems.append(Problem(where, "contested_evidence {!r} has no entry in by_evidence, so "
                                           "there is no reading to contest".format(value)))
        if value in (locus_map.get("defer_evidence") or []):
            problems.append(Problem(where, "contested_evidence {!r} is also deferred, and a deferred "
                                           "type already commits nothing".format(value)))

    # tier_order was documentation that nothing read. Reversing it changed no output and
    # failed no check, so the file could describe a ladder the code does not run. span_order
    # is held to the code the same way from the release that introduced it.
    if _locus is not None and list(locus_map.get("tier_order") or []) != list(_locus.LOCUS_TIERS):
        problems.append(Problem(where, "tier_order {} does not match the ladder scripts/consult.py "
                                       "runs, {}".format(locus_map.get("tier_order"),
                                                         list(_locus.LOCUS_TIERS))))
    if _locus is not None and list(locus_map.get("span_order") or []) != list(_locus.LOCUS_SPAN_SOURCES):
        problems.append(Problem(where, "span_order {} does not match the span sources "
                                       "scripts/consult.py tries, {}".format(
                                           locus_map.get("span_order"), list(_locus.LOCUS_SPAN_SOURCES))))
    check_identifier_reading(locus_map, where, problems)
    map_problems = len(problems) - before

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
    return map_problems


def check_identifier_reading(locus_map, where, problems):
    """identifier_reading is the table the generators write what.identifier_signals from and
    check_identifier_signals() holds every entry to, so a table that cannot be read the way
    both read it fails here, before any record is read through it (0.44.0)."""
    table = locus_map.get("identifier_reading")
    if not isinstance(table, dict):
        problems.append(Problem(where, "identifier_reading must be a table: the generators write "
                                       "what.identifier_signals from it and this file holds every "
                                       "entry to it"))
        return
    loci = list(locus_map.get("locus_order") or [])
    by_class = locus_map.get("by_class") or {}
    fields = table.get("fields")
    if not isinstance(fields, dict) or set(fields) != set(locus_map.get("untrusted_surface_tags") or {}):
        problems.append(Problem(where, "identifier_reading.fields must name the fields read for "
                                       "exactly the generator tags in untrusted_surface_tags, {}".format(
                                           sorted(locus_map.get("untrusted_surface_tags") or {}))))
    undecomposed = table.get("undecomposed_classes")
    if not isinstance(undecomposed, list):
        problems.append(Problem(where, "identifier_reading.undecomposed_classes must be a list"))
        undecomposed = []
    for value in undecomposed:
        if value not in by_class:
            problems.append(Problem(where, "identifier_reading.undecomposed_classes {!r} has no "
                                           "entry in by_class".format(value)))
    for value in sorted(c for c, locus in by_class.items() if locus == "ENDPOINT"):
        if value not in undecomposed:
            problems.append(Problem(where, "identifier_reading.undecomposed_classes leaves out {!r}, "
                                           "which by_class places on ENDPOINT, the locus the "
                                           "vocabulary gives no plane decomposition".format(value)))
    if not isinstance(table.get("class_requires_prefix"), str) or not table.get("class_requires_prefix"):
        problems.append(Problem(where, "identifier_reading.class_requires_prefix must be a class "
                                       "prefix, or a VPN client on an endpoint reads as a gateway"))
    names = set()
    for index, rule in enumerate(table.get("rules") or []):
        label = "identifier_reading.rules[{}]".format(index)
        if not isinstance(rule, dict):
            problems.append(Problem(where, "{} must be an object".format(label)))
            continue
        name = rule.get("rule")
        if not name or name in names:
            problems.append(Problem(where, "{} needs a rule name no other rule carries, {!r}".format(
                label, name)))
        names.add(name)
        if bool(rule.get("locus")) == bool(rule.get("class")):
            problems.append(Problem(where, "{} ({}) must carry exactly one of locus or class".format(
                label, name)))
        if rule.get("locus") and rule["locus"] not in loci:
            problems.append(Problem(where, "{} ({}) locus {!r} is not in locus_order".format(
                label, name, rule["locus"])))
        if rule.get("class") and rule["class"] not in by_class:
            problems.append(Problem(where, "{} ({}) class {!r} has no entry in by_class".format(
                label, name, rule["class"])))
        try:
            re.compile(rule.get("pattern") or "")
        except re.error as err:
            problems.append(Problem(where, "{} ({}) pattern does not compile: {}".format(
                label, name, err)))
        if not rule.get("pattern"):
            problems.append(Problem(where, "{} ({}) has no pattern".format(label, name)))
        if "unless" in rule:
            try:
                if not isinstance(rule["unless"], str) or not rule["unless"]:
                    raise re.error("it must be a non-empty pattern")
                re.compile(rule["unless"])
            except re.error as err:
                problems.append(Problem(where, "{} ({}) unless does not compile: {}".format(
                    label, name, err)))
    if not names:
        problems.append(Problem(where, "identifier_reading.rules is empty"))


def check_identifier_signals(record, locus_map, where, problems):
    """what.identifier_signals must be what the rule in identifier_reading would write.

    A generator writes it from each identifier's own catalogue or advisory text, and a locus
    every identifier reads decides a generated exposure's primary, so a hand edit or a stale
    regeneration would place a record by words its source does not say. Every entry is held
    to the table; and where the record's summary quotes an identifier's catalogue description,
    that quotation is read again with the same function the generator calls, and the entries
    it yields must be the record's, both ways. A title or database description is not quoted
    by identifier anywhere in a record, so those entries are held to the table only.

    A generated exposure with no key at all is read as carrying none, because the generators
    leave the key out where the rule reads nothing. Until a review of 0.44.0 an absent key
    returned at once, so the re-read ran on the 59 catalogue records carrying the field and
    not on the other 640, and a record whose field was dropped passed with no problem while
    its exposure moved plane.
    """
    entries = (record.get("what") or {}).get("identifier_signals")
    rid = record.get("id")
    tags = locus_map.get("untrusted_surface_tags") or {}
    carried = [t for t in tags if t in (record.get("tags") or [])]
    absent = entries is None
    if absent:
        if record.get("record_type") != "exposure" or not carried:
            return
        entries = []
    if record.get("record_type") != "exposure" or not carried:
        problems.append(Problem(where, "what.identifier_signals on {}, which no generator wrote: "
                                       "it is written from a generated exposure's own catalogue or "
                                       "advisory text, and an observation or a hand-written exposure "
                                       "states its plane in its own fields; remove it".format(rid)))
        return
    table = (_locus.Q.identifier_reading(locus_map) if _locus is not None else None)
    if not table:
        return
    rules = {name: (locus, cls, regex) for name, locus, cls, regex in table["rules"]}
    tag = carried[0]
    fields = table["fields"].get(tag) or []
    nonproduct = set(locus_map.get("nonproduct_class") or [])
    classes = list((record.get("who") or {}).get("product_class") or [])
    productive = [c for c in classes if c not in nonproduct]
    if productive and productive[0] in table["undecomposed"]:
        if absent:
            return
        problems.append(Problem(where, "{} lists {} first, which identifier_reading does not read "
                                       "(undecomposed_classes), and carries what.identifier_signals; "
                                       "regenerate".format(rid, productive[0])))
        return
    ids = list((record.get("what") or {}).get("vulnerabilities") or [])
    prefixed = any(c.startswith(table["prefix"]) for c in classes) if table["prefix"] else False
    seen, last = set(), (-1, -1)
    for entry in entries:
        ident, name = entry.get("id"), entry.get("rule")
        phrase = entry.get("phrase")
        said = "{} {} rule {!r} words {!r}".format(rid, ident, name, phrase)
        kind = "locus" if entry.get("locus") else "class"
        if ident not in ids:
            problems.append(Problem(where, "{}: the identifier is not in what.vulnerabilities; "
                                           "regenerate".format(said)))
            continue
        if (ident, kind) in seen:
            problems.append(Problem(where, "{}: a second {} entry for one identifier; "
                                           "regenerate".format(said, kind)))
        seen.add((ident, kind))
        position = (ids.index(ident), 0 if kind == "locus" else 1)
        if position < last:
            problems.append(Problem(where, "{}: out of what.vulnerabilities order, locus before "
                                           "class; regenerate".format(said)))
        last = max(last, position)
        if name not in rules:
            problems.append(Problem(where, "{}: no rule of that name in identifier_reading; "
                                           "regenerate".format(said)))
            continue
        locus, cls, regex = rules[name]
        if bool(entry.get("locus")) == bool(entry.get("class")) or entry.get("locus") != locus \
                or entry.get("class") != cls:
            problems.append(Problem(where, "{}: the rule reads {}, the entry says {}; "
                                           "regenerate".format(said, locus or cls,
                                                               entry.get("locus") or entry.get("class"))))
        if not isinstance(phrase, str) or not regex.fullmatch(phrase):
            problems.append(Problem(where, "{}: the words are not what the rule's pattern matches; "
                                           "regenerate".format(said)))
        if entry.get("field") not in fields:
            problems.append(Problem(where, "{}: field {!r} is not one identifier_reading reads for "
                                           "{}, {}; regenerate".format(said, entry.get("field"), tag,
                                                                       fields)))
        if cls and not prefixed:
            problems.append(Problem(where, "{}: a class reading on a record carrying no class "
                                           "beginning {!r}; regenerate".format(said, table["prefix"])))
        if cls and cls in classes:
            problems.append(Problem(where, "{}: the record already carries {}, so the rule does not "
                                           "read it; regenerate".format(said, cls)))
    # The quoted descriptions, read again, both ways. An entry read from vulnerabilityName is
    # accepted only where the quotation yields none of its kind, which is the only case the
    # rule reads that field in.
    for ident, quoted in _locus.Q.catalogue_descriptions(record).items():
        expect = _locus.Q.read_identifier([("shortDescription", quoted)], prefixed, locus_map,
                                          held=classes)
        for kind, want in zip(("locus", "class"), expect):
            have = [{k: v for k, v in e.items() if k != "id"} for e in entries
                    if e.get("id") == ident and e.get(kind)]
            got = have[0] if have else None
            if want is not None and got != want:
                problems.append(Problem(where, "{} {}: the catalogue description the summary quotes "
                                               "reads {} {!r} by rule {!r}, and the record carries {}; "
                                               "regenerate".format(
                                                   rid, ident, want[kind], want["phrase"], want["rule"],
                                                   "{} {!r} by rule {!r} from {}".format(
                                                       got.get(kind), got.get("phrase"), got.get("rule"),
                                                       got.get("field")) if got else "no {} entry".format(kind))))
            elif want is None and got is not None and got.get("field") == "shortDescription":
                problems.append(Problem(where, "{} {} rule {!r} words {!r}: the catalogue description "
                                               "the summary quotes reads no {} here; regenerate".format(
                                                   rid, ident, got.get("rule"), got.get("phrase"), kind)))


def check_generated_surface(record, locus_map, where, problems):
    """An exposure's attack_surface is read or ignored on its tags, so the tags must be honest.

    The ladder ignores the surface of an exposure carrying a tag in untrusted_surface_tags,
    because a generator assigned it from a class table. That makes the tag load-bearing: a
    generator that forgot to write it would have its assigned surface read as authored, and
    nothing would say so. Each tag names the source_type its generator writes, so the two
    are checked against each other in both directions.
    """
    tags = locus_map.get("untrusted_surface_tags")
    if record.get("record_type") != "exposure" or not isinstance(tags, dict) or not tags:
        return
    source_type = (record.get("where") or {}).get("source_type")
    carried = [tag for tag in tags if tag in (record.get("tags") or [])]
    for tag in carried:
        if source_type != tags[tag]:
            problems.append(Problem(where, "exposure tagged {!r} carries where.source_type {!r}, "
                                           "and that generator writes {!r}".format(
                                               tag, source_type, tags[tag])))
    if not carried and source_type in set(tags.values()):
        problems.append(Problem(where, "exposure carries where.source_type {!r}, which a generator "
                                       "writes, and no tag in locus-map.json untrusted_surface_tags, so "
                                       "its assigned attack_surface would be read as authored; tag it "
                                       "with its generator's tag or correct the source_type".format(source_type)))


def check_declared_locus(record, locus_map, where, problems):
    """A declared how[].locus has to change the answer, and has to say why in notes.

    observation.schema.json already said so: set it only where the derivation is provably
    wrong, and say why in notes, because a hand-set value that agrees with the derivation
    will silently stop agreeing when the derivation changes. Only membership in vocab.locus
    was checked, so three overrides restated the derivation and none of the others carried
    its reason anywhere that ships.
    """
    notes = record.get("notes") or ""
    for i, how in enumerate(record.get("how") or []):
        declared = how.get("locus")
        if not declared:
            continue
        underived = {key: value for key, value in how.items() if key != "locus"}
        derived = _locus.locus_for(record, underived, None, locus_map)[0]
        if derived == declared:
            problems.append(Problem(where, "how[{}].locus declares {}, which the derivation already "
                                           "gives; remove it".format(i, declared)))
        elif "how[{}].locus".format(i) not in notes:
            problems.append(Problem(where, "how[{}].locus overrides the derivation ({} declared, {} "
                                           "derived) with no reason in notes; give it there, naming "
                                           "how[{}].locus".format(i, declared, derived, i)))


def check_declared_pattern_locus(pattern, vocab, locus_map, where, problems):
    """A pattern's declared locus must change its placement, and must say why.

    It is read only where a pattern is placed with no block -- advise.py and a LIBRARY block
    -- for the plane no class on its list can say: a network device's administration has no
    class of its own. It is held to the rule how[].locus is held to, with the reason in the
    pattern's own `locus_reason`, because a pattern has no notes. The reason is printed inside
    LOCUS_BASIS, whose fields are separated by semicolons, so it may not carry one.
    """
    declared = pattern.get("locus")
    reason = pattern.get("locus_reason")
    if not declared:
        if reason:
            problems.append(Problem(where, "locus_reason is set and no locus is declared"))
        return
    if declared not in (vocab.get("locus") or {}):
        problems.append(Problem(where, "locus {!r} is not in vocab.locus".format(declared)))
    if not isinstance(reason, str) or not reason.strip():
        problems.append(Problem(where, "locus {} is declared with no locus_reason; give the reason "
                                       "there".format(declared)))
    elif ";" in reason:
        problems.append(Problem(where, "locus_reason carries a semicolon, which would split "
                                       "LOCUS_BASIS"))
    if _locus is not None and locus_map:
        underived = {key: value for key, value in pattern.items()
                     if key not in ("locus", "locus_reason")}
        derived = _locus.locus_for(None, None, underived, locus_map)[0]
        if derived == declared:
            problems.append(Problem(where, "locus declares {}, which the derivation already gives; "
                                           "remove it".format(declared)))


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
        check_marker_list(markers, marker_types, where, base, problems,
                          normalised_types=vocab.get("normalised_marker_types"))


def check_normalised_words(entries, vocab, problems):
    """A word one marker flags as this corpus's own is flagged wherever it is used.

    The flag is the author's statement that no source writes the value, so it cannot be checked
    against a source; what can be checked is that the corpus says it once and means it
    everywhere. An unflagged event_type or zone marker holding a word another marker flags
    would print the live filter the flag exists to stop. Returns {type: flagged markers}.
    """
    types = [t for t in (vocab.get("normalised_marker_types") or {}) if not t.startswith("_")]

    def words(m):
        value = m.get("value")
        return {str(v).lower() for v in (value if isinstance(value, list) else [value])}
    flagged = collections.defaultdict(dict)
    counts = collections.Counter()
    for where, at, m in entries:
        if m.get("type") in types and m.get("normalised"):
            counts[m["type"]] += 1
            for word in words(m):
                flagged[m["type"]].setdefault(word, "{} {}".format(where, at))
    for where, at, m in entries:
        if m.get("type") in types and not m.get("normalised"):
            shared = sorted(w for w in words(m) if w in flagged[m["type"]])
            if shared:
                problems.append(Problem(where, "{} holds {} unflagged, a word {} flags as this "
                                        "corpus's own and not a source literal; flag it "
                                        "normalised, or bind the value the source "
                                        "writes".format(at, ", ".join(repr(w) for w in shared),
                                                        flagged[m["type"]][shared[0]])))
    return counts


def marker_item_schema(schema):
    """The observation schema's definition of one marker, which a pattern marker also meets."""
    return (((((schema.get("properties") or {}).get("how") or {}).get("items") or {})
             .get("properties") or {}).get("markers") or {}).get("items") or {}


def check_marker_list(markers, marker_types, where, base, problems, item_schema=None,
                      normalised_types=None):
    """One list's markers against the vocabulary, on a record's block or on a pattern.

    Until 0.43.0 only a record's markers were held to this, and to the schema's match list; a
    pattern's got the binding check alone, which reads a match it does not know as equality,
    so a pattern marker valued not_equals passed here and printed the clause it negates.
    `item_schema` is given for a pattern, which the observation schema never reaches. The
    response-plan check stays with records: six inventory patterns ask whether a response plan
    exists, and there the plan is the subject of the question, not doctrine in a detection.
    """
    for j, m in enumerate(markers or []):
        at = "{}.markers[{}]".format(base, j)
        if item_schema:
            check_schema(m, item_schema, "{}: {}".format(where, at), problems)
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
        allowed = [t for t in (normalised_types or {}) if not t.startswith("_")]
        if "normalised" in m and mtype not in allowed:
            problems.append(Problem(where, "{}.normalised is set on a {} marker; only {} may "
                                    "hold this corpus's own word rather than a source literal "
                                    "(vocab.json normalised_marker_types)".format(
                                        at, mtype, ", ".join(allowed) or "no type")))
        if mtype == "computed" and not item_schema:
            doctrine = PLAN_ASSERTION.search(m.get("expr") or "")
            if doctrine:
                problems.append(Problem(where, "{}.expr asserts a response plan ({!r}) rather "
                                        "than computing over telemetry. Response doctrine "
                                        "belongs in corpus/reference/response-doctrine.json, "
                                        "where it can be cited and matched on class and "
                                        "impact.".format(at, doctrine.group(0))))


def check_combination(markers, combine, where, base, problems):
    """The combination key and the event labels it relies on (corpus/README.md, How markers
    combine). A label on some event-bound markers and not others leaves the unlabelled ones in
    no event, and a label with no combine key says nothing about how the events relate."""
    if combine is not None and combine not in ("all", "any"):
        problems.append(Problem(where, "{}.combine {!r} is not one of all, any".format(
            base, combine)))
    if combine is not None and not markers:
        problems.append(Problem(where, "{}.combine is set but {} carries no markers of its own "
                                "for it to combine".format(base, base)))
    event_bound = [m for m in markers or [] if m.get("type") not in ("computed", "cve",
                                                                      "software_version")]
    for j, m in enumerate(markers or []):
        label = m.get("event")
        if label is not None and not re.match(r"^[a-z][a-z0-9_]*$", str(label)):
            problems.append(Problem(where, "{}.markers[{}].event {!r} is not a lower-case "
                                    "label".format(base, j, label)))
    labelled = [m for m in event_bound if m.get("event")]
    if labelled and len(labelled) != len(event_bound):
        problems.append(Problem(where, "{} labels {} of its {} event-bound markers with an event; "
                                "once one carries a label every one must".format(
                                    base, len(labelled), len(event_bound))))
    if labelled and not combine:
        problems.append(Problem(where, "{} labels its markers with events but sets no combine, "
                                "so nothing says whether the events are alternatives or all "
                                "required".format(base)))
    # A requirement -- a computed, CVE or version marker -- may name the event it qualifies,
    # so that under any the qualifier of one alternative is not read as a condition on the
    # others. It must name an event the list tests.
    labels = {m.get("event") for m in labelled}
    for j, m in enumerate(markers or []):
        if m.get("type") in ("computed", "cve", "software_version") and m.get("event") \
                and m.get("event") not in labels:
            problems.append(Problem(where, "{}.markers[{}] is a {} requirement labelled {!r}, "
                                    "which no event-bound marker in the list carries; label it "
                                    "with an event the list tests, or leave it unlabelled to "
                                    "qualify the whole list".format(base, j, m.get("type"),
                                                                    m.get("event"))))


def check_event_kind_join(markers, combine, xdm_fields, where, base, problems):
    """An event identifier, type or raw action joined with an artefact, with no combine.

    The emitter counts xdm.event.* as neutral, so an unkeyed list joining one with a process,
    file, registry, DNS or HTTP marker printed as one event: the log-cleared identifiers 1102
    and 104 with the command line of the utility that clears logs, under fidelity=alert and
    filter=complete, though the log-cleared record carries no command line. Whether they are
    one event is what the identifier cannot say, so the list must: combine all where the
    identifier names the event the artefact is on (Sysmon 11 and the file it writes), any or
    labelled events where it does not.
    """
    joined = _emit.unkeyed_event_kind_join(markers, xdm_fields, combine)
    if joined:
        kinds, families = joined
        problems.append(Problem(where, "{} joins {} with {} marker(s) and sets no combine; an "
                                "event identifier or type does not say whether the other "
                                "markers sit on the same event, so say it: combine all if "
                                "they do, any or event labels if they do not".format(
                                    base, " and ".join(kinds), " and ".join(families))))


def check_connection_actor(markers, combine, xdm_fields, where, base, problems):
    """A connection's port, address, zone or protocol joined with a process acted upon.

    The process that opens a connection is the event's actor, xdm.source.process, and a
    connection carries no xdm.target.process, which is a process acted upon. The emitter counts
    address, port and zone fields as neutral, so it printed a tunnel client's image on
    xdm.target.process beside its port as one event, under fidelity=alert and filter=complete,
    and nothing here said so.
    """
    joined = _emit.acted_upon_process_on_a_connection(markers, xdm_fields, combine)
    if joined:
        process, connection = joined
        problems.append(Problem(where, "{} joins {} with {} on one event; a connection's process "
                                "is its actor, so bind it to xdm.source.process, or label the "
                                "markers as separate events if the process is really acted "
                                "upon".format(base, " and ".join(process),
                                              " and ".join(connection))))


def check_bindings(markers, xdm_fields, where, base, problems):
    """Every marker's field against the bundled XDM snapshot, through the emitter's own binder.

    38 markers were bound to xdm.event.operation, the derived OPERATION_TYPE enum, with raw API
    names it can never hold, and four to xdm.target.file.name, which is not an XDM field; the
    skeletons printed from them could never match, and nothing checked. An enum literal that is
    not a member is refused whether the marker names the field or takes the default: a default
    binding was waved through, so event_outcome "DENIED" passed here and printed as UNBOUND.
    Every refusal the emitter marks as the marker's fault is refused too -- a pattern the regex
    engine behind XQL's ~= cannot run, a digest of the wrong length for its field, a list where
    the test takes one value -- while a limit of the skeleton, such as a range on an address
    field, is left to print as UNBOUND.
    """
    for j, m in enumerate(markers or []):
        at = "{}.markers[{}]".format(base, j)
        b = _emit.bind(m, xdm_fields)
        ftype = ((xdm_fields or {}).get("fields") or {}).get(b.field or "", {}).get("type") or ""
        if m.get("normalised") and ftype.startswith("XDM_CONST."):
            problems.append(Problem(where, "{} is flagged normalised but binds {}, an {} enum, "
                                    "whose members are values the platform writes; drop the "
                                    "flag or the binding".format(at, b.field, ftype)))
        if b.status == "not_an_xdm_field":
            problems.append(Problem(where, "{} binds {}, which is not a field of the bundled XDM "
                                    "snapshot corpus/schema/xdm-fields.json. Correct the path, or "
                                    "copy the field's line from the XDM schema into the "
                                    "snapshot".format(at, b.field)))
        elif b.status == "enum_literal":
            enum = ((xdm_fields or {}).get("enums") or {}).get(
                ((xdm_fields or {}).get("fields") or {}).get(b.field, {}).get("type")) or {}
            if enum.get("members"):
                problems.append(Problem(where, "{} binds {}; {}".format(at, b.field, b.reason)))
        elif b.fault:
            problems.append(Problem(where, "{}: {}{}".format(
                at, b.reason, ". XQL's ~= runs RE2" if m.get("match") == "regex"
                and (b.reason or "").startswith("the pattern") else "")))


# A doubled backslash anywhere but at the very start of a value.
DOUBLED_BACKSLASH = re.compile(r"^.+?\\\\", re.S)


def check_literal_backslashes(items, where, base, key, problems):
    """A literal holds a path as the event holds it, one backslash per separator.

    A doubled backslash in a value that is not a regex is the JSON escape applied twice. The
    AV-exclusion markers named the key `Windows Defender\\\\Exclusions\\\\Paths`, which no
    registry key contains, and the skeleton printed that faithfully under filter=complete: a
    clause that can never match, reading as a true negative. Only a UNC path starts with two, so
    a pair at the start is allowed. A regex is exempt, because `\\\\` is how one asks for one
    backslash.
    """
    for j, item in enumerate(items or []):
        op = item.get("match", "equals") if key == "markers" else item.get("op")
        if op == "regex" or item.get("type") == "computed":
            continue
        value = item.get("value")
        for v in (value if isinstance(value, list) else [value]):
            if isinstance(v, str) and DOUBLED_BACKSLASH.match(v):
                problems.append(Problem(where, "{}.{}[{}].value {!r} holds a doubled backslash. A "
                                        "literal is written as the event holds it, one "
                                        "backslash per separator; two test for a pair no path "
                                        "contains. Only a UNC path may start with "
                                        "two".format(base, key, j, v)))


# Legacy fields[] items the emitter never binds, so check_bindings cannot see them: a path is
# recorded expanded, and an extension without its dot.
LEGACY_PATH_FIELDS = ("xdm.target.file.path", "xdm.target.process.executable.path",
                      "xdm.target.file.filename")
ENV_VARIABLE = re.compile(r"%[A-Za-z_][A-Za-z0-9_]*%")


def check_legacy_literals(items, where, base, problems):
    """The two literal shapes the binder refuses on a marker, on a legacy field test.

    `%TEMP%\\rust-setup.ps1` sat in a file path marker and its legacy field alike, and `.lnk` in
    an extension marker. No file or process event holds either, and the handoff forwards
    fields[] verbatim to the rule author.
    """
    for j, item in enumerate(items or []):
        value = item.get("value")
        texts = [str(v) for v in (value if isinstance(value, list) else [value])]
        if item.get("xdm") in LEGACY_PATH_FIELDS and any(ENV_VARIABLE.search(t) for t in texts):
            problems.append(Problem(where, "{}.fields[{}] tests {} for an unexpanded variable; an "
                                    "event records the path expanded".format(
                                        base, j, item.get("xdm"))))
        if item.get("xdm") == "xdm.target.file.extension" and any(t.startswith(".") for t in texts):
            problems.append(Problem(where, "{}.fields[{}] tests xdm.target.file.extension with "
                                    "a leading dot; the field holds an extension without its "
                                    "dot".format(base, j)))


SKETCH_FIELD = re.compile(r"xdm\.[A-Za-z0-9_.]*[A-Za-z0-9_]")


def check_sketch(sketch, xdm_fields, where, problems):
    """A pattern's xql_sketch against the defects the skeleton had, which a reader copies.

    A sketch is pseudo-code (corpus/README.md, "xql_sketch"): placeholders, vendor columns beside
    modelled fields, schematic operators. It was never checked, and at 0.43.0 22 sketches called
    bin() as a function, ten named fields XDM does not have, three matched a raw action against
    the OPERATION_TYPE enum and one compared xdm.event.id to bare numbers -- each a defect the
    skeleton was fixed for in the same release.
    """
    if not sketch:
        return
    if "bin(" in sketch:
        problems.append(Problem(where, "xql_sketch calls bin(), and bin is a stage: `| bin _time "
                                "span = <window> | comp ... by ..., _time`"))
    names = set((xdm_fields or {}).get("schema_field_names") or [])
    unknown = sorted({f for f in SKETCH_FIELD.findall(sketch) if f not in names}) if names else []
    if unknown:
        problems.append(Problem(where, "xql_sketch names {}, not a field of the XDM schema "
                                "(corpus/schema/xdm-fields.json, schema_field_names)".format(
                                    ", ".join(unknown))))
    if re.search(r'xdm\.event\.operation(?![\w.])\s*(?:~=|!?=\s*"|in\s*\(\s*")', sketch):
        problems.append(Problem(where, "xql_sketch tests xdm.event.operation, the OPERATION_TYPE "
                                "enum, against a string; a raw action is "
                                "xdm.event.original_event_type"))
    if re.search(r"xdm\.event\.outcome\s*(?:!?=|in\s*\()\s*XDM_CONST", sketch):
        problems.append(Problem(where, "xql_sketch compares xdm.event.outcome to a constant, which "
                                "fails a pack install; compare the rendered string"))
    if re.search(r"xdm\.event\.id\s*(?:!?=|in\s*\()\s*\d", sketch):
        problems.append(Problem(where, "xql_sketch compares xdm.event.id, a String, to a bare "
                                "number; quote it"))
    members = {c for enum in ((xdm_fields or {}).get("enums") or {}).values()
               for c in enum.get("members") or []}
    constants = sorted(set(re.findall(r"XDM_CONST\.[A-Z0-9_]+", sketch)) - members)
    if members and constants:
        problems.append(Problem(where, "xql_sketch names {}, no member of an XDM_CONST group the "
                                "snapshot holds".format(", ".join(constants))))


def check_kev_membership(tagged, kev_ids, problems):
    """A record's KEV tag must agree with the corpus's own KEV records.

    The ZDI, PSIRT and vulnerability-database generators stamp `not-in-kev`, and a sentence
    saying the same, when they run. The catalogue moves after that, and nothing re-derived
    either: on 2026-09-25 six records denied membership of an identifier the KEV records in
    the same corpus listed, and query.py printed the KEV record and the denial three lines
    apart. Checked against the corpus rather than a snapshot, so a KEV refresh that is not
    followed by regenerating the other families fails here.
    """
    for where, tags, vulns in tagged:
        held = sorted(set(vulns) & kev_ids)
        if "not-in-kev" in tags and "in-kev" in tags:
            problems.append(Problem(where, "tagged both in-kev and not-in-kev"))
        elif "not-in-kev" in tags and held:
            problems.append(Problem(where, "tagged not-in-kev but carries {}, which a "
                                    "known-exploited-catalogue record holds; regenerate this "
                                    "family against the current catalogue".format(", ".join(held))))
        elif "in-kev" in tags and not held:
            problems.append(Problem(where, "tagged in-kev but carries no identifier a "
                                    "known-exploited-catalogue record holds"))


def check_generated_classes(generated, aliases, problems):
    """One product carries one class list, whichever generator wrote its record.

    A generated exposure's surface is never read, so its class is the only plane it has, and
    the class decides whether a question about another product in that class lists it. The
    four generators classed independently: FortiSandbox was a firewall in its KEV record and
    endpoint security in its PSIRT and ZDI ones, so whether a FortiGate question listed it
    depended on which record it met, and FortiManager's KEV exposure sat on CONTROL beside a
    MANAGEMENT observation of the same CVE. `generated` is (where, generator tag, record) for
    every exposure carrying a tag in untrusted_surface_tags; products are grouped by the vendor
    the alias table resolves and the name with case and punctuation dropped.
    """
    vendor_aliases = {k.lower(): v for k, v in (aliases.get("vendor_aliases") or {}).items()
                      if isinstance(v, str)}
    groups = {}
    for where, family, record in generated:
        who = record.get("who") or {}
        vendor = vendor_aliases.get(str(who.get("vendor") or "").lower(), who.get("vendor"))
        classes = tuple(who.get("product_class") or [])
        for product in who.get("products") or []:
            key = (vendor, re.sub(r"[^a-z0-9]", "", str(product).lower()))
            groups.setdefault(key, []).append((where, family, classes, product))
    for (vendor, _), held in sorted(groups.items(), key=lambda item: str(item[0])):
        if len({h[1] for h in held}) > 1 and len({h[2] for h in held}) > 1:
            problems.append(Problem(held[0][0], "{} {} is classed differently by its generators: "
                                    "{}; correct the generator that disagrees, then "
                                    "regenerate".format(vendor, held[0][3], "; ".join(
                                        "{} [{}] {}".format(family, ", ".join(c), where)
                                        for where, family, c, _ in held))))


def check_scope(scope, exposures, problems):
    """schema/scope.json's handset table names vendors and terms this corpus holds.

    consult.py refuses an exposure from its EXPOSURE blocks when its vendor is a key here and
    every platform its products name matches one of that vendor's terms. A key no exposure is
    filed under, or a term matching none of that vendor's products, refuses nothing, and a
    table left to rot like that reads as a decision still in force. `exposures` is the
    (who.vendor, who.products) of every exposure record.
    """
    where = "corpus/schema/scope.json"
    table = scope.get("handset_exposures")
    if table is None:
        return
    if not isinstance(table, dict):
        problems.append(Problem(where, "handset_exposures must map a who.vendor to a list of terms"))
        return

    def words(text):
        return " " + re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]+", " ", str(text).lower())).strip() + " "

    held = {}
    for vendor, products in exposures:
        held.setdefault(vendor, []).extend(words(p) for p in products or [])
    for vendor, terms in sorted(table.items()):
        if not isinstance(terms, list) or not terms:
            problems.append(Problem(where, "handset_exposures[{!r}] must be a non-empty list of "
                                    "terms, or [\"*\"]".format(vendor)))
            continue
        if vendor not in held:
            problems.append(Problem(where, "handset_exposures names {!r}, and no exposure record "
                                    "is filed under that who.vendor".format(vendor)))
            continue
        for term in terms:
            if term != "*" and not any(words(term) in p for p in held[vendor]):
                problems.append(Problem(where, "handset_exposures[{!r}] term {!r} matches none of "
                                        "that vendor's exposure products".format(vendor, term)))


def check_handset_names(scope, aliases, problems):
    """scope.json's `handset_names` are words consult.py can refuse.

    Each is matched against the unresolved words of a question that resolved nothing, so a
    name that is not one lower-case word of three letters or more, or that an unambiguous alias
    consumes before it is read, is refused by nothing: "android" is a vendor alias, and the
    vendor path refuses its records. An ambiguous alias ("ios") is gated and stays a word.
    """
    where = "corpus/schema/scope.json"
    names = scope.get("handset_names")
    if names is None:
        return
    if not isinstance(names, list) or not names:
        problems.append(Problem(where, "handset_names must be a non-empty list of words"))
        return
    gated = {str(k).lower() for gate in ("ambiguous_aliases", "ambiguous_vendor_aliases",
                                         "ambiguous_class_aliases")
             for k in aliases.get(gate) or {}}
    consumed = {str(k).lower() for table in ("vendor_aliases", "product_aliases", "class_aliases",
                                             "sector_aliases")
                for k in aliases.get(table) or {}} - gated
    noise = getattr(getattr(_locus, "Q", None), "NOISE", set())
    for name in names:
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9]{3,}", name) or name in noise:
            problems.append(Problem(where, "handset_names entry {!r} is not one lower-case word of "
                                    "three or more letters, so no question word can match it"
                                    .format(name)))
        elif name in consumed:
            problems.append(Problem(where, "handset_names entry {!r} is an unambiguous alias, "
                                    "which resolves before it could be refused".format(name)))
    # A place is read as one only beside a sector, so a word listed as a place and not as a
    # handset name would excuse nothing, and reads as though it did.
    places = scope.get("handset_names_also_places")
    if places is not None and not isinstance(places, list):
        problems.append(Problem(where, "handset_names_also_places must be a list of words"))
        return
    for name in places or ():
        if name not in names:
            problems.append(Problem(where, "handset_names_also_places entry {!r} is not in "
                                    "handset_names, so it is never read".format(name)))


# The advisory pages reference/advisory-identifiers.json can list, recognised in a citation so a
# record citing one the file does not hold is counted rather than silently passed.
CISA_PAGE = re.compile(r"cisa\.gov/news-events/(?:cybersecurity-advisories|analysis-reports)/",
                       re.I)
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,7}")
# Prose about the record and the citation itself: a note may name an identifier the record was
# corrected to drop, and a title is the publisher's. Everything else a record holds is a claim.
IDENTIFIER_FREE_KEYS = frozenset({"notes", "note", "where"})


def canonical_url(url):
    """A citation URL compared without scheme, `www.` or a trailing slash."""
    return re.sub(r"^https?://(?:www\.)?", "", str(url or "").strip().lower()).rstrip("/")


def carried_identifiers(value, key=None):
    """Every CVE identifier a record carries, outside IDENTIFIER_FREE_KEYS."""
    if key in IDENTIFIER_FREE_KEYS:
        return set()
    if isinstance(value, dict):
        return set().union(*(carried_identifiers(v, k) for k, v in value.items())) \
            if value else set()
    if isinstance(value, list):
        return set().union(*(carried_identifiers(v, key) for v in value)) if value else set()
    return set(CVE_ID.findall(value)) if isinstance(value, str) else set()


def cited_urls(record):
    """The record's citation and every corroboration it names, as written."""
    where = record.get("where") or {}
    return [u for u in [where.get("url")] + [c.get("url") for c in where.get("corroborations")
                                             or [] if isinstance(c, dict)] if u]


def check_cited_advisory_identifiers(cited, advisories, problems):
    """A record whose every cited source is held locally carries only identifiers they name.

    `advisories` is reference/advisory-identifiers.json's map of page URL to the identifiers its
    text names. Nothing compared what a record carries with what its source says:
    exp-fortinet-fortios-mfa-bypass-username-case carried CVE-2020-12812 on the citation of
    AA22-011A, which lists seventeen identifiers and not that one, and printed `verified=yes`
    beside it. A record also citing a source not held here is not decided, because the
    identifier may be that source's, and is counted instead. `cited` is (where, record) for
    every record. Returns (checked, partly held, citing a CISA page not held).
    """
    held = {canonical_url(url): set(entry.get("identifiers") or [])
            for url, entry in (advisories or {}).items()}
    checked = partial = unheld = 0
    for where, record in cited:
        urls = [canonical_url(u) for u in cited_urls(record)]
        known = [u for u in urls if u in held]
        if any(CISA_PAGE.search(u) and u not in held for u in urls):
            unheld += 1
        if not known:
            continue
        if len(known) < len(urls):
            partial += 1
            continue
        checked += 1
        named = set().union(*(held[u] for u in known))
        missing = sorted(carried_identifiers(record) - named)
        if missing:
            problems.append(Problem(where, "carries {}, which {}; cite the source that does, or "
                                    "cut the identifier".format(
                                        ", ".join(missing),
                                        "the advisory page it cites never names" if len(known) == 1
                                        else "none of the {} advisory pages it cites names".format(
                                            len(known)))))
    return checked, partial, unheld


def check_dates(record, where, problems):
    date_re = re.compile(r"^\d{4}(-\d{2}(-\d{2})?)?$")
    for key, value in (record.get("when") or {}).items():
        if key == "precision":
            continue
        if not date_re.match(str(value)):
            problems.append(Problem(where, "when.{} {!r} is not YYYY, YYYY-MM or YYYY-MM-DD".format(key, value)))


def check_seed_support(record, where, problems):
    """A record claims no more support than its fields record.

    how[].unconfirmed belongs to a seed record whose source was re-read (where.verified true),
    on every block, saying whether the re-read source supports it; it is refused on a verified
    record and on a seed not fully re-read, where seed_support() never reads it. confidence
    high is refused on a block consult.py calls NOT CONFIRMED: a block of a seed not fully
    re-read against its source, or one marked unconfirmed. how.confidence is confidence
    that the logic reflects what the source described, and emit_xql.py handed the ArcaneDoor
    block, written from general knowledge, and the Fortinet family argument its re-read source
    never makes, to a rule author at high. A supported block keeps its confidence: four of the
    eight high seed blocks are the halves their re-read sources support, so a blanket seed rule
    would make the corpus claim less than its evidence. The state is consult.seed_support's,
    so this refusal and the STATUS line cannot disagree.
    """
    status = record.get("status")
    source = record.get("where") or {}
    blocks = record.get("how") or []
    if status == "verified":
        for i, how in enumerate(blocks):
            if "unconfirmed" in how:
                problems.append(Problem(where, "how[{}].unconfirmed is set on a verified record; "
                                        "only a re-read seed record has an unconfirmed part"
                                        .format(i)))
        if source.get("verified") is False:
            problems.append(Problem(where, "status verified beside where.verified false"))
        return
    if status != "seed":
        return
    for i, how in enumerate(blocks):
        if source.get("verified") is not True and "unconfirmed" in how:
            # seed_support() reads the flag only once the source was re-read, so on an unread
            # seed it was silently ignored, and read as though it said something.
            problems.append(Problem(where, "how[{}].unconfirmed is set on a seed record not fully "
                                    "re-read against its source; only a re-read seed record "
                                    "has an unconfirmed part".format(i)))
        if source.get("verified") is True and not isinstance(how.get("unconfirmed"), bool):
            # One problem per defect: the unset flag is the fault, not the confidence beside it.
            problems.append(Problem(where, "how[{}].unconfirmed is unset on a seed record whose "
                                    "source was re-read: say whether the source supports it"
                                    .format(i)))
            continue
        part = _locus.seed_support(record, i) if _locus is not None else None
        if part in ("unread", "unconfirmed") and how.get("confidence") == "high":
            problems.append(Problem(where, "how[{}].confidence is high on a block that is not "
                                    "confirmed ({}): confidence is that the logic reflects what "
                                    "the source described".format(i, part)))


# The modes resolve() knows for a gated class alias, and the platforms query.py breaks ties on.
CLASS_GATE_MODES = ("upper", "refuse_near", "require_near")
PLATFORMS = ("windows", "linux", "macos", "unix")
SENTINEL_VENDORS = ("any", "Multiple")


def check_aliases(aliases, vocab, problems):
    """The gate tables in aliases.json must point at entries that exist, and say why.

    A gate on a key that no table holds protects nothing and reads as though it does, and
    resolve() fails closed on a gate mode it does not know, so a misspelt mode silently turns a
    class alias off. Each of these is checked by a test as well; the validator is what checks a
    corpus passed with --corpus, which the tests never see.
    """
    where = "schema/aliases.json"

    def norm(key):
        return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]+", " ", key.lower())).strip()

    tables = {name: {norm(k) for k in (aliases.get(name) or {})}
              for name in ("product_aliases", "vendor_aliases", "class_aliases")}
    classes = set(vocab.get("product_class") or {})
    for key, value in (aliases.get("vendor_aliases") or {}).items():
        if value in SENTINEL_VENDORS:
            problems.append(Problem(where, "vendor alias {!r} names {!r}, which is not a vendor"
                                    .format(key, value)))
    for gate, table in (("ambiguous_aliases", "product_aliases"),
                        ("_ambiguous_reviewed_keep", "product_aliases"),
                        ("ambiguous_vendor_aliases", "vendor_aliases"),
                        ("ambiguous_class_aliases", "class_aliases")):
        for key, reason in (aliases.get(gate) or {}).items():
            if norm(key) not in tables[table]:
                problems.append(Problem(where, "{} key {!r} is not a key of {}".format(
                    gate, key, table)))
            text = reason.get("reason") if isinstance(reason, dict) else reason
            if not str(text or "").strip():
                problems.append(Problem(where, "{} key {!r} gives no reason".format(gate, key)))
            if gate == "ambiguous_class_aliases":
                mode = (reason or {}).get("mode") if isinstance(reason, dict) else None
                if mode not in CLASS_GATE_MODES:
                    problems.append(Problem(where, "ambiguous_class_aliases {!r} has mode {!r}, "
                                            "not one of {}".format(key, mode,
                                                                   ", ".join(CLASS_GATE_MODES))))
                elif mode != "upper" and not (reason or {}).get("near"):
                    problems.append(Problem(where, "ambiguous_class_aliases {!r} ({}) lists no "
                                            "context words".format(key, mode)))
                if isinstance(reason, dict) and "acronym_plural" in reason and (
                        mode != "upper" or not isinstance(reason["acronym_plural"], bool)):
                    problems.append(Problem(where, "ambiguous_class_aliases {!r} sets "
                                            "acronym_plural, which is a true or false for the "
                                            "upper mode only".format(key)))
    overlap = {norm(k) for k in aliases.get("ambiguous_aliases") or {}} \
        & {norm(k) for k in aliases.get("_ambiguous_reviewed_keep") or {}}
    for key in sorted(overlap):
        problems.append(Problem(where, "{!r} is both gated and reviewed as kept".format(key)))
    for key in aliases.get("singular_only") or []:
        if not any(norm(key) in names for names in tables.values()):
            problems.append(Problem(where, "singular_only {!r} is not an alias".format(key)))
    # A family is directional, parent to the lines it acquired, and a line has one parent. A
    # flat list read both ways made sibling acquisitions each other's vendor, so the shape is
    # checked as well as the contents.
    families = aliases.get("vendor_families") or {}
    if not isinstance(families, dict):
        problems.append(Problem(where, "vendor_families is not a map of a parent vendor to the "
                                "lines it acquired"))
        families = {}
    seen = {}
    for head, lines in families.items():
        if not isinstance(lines, list) or not lines or not all(
                isinstance(line, str) and line.strip() for line in lines):
            problems.append(Problem(where, "vendor_families {!r} is not a list of one or more "
                                    "vendor names".format(head)))
            continue
        for line in lines:
            if line == head or line in families:
                problems.append(Problem(where, "vendor_families {!r} lists {!r}, which is a "
                                        "parent itself".format(head, line)))
            if line in seen and seen[line] != head:
                problems.append(Problem(where, "vendor_families line {!r} has two parents, {!r} "
                                        "and {!r}".format(line, seen[line], head)))
            seen[line] = head
    for group in aliases.get("vendor_spellings") or []:
        if not isinstance(group, list) or len(group) < 2:
            problems.append(Problem(where, "vendor_spellings entry {!r} is not a list of two or "
                                    "more names for one vendor".format(group)))
    # A product family makes records naming one of its names product matches for a question
    # naming another, so an entry that is malformed, or says nothing about why, changes answers
    # with no one able to check it.
    for entry in aliases.get("product_families") or []:
        if not isinstance(entry, dict):
            problems.append(Problem(where, "product_families entry {!r} is not an object".format(
                entry)))
            continue
        names = entry.get("names")
        components = entry.get("components") or []
        members = (names if isinstance(names, list) else []) + \
            (components if isinstance(components, list) else [])
        if not str(entry.get("vendor") or "").strip():
            problems.append(Problem(where, "product_families entry {!r} names no vendor".format(
                names)))
        if not isinstance(names, list) or not names or not isinstance(components, list) or len(
                members) < 2 or not all(isinstance(m, str) and m.strip() for m in members):
            problems.append(Problem(where, "product_families entry {!r} does not list two or more "
                                    "names and components for one product".format(names)))
        if not str(entry.get("reason") or "").strip():
            problems.append(Problem(where, "product_families entry {!r} gives no reason".format(
                names)))
    for key, platform in (aliases.get("platform_of") or {}).items():
        if platform not in PLATFORMS:
            problems.append(Problem(where, "platform_of {!r} is {!r}, not one of {}".format(
                key, platform, ", ".join(PLATFORMS))))
    for alias, value in (aliases.get("class_aliases") or {}).items():
        for klass in (value if isinstance(value, list) else [value]):
            if classes and klass not in classes:
                problems.append(Problem(where, "class alias {!r} names {!r}, which is not a "
                                        "product_class".format(alias, klass)))


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
    # Read here as well as at the end: the locus map's technique lists are held to it.
    attack_techniques = {}
    attack_path = os.path.join(args.corpus, "reference", "attack-techniques.json")
    if os.path.exists(attack_path):
        try:
            with open(attack_path, "r", encoding="utf-8") as handle:
                attack_techniques = json.load(handle).get("techniques") or {}
        except (OSError, ValueError):
            attack_techniques = {}

    problems = []
    xdm_fields = None
    xdm_fields_path = os.path.join(schema_dir, "xdm-fields.json")
    if os.path.exists(xdm_fields_path):
        with open(xdm_fields_path, "r", encoding="utf-8") as handle:
            xdm_fields = json.load(handle)
    else:
        problems.append(Problem(xdm_fields_path, "the bundled XDM field snapshot is absent, so no "
                                "marker binding can be checked and emit_xql.py refuses to run"))
    bindings_checked = bool(xdm_fields) and _emit is not None
    # Checked before the records rather than after them, because every how-block is derived
    # through this map in the loop below. Checked after, a broken map crashed the loop with
    # a traceback and the problem that would have explained it was never printed.
    map_problems = check_locus_map(vocab, schema, locus_map, problems, attack_techniques)
    if not locus_map:
        derivation_skipped = "corpus/schema/locus-map.json is absent"
    elif _locus is None:
        # The import is optional so that this script runs without the consultation script.
        # The tally below dereferenced it anyway, so its absence was an AttributeError.
        derivation_skipped = "scripts/consult.py is not importable"
    elif map_problems:
        derivation_skipped = ("corpus/schema/locus-map.json has {} problem(s), listed above"
                              .format(map_problems))
    else:
        derivation_skipped = None
    # The prose ships too. Scanned from the bundle root rather than from --corpus, because the
    # file that leaked a licensed identifier was corpus/README.md's sibling documentation and
    # a corpus-scoped walk would have missed SKILL.md and README.md entirely.
    check_markdown_disclosure(pathlib.Path(BUNDLE_ROOT), problems)
    aliases_path = os.path.join(schema_dir, "aliases.json")
    aliases = {}
    if os.path.exists(aliases_path):
        with open(aliases_path, "r", encoding="utf-8") as handle:
            aliases = json.load(handle)
            check_aliases(aliases, vocab, problems)
    locus_counts, exposure_counts = {}, {}
    coverage = {"how_total": 0, "how_with_markers": 0, "alert_total": 0,
                "alert_with_markers": 0, "alert_missing": [], "how_inherited": 0}

    pattern_ids = set()
    pattern_markers = {}
    # Every marker, with where it sits, for the one check that reads across the corpus: a word
    # one marker flags as normalised is not a literal anywhere else.
    word_markers = []
    declared_patterns = 0
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
                where = "patterns.jsonl:{} ({})".format(lineno, pid)
                # Derived only through a map that checked clean, as every block is below.
                check_declared_pattern_locus(pattern, vocab,
                                             {} if derivation_skipped else locus_map,
                                             where, problems)
                if pattern.get("locus"):
                    declared_patterns += 1
                check_marker_list(pattern.get("markers"), vocab.get("marker_type", {}), where,
                                  "pattern", problems, marker_item_schema(schema),
                                  vocab.get("normalised_marker_types"))
                for j, m in enumerate(pattern.get("markers") or []):
                    word_markers.append((where, "pattern.markers[{}]".format(j), m))
                check_combination(pattern.get("markers"), pattern.get("combine"), where,
                                  "pattern", problems)
                if bindings_checked:
                    check_bindings(pattern.get("markers"), xdm_fields, where, "pattern", problems)
                    check_event_kind_join(pattern.get("markers"), pattern.get("combine"),
                                          xdm_fields, where, "pattern", problems)
                    check_connection_actor(pattern.get("markers"), pattern.get("combine"),
                                           xdm_fields, where, "pattern", problems)
                check_literal_backslashes(pattern.get("markers"), where, "pattern", "markers",
                                          problems)
                if xdm_fields:
                    check_sketch(pattern.get("xql_sketch"), xdm_fields, where, problems)
                for tid in pattern.get("technique") or []:
                    cited_techniques.setdefault(tid, set()).add(pid)

    scope = {}
    scope_path = os.path.join(schema_dir, "scope.json")
    if os.path.exists(scope_path):
        with open(scope_path, "r", encoding="utf-8") as handle:
            scope = json.load(handle)
    exposure_names, refused = [], 0

    advisories = None
    advisories_path = os.path.join(args.corpus, "reference", "advisory-identifiers.json")
    if os.path.exists(advisories_path):
        try:
            with open(advisories_path, "r", encoding="utf-8") as handle:
                advisories = json.load(handle).get("advisories")
        except (OSError, ValueError, AttributeError):
            advisories = None
    cited = []

    obs_dir = os.path.join(args.corpus, "observations")
    seen_ids = {}
    count = 0
    kev_ids, kev_tagged = set(), []
    generated = []

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
            check_seed_support(record, where, problems)
            check_markers(record, vocab, where, problems, coverage, pattern_markers)
            check_generated_surface(record, locus_map, where, problems)
            cited.append((where, record))
            if not derivation_skipped:
                # Read through the table, so only once check_locus_map() has passed it.
                check_identifier_signals(record, locus_map, where, problems)
                check_declared_locus(record, locus_map, where, problems)
                # Exposures carry no how-block, so the block tally below never saw one. They
                # are tallied on their own line, because their placement follows a different
                # rule: a generated exposure's surface is not read.
                if record.get("record_type") == "exposure":
                    locus, _, basis = _locus.locus_for(record, None, None, locus_map)
                    exposure_counts[locus] = exposure_counts.get(locus, 0) + 1
                    if set(locus_map.get("untrusted_surface_tags") or {}) & set(record.get("tags") or []):
                        exposure_counts["_generated"] = exposure_counts.get("_generated", 0) + 1
                    if (record.get("what") or {}).get("identifier_signals"):
                        exposure_counts["_signals"] = exposure_counts.get("_signals", 0) + 1
                    if basis.startswith("tier=identifier;"):
                        exposure_counts["_identifier"] = exposure_counts.get("_identifier", 0) + 1
            if record.get("record_type") == "exposure":
                who = record.get("who") or {}
                exposure_names.append((who.get("vendor"), who.get("products") or []))
                if _locus is not None and _locus.handset_record(record, scope):
                    refused += 1
            tags = record.get("tags") or []
            vulns = (record.get("what") or {}).get("vulnerabilities") or []
            if "known-exploited-catalogue" in tags:
                kev_ids.update(vulns)
            if "in-kev" in tags or "not-in-kev" in tags:
                kev_tagged.append((where, tags, vulns))
            if record.get("record_type") == "exposure":
                family = [t for t in (locus_map.get("untrusted_surface_tags") or {}) if t in tags]
                if family:
                    generated.append((where, family[0], record))

            rid = record.get("id")
            if rid:
                if rid in seen_ids:
                    problems.append(Problem(where, "duplicate id {!r}, first seen at {}".format(rid, seen_ids[rid])))
                else:
                    seen_ids[rid] = where

            for i, how in enumerate(record.get("how", [])):
                check_combination(how.get("markers"), how.get("combine"), where,
                                  "how[{}]".format(i), problems)
                for j, m in enumerate(how.get("markers") or []):
                    word_markers.append((where, "how[{}].markers[{}]".format(i, j), m))
                if bindings_checked:
                    check_bindings(how.get("markers"), xdm_fields, where, "how[{}]".format(i),
                                   problems)
                    check_event_kind_join(how.get("markers"), how.get("combine"), xdm_fields,
                                          where, "how[{}]".format(i), problems)
                    check_connection_actor(how.get("markers"), how.get("combine"), xdm_fields,
                                           where, "how[{}]".format(i), problems)
                for key in ("markers", "fields"):
                    check_literal_backslashes(how.get(key), where, "how[{}]".format(i), key,
                                              problems)
                check_legacy_literals(how.get("fields"), where, "how[{}]".format(i), problems)
                # Tallied here rather than reported per record: the number that says
                # the axis has broken is the distribution, not any single label. A
                # locus that collapses to nothing, or swallows everything, shows up
                # in one line at the bottom and nowhere else.
                if not derivation_skipped:
                    locus, span, basis = _locus.locus_for(record, how, None, locus_map)
                    locus_counts[locus] = locus_counts.get(locus, 0) + 1
                    if span:
                        locus_counts["_span"] = locus_counts.get("_span", 0) + 1
                    if basis.startswith("tier=declared"):
                        locus_counts["_declared"] = locus_counts.get("_declared", 0) + 1
                    # The per-block rules, counted so a change that makes any of them fire
                    # everywhere, or nowhere, shows in one line as the distribution does.
                    if "set aside for this block" in basis:
                        kind = ("_set_aside_supply" if (record.get("what") or {}).get(
                            "attack_surface") in (locus_map.get("surface_supply") or [])
                            else "_set_aside_surface")
                        locus_counts[kind] = locus_counts.get(kind, 0) + 1
                    for rule in ("host_evidence", "operation", "posture", "admin_api_unread",
                                 "admin_api_listed", "host_listed"):
                        if basis.startswith("tier={};".format(rule)):
                            locus_counts["_" + rule] = locus_counts.get("_" + rule, 0) + 1
                pid = how.get("pattern_id")
                if pid and pid not in pattern_ids:
                    problems.append(Problem(where, "how[{}].pattern_id {!r} is not in patterns.jsonl".format(i, pid)))
                for tid in how.get("technique") or []:
                    cited_techniques.setdefault(tid, set()).add(rid or where)

    normalised_counts = check_normalised_words(word_markers, vocab, problems)
    check_kev_membership(kev_tagged, kev_ids, problems)
    check_generated_classes(generated, aliases, problems)
    check_scope(scope, exposure_names, problems)
    check_handset_names(scope, aliases, problems)
    advisory_counts = None if advisories is None else \
        check_cited_advisory_identifiers(cited, advisories, problems)

    for problem in problems:
        print(problem)

    pct = lambda a, b: (100 * a // b) if b else 0
    print("\n{} record(s) across {} file(s), {} pattern(s), {} problem(s)".format(
        count, len(files), len(pattern_ids), len(problems)))
    print("marker coverage: {}/{} how-blocks ({}%), {}/{} alert-fidelity blocks ({}%)".format(
        coverage["how_with_markers"] + coverage["how_inherited"], coverage["how_total"],
        pct(coverage["how_with_markers"] + coverage["how_inherited"], coverage["how_total"]),
        coverage["alert_with_markers"], coverage["alert_total"], pct(coverage["alert_with_markers"], coverage["alert_total"])))
    print("normalised markers: {} ({}), printed as a requirement naming the field, never as a "
          "live clause".format(sum(normalised_counts.values()), ", ".join(
              "{} {}".format(t, n) for t, n in sorted(normalised_counts.items())) or "none"))
    if coverage["alert_missing"] and args.gaps:
        print("\nalert-fidelity blocks with no markers (these cannot become rules):")
        for g in coverage["alert_missing"]:
            print("  " + g)
    if coverage["alert_missing"]:
        print("{} alert-fidelity block(s) still have no markers; run with --gaps to list them".format(len(coverage["alert_missing"])))

    if not bindings_checked:
        print("marker bindings: skipped - {}, so no marker's field was checked".format(
            "scripts/emit_xql.py is not importable" if xdm_fields else
            "corpus/schema/xdm-fields.json is absent"))
    if derivation_skipped:
        print("locus derivation: skipped - {}, so no block was derived".format(derivation_skipped))
    elif locus_counts:
        order = locus_map.get("locus_order") or sorted(k for k in locus_counts if k[0] != "_")
        total = sum(v for k, v in locus_counts.items() if k[0] != "_")
        print("locus derivation: {} how-blocks -> {}; {} declared override(s), {} carrying a span".format(
            total, " ".join("{}={}".format(k, locus_counts.get(k, 0)) for k in order),
            locus_counts.get("_declared", 0), locus_counts.get("_span", 0)))
        print("locus derivation (per block): {} block(s) past their record's surface placed "
              "without it, {} of them on a supply surface and {} by their host evidence; {} "
              "placed by a cloud administrative operation; {} placed as a posture question; {} "
              "placed off an administrative API class they never read; {} placed by an "
              "administrative API class listed after the first; {} placed by an endpoint class "
              "listed after the first; {} pattern(s) declaring a locus".format(
                  locus_counts.get("_set_aside_supply", 0) + locus_counts.get("_set_aside_surface", 0),
                  locus_counts.get("_set_aside_supply", 0), locus_counts.get("_host_evidence", 0),
                  locus_counts.get("_operation", 0), locus_counts.get("_posture", 0),
                  locus_counts.get("_admin_api_unread", 0), locus_counts.get("_admin_api_listed", 0),
                  locus_counts.get("_host_listed", 0), declared_patterns))
    if not derivation_skipped and exposure_counts:
        order = locus_map.get("locus_order") or sorted(k for k in exposure_counts if k[0] != "_")
        print("locus derivation (exposures): {} records -> {}; {} generator-tagged, placed with "
              "their assigned attack_surface not read; {} carrying what.identifier_signals, {} "
              "placed by every identifier's own text".format(
                  sum(v for k, v in exposure_counts.items() if k[0] != "_"),
                  " ".join("{}={}".format(k, exposure_counts.get(k, 0)) for k in order),
                  exposure_counts.get("_generated", 0), exposure_counts.get("_signals", 0),
                  exposure_counts.get("_identifier", 0)))
    if advisory_counts is None:
        print("cited advisory identifiers: skipped - corpus/reference/advisory-identifiers.json "
              "is absent or unreadable, so no record's identifiers were held to its source")
    else:
        print("cited advisory identifiers: {} record(s) cite only CISA pages held in "
              "corpus/reference/advisory-identifiers.json ({} pages) and were held to the "
              "identifiers those pages name; {} also cite a source not held there, and {} cite a "
              "CISA page not held there, and are not checked".format(
                  advisory_counts[0], len(advisories), advisory_counts[1], advisory_counts[2]))
    if _locus is not None and scope.get("handset_exposures"):
        # Held, validated and listed by query.py; refused only from a consultation.
        print("handset scope: {} of {} exposure records are handset records consult.py "
              "refuses (corpus/schema/scope.json)".format(refused, len(exposure_names)))

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
    #
    # Resolving is not the same as live. The reference lists revoked and deprecated ids as
    # entries, so key membership counted a reintroduced T1562.001 as resolving; since 0.43.0
    # the reference carries `revoked`, `deprecated` and `replaced_by`, and the line splits
    # the two. tests/test_attack_reference.py holds the shipped corpus to zero withdrawn
    # citations, so the split is a release gate without being fatal here.
    ref_path = os.path.join(args.corpus, "reference", "attack-techniques.json")
    if cited_techniques and os.path.exists(ref_path):
        try:
            with open(ref_path, "r", encoding="utf-8") as handle:
                reference = json.load(handle)
            techniques = reference.get("techniques") or {}
            known = set(techniques)
        except (OSError, ValueError):
            known = None
        if known:
            unresolved = sorted(t for t in cited_techniques if t not in known)
            withdrawn = sorted(t for t in cited_techniques if t in known
                               and (techniques[t].get("revoked") or techniques[t].get("deprecated")))
            total = len(cited_techniques)
            print("technique ids resolving against the shipped reference: {}/{}; to a live id "
                  "{}, to a REVOKED or DEPRECATED id {}".format(
                      total - len(unresolved), total,
                      total - len(unresolved) - len(withdrawn), len(withdrawn)))
            if withdrawn:
                def fate(tid):
                    entry = techniques[tid]
                    if entry.get("revoked") and entry.get("replaced_by"):
                        return "{} -> {}".format(tid, entry["replaced_by"])
                    if entry.get("revoked"):
                        return "{} (REVOKED, {})".format(tid, "successor {} deprecated".format(
                            entry["successor_deprecated"]) if entry.get("successor_deprecated")
                            else "no replacement")
                    return "{} (DEPRECATED, no replacement)".format(tid)
                print("{} cited technique id(s) are REVOKED or DEPRECATED in ATT&CK {}: {}".format(
                    len(withdrawn), reference.get("version") or "?",
                    ", ".join(fate(t) for t in withdrawn)))
                if args.gaps:
                    for tid in withdrawn:
                        print("  {} cited by {}".format(tid, ", ".join(sorted(cited_techniques[tid]))))
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
