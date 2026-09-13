#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Check that a record's markers are complete enough to hand to a rule author.

This corpus does not author detection rules. It supplies the evidence a
rule-authoring skill needs: typed literal markers, the query shape they imply,
and an explicit note where a value has to be measured locally rather than
assumed. This script exists to keep that handoff honest. A marker set that
cannot be turned into a query is not a marker set, it is prose.

The XQL it prints is a skeleton for inspection, not a finished rule. Dataset
selection, field mapping and every threshold marked <bound> are the downstream
author's decisions, and are deliberately left unresolved here.

Usage:
    emit_xql.py <record-id-or-substring> [--corpus DIR]
    emit_xql.py --all [--shape single_event]
    emit_xql.py <record-id> --json      # structured handoff, what a skill consumes
"""
import argparse
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import consult as C  # noqa: E402  the locus ladder is shared deliberately, not reimplemented

# Where a marker type has an obvious XDM home, use it. A marker's own "xdm" key
# always wins over this table, because the record author knows the context.
DEFAULT_XDM = {
    "process_name": "xdm.target.process.name",
    "process_path": "xdm.target.process.executable.path",
    "command_line": "xdm.target.process.command_line",
    "parent_process": "xdm.source.process.name",
    "file_path": "xdm.target.file.path",
    "file_name": "xdm.target.file.filename",
    "file_extension": "xdm.target.file.extension",
    "file_hash": "xdm.target.file.sha256",
    "domain": "xdm.network.dns.dns_question.name",
    "url_path": "xdm.network.http.url",
    "user_agent": "xdm.network.http.user_agent",
    "ip": "xdm.target.ipv4",
    "port": "xdm.target.port",
    "username": "xdm.source.user.username",
    "group_name": "xdm.source.user.groups",
    "event_id": "xdm.event.id",
    "tls_cert_subject": "xdm.network.tls.server_certificate.subject",
    "protocol": "xdm.network.ip_protocol",
    "service_name": "xdm.target.service.name",
    "cloud_operation": "xdm.event.operation",
    "registry_key": "xdm.target.registry.key",
    "registry_value_name": "xdm.target.registry.value_name",
}

# Marker types that describe state rather than an event field. These belong in an
# inventory question, not a filter clause.
STATE_TYPES = {"cve", "software_version"}


def quote(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return '"{}"'.format(str(value).replace('\\', '\\\\').replace('"', '\\"'))


def predicate(marker):
    """One marker becomes one filter clause, or a reason it cannot."""
    mtype = marker.get("type")
    match = marker.get("match", "equals")
    value = marker.get("value")

    if mtype == "computed":
        expr = marker.get("expr", "")
        op = {"gt": ">", "lt": "<", "equals": "="}.get(match, "=")
        return "{} {} {}".format(expr, op, quote(value)), None

    field = marker.get("xdm") or DEFAULT_XDM.get(mtype)
    if not field:
        return None, "no XDM binding for marker type {!r}".format(mtype)

    if match == "in":
        items = ", ".join(quote(v) for v in (value if isinstance(value, list) else [value]))
        return "{} in ({})".format(field, items), None
    if match == "regex":
        return '{} ~= {}'.format(field, quote(value)), None
    if match == "contains":
        return '{} contains {}'.format(field, quote(value)), None
    if match == "prefix":
        return '{} ~= {}'.format(field, quote("^" + str(value))), None
    if match == "suffix":
        return '{} ~= {}'.format(field, quote(str(value) + "$")), None
    if match in ("gt", "lt"):
        return "{} {} {}".format(field, ">" if match == "gt" else "<", quote(value)), None
    return "{} = {}".format(field, quote(value)), None


def emit(record, how, index):
    """Build the XQL skeleton for one how-block."""
    markers = how.get("markers") or []
    shape = how.get("rule_shape")
    dataset = how.get("dataset_hint") or "<dataset>"
    lines = []
    notes = []

    state = [m for m in markers if m.get("type") in STATE_TYPES]
    event = [m for m in markers if m.get("type") not in STATE_TYPES]

    clauses = []
    for m in event:
        clause, why = predicate(m)
        if clause:
            clauses.append(clause)
        else:
            notes.append(why)

    header = "// {} :: how[{}]  pattern={}  fidelity={}  shape={}".format(
        record.get("id"), index, how.get("pattern_id"), how.get("fidelity"), shape or "UNSET")
    lines.append(header)

    if state:
        vals = ", ".join(str(m.get("value")) for m in state)
        lines.append("// inventory precondition: {}".format(vals))

    if shape == "inventory" or (state and not clauses):
        lines.append("// answered against asset or configuration state, not an event stream")
        if clauses:
            lines.append("dataset = <asset_dataset> | filter " + " and ".join(clauses))
        return lines, notes

    if not clauses:
        notes.append("no event-bound markers, nothing to filter on")
        return lines, notes

    lines.append("dataset = {}".format(dataset))
    lines.append("| filter " + "\n         and ".join(clauses))

    if shape == "threshold":
        lines.append("| comp count() as hits by <grouping_key>, bin(_time, <window>)")
        lines.append("| filter hits > <bound>          // bound must be measured, not assumed")
    elif shape == "correlation":
        lines.append("// correlation: join the above against <second_event_set> on <join_key>")
    elif shape == "sequence":
        lines.append("// sequence: the above must precede <following_event> within <window>")
    elif shape == "absence":
        lines.append("| comp count() as hits by <grouping_key>, bin(_time, <window>)")
        lines.append("| filter hits = 0                // the signal is the expected event not arriving")

    return lines, notes


def load(corpus):
    out = []
    for path in sorted(glob.glob(os.path.join(corpus, "observations", "*.jsonl"))):
        for line in open(path, encoding="utf-8"):
            if line.strip():
                out.append(json.loads(line))
    return out


def load_attack(corpus):
    """ATT&CK reference, so a rule author does not need their own copy."""
    path = os.path.join(corpus, "reference", "attack-techniques.json")
    if os.path.exists(path):
        return json.load(open(path, encoding="utf-8")).get("techniques", {})
    return {}


def load_patterns(corpus):
    out = {}
    path = os.path.join(corpus, "patterns", "patterns.jsonl")
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            if line.strip():
                p = json.loads(line)
                out[p["id"]] = p
    return out


def load_d3fend(corpus):
    """D3FEND countermeasures, so the handoff carries what to do as well as what to see."""
    path = os.path.join(corpus, "reference", "d3fend-countermeasures.json")
    if os.path.exists(path):
        return json.load(open(path, encoding="utf-8"))
    return {}


def handoff(record, how, index, patterns, attack=None, d3fend=None, locus_map=None):
    """The structured object a rule-authoring skill consumes.

    Record markers are the literals this particular source gave us. Pattern
    markers are the generic shape of the detection, shared across every record
    that cites it. Both are supplied separately so the author can decide which
    to anchor on rather than receiving them pre-merged.
    """
    pat = patterns.get(how.get("pattern_id")) or {}
    locus, span, locus_basis = C.locus_for(record, how, pat, locus_map)
    return {
        "record_id": record.get("id"),
        "how_index": index,
        "pattern_id": how.get("pattern_id"),
        "pattern_name": pat.get("name"),
        "rule_shape": how.get("rule_shape") or pat.get("rule_shape"),
        # The typed handoff is the one consumer that parses rather than reads. Omitting
        # the axis here would mean a downstream author could not group or filter by it
        # without re-deriving the whole ladder.
        "locus": locus,
        "locus_span": [locus] + ([span] if span else []),
        "locus_basis": locus_basis,
        "fidelity": how.get("fidelity"),
        "confidence": how.get("confidence"),
        "evidence_type": how.get("evidence_type") or pat.get("evidence_type"),
        "technique": how.get("technique") or pat.get("technique"),
        "markers_from_source": how.get("markers") or [],
        "markers_from_pattern": pat.get("markers") or [],
        # How many independent public rule sets implement a detection for the same
        # techniques. Evidence that the scenario runs against real telemetry, not a
        # quality score: several corpus-unique patterns are posture questions that no
        # detection rule expresses, and OT is barely covered externally at all.
        "external_corroboration": pat.get("external_corroboration"),
        # ATT&CK's own view of the cited techniques: what they are called, which
        # telemetry they are visible in, and which elements the framework states
        # must be tuned locally rather than shipped as constants.
        "attack": [
            {"id": t, "name": (attack or {}).get(t, {}).get("name"),
             "tactics": (attack or {}).get(t, {}).get("tactics"),
             "log_sources": (attack or {}).get(t, {}).get("log_sources"),
             "tune_locally": (attack or {}).get(t, {}).get("mutable_elements")}
            for t in (how.get("technique") or pat.get("technique") or [])
            if (attack or {}).get(t)
        ],
        # What to do once the rule fires, keyed off the same technique ids. Ordered
        # contain-eradicate-recover first, so a truncating consumer keeps the steps
        # that matter on the day. An empty list is a gap in D3FEND, not an all-clear.
        "countermeasures": [
            dict({"id": cid}, **{k: v for k, v in
                                 ((d3fend or {}).get("countermeasures") or {}).get(cid, {}).items()
                                 if k in ("name", "tactic", "definition", "url")})
            for t in (how.get("technique") or pat.get("technique") or [])
            for cid in (((d3fend or {}).get("by_attack") or {}).get(t.upper()) or [])
        ][:12],
        "logic": how.get("logic") or pat.get("logic"),
        "caveat": how.get("caveat") or pat.get("caveat"),
        "provenance": {
            "publisher": record.get("where", {}).get("publisher"),
            "title": record.get("where", {}).get("title"),
            "url": record.get("where", {}).get("url"),
            "vulnerabilities": record.get("what", {}).get("vulnerabilities", []),
        },
        "vendor": record.get("who", {}).get("vendor"),
        "product_class": record.get("who", {}).get("product_class", []),
    }


def tally(shown, verb, skipped, filtered, available, wanted_shape):
    """The one-line account of what became of every candidate block.

    Both modes drop blocks for two unrelated reasons and only ever reported one of them,
    so `--shape correlation` over a record holding two single_event blocks printed
    "0 block(s) emitted, 0 skipped for having no markers" -- numbers each true and
    together describing nothing. A reader could not tell an empty record from a filter
    that matched no shape, and the second is usually a typo in the shape name, so the
    shapes that were actually there are named when the filter took everything.
    """
    line = "// {} block(s) {}, {} skipped for having no markers".format(shown, verb, skipped)
    if wanted_shape:
        line += ", {} filtered out by --shape {}".format(filtered, wanted_shape)
        if filtered and not shown:
            line += " (shapes present: {})".format(
                ", ".join(sorted(s or "unset" for s in available)))
    return line


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", help="record id or substring")
    ap.add_argument("--corpus", default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "corpus"))
    ap.add_argument("--all", action="store_true")
    # Deliberately not a choices= list. The vocabulary lives in the corpus, so pinning it
    # here would reject a shape the corpus legitimately gains. A value matching nothing is
    # reported instead, with the shapes that were actually available.
    ap.add_argument("--shape",
                    help="emit only blocks of this rule_shape: single_event, correlation, "
                         "sequence, threshold, absence or inventory")
    ap.add_argument("--json", action="store_true",
                    help="emit the structured handoff a rule-authoring skill consumes")
    args = ap.parse_args()

    records = load(args.corpus)
    patterns = load_patterns(args.corpus)
    attack = load_attack(args.corpus)
    d3fend = load_d3fend(args.corpus)
    locus_map = C.load_locus_map(args.corpus)
    if args.target:
        records = [r for r in records if args.target.lower() in r.get("id", "").lower()]
    if not records:
        print("no matching record", file=sys.stderr)
        return 1

    if args.json:
        out, skipped, filtered, available = [], 0, 0, set()
        for r in records:
            for i, how in enumerate(r.get("how", [])):
                pat = patterns.get(how.get("pattern_id")) or {}
                if not (how.get("markers") or pat.get("markers")):
                    skipped += 1
                    continue
                shape = how.get("rule_shape") or pat.get("rule_shape")
                if args.shape and shape != args.shape:
                    filtered += 1
                    available.add(shape)
                    continue
                out.append(handoff(r, how, i, patterns, attack, d3fend, locus_map))
        print(json.dumps(out, indent=1))
        print(tally(len(out), "handed off", skipped, filtered, available, args.shape),
              file=sys.stderr)
        return 0

    emitted = skipped = filtered = 0
    available = set()
    for r in records:
        for i, how in enumerate(r.get("how", [])):
            pat = patterns.get(how.get("pattern_id")) or {}
            if not how.get("markers"):
                if pat.get("markers"):
                    how = dict(how, markers=pat["markers"],
                               rule_shape=how.get("rule_shape") or pat.get("rule_shape"))
                else:
                    skipped += 1
                    continue
            if args.shape and how.get("rule_shape") != args.shape:
                filtered += 1
                available.add(how.get("rule_shape"))
                continue
            lines, notes = emit(r, how, i)
            print("\n".join(lines))
            for n in notes:
                print("// GAP: {}".format(n))
            print()
            emitted += 1

    print(tally(emitted, "emitted", skipped, filtered, available, args.shape), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
