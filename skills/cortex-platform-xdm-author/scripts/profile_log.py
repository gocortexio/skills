#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: GoCortexIO
"""profile_log.py <sample>

Static profiler for raw vendor log samples. Reads a single file,
detects the format, walks each record into leaf paths, infers types,
computes null rates, and attaches ranked XDM candidates per field
from the shipped anchor index.

Output is a JSON worksheet on stdout:

    {
      "source": "<input path>",
      "detected_format": "json|jsonl|cef|leef|syslog-5424|syslog-3164|kv|csv|tsv",
      "record_count": <int>,
      "fields": [
        {
          "path": "transactions[].http.method",
          "leaf": "method",
          "type": "string|integer|float|boolean|ip|timestamp|object-array|null",
          "sample": <representative value or null>,
          "null_rate": <0.0..1.0>,
          "in_object_array": <bool>,
          "xdm_candidates": [
            {"xdm_path": "...", "frequency": int, "score": int}
          ]
        }
      ],
      "object_arrays": [
        {"path": "transactions[]",
         "discriminator": "phase",
         "values": ["request", "response"]}
      ],
      "authentication": {"detected": bool, "signals": [...],
                         "mandatory_fields": [...]},
      "network": {"detected": bool, "signals": [...],
                  "mandatory_fields": [...]}
    }

The ``authentication`` and ``network`` blocks are independent story
detections (an event can be both -- xdm.event.tags takes the union);
each carries the mandatory XDM field set for its story when detected.

``null_rate`` is per top-level record. For a field inside an object-
array, multiple elements within a single record collapse to one
observation, so ``transactions[].http.status`` with
``null_rate = 0.5`` means the path was absent or null in half the
records, not in half the transactions.

Pass ``--format text`` for a table instead of JSON.

Exit codes:
    0   profile produced
    1   argument error
    2   cannot read or parse the sample

Scope: describe the log shape. Does not write rule stages, choose an
array-projection strategy, or compile the rule. See
../references/workflow.md for the workflow.

Python 3.9+ stdlib only.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

# Shared field-anchor helpers live in _anchor_index so this script and
# lookup_anchor.py do not duplicate the corpus knowledge.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _anchor_index import (  # noqa: E402
    build_reverse_index,
    load_anchors,
    normalise_synonym,
)


# --------------------------------------------------------------------
# Format detection
# --------------------------------------------------------------------

# Order matters: more specific markers first.
_CEF_HEADER_RE = re.compile(r"^CEF:\d+\|")
_LEEF_HEADER_RE = re.compile(r"^LEEF:\d+\.\d+\|")
_SYSLOG_5424_RE = re.compile(
    r"^<\d{1,3}>\d{1,2}\s+\d{4}-\d{2}-\d{2}T"  # <PRI>VERSION YYYY-MM-DDT...
)
# The priority token is optional as a WHOLE GROUP: a relay can strip the
# <NNN> entirely (the case syslog-envelope.md documents), and the old
# pattern's `>?` only made the closing bracket optional, so those lines
# fell through to "unknown".
_SYSLOG_3164_RE = re.compile(
    r"^(?:<\d{1,3}>)?[A-Z][a-z]{2}\s+\d{1,2}\s+\d{1,2}:\d{2}:\d{2}\s"
)
_KV_LINE_RE = re.compile(r"^\s*[a-zA-Z_][\w.-]*=\S")


def detect_format(text: str) -> str:
    """Classify the sample's wire format. Single most-confident answer."""
    stripped = text.strip()
    if not stripped:
        return "unknown"

    # JSON / JSONL: parse-driven detection is the only reliable signal.
    if stripped[0] in "{[":
        try:
            json.loads(stripped)
            return "json"
        except json.JSONDecodeError:
            pass
    # JSONL: every non-blank line parses as standalone JSON.
    non_blank = [ln for ln in stripped.splitlines() if ln.strip()]
    if non_blank and all(ln.lstrip().startswith(("{", "[")) for ln in non_blank):
        try:
            for ln in non_blank:
                json.loads(ln)
            return "jsonl"
        except json.JSONDecodeError:
            pass

    first_line = non_blank[0] if non_blank else ""
    if _CEF_HEADER_RE.search(first_line):
        return "cef"
    if _LEEF_HEADER_RE.search(first_line):
        return "leef"
    if _SYSLOG_5424_RE.match(first_line):
        return "syslog-5424"
    if _SYSLOG_3164_RE.match(first_line):
        return "syslog-3164"

    # key=value: at least two `key=value` tokens per line on most lines.
    kv_like = sum(1 for ln in non_blank if _looks_like_kv(ln))
    if non_blank and kv_like >= max(1, len(non_blank) // 2):
        return "kv"

    # CSV / TSV: a header row plus at least one body row, each with the
    # same delimiter count. Try TAB first (less likely to be a false
    # positive than comma).
    csv_format = _detect_delimited(non_blank)
    if csv_format:
        return csv_format

    return "unknown"


def _looks_like_kv(line: str) -> bool:
    # Strip CEF / LEEF prefix-extension separator so the tail-as-kv case
    # does not slip through to a false positive against bare CEF.
    if _CEF_HEADER_RE.search(line) or _LEEF_HEADER_RE.search(line):
        return False
    tokens = re.findall(r"[a-zA-Z_][\w.-]*=", line)
    return len(tokens) >= 2


def _detect_delimited(lines: List[str]) -> Optional[str]:
    if len(lines) < 2:
        return None
    for delim, name in ((",", "csv"), ("\t", "tsv")):
        first_count = lines[0].count(delim)
        if first_count < 1:
            continue
        if all(ln.count(delim) == first_count for ln in lines[:5]):
            return name
    return None


# --------------------------------------------------------------------
# Format-specific record parsers
# --------------------------------------------------------------------


def parse_records(text: str, fmt: str) -> List[dict]:
    """Convert the raw sample into a list of dict records for
    flattening. Each format yields one record per logical event."""
    if fmt == "json":
        data = json.loads(text)
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        if isinstance(data, dict):
            return [data]
        raise ValueError("JSON top-level must be an object or array of objects")
    if fmt == "jsonl":
        out = []
        for ln in text.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            obj = json.loads(ln)
            if isinstance(obj, dict):
                out.append(obj)
        return out
    if fmt == "cef":
        return [_parse_cef(ln) for ln in _non_blank_lines(text)]
    if fmt == "leef":
        return [_parse_leef(ln) for ln in _non_blank_lines(text)]
    if fmt in ("syslog-5424", "syslog-3164"):
        # We don't decompose the syslog wrapper itself -- the body is the
        # interesting payload. Record per line, with the message body
        # extracted into "_message", plus any key=value body merged in
        # alongside (see _envelope_record).
        return [_envelope_record(ln) for ln in _non_blank_lines(text)]
    if fmt == "kv":
        return [_parse_kv(ln) for ln in _non_blank_lines(text)]
    if fmt in ("csv", "tsv"):
        delim = "," if fmt == "csv" else "\t"
        rdr = csv.DictReader(io.StringIO(text), delimiter=delim)
        return [dict(row) for row in rdr]
    # Unknown / positional text (for example a raw AWS VPC Flow export):
    # expose each line as _message, exactly like the syslog wrapper, so
    # the value-signal story detection still runs over the content
    # instead of silently seeing zero records.
    return [_envelope_record(ln) for ln in _non_blank_lines(text)]


def _non_blank_lines(text: str) -> List[str]:
    return [ln for ln in text.splitlines() if ln.strip()]


# A syslog envelope routinely wraps a key=value BODY: a relay in front of
# a FortiGate produces `Aug 28 14:16:41 fw01 <189>date=... srcip=...`,
# and detect_format answers syslog-3164 because the envelope is the more
# specific marker. Keeping the line as one opaque _message hid every one
# of the body's fields from anchor ranking and from all four story
# detectors. Merge the body's pairs in alongside _message so both halves
# are visible; the envelope stays intact, so recommended_pattern is still
# correctly B and references/syslog-envelope.md still applies.
_ENVELOPE_KV_MIN_TOKENS = 4


def _envelope_record(line: str) -> dict:
    """One record for an envelope-wrapped line: always ``_message``, plus
    the key=value body merged in when the line carries enough pairs to be
    a kv body rather than prose that happens to contain one ``foo=bar``."""
    rec: dict = {"_message": line}
    if len(_KV_TOKEN_RE.findall(line)) < _ENVELOPE_KV_MIN_TOKENS:
        return rec
    for key, value in _parse_kv(line).items():
        rec.setdefault(key, value)
    return rec


def _parse_cef(line: str) -> dict:
    """CEF: ``CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|ext``.
    The extension is space-separated key=value pairs."""
    # CEF separator is '|' but '\|' inside values is escaped.
    parts = re.split(r"(?<!\\)\|", line, maxsplit=7)
    rec: dict = {}
    if len(parts) >= 7:
        headers = [
            "cef_version", "cef_vendor", "cef_product", "cef_version_field",
            "cef_signature_id", "cef_name", "cef_severity",
        ]
        for h, v in zip(headers, parts[:7]):
            rec[h] = v.replace("\\|", "|")
        if len(parts) == 8:
            rec.update(_parse_kv(parts[7]))
    return rec


def _parse_leef(line: str) -> dict:
    """LEEF: ``LEEF:Version|Vendor|Product|Version|EventID|ext``."""
    parts = re.split(r"(?<!\\)\|", line, maxsplit=5)
    rec: dict = {}
    if len(parts) >= 5:
        headers = [
            "leef_version", "leef_vendor", "leef_product",
            "leef_version_field", "leef_event_id",
        ]
        for h, v in zip(headers, parts[:5]):
            rec[h] = v.replace("\\|", "|")
        if len(parts) == 6:
            # LEEF extension delimiter may be tab or '|' or the value of
            # `delimChar` field within the extension; default is tab.
            rec.update(_parse_kv(parts[5].replace("\t", " ")))
    return rec


_KV_TOKEN_RE = re.compile(
    r"([a-zA-Z_][\w.-]*)=(\"(?:[^\"\\]|\\.)*\"|\S*)"
)


def _parse_kv(line: str) -> dict:
    """Best-effort key=value parser. Supports `key="quoted value"` and
    `key=bareword`."""
    out: dict = {}
    for m in _KV_TOKEN_RE.finditer(line):
        k, v = m.group(1), m.group(2)
        if v.startswith('"') and v.endswith('"') and len(v) >= 2:
            v = v[1:-1].replace('\\"', '"')
        out[k] = v
    return out


# --------------------------------------------------------------------
# Flattening
# --------------------------------------------------------------------


_HEADER_PAIR_KEYS = ({"name", "value"}, {"key", "value"})


def _is_header_pair_array(arr: list) -> bool:
    """Detect ``[{name: X, value: Y}, ...]`` (or key/value) so the named
    items surface as fields rather than positional array entries."""
    if not arr or not all(isinstance(el, dict) for el in arr):
        return False
    for shape in _HEADER_PAIR_KEYS:
        if all(shape.issubset(el.keys()) for el in arr):
            return True
    return False


def flatten_record(rec: dict) -> "OrderedDict[str, object]":
    """Walk a single record into ``{path: value}`` leaf entries.

    Object arrays produce a synthetic entry with the array path (value
    is the list of inner dicts; the caller infers element schema and
    discriminator), AND per-leaf entries with ``[]`` in the path so a
    consumer can render ``transactions[].http.method``.

    Primitive arrays surface as a single entry with the path unchanged
    and value of type ``list`` (the type inference handles arrays).

    Header-pair arrays (``[{name: X, value: Y}, ...]``) also surface
    each ``name`` as a synthetic field at ``<path>[name=<X>]``.
    """
    out: "OrderedDict[str, object]" = OrderedDict()
    _walk(rec, "", out)
    return out


def _walk(value: object, path: str, out: "OrderedDict[str, object]") -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            sub = f"{path}.{k}" if path else k
            _walk(v, sub, out)
        return
    if isinstance(value, list):
        if not value:
            out[path] = []  # type: ignore[assignment]
            return
        if all(isinstance(el, dict) for el in value):
            # Record the array shape itself.
            out[path] = value  # whole list for discriminator detection
            if _is_header_pair_array(value):
                # Surface each header by name as a synthetic field.
                for el in value:
                    pair = el if isinstance(el, dict) else {}
                    name = pair.get("name") or pair.get("key")
                    if name is None:
                        continue
                    syn_path = f"{path}[name={name}]"
                    out[syn_path] = pair.get("value")
            # Then descend into each element to gather inner leaf paths.
            arr_path = f"{path}[]"
            for el in value:
                _walk(el, arr_path, out)
            return
        # Primitive array (or mixed). Keep as a single leaf.
        out[path] = value
        return
    # Scalar leaf.
    out[path] = value


# --------------------------------------------------------------------
# Type inference
# --------------------------------------------------------------------


_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

# MAC address (six pairs of hex separated by colons) and bare clock
# times (``12:34`` / ``12:34:56`` / ``12:34:56.789``) both look hex-and-
# colons enough to fool a naive IPv6 check. Reject them up front so
# they fall through to the timestamp / string typing path instead.
_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
_CLOCK_TIME_RE = re.compile(r"^\d{1,2}:\d{2}(:\d{2})?(\.\d+)?$")

# Real IPv6 form. An optional leading hex segment of 1-4 chars,
# followed by 2-7 ``:[hex?]`` repetitions. Empty segments are allowed
# so the ``::`` shorthand (and bare ``::``) is captured by the same
# regex without a separate alternative. The colon-count guard below
# rejects ``1:2``-style two-segment near-misses.
_IPV6_RE = re.compile(
    r"^([0-9a-fA-F]{1,4})?(:[0-9a-fA-F]{0,4}){2,7}$"
)
_TIMESTAMP_PATTERNS = [
    # ISO-8601 with optional fractional and Z/+/-HH:MM offset
    re.compile(
        r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
        r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$"
    ),
    # Common epoch-second / epoch-ms representations are caught by the
    # integer/float branch.
]


def infer_type(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "float"
    if isinstance(value, list):
        if value and all(isinstance(el, dict) for el in value):
            return "object-array"
        return "array"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return "string"
        if _IPV4_RE.match(s):
            # Range-check the octets to avoid mis-tagging "999.999.999.999".
            octets = s.split(".")
            if all(0 <= int(o) <= 255 for o in octets):
                return "ip"
        if s.count(":") >= 2:
            # At least two colons rules out two-segment near-misses like
            # ``1:2`` that the IPv6 alternation would otherwise accept.
            # MAC and clock-time forms fall through to the timestamp /
            # string branches instead.
            if not (_MAC_RE.match(s) or _CLOCK_TIME_RE.match(s)):
                if _IPV6_RE.match(s):
                    return "ip"
        for pat in _TIMESTAMP_PATTERNS:
            if pat.match(s):
                return "timestamp"
        # Numeric-looking strings stay strings -- they are routed through
        # to_number() at extraction time; type inference reports the
        # observed wire type.
        return "string"
    return "string"


# --------------------------------------------------------------------
# Aggregation across records
# --------------------------------------------------------------------


def aggregate_fields(records: List[dict]) -> "OrderedDict[str, dict]":
    """Walk every record, accumulate first-seen leaf paths, capture a
    representative sample value (first non-null), tally type votes, and
    compute the per-path null/absence rate across the sample.

    ``null_rate`` is per top-level record. For paths inside an object-
    array, several elements within one record collapse to a single
    observation, so a 0.5 rate on a nested-array path means the path
    was absent or null in half the records, not in half the array
    elements.
    """
    total = len(records) or 1
    agg: "OrderedDict[str, dict]" = OrderedDict()

    for rec in records:
        flat = flatten_record(rec)
        for path, value in flat.items():
            entry = agg.get(path)
            if entry is None:
                entry = {
                    "paths_seen": 0,
                    "non_null_seen": 0,
                    "types": [],
                    "sample": None,
                    "in_object_array": ("[]" in path) or ("[name=" in path),
                    "raw_first_value": value,
                }
                agg[path] = entry
            entry["paths_seen"] += 1
            t = infer_type(value)
            entry["types"].append(t)
            if value is not None and t != "null":
                entry["non_null_seen"] += 1
                if entry["sample"] is None and not isinstance(value, (list, dict)):
                    entry["sample"] = value

    finalised: "OrderedDict[str, dict]" = OrderedDict()
    for path, entry in agg.items():
        # absence rate = (total_records - times_path_was_seen) / total
        # null rate at path = (times_seen_with_null) / total
        present = entry["paths_seen"]
        present_with_null = entry["paths_seen"] - entry["non_null_seen"]
        absent = total - present
        null_rate = (present_with_null + absent) / total

        # Pick the dominant non-null type, else null.
        type_counts: dict = {}
        for t in entry["types"]:
            type_counts[t] = type_counts.get(t, 0) + 1
        non_null = {k: v for k, v in type_counts.items() if k not in ("null",)}
        if non_null:
            chosen_type = max(non_null.items(), key=lambda kv: kv[1])[0]
        else:
            chosen_type = "null"

        leaf = _leaf_name(path)
        finalised[path] = {
            "path": path,
            "leaf": leaf,
            "type": chosen_type,
            "sample": entry["sample"],
            "null_rate": round(null_rate, 3),
            "in_object_array": entry["in_object_array"],
        }
    return finalised


def _leaf_name(path: str) -> str:
    """Return the last dot-separated segment, stripped of array / pair
    markers (``transactions[].http.method`` -> ``method``;
    ``http.headers[name=User-Agent]`` -> ``User-Agent``)."""
    # Strip array markers from the tail.
    if path.endswith("[]"):
        path = path[:-2]
    # ``[name=X]`` suffix -> use X
    m = re.search(r"\[name=([^\]]+)\]$", path)
    if m:
        return m.group(1)
    tail = path.split(".")[-1]
    tail = re.sub(r"\[\]$", "", tail)
    return tail


# --------------------------------------------------------------------
# Object-array discriminator detection
# --------------------------------------------------------------------


def find_object_arrays(records: List[dict]) -> List[dict]:
    """Identify every object-array path, and within each, flag low-
    cardinality keys whose values neatly partition the array elements
    (likely discriminators -- ``phase``, ``role``, ``type``, etc.)."""
    out: List[dict] = []
    array_paths: "OrderedDict[str, list]" = OrderedDict()

    for rec in records:
        _collect_object_arrays(rec, "", array_paths)

    for path, elements in array_paths.items():
        if not elements:
            continue
        # Tally values per key across all element dicts.
        per_key: dict = {}
        per_key_count: dict = {}
        for el in elements:
            if not isinstance(el, dict):
                continue
            for k, v in el.items():
                # Discriminators are scalar string or integer values.
                # ``bool`` is a subclass of ``int`` in Python and a binary
                # flag is not a useful discriminator, so it is excluded
                # explicitly. Integer values (HTTP status code, severity
                # level, etc.) are coerced to ``str`` so the existing
                # ``values: List[str]`` contract holds end-to-end.
                if isinstance(v, (str, int)) and not isinstance(v, bool):
                    per_key.setdefault(k, []).append(str(v))
                    per_key_count[k] = per_key_count.get(k, 0) + 1

        discriminator = None
        values: List[str] = []
        for k, vals in per_key.items():
            unique = sorted(set(vals))
            present_count = per_key_count.get(k, 0)
            # Low cardinality + present on most elements + at least two
            # distinct values is the signal.
            if 2 <= len(unique) <= 5 and present_count >= max(2, len(elements) // 2):
                # Prefer keys named like classic discriminators.
                if k.lower() in ("phase", "role", "type", "kind", "action", "direction"):
                    discriminator = k
                    values = unique
                    break
                if discriminator is None:
                    discriminator = k
                    values = unique

        out.append(
            {
                "path": f"{path}[]",
                "element_count": len(elements),
                "discriminator": discriminator,
                "values": values,
            }
        )
    return out


def _collect_object_arrays(
    value: object, path: str, out: "OrderedDict[str, list]"
) -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            sub = f"{path}.{k}" if path else k
            _collect_object_arrays(v, sub, out)
        return
    if isinstance(value, list):
        if value and all(isinstance(el, dict) for el in value):
            out.setdefault(path, []).extend(value)
            arr_path = f"{path}[]"
            for el in value:
                _collect_object_arrays(el, arr_path, out)


# --------------------------------------------------------------------
# XDM candidate attachment
# --------------------------------------------------------------------


def attach_xdm_candidates(
    fields: "OrderedDict[str, dict]", reverse_index: dict, limit: int = 3
) -> None:
    """Look each field's leaf name up in the reverse anchor index. If
    the leaf misses, try a parent-qualified variant (e.g.
    ``http.method`` -> ``http_method``)."""
    for path, field in fields.items():
        leaf = field["leaf"]
        candidates = _lookup(reverse_index, leaf, limit)
        if not candidates:
            parent_qual = _parent_qualified(path)
            if parent_qual and parent_qual != leaf:
                candidates = _lookup(reverse_index, parent_qual, limit)
        field["xdm_candidates"] = candidates


def _lookup(reverse_index: dict, name: str, limit: int) -> List[dict]:
    key = normalise_synonym(name)
    if not key:
        return []
    raw = reverse_index.get(key, [])
    # Compact each candidate to the fields the worksheet documents.
    return [
        {
            "xdm_path": c["xdm_path"],
            "frequency": c["frequency"],
            "score": c["score"],
        }
        for c in raw[:limit]
    ]


def _parent_qualified(path: str) -> str:
    """Build a parent-qualified candidate name from a dotted path.

    ``transactions[].http.method`` -> ``http_method``
    ``session.user_id``           -> ``user_id``
    ``foo.bar.baz``               -> ``bar_baz``
    """
    bare = path.replace("[]", "")
    # Strip ``[name=X]`` segments entirely.
    bare = re.sub(r"\[name=[^\]]+\]", "", bare)
    parts = [p for p in bare.split(".") if p]
    if len(parts) < 2:
        return ""
    return f"{parts[-2]}_{parts[-1]}"


# --------------------------------------------------------------------
# Top-level profile builder
# --------------------------------------------------------------------


def recommend_pattern(fmt: str, arrays: list) -> dict:
    """Map the detected format and object-array shape onto the A/B/C/D
    extraction patterns from references/extraction-patterns.md. Returns
    ``{"primary": str, "reason": str, "also": [str, ...]}``."""
    discriminated = [
        oa for oa in arrays if oa.get("discriminator")
    ]
    header_pairs = [
        oa for oa in arrays
        if any("[name=" in (v or "") for v in [oa.get("path", "")])
    ]
    also: List[str] = []

    if fmt in ("json", "jsonl"):
        primary = "A"
        reason = (
            "JSON sample: extract with json_extract_scalar(_raw_log, "
            '"$.path"). If the tenant pre-parses into typed top-level '
            "columns (so _raw_log is null), switch to Pattern D (arrow "
            "operator)."
        )
        for oa in discriminated:
            also.append(
                f"Pattern D' for the role-tagged array {oa['path']} "
                f"(discriminator '{oa['discriminator']}'): project one "
                "scalar at a time."
            )
        if not discriminated and arrays:
            also.append(
                "label/value pairs present -- consider Pattern C "
                "(regextract on the key/value structure) if paths are not "
                "fixed."
            )
    elif fmt in ("cef", "leef", "syslog-3164", "syslog-5424"):
        primary = "B"
        reason = (
            f"{fmt} is positional / syslog-wrapped: strip the envelope with "
            "regextract, then split + arrayindex for the positional fields. "
            "Wrap arrayindex output in to_string() before any downstream "
            "split / regextract."
        )
    elif fmt == "kv":
        primary = "A"
        reason = (
            "key=value parses into a top-level column; apply Pattern A with "
            "json_extract_scalar(to_string(<column>), \"$.path\") or read "
            "the parsed columns directly (Pattern D)."
        )
    elif fmt in ("csv", "tsv"):
        primary = "D"
        reason = (
            f"{fmt} parses into named top-level columns: reference them "
            "directly (Pattern D). If the row is carried whole in _raw_log, "
            "use Pattern B (split + arrayindex)."
        )
    else:
        primary = "?"
        reason = (
            "format not recognised; inspect the sample by hand and pick a "
            "pattern from references/extraction-patterns.md."
        )

    return {"primary": primary, "reason": reason, "also": also}


# --------------------------------------------------------------------
# Authentication-event detection
# --------------------------------------------------------------------

# Mandatory XDM target set for the authentication story. Mirrors
# _AUTH_MANDATORY in lint_rule.py (which raises the advisory WARN-042).
# Kept here so the profiler can surface the checklist at analysis time.
# The recommended identity mirror: each of these user leaves has an
# xdm.<side>.identity.<leaf> twin that a rule is encouraged to assign
# from the same derivation, appended beside the user field. Canonical
# source: the "Recommended fields (the identity mirror)" table in
# references/authentication-mapping.md. Mirrored in lint_rule.py as
# _IDENTITY_MIRROR_LEAVES and in scaffold_rule.py as _AUTH_RECOMMENDED;
# a test pins the three lists together.
_AUTH_IDENTITY_MIRROR = [
    "xdm.source.identity.upn",
    "xdm.source.identity.identity_type",
    "xdm.source.identity.user_type",
    "xdm.source.identity.username",
    "xdm.source.identity.identifier",
    "xdm.source.identity.domain",
]

_AUTH_MANDATORY = [
    "xdm.source.ipv4",
    "xdm.source.port",
    "xdm.target.ipv4",
    "xdm.target.port",
    "xdm.target.resource.name",
    "xdm.network.ip_protocol",
    "xdm.event.type",
    "xdm.event.tags",
    "xdm.event.operation",
    "xdm.event.original_event_type",
    "xdm.event.outcome",
    "xdm.auth.service",
    "xdm.source.user.upn",
    "xdm.source.user.identity_type",
    "xdm.source.user.user_type",
]

# Field-name signal. The (?<![a-z]) / (?![a-z]) boundaries keep "auth"
# from matching inside "author" / "authority" / "authorize" while still
# firing on "auth_method", "x.auth.result", and similar leaf segments.
_AUTH_NAME_RE = re.compile(
    r"(?<![a-z])("
    r"logon|logoff|login|logout|signin|signon|sign_in|sign_on|"
    r"authentication|authorization|authorized|unauthorized|authz|"
    r"authn|auth|mfa|2fa|otp|sso|saml|oauth|oidc|"
    r"kerberos|ntlm|credential|password|passwd|upn|idp"
    r")(?![a-z])"
)

# Value signal. A representative value matches an authentication-specific
# token. Matched with word-ish boundaries rather than a raw substring:
# now that the value scan walks EVERY record's values (not just the first
# representative sample), a loose substring would false-fire on incidental
# matches ("sso" inside "lesson", "otp" inside "crypto", "saml" inside a
# hostname). The leading boundary allows "_" / "-" so vendor mnemonics
# such as ssh_user_login and cli_user_login_failed still match "login".
# The trailing (?![a-z0-9=]) guard excludes tokens that are immediately
# followed by "=": inside a syslog / kv message, "login=alice" is a FIELD
# NAME carrying user attribution (a proxy web log, for example), not a
# login event. Event descriptions ("Logged in Successfully",
# "action=login", "ssl-login") are unaffected.
_AUTH_VALUE_RE = re.compile(
    r"(?<![a-z0-9])("
    r"logon|logoff|login|logout|logged[ _-]?in|logged[ _-]?out|"
    r"sign[ _-]?in|sign[ _-]?on|signin|signon|"
    r"authentication|authenticated|auth success|auth failure|"
    r"authorization|authorized|unauthorized|"
    r"mfa|multi-factor|two-factor|2fa|otp|sso|saml|kerberos|"
    r"password|credential"
    r")(?![a-z0-9=])",
    re.IGNORECASE,
)

# Stop scanning once we have collected this many distinct signals. The
# detection result only needs a handful; a mixed multi-event log can carry
# hundreds of auth lines, and there is no value in walking them all.
_AUTH_SIGNAL_CAP = 24

# How many signals travel in the worksheet. The list is evidence for a verdict
# that has already been reached, so a sample is enough to audit it by.
_SIGNAL_SAMPLE = 12


def _signal_block(detected: bool, signals: List[dict], capped: bool = False) -> dict:
    """The common shape of a detector's result, with an honest count.

    ``signals`` is truncated for transport, so ``len()`` of what ships is the
    sample size, not the finding. Every section but syslog_relay used to report
    that truncated length as the total: a sample carrying 20 auth-named fields
    reported "12 signal(s)", and no larger number could ever be printed however
    many the log held. The count is taken here, before truncation.

    ``capped`` is passed by the detector, which is the only thing that knows
    whether it stopped early -- the per-record scan caps but the field-name scan
    does not, so comparing the count against the cap infers truncation that
    often did not happen.
    """
    return {
        "detected": detected,
        "signal_count": len(signals),
        "signal_count_capped": capped,
        "signals": signals[:_SIGNAL_SAMPLE],
    }


def detect_authentication(
    fields: dict, records: "Optional[List[dict]]" = None
) -> dict:
    """Auto-detect whether the sample is an authentication event.

    Two independent signals:
      * name  -- a discovered field/leaf path matches _AUTH_NAME_RE.
      * value -- a record value matches _AUTH_VALUE_RE.

    The value signal scans EVERY record when ``records`` is supplied,
    not just the first representative sample. This is essential for
    positional / syslog-wrapped formats (CEF, LEEF, RFC 3164/5424), where
    every line collapses into a single ``_message`` field: the auth lines
    are frequently a minority buried among unrelated traffic, so a
    first-record-only scan silently misses them. Falls back to per-field
    sample scanning when records are not supplied.

    Conservative and deterministic: returns the list of signals so the
    author can see why it fired, plus the mandatory XDM field set to map.
    Detection feeds the advisory WARN-042 in lint_rule.py -- it never
    blocks. See references/authentication-mapping.md."""
    signals: List[dict] = []
    capped = False
    seen: set = set()

    def _add(field: str, match: str, kind: str) -> None:
        key = (kind, field, match)
        if key not in seen:
            seen.add(key)
            signals.append({"field": field, "match": match, "kind": kind})

    # Name signal -- every discovered field path.
    for info in fields.values():
        path = info.get("path", "")
        m = _AUTH_NAME_RE.search(path.lower())
        if m:
            _add(path, m.group(1), "name")

    # Value signal -- scan all records when available, else fall back to
    # the per-field representative samples.
    if records:
        for rec in records:
            for path, value in flatten_record(rec).items():
                if not isinstance(value, str):
                    continue
                vm = _AUTH_VALUE_RE.search(value)
                if vm:
                    _add(path, vm.group(1).lower(), "value")
            if len(signals) >= _AUTH_SIGNAL_CAP:
                # Only a floor if records were actually left unscanned. Stopping
                # on the last one missed nothing, and reporting "24+" there would
                # be the same overclaim in the other direction.
                capped = rec is not records[-1]
                break
    else:
        for info in fields.values():
            sample = info.get("sample")
            if isinstance(sample, str):
                vm = _AUTH_VALUE_RE.search(sample)
                if vm:
                    _add(info.get("path", ""), vm.group(1).lower(), "value")

    detected = bool(signals)
    out: dict = _signal_block(detected, signals, capped)
    if detected:
        out["mandatory_fields"] = list(_AUTH_MANDATORY)
        out["recommended_fields"] = list(_AUTH_IDENTITY_MIRROR)
        out["guidance"] = (
            "Authentication signal detected. Map the full mandatory XDM "
            "field set for the authentication story (see "
            "references/authentication-mapping.md). Enforcement is advisory "
            "(lint WARN-042), never a block. Recommended on top of the "
            "mandatory set: mirror each user.* field listed above into its "
            "xdm.<side>.identity.* twin from the SAME derivation, appended "
            "beside the user assignment and never instead of it, so the "
            "Identity data model populates. The mirror is recommended, not "
            "required -- absence is never flagged."
        )
    return out


# --------------------------------------------------------------------
# Network-event detection
# --------------------------------------------------------------------

# Mandatory XDM target set for the network story. Mirrors
# _NETWORK_MANDATORY in lint_rule.py (which raises the advisory
# WARN-043). Canonical in-bundle source: the "Mandatory fields" table in
# references/network-mapping.md (the drift-guard test keeps all three
# aligned).
_NETWORK_MANDATORY = [
    "xdm.event.outcome",
    "xdm.event.type",
    "xdm.event.tags",
    "xdm.network.ip_protocol",
    "xdm.network.protocol_layers",
    "xdm.source.host.device_id",
    "xdm.source.ipv4",
    "xdm.source.ipv6",
    "xdm.source.is_internal_ip",
    "xdm.source.port",
    "xdm.source.sent_bytes",
    "xdm.target.host.device_id",
    "xdm.target.ipv4",
    "xdm.target.ipv6",
    "xdm.target.is_internal_ip",
    "xdm.target.port",
    "xdm.target.sent_bytes",
]

# Mandatory only where the network event carries an HTTP layer (proxy,
# web gateway, WAF, CASB, DNS-over-HTTPS). Mirrors
# _NETWORK_HTTP_MANDATORY in lint_rule.py.
_NETWORK_HTTP_MANDATORY = [
    "xdm.network.http.http_header.header",
    "xdm.network.http.http_header.value",
    "xdm.network.http.url_category",
]

# Network detection is deliberately more conservative than authentication
# detection: an IP or a port appears in almost every log, so transport
# fields alone NEVER mark a sample as a network event. Only distinctive
# traffic vocabulary counts as a name signal.
# The counter half is morphology-tolerant rather than an ever-growing
# alternation: vendors spell the same idea `sent_bytes`, `sentbytes`,
# `sentbyte` (FortiGate), `orig_bytes` (Zeek) and `bytes_out`. Matching
# the direction word plus the unit covers all of them, and still refuses
# a bare `srcip` / `policyid` / `duration` / `sessionid`.
_NETWORK_NAME_RE = re.compile(
    r"(?<![a-z])("
    r"firewall|netflow|flow|traffic|conn|connection|packets|packet|pkts|"
    r"(?:sent|rcvd|recv|received|in|out|orig|resp)_?"
    r"(?:bytes|byte|pkts|pkt|packets|packet)|"
    r"bytes_sent|bytes_received|sent_bytes|recv_bytes|bytes_in|bytes_out|"
    r"ip_protocol"
    r")(?![a-z])"
)

# The same traffic vocabulary, applied to VALUES -- but only to the value
# of a discriminator-ish field. FortiGate carries the story in
# `type="traffic"`, not in a field NAME, so a name-only scan misses it
# entirely. Gating on the field name is what keeps a stray "connection"
# inside a free-text `msg` from firing.
_DISCRIMINATOR_FIELD_RE = re.compile(
    r"(?:^|[._])(?:log)?(?:type|subtype|event_?type|category|class|logtype)$"
)
_NETWORK_VALUE_VOCAB_RE = re.compile(
    r"(?<![a-z])(firewall|netflow|flow|traffic|connection|session)(?![a-z])",
    re.IGNORECASE,
)

# Value signal, in two families. These carry detection on syslog /
# positional formats, where every line collapses into a single _message
# field and only values are visible.
#
# The ACTION family (allow / deny / drop / ...) is ambiguous on its own:
# an AAA gateway (TACACS+, RADIUS, ISE) logs PERMIT / DENY as an
# AUTHENTICATION decision, with no transport flow behind it. So when the
# sample is already detected as an authentication event and the ONLY
# network evidence is action-family values -- no traffic vocabulary in
# the field names, no transport 5-tuple, no protocol-family token --
# detection is suppressed: the permit/deny belongs to the auth story.
# The PROTOCOL family (tcp / udp / icmp) is unambiguous flow evidence
# and always counts.
_NETWORK_ACTION_VALUE_RE = re.compile(
    r"(?<![a-z0-9])("
    r"allow|allowed|permit|permitted|deny|denied|drop|dropped|"
    r"block|blocked|reset|accept|accepted|reject|rejected"
    r")(?![a-z0-9=])",
    re.IGNORECASE,
)
_NETWORK_PROTO_VALUE_RE = re.compile(
    r"(?<![a-z0-9])(tcp|udp|icmp)(?![a-z0-9])",
    re.IGNORECASE,
)

# Many firewalls emit the IANA protocol NUMBER, not the name -- FortiGate
# sends `proto=6`. A bare integer is meaningless on its own, so this only
# counts when the field name is protocol-ish (_TUPLE_PROTO_RE), which
# stops every other integer column from firing.
_NETWORK_PROTO_NUMBERS = {
    "1": "icmp", "6": "tcp", "17": "udp",
    "47": "gre", "50": "esp", "58": "ipv6-icmp",
}

# Session-teardown dispositions. These are gated to an action-ish field
# NAME, unlike the allow / deny family above which scans every value: the
# bare word "timeout" appears inside exception strings and log prose
# (measured against tests/fixtures/nokia_nfmp.jsonl), and only its
# appearance as the value of an `action` field means a flow disposition.
_ACTION_FIELD_RE = re.compile(
    r"(?:^|[._])(?:action|disposition|verdict|outcome|result|event_action|"
    r"utmaction)(?:$|[._])"
)
_NETWORK_TEARDOWN_VALUE_RE = re.compile(
    r"^(?:close|closed|timeout|teardown|passthrough|server-rst|client-rst|"
    r"ip-conn)$",
    re.IGNORECASE,
)
# The subset that is unambiguously a TRANSPORT event and therefore lifts
# the AAA suppression below: an authentication gateway never emits a TCP
# reset. The rest (close / timeout / passthrough / teardown) stay inside
# the suppression, because a session on an auth gateway also closes and
# also times out.
_NETWORK_TEARDOWN_FLOW_ONLY_RE = re.compile(
    r"^(?:server-rst|client-rst|ip-conn)$", re.IGNORECASE
)

# Transport-pair evidence: TWO or more IPv4:port tokens inside one value
# string describe both ends of a connection (src=IP:PORT ... dst=IP:PORT)
# and are unambiguous flow evidence even without a protocol word. One
# lone IP:port is NOT enough -- diagnostic lines routinely quote a single
# peer ("request from 10.0.76.10:40548") without describing any flow.
_NETWORK_ENDPOINT_RE = re.compile(
    r"\b\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}\b"
)

# Structural signal: a complete transport 5-tuple named in the schema --
# both endpoint addresses, a port, and a protocol. Any one of these alone
# is NOT a signal; only the complete tuple is.
_TUPLE_SRC_IP_RE = re.compile(r"(?:^|[._])(?:src|source|client)[._]?(?:ip|addr)")
_TUPLE_DST_IP_RE = re.compile(
    r"(?:^|[._])(?:dst|dest|destination|remote|server)[._]?(?:ip|addr)"
)
_TUPLE_PORT_RE = re.compile(r"(?:^|[._])[a-z_]*port(?:$|[._])")
_TUPLE_PROTO_RE = re.compile(r"(?:^|[._])proto(?:col)?(?:$|[._])")

_NETWORK_SIGNAL_CAP = 24


def detect_network(
    fields: dict,
    records: "Optional[List[dict]]" = None,
    auth_detected: bool = False,
) -> dict:
    """Auto-detect whether the sample is a network / traffic event.

    Deliberately conservative (an IP alone never fires). Three signals:
      * name      -- a field path carries distinctive traffic vocabulary
                     (firewall / flow / traffic / conn / packets / byte
                     counters), never a bare address or port name.
      * value     -- a record value matches the allow / deny action
                     family or a bare protocol name (tcp / udp / icmp).
                     Scans every record when supplied, which is what
                     carries detection on syslog formats where the whole
                     line is one _message value.
      * structure -- the complete transport 5-tuple is named: source
                     address, destination address, a port, and a
                     protocol all present in the field paths.

    Precision rule for AAA sources: when ``auth_detected`` is True and
    the only evidence is action-family values (permit / deny / ...),
    detection is suppressed -- on a TACACS+ / RADIUS / ISE gateway those
    words are the AUTHENTICATION outcome, not a network action, and the
    records carry no transport flow. Any name signal, structure signal,
    or protocol-family token lifts the suppression.

    Otherwise independent of detect_authentication: a VPN login carries
    both signals and receives both worksheet blocks (the event is BOTH
    stories; xdm.event.tags takes the union). Detection feeds the
    advisory WARN-043 in lint_rule.py -- it never blocks. See
    references/network-mapping.md."""
    signals: List[dict] = []
    capped = False
    seen: set = set()
    non_action_evidence = False

    def _add(field: str, match: str, kind: str) -> None:
        key = (kind, field, match)
        if key not in seen:
            seen.add(key)
            signals.append({"field": field, "match": match, "kind": kind})

    paths = [info.get("path", "") for info in fields.values()]

    # Name signal -- distinctive traffic vocabulary only.
    for path in paths:
        m = _NETWORK_NAME_RE.search(path.lower())
        if m:
            _add(path, m.group(1), "name")
            non_action_evidence = True

    # Structural signal -- the complete 5-tuple.
    lower_paths = [p.lower() for p in paths]
    if (
        any(_TUPLE_SRC_IP_RE.search(p) for p in lower_paths)
        and any(_TUPLE_DST_IP_RE.search(p) for p in lower_paths)
        and any(_TUPLE_PORT_RE.search(p) for p in lower_paths)
        and any(_TUPLE_PROTO_RE.search(p) for p in lower_paths)
    ):
        _add("(field set)", "src+dst+port+protocol", "structure")
        non_action_evidence = True

    # Value signal -- scan all records when available, else fall back to
    # the per-field representative samples.
    def _scan_value(path: str, value: str) -> None:
        nonlocal non_action_evidence
        lower_path = path.lower()
        pm = _NETWORK_PROTO_VALUE_RE.search(value)
        if pm:
            _add(path, pm.group(1).lower(), "value")
            non_action_evidence = True
        # IANA protocol number, only under a protocol-ish field name.
        if _TUPLE_PROTO_RE.search(lower_path):
            named = _NETWORK_PROTO_NUMBERS.get(value.strip())
            if named:
                _add(path, named, "value")
                non_action_evidence = True
        # Traffic vocabulary in the value of a discriminator field --
        # FortiGate's type="traffic" and friends.
        if _DISCRIMINATOR_FIELD_RE.search(lower_path):
            vm = _NETWORK_VALUE_VOCAB_RE.search(value)
            if vm:
                _add(path, vm.group(1).lower(), "value")
                non_action_evidence = True
        if len(_NETWORK_ENDPOINT_RE.findall(value)) >= 2:
            _add(path, "ip:port pair", "value")
            non_action_evidence = True
        am = _NETWORK_ACTION_VALUE_RE.search(value)
        if am:
            _add(path, am.group(1).lower(), "value")
        # Session-teardown disposition, only under an action-ish name.
        if _ACTION_FIELD_RE.search(lower_path):
            stripped = value.strip()
            if _NETWORK_TEARDOWN_VALUE_RE.match(stripped):
                _add(path, stripped.lower(), "value")
                if _NETWORK_TEARDOWN_FLOW_ONLY_RE.match(stripped):
                    non_action_evidence = True

    if records:
        for rec in records:
            for path, value in flatten_record(rec).items():
                if isinstance(value, str):
                    _scan_value(path, value)
            if len(signals) >= _NETWORK_SIGNAL_CAP:
                capped = rec is not records[-1]
                break
    else:
        for info in fields.values():
            sample = info.get("sample")
            if isinstance(sample, str):
                _scan_value(info.get("path", ""), sample)

    # AAA precision rule: action-family words inside an authentication
    # context, with no other flow evidence, are the auth outcome
    # vocabulary (PERMIT / DENY), not a network action.
    if signals and auth_detected and not non_action_evidence:
        return {
            "detected": False,
            "signals": [],
            "suppressed": (
                "action-family values (permit / deny / ...) inside an "
                "authentication event with no transport-flow evidence; "
                "treated as the authentication outcome vocabulary, not a "
                "network action"
            ),
        }

    detected = bool(signals)
    out: dict = _signal_block(detected, signals, capped)
    if detected:
        out["mandatory_fields"] = list(_NETWORK_MANDATORY)
        out["guidance"] = (
            "Network signal detected. Map the full mandatory XDM field "
            "set for the network story (see references/network-mapping.md). "
            "Enforcement is advisory (lint WARN-043), never a block."
        )
    return out


# --------------------------------------------------------------------
# Process / command-execution detection
# --------------------------------------------------------------------

# Recommended (NOT mandatory) process fields the profiler surfaces. XDM
# has no process story tag, so this is advisory only -- see
# references/process-mapping.md and lint WARN-044. Mirrored in
# lint_rule.py's _PROCESS_RECOMMENDED.
_PROCESS_RECOMMENDED = [
    "xdm.source.process.name",
    "xdm.source.process.command_line",
    "xdm.source.process.pid",
    "xdm.source.process.executable.path",
]

# Strong name signal: distinctive process / command vocabulary in a field
# path. Word-ish boundaries keep "proc" out of "procedure" and "process"
# out of "processed". A bare pid is NOT here (it is weak corroboration
# only) -- a pid appears in countless non-process logs.
_PROCESS_STRONG_RE = re.compile(
    r"(?<![a-z0-9])("
    r"command[_ ]?line|cmdline|cmdset|command[_ ]?text|"
    r"process[_ ]?name|proc[_ ]?name|process[_ ]?path|"
    r"image[_ ]?path|exec[_ ]?path|executable|"
    r"script[_ ]?block|"
    r"process|proc|cmd"
    r")(?![a-z0-9])",
    re.IGNORECASE,
)

# Weak corroboration -- recorded when a strong signal is also present, but
# never enough to mark a sample as a process event on its own.
_PROCESS_WEAK_RE = re.compile(
    r"(?<![a-z0-9])(p?pid|parent[_ ]?process|thread[_ ]?id|ppid)(?![a-z0-9])",
    re.IGNORECASE,
)

# Value signal: an executable path or an .exe reference is unambiguous
# process evidence even when no field name carries process vocabulary
# (a positional syslog line, say).
_PROCESS_VALUE_RE = re.compile(
    r"[A-Za-z]:\\[^\s\"]*\.(?:exe|dll|ps1|bat|cmd|scr|vbs)\b"
    r"|/(?:usr|bin|sbin|opt)/[^\s\"]+"
    r"|(?<![a-z0-9])[\w.-]+\.exe(?![a-z0-9])",
    re.IGNORECASE,
)

# A command-accounting token inside a value: cmd= / command= / CmdSet=
# with a value. This carries detection on positional / syslog formats
# where the executed command lives inside the single _message value --
# e.g. TACACS+ "type=ACCOUNTING ... cmd=\"show bgp neighbors\"", which is
# a command execution, not an authentication event.
_PROCESS_CMD_VALUE_RE = re.compile(
    r'(?<![a-z0-9])(?:cmd|cmdset|command)\s*=\s*"?\S',
    re.IGNORECASE,
)

# Endpoint-telemetry shape: a Windows / Sysmon / EVTX record carries an
# event-id discriminator plus an event_data container or an event channel /
# provider. Used only to enrich process guidance (the channel/verb model);
# never a detection gate on its own.
_ENDPOINT_SHAPE_RE = re.compile(
    r"(?<![a-z0-9])(event[_ ]?id|eventid|event[_ ]?data|"
    r"channel|provider[_ ]?name|provider[_ ]?guid)(?![a-z0-9])",
    re.IGNORECASE,
)

_PROCESS_SIGNAL_CAP = 24


def detect_process(
    fields: dict,
    records: "Optional[List[dict]]" = None,
) -> dict:
    """Auto-detect a process or command-execution event.

    Conservative: a lone pid never fires. Signals:
      * name  -- a field path carries distinctive process / command
                 vocabulary (command_line, process_name, executable,
                 cmd, ...). A pid / ppid is weak corroboration only.
      * value -- a record value is an executable path, an .exe
                 reference, or a cmd= / command= / CmdSet= token.
                 Carries detection on positional / syslog formats where
                 the whole line is one value (a TACACS+ type=ACCOUNTING
                 cmd= line is a command execution, not authentication).

    Independent of the auth / network blocks. A TACACS+ / AAA
    command-accounting record carries a `cmd` token, so this block fires
    on it deliberately: an accounting record with a command is a command
    execution, not authentication -- map the command to
    xdm.target.process.command_line with xdm.event.type a process value
    and operation OPERATION_TYPE_AUDIT (see references/process-mapping.md).
    Only the AUTHEN (login) and AUTHOR shapes are authentication. Feeds
    advisory WARN-044; never blocks."""
    signals: List[dict] = []
    capped = False
    seen: set = set()
    strong = False

    def _add(field: str, match: str, kind: str) -> None:
        key = (kind, field, match)
        if key not in seen:
            seen.add(key)
            signals.append({"field": field, "match": match, "kind": kind})

    paths = [info.get("path", "") for info in fields.values()]

    for path in paths:
        m = _PROCESS_STRONG_RE.search(path.lower())
        if m:
            _add(path, m.group(1), "name")
            strong = True

    def _scan_value(path: str, value: str) -> None:
        nonlocal strong
        vm = _PROCESS_VALUE_RE.search(value)
        if vm:
            _add(path, "executable path", "value")
            strong = True
        if _PROCESS_CMD_VALUE_RE.search(value):
            _add(path, "cmd=", "value")
            strong = True

    if records:
        for rec in records:
            for path, value in flatten_record(rec).items():
                if isinstance(value, str):
                    _scan_value(path, value)
            if len(signals) >= _PROCESS_SIGNAL_CAP:
                capped = rec is not records[-1]
                break
    else:
        for info in fields.values():
            sample = info.get("sample")
            if isinstance(sample, str):
                _scan_value(info.get("path", ""), sample)

    # Weak corroboration is only added once a strong signal exists, so it
    # can never trip detection on its own.
    if strong:
        for path in paths:
            m = _PROCESS_WEAK_RE.search(path.lower())
            if m:
                _add(path, m.group(1), "weak")

    # An endpoint-telemetry shape (Windows Security / Sysmon / EVTX): an
    # event-id discriminator alongside an event_data container or a channel.
    # Recorded only to tailor guidance -- it never changes the detection gate.
    endpoint_shape = any(
        _ENDPOINT_SHAPE_RE.search(p.lower()) for p in paths
    )

    out: dict = _signal_block(strong, signals, capped)
    if strong:
        out["recommended_fields"] = list(_PROCESS_RECOMMENDED)
        guidance = (
            "Process / command-execution signal detected. Map the "
            "xdm.*.process.* family the log provides (see "
            "references/process-mapping.md). Recommended, not mandatory "
            "(advisory lint WARN-044). Set xdm.event.operation to the precise "
            "XDM_CONST.OPERATION_TYPE_* verb (PROCESS_CREATE, IMAGE_LOAD, "
            "FILE_REMOVE, REGISTRY_SET_VALUE, EXECUTION, ...); do not leave it "
            "blank when a verb fits. A TACACS+ / AAA command-accounting (cmd=) "
            "record is a command execution, not authentication: map the "
            "command to xdm.target.process.command_line with operation "
            "OPERATION_TYPE_AUDIT and no outcome."
        )
        if endpoint_shape:
            out["endpoint_shape"] = True
            guidance += (
                " This looks like Windows / Sysmon / EVTX endpoint telemetry: "
                "classify each record on three fields -- xdm.event.type = the "
                "channel / source label, xdm.event.original_event_type = the "
                "per-event semantic name, xdm.event.operation = the verb -- and "
                "expect blank xdm.event.tags (there is no process story tag). "
                "A modelled endpoint record does NOT take the "
                "GOCORTEX_UNMODELLED catch-all."
            )
        out["guidance"] = guidance
    return out


def classify(auth_block: dict, network_block: dict, process_block: dict) -> dict:
    """Summarise the per-record classification picture for the sample.

    The auth / network / process detectors are sample-level, so a sample
    that trips more than one is carrying MORE THAN ONE record kind (a
    TACACS+ feed with logins AND command accounting, a firewall feed with
    flows AND VPN sign-ins). Classification is a per-RECORD decision, so
    this block reminds the author to branch xdm.event.type and
    xdm.event.tags per record and to catch-all everything the branches do
    not recognise -- never to stamp one story across the whole feed. See
    references/record-classification.md."""
    families = [
        name
        for name, block in (
            ("authentication", auth_block),
            ("network", network_block),
            ("process", process_block),
        )
        if block.get("detected")
    ]
    multi_kind = len(families) > 1
    detected = ", ".join(families) if families else "none recognised"
    guidance = (
        "Classify PER RECORD, not per sample. Detected kind(s): "
        f"{detected}. A dataset routinely mixes kinds, so decide "
        "xdm.event.type and xdm.event.tags on EACH record via if() over "
        "its own discriminators. xdm.event.tags is the closed six-member "
        "enum (AUTHENTICATION / NETWORK / CLOUD / SAAS / ONPREM / VPN); "
        "end the if-chain with no default so an unrecognised record gets "
        "blank tags, never a guessed marker. Never drop a record: keep "
        "only filter _raw_log != null and give any record no branch "
        'matches the catch-all xdm.event.original_event_type = '
        '"GOCORTEX_UNMODELLED", so a datamodel search returns the same row '
        "count as the raw dataset. See references/record-classification.md."
    )
    return {
        "families_detected": families,
        "multi_kind": multi_kind,
        "guidance": guidance,
    }


# A field whose NAME references MITRE, or a value shaped like an ATT&CK id
# (T#### / T####.### / TA####), signals a MITRE reference in the log.
_MITRE_NAME_RE = re.compile(r"mitre|att.?ck|technique|tactic|\bttp\b", re.IGNORECASE)
_MITRE_VALUE_RE = re.compile(r"(?<![A-Za-z0-9])TA?\d{4}(?:\.\d+)?(?![0-9])")


def detect_mitre(fields: Dict[str, dict], records: List[dict]) -> dict:
    """Flag a MITRE ATT&CK reference in the log: a field NAME carrying
    mitre / att&ck / technique / tactic / ttp, or a value shaped like an
    ATT&CK id (T#### / TA####). Enrichment, not a record kind -- reports
    the target array fields and how to map. See references/mitre-mapping.md."""
    signals: List[dict] = []
    seen: set = set()
    for path, meta in fields.items():
        if _MITRE_NAME_RE.search(path) and ("name", path) not in seen:
            signals.append({"field": path, "kind": "name"})
            seen.add(("name", path))
        sample = meta.get("sample")
        if (
            isinstance(sample, str)
            and _MITRE_VALUE_RE.search(sample)
            and ("value", path) not in seen
        ):
            signals.append({"field": path, "kind": "value"})
            seen.add(("value", path))
    # No collection cap on the MITRE scan, so the count is a true total.
    out: dict = _signal_block(bool(signals), signals)
    if signals:
        out["target_fields"] = [
            "xdm.alert.mitre_techniques",
            "xdm.alert.mitre_tactics",
        ]
        out["guidance"] = (
            "MITRE ATT&CK reference detected (both target fields are Arrays). "
            "For explicit ids/names: scripts/mitre_map.py --kind technique "
            "--ids T1078,... (full crosswalk in assets/mitre_crosswalk.json, "
            "unresolved ids omitted). For a category / name / description "
            "field carrying tactic words: scripts/mitre_map.py --fuzzy-tactics "
            "--temp <column> emits a high-confidence keyword chain that "
            "collects EVERY matched tactic into xdm.alert.mitre_tactics. See "
            "references/mitre-mapping.md."
        )
    return out


# --------------------------------------------------------------------
# Relay / prepend advisory
# --------------------------------------------------------------------
#
# An intermediate syslog server prepends its own header to the payload, so
# a source arrives both direct and relay-wrapped. Two strong, low-false-
# positive signatures: a second <PRI> token (the relay wraps the whole
# original line), or a second RFC-3164 timestamp (the transport header plus
# a device that restates its own clock, e.g. Cisco WLC). A direct single-
# header line -- one <PRI>, one timestamp -- never matches, so normal Cisco
# syslog is not flagged. Advisory only: it points the author at the
# relay-aware Stage 0 and the token-anchoring hard rule (ERR-030); it does
# not change detected_format or classification.
_DOUBLE_PRI_RE = re.compile(r"<\d{1,3}>.*<\d{1,3}>")
_TS_3164 = r"[A-Za-z]{3}\s+\d{1,2}\s+\d{1,2}:\d{2}:\d{2}"
_DOUBLE_TS_RE = re.compile(_TS_3164 + r".*" + _TS_3164)


def detect_syslog_relay(text: str) -> dict:
    """Flag lines that show an intermediate-relay prepend (double <PRI> or a
    transport header in front of a device that restates its timestamp).
    Advisory; feeds the relay-aware Stage 0 + ERR-030 guidance."""
    signals: List[dict] = []
    for ln in _non_blank_lines(text):
        s = ln.strip()
        if _DOUBLE_PRI_RE.search(s):
            kind = "double-pri"
        elif _DOUBLE_TS_RE.search(s):
            kind = "wrapped-device-message"
        else:
            continue
        signals.append({"kind": kind, "sample": s[:80]})
    out: dict = {"detected": bool(signals), "signal_count": len(signals),
                 "signals": signals[:5]}
    if signals:
        out["guidance"] = (
            "Relay/prepend shape detected: an intermediate syslog server has "
            "prepended its own header. Capture the envelope relay-aware (the "
            "Stage 0 greedy ^.* prefix takes the origin host/PRI) and anchor "
            "every payload field on its own token, never on ^ -- so extraction "
            "is identical whether the record arrives direct or prepended. See "
            "references/syslog-envelope.md (HARD RULE); ERR-030 flags "
            "^-anchored body captures."
        )
    return out


def detect_cloud(fields: dict) -> dict:
    """Auto-detect a cloud audit-log source (AWS CloudTrail, Azure Activity /
    Entra sign-in, GCP Cloud Audit) by its distinctive JSON field paths.
    Conservative: each provider needs two corroborating markers so an ordinary
    JSON log that happens to carry one generic key does not trip it. Advisory --
    steers toward references/cloud-mapping.md; never blocks."""
    paths = " ".join(
        info.get("path", "").lower() for info in fields.values()
    )

    def has(*needles: str) -> bool:
        return all(n in paths for n in needles)

    provider = None
    if has("eventname") and (
        "eventsource" in paths or "useridentity" in paths
        or "recipientaccountid" in paths
    ):
        provider = "aws"
    elif (has("operationname") and ("resulttype" in paths or "calleripaddress" in paths)) \
            or (has("userprincipalname") and "conditionalaccessstatus" in paths):
        provider = "azure"
    elif has("protopayload", "methodname") or has("authenticationinfo", "principalemail"):
        provider = "gcp"

    out: dict = {"detected": provider is not None}
    if provider:
        out["provider"] = provider
        out["guidance"] = (
            f"Cloud audit-log source detected ({provider}). Map on the cloud "
            "model: xdm.event.type = the service, xdm.event.original_event_type "
            "= the raw action (eventName / operationName / methodName), "
            "xdm.event.operation = the verb DERIVED from the action-naming "
            "convention, and xdm.event.tags = CLOUD (plus AUTHENTICATION for a "
            "console login / interactive sign-in). Set xdm.source.cloud.provider "
            "reliably and set xdm.source.cloud.service only on a confident known "
            "match; otherwise record the raw service name in NOT MAPPED (never "
            "xdm.source.cloud.source_type -- it is banned, lint ERR-029). "
            "See references/cloud-mapping.md."
        )
    return out


def profile(source_path: str, text: str) -> dict:
    fmt = detect_format(text)
    try:
        records = parse_records(text, fmt)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"could not parse {source_path} as {fmt}: {exc}") from exc

    fields = aggregate_fields(records)
    arrays = find_object_arrays(records)
    reverse_index = build_reverse_index(load_anchors())
    attach_xdm_candidates(fields, reverse_index)

    auth_block = detect_authentication(fields, records)
    network_block = detect_network(
        fields, records, auth_detected=bool(auth_block.get("detected"))
    )
    process_block = detect_process(fields, records)
    cloud_block = detect_cloud(fields)
    return {
        "source": source_path,
        "detected_format": fmt,
        "record_count": len(records),
        "recommended_pattern": recommend_pattern(fmt, arrays),
        "classification": classify(auth_block, network_block, process_block),
        "authentication": auth_block,
        "network": network_block,
        "process": process_block,
        "cloud": cloud_block,
        "mitre": detect_mitre(fields, records),
        "syslog_relay": detect_syslog_relay(text),
        "fields": list(fields.values()),
        "object_arrays": arrays,
    }


# --------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------


def _signal_summary(section: dict, shown: int) -> str:
    """The count phrase for one detector, distinguishing total from sample.

    Falls back to the sample length only for a worksheet written before
    signal_count existed, where no better number survives.
    """
    total = section.get("signal_count", len(section.get("signals", [])))
    floor = "+" if section.get("signal_count_capped") else ""
    if shown < total:
        return f"detected -- {total}{floor} signal(s), showing {shown}"
    return f"detected -- {total}{floor} signal(s)"


def _format_text(worksheet: dict) -> str:
    rec = worksheet.get("recommended_pattern") or {}
    lines = [
        f"source:          {worksheet['source']}",
        f"detected_format: {worksheet['detected_format']}",
        f"record_count:    {worksheet['record_count']}",
        f"pattern:         {rec.get('primary', '?')} -- {rec.get('reason', '')}",
    ]
    for extra in rec.get("also", []):
        lines.append(f"                 also: {extra}")
    lines.extend(["", "fields:"])
    for f in worksheet["fields"]:
        cand = f.get("xdm_candidates") or []
        cand_str = (
            ", ".join(c["xdm_path"] for c in cand[:2]) if cand else "(no candidate)"
        )
        sample = f.get("sample")
        if isinstance(sample, str) and len(sample) > 40:
            sample = sample[:37] + "..."
        lines.append(
            f"  {f['path']:<48} {f['type']:<14} "
            f"null={f['null_rate']:<5} -> {cand_str}  sample={sample!r}"
        )
    auth = worksheet.get("authentication") or {}
    if auth.get("detected"):
        sample = auth.get("signals", [])[:5]
        rendered = ", ".join(f"{s['field']}({s['match']})" for s in sample)
        lines.append("")
        lines.append("authentication:")
        lines.append(f"  {_signal_summary(auth, len(sample))}: {rendered}")
        lines.append(
            "  map the mandatory set (advisory WARN-042): "
            + ", ".join(auth.get("mandatory_fields", []))
        )
        lines.append(
            "  recommended (identity mirror): "
            + ", ".join(auth.get("recommended_fields", []))
        )
    net = worksheet.get("network") or {}
    if net.get("detected"):
        sample = net.get("signals", [])[:5]
        rendered = ", ".join(f"{s['field']}({s['match']})" for s in sample)
        lines.append("")
        lines.append("network:")
        lines.append(f"  {_signal_summary(net, len(sample))}: {rendered}")
        lines.append(
            "  map the mandatory set (advisory WARN-043): "
            + ", ".join(net.get("mandatory_fields", []))
        )
    proc = worksheet.get("process") or {}
    if proc.get("detected"):
        sample = proc.get("signals", [])[:5]
        rendered = ", ".join(f"{s['field']}({s['match']})" for s in sample)
        lines.append("")
        lines.append("process / command execution:")
        lines.append(f"  {_signal_summary(proc, len(sample))}: {rendered}")
        lines.append(
            "  map the process family (advisory WARN-044): "
            + ", ".join(proc.get("recommended_fields", []))
        )
    mitre = worksheet.get("mitre") or {}
    if mitre.get("detected"):
        sample = mitre.get("signals", [])[:5]
        rendered = ", ".join(f"{s['field']}({s['kind']})" for s in sample)
        lines.append("")
        lines.append("mitre att&ck:")
        lines.append(f"  {_signal_summary(mitre, len(sample))}: {rendered}")
        lines.append("  " + mitre.get("guidance", ""))
    relay = worksheet.get("syslog_relay") or {}
    if relay.get("detected"):
        lines.append("")
        lines.append("syslog relay / prepend:")
        lines.append(
            f"  detected -- {relay.get('signal_count', 0)} line(s) show a "
            "prepended header"
        )
        lines.append("  " + relay.get("guidance", ""))
    clf = worksheet.get("classification") or {}
    if clf:
        lines.append("")
        lines.append("classification (per record):")
        fam = clf.get("families_detected") or []
        lines.append(
            "  detected kind(s): "
            + (", ".join(fam) if fam else "none recognised")
            + ("  [MULTI-KIND: classify per record]" if clf.get("multi_kind") else "")
        )
        lines.append("  " + clf.get("guidance", ""))
    if worksheet["object_arrays"]:
        lines.append("")
        lines.append("object_arrays:")
        for oa in worksheet["object_arrays"]:
            disc = (
                f"discriminator={oa['discriminator']} values={oa['values']}"
                if oa["discriminator"]
                else "no discriminator"
            )
            lines.append(f"  {oa['path']:<32} elements={oa['element_count']} {disc}")
    return "\n".join(lines)


class _ArgvErrorParser(argparse.ArgumentParser):
    """Make argparse exit with status 1 on argument errors, matching
    the script's documented exit-code contract (1 = argument error,
    2 = I/O / parse failure on the sample file)."""

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        sys.stderr.write(f"{self.prog}: error: {message}\n")
        sys.exit(1)


def main(argv: List[str]) -> int:
    ap = _ArgvErrorParser(
        prog="profile_log.py",
        description="Static profiler for raw vendor log samples. "
        "Emits a JSON worksheet describing format, fields, types, "
        "null rates, object-array discriminators, and ranked XDM "
        "candidate suggestions.",
    )
    ap.add_argument("sample", help="path to a raw log sample file")
    ap.add_argument(
        "--format",
        choices=("json", "text"),
        default="json",
        help="output format (default: json)",
    )
    args = ap.parse_args(argv[1:])

    path = Path(args.sample)
    if not path.is_file():
        sys.stderr.write(f"error: {path} not found or not a file\n")
        return 2
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        sys.stderr.write(f"error: cannot read {path}: {exc}\n")
        return 2

    try:
        worksheet = profile(str(path), text)
    except ValueError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2

    if args.format == "json":
        sys.stdout.write(json.dumps(worksheet, indent=2, default=_json_default) + "\n")
    else:
        sys.stdout.write(_format_text(worksheet) + "\n")
    return 0


def _json_default(obj: object) -> object:
    # Object arrays carry the raw list-of-dicts so discriminator
    # detection can read it; the JSON serialiser handles those
    # natively. Anything else unexpected becomes a string.
    return str(obj)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
