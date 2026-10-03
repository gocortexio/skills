#!/usr/bin/env python3
# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Check that a record's markers are complete enough to hand to a rule author.

This corpus does not author detection rules. It supplies the evidence a
rule-authoring skill needs: typed literal markers, the query shape they imply,
and an explicit note where a value has to be measured locally rather than
assumed. This script exists to keep that handoff honest. A marker set that
cannot be turned into a query is not a marker set, it is prose.

The XQL it prints is a skeleton for inspection, not a finished rule. Dataset
selection, grouping, windows and every threshold marked <bound> are the
downstream author's decisions, and are deliberately left unresolved here. What
the skeleton does promise is that every line it prints as XQL is XQL, and says
what the marker says: a condition it cannot write as a field test is printed as
a comment naming why, never pasted into the filter.

Usage:
    emit_xql.py <record-id-or-substring> [--corpus DIR]
    emit_xql.py --all [--shape single_event]
    emit_xql.py <record-id> --json      # structured handoff, what a skill consumes
    emit_xql.py <record-id>#how<n>      # one block, by the FINDING_KEY consult.py prints
"""
import argparse
import collections
import glob
import json
import os
import re
import sys
import textwrap
import warnings

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import consult as C  # noqa: E402  the locus ladder is shared deliberately, not reimplemented

# Where a marker type has an obvious XDM home, use it. A marker's own "xdm" key always wins
# over this table, because the record author knows the context. Every value here must be a
# field of corpus/schema/xdm-fields.json, the bundled copy of the published XDM schema; until
# 0.43.0 this table was written without reference to it, and five defaults named fields that
# are not in XDM or an enum that cannot hold the corpus's values.
DEFAULT_XDM = {
    "process_name": "xdm.target.process.name",
    "process_path": "xdm.target.process.executable.path",
    "command_line": "xdm.target.process.command_line",
    "parent_process": "xdm.source.process.name",
    "file_path": "xdm.target.file.path",
    "file_name": "xdm.target.file.filename",
    "file_extension": "xdm.target.file.extension",
    "domain": "xdm.network.dns.dns_question.name",
    "url_path": "xdm.network.http.url",
    "user_agent": "xdm.source.user_agent",
    "ip": "xdm.target.ipv4",
    "port": "xdm.target.port",
    "username": "xdm.source.user.username",
    "event_id": "xdm.event.id",
    "event_outcome": "xdm.event.outcome",
    "http_status": "xdm.network.http.response_code",
    "content_type": "xdm.network.http.content_type",
    "tls_cert_subject": "xdm.network.tls.server_certificate.subject",
    # The raw API action. xdm.event.operation is the derived OPERATION_TYPE enum (CREATE,
    # DELETE, READ), which never holds ConsoleLogin or StopLogging, so every management-plane
    # skeleton bound there could never match.
    "cloud_operation": "xdm.event.original_event_type",
    "registry_key": "xdm.target.registry.key",
    "registry_value_name": "xdm.target.registry.value",
    "registry_data": "xdm.target.registry.data",
}

# Marker types with no default, and why. Each once had one, and each default was wrong for
# some of the corpus: a guess at the field is worse than a comment asking for it.
NO_DEFAULT = {
    "api_path": "an API route is carried by an HTTP log's URL, a container runtime's audit or a "
                "cloud audit's resource, whichever the source is; bind it per event with the "
                "marker's xdm",
    "group_name": "the group acted on is a target of the event, and the actor's groups "
                  "(xdm.source.user.groups) are not it; bind it per event with the marker's xdm",
    "protocol": "xdm.network.ip_protocol is the layer-4 enum (TCP, UDP), while most protocol "
                "markers name an application protocol, whose field is "
                "xdm.network.application_protocol; the marker must say which it means",
    "service_name": "XDM has no service-name field; bind it per event with the marker's xdm",
    "zone": "a zone sits on either side of a session (xdm.source.zone or xdm.target.zone); "
            "bind it per event with the marker's xdm",
}

# A file digest's field follows from the digest, not from the marker type. XDM gives a file an
# MD5 and a SHA256 and nothing else, and file_hash defaulted to the SHA256 field whatever it
# held, so six MD5s and two SHA-1s were tested live against xdm.target.file.sha256, where they
# can never match. Keyed by the length of the hexadecimal digest.
FILE_DIGEST_XDM = {32: "xdm.target.file.md5", 64: "xdm.target.file.sha256"}

# The snapshot's digest types and the hexadecimal length each holds. A value of another length
# is not that digest, whichever field the marker names.
DIGEST_HEX = {"MD5": 32, "SHA256": 64}
HEX = re.compile(r"^[0-9a-fA-F]+$")

# The string each outcome constant renders as on a modelled dataset, which is what a query
# compares. A modelling rule assigns XDM_CONST.OUTCOME_*, but a query comparing
# xdm.event.outcome to the constant fails the whole pack install with a 101704 that names no
# file and no field; the correlation-author bundle proved it on three rules across two packs,
# lints it as ERR-CORR-OUTCOME-CONST, and compares "SUCCESS" and "FAILED" instead. Only those
# two are recorded, so the others print as UNBOUND rather than as a guessed string.
OUTCOME_RENDERED = {"XDM_CONST.OUTCOME_SUCCESS": "SUCCESS", "XDM_CONST.OUTCOME_FAILED": "FAILED"}

# Fields holding a whole URL, and the marker types whose values are only a path within one.
# A path tested whole against a whole URL can never match: `xdm.network.http.url = "/beacon"`
# was printed under fidelity=alert, and the field holds the full requested URL.
URL_FIELDS = ("xdm.network.http.url", "xdm.target.url")
PATH_TYPES = ("url_path", "api_path")
# What may precede a path in a whole URL: an optional scheme, then an authority, which may be
# empty where a source logs the request target alone. The authority was optional only after a
# scheme, so a URL recorded as host/path or host:port/path, which the xdm-author bundle's own
# proxy mapping extracts a host from, never matched. It holds no /, so it cannot swallow a path
# segment. What may follow the whole of one: a query, a fragment, or the end.
URL_HEAD = r"^(?:[A-Za-z][A-Za-z0-9+.-]*://)?[^/?#]*"
URL_TAIL = r"(?:[?#]|$)"

# The closed list of match values, as corpus/schema/observation.schema.json holds it. Anything
# else fell through bind() to = or in, so a negation such as not_equals printed as the positive
# clause it negates: the inverse of the marker, live.
MATCH_VALUES = ("equals", "contains", "prefix", "suffix", "regex", "in", "gt", "lt")

# Fields that say which kind of event a record is: its identifier, type, operation or raw
# action. They sit on every event, so the emitter counts them as neutral, and they say nothing
# about whether a process, file, registry, DNS or HTTP marker beside them is on the same event:
# a log-cleared event identifier joined with the command line of the utility that clears logs
# is two events. validate.py refuses such a join in a list that does not say how it combines.
EVENT_KIND_FIELDS = ("xdm.event.id", "xdm.event.type", "xdm.event.operation",
                     "xdm.event.operation_sub_type", "xdm.event.original_event_type")

# A path literal holds the path as the event does, expanded. An unexpanded variable such as
# %TEMP% is in no file or process event, so a clause testing one can never match.
PATH_LITERAL_TYPES = ("file_path", "process_path", "file_name")
ENV_VARIABLE = re.compile(r"%[A-Za-z_][A-Za-z0-9_]*%")

# Marker types that describe state rather than an event field. These belong in an
# inventory question, not a filter clause.
STATE_TYPES = {"cve", "software_version"}

# The closed list of what became of a marker, carried per marker in the JSON handoff so a
# consumer sees the emitter's view without re-deriving any of it.
BINDING_STATUSES = ("bound", "computed", "state", "unbound", "not_an_xdm_field",
                    "enum_literal", "array_field", "unrenderable", "normalised")

# How a marker set combines, when the block or pattern says (corpus/README.md, "How markers
# combine"). Absent, the emitter conjoins only what cannot be two events.
COMBINE_VALUES = ("all", "any")

# A block's filter status, in the header and the tally. complete: every marker is a clause in
# the live filter. partial: a live filter, plus conditions left as comments. none: no live
# filter at all.
FILTER_STATUSES = ("complete", "partial", "none")

# Fields that can only come from one kind of event. Clauses from two of these families in one
# conjunction describe two events, which no single event satisfies. Actor, event-level,
# address, port and zone fields sit on every kind of event and are neutral, with one exception
# the emitter cannot see and validate.py refuses (CONNECTION_FIELDS, below). HTTP fields are a
# family of their own: a URL and a user agent come from a proxy or web log, which carries no
# process image, file write or registry key.
EVENT_FAMILIES = (("xdm.target.process.", "process"), ("xdm.target.file.", "file"),
                  ("xdm.target.registry.", "registry"), ("xdm.network.dns.", "dns"),
                  ("xdm.network.http.", "http"), ("xdm.target.url", "http"),
                  ("xdm.source.user_agent", "http"))

# The fields that say an event is a connection: where it went and what it carried. The process
# that opens a connection is the event's actor, xdm.source.process in the platform's own mapping
# and in the xdm-author bundle's ("the process that ACTED ... is the source"); xdm.target.process
# is a process acted upon -- a child launched, a process injected into -- which a connection does
# not carry. So an acted-upon process joined with one of these is two events, and no single event
# satisfies the filter. A tunnel client's port and image printed that way under fidelity=alert and
# filter=complete, and a remote access tool's image beside the control-network zone as partial.
CONNECTION_FIELDS = ("xdm.target.port", "xdm.target.ipv4", "xdm.target.zone",
                     "xdm.network.application_protocol", "xdm.network.ip_protocol")
ACTED_UPON_PROCESS = "xdm.target.process."

# The families a management-plane audit event never carries. A cloud_operation marker is the
# raw API action from such an audit, on a field every event has, so it joins any family in a
# single_event block, where the author says there is one event: a storage audit's read can name
# the object as a file. In a sequence or a correlation, whose shape spans events, the action and
# a process, file, registry or DNS artefact are two of them. The ESXi chain joined a password
# reset in the management audit, an SSH port and a VMFS file write into one filter this way,
# under filter=complete. A user agent is carried by the audit itself, so HTTP is not listed.
AUDIT_EXCLUSIVE = ("process", "file", "registry", "dns")

BANNER = ("// SKELETON, NOT A RULE: dataset, grouping, windows, joins and every <bound> are the "
          "author's.")

IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
REGEX_META = re.compile(r'([.^$*+?()\[\]{}|\\])')

# `fault` marks a refusal that is the marker's error rather than a limit of the skeleton -- a
# pattern RE2 cannot run, a digest of the wrong length, a list where one value is meant -- and
# is what validate.py refuses in the corpus. A range on an address field is not a fault: the
# value is right, and only `=` cannot test it.
Binding = collections.namedtuple("Binding", "kind status field text reason event fault",
                                 defaults=(False,))


def load_xdm_fields(corpus):
    """The bundled XDM field snapshot, or None when it is absent."""
    path = os.path.join(corpus, "schema", "xdm-fields.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def family(field):
    for prefix, name in EVENT_FAMILIES:
        if field and field.startswith(prefix):
            return name
    return None


def re2_refusal(pattern):
    """Why RE2, the engine XQL's ~= runs, would reject this pattern, or None.

    RE2 has no lookaround, no backreference numbered or named, no atomic group, no possessive
    quantifier, no conditional group, no comment group, no \\Z, no \\u or \\N escape, no counted
    repeat above 1000, and no inline flag beyond i, m, s and U. Python's re accepts every one of
    them in some version, so a pattern that compiles here can still be a syntax error on the
    tenant. The other way round, RE2 has \\z, the Unicode classes \\pL and \\p{Greek}, \\Q...\\E,
    \\x{...}, the U flag and inline flags anywhere in the pattern, and some Pythons refuse each
    of them, which would refuse a sound marker as its own fault.

    So every construct where the two engines differ is looked for here, by name, and only what
    they share is left to Python's compiler: RE2's own constructs are rewritten to a Python
    equivalent for that check, which is never printed. `{,n}` is refused whichever engine
    accepts it, because RE2 reads it as literal text and Python as a repeat of 0 to n.
    `(?<name>...)` is refused because only RE2 releases from 2023 accept it, where
    `(?P<name>...)` is accepted by every release and by Python, and `\\C` because it matches one
    byte and can split a character.
    """
    possessive = "uses a possessive quantifier, which RE2 does not support"
    py = []
    i, in_class, repeatable = 0, False, False
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            following = pattern[i + 1:i + 2]
            if following.isdigit() and following != "0":
                return "uses a backreference, which RE2 does not support"
            if following == "Z":
                return "uses \\Z, which RE2 does not support; RE2's end of text is \\z"
            if following in ("u", "U", "N"):
                return "uses \\{}, which RE2 does not support; write \\x{{...}}".format(following)
            if following == "C":
                return "uses \\C, which matches one byte and can split a character; write ."
            repeatable = not in_class
            if following == "z":
                py.append("\\Z")
                i += 2
                continue
            if following in ("p", "P"):
                named = re.match(r"\\[pP](?:\{\^?[A-Za-z_]+\}|[A-Za-z])", pattern[i:])
                if not named:
                    return "uses \\{} with no class name after it".format(following)
                py.append("a")
                i += len(named.group(0))
                continue
            if following == "x" and pattern[i + 2:i + 3] == "{":
                code = re.match(r"\\x\{[0-9A-Fa-f]{1,6}\}", pattern[i:])
                if not code:
                    return "uses \\x{ without a hexadecimal code and a closing brace"
                py.append("a")
                i += len(code.group(0))
                continue
            if following == "Q" and not in_class:
                end = pattern.find("\\E", i + 2)
                py.append(re.escape(pattern[i + 2:] if end < 0 else pattern[i + 2:end]))
                i = len(pattern) if end < 0 else end + 2
                continue
            py.append(pattern[i:i + 2])
            i += 2
            continue
        if in_class:
            in_class = ch != "]"
            repeatable = not in_class
            py.append(ch)
            i += 1
            continue
        if ch == "[":
            # A ] straight after the opening bracket, or after its ^, is a member, not the end.
            start = i
            i += 1
            if pattern[i:i + 1] == "^":
                i += 1
            if pattern[i:i + 1] == "]":
                i += 1
            py.append(pattern[start:i])
            in_class = True
            continue
        if pattern.startswith(("(?=", "(?!", "(?<=", "(?<!"), i):
            return "uses lookaround, which RE2 does not support"
        if pattern.startswith("(?>", i):
            return "uses an atomic group, which RE2 does not support"
        if pattern.startswith("(?P=", i):
            return "uses a named backreference, which RE2 does not support"
        if pattern.startswith("(?(", i):
            return "uses a conditional group, which RE2 does not support"
        if pattern.startswith("(?#", i):
            return "uses a comment group, which RE2 does not support"
        if pattern.startswith("(?<", i):
            return "uses (?<name>...), which only RE2 releases from 2023 accept; write " \
                   "(?P<name>...)"
        flags = re.match(r"\(\?([A-Za-z-]+)([:)])", pattern[i:])
        if flags:
            if set(flags.group(1)) - set("imsU-"):
                return "uses the inline flag(s) {}, and RE2 takes only i, m, s and U".format(
                    "".join(sorted(set(flags.group(1)) - set("imsU-"))))
            # Flags change no syntax. Python refuses U, a cleared flag outside a group and,
            # from 3.11, a flag anywhere but the start, all of which RE2 takes, so the check
            # reads a flag group as a plain group and a bare one as nothing.
            py.append("(?:" if flags.group(2) == ":" else "")
            i += len(flags.group(0))
            repeatable = False
            continue
        counted = re.match(r"\{(\d*)(?:,(\d*))?\}", pattern[i:])
        if counted and counted.group(1) == "" and counted.group(2):
            return "uses {{,{0}}}, which RE2 reads as literal text and Python as a repeat of 0 " \
                   "to {0}; write {{0,{0}}}".format(counted.group(2))
        if counted and counted.group(1) == "":
            counted = None
        if counted and max(int(n) for n in counted.groups() if n) > 1000:
            return "uses the counted repeat {}, and RE2 repeats at most 1000 times".format(
                counted.group(0))
        # A quantifier -- *, +, ?, or a counted {n,m} -- after something repeatable, followed
        # by +, is possessive. The ? that opens a group's syntax repeats nothing.
        if repeatable and (ch in "*+?" or counted):
            step = len(counted.group(0)) if counted else 1
            py.append(pattern[i:i + step])
            i += step
            if pattern[i:i + 1] == "?":
                py.append("?")
                i += 1
            elif pattern[i:i + 1] == "+":
                return possessive
            repeatable = False
            continue
        repeatable = ch not in "(|^"
        py.append(ch)
        i += 1
    try:
        with warnings.catch_warnings():
            # A POSIX class such as [[:alpha:]] is RE2 syntax, and Python warns of a nested set.
            warnings.simplefilter("ignore")
            re.compile("".join(py))
    except re.error as exc:
        return "does not compile ({})".format(exc)
    return None


def regex_body(pattern):
    """A regex written into an XQL string: backslashes once, a double quote as \\x22.

    XQL passes a string's backslashes through to the regex engine, so a pattern is written
    exactly as the engine should receive it. Doubling them, as this script did until 0.43.0,
    turned `nc\\.exe` into a literal backslash followed by any character, and `\\s` into a
    literal backslash and an s: a silent zero that reads as a true negative. A double quote
    would end the string, so it is written as the hex escape RE2 reads as the same character,
    and an escaped quote in the pattern is replaced whole, escape included. A pattern ending in
    an escaped backslash ends in the class [\\] instead, which matches the same character and
    leaves no backslash immediately before the closing quote, where XQL might read it as an
    escape of the quote.
    """
    out, i = [], 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and pattern[i + 1:i + 2] == '"':
            out.append("\\x22")
            i += 2
        elif ch == "\\":
            out.append(pattern[i:i + 2])
            i += 2
        elif ch == '"':
            out.append("\\x22")
            i += 1
        else:
            out.append(ch)
            i += 1
    if out and out[-1] == "\\\\":
        out[-1] = "[\\\\]"
    return '"{}"'.format("".join(out))


def string_literal(value):
    """A plain string for =, in and contains, or None when it cannot be written safely.

    Backslashes pass through once, as they do in a regex. A value holding a double quote is
    refused rather than escaped: how XQL escapes a quote inside a string is not recorded
    anywhere this bundle can cite, and a guessed escape is a syntax error or a different value.
    A value ending in a backslash is refused for the same reason, because written between
    quotes it puts a backslash immediately before the closing one.
    """
    text = str(value)
    if '"' in text or text.endswith("\\"):
        return None
    return '"{}"'.format(text)


def alternation(items):
    """Literal values as one regex matching any of them, each escaped: `a` alone, else `(?:a|b)`.

    The group keeps an anchor added around it on every alternative, not only the first and last.
    """
    escaped = [REGEX_META.sub(r"\\\1", str(v)) for v in items]
    return escaped[0] if len(escaped) == 1 else "(?:{})".format("|".join(escaped))


def file_digest_field(items):
    """(field, reason, fault) for a file_hash marker's values, the field None where none fits.

    The field is the one whose digest the values are. A SHA-1 is a real indicator with no XDM
    home, so it is left unbound, not refused; a list mixing digest lengths, or a value that is
    no digest XDM knows, is the marker's error.
    """
    texts = [str(v) for v in items]
    if not all(HEX.match(t) for t in texts):
        return None, "a file hash is hexadecimal, and {} is not".format(
            ", ".join(repr(t) for t in texts if not HEX.match(t))), True
    lengths = sorted({len(t) for t in texts})
    if len(lengths) > 1:
        return None, "the values mix digests of {} hexadecimal digits; a marker holds one " \
                     "digest type, so split it".format(" and ".join(str(n) for n in lengths)), True
    if lengths[0] in FILE_DIGEST_XDM:
        return FILE_DIGEST_XDM[lengths[0]], None, False
    if lengths[0] == 40:
        return None, "a digest of 40 hexadecimal digits is a SHA-1, and XDM gives a file an MD5 " \
                     "({}) and a SHA256 ({}) but no SHA-1".format(FILE_DIGEST_XDM[32],
                                                                  FILE_DIGEST_XDM[64]), False
    return None, "a digest of {} hexadecimal digits is neither an MD5 (32) nor a SHA256 (64), " \
                 "the two digests XDM gives a file".format(lengths[0]), True


def enum_constant(value, enum):
    """The XDM_CONST member a literal names, or None."""
    members = (enum or {}).get("members")
    if not members:
        return None
    text = str(value).strip()
    if text in members:
        return text
    if "XDM_CONST." + text in members:
        return "XDM_CONST." + text
    literals = (enum or {}).get("literals") or {}
    return literals.get(text) or literals.get(text.upper())


def bind(marker, xdm_fields):
    """One marker becomes a live clause, a requirement, or a reason it is neither.

    Nothing computed is ever live. A computed marker's expression is pseudo-code -- aggregates,
    English connectives, a second threshold -- and pasted into a filter it produced XQL that
    was neither valid nor what the marker meant: `value: false` appended to a compound
    expression bound as "a and (b = false)", not "not (a and b)".
    """
    mtype = marker.get("type")
    match = marker.get("match", "equals")
    value = marker.get("value")
    event = marker.get("event")
    shown = json.dumps(value)

    def refuse(status, field, reason, fault=False):
        return Binding("unbound", status, field, "{} {} {}".format(mtype, match, shown),
                       reason, event, fault)

    if marker.get("normalised"):
        # The corpus's own word for the event or zone (vocab.json normalised_marker_types),
        # not a literal the source writes. Printed live, xdm.event.type = "integrity_check"
        # and xdm.source.zone = "dmz" sat in six filter=complete alert blocks and could never
        # match, which reads as a true negative. The clause it would be is printed as a
        # requirement naming the field, so the author binds the source's own value. A fault
        # of the marker itself is still the marker's fault.
        inner = bind({k: v for k, v in marker.items() if k != "normalised"}, xdm_fields)
        if inner.fault:
            return inner
        text = inner.text if inner.kind == "clause" else "{} {} {}".format(
            inner.field or "<field>", match, shown)
        return Binding("requires", "normalised", inner.field, text,
                       "this corpus's word for the {}, not a value any source writes; "
                       "replace it with the value your source records{}".format(
                           "zone" if mtype == "zone" else "event",
                           "" if inner.field else ", on the field it records it in"), event)

    if match not in MATCH_VALUES:
        # Refused before anything reads it: every branch below treats a value it does not
        # name as equality, which printed not_equals as the clause it negates.
        return refuse("unrenderable", None, "match {!r} is not one of {}, and a test the "
                      "contract has no word for is not printed as one it has; a negation is a "
                      "computed marker valued false".format(match, ", ".join(MATCH_VALUES)),
                      True)

    if mtype == "computed":
        expr = marker.get("expr", "")
        if match == "equals" and value is True:
            text = expr
        elif match == "equals" and value is False:
            text = "NOT ({})".format(expr)
        elif match in ("gt", "lt"):
            text = "{} {} {} (source bound; measure locally)".format(
                expr, ">" if match == "gt" else "<", shown)
        elif match == "in":
            text = "{} IN {}".format(expr, shown)
        else:
            text = "{} = {}".format(expr, shown)
        return Binding("requires", "computed", None, text, None, event)

    if mtype in STATE_TYPES:
        # Joined, as the dataset hint is: str() of a list printed Python's repr of it.
        return Binding("state", "state", None, ", ".join(str(v) for v in value)
                       if isinstance(value, list) else str(value), None, event)

    items = value if isinstance(value, list) else [value]
    # A list on equals or contains is any of its values. bind() kept the first and called the
    # marker bound, so a pattern listing four URL paths was a skeleton testing one of them.
    many = len(items) > 1
    field = marker.get("xdm") or DEFAULT_XDM.get(mtype)
    if not field and mtype == "file_hash":
        field, why, fault = file_digest_field(items)
        if not field:
            return refuse("unbound", None, why, fault)
    if not field:
        return refuse("unbound", None, NO_DEFAULT.get(
            mtype, "no XDM field is recorded for marker type {!r}".format(mtype)))
    fields = (xdm_fields or {}).get("fields") or {}
    spec = fields.get(field)
    if spec is None:
        return refuse("not_an_xdm_field", field,
                      "{} is not a field of the bundled XDM snapshot".format(field))
    ftype = spec.get("type") or "String"
    if spec.get("array"):
        return refuse("array_field", field,
                      "{} is an array; = and in do not test membership".format(field))
    if match in ("gt", "lt") and many:
        return refuse("unrenderable", field, "a {} test takes one bound, and the value is a "
                      "list of {}".format(match, len(items)), True)

    if ftype.startswith("XDM_CONST."):
        enum = ((xdm_fields or {}).get("enums") or {}).get(ftype) or {}
        consts = [enum_constant(v, enum) for v in items]
        if (match in ("equals", "in") and consts and all(consts)
                and (field == "xdm.event.outcome" or ftype == "XDM_CONST.OUTCOME")):
            # The union the correlation-author bundle lints, since which of the two is the
            # platform's boundary is untested: the field, or the constant group.
            unrecorded = [c for c in consts if c not in OUTCOME_RENDERED]
            if unrecorded:
                return refuse("enum_literal", field, "{} is compared as the string its constant "
                              "renders as, because comparing it to the constant fails the pack "
                              "install, and the string {} renders as is not recorded".format(
                                  field, ", ".join(unrecorded)))
            shown_as = ['"{}"'.format(OUTCOME_RENDERED[c]) for c in consts]
            text = ("{} = {}".format(field, shown_as[0]) if len(shown_as) == 1
                    else "{} in ({})".format(field, ", ".join(shown_as)))
            return Binding("clause", "bound", field, text, None, event)
        if match in ("equals", "in") and consts and all(consts):
            text = ("{} = {}".format(field, consts[0]) if len(consts) == 1
                    else "{} in ({})".format(field, ", ".join(consts)))
            return Binding("clause", "bound", field, text, None, event)
        if not enum.get("members"):
            why = "{} is {}, whose members the snapshot does not enumerate; no constant is " \
                  "invented".format(field, ftype)
        elif match not in ("equals", "in"):
            why = "{} is {}; a {} test cannot run against an enum".format(field, ftype, match)
        else:
            why = "{} is {}, and {} is not one of its members".format(
                field, ftype, ", ".join(str(v) for v, c in zip(items, consts) if not c))
        return refuse("enum_literal", field, why)

    if ftype == "Number":
        if match not in ("equals", "in", "gt", "lt"):
            return refuse("unrenderable", field,
                          "{} is a Number; a {} test cannot run against it".format(field, match),
                          True)
        numbers = []
        for v in items:
            if isinstance(v, bool) or not re.match(r"^-?\d+(\.\d+)?$", str(v)):
                return refuse("unrenderable", field,
                              "{} is a Number and {!r} is not one".format(field, v), True)
            numbers.append(str(v))
        if match == "in" or many:
            return Binding("clause", "bound", field,
                           "{} in ({})".format(field, ", ".join(numbers)), None, event)
        op = {"gt": ">", "lt": "<"}.get(match, "=")
        return Binding("clause", "bound", field, "{} {} {}".format(field, op, numbers[0]),
                       None, event)

    if ftype == "Boolean":
        if match == "equals" and isinstance(value, bool):
            return Binding("clause", "bound", field, "{} = {}".format(
                field, "true" if value else "false"), None, event)
        return refuse("unrenderable", field, "{} is a Boolean".format(field), True)

    if ftype.startswith("IPv"):
        if match not in ("equals", "in"):
            return refuse("unrenderable", field,
                          "{} is an address; a {} test cannot run against it".format(field, match),
                          True)
        for v in items:
            if not IPV4.match(str(v)):
                if "/" in str(v):
                    return refuse("unrenderable", field,
                                  "{!r} is a range, and a range needs incidr(), not =".format(v))
                return refuse("unrenderable", field,
                              "{!r} is not an IPv4 address".format(v), True)
        quoted = ['"{}"'.format(v) for v in items]
        text = ("{} = {}".format(field, quoted[0]) if match == "equals" and not many
                else "{} in ({})".format(field, ", ".join(quoted)))
        return Binding("clause", "bound", field, text, None, event)

    if ftype in DIGEST_HEX:
        # A digest is tested whole, and a value of the wrong length is a different digest: an
        # MD5 tested against a SHA256 field is a clause that can never match.
        if match not in ("equals", "in"):
            return refuse("unrenderable", field, "{} is a {} digest, tested whole with = or in, "
                          "not with {}".format(field, ftype, match), True)
        for v in items:
            if not (HEX.match(str(v)) and len(str(v)) == DIGEST_HEX[ftype]):
                return refuse("unrenderable", field, "{} is {}, and {!r} is not a digest of {} "
                              "hexadecimal digits".format(field, ftype, v, DIGEST_HEX[ftype]),
                              True)

    # Every other type -- String, and the digest types, which hold strings -- takes a quoted
    # literal. A number written against a String field is quoted, because XDM holds event ids
    # as strings and an unquoted 4720 is a type mismatch.
    texts = [str(v) for v in items]
    variables = sorted({v for t in texts for v in ENV_VARIABLE.findall(t)})
    if mtype in PATH_LITERAL_TYPES and variables:
        return refuse("unrenderable", field, "{} holds the path an event records, expanded, and "
                      "the value carries the unexpanded {}; write the expanded path, or a "
                      "suffix or regex that does not depend on it".format(
                          field, ", ".join(variables)), True)
    if field == "xdm.target.file.extension" and any(t.startswith(".") for t in texts):
        return refuse("unrenderable", field, "{} holds an extension without its dot, and {} "
                      "carries one".format(field, ", ".join(repr(t) for t in texts
                                                             if t.startswith("."))), True)
    whole_url = field in URL_FIELDS and mtype in PATH_TYPES
    if whole_url and match == "regex" and re.match(r"^(?:\(\?[A-Za-z]+\))?\^/", texts[0]):
        return refuse("unrenderable", field, "the pattern is anchored at the start of a path, "
                      "and {} holds the whole URL, scheme and host first; drop the ^ or match "
                      "the authority before the path".format(field), True)
    if whole_url and match in ("equals", "in", "prefix", "suffix"):
        # A path is tested where it sits in the whole URL: after the scheme and authority, or
        # at the start where a source logs the request target alone, and up to a query, a
        # fragment or the end. Tested whole with = or in, the path can never match.
        if match != "suffix" and not all(t.startswith("/") for t in texts):
            return refuse("unrenderable", field, "{} holds the whole URL, so a {} tested with "
                          "{} must be a path beginning with /, and {} is not".format(
                              field, mtype, match, ", ".join(repr(t) for t in texts
                                                              if not t.startswith("/"))), True)
        pattern = alternation(items)
        if match != "suffix":
            pattern = URL_HEAD + pattern
        if match != "prefix":
            pattern = pattern + URL_TAIL
        return Binding("clause", "bound", field, "{} ~= {}".format(field, regex_body(pattern)),
                       None, event)
    if match == "regex":
        if many:
            return refuse("unrenderable", field, "a regex marker takes one pattern, and the "
                          "value is a list of {}; write the alternatives inside it with "
                          "|".format(len(items)), True)
        pattern = str(items[0])
        refusal = re2_refusal(pattern)
        if refusal:
            return refuse("unrenderable", field, "the pattern {}".format(refusal), True)
        return Binding("clause", "bound", field, "{} ~= {}".format(field, regex_body(pattern)),
                       None, event)
    if match in ("gt", "lt"):
        return refuse("unrenderable", field,
                      "{} is a {}; a {} test cannot run against it".format(field, ftype, match),
                      True)
    if any(isinstance(v, bool) for v in items):
        return refuse("unrenderable", field, "{} is a {}, not a Boolean".format(field, ftype),
                      True)
    if match in ("prefix", "suffix"):
        pattern = alternation(items)
        pattern = "^" + pattern if match == "prefix" else pattern + "$"
        return Binding("clause", "bound", field, "{} ~= {}".format(field, regex_body(pattern)),
                       None, event)
    quoted = [string_literal(v) for v in items]
    if not all(quoted) or (match == "contains" and many):
        # A value holding a double quote, or a Windows directory written with its trailing
        # separator, cannot sit between quotes as it stands, and contains takes one value. The
        # same test is written as a regex of the escaped literals, which XQL folds case in as it
        # does contains and =, and which regex_body can carry both characters in.
        pattern = alternation(items)
        if match != "contains":
            pattern = "^" + pattern + "$"
        return Binding("clause", "bound", field, "{} ~= {}".format(field, regex_body(pattern)),
                       None, event)
    if match == "in" or many:
        return Binding("clause", "bound", field,
                       "{} in ({})".format(field, ", ".join(quoted)), None, event)
    if match == "contains":
        return Binding("clause", "bound", field, "{} contains {}".format(field, quoted[0]),
                       None, event)
    return Binding("clause", "bound", field, "{} = {}".format(field, quoted[0]), None, event)


def represented(item, markers, bindings):
    """True when a legacy fields[] item says nothing the markers do not already say."""
    xdm = item.get("xdm")
    if xdm and any(b.field == xdm for b in bindings):
        return True
    if xdm and any(m.get("xdm") == xdm for m in markers):
        return True
    # exists and absent carry no value worth comparing, and a Boolean would match any
    # computed marker's true: only a literal matching a field-test marker's literal counts.
    if item.get("op") in ("exists", "absent") or isinstance(item.get("value"), bool):
        return False
    wanted = item.get("value")
    wanted = {str(v) for v in (wanted if isinstance(wanted, list) else [wanted])}
    for m in markers:
        if m.get("type") == "computed":
            continue
        have = m.get("value")
        have = {str(v) for v in (have if isinstance(have, list) else [have])}
        if wanted and wanted <= have:
            return True
    return False


def wrap(prefix, text):
    """Prose wrapped at 96. Only prose: a marker's value is printed whole, on one line, because
    a wrap inside a pattern or a quoted literal changes what a reader copies."""
    return textwrap.wrap(" ".join(str(text).split()), 96, initial_indent="// " + prefix,
                         subsequent_indent="//   ", break_long_words=False,
                         break_on_hyphens=False) or ["// " + prefix.rstrip()]


def dataset_lines(how):
    """The opening stage. `datamodel dataset`, because every live clause names an xdm.* field.

    A raw `dataset =` stage exposes the vendor's columns, not the model's, so a skeleton
    opening on one and filtering xdm.* paths filters fields the stage does not carry. This is
    a preference for the modelled stage and not a prohibition of raw datasets. dataset_hint is
    a list, and was printed as a Python list. A correlation refuses `datamodel dataset in
    (...)`, so a second hint is named for its own query rather than joined into one.
    """
    hints = [h for h in (how.get("dataset_hint") or []) if h]
    lines = ["datamodel dataset = {}".format(hints[0] if hints else "<dataset>")]
    if len(hints) > 1:
        lines.append("// one dataset per query: run the same filter over {}".format(
            ", ".join(hints[1:])))
    return lines


def unkeyed_event_kind_join(markers, xdm_fields, combine=None):
    """(event-kind fields, families) an unkeyed marker list joins, or None.

    The emitter counts an event identifier, type or raw action as neutral, because it sits on
    every event, so without a combination key it would join one with a process, file, registry,
    DNS or HTTP marker as one event. Whether they are one event is exactly what the identifier
    does not say: 1102 is the log-cleared record and carries no command line, while Sysmon 11
    is the file write its path is on. validate.py asks the author to say, with combine.
    """
    if combine in COMBINE_VALUES:
        return None
    bindings = [bind(m, xdm_fields) for m in markers or []]
    kinds = sorted({b.field for b in bindings if b.field in EVENT_KIND_FIELDS})
    families = sorted({family(b.field) for b in bindings if family(b.field)})
    return (kinds, families) if kinds and families else None


def acted_upon_process_on_a_connection(markers, xdm_fields, combine=None):
    """(process fields, connection fields) one event of a marker list joins, or None.

    A connection's port, address, zone or protocol beside xdm.target.process asks one event to
    be a connection and a process acted upon (CONNECTION_FIELDS). Checked per event: markers a
    list labels as separate events may name either, and an unlabelled list under combine any is
    alternatives, each its own event, so nothing there is joined.
    """
    bindings = [(m, bind(m, xdm_fields)) for m in markers or []]
    labelled = any(m.get("event") for m, _ in bindings)
    if combine == "any" and not labelled:
        return None
    groups = collections.OrderedDict()
    for m, b in bindings:
        if b.field:
            groups.setdefault(m.get("event") or "", []).append(b.field)
    for fields in groups.values():
        process = sorted({f for f in fields if f.startswith(ACTED_UPON_PROCESS)})
        connection = sorted({f for f in fields if f in CONNECTION_FIELDS})
        if process and connection:
            return process, connection
    return None


def event_groups(bindings):
    """Event-bound bindings grouped by their `event` label, in order of first appearance."""
    groups = collections.OrderedDict()
    for b in bindings:
        groups.setdefault(b.event or "", []).append(b)
    return groups


def render(record, how, index, pattern=None, locus_map=None, xdm_fields=None, combine=None,
           source_how=None):
    """The XQL skeleton for one how-block: (lines, status, bindings).

    `how` carries the markers to render, the pattern's when the record has none, and `combine`
    is the combination key that came with them. `source_how` is the block as the record holds
    it, which is what the locus is derived from, so this header and a consultation agree.
    """
    pattern = pattern or {}
    markers = how.get("markers") or []
    shape = how.get("rule_shape")
    # validate.py refuses any other value; read defensively all the same, as no key at all.
    combine = combine if combine in COMBINE_VALUES else None
    bindings = [bind(m, xdm_fields) for m in markers]
    clauses = [b for b in bindings if b.kind == "clause"]
    requires = [b for b in bindings if b.kind == "requires"]
    unbound = [b for b in bindings if b.kind == "unbound"]
    state = [b for b in bindings if b.kind == "state"]
    # A normalised marker names an event as a clause does, so it keeps its event's place in a
    # labelled sequence even though it is never live.
    event_bound = [b for b in bindings if b.kind in ("clause", "unbound")
                   or b.status == "normalised"]
    legacy = [f for f in (how.get("fields") or []) if not represented(f, markers, bindings)]

    notes, pipelines, commented = [], [], []
    labelled = any(b.event for b in event_bound)
    groups = event_groups(event_bound)
    if shape == "inventory":
        commented = clauses
        if clauses:
            notes.append("NO LIVE FILTER: answered against asset or configuration state, not an "
                         "event stream")
    elif not clauses:
        if any(b.status == "normalised" for b in event_bound):
            notes.append("NO LIVE FILTER: no marker could be written as a field test, and those "
                         "naming the event hold this corpus's normalised word, not a value the "
                         "source writes")
        elif event_bound:
            notes.append("NO LIVE FILTER: no marker could be written as a field test")
        else:
            notes.append("NO LIVE FILTER: no marker is a field test")
    elif combine == "any":
        # Alternatives: each labelled group, or each marker when none is labelled, is one way
        # the detection fires, so they are joined with or inside one filter.
        alternatives = ([[b for b in g if b.kind == "clause"] for g in groups.values()]
                        if labelled else [[b] for b in clauses])
        alternatives = [a for a in alternatives if a]
        pipelines.append((None, alternatives, "or"))
        if labelled:
            # An alternative with no field test is not in the filter, and the filter alone
            # would read as every way the detection fires.
            for label, group in groups.items():
                if label and not [b for b in group if b.kind == "clause"]:
                    notes.append("NO LIVE FILTER for EVENT {}: none of its markers is a field "
                                 "test, so that alternative is not in the filter".format(label))
    elif combine == "all" and labelled and len(groups) > 1:
        # Every labelled group is its own event, and every one must occur; a single filter
        # over them would ask one event to be several.
        for label, group in groups.items():
            live = [b for b in group if b.kind == "clause"]
            if live:
                pipelines.append((label, [live], "and"))
            else:
                notes.append("NO LIVE FILTER for EVENT {}: none of its markers is a field "
                             "test".format(label))
    elif combine == "all":
        pipelines.append((None, [clauses], "and"))
    else:
        # No combination key: the marker contract used to leave it unsaid, and every clause
        # was joined with and. Two event families, or one field tested twice, cannot be one
        # event, so those are printed as clauses and not as a filter. What this cannot see --
        # an event identifier beside an artefact of another event, two files of one family --
        # is the author's to key; validate.py refuses the first unkeyed in the corpus.
        families = sorted({family(b.field) for b in clauses if family(b.field)})
        if shape in ("sequence", "correlation") and set(families) & set(AUDIT_EXCLUSIVE) and any(
                m.get("type") == "cloud_operation" and b.kind == "clause"
                for m, b in zip(markers, bindings)):
            families = sorted(families + ["audit"])
        counted = collections.Counter(b.field for b in clauses)
        repeated = sorted(f for f, n in counted.items() if n > 1)
        if len(families) > 1 or repeated:
            commented = clauses
            why = []
            if len(families) > 1:
                why.append("clauses span {} event types ({})".format(
                    len(families), ", ".join(families)))
            if repeated:
                why.append("test {} more than once".format(", ".join(repeated)))
            notes.append("NO LIVE FILTER: {}; the block does not say whether its markers "
                          "combine with and or or (corpus/README.md, How markers combine)".format(
                              " and ".join(why)))
        else:
            pipelines.append((None, [clauses], "and"))

    live = bool(pipelines)
    complete = (live and not commented and not requires and not unbound and not state
                and not legacy)
    status = "complete" if complete else ("partial" if live else "none")

    locus = C.locus_for(record, source_how or how, pattern, locus_map)[0]
    lines = ["// {} :: how[{}]  pattern={}  fidelity={}  shape={}  locus={}  filter={}  "
             "key={}".format(record.get("id"), index, how.get("pattern_id") or "-",
                             how.get("fidelity"), shape or "UNSET", locus, status,
                             C.finding_key(record, index))]
    if record.get("status") == "seed":
        # consult.py's STATUS line for the same key, banner and all. The skeleton printed none,
        # so a rule built from a block its own record calls unconfirmed read as confirmed.
        lines.append("// " + C.status_line(record, index))
    lines += wrap("CAVEAT: ", how.get("caveat") or pattern.get("caveat") or "none recorded")
    lines += wrap("LOGIC: ", how.get("logic") or pattern.get("logic") or "none recorded")
    if combine:
        lines.append("// COMBINE: {}{}".format(combine, " by event label" if labelled else ""))
    if state:
        lines.append("// inventory precondition: {}".format(", ".join(b.text for b in state)))

    for label, alternatives, joiner in pipelines:
        if label:
            lines.append("// EVENT {}:".format(label))
        lines += dataset_lines(how)
        if joiner == "or" and len(alternatives) > 1:
            # One alternative per line, each parenthesised, so and never has to be read
            # against or by precedence.
            parts = ["({})".format(" and ".join(b.text for b in alt)) for alt in alternatives]
            lines.append("| filter " + "\n         or ".join(parts))
        else:
            parts = [b.text for alt in alternatives for b in alt]
            lines.append("| filter " + "\n         and ".join(parts))
        if len(pipelines) == 1 and shape == "threshold":
            # bin is a stage, not a function: `by ..., bin(_time, <window>)` was printed here
            # and is not XQL. The stage floors _time to the window, and comp groups by it.
            lines.append("| bin _time span = <window>")
            lines.append("| comp count() as hits by <grouping_key>, _time")
            lines.append("| filter hits > <bound>          // bound must be measured, not assumed")

    labels = [label for label, _, _ in pipelines if label]
    if combine == "all" and labelled and len(groups) > 1:
        # Every labelled event, live or not: a sequence whose second event holds only a
        # normalised word is still two events, in that order.
        labels = [label for label in groups if label]
    if len(labels) < 2:
        labels = []
    if shape == "threshold" and labels:
        lines.append("// threshold: count the joined events by <grouping_key> in <window>; the "
                     "<bound> is measured, not assumed")
    elif shape == "correlation" and live:
        lines.append("// correlation: join {} on <join_key>".format(
            "EVENT " + ", ".join(labels) if labels else "the above against <second_event_set>"))
    elif shape == "sequence" and live:
        lines.append("// sequence: {} within <window>, on <join_key>".format(
            "EVENT " + ", then ".join(labels) + ", in that order" if labels
            else "the above must precede <following_event>"))
    elif shape == "absence":
        lines.append("// ABSENCE: compare the expected reporters (an inventory) with those "
                     "seen in <window>; comp over events cannot produce a zero row")
    elif labels:
        lines.append("// every EVENT above must occur: join EVENT {} on <join_key> within "
                     "<window>".format(", ".join(labels)))

    audit = {id(b) for m, b in zip(markers, bindings) if m.get("type") == "cloud_operation"}
    for b in commented:
        lines.append("// CLAUSE ({}): {}".format(
            family(b.field) or ("audit" if id(b) in audit else "event"), b.text))
    for note in notes:
        lines += wrap("", note)
    for b in requires:
        # A labelled requirement belongs to that event alone: under any, the qualifier of one
        # alternative is not a condition on the others.
        if b.status == "normalised":
            lines.append("// REQUIRES{} (normalised, not a source literal): {} -- {}".format(
                " for EVENT {}".format(b.event) if b.event else "", b.text, b.reason))
            continue
        lines.append("// REQUIRES{} (computed, not a field test): {}".format(
            " for EVENT {}".format(b.event) if b.event else "", b.text))
    for b in unbound:
        lines.append("// UNBOUND: {} -- {}".format(b.text, b.reason))
    for item in legacy:
        lines.append("// FIELD (legacy fields[]): {} {} {}{}".format(
            item.get("xdm") or item.get("raw") or "?", item.get("op"),
            json.dumps(item.get("value")),
            " -- {}".format(item["note"]) if item.get("note") else ""))
    return lines, status, bindings


def effective(how, pattern):
    """The markers, shape and combination key a block is rendered with.

    A block with no markers of its own is rendered from its pattern's, with the pattern's
    shape and combination key; its own markers always win, with its own key.
    """
    if how.get("markers"):
        return how, how.get("combine")
    if (pattern or {}).get("markers"):
        return (dict(how, markers=pattern["markers"],
                     rule_shape=how.get("rule_shape") or pattern.get("rule_shape")),
                pattern.get("combine"))
    return None, None


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


def binding_rows(markers, source, xdm_fields):
    rows = []
    for i, m in enumerate(markers or []):
        b = bind(m, xdm_fields)
        row = {"source": source, "index": i, "type": m.get("type"), "field": b.field,
               "status": b.status}
        if b.kind == "clause":
            row["clause"] = b.text
        elif b.status == "normalised":
            # The clause it would be, for the author to rebind; never a live filter.
            row["requires"] = b.text
        if b.reason:
            row["reason"] = b.reason
        if b.event:
            row["event"] = b.event
        rows.append(row)
    return rows


def handoff(record, how, index, patterns, attack=None, d3fend=None, locus_map=None,
            xdm_fields=None):
    """The structured object a rule-authoring skill consumes.

    Record markers are the literals this particular source gave us. Pattern
    markers are the generic shape of the detection, shared across every record
    that cites it. Both are supplied separately so the author can decide which
    to anchor on rather than receiving them pre-merged.
    """
    pat = patterns.get(how.get("pattern_id")) or {}
    locus, span, locus_basis = C.locus_for(record, how, pat, locus_map)
    rendered, combine = effective(how, pat)
    status = (render(record, rendered, index, pat, locus_map, xdm_fields, combine, how)[1]
              if rendered else "none")
    table = (d3fend or {}).get("countermeasures") or {}
    # The selection a consultation's finding prints, from the same function, at twelve rather
    # than six: deduplicated, one control per D3FEND tactic in turn, shown in tactic order.
    # The handoff concatenated each technique's list and cut at twelve with no count, so 549
    # of 703 handoffs were cut silently, 229 lost every Evict entry, 230 every Restore entry,
    # and 14 repeated an id.
    selection = C.select_countermeasures(how, pat, d3fend, limit=12)
    chosen = selection.chosen if selection else []
    return {
        "record_id": record.get("id"),
        "how_index": index,
        # The same key consult.py prints as FINDING_KEY, so a finding and its handoff can
        # be joined without re-deriving which of a record's blocks it was.
        "finding_key": C.finding_key(record, index),
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
        # The record's status, as consult.py prints it on STATUS, and which seed meaning applies
        # to this block (C.seed_support: unread, unconfirmed or supported; null when not seed).
        # SKILL.md rules 3 and 4 cannot be obeyed downstream without them. `confidence` is the
        # block's own, and does not say whether anybody re-read the source.
        "status": record.get("status"),
        "seed_support": C.seed_support(record, index),
        "confidence": how.get("confidence"),
        "evidence_type": how.get("evidence_type") or pat.get("evidence_type"),
        "technique": how.get("technique") or pat.get("technique"),
        "markers_from_source": how.get("markers") or [],
        "markers_from_pattern": pat.get("markers") or [],
        # How each list's markers combine, where the block or pattern says (all or any).
        "combine_from_source": how.get("combine"),
        "combine_from_pattern": pat.get("combine"),
        # What the emitter made of every marker in both lists, one entry each, in the closed
        # BINDING_STATUSES list: a default binding, an enum constant, a field the snapshot
        # does not hold. A consumer re-deriving DEFAULT_XDM would inherit any wrong default
        # silently; this says what was decided and why.
        "marker_bindings": (binding_rows(how.get("markers"), "record", xdm_fields)
                            + binding_rows(pat.get("markers"), "pattern", xdm_fields)),
        # The text skeleton's status for this block: complete, partial or none.
        "filter_status": status,
        # The legacy field tests, verbatim. Some constraints live only here -- the Log4j
        # block's server-role restriction among them -- and nothing forwarded them.
        "fields_from_source": how.get("fields") or [],
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
        # What to do once the rule fires. An empty list is a gap in D3FEND, not an all-clear.
        # `mapping` is how D3FEND reaches the control from the cited techniques, as a
        # consultation prints it: direct, inferred-narrower or inferred-broader.
        "countermeasures": [
            dict({"id": cid}, **{k: v for k, v in (table.get(cid) or {}).items()
                                 if k in ("name", "tactic", "definition", "url")},
                 mapping="direct" if selection.grade[cid] == "direct"
                 else "inferred-" + selection.grade[cid])
            for cid in chosen
        ],
        "countermeasures_shown": len(chosen),
        "countermeasures_total": len(selection.picked) if selection else 0,
        "countermeasures_not_shown": list(selection.not_shown) if selection else [],
        "logic": how.get("logic") or pat.get("logic"),
        "caveat": how.get("caveat") or pat.get("caveat"),
        "provenance": {
            "publisher": record.get("where", {}).get("publisher"),
            "title": record.get("where", {}).get("title"),
            "url": record.get("where", {}).get("url"),
            "vulnerabilities": record.get("what", {}).get("vulnerabilities", []),
            # What consult.py prints as SOURCE_DISCLOSURE and SUPPORT for the same key:
            # restricted means cite the title as given and nothing further, and a null is a
            # value the record does not state.
            "disclosure": record.get("where", {}).get("disclosure"),
            "retrieved": record.get("where", {}).get("retrieved"),
            "verified": record.get("where", {}).get("verified"),
        },
        "vendor": record.get("who", {}).get("vendor"),
        "product_class": record.get("who", {}).get("product_class", []),
    }


def tally(shown, verb, skipped, filtered, available, wanted_shape, statuses=None,
          without_how=0):
    """The one-line account of what became of every candidate block.

    Both modes drop blocks for two unrelated reasons and only ever reported one of them,
    so `--shape correlation` over a record holding two single_event blocks printed
    "0 block(s) emitted, 0 skipped for having no markers" -- numbers each true and
    together describing nothing. A reader could not tell an empty record from a filter
    that matched no shape, and the second is usually a typo in the shape name, so the
    shapes that were actually there are named when the filter took everything.

    The filter statuses of the blocks shown follow, and then the matched records that hold
    no how-block at all: an exposure record matched by id printed "0 block(s) emitted, 0
    skipped", accounting for nothing.
    """
    line = "// {} block(s) {}, {} skipped for having no markers".format(shown, verb, skipped)
    if wanted_shape:
        line += ", {} filtered out by --shape {}".format(filtered, wanted_shape)
        if filtered and not shown:
            line += " (shapes present: {})".format(
                ", ".join(sorted(s or "unset" for s in available)))
    if statuses is not None:
        line += "; filter: {}".format(", ".join(
            "{} {}".format(statuses.get(s, 0), s) for s in FILTER_STATUSES))
    if without_how:
        line += "; {} matched record(s) carry no how-blocks (exposure records hold no " \
                "detection logic)".format(without_how)
    return line


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", help="record id or substring")
    ap.add_argument("--corpus", default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "corpus"))
    ap.add_argument("--all", action="store_true",
                    help="every record; what no target already means, and refused beside one")
    # Deliberately not a choices= list. The vocabulary lives in the corpus, so pinning it
    # here would reject a shape the corpus legitimately gains. A value matching nothing is
    # reported instead, with the shapes that were actually available.
    ap.add_argument("--shape",
                    help="emit only blocks of this rule_shape: single_event, correlation, "
                         "sequence, threshold, absence or inventory")
    ap.add_argument("--json", action="store_true",
                    help="emit the structured handoff a rule-authoring skill consumes")
    args = ap.parse_args()
    if args.all and args.target:
        # Parsed and never read, so `<target> --all` narrowed to the target without a word.
        print("give a record id, a FINDING_KEY or --all, not both", file=sys.stderr)
        return 2

    xdm_fields = load_xdm_fields(args.corpus)
    if not xdm_fields:
        # Every binding is checked against it, so without it nothing can be written honestly.
        print("ERROR: corpus/schema/xdm-fields.json is absent, so no binding can be checked "
              "against the XDM schema", file=sys.stderr)
        return 2
    records = load(args.corpus)
    patterns = load_patterns(args.corpus)
    attack = load_attack(args.corpus)
    d3fend = load_d3fend(args.corpus)
    locus_map = C.load_locus_map(args.corpus)
    # A FINDING_KEY names one block of one record exactly, so it is matched exactly rather
    # than as a substring: a substring would also take a longer id that happens to start
    # with this one.
    only_block = None
    keyed = re.match(r"^(.+)#how(\d+)$", args.target or "")
    if keyed:
        records = [r for r in records if r.get("id") == keyed.group(1)]
        only_block = int(keyed.group(2))
        if records and only_block >= len(records[0].get("how") or []):
            print("no matching block: {} has {} how-block(s), numbered from 0".format(
                keyed.group(1), len(records[0].get("how") or [])), file=sys.stderr)
            return 1
    elif args.target:
        records = [r for r in records if args.target.lower() in r.get("id", "").lower()]
    if not records:
        print("no matching record", file=sys.stderr)
        return 1
    without_how = sum(1 for r in records if not r.get("how"))

    statuses = collections.Counter()
    if args.json:
        out, skipped, filtered, available = [], 0, 0, set()
        for r in records:
            for i, how in enumerate(r.get("how", [])):
                if only_block is not None and i != only_block:
                    continue
                pat = patterns.get(how.get("pattern_id")) or {}
                if not (how.get("markers") or pat.get("markers")):
                    skipped += 1
                    continue
                shape = how.get("rule_shape") or pat.get("rule_shape")
                if args.shape and shape != args.shape:
                    filtered += 1
                    available.add(shape)
                    continue
                block = handoff(r, how, i, patterns, attack, d3fend, locus_map, xdm_fields)
                statuses[block["filter_status"]] += 1
                out.append(block)
        print(json.dumps(out, indent=1))
        print(tally(len(out), "handed off", skipped, filtered, available, args.shape, statuses,
                    without_how), file=sys.stderr)
        return 0

    print(BANNER)
    print()
    emitted = skipped = filtered = 0
    available = set()
    for r in records:
        for i, how in enumerate(r.get("how", [])):
            if only_block is not None and i != only_block:
                continue
            pat = patterns.get(how.get("pattern_id")) or {}
            rendered, combine = effective(how, pat)
            if rendered is None:
                skipped += 1
                continue
            if args.shape and rendered.get("rule_shape") != args.shape:
                filtered += 1
                available.add(rendered.get("rule_shape"))
                continue
            lines, status, _ = render(r, rendered, i, pat, locus_map, xdm_fields, combine, how)
            statuses[status] += 1
            print("\n".join(lines))
            print()
            emitted += 1

    print(tally(emitted, "emitted", skipped, filtered, available, args.shape, statuses,
                without_how), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
