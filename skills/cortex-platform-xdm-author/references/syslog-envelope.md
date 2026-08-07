<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Syslog envelope parsing -- the transport layer beneath Pattern B

## The requirement, stated once

Syslog reaches Cortex in two arrival forms: direct off the device, and
behind one or more intermediate relays, each of which prepends its own
`<PRI> timestamp host tag:` header. The same source produces both, often
in the same feed, and a sample almost always shows only one.

Every syslog rule this skill produces must model BOTH forms in ONE rule,
always. Not the form the sample happened to show. Not two rules with a
dataset split. One rule whose output is identical either way.

Two mechanisms make that true, and both are required:

1. The envelope is captured relay-aware, with a greedy `^.*` that skips
   any number of prepended headers to reach the ORIGIN priority and host.
   Anchoring on `^<` alone reads the outermost relay's values instead of
   the device's.
2. Every payload field is anchored on its OWN token, never on `^` and
   never on a positional offset from the start of the line. A positional
   capture shifts the moment a header is added or removed. Lint blocks
   this as ERR-030, an error rather than an advisory.

Static lint cannot prove the property on its own -- a pattern can look
like a sanctioned envelope capture and still be position-dependent -- so
prove it mechanically before emitting:

```sh
python3 scripts/verify_rule.py <rule.xql> <sample> --prepend-check
```

That evaluates every record twice, as supplied and with a relay header
prepended, and exits 1 naming any field whose value differs. A
difference is a defect in the anchor; fix the anchor rather than
special-casing the second form.

Every syslog source carries two independent layers. The envelope is the
RFC 3164 or RFC 5424 transport wrapper (priority, timestamp, host, tag).
The payload is the vendor body that Pattern B parses. Today rules parse
the payload and hand-roll a one-off header regex anchored on a vendor
literal (for example the trailing tag word). That anchor breaks on the
next source and discards the priority value entirely.

Parse the envelope first, with the one canonical idiom below, then parse
the payload. The envelope idiom is identical across every syslog source,
so it is written once and reused. See [extraction-patterns.md](extraction-patterns.md)
for the payload patterns (A, B, C, D) that run after Stage 0.

## When this applies

Apply this whenever `_raw_log` begins with a syslog priority token
`<NNN>` (RFC 3164 or RFC 5424). `profile_log.py` reports a
`detected_format` of `syslog-3164` or `syslog-5424` for these sources.
If there is no `<NNN>` priority (a relay stripped it), skip the priority
decode; the host then has no fixed position either, so read it from a
payload field instead of the envelope (see "When the priority is
stripped" below).

## The two-layer model

```
Stage 0  envelope   priority, host, app/tag      <- this file, identical everywhere
Stage 1+ payload    vendor key=value / JSON      <- extraction-patterns.md
```

Keep Stage 0 as the first `alter` after the MODEL header (after the
mandatory `filter _raw_log != null` guard). Never assign `_time` in a
MODEL rule (Cortex sets it at INGEST -- see WARN-018); the envelope
timestamp is therefore NOT MAPPED.

## HARD RULE: support both direct and relay-prepended syslog

Syslog rarely arrives byte-for-byte as the device emits it. A source
reaches Cortex both direct (the device's own bytes) and behind an
intermediate relay that prepends its own header to the payload. The
build-time sample usually shows only one of these, but the rule must
handle both -- so for every syslog source this is non-negotiable, not a
per-vendor nicety. Two arrival shapes to design for:

1. Double `<PRI>` -- the relay wraps the whole original line:
   `<190>Jun 30 12:00:10 relay01 <134>Jun 30 12:00:04 originhost app: msg`
2. Transport wrap of a device message -- a `<PRI> ts host tag:` header in
   front of a device body that may restate its own timestamp/task:
   `<134>Jul 14 15:41:24 relay.example.net wlc01: *taskName: Jul 14 15:41:24.640: %APF-6-USER_NAME_CREATED: ... for mobile 3e:a8:8d:20:d1:1e`
   Direct off the box the same event is just
   `*taskName: Jul 14 15:41:24.640: %APF-6-USER_NAME_CREATED: ...` -- no
   `<PRI>`, no relay host.

A rule that anchors on a fixed prefix silently drops every record whose
arrival form differs from the sample. Make it robust in two places:

- Envelope (host / PRI / tag): use the relay-aware Stage 0 below. Its
  greedy `^.*` prefix absorbs any relay header(s) and captures the origin
  host + origin PRI. A single, direct line matches identically.
- Body (every payload field): anchor on the field's own token with a
  position-independent `regextract` -- `key=([^\s]+)`, `[field: (...)]`,
  the `%FAC-SEV-MNEMONIC` token, `for mobile (<mac>)` -- so it matches
  whether or not a prefix is present. Never anchor a body field on `^`,
  never extract "everything after the header" (`^...(.*)`), and never rely
  on a fixed column offset from the header.

The bundled linter enforces the body half: a `^`-anchored / positional
body capture in a syslog rule is flagged ERR-030. The relay-aware
envelope captures are exempt (they are the sanctioned transport layer).

## Stage 0 -- canonical envelope capture (RFC 3164 and RFC 5424)

Anchor on the priority token, never on a vendor literal. The host sits
in a different position in each RFC, so capture both and coalesce; the
two patterns are mutually exclusive (5424 has a numeric version after
the priority, 3164 has a month name), so the coalesce is unambiguous.

The capture is relay-aware: the RFC 3164 host and priority are read
through a greedy `^.*` prefix so that an intermediate relay which prepends
its own `<PRI> ts host` header (see the HARD RULE section above) is
skipped, and the innermost origin host/PRI are captured -- not the
relay's. On a direct line the greedy prefix matches nothing extra, so the
result is byte-identical.

The RFC 5424 fields are anchored on the ISO TIMESTAMP that follows the
version digit, not on `^` and not on a count of `\S+` from the start of
the line. A compliant 5424 relay records itself in structured data rather
than prepending a header, but a BSD relay in a mixed estate will happily
prepend one onto a 5424 line, and a `^`-anchored 5424 capture then reads
the relay's fields instead of the origin's. The `<PRI>VERSION ISO-8601`
sequence is unambiguous and occurs once, so anchoring there is correct
for both arrival forms at no cost.

```
filter
    _raw_log != null
| alter
    tmp_pri        = to_integer(to_number(coalesce(arrayindex(regextract(_raw_log, "^.*<(\d{1,3})>[A-Za-z]{3}\s+\d+\s+[\d:]+"), 0), arrayindex(regextract(_raw_log, "<(\d{1,3})>\d\s+\d{4}-\d{2}-\d{2}T"), 0)))),
    tmp_host_5424  = arrayindex(regextract(_raw_log, "<\d{1,3}>\d\s+\d{4}-\d{2}-\d{2}T[\d:.+\-]+\s+(\S+)"), 0),
    tmp_host_3164  = arrayindex(regextract(_raw_log, "^.*<\d{1,3}>[A-Za-z]{3}\s+\d+\s+[\d:]+\s+(\S+)\s"), 0)
| alter
    tmp_syslog_host_raw = coalesce(tmp_host_5424, tmp_host_3164)
| alter
    tmp_syslog_host = if(tmp_syslog_host_raw != "-", tmp_syslog_host_raw)
```

### The observer has no address field, and the hostname slot often holds one

Two related facts that both bite on the first attempt.

There is no `xdm.observer.ipv4`. The observer family carries `name`,
`type`, `product`, `vendor`, `version`, `sub_type`, `action`,
`content_version` and `unique_identifier` -- and no address at all, so
ERR-020 rejects the natural first mapping. For a syslog source the
observer IS the device and its address is a first-class fact about the
record, so the gap is real. The workaround is `xdm.target.ipv4` plus
`xdm.target.host.ipv4_addresses`, accepting that this conflates "the
device that reported this" with "the device this happened to". Those
coincide when a device self-reports an administrative login and diverge
when it reports something about a peer, so state the choice in the
MAPPED header NOTES rather than leaving a reader to infer it.

Separately, the HOSTNAME slot frequently contains an ADDRESS rather than
a name -- on some sources, on every record:

```
<185>Jul 29 13:23:56 172.22.205.92 host-aeeeb42e: 47596 Base CHASSIS-CRITICAL-...
                     ^^^^^^^^^^^^^ hostname slot  ^^^^^^^^^^^^ tag
```

Mapping that slot to `xdm.observer.name` is correct, and it leaves the
address unreachable by any address-based correlation, because nothing
downstream knows the name field happens to hold one. Map the name
unconditionally and the address only when the value IS an address:

```
    tmp_dev_ip = arrayindex(regextract(tmp_dev_host, "^(\d{1,3}(?:\.\d{1,3}){3})$"), 0)
```

The `^...$` anchoring is load bearing: an unanchored test matches an
address embedded in a longer hostname and would map a fragment.

### The RFC 5424 field layout

Count the fields from the ISO timestamp, and get the offset right: the
fields are all bare tokens, so extracting one and believing it is another
produces plausible-looking output. APP-NAME mistaken for MSGID yields
daemon names, which is exactly why the error survives review.

```
<190>1 2026-07-25T10:34:24.316+10:00 host-a mgd 16590 UI_LOGIN_EVENT [junos@2636 k="v"] MSG
 |    | |                            |      |   |     |              |                  |
 PRI  V TIMESTAMP                    HOST   APP PROCID MSGID         STRUCTURED-DATA    MSG
```

| Field | Offset after the ISO timestamp | Typical use |
| --- | --- | --- |
| HOSTNAME | 1 | `xdm.observer.name` (guard the nil) |
| APP-NAME | 2 | the emitting daemon / process name |
| PROCID | 3 | the PID |
| MSGID | 4 | the event identity, when present |
| STRUCTURED-DATA | 5 | `[id k="v" ...]` or a nil `-` |
| MSG | rest | the free-text body |

Add one `\S+\s+` per field after the timestamp anchor to reach the next.

### A nil field is first-class, not an edge case

RFC 5424 permits the NILVALUE `-` in ANY header field, and vendors use it
heavily -- a nil MSGID is common rather than rare, and a record with
APP-NAME, PROCID, MSGID and SD all nil is the standard
`last message repeated N times` marker.

So every 5424 header field must be tested for the dash explicitly, not
merely for null. A dash is a value: it is not null, it has non-zero
length, and it passes every population check.

```
// WRONG -- yields the identity "JUNOS_DAEMON_-" on every nil-MSGID record,
// a label no daemon has, and puts a dash in the process name
tmp_identity = if(tmp_msgid = null, concat("JUNOS_DAEMON_", tmp_app), tmp_msgid)

// RIGHT -- MSGID, then APP-NAME only if it is not nil, then the catch-all
tmp_identity = coalesce(
    if(tmp_msgid != "-", tmp_msgid),
    if(tmp_app != "-", concat("DAEMON_", tmp_app)),
    "GOCORTEX_UNMODELLED")
```

Guard each field once, at the point of capture, so no downstream stage
has to remember:

```
    tmp_app   = if(tmp_app_raw != "-", tmp_app_raw),
    tmp_procid = if(tmp_procid_raw != "-", tmp_procid_raw),
    tmp_msgid = if(tmp_msgid_raw != "-", tmp_msgid_raw)
```

### Never anchor the body on an optional structural character

The MSG field is easiest to reach by anchoring on the end of the
structured-data element, `"\]\s+(.+)$"`. That breaks silently on every
record whose SD is nil, because there is no `]` anywhere in the line -- an
ordinary daemon line in 5424 clothing has none. The capture returns null,
the field falls back to its default, and if that default is the catch-all
sentinel the result passes both a lint and a population count.

Anchor the body positionally from the timestamp instead (six fields in),
or coalesce the SD-anchored form with a positional fallback. And measure
the two separately: envelope coverage and payload-structure coverage are
different figures. A feed can be almost entirely 5424 by envelope while
only around half of it carries a structured-data element, and the two
drive different parts of the rule -- the envelope drives extraction, the
payload structure drives classification.

`tmp_pri` takes the origin priority through the greedy 3164 capture and
falls back to the first `<NNN>` for RFC 5424 / PRI-only lines. The greedy
`.*` stops at the last `<PRI>` that is followed by a timestamp, so a stray
`<500>`-style token inside the payload never captures.

RFC 5424 permits the NILVALUE `-` for the HOSTNAME field, so the final
guard stage nulls it out: a relay that hides the host can never leak a
literal `-` into `xdm.observer.name` -- the field stays null and the
author sources the observer from a payload field instead.

Optional envelope fields (capture only when you will map them):

```
    tmp_app_5424 = arrayindex(regextract(_raw_log, "^<\d{1,3}>\d+\s+\S+\s+\S+\s+(\S+)\s"), 0),
    tmp_tag_3164 = arrayindex(regextract(_raw_log, "^.*<\d{1,3}>[A-Za-z]{3}\s+\d+\s+[\d:]+\s+\S+\s+([A-Za-z0-9_\-]+)(?:\[|:)"), 0),
    tmp_sd_param = arrayindex(regextract(_raw_log, "\[[^\]]*\bKEYNAME=\"([^\"]+)\""), 0)
```

Standard envelope assignment:

```
    xdm.observer.name = tmp_syslog_host
```

## Priority decode -- facility and severity (function-form, ERR-012 safe)

The priority encodes two values: `facility = PRI div 8` and
`severity = PRI mod 8`. There is no `modulo()` or `floor()` function and
infix arithmetic is banned (see [parser-idioms.md](parser-idioms.md)
ERR-012), so decode with the documented function-form arithmetic. This
works because `to_integer()` truncates toward zero and PRI is never
negative, so `to_integer(divide(...))` is an exact floor.

Facility and severity sit in two separate `alter` stages: severity reads
the facility temp, and Cortex evaluates every target in a single `alter`
in parallel, so referencing a sibling temp in the same stage is rejected
as an unknown field (the bundled linter flags it as ERR-024). Compute the
facility first, then read it in the next stage.

```
| alter
    tmp_pri_facility = to_integer(divide(tmp_pri, 8))
| alter
    tmp_pri_severity = to_integer(subtract(tmp_pri, multiply(tmp_pri_facility, 8)))
```

Worked check: `<134>` -> `divide(134, 8) = 16.75` -> `to_integer = 16`
(facility 16, local0); `subtract(134, multiply(16, 8)) = 6` (severity 6,
Informational). A rounding-sensitive case to keep in the test suite:
`<12>` -> facility 1, severity 4; if `to_integer` ever rounded instead of
truncating, severity would compute as -4 and the test would catch it.

Map the numeric severity (0-7) onto the constants already shipped
(see [xdm-const.md](xdm-const.md)). XDM has no Debug or Emergency/Alert
level, so floor the ends:

```
| alter
    tmp_pri_log_level = if(
        tmp_pri_severity <= 2, XDM_CONST.LOG_LEVEL_CRITICAL,
        tmp_pri_severity = 3,  XDM_CONST.LOG_LEVEL_ERROR,
        tmp_pri_severity = 4,  XDM_CONST.LOG_LEVEL_WARNING,
        tmp_pri_severity = 5,  XDM_CONST.LOG_LEVEL_NOTICE,
        tmp_pri_severity != null, XDM_CONST.LOG_LEVEL_INFORMATIONAL),
    tmp_pri_sev_band = if(
        tmp_pri_severity <= 2, "Critical",
        tmp_pri_severity = 3,  "High",
        tmp_pri_severity = 4,  "Medium",
        tmp_pri_severity != null, "Low")
```

## Use the decoded priority as a FALLBACK, never an override

The payload almost always carries a richer severity (for example
`sev=68`). The decoded priority is the floor that keeps the field
populated when the payload omits severity. Always prefer the payload:

```
| alter
    xdm.alert.severity  = coalesce(tmp_payload_sev_band, tmp_pri_sev_band),
    xdm.event.log_level = coalesce(tmp_payload_log_level, tmp_pri_log_level)
```

If the payload has its own severity, the priority decode is dropped by
the coalesce -- that is correct. (Both payload temps must be produced
from raw columns earlier in the rule; a coalesce over an undefined
underscore field is rejected by the linter as ERR-027.)

## Greedy `^.*` is necessary but NOT sufficient

The greedy prefix works by making the regex prefer the LAST place the
pattern can match, which on a relayed line is the origin's copy rather
than the relay's. That reasoning holds only while the origin actually
satisfies the WHOLE pattern. When it does not, the engine does not give
up -- it BACKTRACKS to an earlier position, and the relay's copy has the
same shape by construction, so the relay wins.

So greedy alone is wrong for any field that can be ABSENT from the origin
record. The process tag is the common case, because a tagless record is
ordinary:

```
// WRONG -- a tagless origin leaves the relay's tag as the only match,
// so greedy backtracks to it and the field says "relayd"
tmp_proc = arrayindex(regextract(_raw_log, ".*\s([A-Za-z][\w\-]*)\[\d+\]:"), 0)

// The obvious fix -- asserting that no further <PRI> follows -- needs a
// negative lookahead, and this engine does not support lookaround: the
// query hangs rather than failing (ERR-033). There is no regex answer.
//
// RIGHT -- do not derive the tag from the line at all on a source that
// emits tagless records behind a relay. Leave the field null and say so
// in the MAPPED header.

```

Re-anchoring on a fuller RFC 3164 header instead does NOT fix this, and
is worth knowing because it is the intuitive next move. A pattern like
`.*<\d{1,3}>[A-Za-z]{3}\s+\d+\s+[\d:]+\s+\S+\s+(\S+)\[\d+\]:` looks more
specific, but the relay's own header matches that shape exactly as well
as the origin's, so backtracking still reaches it -- and it now fails on
a relayed line whose origin PRI was stripped, where the looser form
succeeded. Specificity in the anchor does not help when the thing being
excluded has the same shape; only asserting what must NOT follow does.

Verify rather than reason about it. `--prepend-check` evaluates each
record as supplied and relay-prepended and fails on any field whose value
differs, which is what catches this class.

## When the priority is stripped

A relay can forward a record with the `<NNN>` token removed. Then `tmp_pri`
is null and the decode chain yields null all the way through, which the
coalesce above handles: severity and log_level fall to whatever the
payload provides.

On a DIRECT line the Stage 0 host captures also return null, because they
are anchored on the priority token by design (never on a vendor literal).
On a RELAYED line they do not: the relay supplies a `<PRI>` of its own,
the origin no longer has one to be preferred, and the greedy prefix
backtracks onto the relay's header, so `tmp_pri` and the host silently
become the RELAY's. That is the same backtracking failure as above, and
it is the one arrival form Stage 0 as written does not survive. For a source that arrives both with and without the PRI, use
the prepend-tolerant host in extraction-recipes.md Recipe 5 -- a greedy
`^.*` prefix with the `<PRI>` made optional
(`^.*(?:<\d{1,3}>)?[A-Za-z]{3}\s+\d+\s+[\d:]+\s+(\S+)\s`) captures the
host across no-PRI, PRI, and relayed lines alike. Otherwise read the host
from a payload field rather than re-anchoring on a vendor word.

## What stays NOT MAPPED

```
NOT MAPPED
  syslog timestamp  -- Cortex sets _time at INGEST; MODEL rules must not assign _time (WARN-018)
  raw PRI integer   -- transport detail; only the decoded facility/severity carry meaning
  facility          -- no XDM home; retain only if a downstream rule needs it, else omit
```

## Determinism notes

- Always emit `xdm.observer.name` from `tmp_syslog_host` on a syslog source.
- Priority decode is a coalesce fallback only; it never overrides payload severity.
- Host capture is anchored on the priority token, never on a vendor literal.
  The linter flags a vendor-anchored header regex as WARN-040.
- The capture is relay-aware (greedy `^.*` prefix): direct and
  relay-prepended lines both yield the origin host / PRI, PROVIDED the
  origin carries the token at all. Where it can be absent, greedy
  backtracks onto the relay's copy, and there is no regex fix -- the
  guard that would express it needs lookaround, which this engine does
  not support (ERR-033). See the section above. Body fields must
  be token-anchored so they too match both forms -- a `^`-anchored /
  positional body capture is flagged ERR-030.
- If you capture the priority, decode it: a PRI captured but never turned
  into log_level or severity is flagged as WARN-041.
- Facility and severity live in separate alter stages (ERR-024).
- See [transformation-patterns.md](transformation-patterns.md) for the
  companion-pair and String-passthrough rules that apply to the payload.

## Checklist

```
[ ] filter _raw_log != null is the first stage
[ ] PRI captured relay-aware: coalesce(^.*<(\d{1,3})> origin, ^<(\d{1,3})> first)
[ ] host captured via the relay-aware RFC 3164 (^.*<) + RFC 5424 coalesce, not a vendor literal
[ ] every payload field token-anchored (no ^-anchored body, no everything-after-header) -- ERR-030
[ ] NILVALUE hostname (-) guarded to null, never mapped literally
[ ] priority decoded with function-form arithmetic (no infix, no modulo)
[ ] facility and severity in separate alter stages (no sibling reference)
[ ] severity/log_level use coalesce(payload, priority) -- payload wins
[ ] no _time assignment (WARN-018)
[ ] proven with verify_rule.py on BOTH a direct and a relay-prepended copy of the sample
[ ] decode proven: <134> -> Informational, <12> -> severity 4
```
