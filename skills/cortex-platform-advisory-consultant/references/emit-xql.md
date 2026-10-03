<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# The XQL skeleton and the handoff

Read this before reading a skeleton `scripts/emit_xql.py` prints, before passing one on, and
before building on its `--json` handoff.

This bundle does not write rules. The skeleton is for inspection: the dataset, the grouping,
every window, every join and every `<bound>` are the rule author's, and one banner on stdout
says so. What the skeleton does promise is narrower and absolute: **every line it prints as XQL
is XQL, and says what the markers say.** A condition it cannot write as a field test is printed
as a comment naming why, and never pasted into the filter.

Until 0.43.0 it promised neither. 574 of 703 blocks pasted a computed marker's pseudo-code into
the live filter, aggregates and English connectives included, and a strict clause grammar
rejected 1,108 of its 1,669 live clause lines. It now prints 458, and none fails.

## One block

```
// <record-id> :: how[<n>]  pattern=<id>  fidelity=<f>  shape=<s>  locus=<L>  filter=<status>  key=<record-id>#how<n>
// STATUS: SEED  <<< SEED - ...                    only on a seed record's block, as consult.py prints it for the same key
// CAVEAT: <how.caveat, else the pattern's, else "none recorded">
// LOGIC: <how.logic, else the pattern's>
// COMBINE: all|any [by event label]              only when the markers say how they combine
// inventory precondition: <cve and version markers>
datamodel dataset = <dataset>
| filter <clause>
         and <clause>
| bin _time span = <window>                        threshold only
| comp count() as hits by <grouping_key>, _time
| filter hits > <bound>
// REQUIRES [for EVENT <label>] (computed, not a field test): <expression>
// UNBOUND: <type> <match> <value as JSON> -- <why it has no field>
// FIELD (legacy fields[]): <field> <op> <value> -- <note>
```

- `locus=` is the question-independent `LOCUS` a consultation prints for the same block, and
  the JSON `locus_span` is the start of its `LOCUS_SPAN`: a consultation can only append the
  locus of a class its question named.
- `key=` is the `FINDING_KEY`; `emit_xql.py <record-id>#how<n>` emits that one block.
- A threshold floors `_time` to the window with the `bin` stage and counts by it. `bin` is a
  stage, not a function: `by <grouping_key>, bin(_time, <window>)`, printed until the 0.43.0
  review, is not XQL whatever fills its placeholders.
- CAVEAT is always printed. A detection handed over without its known false positive is worse
  than none, and the text form, which is what a reader eyeballs, carried neither caveat nor
  logic.

### `filter=`

| Status | Meaning |
| --- | --- |
| `complete` | Every marker is a clause in the live filter. |
| `partial` | A live filter, plus conditions left as comments: `REQUIRES`, `UNBOUND`, `CLAUSE`, `FIELD` or an inventory precondition. |
| `none` | No live filter at all. |

The status is about the markers' conditions only. The shape's own placeholders -- `<bound>`,
`<window>`, the join, the absence comparison -- are always the author's. The stderr tally
appends `; filter: <n> complete, <n> partial, <n> none`, and then, when the match held records
with no how-block, `<n> matched record(s) carry no how-blocks`. An exposure holds none.

At 0.43.0 the corpus gives 68 complete, 243 partial and 392 none, and at `fidelity=alert` 54,
199 and 173. That is the honest figure: most blocks carry a computed condition no field test
expresses, and the old skeleton only looked complete because it pasted those into the filter.
Seven of the blocks it once called complete tested a word this corpus uses for an event or
zone, `integrity_check`, `account_create`, `dmz`, which no source writes; they are now
partial or none (below).

### The comment kinds

- **REQUIRES** -- a computed marker, rendered as a requirement: `value: true` prints the
  expression, `value: false` prints `NOT (<expression>)`, `gt` and `lt` add `(source bound;
  measure locally)`. A computed marker is never live, because its expression is pseudo-code,
  and pasted into a filter a `false` bound to the last word of a compound expression. One
  labelled with an event prints `for EVENT <label>`: it qualifies that event alone.
- **REQUIRES (normalised, not a source literal)** -- an `event_type` or `zone` marker flagged
  `normalised`: its value is this corpus's own word for the event or zone (`integrity_check`,
  `configuration_change`, `group_create`, `dmz`, `workstation`), not a value any source writes,
  so it prints the clause it would be, with its field, and says to bind the value the source
  records. It is never live, so no filter holding one is complete: printed live, six
  `fidelity=alert` blocks marked complete tested values no tenant holds and returned nothing,
  which reads as a true negative. Its JSON binding has status `normalised` and the would-be
  clause under `requires`. `vocab.json` lists the types that may carry the flag in
  `normalised_marker_types`, and `validate.py` refuses the flag elsewhere, on an XDM_CONST
  field, and an unflagged marker holding a word another marker flags.
- **UNBOUND** -- an event-bound marker with no field, or a field that cannot take it. The
  reason is one of: no field is recorded for the type; the field is not in the bundled XDM
  snapshot; it is an XDM_CONST enum and the literal is not a member, or its members are not
  enumerated, or it is an outcome whose rendered string is not recorded; it is an array, where
  `=` and `in` do not test membership; it is a file hash whose digest XDM has no field for (a
  SHA-1); the match is not one of the eight the contract names (a `not_equals` printed as the
  clause it negates until 0.43.0); or the value cannot be written as the event holds it (a
  range on an address field, a pattern RE2 cannot run, a path holding an unexpanded `%VAR%`, an
  extension with its dot, a URL path that is not a path).
- **CLAUSE (family)** -- a clause that could be written but is not joined into a filter,
  because the markers' combination is unknown (below) or the shape is `inventory`. The family
  is `audit` for a cloud action split from an endpoint clause in a chain.
- **FIELD (legacy fields[])** -- a `how.fields` test no marker carries. Some constraints live
  only there: the Log4j block's server-role restriction is one.
- **NO LIVE FILTER** -- why there is no pipeline.

## Values

The type comes from `corpus/schema/xdm-fields.json`, a copy of the published XDM schema holding
the fields the corpus binds, with their types, and the name of every field the schema has,
taken from the `cortex-platform-xdm-author` bundle, which owns it.

- A regex is written once. XQL passes a string's backslashes through to the regex engine, so
  doubling them, as the script did, turned `nc\.exe` into a literal backslash and `\s` into a
  backslash and an s: a silent zero that reads as a true negative. A double quote becomes
  `\x22`. A pattern ending in an escaped backslash ends in `[\\]` instead, so no backslash sits
  before the closing quote. A pattern RE2 cannot run is refused, and `validate.py` refuses it in
  the corpus: lookaround, a backreference numbered or named (`(?P=name)`), an atomic group, a
  possessive quantifier (`a++`, `{2}+`), a conditional or comment group, `\Z`, `\u` and `\N`,
  a counted repeat above 1000, and an inline flag other than `i`, `m`, `s` and `U`. Three more
  are refused although some engine takes them: `{,n}`, which RE2 reads as literal text and
  Python as a repeat, `(?<name>...)`, which only RE2 releases from 2023 accept (`(?P<name>...)`
  is portable), and `\C`, which can split a character. Every construct where RE2 and Python
  differ is handled by name, and RE2's own -- `\z`, `\pL` and `\p{Greek}`, `\Q...\E`,
  `\x{...}`, a flag anywhere in the pattern -- is rewritten to its Python equivalent before
  the syntax check, so a sound marker is never refused as its own fault by the Python that
  runs the check. What is left to Python's compiler is syntax both engines share.
- `prefix` and `suffix` are escaped as literals and anchored: `.workers.dev` is `\.workers\.dev$`,
  where it was a dot matching any character.
- `=`, `in` and `contains` take a quoted string, written as the event holds it: one backslash
  per Windows separator. A value that cannot sit between quotes -- one holding a double quote,
  or a directory with its trailing separator -- is written as the equivalent regex of the
  escaped literal. XQL folds case in all three, so the test is the same. Two markers held
  `Windows Defender\\Exclusions\\Paths`, the JSON escape applied twice, and the skeleton printed
  a clause looking for a pair of backslashes no registry key contains, under `filter=complete`;
  `validate.py` now refuses a doubled backslash in any literal except at the start of a UNC path.
- A list on `equals` or `contains` is any of its values, and every one is printed: `=` becomes
  `in (...)`, and `contains` the regex alternation of the escaped values, `(?:a|b)`. The first
  value alone used to be printed and the marker called bound. `prefix` and `suffix` take the
  same alternation inside their anchor. `regex`, `gt` and `lt` take one value, and a list there
  is refused.
- A file hash binds by its digest, not its type: 32 hexadecimal digits to `xdm.target.file.md5`,
  64 to `xdm.target.file.sha256`. XDM gives a file no SHA-1 field, so a SHA-1 prints as UNBOUND
  and is not an error. One marker holds one digest type; a digest bound to a field of the other
  type, or a list mixing lengths, is refused. Six MD5s and two SHA-1s had been tested live
  against the SHA256 field, where they can never match.
- A number against a String field is quoted (`xdm.event.id in ("4720", ...)`), bare against a
  Number field. An enum field takes its constant, unquoted: 200 is `XDM_CONST.HTTP_RSP_CODE_OK`,
  `udp` is `XDM_CONST.IP_PROTOCOL_UDP`.
- **Except `xdm.event.outcome`, which is compared as the string its constant renders as**:
  `SUCCESS` is `"SUCCESS"`, `FAILURE` is `"FAILED"`. The `cortex-platform-correlation-author`
  bundle proved on three rules across two packs that comparing it to `XDM_CONST.OUTCOME_*`
  fails the whole pack install with a 101704 naming no file and no field, and lints it as
  `ERR-CORR-OUTCOME-CONST`. The constant is right in a modelling rule's assignment, which is
  what the xdm-author bundle's "never quote them" is about; this page said otherwise until the
  second 0.43.0 review, and 12 alert-fidelity skeletons printed the constant. `PARTIAL` and
  `UNKNOWN` print as UNBOUND, because the string they render as is not recorded. The same
  bundle records `XDM_CONST.OPERATION_TYPE_*` installing and running in a query; the HTTP
  status, method and IP protocol constants are untested there (Before production).
- A path in `xdm.network.http.url` or `xdm.target.url` is tested where it sits in the whole
  URL, which those fields hold, scheme and host first. A `url_path` or `api_path` tested with
  `equals` or `in` is written `~= "^(?:<scheme>://)?<authority><path>(?:[?#]|$)"`, where the
  authority holds no `/` and may be empty; `prefix` drops the tail and `suffix` the head, and
  the value must begin with `/`; a regex anchored `^/` is refused. `xdm.network.http.url =
  "/beacon"`, printed under `fidelity=alert` until then, can never match. The authority was
  optional only after a scheme until the third review, so a URL recorded as `host/path` or
  `host:port/path`, which the xdm-author bundle's proxy mapping extracts a host from, never
  matched; `/x/beacon` and `/beacons` still do not. `contains` and an unanchored regex are unchanged. An `api_path` has no default
  field: an HTTP log's URL, a container runtime's audit or a cloud audit's resource carries it,
  whichever the source is.
- A path, a process path or a file name holds what the event records, expanded: a value
  holding `%TEMP%` is refused, as is an extension written with its dot, since the marker
  vocabulary and XDM both hold `lnk`, not `.lnk`. A command line keeps its variables, because it
  holds what was typed.

`datamodel dataset` opens every pipeline, because every live clause names an `xdm.*` field,
which a raw `dataset =` stage does not expose. That is a preference, not the retired
raw-dataset prohibition. A block with more than one `dataset_hint` names the rest for their own
query, because a correlation refuses `datamodel dataset in (...)`.

## How markers combine

A block, or a pattern, may say how its markers combine (`corpus/README.md`, How markers
combine). Absent, the skeleton joins clauses with `and` unless it can see they are not one
event: two clauses from different event families (process, file, registry, DNS, HTTP), or one
field tested twice, are printed as `CLAUSE` lines under `NO LIVE FILTER`, because no single
event satisfies them. Actor, event-level, address, port and zone fields sit on every event and
decide nothing here, with one exception `validate.py` refuses: a connection's port, address,
zone or protocol beside a process bound to `xdm.target.process`. The process that opens a
connection is the event's actor, `xdm.source.process`, as the platform and the xdm-author bundle
map it, and a process acted upon is not on a connection, so a tunnel client's port and image on
the target side were one event no event satisfies, under `filter=complete`. What the skeleton
cannot see is the author's to key, and two shapes of it were printed as one event under
`filter=complete` until the third review: an event identifier or type beside an artefact of
another event (the log-cleared identifiers 1102 and 104 with the command line of the utility
that clears logs, which that record does not carry), and two things of one family (a key file in
the drive root and a ransom note in every directory). The first is refused by `validate.py` in a
list without `combine`, since an identifier names which event it is and not whether the other
markers sit on it; the second no check can see, and the sweep that keyed it read every unkeyed
list with more than one live clause against its logic. One more pair cannot be one event where
the shape spans events: in a `sequence` or a `correlation`, a cloud action (a `cloud_operation`
marker) and a process, file, registry or DNS clause are printed as `CLAUSE (audit)` and
`CLAUSE (<family>)`. In a `single_event` block they join, because the author says there is one
event, and a storage audit's read can name its object as a file. A user agent is carried by the
audit itself, so HTTP does not split.

- `combine: any` prints the alternatives joined with `or`, one parenthesised alternative per
  line. With event labels, each label's markers are one alternative, joined inside with `and`.
- `combine: all` joins every clause with `and`, trusting the author that they are one event.
  With event labels, each label is its own pipeline under `// EVENT <label>:`, and a closing
  comment relates them: the join for `correlation`, the order for `sequence` (the order the
  labels first appear), and for any other shape that every event must occur.
- A computed marker qualifies the whole list, unless it carries an event label, when it
  qualifies that event alone and prints `REQUIRES for EVENT <label>`: under `any`, the
  qualifier of one alternative is no condition on the others. Its label must be one the list's
  event-bound markers carry.
- A consultation prints the same contract. Every `MARKERS` and `LIBRARY_MARKERS` line carries
  `xdm=` when the marker names its field, `event=` when it is labelled, and `combine=` on every
  line of a keyed list; a list with no `combine=` is unkeyed and reads as above.
- `inventory` never prints a pipeline. `absence` never prints `filter hits = 0`: comp over
  events cannot produce a zero row, so the comparison with an inventory of expected reporters
  is stated as an `ABSENCE:` comment.

## The JSON handoff

`--json` is what a rule-authoring skill consumes. Beside the markers, ATT&CK and provenance:

| Key | What it carries |
| --- | --- |
| `markers_from_source`, `markers_from_pattern` | Both lists, unmerged. |
| `combine_from_source`, `combine_from_pattern` | Each list's combination key, or null. |
| `marker_bindings` | One entry per marker in both lists: `source`, `index`, `type`, `field`, `status`, and `clause`, `requires`, `reason` or `event` where they apply. |
| `filter_status` | The text skeleton's status for the block. |
| `status` | The record's `status`, as a consultation prints it on `STATUS:` for the same key. `seed` is unconfirmed whatever `confidence` says: `confidence` is the block's own, and does not say whether anybody re-read the source. |
| `seed_support` | Which seed meaning applies to this block: `unread` (not fully re-read against its source: `where.verified` is not true), `unconfirmed` (re-read, and it does not support this block), `supported` (re-read, and it supports this block but not the whole record), or null on a record that is not seed. The text skeleton's `// STATUS:` line says the same. |
| `provenance.disclosure`, `provenance.retrieved`, `provenance.verified` | `where.disclosure`, `where.retrieved` and `where.verified`, as `SOURCE_DISCLOSURE` and `SUPPORT` print them: `restricted` means cite the title as given and nothing further, and a null is a value the record does not state. |
| `fields_from_source` | `how.fields`, verbatim. |
| `countermeasures`, `countermeasures_shown`, `countermeasures_total`, `countermeasures_not_shown` | The consultation's own selection, at twelve: deduplicated, one control per D3FEND tactic in turn, a control D3FEND maps directly before one it only infers, then the one more cited techniques reach, then one acting on the artefact before one acting on the whole host, in tactic order, with what was cut named by id. Each control carries `mapping`: `direct`, `inferred-narrower` or `inferred-broader`. |

`status` is one of `bound`, `computed`, `state`, `unbound`, `not_an_xdm_field`,
`enum_literal`, `array_field`, `unrenderable` and `normalised`. A consumer reads the emitter's decision there
rather than re-deriving a default binding, so a wrong default can never pass downstream
silently.

## Before production

Two tenant probes are owed before a skeleton is trusted in production:

- The escaping rests on the xdm-author bundle's recorded XQL behaviour: escape once, and `\\s`
  matches nothing. One probe of a single-backslash pattern, printed as the platform receives
  it, should confirm it.
- An enum constant other than an outcome or an OPERATION_TYPE member -- the HTTP status,
  method and IP protocol constants -- has not been seen to install in a query. One correlation
  comparing `xdm.network.http.response_code` to `XDM_CONST.HTTP_RSP_CODE_OK`, installed on a
  development tenant, settles whether the constant or its rendered string is the form.

Nothing else in this page needs a tenant.
