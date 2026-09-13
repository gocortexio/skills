<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# The corpus

A flat store of what happened to vendor technologies, and how it was spotted. One record answers six questions about one technology in one scenario, taken from one source.

Nothing here is prose for people to read end to end. It is written to be loaded, filtered and turned into Cortex XQL.

## Layout

```
corpus/
  schema/
    observation.schema.json   the record contract
    vocab.json                closed value lists
    aliases.json              how a person's words map to a lookup
    locus-map.json            which product class sits on which locus
    example-record.json       two worked records, one public and one restricted
  observations/
    observations.jsonl        one record per line, grouped by vendor
  patterns/
    patterns.jsonl            detection scenarios shared across records
  reference/
    attack-techniques.json    ATT&CK v19.1, log sources and locally tunable elements
    d3fend-countermeasures.json  D3FEND 1.5.0, what to do, keyed by ATT&CK id
    response-doctrine.json    how a response is sequenced and scoped, by class and impact
    url-liveness.json         cached liveness verdicts, re-checked after 14 days
```

JSON Lines, not YAML, and no third-party parser. Appending is a one-line diff, `grep` works, and the scripts run on a stock Python 3.9.

`reference/` is the exception to the JSON Lines rule: these are whole-file JSON objects, harvested from an upstream framework by a maintainer-side script rather than written by hand, and never edited in place. That harvest step is not part of the published bundle; what ships is its output. Nothing in `reference/` is validated by `scripts/validate.py`; a missing or malformed file degrades the block that reads it rather than failing the run. Each carries the upstream version and an `attribution` key naming the licence it travels under.

## The six questions

| Key | Question | Holds |
| --- | --- | --- |
| `who` | Who is the technology? | Vendor, product names, product class |
| `what` | What was observed? | The role it played, the impact, any CVEs |
| `how` | How was it seen? | Detection logic, telemetry needed, fields, indicators |
| `where` | Where did this come from? | Publisher, citation, public URL or restricted marker |
| `who2` | Who else is named? | Threat actor, target sector, target region |
| `when` | When? | Absolute dates only |

`who.product_class` is what makes the corpus useful. Somebody asking about their firewall does not care that the record is about a Cisco appliance and theirs is a Fortinet one; the class is what carries the lesson across.

## Two record types

Every record declares a `record_type`, and the two behave differently.

**`observation`** is something that was seen happening. It carries detection logic in `how[]`,
is written by hand from a source, and answers "what should I watch for on this technology".
Its id starts `obs-`. At least one `how` block is mandatory; the validator rejects an
observation without one, because the detection logic is the whole point of the record.

**`exposure`** is a published statement that a product is affected by a named vulnerability.
It carries no detection logic, is generated in bulk from vulnerability advisories, and answers
"what has been published about my kit". Its id starts `exp-`. It must carry
`what.vulnerabilities` or `who.versions_affected`, and it must carry `where.url` so that a
generated record is always traceable back to the advisory it came from.

The lookup ranks observations first and returns exposures as a separate block afterwards, with
its own limit. That separation is deliberate: a vulnerability feed can run to thousands of
entries and would otherwise bury the handful of records that actually tell you what to detect.
An exposure only earns a `how` block where the advisory itself published detection guidance.

## One record per advisory-observation

One record is one vendor technology, one observed behaviour, one source. A report covering three products becomes three records. A report describing two distinct behaviours against one product becomes two records.

Overlap is the point, not a problem. Two records describing the same detection scenario share a `pattern_id`, and the pattern carries the reusable logic. That is how "edge VPN appliance dropping a web shell" collapses into one thing to detect across five vendors.

## Restricted sources

Some sources are licensed intelligence, not public research. Those records carry `where.disclosure: "restricted"` and follow four rules:

1. **No report identifier anywhere in the record.** Not in `id`, not in `source_id`, not in `notes`. `validate.py` fails the build if it finds one.
2. **Abstract citation only.** `where.title` takes the form `<Publisher> commentary on <subject>`. A report filed as `TR-<year>-<n>_<Subject>_<Product>` is cited as `<Publisher> commentary on <subject>`. The example is a placeholder rather than a real filing on purpose: a worked example of a redaction rule is the likeliest place in a bundle for a specimen of the forbidden thing to end up, because an example feels like an exception to the rule it illustrates. It is not one, and `validate.py` now checks the prose as well as the records. No `where.url`, because there is nothing a reader could open.
3. **No verbatim wording.** Every field is written fresh. `what.summary` states the behaviour in plain words; `how.logic` states the detection in plain words. If a phrasing could only have come from the report, rewrite it.
4. **Month precision on dates.** A restricted record uses `YYYY-MM` at finest, with `when.precision` set to `month`. An exact publication date plus a subject line is close enough to a fingerprint to identify the report; the month keeps the timeline useful without that.

The technical substance is kept in full: field names, log messages, protocols, ports, file paths, indicators, ATT&CK techniques. Abstraction applies to the source's identity and its wording, not to the detection.

## Public sources

Most sources are public and none of the above applies to them. A record drawn from a government
advisory, a vendor security bulletin or published research carries `where.disclosure: "public"`,
a real `where.url` a reader can open, the source's actual title, and dates at whatever precision
the source gave. Nothing is abstracted, because there is nothing to protect.

Two consequences worth knowing:

- Government advisory output, such as CISA material, is public domain. It can be cited directly
  and quoted where quoting helps. `source_type` is `government_advisory`.
- Where a public source covers the same campaign as a restricted one, add the public citation to
  the existing record rather than creating a second record. That upgrades a record from an
  abstract citation nobody can check into one with a link, which is a real improvement to a
  corpus that has to be trusted by people who cannot see the original.

## Adding records

1. Read the source. Decide how many technologies and how many distinct behaviours it describes; that is the record count.
2. Write each record as one line in `observations/observations.jsonl`, next to the other records for that vendor. `who.vendor` is what groups them, so the file stays navigable with `grep '"vendor": "Cisco"'`; the loaders read the file in order and do not care where a line sits. Where a record covers a class rather than a named vendor, `who.vendor` is `any`.
3. Every value going into `who.product_class`, `what.role`, `what.impact`, `what.attack_surface`, `how.evidence_type` and `who2.actor_type` must already exist in `vocab.json`. If it does not, add it there in the same change, with a one-line description.
4. If the detection is one already described by another record, reuse its `pattern_id` rather than restating the logic.
5. Set `status` to `seed` unless the source was read directly while writing the record, in which case `verified`.
6. Run the validator.

```bash
python3 scripts/validate.py
```

## Writing the `how` block

`how` exists to become a query. Write it so an engineer could produce the XQL without going back to the source.

- `logic` is one or two sentences of precise plain words. "Configuration read via SNMP from an address outside the management subnet, followed within an hour by a configuration write" is usable. "Suspicious SNMP activity" is not.
- `fields` are the concrete tests. Give the XDM path where one is known, the raw vendor field where it is not, and never guess a field name to fill the slot; leave it out instead.
- `fidelity` is honest about what the logic can carry. `alert` means it is specific enough to wake someone. Most of what comes out of a threat report is `hunt`.
- `caveat` is where the known false positive goes. An engineer who finds it out the hard way will not trust the rest of the record.

## Markers: the handoff to a rule-authoring skill

This corpus does not author detection rules. It supplies what a rule-authoring
skill needs in order to. `logic` and `caveat` are for a human deciding whether a
detection is worth building; **`markers` are for the skill that builds it.**

A marker is a typed, literal, rule-generatable observable. `fields` predates it
and is kept for continuity, but `fields` allowed any invented name in its `raw`
slot, which produced 196 distinct pseudo-field names across the corpus and could
not be consumed mechanically. `markers` is the contract that replaced it.

```json
"rule_shape": "single_event",
"markers": [
  {"type": "process_name", "match": "in", "value": ["vssadmin.exe", "wbadmin.exe"]},
  {"type": "command_line", "match": "regex", "value": "(?i)delete shadows"},
  {"type": "computed", "match": "gt", "value": 7.9, "expr": "shannon_entropy(registry_value_data)"}
]
```

- `type` comes from `vocab.json` `marker_type`. Closed list.
- `match` defaults to `equals`. `in` requires an array.
- `value` must be a literal drawn from the source. Never a placeholder.
- `xdm` binds the marker to a field where one is known; otherwise the consumer
  resolves it from `type`.
- `type: computed` is for anything requiring calculation rather than a field
  lookup, and `expr` is then mandatory. This is the honest home for entropy,
  counts, rates, distinct-counts and time differences. Without the separation a
  consumer cannot tell a field test from an aggregation.

### rule_shape

Tells the consumer what query structure the markers imply, which it cannot
reliably infer from the markers alone.

`single_event` a filter; `threshold` needs a count and a bound;
`correlation` needs a join; `sequence` needs ordering within a window;
`absence` the signal is an expected event not arriving; `inventory` answered
against asset or configuration state, not an event stream.

Only set `correlation` where the detection genuinely needs two event types
joined. It was over-assigned once by inference and produced skeletons telling the
consumer to join against nothing.

### Where markers live

Generic markers belong on the **pattern**, because a pattern is the reusable
detection scenario cited by many records. Source-specific literals belong on the
**record**. A `how` block satisfies the marker contract if either it or its
pattern carries markers, and the handoff supplies both separately as
`markers_from_pattern` and `markers_from_source` so the consumer decides which to
anchor on rather than receiving them pre-merged.

### Thresholds are never invented

Where a bound has to be measured against the consumer's own estate, say so in the
marker or the caveat and leave it unresolved. A shipped rule with a fabricated
threshold is worse than no rule, because it will be trusted.

### Checking the handoff

```bash
python3 scripts/emit_xql.py <record-id> --json
```

Emits the structured object a rule-authoring skill consumes. Without `--json` it
prints an XQL skeleton for eyeball inspection -- that skeleton is deliberately
incomplete, with dataset selection and every `<bound>` left to the author.

`validate.py` reports marker coverage on every run, separately for all how-blocks
and for `alert`-fidelity ones. Alert-fidelity blocks are the ones that become
rules, so that second figure is the one that matters. A block with no markers and
no `inventory`/`absence` shape is reported as a gap.

## Bulk-generated exposure records

704 of the exposure records are generated from the CISA Known Exploited
Vulnerabilities catalogue, one per vendor/product pair. They are distinguishable
by the `exp-kev-` id prefix, `where.source_type: database`, and the
`known-exploited-catalogue` tag.

They exist for **findability**, not analysis. A generated record asserts only that
the named identifiers were exploited; it carries no `how` block and therefore no
markers, because the catalogue contains no detection logic. Where an identifier is
also covered by a hand-written observation, the generated record says so and points
at the observation as the place the detection lives.

Three things about them are derived rather than sourced, and all three are stated in
the record itself: `who.product_class`, mapped from the vendor and product names;
`what.impact`, mapped from the catalogue's vulnerability name and description text; and
`what.attack_surface`, mapped from the derived class, the catalogue having no
attack-surface field of its own. Nothing else is inferred.

Do not add markers to these records. If a product needs detection logic, write an
observation for it from a source that actually describes the behaviour.

## external_corroboration on patterns

Most patterns carry an `external_corroboration` block counting how many
independent SigmaHQ and Splunk security_content rules implement a detection for
the same techniques, with the licences of both named. It is regenerated on the
maintainer side when either rule corpus is re-indexed, and reaches a rule author
through the handoff.

It is evidence that a detection scenario has been implemented against real
telemetry by other people. It is **not** a quality score, and a pattern without it
is not weaker. 183 of the 475 patterns have none. Operational technology is the
clearest case, because the public rule corpora barely cover that domain, but it is
not the bulk of it: 41 of the 183 apply to an `ot.*` class and the rest spread
across application, network and cloud. Every pattern added in the most recent
ingest is in that set, corroboration being a separate pass that has not been run
since. For those the corpus is often the only written source, which is a reason to
scrutinise them harder before shipping, not a reason to discount them.

## Library patterns

A pattern normally reaches a consumer through a record that cites it. 33 patterns
are cited by no record: they are derived from technique space, via the public rule
corpora, rather than from an incident. Writing an observation to carry them would
mean inventing a source, so they stay uncited.

That made them unreachable, because `query.py` only ever loaded patterns to enrich
records and `emit_xql.py` iterates records. `query.py` now surfaces them: it reports
a **library patterns** block, matched on `applies_to_classes` and ranked by external
corroboration, whenever a query resolves to a class. `emit_xql.py` still does not,
because it takes a record id and walks that record's blocks; an uncited pattern has
no record to be reached through, so it is visible to a lookup and not to the XQL
handoff.

Two consequences for anyone adding patterns:

- An uncited pattern needs both `markers` and `applies_to_classes` or it cannot be
  reached at all. That is now the definition of a complete pattern.
- Product aliases need a `product_class`, or a product query resolves to a vendor
  and product but no class and never reaches the library block. 64 aliases were
  backfilled from the records for exactly this reason.

## Class aliases

`class_aliases` maps natural language onto the `product_class` vocabulary, and it
is what makes the library-pattern block reachable: a query that resolves only to a
vendor never reaches a pattern.

The cloud classes originally had **no aliases at all**, so nobody asking about AWS,
Azure, Kubernetes or Entra reached any of that material, including the exposure
records generated for it. 159 aliases were added across every class in the vocab.

When adding a class to `vocab.json`, add its aliases in the same change. A class
with no alias is only reachable by someone who already knows the vocabulary, which
is not who the lookup is for.
