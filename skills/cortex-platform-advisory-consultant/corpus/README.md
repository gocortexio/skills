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
    locus-map.json            the ladder that places each finding on a locus
    scope.json                what the corpus holds and a consultation declines to list
    example-record.json       two worked records, one public and one restricted
  observations/
    observations.jsonl        one record per line, grouped by vendor
  patterns/
    patterns.jsonl            detection scenarios shared across records
  reference/
    attack-techniques.json    ATT&CK v19.2, log sources, locally tunable elements, and
                              which ids are revoked or deprecated and what replaced them
    d3fend-countermeasures.json  D3FEND 1.6.0, what to do, keyed by ATT&CK id, a revoked
                              id's list carried to its replacement
    response-doctrine.json    how a response is sequenced and scoped, by class and impact
    url-liveness.json         cached liveness verdicts, re-checked after 14 days
    advisory-identifiers.json the CVE identifiers each CISA advisory page names, which a
                              record citing only such pages is held to
```

JSON Lines, not YAML, and no third-party parser. Appending is a one-line diff, `grep` works, and the scripts run on a stock Python 3.9.

`reference/` is the exception to the JSON Lines rule: these are whole-file JSON objects, harvested from an upstream framework by a maintainer-side script rather than written by hand, and never edited in place. That harvest step is not part of the published bundle; what ships is its output. Nothing in `reference/` is validated by `scripts/validate.py`; a missing or malformed file degrades the block that reads it rather than failing the run. One file is read by the validator rather than validated by it: `advisory-identifiers.json`, taken from a maintainer-side copy of each CISA advisory and analysis report page's text, lists the CVE identifiers each page names, and a record whose every cited source is listed there is refused for carrying an identifier none of them names (outside `notes` and the citation itself). A record also citing a source not listed is not decided. Without the file the check is reported as skipped. Each carries the upstream version and an `attribution` key naming the licence it travels under.

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
It carries no detection logic, is generated in bulk from vulnerability advisories or written
by hand from a joint government advisory, and answers "what has been published about my kit".
Its id starts `exp-`. It must carry `what.vulnerabilities` or `who.versions_affected`, and it
must carry `where.url` so that a generated record is always traceable back to the advisory it
came from.

Both `query.py` and `consult.py` rank observations first and return exposures as a separate
block afterwards, with its own limit, `--exposure-limit`. That separation is deliberate: a
vulnerability feed can run to thousands of entries and would otherwise bury the handful of
records that actually tell you what to detect. `consult.py` lists only the exposures naming
what was asked, never another vendor's by class, and refuses the handset records
`schema/scope.json` names, counting both; `references/exposures.md` in the bundle has the
contract. An exposure only earns a `how` block where the advisory itself published detection
guidance.

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
2. Write each record as one line in `observations/observations.jsonl`, next to the other records for that vendor. `who.vendor` is what groups them, so the file stays navigable with `grep '"vendor": "Cisco"'`; the loaders read the file in order and do not care where a line sits. Where a record covers a class rather than a named vendor, `who.vendor` is `any`. `any` is never matched as a vendor, so name the makers the record covers in `who.products`: a question naming one of them reaches the record as that vendor, as `vendor GitHub (named in product GitHub)`. An entry names a product only where it carries the vendor ("VMware ESXi") or is the product's own name ("Zimbra Collaboration Suite"); a class noun such as "firewalls" or "routers" names every vendor's product and nobody's, so write "Sophos firewalls" when the record is about Sophos's.
3. Every value going into `who.product_class`, `what.role`, `what.impact`, `what.attack_surface`, `how.evidence_type` and `who2.actor_type` must already exist in `vocab.json`. If it does not, add it there in the same change, with a one-line description.
4. If the detection is one already described by another record, reuse its `pattern_id` rather than restating the logic.
5. Set `status` to `verified` only when the source was read directly while writing the record and supports all of it, and record the read date in `where.retrieved`. Otherwise set `seed`. That includes a source that was read and supports only part of the record, in which case `notes` opens with "Seed." and names the part it supports, and every how-block carries `unconfirmed`: true where the re-read source does not support it, false where it does. `validate.py` refuses `confidence: high` on such a block and on any block of a seed record not fully re-read against its source. A read of one block is recorded in `notes`, not in `where`, whose `verified` and `retrieved` state a re-read of the whole record.
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

## Where a record sits (LOCUS)

Every finding prints a `LOCUS`, one of the six values in `vocab.json`, derived by the ladder in `schema/locus-map.json` from what the record says; `references/locus-and-coverage.md` has the whole ladder. Nine authoring choices decide it, so make them deliberately; a tenth, the evidence, decides only through five narrow rules among them and otherwise can only add a span.

- **Class order picks the plane.** The first-listed `who.product_class` is read as the primary subject. List the product the record is about first: a record about a firewall that also names the web server behind it lists `network.firewall` first. The later classes still count: a question naming one of them has that class's locus appended to `LOCUS_SPAN`, after the record's own span, where it differs from both, but never as the `LOCUS`.
- **`cross_sector` and `process.service_desk` are subjects, not tags.** Listed first, or alone, they place the record on `ORGANISATION`, which tells the reader the finding is an inventory or advice question rather than an event on a device. Record the sectors an incident targeted in `who2.target_sectors`. A non-product class listed after a product class decides nothing and travels only as a span.
- **`what.attack_surface` decides only where it names a plane, and only for the blocks it reaches.** Six surfaces are deferred as reachability rather than plane. `email_flow` and `remote_access_service` are span-only: they name the way in, so a renderer breakout delivered by mail is still an `ENDPOINT` finding. Write the surface the incident used, never one chosen to move the label.
- **`how.technique` says which block is about the way in.** A surface is per record and a block is one detection. A supply surface (`supply_chain_update`, `third_party_access`) places only a block citing the technique its vector is filed under -- Supply Chain Compromise or Trusted Relationship, in `surface_vector_techniques` -- or reading `integrity_check`; the record's other blocks detect what followed and are placed by the class, with the surface as their span. Any other committing surface places every block except one that has gone past the way in: it cites no initial-access technique (`way_in_techniques`), reads no evidence on the surface's plane, and its evidence reads the first-listed class's plane, only posture, or only host evidence (`edr_process`, `edr_file`, `registry`, `memory`, `file_artefact`), which places it on `ENDPOINT` by `host_evidence`. So cite on each block the technique it detects: the delivery on the block that detects the delivery, the way in on the block that detects the way in.
- **A block whose live test is a cloud administrative operation sits on `MANAGEMENT`.** When every typed marker on a block is a `cloud_operation`, or the block reads only the provider's audit trail (`cloud_audit`) and its other typed markers are fields of the same audit event, the `operation` tier places it on `MANAGEMENT` whatever class is listed first, because a cloud provider's or tenant's administrative API is administration. An operation that is a use of the service rather than its administration -- reading mail, invoking a model, reading a stored object -- goes in `non_administrative_operations` in the locus map, not into another marker type; a block testing only listed operations is left to the ladder.
- **`rule_shape: inventory` with posture-only evidence makes a block an `ORGANISATION` finding.** A block answered against asset or configuration state whose evidence is only `vuln_scan` and `asset_inventory` is an inventory question, and the `posture` tier places it on `ORGANISATION` whatever class or non-supply surface its record carries; the surface travels as its span. Shape alone decides nothing, and nor does posture evidence beside any other type, so write the shape and the evidence the block actually has. A library pattern is read the same way, so give an inventory pattern its `rule_shape` too.
- **A block on a record listing `cloud.iaas` first is placed by the class only if it reads the provider's API.** The class is defined as an administrative API and console. A block carrying no `cloud_operation` marker and reading nothing on `MANAGEMENT` or from inventory, whose evidence reads one other locus -- a workload's flow and DNS records, a certificate seen in TLS metadata -- is placed there by `admin_api_unread`. The other way round, a block on a record listing `cloud.iaas` after its first class, reading the provider's audit trail or configuration and nothing on the first class's plane, is placed on `MANAGEMENT` by `admin_api_listed`, unless its operations are all uses of a service. The classes both apply to are `administrative_api_classes` in the locus map.
- **List the host's class when a block reads only the host.** A block reading only process, file, registry or memory evidence, and nothing on the first-listed class's plane, sits on `ENDPOINT` by `host_listed` when the record lists an operating system, browser or agent class after the first: an NTDS.dit copy staged in a temp path on a directory record that also lists `endpoint.os`. Without that class it keeps the first-listed class, deliberately, because a product with a plane decomposition is not an `ENDPOINT` subject; list the host's class only where the incident ran on one.
- **`how[].locus` overrides the derivation, and almost never should.** Set it only where the derivation is provably wrong, and give the reason in `notes`, naming `how[<n>].locus`. `validate.py` refuses an override the derivation already gives, and one whose reason is missing. A pattern may declare `locus` too, with the reason in its own `locus_reason`, for a plane its class list cannot say: a network or OT device's administration, which has no class of its own. One declares against its own markers instead: a mailbox property sweep whose mailbox audit actions would place it by the operation tier, while what it reads is mail held. It places the pattern where it has no block -- `advise.py` and a `LIBRARY` block -- and never reaches a record's block.
- **`how.evidence_type` says where the detection is read, not where the attack sits.** It decides the `LOCUS` only inside the rules above, each on a narrow test met only where the block reads nothing on the plane it displaces, and each, with the surface reach test, leaving out `process_telemetry`, whose reading is contested. When every type but `syslog` agrees on one locus other than the primary, and no earlier source has given a span, that locus is the span: evidence is the last source a span is taken from, and `LOCUS_BASIS` prints `evidence-signal=` either way. List the telemetry the detection actually reads.

An exposure carrying one of the generator tags in `untrusted_surface_tags` is placed by its class and, where its generator wrote `what.identifier_signals`, by what each identifier's own catalogue or advisory text names, because a generator assigned its `attack_surface` from a class table rather than reading it from the advisory. A locus every identifier reads decides; otherwise it is the span. The field is the generator's: `validate.py` refuses it on an observation or a hand-written exposure, and holds every entry to `identifier_reading` in the locus map, so correct it by regenerating, never by hand. A hand-written exposure's surface is read like any observation's.

## Markers: the handoff to a rule-authoring skill

This corpus does not author detection rules. It supplies what a rule-authoring
skill needs in order to. `logic` and `caveat` are for a human deciding whether a
detection is worth building; **`markers` are for the skill that builds it.**

A marker is a typed, literal, rule-generatable observable. `fields` predates it
and is kept for continuity, but `fields` allowed any invented name in its `raw`
slot, which produced 196 distinct pseudo-field names across the corpus and could
not be consumed mechanically. `markers` is the contract that replaced it. A
`fields` test no marker carries is still handed on, as `fields_from_source` and as a
`FIELD` comment in the skeleton, because some constraints live only there.

```json
"rule_shape": "single_event",
"markers": [
  {"type": "process_name", "match": "in", "value": ["vssadmin.exe", "wbadmin.exe"]},
  {"type": "command_line", "match": "regex", "value": "(?i)delete shadows"},
  {"type": "computed", "match": "gt", "value": 7.9, "expr": "shannon_entropy(registry_value_data)"}
]
```

- `type` comes from `vocab.json` `marker_type`. Closed list.
- `match` defaults to `equals`. `in` requires an array. `equals` and `contains` may take one
  too, read as any of its values; `regex`, `gt` and `lt` take one value.
- `value` must be a literal drawn from the source. Never a placeholder. The one exception is
  declared: an `event_type` or `zone` marker may hold this corpus's own word for the event or
  zone (`integrity_check`, `group_create`, `dmz`) where the source's event name or the site's
  zone name differs by product or site, and then carries `"normalised": true`. The skeleton
  prints it as a requirement naming its field, never as a live clause. `vocab.json` lists the
  types in `normalised_marker_types`; `validate.py` refuses the flag on any other type or on an
  XDM_CONST field, and an unflagged marker holding a word another marker flags. A path is written as
  the event holds it, one backslash per separator, which in JSON is `\\`; `validate.py`
  refuses a doubled backslash in any literal but a regex, except at the start of a UNC path.
  The event holds a path expanded, so a file path, process path or file name never carries
  `%TEMP%` or another variable, and an extension is written without its dot (`lnk`); both are
  refused, in `fields` as well. A command line keeps its variables: it holds what was typed.
- A `url_path` tested with `equals`, `in`, `prefix` or `suffix` is a path beginning with `/`.
  Its field, `xdm.network.http.url`, holds the whole URL, so the skeleton matches the path
  where it sits in it, and a `regex` over a URL must not anchor `^/`. An `api_path` has no
  default field and names its own with `xdm`.
- An `event_outcome` is `SUCCESS` or `FAILED` (`FAILURE` is read as `FAILED`), and the skeleton
  compares it as that string: comparing `xdm.event.outcome` to its constant in a query fails
  the whole pack install.
- A `file_hash` binds by its digest: 32 hexadecimal digits to `xdm.target.file.md5`, 64 to
  `xdm.target.file.sha256`. XDM has no SHA-1 field for a file, so a SHA-1 is kept and printed
  as UNBOUND. One marker holds one digest type; `validate.py` refuses a list mixing them.
- `xdm` binds the marker to a field where one is known; otherwise the consumer
  resolves it from `type`. The field must be in `schema/xdm-fields.json`, the bundled
  copy of the published XDM schema, and an enum field whose members the snapshot lists
  takes only a literal naming one of them, whether the marker names the field or takes
  the default: `validate.py` refuses both. A cloud or SaaS action name is
  `xdm.event.original_event_type`, never `xdm.event.operation`, which is the derived
  verb (CREATE, READ); an application protocol is `xdm.network.application_protocol`,
  never the layer-4 `xdm.network.ip_protocol`; and a group or account the event acts
  on is a `xdm.target.user.*` field, never the actor's.
- A `regex` value must run under RE2, which XQL's `~=` uses: no lookaround, no
  backreference numbered or named, no atomic group, possessive quantifier, conditional
  or comment group, no `\Z`, `\u` or `\N`, and no inline flag but `i`, `m`, `s` and `U`.
  Write `{0,n}`, not `{,n}`, and `(?P<name>...)`, not `(?<name>...)`. Write an exclusion as
  a computed marker valued `false`.
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

### How markers combine

Nothing in a marker list says whether its markers are conditions on one event or
alternatives, and until 0.43.0 the skeleton joined every one with `and`: a registry key
and a process name in one event, two different paths on one file. Say it, with two keys.

- `combine` on the `how` block, or on the pattern, for its own markers: `all` means every
  event-bound marker holds, `any` means each is an alternative way the detection fires.
- `event` on a marker, a lower-case label. Markers sharing a label are conditions on one
  event. Under `any` each label's group is one alternative; under `all` each is its own
  event and every one must occur, related by the `rule_shape` -- for a `sequence`, in the
  order the labels first appear.

```json
"combine": "any",
"markers": [
  {"type": "process_name", "match": "in", "value": ["netsh.exe"], "event": "netsh"},
  {"type": "command_line", "match": "regex", "value": "(?i)advfirewall", "event": "netsh"},
  {"type": "event_id", "match": "in", "value": [2004, 2006], "event": "firewall_log"}
]
```

A computed marker is a requirement of the whole block, unless it carries a label, when it
qualifies that event alone: under `any`, the qualifier of one alternative is no condition on
the others. Once one event-bound marker carries a label every one must, labels need
`combine`, and a computed marker's label must be one an event-bound marker carries;
`validate.py` refuses each gap. Without the key, the skeleton joins clauses unless it can see
they are two events -- two event families, or one field tested twice -- and prints those as
`CLAUSE` comments; `references/emit-xql.md` has the rules. It cannot see the rest, so say it:
an event identifier, type or raw action (`event_id`, `event_type`, `cloud_operation`) beside
a process, file, registry, DNS or HTTP marker is refused without `combine`, because the
identifier names which event it is and not whether the others sit on it -- `all` for Sysmon
11 and the path it writes, `any` for the log-cleared record and the command that clears a
log. Two things of one family, such as a key file and a ransom note, no check can see. And a
process on a connection is its actor: beside a port, address, zone or protocol, bind the process
to `xdm.source.process`, because `xdm.target.process` is a process acted upon, which a
connection does not carry; `validate.py` refuses the pair on one event.

A marker's `match` is one of the eight the schema lists, on a pattern as on a record. The
contract has no negated test: a negation is a computed marker valued `false`, as
`source_in_management_network` is, and never a positive test with a note saying otherwise.

Under `any` every alternative fires alone, so each must carry what gives the detection its
fidelity, not only the act: an exclusion cmdlet with the path it excludes, a Run dialog
history entry with the script it recorded, or, where no field test holds it, a requirement
labelled with its event, as the endpoint mapper connection carries the dynamic port that must
follow it. A `sequence` or `correlation` is several events by
its shape, so label its markers whenever they are not all on one event.

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

Emits the structured object a rule-authoring skill consumes, including what became
of every marker (`marker_bindings`). Without `--json` it prints an XQL skeleton for
eyeball inspection -- deliberately incomplete, with dataset selection and every
`<bound>` left to the author, but never wrong: a condition it cannot write as a field
test is printed as a `REQUIRES` or `UNBOUND` comment, each header says whether the
filter is `complete`, `partial` or `none`, and the caveat is always printed.
`references/emit-xql.md` has the whole contract.

`validate.py` reports marker coverage on every run, separately for all how-blocks
and for `alert`-fidelity ones. Alert-fidelity blocks are the ones that become
rules, so that second figure is the one that matters. A block with no markers and
no `inventory`/`absence` shape is reported as a gap.

## Bulk-generated exposure records

699 of the exposure records are generated from the CISA Known Exploited
Vulnerabilities catalogue, one per vendor/product pair. They are distinguishable
by the `exp-kev-` id prefix, `where.source_type: database`, and the
`known-exploited-catalogue` tag. A product the catalogue files under two strings, such
as "Kernel" and "Android Kernel" or a former owner's name, is one record: the generator
maps the second string onto the first and refuses a run that would split a product again.

Three more families are generated the same way and carry no detection logic either:
`exp-zdi-` from the Zero Day Initiative's published advisories, `exp-psirt-` from vendor
security advisory feeds, and `exp-nvd-` from the vulnerability database. Each carries
`not-in-kev` or `in-kev`, and its summary says the same, checked against the KEV
snapshot of the same pass, so a catalogue refresh means regenerating all four families.
`validate.py` refuses a record tagged `not-in-kev` that carries an identifier a
`known-exploited-catalogue` record holds. A ZDI advisory with no CVE is carried by its
programme identifier, such as `ZDI-26-226`, so the advisory count in the summary
reconciles with the identifiers the record lists.

They exist for **findability**, not analysis. A generated record asserts only that
the named identifiers were exploited; it carries no `how` block and therefore no
markers, because the catalogue contains no detection logic. Where an identifier is
also covered by a hand-written observation, the generated record says so and names the
observation, whose detection logic is written for the incident it describes and not
necessarily for this product. A KEV record describes each identifier it carries in the
catalogue's own words, newest first, up to six, and says how many more it leaves to the
catalogue. A PSIRT record carries an advisory only for a product the vendor's own status
or version table marks affected, or, where the table has no row for it, one the summary
names as the vulnerable product; a product mentioned as the attacker's device, or whose
every row reads "None" or "Not affected", is not attributed the advisory. Its summary
names every advisory it counts by the vendor's identifier, and it is dated by the newest
advisory where the vendor's feed or page dates each one.

Three things about them are derived rather than sourced, and all three are stated in
the record itself: `who.product_class`, mapped from the vendor and product names;
`what.impact`, mapped from the catalogue's vulnerability name and description text; and
`what.attack_surface`, mapped from the derived class, the catalogue having no
attack-surface field of its own. Nothing else is inferred. The other three families take
the same class-to-surface table, except that a ZDI record whose advisories mostly need
local access first carries `credentialed_user`, and one needing physical presence
`physical_or_console`, because ZDI states the attacker's position and the class default
would overstate it. Because the surface restates the class, the locus ladder does not
read it on any of the four families and places them by class; see "Where a record sits".

Do not add markers to these records. If a product needs detection logic, write an
observation for it from a source that actually describes the behaviour.

## xql_sketch on patterns

A pattern may carry `xql_sketch`, one line showing the shape of the query it implies: what is
counted, what is joined against which inventory or baseline, what is excluded. It is
pseudo-code, not XQL and not the skeleton: placeholders in angle brackets, a vendor's own
columns beside modelled fields, schematic operators. No script reads it; `emit_xql.py` prints
the skeleton from the markers. A sketch whose leading pipeline reads only `xdm.*` fields opens
on `datamodel dataset`; one that reads a vendor's columns opens on the raw stage that carries
them, and its `xdm.*` references are the half a modelling rule supplies.

`validate.py` holds a sketch to the rules the skeleton was fixed for, because a reader copies
it: no `bin()` call, since `bin` is a stage; every `xdm.*` field in the XDM schema
(`schema/xdm-fields.json`, `schema_field_names`); no string test on `xdm.event.operation`, the
OPERATION_TYPE enum; no constant compared to `xdm.event.outcome`; no bare number compared to
`xdm.event.id`, a String; and every constant a member of a group the snapshot holds.

## external_corroboration on patterns

Most patterns carry an `external_corroboration` block counting the distinct SigmaHQ
and Splunk security_content rules that tag at least one technique the pattern cites,
with the licence of each library that contributed. A rule tagging two of a pattern's
techniques counts once. Rules their own library has deprecated are not counted. It is
regenerated on the maintainer side when either rule corpus is re-indexed, and reaches a
rule author through the handoff.

It is evidence that a detection scenario has been implemented against real
telemetry by other people. It is **not** a quality score, and a pattern without it
is not weaker. 31 of the 475 patterns have none, and 22 of the 31 apply to an
`ot.*` class, because the public rule corpora barely cover operational technology.
For those the corpus is often the only written source, which is a reason to
scrutinise them harder before shipping, not a reason to discount them.

Counts are joined on technique, not on detection shape, so a large count says many
rules watch the technique, not that they implement this pattern's logic. A rule still
tagging an id ATT&CK has revoked is counted for its replacement, because the corpus
cites the replacement. D3FEND 1.6.0 maps some revoked ids and not their replacements,
and its countermeasures are joined the same way: the harvest gives a replacement with no
mapping of its own the lists of the ids it replaced, and names them in `by_attack_via`.
Each list holds the controls D3FEND states and those it infers through a class above or
below them; `by_attack_inferred` marks the inferred ones, and a consultation shows the
stated ones first within each tactic. `host_wide` names the controls D3FEND defines as
acting on the whole host (Host Reboot, Host Shutdown), which map to a process-level technique
through the same relation as Process Termination; they sort after the controls acting on the
artefact, so the eviction advice for LSASS dumping is the process, not a reboot that loses the
memory a responder collects first.
`tests/test_external_corroboration.py` fails when a block disagrees with its pattern,
which is how a missed regeneration shows up. The block was
last regenerated at 0.42.0, against Splunk security_content v6.7.0 and the SigmaHQ
index already held. Before that it had not been run since 2026-07-31, so every
pattern added after that date carried none and read as uncorroborated.

## Library patterns

A pattern normally reaches a consumer through a record that cites it. 34 patterns
are cited by no record, and each says in `derived_from` where it came from: 25 from
the public rule corpora (Sigma and Splunk), 3 from MITRE ATT&CK, 3
from CISA malware analysis reports, 1 from MITRE FiGHT, and 2 record none. Writing an
observation to carry them would mean inventing a source, so they stay uncited. One
of the two with none, `pat-lnk-pointing-to-user-writable-path`, lost its only
citation in 0.43.0, when the block citing it turned out to describe a different
mechanism; it carries markers taken from its own sketch so the library block can
still reach it. A consultation's `LIBRARY_MATCH` and `query.py`'s library listing
quote `derived_from` as written: they said every one was "derived from technique
space rather than from an incident", which the three drawn from CISA's analysis of
recovered malware are not; one of them names a single vendor's appliance paths.

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

An alias that is also an ordinary word needs a gate as well as an entry: a false
class sets the plane the whole answer is about. `ambiguous_aliases`,
`ambiguous_vendor_aliases` and `ambiguous_class_aliases` hold the gates, each entry
with its reason, and `_gate_comment` in the file says how each is read. A new
single-word product alias that is a dictionary word fails the tests until it is
either gated or listed in `_ambiguous_reviewed_keep` with a reason.
`references/resolution.md` has the rules and what each one fixed.
