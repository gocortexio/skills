---
name: cortex-platform-xdm-author
description: Author Cortex XSIAM Data Model Rules in Cortex Query Language (XQL). Turns a raw vendor log sample into a production-ready rule with a MAPPED-header comment block.
version: 2.15.0
license: AGPL-3.0-or-later
---

<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# cortex-platform-xdm-author

Author Cortex XSIAM data model rules in Cortex Query Language (XQL) from raw vendor log samples.

The current version is 2.15.0; the per-version change history lives in [CHANGELOG.md](CHANGELOG.md).

On top of base rule authoring, the skill auto-detects the source kind and applies the matching mapping set, each backed by a linter check. The table is the index; the detail lives in the reference, which is where to read before mapping that kind. Anything in the Hard rules or the Mapping decision checklist below applies whether or not you load a reference.

| Capability | Applies to | Lint codes | Reference |
| --- | --- | --- | --- |
| Record classification and catch-all | every rule -- `xdm.event.type` / `xdm.event.tags` decided per record; six markers are closed `EVENT_TAG` constants and virtualization is the bare string `"VIRTUALIZATION"`, unclassified records kept via the `GOCORTEX_UNMODELLED` sentinel so datamodel rows equal raw rows | WARN-045, WARN-046 | [record-classification.md](references/record-classification.md) |
| Syslog Stage 0 envelope | any syslog source -- relay-aware host capture and priority decode, modelling direct and relay-prepended arrival in ONE rule | WARN-040, WARN-041, ERR-030 | [syslog-envelope.md](references/syslog-envelope.md) |
| Authentication story | login / logon / MFA / SSO -- the mandatory field set, the `xdm.auth.service` role vocabulary, the never-padded target, and the recommended identity mirror | WARN-042, WARN-055, WARN-057 | [authentication-mapping.md](references/authentication-mapping.md) |
| Network / firewall story | firewall, flow, proxy, IDS/IPS and DNS traffic; the foundational layer, so a dual event takes this set as well as its own | WARN-043 | [network-mapping.md](references/network-mapping.md) |
| Endpoint telemetry | process / file / registry / image events on the channel/verb model, over the 56-member `OPERATION_TYPE` enum | WARN-050 | [process-mapping.md](references/process-mapping.md) |
| Process / command execution | EDR process starts, script runs, and AAA command accounting, which is a command execution and not authentication | WARN-044 | [process-mapping.md](references/process-mapping.md) |
| Cloud audit story | AWS CloudTrail, Azure Activity / Entra sign-in, GCP Cloud Audit -- verb derived from the provider's action-naming convention | ERR-029 | [cloud-mapping.md](references/cloud-mapping.md) |
| MITRE ATT&CK arrays | any source carrying technique or tactic identifiers or names | -- | [mitre-mapping.md](references/mitre-mapping.md) |
| Install-blocking constructs | every rule -- constructs the platform rejects with an opaque 101704 naming no field and no line | ERR-031, ERR-032, ERR-033, ERR-034 | [install-blockers.md](references/install-blockers.md) |
| Cisco IOS / IOS-XE / WLC families | Cisco syslog, where the SUBFACILITY is optional and a card-prefixed line wraps a second complete token | -- | [extraction-recipes.md](references/extraction-recipes.md) |

Extraction is aided by the verified recipes in [references/extraction-recipes.md](references/extraction-recipes.md) and by a field-anchor index that resolves raw vendor field names to their XDM location. The scripts validate rules instead of relying on a mental checklist.

## Announcing, and stopping loudly

Print a STAGE banner on entering every stage of this skill's own workflow, and NEVER ask the
caller a question outside a `!` or `?` banner. A question in a paragraph is how a run sits idle
while everyone waits for the other one; a stage nobody announced is a stage nobody can see you
are in.

COPY the templates from [references/console-output.md](references/console-output.md), at the
boundary, and never render one from memory -- a typed banner loses the squirrel first, then the
rules, then the named sections. That page is identical in every bundle in this project and carries
the three fills, the art and the rules for each. The banner is the FIRST thing in the reply that
enters a stage, and the LAST thing in a reply that stops.

## Scope

In scope: Data Model Rules (`[MODEL: dataset=..._raw]`).

Out of scope:

- Parsing rules (`[INGEST: ...]`). The references mention them only in validation rules ERR-001 / 002 / 003 / 005 and in the MAPPED-header instruction.
- Reading parser-stamped underscore anchor columns. A MODEL rule must derive every value from the raw dataset columns (or `_raw_log`), never by coalescing a parser-only `_` anchor. Cortex validates a MODEL rule statically against the dataset schema, where parser-only `_` anchors do not exist, so reading one is rejected as an unknown field before any `coalesce()` fallback can run (see ERR-027). Re-derive from raw instead.

The field-anchor synonym index is in scope as a static lookup table. The bundle ships a CLI to query it.

## Called as an instrument

This bundle is usually invoked on its own, but it is also called as an INSTRUMENT by `cortex-content-pack-go-again`, which owns the pack-building process and dispatches the rule-authoring work here. Four standing commitments to that caller live in this section, because a promise stored only in the bundle that RECEIVES it is a promise the next session here cannot keep.

The rule-versus-files line. A pack install rejected with an opaque 101704 names no field and no line, so the cause has to be bisected. Causes reachable from the RULE TEXT are this bundle's, and ERR-029 through ERR-034 all arrived exactly that way: a 101704 that bisects to a construct inside the rule belongs HERE and becomes a lint code, which is a standing offer and not a case-by-case favour. Causes that need the pack's FILES are not -- "if the minimal block also fails, stop bisecting content and bisect FILES" is a statement about pack STRUCTURE, and the case that produced it was a missing `_schema.json`, a file this bundle never sees and has no vocabulary for. That half stays with the caller, and the ordered bisect procedure with it.

The ERR-034 reserved set is MIRRORED, so a change to it must be announced. `_ERR034_RESERVED` in `scripts/lint_rule.py` is copied by hand into `RESERVED_COLUMNS` in the pack-building harness's release gate, which gates the same fault at upload time. Deciding that a further name is reserved, or retiring one, is therefore not a local edit: message that bundle in the same change, because nothing in either repository can see the other and each side has already believed itself current while holding a list one word behind. `tests/test_lint_rule.py` pins the set at its current membership and its failure message says who to tell -- and it works: the pin is what routed the 2.1.3 `config` report to both bundles rather than one. A second test compares the `--list-codes` name list to the same tuple, that being a further copy which had been a name behind since 1.9.1 with nothing to notice.

EVERY RELEASE MUST DECLARE ITS FIELD IMPACT, because a consumer measures against it. `assets/field_impact.json` answers "did version X change the MEANING of field F" per version, and phase 900 of the content-pack bundle reads it as a precondition: a migration that measures a SECOND field against the still-installed old model is only valid if this bundle did not move that field underneath it. Adding a version to `CHANGELOG.md` without an entry here FAILS the suite, deliberately, because absence in the registry reads as "no impact" and a missing entry is therefore a false negative rather than a gap. Classify every `xdm.` path the entry names into exactly one of `meaning_changed`, `mandatory_changed`, `banned` or `mentioned_only` -- and `mentioned_only` needs a NOTE saying why there is no impact, since a version can discuss a field at length without moving it. Query it with `scripts/field_impact.py`; do not hand-read the JSON for a range, because entries are per-version deltas and the union is the answer.

Replying to that caller. It asks for FOUR verdicts per item -- COVERED (with a `file:line` it can open, never a bare "we do that"), TAKING IT (with where it will live), DECLINED (with the reason, which it records verbatim and never re-sends), and CORRECTED (the right rule, when the premise of the question is wrong). Send ONE reply through the channel it asked on rather than a trickle across several, state the version of this bundle you are replying at, and say so in the same reply if you edited a file of theirs. Silence is not a decline there: an unanswered item stays open indefinitely.

## Inputs accepted

1. Required: at least one raw log sample (JSONL, plain JSON, syslog text, CEF -- anything Cortex XSIAM ingests as `_raw_log`). If no sample is supplied, ask for one. Do NOT guess vendor field names.
2. Optional: vendor / product / dataset name. These cannot be derived from the log body; infer them from the product or API title, then flag them as tenant-adjustable in the MAPPED header, naming the three touch-points the reviewer edits: `xdm.observer.vendor`, `xdm.observer.product`, and the `[MODEL: dataset=...]` header.
3. Optional but recommended: a source reference document that describes the fields -- an OpenAPI / JSON Schema spec or API field docs for a JSON / JSONL source, a message / mnemonic reference for a syslog source, a CEF / LEEF extension dictionary, or a column dictionary for CSV / TSV. A sample alone shows the shape but not the meaning: the reference resolves cryptic field names, authoritative datatypes (array vs scalar -- the class of the `xdm.alert.risks` "expected array" defect), enum values (for `XDM_CONST` mapping) and which fields carry the identity / auth story. The skill ASKS for the format-matched reference after profiling (workflow step 3) and proceeds without it when unavailable, recording the basis in provenance (`GOCORTEX_SKILLS_SOURCE_BASIS`). Accept a link (fetch and mine it), pasted text, or a file path.

## Outputs produced

One XQL file (or one code block if inline). The top comment block MUST follow this fixed order for predictability -- SPDX licence always first, the skill-issues pointer always last:

1. SPDX licence header (`SPDX-FileCopyrightText` + `SPDX-License-Identifier`) -- ALWAYS the first lines.
2. Provenance block (`GOCORTEX_SKILLS_*`).
3. Identity: vendor / product / dataset / one-paragraph description.
4. ALERT / EVENT FIELD MAPPING (`->` arrows) + any advisory NOTES + NOT MAPPED list with reasons.
5. REVIEW UNMODELLED query.
6. RAISE SKILL ISSUES pointer.

Then the `[MODEL: ...]` body. The sections in detail:

- A MAPPED-header comment block (mandatory). Vendor / product / dataset / one-paragraph description / Alert-or-Event Field Mapping with `->` arrows / NOT MAPPED list with reasons. The SPDX licence sits at the very TOP of this block (never at the bottom). See [assets/modeling_header_template.xql](assets/modeling_header_template.xql).
- A provenance block (mandatory), emitted verbatim as comment lines directly under the SPDX header so a script can grep it. Fill `GOCORTEX_SKILLS_MODEL` with the model id that authored the rule, `GOCORTEX_SKILLS_SKILL_NAME` / `GOCORTEX_SKILLS_SKILL_VERSION` from this skill's frontmatter (`cortex-platform-xdm-author` / `2.15.0`), `GOCORTEX_SKILLS_SKILL_WARNING_COUNT` with the advisory count from the final `scripts/lint_rule.py` run, and `GOCORTEX_SKILLS_SOURCE_BASIS` with `"spec-backed"` when a source reference (OpenAPI spec, vendor mnemonic doc, ...) informed the mapping or `"sample-only"` when only the raw sample was available (see workflow step 3):
  ```
  // Generated via
  // GOCORTEX_SKILLS_MODEL="<model id>"
  // GOCORTEX_SKILLS_SKILL_NAME="cortex-platform-xdm-author"
  // GOCORTEX_SKILLS_SKILL_VERSION="2.15.0"
  // GOCORTEX_SKILLS_SKILL_WARNING_COUNT="<lint warning count>"
  // GOCORTEX_SKILLS_SOURCE_BASIS="<spec-backed | sample-only>"
  ```
  `scripts/scaffold_rule.py` emits this automatically (name / version from SKILL.md, model and count from the build environment or its self-lint); when hand-authoring, add it yourself.
- The commented REVIEW UNMODELLED query (mandatory), placed as the second-to-last section, so unclassified records are discoverable -- see [references/record-classification.md](references/record-classification.md).
- A RAISE SKILL ISSUES pointer (mandatory), the LAST comment section, inviting the user to report a mis-mapping and include the REVIEW UNMODELLED output:
  ```
  // RAISE SKILL ISSUES -- if this rule mis-modelled something, please open
  // an issue and include the REVIEW UNMODELLED output above:
  //   https://github.com/gocortexio/skills/issues
  ```
- A `[MODEL: dataset=<vendor>_<product>_raw]` block in the three-stage shape: `filter` -> `alter` (extract) -> `alter` (assign).

## Authoring workflow

Thirteen steps, in full in [references/workflow.md](references/workflow.md), which is the authority on each. The spine:

1. Confirm sample present. If not, ask for one. A sample pulled from a live dataset must be STRATIFIED -- a `limit N` pull is not a sample.
2. Profile it: `python3 scripts/profile_log.py "<path/to/sample>"`. Detects format, walks leaf paths, infers types, computes null rates, flags object-array discriminators, ranks XDM candidates, and proposes a `recommended_pattern`.
3. Ask once for the format-matched source reference (soft gate). Proceed either way, and record which in `GOCORTEX_SKILLS_SOURCE_BASIS` -- `"spec-backed"` or `"sample-only"`.
4. Pick the extraction pattern, confirming the profiler's proposal against [references/extraction-patterns.md](references/extraction-patterns.md). A `<NNN>` priority token means the Stage 0 envelope is parsed first.
5. Look up XDM targets: `python3 scripts/lookup_anchor.py <vendor_field_name>`. A `0` result means no PRECEDENT, not "no XDM home" -- grep [references/xdm-schema.md](references/xdm-schema.md) before writing anything to NOT MAPPED.
6. Cross-reference types against [references/xdm-schema.md](references/xdm-schema.md) and apply [references/transformation-patterns.md](references/transformation-patterns.md). Where the profiler flags a story, apply that story's mapping set from the capability table above. Classification is PER RECORD throughout.
7. Draft the rule. Three stages minimum: `filter` (null guard), `alter` (extract `tmp_` temps), `alter` (assign XDM). Semicolon at the end, no trailing comma, MAPPED header on the front.
8. Lint: `python3 scripts/lint_rule.py <rule.xql>`.
9. Fix earliest-first -- the earliest violation is almost always the root cause and the rest are cascade noise (INFO-012).
10. Re-lint until clean.
11. For a SYSLOG source, prove both arrival forms: `python3 scripts/verify_rule.py <rule.xql> <sample> --prepend-check`. Mandatory, because static lint cannot establish prepend-robustness.
12. If this rule REPLACES an existing one, diff the emitted `xdm.*` field set against the old one. A dropped field makes any correlation that reads it structurally incapable of firing, and nothing detects that.
13. Emit the final output.

## Note on intermediate variables

Scratch temporaries use the `tmp_` prefix (`tmp_user`, `tmp_src_ip`, ...). The `_` prefix is reserved by the platform for internal / system-generated fields (`_raw_log`, `_time`, `_message`, ...), so a rule must never CREATE a `_`-prefixed field -- `lint_rule.py` raises ERR-028 if it does (reading `_raw_log` is fine). No explicit `| fields -...` cleanup stage is needed: a MODEL rule surfaces only `xdm.*` fields, so `tmp_` temporaries never reach the datamodel regardless of name; the linter therefore does NOT flag a missing cleanup stage (INFO-006). See [references/extraction-patterns.md](references/extraction-patterns.md) "A note on intermediate variables".

## Output discipline

XQL is a formal language, not a creative-writing surface. Emission discipline matters as much as content correctness:

- Emit the rule, not narration about emitting the rule. No "I'll now draft the rule that...", no "Here is the rule:". The MAPPED header is the documentation; the rule body is the answer.
- Determinism over variety. Two runs against the same log sample should produce the same rule. Pick the highest-frequency XDM target from the field-anchor index (workflow step 4) rather than rotating through alternatives.
- One draft, then lint, then fix-earliest-first. Do not draft three variants and pick one. Draft once, run `scripts/lint_rule.py`, fix the earliest violation, re-lint. See workflow steps 6-9.
- No re-verification loops. Trust the linter. If it reports nothing, the rule is done. If it reports something, fix that one thing.
- No "Not available" enumeration. A vendor field with no XDM home (confirmed against [references/xdm-schema.md](references/xdm-schema.md), not just a zero anchor result) goes in the NOT MAPPED block with a one-line reason. It does NOT generate a list of XDM fields considered and rejected.
- Stop when done. No "let me also check...", no postscript on future improvements. The rule plus its MAPPED header is the deliverable.

These rules exist because the Cortex parser is the ground truth. A rule that reads beautifully but the parser rejects is worse than a rule that reads tersely but the parser accepts.

## Hard rules (do not violate)

**The full set is [references/hard-rules.md](references/hard-rules.md). Read it before
authoring.** These four are cheap to state and expensive to miss, so they stay here:

- Claim a story only where its mandatory set can be populated. A story tag is a promise that the story's fields mean something on that record, and downstream content queries them as though populated. Before tagging AUTHENTICATION, confirm the record can supply an actor (`xdm.source.user.username` / `upn`); before tagging NETWORK, confirm it can supply a peer (`xdm.source.ipv4`). Two records from one subsystem can differ -- an interface transition has no peer and is a device status change, not a flow. When a record cannot fill a story, give it an honest `xdm.event.type` (`system`, `status`, the subsystem name) plus a descriptive `xdm.event.description`. This is the class of error the linter cannot see: every mandatory field assigned, a clean lint, and the rule still wrong about what the record IS. Never gate `xdm.event.type`, `xdm.event.tags` or any mandatory story field on a facility or subsystem flag -- a facility names the subsystem that spoke, only the mnemonic says what happened -- and never end an `xdm.event.operation` chain on a broad subsystem flag; if nothing specific matches, leave the verb unset. See [references/record-classification.md](references/record-classification.md).
- Never invent XDM field paths. Every `xdm.*` path must appear in [references/xdm-schema.md](references/xdm-schema.md). If a vendor field has no XDM home, document it in the NOT MAPPED block -- but only after confirming the schema genuinely lacks a field for the concept. A zero anchor-index result is not that confirmation.
- Never assign a banned XDM field. A banned field is a REAL Cortex path belonging to an internal or non-event data model (for example `xdm.*.cloud.source_type`, an XCloud asset attribute), so assigning it fails tenant validation with "not part of the selected data model" even though the path looks legitimate. Registry: [assets/banned_fields.json](assets/banned_fields.json), blocked as ERR-029. See [references/banned-fields.md](references/banned-fields.md).
- Never invent `XDM_CONST` values. Closed lists in [references/xdm-const.md](references/xdm-const.md). If no constant matches, OMIT the field and fall back to the String alternative per [references/pitfall-traps.md](references/pitfall-traps.md).


## Mapping decision checklist

Run this before emitting, so the same log maps the same way every time. Each item is a deterministic rule, not a judgement call:

- Outcome only on a real result. Set `xdm.event.outcome` only when the log reports success / failure / blocked. A detection disposition (`alert`, `monitor`, `isolate`) is NOT an outcome -- keep it in `xdm.observer.action`.
- Host + IP -> emit the address companion ONLY where both fields describe the SAME entity. When `xdm.<side>.host.hostname` and `xdm.<side>.ipv4` are both set AND name the same host, also set `xdm.<side>.host.ipv4_addresses = if(ip != null, arraycreate(ip), null)` (WARN-038, advisory). They often do NOT name the same host: on a flow-bearing record the hostname is routinely the device that EMITTED the log while the address is a flow endpoint, and hanging the flow address off the emitter yields a populated, non-sentinel and WRONG value that every host-based join would silently use. Name the entity each field describes before satisfying the advisory; where the premise is false, say so in the rule header and leave the array unset. See [references/pitfall-traps.md](references/pitfall-traps.md).
- Syslog source -> parse the envelope (Stage 0) before the payload, and make it prepend-robust (HARD RULE). The same source arrives direct and behind a relay that prepends its own `<PRI>` header, so capture the envelope relay-aware (greedy `^.*` to the origin host and origin PRI) and anchor every payload field on its own token, never on `^`. Extraction must be identical for both arrival forms even if the sample showed only one, in ONE rule -- never two rules and never only the observed form. Prove it with `scripts/verify_rule.py --prepend-check`; lint alone cannot establish it. Decode the priority into `xdm.event.log_level` / `xdm.alert.severity` as a fallback under the payload severity -- see [references/syslog-envelope.md](references/syslog-envelope.md) (WARN-040, WARN-041, ERR-030).
- Named asset is a host, cloud object is a resource -- EXCEPT on an authentication event. An OT / ICS asset (`asset=PLC-17`) or server name goes to `xdm.target.host.hostname`; a cloud resource goes to `xdm.target.resource.name`. On an authentication event `xdm.target.resource.name` is MANDATORY regardless of the target's kind: it names the device / application / service the principal authenticated TO, set IN ADDITION to the type-correct field and NEVER padded, because a padded target is how an inverted authentication rule passes the linter with every mandatory field assigned. WARN-055 flags a placeholder. House convention, recorded with its reason in [references/house-conventions.md](references/house-conventions.md).
- Numeric severity scale -> band both fields. Read the vendor band table, normalise labels to Critical / High / Medium / Low (vendor `Moderate` -> `Medium`), and emit both `xdm.alert.severity` and `xdm.event.log_level`.
- Risk / deviation metric -> `xdm.alert.risks`. A ratio or deviation with no typed numeric home is parked there, not dropped. The field is an ARRAY of String, so wrap the value with `arraycreate()` -- a bare `concat()` is the scalar-into-array shape WARN-035 catches. If you do drop it, write "intentionally omitted", never "no XDM home".
- Vendor / product / dataset are tenant-adjustable. Infer them, and flag the three touch-points (`xdm.observer.vendor`, `xdm.observer.product`, `[MODEL: dataset=...]`) in the MAPPED header.
- Never bury a value that has a structured home. The description summarises with `concat()` over the fields that matter; it never substitutes for a queryable field, and it NEVER receives the whole payload (`_raw_log` or `to_json_string(...)` -- WARN-039). See also WARN-038 / INFO-013 and [references/failure-modes.md](references/failure-modes.md).

## References (load on demand)

- [references/workflow.md](references/workflow.md) -- the thirteen steps in full
- [references/modeling-rules.md](references/modeling-rules.md) -- `[MODEL: ...]` structure and the manual validation checklist
- [references/xql-language.md](references/xql-language.md) -- rule structure, functions, operators
- [references/parser-idioms.md](references/parser-idioms.md) -- ERR-012 through ERR-019, INFO-012
- [references/install-blockers.md](references/install-blockers.md) -- ERR-030 through ERR-034: constructs the platform rejects with an opaque 101704
- [references/xdm-schema.md](references/xdm-schema.md) -- the 643-field XDM path list
- [references/xdm-const.md](references/xdm-const.md) -- the closed-list constants
- [references/banned-fields.md](references/banned-fields.md) -- real Cortex paths a MODEL rule must never assign, enforced by ERR-029 from [assets/banned_fields.json](assets/banned_fields.json)
- [references/extraction-patterns.md](references/extraction-patterns.md) -- the A / B / C / D extraction patterns
- [references/extraction-recipes.md](references/extraction-recipes.md) -- verified regex recipes for common syslog / text / CEF / LEEF shapes
- [references/syslog-envelope.md](references/syslog-envelope.md) -- Stage 0 transport layer: PRI-anchored host and priority decode
- [references/transformation-patterns.md](references/transformation-patterns.md) -- coercion, companion pairs, banded scoring, mirroring
- [references/authentication-mapping.md](references/authentication-mapping.md) -- the mandatory field set for authentication events
- [references/network-mapping.md](references/network-mapping.md) -- the mandatory field set for network events
- [references/process-mapping.md](references/process-mapping.md) -- the recommended mapping for process / command-execution events
- [references/virtualization-mapping.md](references/virtualization-mapping.md) -- the recommended mapping for the virtualization deviation story
- [references/record-classification.md](references/record-classification.md) -- per-record classification over the closed `EVENT_TAG` enum, and the catch-all that keeps row counts equal
- [references/cloud-mapping.md](references/cloud-mapping.md) -- AWS / Azure / GCP audit-log mapping and nested-JSON extraction
- [references/mitre-mapping.md](references/mitre-mapping.md) -- MITRE ATT&CK into the technique / tactic arrays, direct and fuzzy
- [references/house-conventions.md](references/house-conventions.md) -- the register of places this bundle requires MORE than the XDM schema does, each with the platform position, our reason, and what evidence would retire it
- [references/pitfall-traps.md](references/pitfall-traps.md) -- non-existent paths, confused pairs
- [references/compatibility-notes.md](references/compatibility-notes.md) -- `_gc_raw` caveats, deprecated fields
- [references/failure-modes.md](references/failure-modes.md) -- "if you see this in your draft, stop and do that"
- [references/worked-examples.md](references/worked-examples.md) -- index of sixteen end-to-end log-to-rule walkthroughs, each in its own file under [references/worked-examples/](references/worked-examples/) so you load only the pattern in front of you

## Scripts

Python 3.9+ stdlib only -- no Node, no `pip install`, no network. Run from the bundle root. Each takes `--help`; the flags are not restated here. The loop is profile -> scaffold -> lint -> verify.

- `profile_log.py <sample>` -- raw sample to a JSON worksheet: format, leaf paths, types, null rates, array discriminators, ranked XDM candidates, recommended pattern. Exit 0 ok, 1 argument error, 2 unreadable or unparseable input.
- `scaffold_rule.py <worksheet.json>` -- worksheet (or `-` for stdin) to a complete, lint-clean starter rule, self-gated through the linter and stamped with the `GOCORTEX_SKILLS_*` provenance block.
- `lookup_anchor.py <vendor_field>` -- ranked XDM targets from the anchor index; `--reverse` for the vendor synonyms behind a target, `--related` for companions.
- `xdm_const_mapper.py` -- the `if()`-chain mapping vendor values to a field's XDM_CONST members, or `--banded` severity / log-level chains for a score column. Never invents a constant.
- `mitre_map.py` -- MITRE technique / tactic IDs or names to `XDM_CONST.MITRE_*` and the `arraymap` chain. Unmapped inputs are reported, not invented.
- `http_status_map.py --render` -- the COMPLETE HTTP status chain for the const-typed `xdm.network.http.response_code`, so no partial hand-written set ships (WARN-048).
- `kerberos_map.py --render --group {encryption_type,error_code}` -- the complete Kerberos enum chains for the 4768 / 4769 const fields.
- `lint_rule.py <rule.xql>` -- the rule linter: structural and parser-conformance, schema-aware, and dataflow checks. Exit 0 clean, 1 on any error-severity finding; warnings and info never change the exit code. `--list-codes` prints the authoritative code list, which is deliberately not restated here because a copy of it goes stale silently, and this one did.
- `verify_rule.py <rule.xql> <sample>` -- evaluates the rule offline and prints the resulting `xdm.*` map per record. `--expect` diffs against expected output, `--prepend-check` proves both syslog arrival forms, `--coverage` flags a field that is predominantly empty, which is the signature of a capture that matches every record and captures nothing.
- `field_impact.py --field <xdm.path> --from <v> --to <v>` -- whether THIS bundle changed a field's meaning between two of its own releases, from `assets/field_impact.json`. Exit 0 safe to measure across the range, 1 the meaning moved, 2 the registry cannot answer. The range is a UNION of per-version deltas and `--from` is EXCLUSIVE, which is what a grep over one changelog entry gets wrong.
- `score_mappings.py --report` -- the author-curated mapping-accuracy corpus (`tests/corpus/mapping_matrix.json`) run through the worked-example rules, scored field-for-field. Ground truth is authored from provider docs and the XDM schema, so the score measures correctness, not agreement with any content pack.

A rule file may hold SEVERAL `[MODEL: ...]` blocks, one per dataset, which is the normal shape for a pack. Both `lint_rule.py` and `verify_rule.py` split such a file and analyse each block on its own, because every check reasons about a single rule. Lint findings carry their dataset; `verify_rule.py --dataset <name>` selects one.

If the scripts cannot run, treat the markdown as the authoritative checklist: walk [references/parser-idioms.md](references/parser-idioms.md), [references/modeling-rules.md](references/modeling-rules.md) and [references/pitfall-traps.md](references/pitfall-traps.md) before emitting.

## Bundle integrity tests

The bundle ships Python stdlib tests under [tests/](tests/). They cover JSON validity, SPDX-header presence, frontmatter shape, doc-to-schema consistency for every `xdm.*` and `XDM_CONST.*` cited in the references, ASCII-only and no-emphasis hygiene, the MAPPED-header template's required rows, and the linter's behaviour on a set of fixtures. Run from the bundle root:

```sh
python3 -m unittest discover -v -s tests
```

Python 3.9+ stdlib only. These tests cover the bundle itself. The path for linting user XQL rules is `python3 scripts/lint_rule.py`. See [tests/README.md](tests/README.md) for what each test guards.
