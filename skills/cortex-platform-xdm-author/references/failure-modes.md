<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Failure modes -- if you see this, stop and do that

Empirical failure modes observed when drafting Cortex XSIAM XQL data model rules. Each entry pairs a recognisable symptom in the draft with the specific recovery action that restores forward progress. Read this if a draft is taking a long time to converge or you notice yourself doing one of the things below.

The single biggest principle behind every entry: producing the rule takes priority over re-verifying the rule. Cortex parser feedback is ground truth. Self-doubt loops cost time and produce worse output than "emit, lint, fix earliest, re-lint".

## 1. Schema-enumeration drift ("Not available" rumination)

You start writing lines that look like:

```
xdm.alert.foo -- Not available in this vendor's log
xdm.alert.bar -- Not available
xdm.alert.baz -- Not in sample
```

This happens when you walk the XDM schema field by field and note non-matches. The XDM schema has 628 fields. Even walking the top-level alert categories produces dozens of "Not available" lines, none of which add information. The downstream rule never references any of these fields, so the enumeration is pure latency.

Recovery: stop the enumeration mid-sentence. Switch to a positive-only strategy: list only the vendor fields that DO have an XDM target. Anything not listed is implicitly unmapped. Document genuine notable omissions (a field a reviewer would expect to see mapped) in the NOT MAPPED block of the MAPPED-header, capped at about 5 to 10 entries with a one-line reason each.

## 2. "Final check" loop after the rule is written

The rule body is complete; you have already emitted the last `;`. Then:

```
Final check on xdm.event.id -- yes, mapped from event_id OK
Final check on xdm.event.type -- yes, set to "ALERT" OK
Final check on xdm.source.ipv4 -- yes, from client.ip OK
...
```

This is re-verifying every field after writing the rule. The bundled linter (`scripts/lint_rule.py`) checks the syntactic parser-conformance rules deterministically in a fraction of a second. Manual re-walking adds nothing the linter does not catch.

Recovery: stop after the semicolon. Hand the rule to the linter. If it reports nothing, the rule is done. If it reports a violation, fix that one violation (earliest-first per INFO-012) and re-run. Do not do a manual schema sweep.

## 3. Vendor-name leakage from in-training exemplars

The user's log sample is from "VendorX", but your draft contains field names like `imperva`, `accesslogs`, `risk_event_name`, `participants`, or `categories` that are not in the user's sample. The reference docs include exemplars from real vendor packs (Imperva, Cisco WSA, ExtraHop RevealX, etc.) and those field names can echo into unrelated outputs.

This is pattern-matching against exemplars in the reference markdown without checking that the field names actually exist in the user's input.

Recovery: cross-check every `tmp_temp` variable and JSON path in your draft against the user's sample. If a field is not in the sample, delete the reference. Use the exemplars in [extraction-patterns.md](extraction-patterns.md) for the shape of the extraction, not as a copy-paste source.

## 4. Analysis-paragraph restatement

Your thinking output contains paragraphs that begin with phrases like:

- "So as established above..."
- "As we noted earlier, the log contains..."
- "Recall that the vendor field is..."
- "To recap the mappings so far..."

This restates conclusions you already reached. Each restatement uses output tokens that could have written the rule itself. In offline thinking-mode this manifested as multi-hour runs that never produced a rule. In agent emission it manifests as walls of narration the user has to skim past.

Recovery: stop the paragraph mid-sentence. The previous statement of the conclusion stands. Move directly to the next concrete action (extraction line, mapping line, linter invocation).

## 5. Verbatim copying from reference exemplars

Your draft includes a code block that matches a snippet in `references/extraction-patterns.md` (or another reference) word for word, including vendor names that are not in the user's sample (e.g. `imperva`, `participants`, `categories`).

The exemplars in the reference files are illustrative shapes. Copying verbatim transplants the wrong vendor's field names into the user's rule. The reference itself says so: "don't copy verbatim into your own rule; reconstruct against your vendor's log shape".

Recovery: treat exemplars as schema-of-the-pattern, not as content. Pull only the shape (the function-call structure, the multi-stage layout, the wrap / cast order) and substitute the user's actual vendor field names.

## 6. Inventing XDM_CONST values

Your draft contains constants like `XDM_CONST.THREAT_CATEGORY_SECURITY`, `XDM_CONST.CLOUD_PROVIDER_ORACLE`, `XDM_CONST.OS_FAMILY_BSD`, or `XDM_CONST.MITRE_TECHNIQUE_*` for vendor labels that do not map deterministically to one of the documented constants.

Speculative constants cause hard validation errors in the Cortex IDE. The constant groups are closed lists ([references/xdm-const.md](xdm-const.md)); appending a plausible-sounding suffix does not make a real constant.

Recovery: if no documented constant matches, OMIT the XDM_CONST field entirely (or use the String fallback documented in [pitfall-traps.md](pitfall-traps.md)). MITRE in particular: only map `xdm.alert.mitre_techniques` / `mitre_tactics` when the vendor provides explicit MITRE labels (`technique_id`, `attack_id`, similar); vendor "attack pattern" or "category" text does NOT justify inventing MITRE constants.

## 7. Raw numeric score assigned to xdm.alert.severity

A line like:

```
xdm.alert.severity = to_string(risk_score)
xdm.alert.severity = severity
```

where `risk_score` or `severity` is a numeric scale (0-100, 0-10, 1-5).

`xdm.alert.severity` is a categorical String field expecting `"Critical"` / `"High"` / `"Medium"` / `"Low"`. A stringified number is a silent regression the linter does not catch -- downstream queries that filter by severity will not match. The bug only surfaces in production.

Recovery: apply Section "Banded numeric scoring" from [transformation-patterns.md](transformation-patterns.md): an if-chain mapping thresholds to the four band strings, plus a parallel `XDM_CONST.LOG_LEVEL_*` if-chain for `xdm.event.log_level`. Any vendor field name containing `score` (and any numeric 0-100 / 0-10 / 1-5 scale) MUST be banded -- never passed through.

## 8. Pre-flight rumination instead of producing

Many output tokens spent on:

- "Let me first list every XDM field that could potentially apply..."
- "Before drafting, I should walk through all 78 validation rules..."
- "Let me consider each of the four extraction patterns A / B / C / D and decide which applies, including reasoning about why the others don't..."

This is pre-flight that takes longer than producing the rule. The skill's workflow ([workflow.md](workflow.md)) prescribes a tight 9-step sequence; deviating into deep contemplation costs tokens and rarely changes the answer.

Recovery: follow the workflow steps in order without expanding them. If a step's decision is unclear, write the most likely answer and let the linter flag any issue -- that round-trip is much faster than internal debate.

## 9. Re-drafting whole rules instead of fixing earliest violation

After the linter reports two or more violations, you discard the draft and start over with a fresh `[MODEL: ...]` block.

Cortex parser errors cascade. The second and later violations are usually downstream noise from the first one (INFO-012, see [parser-idioms.md](parser-idioms.md) for the cascade suppression behaviour). Rewriting from scratch loses every line that was correct.

Recovery: fix the EARLIEST reported violation only, re-run the linter, then assess. Most cascades resolve on the first fix. Repeat. Do not regenerate the whole rule.

## 10. Anchor-lookup miss read as "no XDM field"

`lookup_anchor.py <field>` returns zero candidates and you write something like:

```
mfa_method -- no xdm.auth.mfa.* path exists; folded into description
```

The anchor index is a PRECEDENT table -- it records what past rules happened to map, nothing more. A zero result means no precedent, not no field. The schema is [xdm-schema.md](xdm-schema.md), and it is much wider than the index. `mfa_method` is the canonical example: the lookup historically returned zero candidates, yet `xdm.auth.mfa.method` sits in the schema -- the false "no path exists" claim buried a queryable value in the description.

Recovery: before declaring a field unmapped, grep [xdm-schema.md](xdm-schema.md) for the concept (`auth`, `mfa`, `host`, `process`, `registry`, ...). Map to the schema field directly when one exists, even with zero anchor precedent. Only write NOT MAPPED when the schema genuinely has no field for the concept.

## 11. Risk signal thrown away as "no home"

You drop a numeric ratio / deviation / anomaly metric (e.g. `metrics.baseline_deviation`) and justify it as "no XDM home for that value". A ratio with no typed numeric field still fits `xdm.alert.risks` (a free-text sink, typed String (Array)), so "no home" is false and a real risk signal is lost.

Recovery: park the metric in `xdm.alert.risks` alongside `risk_score`, wrapped with `arraycreate()` because the field is array-typed (see [transformation-patterns.md](transformation-patterns.md) "Risk and deviation metrics"). If you genuinely choose to drop it, record it in NOT MAPPED as "intentionally omitted" with a reason, not "no home".

## 12. Whole payload dumped into the description

You assign the entire ingested log to the issue description, e.g.

```
xdm.event.description = _raw_log
xdm.event.description = to_json_string(detail)
```

This looks like "nothing is lost" but it is the opposite of useful: every value is buried in one free-text blob where structured queries, correlation, and dashboards cannot reach it. The description is the analyst's one-line summary, not a payload archive.

Recovery: build `xdm.event.description` with `concat()` over the handful of identifying fields (vendor, action, subject, outcome), and map every other field to its own structured XDM home. Never put `_raw_log` or `to_json_string(...)` in the description. The linter flags this as WARN-039.

## Quick scan -- what each symptom tells you

| Symptom in your draft | Failure mode | Action |
| --- | --- | --- |
| `"Not available"` appearing as a line | #1 schema enumeration | Drop the line; switch to positive-only |
| "Final check on..." after the `;` | #2 final-check loop | Stop; hand to linter |
| Vendor field names not in the user sample | #3 leakage | Cross-check vs sample; delete |
| "As established earlier..." paragraph | #4 restatement | Stop mid-sentence; move on |
| Code block matching a reference exemplar verbatim | #5 verbatim copy | Reconstruct against the user's fields |
| `XDM_CONST.X` not in `xdm-const.md` | #6 invented constant | OMIT or String fallback |
| `xdm.alert.severity = <numeric>` | #7 raw score | Apply banded scoring |
| Long pre-flight prose, no `[MODEL:` yet | #8 rumination | Start writing the rule |
| Discarding the draft after linter output | #9 re-drafting | Fix earliest violation only |
| "no xdm.* path exists" after a zero anchor result | #10 anchor miss | Grep xdm-schema.md for the concept first |
| ratio / deviation dropped as "no home" | #11 risk signal lost | Park it in xdm.alert.risks |
| `xdm.event.description = _raw_log` / `to_json_string(...)` | #12 payload dump | Build a concat() summary; map fields to homes |
