<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Authoring workflow -- full detail

This expands on the workflow in [../SKILL.md](../SKILL.md). Use SKILL.md as the quick reference and this file when you need the rationale or worked detail.

## Step 1 -- Confirm sample present

Without sample log data you will hallucinate field names. The hard rule: if the user has NOT provided sample log data, request it before generating a rule.

Ask for the sample in whatever form the user has -- JSONL, JSON, syslog, CEF. Vendor / product / dataset name can be inferred from the log and confirmed.

## Step 2 -- Analyse the raw log structure

The bundled profiler does this step deterministically. Run:

```sh
python3 scripts/profile_log.py "<path/to/sample>"
```

The script auto-detects the format (JSON, JSONL, CEF, LEEF, syslog 5424, syslog 3164, key=value, CSV, TSV), walks every record into leaf paths (with `[]` markers for arrays and named-key entries for `{name, value}` header-pair arrays), infers each field's type, computes a per-field null/absence rate across the sample, and lists each object-array's discriminator key (so a `transactions[]` with a `phase` of request vs response is flagged before mapping starts). Each discovered field carries the top ranked XDM candidate suggestions from the shipped anchor index.

Output is JSON on stdout by default; pass `--format text` for a human-readable table. See the worksheet shape in the script's docstring.

If `profile_log.py` cannot be run (no Python on the host, or the bundle has been installed into a sandbox without script execution), fall back to manual inspection. Examine the sample and identify:

- Format: JSON, syslog-wrapped positional, CSV, key-value pairs, or other.
- Top-level columns: fields already parsed by the XSIAM ingest pipeline.
- Nested fields: data inside JSON strings or `_raw_log`.
- `_raw_log` availability: some datasets have an empty `_raw_log` column. The parser extracts fields into top-level columns instead.
- Data types: strings vs numbers vs timestamps vs IPs.
- Event-type discrimination: does a single field split logs into different subtypes?

## Step 3 -- Gather the source reference (optional, skippable)

A sample shows the shape of a log, not the meaning of its fields. Once you
know `detected_format`, ask the user once for the matching reference and
proceed either way:

- JSON / JSONL -> the OpenAPI / JSON Schema spec or API field docs. This is
  the highest-value artifact: it gives field descriptions, authoritative
  datatypes (array vs scalar), enum values (for `XDM_CONST` mapping) and
  which fields carry the identity / auth story. A cryptic JSON key is a
  guess without it.
- syslog / positional -> the vendor message / mnemonic reference (decodes
  `%FAC-SEV-MNEMONIC`, positional fields, severity), and confirm whether
  the source can arrive relay-prepended (see [syslog-envelope.md](syslog-envelope.md)).
- CEF / LEEF -> the vendor's extension dictionary. CSV / TSV -> the column
  dictionary.

Given a link, fetch and mine it; given pasted text or a file, read it. If
none is available, proceed with the sample alone -- never block. Record the
basis in the provenance block: `GOCORTEX_SKILLS_SOURCE_BASIS = "spec-backed"`
when a reference informed the mapping, `"sample-only"` otherwise. A
sample-only rule is lower-confidence and worth closer review.

## Step 4 -- Choose the extraction strategy

Decision tree:

```
_raw_log contains valid JSON                          -> Pattern A
_raw_log empty, top-level columns are JSON strings    -> Pattern A (wrap with to_string)
_raw_log empty, fields are direct top-level columns   -> Pattern D
_raw_log contains syslog-wrapped positional data      -> Pattern B
data is in label / value array pairs                  -> Pattern C
```

Full pattern definitions and worked examples in [extraction-patterns.md](extraction-patterns.md). Critical: `json_extract_scalar` on a null `_raw_log` returns null for EVERY field. If `_raw_log` is null, use Pattern D.

For a syslog source (`_raw_log` opens with a `<NNN>` priority token, `detected_format` of `syslog-3164` or `syslog-5424`), insert Stage 0 before the payload parse: capture the host with the PRI-anchored RFC 3164 + 5424 coalesce, decode the priority into facility / severity, and seed `xdm.observer.name`, `xdm.event.log_level`, and `xdm.alert.severity` from it as a fallback. The idiom is identical for every syslog vendor -- see [syslog-envelope.md](syslog-envelope.md). Then apply Pattern B to the payload body.

## Step 5 -- Look up XDM targets via the field-anchor index

For each distinct vendor field name, query the shipped field-anchor index:

```sh
python3 scripts/lookup_anchor.py "<vendor_field_name>"
```

Returns a ranked list of `{xdm_path, frequency, exampleVendors[]}`. Treat the frequencies as confidence:

| Frequency | Treatment |
| --- | --- |
| `>= 10` | Strong -- use without further question |
| `3 - 9` | Default -- use unless the user's schema reference contradicts |
| `1 - 2` | Candidate only -- surface to user, do not auto-apply |
| `0` (no match) | No anchor PRECEDENT -- check the schema before declaring no XDM home |

A `0` result is NOT proof the field has no XDM home. The anchor index records what past rules happened to map; the schema is [xdm-schema.md](xdm-schema.md). Before documenting a field in the NOT MAPPED block, grep xdm-schema.md for the concept (`auth`, `mfa`, `host`, `process`, ...) and only declare no home when the schema genuinely lacks a field. Example: `mfa_method` historically returned `0` anchors, yet `xdm.auth.mfa.method` exists in the schema -- burying it in the description on the strength of the `0` was a mis-mapping.

The script normalises case, whitespace, `.` and `-` punctuation. `Src.IP`, `src-ip`, `tmp_src_ip` all resolve to `src_ip`. If a query returns nothing, try stripping suffixes or prefixes (`srcAddress` -> `src_addr`, drop a leading `client_` or `service_`, drop a trailing `_id` or `tmp_name`).

If `lookup_anchor.py` cannot be run (no Python on the host, or the bundle has been installed into a sandbox without script execution), fall back to grepping `assets/field_anchors.json` directly:

```sh
grep -i '"<vendor_field_name>"' assets/field_anchors.json
```

The JSON is human-readable; each anchor block lists every synonym that has historically mapped to that XDM target along with the per-synonym count. Pick the target whose synonym-count for your input field is highest, breaking ties with the anchor's total frequency.

## Step 6 -- Map source fields to XDM

Assign in this priority order:

1. Observer: `xdm.observer.vendor` and `xdm.observer.product` (hardcoded strings).
2. Event classification: `xdm.event.type` -- normalised category: `"ALERT"`, `"NETWORK"`, `"authentication"`, `"EMAIL"`, `"FILE"`, `"PROCESS"`, `"ENDPOINT_ACTIVITY"`, `"AUDIT"`. Then `xdm.event.id`, `xdm.event.original_event_type`, `xdm.event.description`, `xdm.event.outcome`, and `xdm.event.operation` (`XDM_CONST.OPERATION_TYPE_*` -- e.g. `OPERATION_TYPE_AUTH_MFA` / `OPERATION_TYPE_AUTH_LOGIN` for authentication events, `OPERATION_TYPE_AUDIT` for audit trails; omit only when no constant fits). For login / logon / sign-in / MFA / SSO events, `xdm.event.type` must resolve to a value that contains `authentication` (not `"AUTH"`); this is the discriminator the authentication story keys on.
3. Source and target identities: IPs, hostnames, ports, users.
4. Domain-specific: `xdm.alert.`, `xdm.email.`, `xdm.network.*`, `xdm.auth.*`.
5. Intermediate fields: for proxy / gateway devices between source and target.

Apply transformation patterns from [transformation-patterns.md](transformation-patterns.md):

- Numeric coercion -- wrap strings in `to_number()`; wrap integer fields in `to_integer(to_number(...))`.
- Companion field pairs -- map both halves when you map one.
- Array wrapping -- array-typed XDM fields need `arraycreate()` with null guard.
- Banded scoring -- vendor field names containing `"score"` or numeric severity scales (0-100, 0-10, 1-5) MUST use banded thresholds.
- Categorical enum routing -- vendor `categories[]` arrays MUST first attempt `xdm.alert.category` via THREAT_CATEGORY constants before falling back to `xdm.alert.subcategory`.
- One-sided actor mirroring -- when the vendor delivers ONE actor and no counterparty, mirror into BOTH `xdm.source.` and `xdm.target.`.
- Authentication mandatory mapping -- when `scripts/profile_log.py` flags the sample as an authentication event (or the rule sets the `EVENT_TAG_AUTHENTICATION` tag / an `OPERATION_TYPE_AUTH_*` operation), map the full mandatory 15-field set from [authentication-mapping.md](authentication-mapping.md). The story is only created when every mandatory field is mapped; the linter raises advisory WARN-042 (warning only, exit code stays 0) for each one left unmapped.
- Network mandatory mapping -- when the profiler flags a network / traffic event (or the rule sets the `EVENT_TAG_NETWORK` tag / a `network` event type), map the full mandatory 17-field set from [network-mapping.md](network-mapping.md), padding absent values with the type-valid placeholders. Advisory WARN-043 flags each one left unmapped. The two detections are independent: a dual event (a VPN login) takes both sets, with the union of the story tags in ONE `xdm.event.tags = arraycreate(...)`.

## Step 7 -- Write the rule

Structure with clear stages:

```
[MODEL: dataset=<vendor>_<product>_raw]
filter <null_guard_condition>
| alter
    <Stage 1: extract intermediary (tmp_temp) fields from the raw log>
| alter
    <Stage 2 (optional): derive composite fields, banded scores, actor projections>
| alter
    <Stage 3: assign XDM fields using the intermediaries>
;
```

Use the template at [../assets/modeling_header_template.xql](../assets/modeling_header_template.xql) for the MAPPED-header comment block.

Stage discipline (parser idiom (xi)): Cortex evaluates all targets in one `alter` in parallel. A target cannot reference a sibling temp defined in the same stage -- split into multiple alter stages so later stages reference only prior-stage temps.

## Step 8 -- Lint

```sh
python3 scripts/lint_rule.py <rule.xql>
```

The bundled linter runs its whole registry in one pass -- structural, schema-aware and dataflow checks alike -- and exits non-zero when any finding is error severity. `python3 scripts/lint_rule.py --list-codes` prints the authoritative set; do not restate it here. Output is a JSON array of `{rule_id, severity, line, message, recommendation}`.

This replaces the mental pre-flight checklist with deterministic checking. The checklist is preserved in [modeling-rules.md](modeling-rules.md) as a manual fallback if the linter cannot run.

## Step 9 -- Fix earliest-first

INFO-012. When the linter reports multiple violations, the EARLIEST is almost always the root cause; the rest are cascade noise from the parser losing position. Fix the first defect, re-lint. Most common cascade roots (priority order):

1. ERR-012 -- infix arithmetic in `alter`
2. ERR-017 -- `arraymap` struct passthrough
3. ERR-018 -- missing `-> []` cast on a JSON-string column
4. ERR-013 -- compound null-guard predicate inside `if()`
5. ERR-014 -- bareword `true` / `false` on a string column

## Step 10 -- Emit final output

Every rule MUST be prefixed with a MAPPED-header comment block:

- Vendor / product / dataset identification
- One-paragraph description of what the rule does
- Alert / Event Field Mapping -- each source field on the left, target on the right, separated by ` -> `; one mapping per line; grouped with sub-comments where useful
- NOT MAPPED sub-block -- every notable source field or XDM target you deliberately did not map, with a short reason (e.g. "no XDM_CONST exists", "tenant is implicit", "Cortex sets `_time` automatically")
- SPDX licence: `SPDX-License-Identifier: AGPL-3.0-or-later`

See the template at [../assets/modeling_header_template.xql](../assets/modeling_header_template.xql).
