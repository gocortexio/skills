<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Pitfall traps -- what NOT to do

Scan this list before emitting any rule. Most of these are caught by `scripts/lint_rule.py`, but a few (notably non-existent XDM paths and the OMIT-and-fall-back rule for XDM_CONST) need human-style judgement.

## Quick-reference pitfalls

| Pitfall | Wrong | Right |
| --- | --- | --- |
| Unused temp field | `tmp_unused = something` (never assigned to XDM) | Remove it or map it to an XDM field |
| String vs number | `severityNumber = "4"` | `severityNumber = 4` |
| Quoted XDM_CONST | `"XDM_CONST.OUTCOME_SUCCESS"` | `XDM_CONST.OUTCOME_SUCCESS` |
| Quoted dataset name (MODEL) | `dataset="name_raw"` | `dataset=name_raw` |
| Self-referencing XDM field | `xdm.target.ipv4 = coalesce(xdm.target.ipv4, tmp_fallback)` | `xdm.target.ipv4 = tmp_fallback` |
| Chained arrow operator | `imperva -> ids -> site_name` | `json_extract_scalar(to_string(imperva), "$.ids.site_name")` |
| Missing `to_string()` wrap | `split(arrayindex(tmp_parts, 3), "/")` | `split(to_string(arrayindex(tmp_parts, 3)), "/")` |
| Array field without `arraycreate` | `xdm.email.recipients = tmp_recipient` | `xdm.email.recipients = if(tmp_recipient != null, arraycreate(tmp_recipient), null)` |
| Leading pipe on first stage | `[MODEL: ...]\n\| alter` | `[MODEL: ...]\nalter` (or `filter`) |
| Missing terminal semicolon | `... = "Foo"` (end of rule) | `... = "Foo";` |
| `from_epoch` (does not exist) | `from_epoch(tmp_ts, "MILLIS")` | `parse_epoch(tmp_ts, "MILLIS")` |
| Trailing comma before `;` | `... = "Foo",;` | `... = "Foo";` |
| Unguarded `parse_epoch` | `_time = parse_epoch(tmp_ts, "MILLIS")` | `_time = if(tmp_ts != null and tmp_ts != "", parse_epoch(tmp_ts, "MILLIS"), null)` |
| `_time` assignment in MODEL rule | `_time = parse_epoch(...)` in MODEL | Remove it. `_time` is set during INGEST or by Cortex automatically. |
| JSON path with `@` prefix | `json_extract_scalar(_raw_log, "$.@timestamp")` | `json_extract_scalar(_raw_log, "$['@timestamp']")` |

Unused intermediaries are BLOCKING (not warnings). Every non-underscore field extracted in an `alter` block MUST be referenced in a subsequent `xdm.*` assignment (directly or transitively). "Data Model Rules contains unused fields" is a hard block on both `_raw` and `_gc_raw` datasets.

## Non-existent XDM paths

These look plausible but are NOT in the schema. They cause validation errors or IDE internal errors.

| Wrong | Right |
| --- | --- |
| `xdm.source.user.email` | `xdm.source.user.upn` (use for email addresses) |
| `xdm.target.user.email` | `xdm.target.user.upn` |
| `xdm.network.http.user_agent` | `xdm.source.user_agent` (top-level source field) |
| `xdm.cloud.provider` | `xdm.source.cloud.provider` (or `xdm.target.cloud.provider`) |
| `xdm.source.cloud.account_id` | `xdm.source.cloud.project_id` (cloud account identifiers) |
| `xdm.source.process.parent_process.*` | `xdm.source.process.parent_id` (only `parent_id` exists for the parent chain) |
| `xdm.event.start_time` | Fold into `xdm.event.duration` via `to_integer(subtract(...))` |
| `xdm.event.end_time` | Fold into `xdm.event.duration` |
| `xdm.network.direction` | Include direction in `xdm.event.description` or `xdm.event.operation_sub_type` |

For each mapping in your draft rule, verify the XDM path exists in [xdm-schema.md](xdm-schema.md) before emitting.

## Commonly confused field pairs

### `xdm.target.host.*` vs `xdm.target.resource.*`

- `xdm.target.host.hostname` -- a named device or asset: a server name, an endpoint, an OT / ICS asset such as `asset=PLC-17`. A host has an IP, so also emit `xdm.target.host.ipv4_addresses` when the IP is known (WARN-038).
- `xdm.target.resource.name` -- a cloud or platform resource: an S3 bucket, a VM id, a Kubernetes object.

A physical or named asset is a host, not a resource. Do NOT route an OT asset name into `xdm.target.resource.*`; that field is for cloud resources. The same split applies on the `source` and `intermediate` sides.

AUTHENTICATION EVENTS ARE THE EXCEPTION, and it is a deliberate one. On an authentication event `xdm.target.resource.name` is MANDATORY and carries whatever the principal authenticated to -- a cloud resource, an application, a named host, or a bare address. It is set IN ADDITION to the type-correct field, so the split above still holds: the router keeps `xdm.target.host.hostname` and gains `xdm.target.resource.name` as well. This is a house convention that supersedes the cloud-only reading for this one event class; see [house-conventions.md](house-conventions.md) for the reason and [authentication-mapping.md](authentication-mapping.md) for the derivation.

### `xdm.target.resource.name` vs `xdm.target.application.name`

- `xdm.target.resource.name` -- cloud resource name (S3 bucket, VM name).
- `xdm.target.application.name` -- software application name (`"Nginx"`, `"MSSQL"`).

Choose based on what the log field represents. Do not use one for the other.

Again, authentication is the exception: a login to an application takes BOTH, `xdm.target.application.name` for the software identity and `xdm.target.resource.name` for the mandatory authentication target. Dual-mapping is correct here, not sloppy.

### `xdm.event.outcome_reason` vs `xdm.observer.action`

Both are valid for raw action strings.

- `xdm.observer.action` -- companion to `xdm.event.outcome` (see [transformation-patterns.md](transformation-patterns.md) "Companion field pairs").
- `xdm.event.outcome_reason` -- explanatory text.

### `xdm.network.http.browser` vs `xdm.source.user_agent`

- `xdm.network.http.browser` -- browser NAME from the User-Agent header (`"Chrome"`, `"Firefox"`).
- `xdm.source.user_agent` -- full User-Agent string or declared client value.

Do NOT assign a detection classification label (`"Bot"`, `"Crawler"`, `"Automated"`) to `xdm.network.http.browser`. If the log has both a declared client (User-Agent) and a classified client (detection result), map the declared client to `browser` or `user_agent`, and include the classification in `xdm.event.description`.

## XDM_CONST fallback rules

General rule: whenever the vendor value does not match any constant listed in [xdm-const.md](xdm-const.md), OMIT the XDM_CONST field entirely and place the raw vendor text in the String fallback below. Never invent a constant by appending a plausible suffix.

### `xdm.alert.category` -> `xdm.alert.subcategory` (String)

If the vendor category string does not map to a known `XDM_CONST.THREAT_CATEGORY_*`, OMIT `xdm.alert.category` and use `xdm.alert.subcategory` (String) for the raw vendor category text instead.

### `xdm.{source,target,intermediate}.cloud.service` (OMIT when no const matches)

Requires `XDM_CONST.CLOUD_SERVICE_TYPE_*`. If the vendor service name does not map, OMIT the XDM_CONST field and record the raw service name in the NOT MAPPED block (or `xdm.event.description` if useful). Do NOT route it to `xdm.{source,target,intermediate}.cloud.source_type` -- that is a banned internal-only XCloud asset field (asset type, e.g. `t2.micro`), rejected by Cortex and blocked by lint ERR-029. See [banned-fields.md](banned-fields.md).

### `xdm.alert.mitre_techniques`

Requires `XDM_CONST.MITRE_TECHNIQUE_*`. Only map when the vendor provides explicit MITRE labels (e.g. `risk_reason`, `attack_type`, `technique_id`). Vendor-specific attack descriptions (`"SQL Injection via UNION SELECT"`) are NOT MITRE labels -- use `xdm.alert.subcategory` or `xdm.event.description` for those.

### Groups with no enumerated constants

For the following groups, treat with OMIT-and-fall-back:

| Field | Fallback |
| --- | --- |
| `xdm.{source,target,intermediate}.agent.type` | OMIT; place raw type in `xdm.event.description` if useful |
| `xdm.{source,target}.user.user_type` | OMIT; `username` and `identity_type` already convey the signal |
| `xdm.{source,target}.user.scope` | OMIT; place scope literal in `xdm.event.description` if useful |
| `xdm.source.process.executable.signature_status` (and all peer `.signature_status`) | OMIT; vendors rarely match the closed set |
| `xdm.event.tags` (`EVENT_TAG` Array) | OMIT unless vendor explicitly produces tags such as AUTHENTICATION/CLOUD/NETWORK/ONPREM/SAAS/VPN; never invent tags |
| `xdm.network.dns.dns_question.type` / `xdm.network.dns.dns_resource_record.type` | OMIT; place raw record type in `xdm.event.description` |
| `xdm.network.dns.response_code` | OMIT; place raw code in `xdm.network.dns.response_code_text` if available, else `xdm.event.description` |
| `xdm.network.http.url_category` | OMIT; place raw category in `xdm.event.description` (NEVER guess `URL_CATEGORY_*`) |
| `xdm.network.ldap.{bind_auth_type,operation,scope}` | OMIT; place raw value in `xdm.event.description` |
| `xdm.network.dcerpc.operation` | OMIT; raw operation name in `xdm.event.description` |
| `xdm.network.dhcp.message_type` | OMIT; raw message type in `xdm.event.description` |
| `xdm.target.registry{,tmp_before}.value_type` | OMIT; raw value type in `xdm.event.description` |
| `xdm.database.operation` | OMIT; raw SQL verb in `xdm.target.application.name` or `xdm.event.description` |

Do NOT invent constants for any of the above. The Cortex IDE rejects unknown `XDM_CONST` values with a hard validation error, and a hallucinated constant typically passes a local-LLM self-check while failing the server-side compile.

## Unused temp variable rule

Every underscore-prefixed variable you extract MUST appear on the RHS of an XDM field assignment. If you extract `tmp_cloud_service` but cannot find a valid XDM_CONST for `xdm.source.cloud.service`, either:

1. Fold the raw value into `xdm.event.description` if it aids the summary, and note it in the NOT MAPPED block.
2. Remove the extraction entirely.

Do NOT park it in `xdm.source.cloud.source_type` -- that field is banned (see [banned-fields.md](banned-fields.md)).

Never leave orphaned temp variables -- they cause a blocking validation error.

## No no-op leading filter stages

Data model rules run inside a MODEL block. A `filter` stage as the FIRST stage is forbidden when the predicate is universally true (a no-op). The Cortex IDE rejects the rule with a parser error.

### Common forbidden patterns

```
// WRONG -- no-op leading filter
filter _raw_log != null
| alter tmp_foo = json_extract_scalar(_raw_log, "$.foo")
| alter xdm.event.id = tmp_foo

// WRONG -- always-true tautology
filter true
| alter ...

// WRONG -- filter re-asserts the dataset selection already implicit in MODEL
filter _vendor = "<vendor>" and _product = "<product>"
| alter ...
```

### Correct

```
alter tmp_foo = json_extract_scalar(_raw_log, "$.foo")
| alter xdm.event.id = tmp_foo
```

RULE: The first stage of the rule MUST be `alter`. Do NOT prefix the rule with a `filter` stage of any kind, even when the intent is "skip null logs" -- nulls are handled per-extraction with `coalesce` / `if` and per-field with null guards.

A legitimate `filter` stage may appear LATER in the pipeline only when it expresses a non-trivial conditional projection (e.g. dropping audit subtypes that should not be modelled). It must never be the first stage and must never have a predicate that is always true.

This applies to ALL data sources -- no vendor for which a no-op leading filter is valid.

## An advisory is not a defect list: name the ENTITY before satisfying one

Every companion-field and mandatory-set check reasons about which FIELDS
are present. None of them can reason about which ENTITY each field
describes, and that is the one thing that decides whether the advice
applies.

`xdm.target.*` is not one object per record. On a device that both emits
telemetry and forwards traffic, the target of the FLOW and the target of
the LOG RECORD are routinely different hosts:

```
// the syslog HOSTNAME field -- the device that EMITTED the record
xdm.target.host.hostname = tmp_syslog_host,
// the destination inside the firewall flow tuple -- some other host
xdm.target.ipv4 = tmp_fw_dip,
```

A checker sees a hostname, an address, and no `ipv4_addresses`
companion, and suggests adding one. Doing so would assert that the
firewall's own host record carries whatever address the traffic happened
to be going to. That value is populated, non-empty and not the sentinel,
so it passes every count-based check, and every host-based correlation
join would silently use it.

This is the fourth failure mode -- a plausible but WRONG value --
arriving through a linter recommendation. It is the most dangerous route
to it, because the author who introduces it is being conscientious.

So, before satisfying ANY companion-field advisory:

1. Name the entity each field belongs to, out loud. "The hostname is the
   emitting device. The address is the flow destination."
2. Confirm they are the same entity. If they are not, the advisory does
   not apply.
3. Where it does not apply, record the false premise in the rule header
   rather than leaving a bare advisory for the next reader to "fix"
   confidently.

The same reasoning retires an advisory that would build an array from a
pad. Where the address is the prescribed semantically-empty `""`,
`arraycreate("")` is junk, and satisfying the check converts a correct
pad into a populated but meaningless value.

Note which way the asymmetry runs. Declining a companion field leaves a
gap that is visible: the field is absent, and anyone can see it is
absent. Satisfying it wrongly leaves no trace at all. Prefer the visible
gap.
