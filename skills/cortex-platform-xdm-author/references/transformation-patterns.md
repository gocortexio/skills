<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Transformation patterns -- applied during XDM mapping

These patterns apply during the mapping stage of a data-model rule, after the extraction has produced underscore-prefixed temps. They are log-type-independent.

## Numeric coercion

The arrow operator (Pattern D) and `json_extract_scalar` (Pattern A) return strings. Wrap in `to_number()` or `to_integer()` when the target XDM field is Number-typed:

- Ports: `xdm.source.port`, `xdm.target.port`, `xdm.intermediate.port`
- Byte counts: `xdm.source.sent_bytes`, `xdm.target.sent_bytes`
- Packet counts: `xdm.source.sent_packets`, `xdm.target.sent_packets`
- Duration: `xdm.event.duration`
- PID: `xdm.source.process.pid`, `xdm.target.process.pid`

```
tmp_src_port = to_integer(Source -> Port)
```

Critical: `to_number()` returns a float. Integer-typed XDM fields MUST be wrapped in `to_integer(to_number(...))` -- see [parser-idioms.md](parser-idioms.md) ERR-015.

## Companion field pairs

When you map one field of a pair, always map the other:

| Pair | Convention |
| --- | --- |
| `xdm.event.outcome` (XDM_CONST) <-> `xdm.observer.action` (String) | Outcome enum next to raw action verb |
| `xdm.event.log_level` (XDM_CONST) <-> `xdm.alert.severity` (String) | Banded level next to human-readable severity |
| `xdm.event.type` (normalised) <-> `xdm.event.original_event_type` (raw) | Always map both when log has an event type |
| `xdm.alert.name` (display) <-> `xdm.alert.original_threat_name` (raw) | Both when log has a threat name |
| `xdm.alert.original_alert_id` <-> `xdm.event.id` | Same value into both when vendor delivers one event ID |
| `xdm.source.user.username` <-> `xdm.source.user.upn` | Mirror when vendor supplies one identity (same for target/intermediate) |
| `xdm.source.host.hostname` <-> `xdm.source.host.fqdn` | Mirror short hostname / FQDN (same for target/intermediate) |
| `xdm.source.user.identifier` <-> `xdm.source.user.username` | Stable user ID + display name when both present |

## String passthrough fallback (mandatory for vendor-text fields)

Every categorical `if()`-chain that assigns to a free-String XDM field carrying vendor text MUST end with a `tmp_field != null, tmp_field` passthrough, so an unmapped vendor value is preserved rather than silently nulled. Without the passthrough, any value your branches did not anticipate vanishes, and the gap only surfaces in production when an analyst notices the field is empty.

```
// WRONG -- unmapped vendor actions are silently dropped
xdm.observer.action = if(
    tmp_action = "ALLOW", "allow",
    tmp_action = "BLOCK", "block")

// RIGHT -- the passthrough preserves anything not explicitly mapped
xdm.observer.action = if(
    tmp_action = "ALLOW", "allow",
    tmp_action = "BLOCK", "block",
    tmp_action != null,   tmp_action)
```

This applies to free-String fields that carry the vendor's own text, such as `xdm.alert.subcategory`, `xdm.observer.action`, `xdm.alert.original_threat_name`, `xdm.event.outcome_reason`. Two exceptions:

- Closed-list `XDM_CONST` targets (`xdm.event.outcome`, `xdm.alert.category`, `xdm.network.http.method`, and the rest in the XDM_CONST-required table below) keep OMITTING the default branch, so an unmatched value resolves to null. A raw string would break the enum type.
- Band-vocabulary String fields like `xdm.alert.severity` floor to a band (`tmp_field != null, "Low"`) or omit the default; they NEVER echo the raw value, because an arbitrary string is not a valid band (see the log-level vocabulary rule).

## Array field construction

Array-typed XDM fields (marked `(Array)` in [xdm-schema.md](xdm-schema.md)) MUST use `arraycreate()`. Always null-guard:

```
if(tmp_value != null, arraycreate(tmp_value), null)
```

Common array fields:

- `xdm.source.host.ipv4_addresses`, `xdm.target.host.ipv4_addresses`
- `xdm.source.host.mac_addresses`, `xdm.target.host.mac_addresses`
- `xdm.source.user.groups`, `xdm.source.user.roles`
- `xdm.email.recipients` -- despite not being labelled Array in the schema, it requires `arraycreate()` (see [xdm-schema.md](xdm-schema.md) notes).

Multi-IP pattern (coalesce + arraycreate together):

```
| alter
    tmp_src_ip     = Source -> IP,
    tmp_src_alt_ip = Source -> AlternateIP
| alter
    tmp_resolved_src_ip = coalesce(tmp_src_ip, tmp_src_alt_ip)
| alter
    xdm.source.ipv4               = tmp_resolved_src_ip,
    xdm.source.host.ipv4_addresses = if(tmp_resolved_src_ip != null,
                                        arraycreate(tmp_resolved_src_ip),
                                        null)
```

`tmp_src_alt_ip` is consumed by the `coalesce`, so it is not an unused temp.

## XDM_CONST-required fields

These fields MUST use XDM_CONST enum values via `if()` chains, never raw strings:

| Field | Constant group |
| --- | --- |
| `xdm.event.outcome` | `XDM_CONST.OUTCOME_*` |
| `xdm.event.log_level` | `XDM_CONST.LOG_LEVEL_*` |
| `xdm.event.operation` | `XDM_CONST.OPERATION_TYPE_*` |
| `xdm.network.http.method` | `XDM_CONST.HTTP_METHOD_*` |
| `xdm.network.http.response_code` | `XDM_CONST.HTTP_RSP_CODE_*` |
| `xdm.{source,target}.cloud.provider` | `XDM_CONST.CLOUD_PROVIDER_*` |
| `xdm.{source,target}.cloud.service` | `XDM_CONST.CLOUD_SERVICE_TYPE_*` |
| `xdm.{source,target}.user.identity_type` | `XDM_CONST.IDENTITY_TYPE_*` |
| `xdm.{source,target}.host.os_family` | `XDM_CONST.OS_FAMILY_*` |
| `xdm.network.ip_protocol` | `XDM_CONST.IP_PROTOCOL_*` |
| `xdm.alert.mitre_tactics` | `XDM_CONST.MITRE_TACTIC_*` |
| `xdm.alert.mitre_techniques` | `XDM_CONST.MITRE_TECHNIQUE_*` |

```
// WRONG
xdm.network.http.method = tmp_http_method

// RIGHT
xdm.network.http.method = if(
    tmp_http_method = "GET",    XDM_CONST.HTTP_METHOD_GET,
    tmp_http_method = "POST",   XDM_CONST.HTTP_METHOD_POST,
    tmp_http_method = "PUT",    XDM_CONST.HTTP_METHOD_PUT,
    tmp_http_method = "DELETE", XDM_CONST.HTTP_METHOD_DELETE)
```

Raw strings on XDM_CONST fields cause silent data loss in Cortex -- the value is dropped.

### Default branch rule for XDM_CONST if-chains

The default (final) branch of an `if()`-chain for an XDM_CONST field must be another XDM_CONST value or be omitted entirely -- never a raw string.

```
// WRONG -- raw string default
xdm.alert.category = if(
    tmp_cat = "sql_injection", XDM_CONST.THREAT_CATEGORY_SQL_INJECTION,
    tmp_cat != null, tmp_cat)                    // raw string default!

// RIGHT
xdm.alert.category = if(
    tmp_cat = "sql_injection", XDM_CONST.THREAT_CATEGORY_SQL_INJECTION,
    tmp_cat = "cryptominer",   XDM_CONST.THREAT_CATEGORY_CRYPTOMINER)
```

If no matching constant exists for the default case, omit the default branch so unmatched values produce null (safe). Use `xdm.alert.subcategory` (String type) for the raw vendor text as a fallback.

If unsure which constant to use, OMIT the field entirely. See [pitfall-traps.md](pitfall-traps.md) for the OMIT-and-fall-back rule.

## Never hardcode sample-derived values

An `if(x contains "token", ...)` chain is correct only when the tokens are
part of the source's own vocabulary and vendor-agnostic -- protocol names
(`kerberos`, `ntlm`), a `$` machine-account suffix, `THREAT_CATEGORY`
keywords. It is WRONG to hardcode a value that came from the sample: a
tenant URL path, a hostname, an IP, an ID, a product-specific route. Baking
those in leaks customer-internal data into the rule and only ever covers
the values that one sample happened to show. The linter flags a hardcoded
path / host / IP / ID literal as WARN-049.

Anti-pattern -- deriving a "resource type" by hardcoding the tenant's URL
paths (and inventing a classification the source never defines):

```
// WRONG -- customer paths baked in, not scalable
tmp_res_type = if(
    requestUri contains "/keys/", "appkey",
    requestUri contains "/apps/", "app",
    requestUri contains "/developers/", "developer")
```

Extract the segment dynamically instead, so any path works:

```
// RIGHT -- pull the first path segment; no sample-specific literal
tmp_res_segment = arrayindex(regextract(requestUri, "^/([^/?]+)"), 0)
```

If the raw value has no closed-list XDM home, keep it verbatim in a
free-String field (`xdm.alert.subcategory`, `xdm.observer.action`) rather
than classifying it against hardcoded sample values. Only ever hardcode
`XDM_CONST` members, the observer vendor / product identity strings, and
well-known vendor-agnostic tokens.

## Event outcome -- only for a real result, not a detection disposition

`xdm.event.outcome` records whether an action succeeded or failed. A detection / IDS / anomaly disposition verb -- `alert`, `monitor`, `investigate`, `isolate` -- is NOT an outcome: the detection fired, it did not "succeed" or "fail". Leave `xdm.event.outcome` UNSET for a pure detection, and keep the disposition verb in `xdm.observer.action`.

```
// WRONG -- a disposition forced into outcome
xdm.event.outcome = if(
    tmp_action = "isolate", XDM_CONST.OUTCOME_FAILED,
    tmp_action != null,     XDM_CONST.OUTCOME_PARTIAL)

// RIGHT -- keep the verb in observer.action; omit outcome
xdm.observer.action = tmp_action
// xdm.event.outcome intentionally not set: a detection has no success / failure.
// Set it only when the log reports a real result, e.g. a permit / block decision:
xdm.event.outcome = if(
    tmp_status = "blocked",   XDM_CONST.OUTCOME_FAILED,
    tmp_status = "permitted", XDM_CONST.OUTCOME_SUCCESS)
```

## Risk and deviation metrics -> xdm.alert.risks

A numeric ratio, deviation, or score with no typed numeric XDM home -- e.g. `metrics.baseline_deviation`, an anomaly multiplier, a confidence ratio -- is NOT homeless. Park it in `xdm.alert.risks` alongside the raw `risk_score`, so the risk signal is preserved for the analyst.

`xdm.alert.risks` is an ARRAY of String, not a String. [xdm-schema.md](xdm-schema.md) types it `String (Array)`, and a bare `concat()` into it is the scalar-into-array shape WARN-035 exists to catch -- the assignment installs and the field then reads back wrong. Wrap the summary, or emit one element per metric:

```
xdm.alert.risks = arraycreate(
    concat("risk_score=", tmp_risk_score),
    if(tmp_baseline_deviation != null,
       concat("baseline_deviation=", tmp_baseline_deviation)))
```

An element whose `if()` finds nothing resolves null and the array carries the rest, so no guard around the whole assignment is needed.

Dropping such a metric is a choice, not a necessity. When you do drop one, record it in the NOT MAPPED block as "intentionally omitted" with a reason -- never as "no XDM home", which is false for any value that fits `xdm.alert.risks`.

## Banded numeric scoring (mandatory for `score` fields)

If a vendor source field name contains `"score"` (e.g. `risk_score`, `riskScore`, `threat_score`, `severity_score`, `confidence_score`, `alert_score`) OR is otherwise a numeric severity scale (0-100, 0-10, 1-5), you MUST apply banded scoring: an `if`-chain mapping thresholds to `"Critical"` / `"High"` / `"Medium"` / `"Low"` for `xdm.alert.severity` AND a parallel `XDM_CONST.LOG_LEVEL_*` `if`-chain into `xdm.event.log_level`.

```
xdm.alert.severity = if(
    tmp_score >= 80, "Critical",
    tmp_score >= 50, "High",
    tmp_score >= 30, "Medium",
    tmp_score != null, "Low"),
xdm.event.log_level = if(
    tmp_score >= 80, XDM_CONST.LOG_LEVEL_CRITICAL,
    tmp_score >= 50, XDM_CONST.LOG_LEVEL_ERROR,
    tmp_score >= 30, XDM_CONST.LOG_LEVEL_WARNING,
    tmp_score != null, XDM_CONST.LOG_LEVEL_INFORMATIONAL)
```

NEVER assign the raw score via `to_string()` or as a number to `xdm.alert.severity`. `xdm.alert.severity` is a categorical String field; an unbanded number-string is a silent regression that the linter cannot catch.

This rule does NOT apply to non-numeric severity columns (already-banded labels like `"low"` / `"medium"` / `"high"` use case-normalisation instead -- see "Severity normalisation" below).

### Reading bands from a vendor prose table

When the log description supplies a numeric severity scale and a band table (for example "1-25 Low, 26-50 Moderate, 51-75 High, 76-100 Critical"), read the thresholds from the prose and use them. Normalise vendor band labels to the closed XDM set -- `Critical` / `High` / `Medium` / `Low` -- so a vendor `"Moderate"` becomes XDM `"Medium"`. Coerce the numeric severity with `to_integer(to_number(...))` (ERR-015) and floor to a band; never echo the raw number.

```
tmp_sev = to_integer(to_number(tmp_sev_str)),
xdm.alert.severity = if(
    tmp_sev >= 76, "Critical",
    tmp_sev >= 51, "High",
    tmp_sev >= 26, "Medium",                 // vendor "Moderate" -> XDM "Medium"
    tmp_sev != null, "Low"),                 // floor to a band, never the raw number
xdm.event.log_level = if(
    tmp_sev >= 76, XDM_CONST.LOG_LEVEL_CRITICAL,
    tmp_sev >= 51, XDM_CONST.LOG_LEVEL_ERROR,
    tmp_sev >= 26, XDM_CONST.LOG_LEVEL_WARNING,
    tmp_sev != null, XDM_CONST.LOG_LEVEL_INFORMATIONAL)
```

## Severity normalisation (for already-banded labels)

```
xdm.alert.severity = if(
    tmp_risk_level = "low",      "Low",
    tmp_risk_level = "medium",   "Medium",
    tmp_risk_level = "high",     "High",
    tmp_risk_level = "critical", "Critical",
    tmp_risk_level != null,      tmp_risk_level)
```

The `tmp_risk_level != null, tmp_risk_level` floor is safe here because the source vocabulary IS the band vocabulary: an unmatched value is still a band word. Do NOT use a raw passthrough when the source vocabulary is something else, such as the log-level words below.

## Log-level vocabulary (severity words that are really log levels)

Some vendors put log-level words in the severity field: `debug`, `info` / `informational`, `notice`, `warning`, `error`, `critical`. These are log levels, not alert severities. Band them into `xdm.alert.severity` (Informational / Low / Medium / High / Critical) AND map them to `xdm.event.log_level` via `XDM_CONST.LOG_LEVEL_*`. Never echo a log-level word -- `"Warning"`, `"Error"`, `"Notice"`, `"Debug"` -- into `xdm.alert.severity`. That field is a band scale, not a syslog level, so a raw log-level word there is a silent miscategorisation that downstream severity filters miss.

```
xdm.alert.severity = if(
    tmp_level = "debug",    "Informational",
    tmp_level = "info",     "Informational",
    tmp_level = "notice",   "Low",
    tmp_level = "warning",  "Medium",
    tmp_level = "error",    "High",
    tmp_level = "critical", "Critical",
    tmp_level != null,      "Low"),
xdm.event.log_level = if(
    tmp_level = "debug",    XDM_CONST.LOG_LEVEL_INFORMATIONAL,
    tmp_level = "info",     XDM_CONST.LOG_LEVEL_INFORMATIONAL,
    tmp_level = "notice",   XDM_CONST.LOG_LEVEL_NOTICE,
    tmp_level = "warning",  XDM_CONST.LOG_LEVEL_WARNING,
    tmp_level = "error",    XDM_CONST.LOG_LEVEL_ERROR,
    tmp_level = "critical", XDM_CONST.LOG_LEVEL_CRITICAL)
```

The `xdm.alert.severity` chain ends with a `tmp_level != null, "Low"` band floor, NOT a raw passthrough, so an unrecognised value still lands on a real band instead of leaking a log-level word. The `xdm.event.log_level` chain omits the default branch: it is an `XDM_CONST` closed list, so an unmatched value resolves to null (safe). The linter flags WARN-037 when a log-level word is assigned to `xdm.alert.severity`.

## Categorical enum array -> THREAT_CATEGORY scalar

If the log has an array of vendor category strings -- columns named `categories`, `threat_categories`, `classifications`, `tags`, `labels`, `attack_categories` -- you MUST first attempt to map them to `xdm.alert.category` via `XDM_CONST.THREAT_CATEGORY_*` using the "Scalar-from-array via arrayindex + arrayfilter" pattern in [extraction-patterns.md](extraction-patterns.md).

Do NOT default-route the array into `xdm.alert.subcategory` via `arraystring()` and then claim "no `XDM_CONST.THREAT_CATEGORY_*` applies" -- the THREAT_CATEGORY enum has 30+ members. Only fall back to `xdm.alert.subcategory` when EVERY category string fails a case-insensitive substring/regex match against the THREAT_CATEGORY tokens. Preserve the full joined text in `xdm.event.description` either way.

## Array MITRE mapping (arraymap, not arraycreate wrapper)

When the log carries an array of MITRE technique IDs (e.g. `["T1059", "T1078"]`) and you must map each ID to its `XDM_CONST.MITRE_TECHNIQUE_*` constant, use `arraymap` with an inner if-chain. The result of `arraymap` IS already an array. Do NOT wrap in `arraycreate()`.

```
// CORRECT
xdm.alert.mitre_techniques = arraymap(
    tmp_mitre_technique_ids,
    if("@element" = "T1059", XDM_CONST.MITRE_TECHNIQUE_COMMAND_AND_SCRIPTING_INTERPRETER,
    if("@element" = "T1078", XDM_CONST.MITRE_TECHNIQUE_VALID_ACCOUNTS,
    if("@element" = "T1110", XDM_CONST.MITRE_TECHNIQUE_BRUTE_FORCE,
        null))))
```

The `XDM_CONST.MITRE_TECHNIQUE_*` constants use the canonical MITRE technique NAME, not the technique ID. E.g. T1078 maps to `XDM_CONST.MITRE_TECHNIQUE_VALID_ACCOUNTS` (no `T1078_` prefix). NEVER prepend the T-id to the constant name -- that creates an invented constant.

```
// WRONG -- double-wrap; produces array-of-arrays
xdm.alert.mitre_techniques = arraycreate(
    arraymap(tmp_mitre_technique_ids, if(...)))

// WRONG -- raw string default; breaks XDM_CONST type
arraymap(tmp_ids, if("@element" = "T1059",
    XDM_CONST.MITRE_TECHNIQUE_COMMAND_AND_SCRIPTING_INTERPRETER,
    "@element"))
```

Tactic IDs follow the same pattern with `XDM_CONST.MITRE_TACTIC_*` into `xdm.alert.mitre_tactics`.

## Single-entity mirroring (when source and target are the same)

When a payload has only one IP or one user, map to BOTH source and target for maximum correlation coverage in XSIAM:

```
xdm.source.ipv4          = tmp_client_ip,
xdm.target.ipv4          = tmp_client_ip,
xdm.source.user.username = tmp_user,
xdm.target.user.username = tmp_user
```

Only do this when there is genuinely a single entity. When source and target are different (email sender vs recipient, web client vs upstream server), do NOT mirror.

## One-sided source/target mirroring (single-actor detections)

Many vendor detections describe a SINGLE actor -- the offender, attacker, principal -- and never deliver a normalised counterparty. ExtraHop RevealX, SentinelOne, Vectra, Darktrace and most NDR products behave this way. Cortex correlation pivots on either `xdm.source.` OR `xdm.target.` depending on the dashboard, so a one-sided detection populated only on one half is half-invisible to the analyst.

THE RULE: When the vendor delivers ONE actor and no counterparty, mirror the actor's identity into BOTH `xdm.source.` AND `xdm.target.`.

Explicit mirror pair list (six pairs, no inference):

- `xdm.source.ipv4` <-> `xdm.target.ipv4`
- `xdm.source.host.ipv4_addresses` <-> `xdm.target.host.ipv4_addresses`
- `xdm.source.host.hostname` <-> `xdm.target.host.hostname`
- `xdm.source.user.username` <-> `xdm.target.user.username`
- `xdm.source.user.upn` <-> `xdm.target.user.upn`
- `xdm.source.is_internal_ip` <-> `xdm.target.is_internal_ip`

Do NOT mirror role-specific fields (`sent_bytes`, `port`, `process.*`, `zone`, `vlan`, `agent.*`) -- those are direction-specific and a wrong-side copy is worse than null.

```
| alter
    xdm.source.ipv4               = tmp_offender_ip,
    xdm.source.user.username      = tmp_offender_username,
    xdm.source.user.upn           = tmp_offender_username,
    xdm.source.is_internal_ip     = tmp_offender_is_internal,
    xdm.target.ipv4               = tmp_offender_ip,
    xdm.target.user.username      = tmp_offender_username,
    xdm.target.user.upn           = tmp_offender_username,
    xdm.target.is_internal_ip     = tmp_offender_is_internal;
```

Why not `xdm.{source,target}.is_external`? That path does NOT exist. The only canonical sink for an external/internal boolean is `is_internal_ip`. When the vendor exposes `external` (or equivalent), invert with:

```
tmp_is_internal = if(
    to_boolean(tmp_external) = true,  to_boolean("false"),
    to_boolean(tmp_external) = false, to_boolean("true"))
```

Then mirror `tmp_is_internal` into BOTH `xdm.source.is_internal_ip` and `xdm.target.is_internal_ip`.

When NOT to mirror:

- The vendor delivers BOTH a real source and a real target (firewall flows, proxy logs, EDR file-write events). Map each side from its own log fields.
- The vendor delivers a victim entity with non-null identifiers. Use those.

Stage boundary caveat: Mirroring lives in the FINAL `alter` stage (the `xdm.*` drain stage), NEVER in the same `alter` that derives the offender temp being mirrored. Cortex evaluates all targets in one `alter` in parallel ([parser-idioms.md](parser-idioms.md) idiom (xi)), so `xdm.source.ipv4 = tmp_offender_ip` in the same stage that defines `tmp_offender_ip` is rejected as "unknown field `tmp_offender_ip`". Always: derive in stage N, drain + mirror in stage N+1.

## Defensive `coalesce(PascalCase, camelCase)`

When the XSIAM parser may produce field names in either PascalCase or camelCase (common with AWS, Azure, GCP sources), use `coalesce` on both forms throughout:

```
finding_resource     = coalesce(Resource, resource),
finding_id           = coalesce(Id, id),
resource_instance_id = coalesce(
    finding_resource -> InstanceDetails.InstanceId,
    finding_resource -> instanceDetails.instanceId)
```

## Directional IP/port resolution

When a finding reports both local and remote IPs with a direction indicator (`INBOUND` / `OUTBOUND`), resolve source and target based on direction:

```
source_ipv4 = if(is_inbound, remote_ip, is_outbound, local_ip, fallback_ip)
target_ipv4 = if(is_inbound, local_ip,  is_outbound, remote_ip)
```

## Transitive field usage

Intermediary fields may feed into other intermediary fields before reaching an XDM assignment. This is valid as long as the chain terminates in an `xdm.*` assignment:

```
tmp_http_code = to_integer(raw_status_code),
xdm.network.http.response_code = if(
    tmp_http_code = 200, XDM_CONST.HTTP_RSP_CODE_OK, ...)
```

If `tmp_http_code` were extracted but NOT mapped, Cortex rejects the rule (unused field -- ERR-019).

## HTTP response code: map the COMPLETE status set

`xdm.network.http.response_code` is const-typed over the full HTTP status set. A production source can return any status code, so the mapping must cover ALL of them -- not just the codes the build sample happened to contain. The abbreviated `..., ...)` above is only shorthand: a real rule never hand-lists a partial set.

Do NOT hand-write the chain. Render the complete, authoritative if-chain from the shipped crosswalk and paste it in:

```
python3 scripts/http_status_map.py --render --temp tmp_http_code
```

This emits every `tmp_http_code = <code>, XDM_CONST.HTTP_RSP_CODE_<NAME>` branch (all 60 codes) with no default branch, so an unmatched code yields null (safe) rather than a wrong constant. The linter flags a hand-written partial chain as WARN-048.

## Identity-type mapping

Common vendor identity tokens map to `XDM_CONST.IDENTITY_TYPE_*` as follows:

| Vendor token | Constant |
| --- | --- |
| `ServiceAccount`, `service_account`, `svc-*` | `IDENTITY_TYPE_MACHINE` |
| `Machine`, `machine`, `system` | `IDENTITY_TYPE_MACHINE` |
| `User`, `user`, `human` | `IDENTITY_TYPE_USER` |
| `Admin`, `admin`, `root` | `IDENTITY_TYPE_BUILTIN` |

Do NOT map `ServiceAccount` to `IDENTITY_TYPE_USER`.

## Authentication and MFA mapping

Authentication logs have dedicated structured homes under `xdm.auth.*`. These fields are easy to miss because the anchor index has thin precedent for them -- check the schema, not just the anchor lookup, before declaring a field unmapped:

| Vendor field | XDM target |
| --- | --- |
| `mfa_method`, `mfa_type`, `factor` | `xdm.auth.mfa.method` (String) |
| `mfa_provider` | `xdm.auth.mfa.provider` (String) |
| `is_mfa_needed`, `mfa_required` | `xdm.auth.is_mfa_needed` (Boolean -- wrap with `to_boolean(...)`) |
| `auth_method`, `authentication_method` | `xdm.auth.auth_method` (String) |

Companion classification: when the log is an authentication event, set `xdm.event.operation` alongside `xdm.event.type`. For the authentication story `xdm.event.type` must resolve to a value containing `authentication` (not the short `"AUTH"` label used for non-story event classification). Use `XDM_CONST.OPERATION_TYPE_AUTH_MFA` when the event involves MFA, otherwise `XDM_CONST.OPERATION_TYPE_AUTH_LOGIN`:

```
xdm.event.type = "authentication",
xdm.event.operation = if(
    tmp_mfa_method != null, XDM_CONST.OPERATION_TYPE_AUTH_MFA,
    XDM_CONST.OPERATION_TYPE_AUTH_LOGIN),
xdm.auth.mfa.method = tmp_mfa_method,
xdm.auth.is_mfa_needed = to_boolean(tmp_mfa_required)
```

An authentication event has a fixed mandatory XDM field set (15 fields) that the authentication story depends on. Map the full set per [authentication-mapping.md](authentication-mapping.md); the linter raises the advisory WARN-042 for each mandatory field an auto-detected authentication rule leaves unmapped.

Never bury `mfa_method` (or device / OS detail) in `xdm.event.description` -- these values have structured homes, and a description-only copy is invisible to downstream queries. The description summarises; it never substitutes (see "Structured event description" below).

## Structured event description

Emit `xdm.event.description` by default: a deterministic human-readable summary built with `concat()` over the identifying fields. It gives the analyst a one-line gist in the alert view and a consistent free-text search target. It is an ADDITION to the structured XDM fields, never a substitute -- map each value to its own queryable field first, then summarise. Never bury data in the description that belongs in a field of its own.

Build the summary with `concat()` and conditional sections:

```
xdm.event.description = concat(
    "Vendor ", eventType,
    if(direction != null, concat(" (", direction, ")"), ""),
    if(Subject != null,   concat(" | Subject: ", Subject), ""),
    if(Action != null,    concat(" | Action: ", Action), ""))
```

Remember idiom (xii): variables whose only consumer is inside a `concat()` body do NOT count toward reach. Inline the derivation directly, or drain through a bareword identity assignment first.

Never dump the whole payload into the description. `xdm.event.description = _raw_log`, `= to_string(_raw_log)`, or `= to_json_string(<object>)` defeats the point: it buries every field in free text where structured queries cannot reach it. The description is a concat() of the fields that matter; everything else goes to its own structured XDM home. The linter flags this as WARN-039.

## No duplicate assignments

Never assign the same temp variable to two different XDM fields unless both fields genuinely require the same value (e.g. `xdm.event.id` and `xdm.alert.original_alert_id` both receiving `tmp_event_id` is acceptable). If you find yourself assigning the same value to two XDM fields that serve different semantic purposes, one of them is wrong.

## Event type vs original event type

- `xdm.event.type` = normalised category: use short generic labels like `"ALERT"`, `"NETWORK"`, `"AUDIT"`, `"AUTH"`. This is the Cortex correlation key.
- `xdm.event.original_event_type` = raw vendor event type exactly as it appears in the log (e.g. `"WAF_BLOCK"`, `"THREAT_DETECT"`, `"LOGIN_FAILED"`).

Always map BOTH when the log provides an event type field.
