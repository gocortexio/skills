<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Walkthrough 5 -- Imperva Audit Trail (Pattern A, JSON-string column)

Vendor / product / dataset: Imperva / Cloud Application Security / `imperva_audittrail_raw`.

What the rule does: maps Imperva Audit Trail SIEM events (administrative actions on the Imperva console -- sites, users, SSL, policy, login, system jobs) to the XDM schema. The shortest of the five walkthroughs at ~92 LOC because it does one thing well: JSON-string extraction with a clean event-action classifier.

## Synthesised raw log sample

Imperva audit-trail events arrive with `_raw_log` null; the XSIAM ingestion has pre-flattened the payload into top-level columns (`imperva`, `user`, `event`) -- but unlike AWS GuardDuty where those columns are typed Objects, here they're JSON STRINGS. That's the distinguishing shape: `to_string(imperva)` is needed because the column type is not guaranteed `string` (XSIAM may type it as a boxed JSON), and `json_extract_scalar` is then applied to the serialised payload.

```json
// Top-level column `imperva` (carried as a JSON string):
{
  "audit_trail": {
    "event_action": "SITE_REMOVE",
    "event_action_description": "Site removed",
    "assumed_by": "alice@example.com",
    "resource_type": "Site",
    "resource_id": "12345",
    "resource_name": "www.acme.local",
    "event_context": "site_management",
    "event_context_description": "Site management ops"
  },
  "ids": {
    "account_id": "98765",
    "account_name": "ACME Production",
    "site_id": "12345"
  }
}

// Top-level column `user` (also a JSON string):
{"email": "alice@example.com", "name": "Alice Admin"}
```

The pre-parser delivers `imperva` and `user` as top-level columns holding these JSON payloads as strings. Other rows in the same dataset might carry different `event_action` values (`USER_LOGIN`, `SSL_RENEW`, `POLICY_UPDATE`, `ACCOUNT_CREATE`, `SYSTEM_*`, etc.) -- the closed action vocabulary is ~30-60 verbs across 7 prefix classes.

## Field inventory

| JSON path (inside `imperva` string) | Type | XDM target candidate |
| --- | --- | --- |
| `$.audit_trail.event_action` | string (closed verb vocabulary) | `xdm.event.original_event_type`, `xdm.event.operation_sub_type`, drives `xdm.event.operation` |
| `$.audit_trail.event_action_description` | string | folded into `xdm.event.description` |
| `$.audit_trail.assumed_by` | email string | folded into `xdm.event.description` |
| `$.audit_trail.resource_type` | enum (Site/User/Policy/SSL/Account/Rule/System) | `xdm.target.resource.type` |
| `$.audit_trail.resource_id` | string | `xdm.target.resource.id` |
| `$.audit_trail.resource_name` | string | `xdm.target.resource.name` (and `xdm.target.host.hostname` when type is Site) |
| `$.audit_trail.event_context` | string | folded into description |
| `$.ids.account_id` | string | `xdm.target.resource.parent_id` |
| `$.ids.account_name` | string | folded into description |
| `$.ids.site_id` | string | folded into description |

Plus from the `user` column:

| Path | Type | XDM target |
| --- | --- | --- |
| `user $.email` | email string | `xdm.source.user.username`, mirrored to `xdm.target.user.username` |

## Pattern selection

`_raw_log` is null; `imperva` and `user` are pre-parsed top-level columns. Per the decision tree in [extraction-patterns.md](../extraction-patterns.md): `_raw_log` is empty, top-level columns hold JSON strings -> Pattern A (with `to_string()` wrap).

This is the JSON-string complement to Pattern D. Both share the "_raw_log is null" precondition, and the distinction lives in the column's runtime type:

- Pattern A -- the column is a JSON STRING. You need `json_extract_scalar(to_string(<column>), "$.path")` because the serialised JSON must be re-parsed at read time. The `to_string()` cast is defensive: the column's declared type may not be `string`, but `json_extract_scalar` requires a string argument.
- Pattern D -- the column is a typed OBJECT (the parser already decoded the JSON). You use the arrow operator `<column> -> Path.Subfield`. No `json_extract_scalar`, no cast.

Using the wrong tool produces silent nulls -- `json_extract_scalar` on a typed Object returns null, arrow on a JSON string returns null. Pick the right tool by inspecting the column's runtime shape in a sample query (`dataset = X | limit 1 | fields imperva` shows you whether it renders as `{...}` typed-object or as a stringified `"{\"...\":...}"`).

> Aside on the parser's own labelling. The Imperva pack's > `parser.xql` header notes that the payload shape is "pattern D" > -- that's using "pattern D" in the broader sense of "`_raw_log` is > null, fields pre-parsed". The MODEL extraction below is genuinely > Pattern A because the pre-parsed columns are JSON strings, not > typed objects. The two senses don't conflict; the parser is > describing the dataset shape, the model rule is describing the > extraction call shape.

## Field-anchor lookups

The Imperva audit-trail field names are mostly Imperva-specific (no canonical synonym matches expected). The well-known leaves do hit:

```sh
$ python3 scripts/lookup_anchor.py email
  -> xdm.source.user.upn  (score=624, freq=52)  [runner-up: xdm.source.user.username (score=190)]

$ python3 scripts/lookup_anchor.py assumed_by
  -> no candidate (Imperva-specific; route to xdm.event.description text)

$ python3 scripts/lookup_anchor.py resource_type
  -> xdm.target.resource.type  (score=128, freq=16)

$ python3 scripts/lookup_anchor.py resource_id
  -> xdm.target.resource.id  (score=144, freq=12)

$ python3 scripts/lookup_anchor.py resource_name
  -> xdm.target.resource.name  (score=140, freq=14)

$ python3 scripts/lookup_anchor.py account_id
  -> xdm.source.cloud.project_id  (score=84, freq=14)
```

Note `email`'s top candidate is `xdm.source.user.upn`, not `xdm.source.user.username` -- both are valid email sinks; the rule chose `username` here because Imperva treats this email as the account credential (login identifier) rather than the user-principal name in an identity-provider sense. Either choice would be accepted; this is a judgement call documented in [transformation-patterns.md](../transformation-patterns.md) "Companion field pairs".

## The MODEL derives everything from raw -- it never reads a parser anchor

The Imperva parser stamps two anchors that a MODEL rule must NOT read (Cortex rejects a parser-only `_` column as an unknown field, ERR-027):

- `tmp_action_class` -- the first underscore-separated token of `event_action`. Closed vocabulary: `SITE`, `USER`, `SSL`, `POLICY`, `LOGIN`, `ACCOUNT`, `SYSTEM`. Drives every per-class triage filter ("show me all SSL ops" -> `| filter tmp_action_class = "SSL"`).
- `tmp_resource_type` -- the resource taxonomy class (Site, User, Policy, SSL, Account, Rule, System). Pulled from the JSON.

The MODEL rule derives both on its own: `tmp_resource_type` from the JSON path, and `tmp_action_class` from the `event_action` prefix. It does not read the parser-stamped anchor of the same name -- Cortex validates a MODEL rule statically against the dataset schema, where parser-only `_` columns do not exist, so the read is rejected before any `coalesce()` fallback can run (ERR-027).

## The full rule

```
// Imperva Audit Trail -- XDM Data Model Rule
// Dataset: imperva_audittrail_raw
// Vendor: Imperva | Product: Cloud Application Security
//
// Maps Imperva Audit Trail SIEM events to the Cortex XDM schema.
// Records administrative actions on the Imperva console (sites, users,
// SSL, policy, login, system jobs).
//
// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later

[MODEL: dataset = imperva_audittrail_raw]

// -- Stage 1: Extract all fields from parsed columns ------------------------
alter
    tmp_event_action = json_extract_scalar(to_string(imperva), "$.audit_trail.event_action"),
    tmp_event_action_description = json_extract_scalar(to_string(imperva), "$.audit_trail.event_action_description"),
    tmp_assumed_by = json_extract_scalar(to_string(imperva), "$.audit_trail.assumed_by"),
    // `tmp_resource_type` is derived in full from the JSON path here. It is
    // NOT lifted from a parser-stamped `tmp_resource_type` anchor: Cortex
    // validates MODEL rules statically against the dataset schema, where
    // parser-only `_` columns are absent, so reading one is rejected as an
    // unknown field before any coalesce() fallback runs (ERR-027).
    // Vocabulary: ~8 closed values (Site, User, Policy, SSL, Account,
    // Rule, System) plus NULL on system-initiated rows.
    tmp_resource_type = json_extract_scalar(to_string(imperva), "$.audit_trail.resource_type"),
    tmp_resource_id = json_extract_scalar(to_string(imperva), "$.audit_trail.resource_id"),
    tmp_resource_name = json_extract_scalar(to_string(imperva), "$.audit_trail.resource_name"),
    tmp_event_context = json_extract_scalar(to_string(imperva), "$.audit_trail.event_context"),
    tmp_event_context_description = json_extract_scalar(to_string(imperva), "$.audit_trail.event_context_description"),
    tmp_account_id = json_extract_scalar(to_string(imperva), "$.ids.account_id"),
    tmp_account_name = json_extract_scalar(to_string(imperva), "$.ids.account_name"),
    tmp_site_id = json_extract_scalar(to_string(imperva), "$.ids.site_id"),
    tmp_user_email = json_extract_scalar(to_string(user), "$.email")

// -- Stage 2: Derive `tmp_action_class` from event_action (prefix) -------------
// `tmp_action_class` is derived in full from `tmp_event_action`. It is NOT lifted
// from a parser-stamped `tmp_action_class` anchor (ERR-027).
| alter
    tmp_action_class = if(tmp_event_action != null, arrayindex(split(tmp_event_action, "_"), 0))

// -- Stage 3: Build description summary string ------------------------------
| alter
    tmp_description = concat(
        coalesce(tmp_event_action_description, tmp_event_action, "Unknown action"),
        if(tmp_action_class != null, concat(" | Class: ", tmp_action_class), ""),
        " | Context: ", coalesce(tmp_event_context_description, tmp_event_context, "unknown"),
        if(tmp_assumed_by != null, concat(" | Assumed by: ", tmp_assumed_by), ""),
        " | Account: ", coalesce(tmp_account_name, tmp_account_id, "unknown"),
        if(tmp_site_id != null, concat(" | Site ID: ", tmp_site_id), ""))

// -- Stage 4: Map to XDM fields --------------------------------------------
| alter
    // XDM Observer fields -- xdm.observer.*
    xdm.observer.vendor = "Imperva",
    xdm.observer.product = "Cloud Application Security",

    // XDM Event fields -- xdm.event.*
    xdm.event.type = "AUDIT",
    xdm.event.description = tmp_description,
    xdm.event.original_event_type = tmp_event_action,
    xdm.event.operation_sub_type = tmp_event_action,
    xdm.event.operation = if(
        tmp_event_action contains "LOGIN" or tmp_event_action contains "SIGN_IN" or tmp_event_action contains "LOGGED_IN" or tmp_event_action contains "LOGGED_OUT", XDM_CONST.OPERATION_TYPE_AUTH_LOGIN,
        tmp_event_action contains "TWO_FACTOR" or tmp_event_action contains "AUTHENTICAT", XDM_CONST.OPERATION_TYPE_AUTH_MFA,
        tmp_event_action contains "CREAT" or tmp_event_action contains "_ADD" or tmp_event_action contains "SIGNUP" or tmp_event_action contains "UPLOAD", XDM_CONST.OPERATION_TYPE_CREATE,
        tmp_event_action contains "REMOV" or tmp_event_action contains "DELET" or tmp_event_action contains "PURG", XDM_CONST.OPERATION_TYPE_DELETE,
        tmp_event_action contains "UPDAT" or tmp_event_action contains "CHANG" or tmp_event_action contains "EDIT" or tmp_event_action contains "RESET", XDM_CONST.OPERATION_TYPE_UPDATE,
        tmp_event_action contains "CONFIG" or tmp_event_action contains "SETTING", XDM_CONST.OPERATION_TYPE_CONFIG_CHANGE,
        tmp_event_action contains "ENABL" or tmp_event_action contains "DISABL" or tmp_event_action contains "LOCK" or tmp_event_action contains "ACTIV", XDM_CONST.OPERATION_TYPE_STATUS_CHANGE,
        XDM_CONST.OPERATION_TYPE_AUDIT),

    // XDM Source fields -- xdm.source.* (who performed the action)
    xdm.source.user.username = tmp_user_email,

    // XDM Target Resource fields -- xdm.target.resource.* (what was acted upon)
    xdm.target.resource.type = tmp_resource_type,
    xdm.target.resource.name = tmp_resource_name,
    xdm.target.resource.id = tmp_resource_id,
    xdm.target.resource.parent_id = tmp_account_id,

    // XDM Target Host -- resource_name is an FQDN when resource_type is "Site"
    xdm.target.host.hostname = if(tmp_resource_type = "Site", tmp_resource_name),

    // XDM Target User -- mirrored from source (only one user in payload)
    xdm.target.user.username = tmp_user_email;
```

## Key decisions called out

- `to_string(<column>)` wrap is mandatory. Every read goes through `json_extract_scalar(to_string(imperva), ...)` not `json_extract_scalar(imperva, ...)`. The column's declared XSIAM type may not be `string` (it can be a boxed JSON), and `json_extract_scalar` requires a string first argument. Omitting the cast surfaces as a generic parser error with no useful pointer -- see [parser-idioms.md](../parser-idioms.md) ERR-018 for the related cast doctrine on arrays.
- `xdm.event.operation` classifier on the verb suffix. Instead of a 60-entry switch over every `event_action` code, the rule pattern-matches on substring tokens (`LOGIN`, `CREAT`, `REMOV`, etc.) to land each verb in the right `OPERATION_TYPE_*` constant. Closes the long-tail case where Imperva adds a new verb code: as long as it contains a known token like `CREATE`, it routes to `OPERATION_TYPE_CREATE`. Otherwise falls through to `OPERATION_TYPE_AUDIT`.
- `xdm.event.type = "AUDIT"` (normalised category). All Imperva audit-trail events are administrative; the normalised category is `AUDIT`. Per workflow step 5 in [workflow.md](../workflow.md), `xdm.event.type` MUST be one of the documented normalised categories -- not the raw vendor event name.
- One user, mirrored. The Imperva payload includes only one user (the admin who performed the action). That user is both source (the actor) and target (since admin actions on user resources implicate themselves). One-sided actor mirroring per [transformation-patterns.md](../transformation-patterns.md): map the same `tmp_user_email` to both `xdm.source.user.username` and `xdm.target.user.username`.
- `xdm.target.host.hostname` only when resource is a Site. `tmp_resource_name` is generic -- it's a site FQDN when `tmp_resource_type = "Site"`, a user email when type is `User`, a policy name when type is `Policy`, etc. The conditional assignment routes the FQDN to its semantic XDM home only when the type discriminator confirms.
- `xdm.target.resource.parent_id = tmp_account_id`. Imperva resources live under an account; the account ID is the resource's organisational parent. Maps to the explicit `parent_id` field rather than overloading another path.
- Both triage temps are derived, not read. `tmp_resource_type` comes from the JSON path and `tmp_action_class` from the `event_action` prefix, so the rule does not depend on the parser having stamped an anchor column of the same name. That is not a preference: a MODEL rule is validated statically against the dataset schema, where parser-only `_` columns do not exist, so reading one is rejected as an unknown field before any `coalesce()` fallback could run (ERR-027). Deriving is also what lets historical rows ingested before the parser shipped model identically.
