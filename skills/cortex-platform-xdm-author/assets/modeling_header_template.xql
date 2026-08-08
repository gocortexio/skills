// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Canonical comment order for every emitted rule: (1) SPDX licence at the
// very TOP, (2) provenance block, (3) identity + description, (4) field
// mapping + NOT MAPPED, (5) REVIEW UNMODELLED, (6) RAISE SKILL ISSUES --
// then the [MODEL: ...] body. Keep this order for predictability.
//
// Generated via
// GOCORTEX_SKILLS_MODEL="<model id>"
// GOCORTEX_SKILLS_SKILL_NAME="cortex-platform-xdm-author"
// GOCORTEX_SKILLS_SKILL_VERSION="2.0.0"
// GOCORTEX_SKILLS_SKILL_WARNING_COUNT="<lint warning count>"
// GOCORTEX_SKILLS_SOURCE_BASIS="<spec-backed | sample-only>"
//
// <Vendor> <Product> -- XDM Data Model Rule
// Dataset: <vendor>_<product>_raw
// Vendor: <Vendor> | Product: <Product>
//
// One-paragraph description: explain what this rule does. Standard shape:
// "Maps <Vendor> <Product> <log family> events to the Cortex XDM schema.
// The <product> emits <event count> distinct event types from <single | N
// log shapes>; this rule normalises them into XDM for cross-source
// correlation."
//
// A MODEL rule derives every value from the raw dataset columns (or
// _raw_log). It never reads a parser-stamped `_` anchor column, not even
// behind a coalesce() fallback: Cortex validates a MODEL rule against the
// dataset schema, where parser-only `_` anchors do not exist, so the read
// is rejected as an unknown field before the fallback can run. ERR-027.
//
// ALERT / EVENT FIELD MAPPING
// ---------------------------
// (Use "ALERT / EVENT FIELD MAPPING" for modelling rules; use "SOURCE
// FIELD MAPPING" for parsing rules. Group related rows with short
// sub-headings: Observer, Event identity, Source, Target, Alert, etc.)
//
// Observer
//   (hardcoded)           -> xdm.observer.vendor
//   (hardcoded)           -> xdm.observer.product
//
// Event identity
//   <vendor_field_1>      -> xdm.event.id, xdm.alert.original_alert_id
//   <vendor_event_type>   -> xdm.event.type (normalised), xdm.event.original_event_type (raw)
//   <vendor_outcome>      -> xdm.event.outcome (XDM_CONST), xdm.observer.action (raw)
//
// Source identity
//   <vendor_src_ip>       -> xdm.source.ipv4
//   <vendor_src_host>     -> xdm.source.host.hostname, xdm.source.host.fqdn
//   <vendor_src_user>     -> xdm.source.user.username, xdm.source.user.upn
//
// Target identity (mirror from source if this is a one-sided detection)
//   <vendor_tgt_ip>       -> xdm.target.ipv4
//   <vendor_tgt_host>     -> xdm.target.host.hostname
//   <vendor_tgt_user>     -> xdm.target.user.username
//
// Alert (if applicable)
//   <vendor_score>        -> xdm.alert.severity (banded), xdm.event.log_level (XDM_CONST.LOG_LEVEL_*)
//   <vendor_category>     -> xdm.alert.category (XDM_CONST.THREAT_CATEGORY_*) or xdm.alert.subcategory (raw)
//   <vendor_name>         -> xdm.alert.name, xdm.alert.original_threat_name
//   <vendor_mitre>        -> xdm.alert.mitre_tactics, xdm.alert.mitre_techniques (when explicit)
//
// Description
//   composed               -> xdm.event.description (concat of identifying fields)
//
// NOT MAPPED
//   <vendor_field_X>      -- <reason, e.g. "no XDM_CONST matches; vendor classification only">
//   <vendor_field_Y>      -- <reason, e.g. "tenant identifier; implicit from dataset">
//   _time                 -- Cortex sets _time automatically in MODEL rules
//   xdm.alert.mitre_techniques -- (only if _gc_raw dataset) WARN-023 blocking on _gc_raw; mitre_tactics only
//
// REVIEW UNMODELLED -- after deploying, list what this rule could not
// classify, and grow it to cover those records:
//   datamodel dataset = <vendor>_<product>_raw
//   | filter xdm.event.original_event_type = "GOCORTEX_UNMODELLED"
//   | fields xdm.event.original_event_type, <vendor>_<product>_raw._raw_log
//
// RAISE SKILL ISSUES -- if this rule mis-modelled something, please open
// an issue and include the REVIEW UNMODELLED output above:
//   https://github.com/gocortexio/skills/issues

[MODEL: dataset=<vendor>_<product>_raw]
filter
    _raw_log != null
| alter
    // Stage 1: extract from _raw_log using the relevant pattern (A/B/C/D).
    tmp_<vendor_field_1> = json_extract_scalar(_raw_log, "$.<path_1>"),
    tmp_<vendor_field_2> = json_extract_scalar(_raw_log, "$.<path_2>")
| alter
    // Stage 2: derive composite fields (banded scores, actor projections,
    // categorical enum routing). One alter per logical step keeps sibling
    // refs out of the same stage (parser idiom (xi)).
    tmp_severity = if(
        tmp_<score> >= 80, "Critical",
        tmp_<score> >= 50, "High",
        tmp_<score> >= 30, "Medium",
        tmp_<score> != null, "Low")
| alter
    // Stage 3: assign XDM fields using the extracted temps.
    xdm.observer.vendor = "<Vendor>",
    xdm.observer.product = "<Product>",
    xdm.event.type = "<NORMALISED_CATEGORY>",                  // ALERT/NETWORK/AUTH/EMAIL/FILE/PROCESS/ENDPOINT_ACTIVITY/AUDIT
    xdm.event.original_event_type = tmp_<vendor_event_type>,
    xdm.event.id = tmp_<vendor_field_1>,
    xdm.alert.original_alert_id = tmp_<vendor_field_1>,           // companion pair with xdm.event.id
    xdm.alert.severity = tmp_severity,
    xdm.event.log_level = if(
        tmp_<score> >= 80, XDM_CONST.LOG_LEVEL_CRITICAL,
        tmp_<score> >= 50, XDM_CONST.LOG_LEVEL_ERROR,
        tmp_<score> >= 30, XDM_CONST.LOG_LEVEL_WARNING,
        tmp_<score> != null, XDM_CONST.LOG_LEVEL_INFORMATIONAL)
    // ... additional xdm.* assignments
;
