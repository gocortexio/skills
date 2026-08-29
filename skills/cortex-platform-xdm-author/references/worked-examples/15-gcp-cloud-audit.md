<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Walkthrough 15 -- GCP Cloud Audit Logs

Vendor / product: Google / Cloud Audit Logs. Dataset: `gcp_cloud_audit_raw`,
JSON (the `protoPayload` envelope).

What this walkthrough shows: GCP Cloud Audit records nest the meaningful fields
under `protoPayload`, and the action lives in `methodName`
(`google.iam.admin.v1.CreateServiceAccount`, `storage.buckets.delete`,
`SetIamPolicy`). The rule derives the operation verb from the last segment of
`methodName` (falling back to the whole value for a dotless name like
`SetIamPolicy`), maps the identity from `authenticationInfo.principalEmail`, and
tags the record CLOUD. Mapped on the cloud model from
[cloud-mapping.md](../cloud-mapping.md), authored from GCP's own method-naming
convention and the XDM schema.

## The full rule

```
[MODEL: dataset = gcp_cloud_audit_raw]
filter
    _raw_log != null
| alter
    tmp_method  = json_extract_scalar(_raw_log, "$.protoPayload.methodName"),
    tmp_service = json_extract_scalar(_raw_log, "$.protoPayload.serviceName"),
    tmp_princ   = json_extract_scalar(_raw_log, "$.protoPayload.authenticationInfo.principalEmail"),
    tmp_ip      = json_extract_scalar(_raw_log, "$.protoPayload.requestMetadata.callerIp"),
    tmp_ua      = json_extract_scalar(_raw_log, "$.protoPayload.requestMetadata.callerSuppliedUserAgent"),
    tmp_res     = json_extract_scalar(_raw_log, "$.protoPayload.resourceName"),
    tmp_status  = json_extract_scalar(_raw_log, "$.protoPayload.status.code"),
    tmp_project = json_extract_scalar(_raw_log, "$.resource.labels.project_id")
| alter
    tmp_verb = lowercase(to_string(coalesce(arrayindex(regextract(to_string(tmp_method), "\.([^.]+)$"), 0), tmp_method)))
| alter
    xdm.event.type = coalesce(tmp_service, "gcp"),
    xdm.event.original_event_type = coalesce(tmp_method, "GOCORTEX_UNMODELLED"),
    xdm.event.operation = if(
        tmp_verb ~= "^(create|insert)", XDM_CONST.OPERATION_TYPE_CREATE,
        tmp_verb ~= "^(delete|remove)", XDM_CONST.OPERATION_TYPE_DELETE,
        tmp_verb ~= "^(get|list|aggregated)", XDM_CONST.OPERATION_TYPE_READ,
        tmp_verb ~= "^(update|patch|set)", XDM_CONST.OPERATION_TYPE_UPDATE),
    xdm.event.tags = if(tmp_method != null, arraycreate(XDM_CONST.EVENT_TAG_CLOUD), null),
    xdm.event.outcome = if(
        tmp_status != null and tmp_status != "0", XDM_CONST.OUTCOME_FAILED,
        tmp_method != null, XDM_CONST.OUTCOME_SUCCESS),
    xdm.event.description = concat(coalesce(tmp_method, "gcp"), " on ", coalesce(tmp_res, "?")),
    xdm.source.cloud.provider = XDM_CONST.CLOUD_PROVIDER_GCP,
    xdm.source.cloud.project_id = tmp_project,
    xdm.source.ipv4 = if(tmp_ip ~= "^\d+\.\d+\.\d+\.\d+$", tmp_ip, null),
    xdm.source.ipv6 = if(to_string(tmp_ip) ~= ":", tmp_ip, null),
    xdm.source.user.username = tmp_princ,
    // Identity mirror (recommended tier): same derivations, appended beside user.* -- never instead of it.
    xdm.source.identity.username = tmp_princ,
    xdm.source.user.upn = if(
        tmp_princ contains "@", tmp_princ,
        tmp_princ != null, concat(tmp_princ, "@gcp")),
    xdm.source.identity.upn = if(
        tmp_princ contains "@", tmp_princ,
        tmp_princ != null, concat(tmp_princ, "@gcp")),
    xdm.source.user.identity_type = if(
        to_string(tmp_princ) ~= "gserviceaccount", XDM_CONST.IDENTITY_TYPE_MACHINE,
        tmp_princ != null, XDM_CONST.IDENTITY_TYPE_USER,
        XDM_CONST.IDENTITY_TYPE_UNKNOWN),
    xdm.source.identity.identity_type = if(
        to_string(tmp_princ) ~= "gserviceaccount", XDM_CONST.IDENTITY_TYPE_MACHINE,
        tmp_princ != null, XDM_CONST.IDENTITY_TYPE_USER,
        XDM_CONST.IDENTITY_TYPE_UNKNOWN),
    xdm.source.user.user_type = if(
        to_string(tmp_princ) ~= "gserviceaccount", XDM_CONST.USER_TYPE_SERVICE_ACCOUNT,
        XDM_CONST.USER_TYPE_REGULAR),
    xdm.source.identity.user_type = if(
        to_string(tmp_princ) ~= "gserviceaccount", XDM_CONST.USER_TYPE_SERVICE_ACCOUNT,
        XDM_CONST.USER_TYPE_REGULAR),
    xdm.source.user_agent = tmp_ua,
    xdm.observer.vendor = "Google",
    xdm.observer.product = "Cloud Audit Logs"
;
// REVIEW UNMODELLED -- list records this rule could not classify and
// grow it to cover them:
//   datamodel dataset = gcp_cloud_audit_raw
//   | filter xdm.event.original_event_type = "GOCORTEX_UNMODELLED"
//   | fields xdm.event.original_event_type, gcp_cloud_audit_raw._raw_log
//
// RAISE SKILL ISSUES -- report a mis-mapping (include the REVIEW
// UNMODELLED output above): https://github.com/gocortexio/skills/issues
```

## Key decisions worth copying

- The verb from the methodName tail, dotless-safe. Take the segment after the
  last dot (`storage.buckets.delete` -> `delete`) and fall back to the whole
  value when there is no dot (`SetIamPolicy` -> `setiampolicy`), then match the
  lowercased convention: create/insert -> CREATE, delete/remove -> DELETE,
  get/list/aggregated -> READ, update/patch/set -> UPDATE. `SetIamPolicy` maps to
  UPDATE (a permission change), `GetIamPolicy` to READ.
- Everything is under protoPayload. `methodName`, `serviceName`,
  `authenticationInfo.principalEmail`, `requestMetadata.callerIp`, `status.code`
  are all deep paths -- ordinary `json_extract_scalar` reaches them.
- Outcome from status.code. GCP omits `status` on success, so a missing or `0`
  code is SUCCESS and any non-zero code (e.g. `7` PERMISSION_DENIED) is FAILED.
- Service-account identity. A `principalEmail` ending in `gserviceaccount.com`
  is a machine identity (`IDENTITY_TYPE_MACHINE` / `USER_TYPE_SERVICE_ACCOUNT`);
  a human principal is a regular user.
- Cloud entity. `provider = CLOUD_PROVIDER_GCP`, `project_id` from
  `resource.labels.project_id`; `cloud.service` (CLOUD_SERVICE_TYPE) is not set.
  The raw `serviceName` already surfaces in `xdm.event.type` (the
  `coalesce(tmp_service, "gcp")` drain), so it is not routed to
  `xdm.source.cloud.source_type` -- a banned XCloud asset field (lint ERR-029).
  See [banned-fields.md](../banned-fields.md).
- Cloud Audit is management-plane. Every record is CLOUD (no auth tag); GCP
  interactive sign-ins arrive on a different feed, so there is no auth branch
  here and no transport tuple to pad.

## NOT MAPPED, with reasons

```
NOT MAPPED
  protoPayload.request / response -- per-method free-form bodies; map a specific
                      field only when it has a worked XDM target
  protoPayload.authorizationInfo[] -- an array of permission grants/denials;
                      reach an element with arrayindex(json_extract_array(...), N)
  resource.labels.* (beyond project_id) -- zone / location / instance labels;
                      add region/zone when the sample carries them
  cloud.service (CLOUD_SERVICE_TYPE) -- not completable; raw serviceName already in
                      xdm.event.type (never xdm.source.cloud.source_type, a banned field)
```

## Checklist

```
[ ] only filter is _raw_log != null (nothing dropped)
[ ] verb DERIVED from the methodName tail, with a dotless fallback (SetIamPolicy)
[ ] deep protoPayload.* paths; principalEmail -> user; callerIp -> ipv4
[ ] outcome: missing/0 status.code -> SUCCESS, non-zero -> FAILED
[ ] gserviceaccount principal -> machine identity / service account
[ ] cloud.provider = GCP; project_id set; raw service in event.type (not source_type)
[ ] unknown record -> GOCORTEX_UNMODELLED; proven with verify_rule.py
```
