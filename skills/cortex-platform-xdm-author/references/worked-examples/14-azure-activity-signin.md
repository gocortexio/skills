<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Walkthrough 14 -- Azure Activity + Entra ID sign-in

Vendor / product: Microsoft / Azure. Dataset: `microsoft_azure_raw`, JSON.

What this walkthrough shows: two Azure record shapes through one rule -- the
Azure Activity log (management plane: `operationName`, `resultType`) and the
Entra ID (Azure AD) sign-in (`userPrincipalName`, `status.errorCode`). Both map
on the cloud model from [cloud-mapping.md](../cloud-mapping.md): the Activity
verb is derived from the `operationName` suffix (`/write` -> UPDATE, `/delete`
-> DELETE, `/read` -> READ, `/action` -> EXECUTION); a sign-in is the
AUTHENTICATION story on a cloud plane. Classified per record with a catch-all.

## The full rule

```
[MODEL: dataset = microsoft_azure_raw]
filter
    _raw_log != null
| alter
    tmp_op        = json_extract_scalar(_raw_log, "$.operationName"),
    tmp_result    = json_extract_scalar(_raw_log, "$.resultType"),
    tmp_category  = json_extract_scalar(_raw_log, "$.category"),
    tmp_caller    = json_extract_scalar(_raw_log, "$.caller"),
    tmp_caller_ip = json_extract_scalar(_raw_log, "$.callerIpAddress"),
    tmp_resource  = json_extract_scalar(_raw_log, "$.resourceId"),
    tmp_upn       = json_extract_scalar(_raw_log, "$.userPrincipalName"),
    tmp_signin_ip = json_extract_scalar(_raw_log, "$.ipAddress"),
    tmp_app       = json_extract_scalar(_raw_log, "$.appDisplayName"),
    tmp_client    = json_extract_scalar(_raw_log, "$.clientAppUsed"),
    tmp_signin_err = json_extract_scalar(_raw_log, "$.status.errorCode")
| alter
    tmp_op_provider = arrayindex(regextract(to_string(tmp_op), "^([^/]+)/"), 0),
    tmp_user = coalesce(tmp_caller, tmp_upn),
    tmp_ip = coalesce(tmp_caller_ip, tmp_signin_ip),
    tmp_is_signin = if(tmp_upn != null, "y")
| alter
    xdm.event.type = coalesce(tmp_category, tmp_op_provider, "azure"),
    xdm.event.original_event_type = coalesce(tmp_op, if(tmp_is_signin = "y", "Sign-in activity"), "GOCORTEX_UNMODELLED"),
    xdm.event.operation = if(
        tmp_op ~= "/write$", XDM_CONST.OPERATION_TYPE_UPDATE,
        tmp_op ~= "/delete$", XDM_CONST.OPERATION_TYPE_DELETE,
        tmp_op ~= "/read$", XDM_CONST.OPERATION_TYPE_READ,
        tmp_op ~= "/action$", XDM_CONST.OPERATION_TYPE_EXECUTION,
        tmp_is_signin = "y", XDM_CONST.OPERATION_TYPE_AUTH_LOGIN),
    xdm.event.tags = if(
        tmp_is_signin = "y", arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION, XDM_CONST.EVENT_TAG_CLOUD),
        tmp_op != null, arraycreate(XDM_CONST.EVENT_TAG_CLOUD),
        null),
    xdm.event.outcome = if(
        tmp_result = "Success", XDM_CONST.OUTCOME_SUCCESS,
        tmp_result ~= "^(Failure|Failed)", XDM_CONST.OUTCOME_FAILED,
        tmp_is_signin = "y" and tmp_signin_err = "0", XDM_CONST.OUTCOME_SUCCESS,
        tmp_is_signin = "y" and tmp_signin_err != null, XDM_CONST.OUTCOME_FAILED),
    xdm.event.description = concat(
        coalesce(tmp_op, "sign-in"), " by ", coalesce(tmp_user, "?"),
        if(tmp_resource != null, concat(" on ", tmp_resource), "")),
    xdm.source.cloud.provider = XDM_CONST.CLOUD_PROVIDER_AZURE,
    xdm.source.ipv4 = if(tmp_ip ~= "^\d+\.\d+\.\d+\.\d+$", tmp_ip, null),
    xdm.source.ipv6 = if(to_string(tmp_ip) ~= ":", tmp_ip, null),
    xdm.source.port = to_integer(0),
    xdm.target.ipv4 = coalesce("", ""),
    xdm.target.port = to_integer(0),
    xdm.target.resource.name = if(tmp_is_signin = "y", coalesce(tmp_app, tmp_resource)),
    xdm.network.ip_protocol = XDM_CONST.IP_PROTOCOL_TCP,
    xdm.source.user.username = tmp_user,
    // Identity mirror (recommended tier): same derivations, appended beside user.* -- never instead of it.
    xdm.source.identity.username = tmp_user,
    xdm.source.user.upn = if(
        tmp_user contains "@", tmp_user,
        tmp_user != null, concat(tmp_user, "@azure")),
    xdm.source.identity.upn = if(
        tmp_user contains "@", tmp_user,
        tmp_user != null, concat(tmp_user, "@azure")),
    xdm.source.user.identity_type = if(
        tmp_user != null, XDM_CONST.IDENTITY_TYPE_USER,
        XDM_CONST.IDENTITY_TYPE_UNKNOWN),
    xdm.source.identity.identity_type = if(
        tmp_user != null, XDM_CONST.IDENTITY_TYPE_USER,
        XDM_CONST.IDENTITY_TYPE_UNKNOWN),
    xdm.source.user.user_type = if(
        lowercase(to_string(tmp_user)) ~= "^svc[-_.]|service", XDM_CONST.USER_TYPE_SERVICE_ACCOUNT,
        XDM_CONST.USER_TYPE_REGULAR),
    xdm.source.identity.user_type = if(
        lowercase(to_string(tmp_user)) ~= "^svc[-_.]|service", XDM_CONST.USER_TYPE_SERVICE_ACCOUNT,
        XDM_CONST.USER_TYPE_REGULAR),
    xdm.auth.service = if(tmp_is_signin = "y", "IDP"),
    xdm.network.http.browser = if(tmp_is_signin = "y", tmp_client),
    xdm.observer.vendor = "Microsoft",
    xdm.observer.product = "Azure"
;
// REVIEW UNMODELLED -- list records this rule could not classify and
// grow it to cover them:
//   datamodel dataset = microsoft_azure_raw
//   | filter xdm.event.original_event_type = "GOCORTEX_UNMODELLED"
//   | fields xdm.event.original_event_type, microsoft_azure_raw._raw_log
//
// RAISE SKILL ISSUES -- report a mis-mapping (include the REVIEW
// UNMODELLED output above): https://github.com/gocortexio/skills/issues
```

## Key decisions worth copying

- The verb from the operationName suffix. Azure encodes the verb as the last
  segment of `Provider/type/<verb>`: `/write` -> UPDATE (a first write is not
  distinguished from an update, so UPDATE is the safe generic), `/delete` ->
  DELETE, `/read` -> READ, `/action` -> EXECUTION. The provider prefix
  (`Microsoft.Compute`) becomes the source-service label.
- Two shapes, one rule. A record with `operationName` is a management event
  (CLOUD); a record with `userPrincipalName` is a sign-in (AUTHENTICATION +
  CLOUD, auth mandatory set padded). The `tmp_is_signin` discriminator drives
  type / tags / operation / outcome; an unrecognised record hits the catch-all.
- Outcome per shape. Activity uses `resultType` (`Success` / `Failure`; `Start`
  and `Accepted` are in-progress and get no outcome). A sign-in uses
  `status.errorCode`: `0` is success, any other code is a failed sign-in.
- Shared identity / address. `coalesce(caller, userPrincipalName)` and
  `coalesce(callerIpAddress, ipAddress)` unify the two shapes onto one drain,
  and the IPv4 map is gated on a dotted-quad shape.
- Cloud entity. `provider = CLOUD_PROVIDER_AZURE`; `cloud.service`
  (CLOUD_SERVICE_TYPE) is not set. The raw provider prefix already surfaces in
  `xdm.event.type` (the `coalesce(tmp_category, tmp_op_provider, ...)` fallback),
  so it is not routed to `xdm.source.cloud.source_type` -- a banned XCloud asset
  field (lint ERR-029). See [banned-fields.md](../banned-fields.md).

## NOT MAPPED, with reasons

```
NOT MAPPED
  properties.* -- per-operation free-form detail (request body, SKU, ...); map a
                  specific field only when it has a worked XDM target
  conditionalAccessStatus / riskState / riskDetail (sign-in) -- Entra risk
                  posture; revisit under an auth-risk mapping, not a core field
  correlationId / tenantId -- correlation ids; add to session / cloud fields
                  when correlating a request chain
  cloud.service (CLOUD_SERVICE_TYPE) -- not completable; raw provider already in
                  xdm.event.type (never xdm.source.cloud.source_type, a banned field)
```

## Checklist

```
[ ] only filter is _raw_log != null (nothing dropped)
[ ] Activity verb DERIVED from the operationName suffix; sign-in -> AUTH_LOGIN
[ ] sign-in tagged AUTHENTICATION + CLOUD, auth mandatory set padded
[ ] outcome: resultType for Activity, status.errorCode==0 for sign-in
[ ] shared caller/upn and callerIpAddress/ipAddress via coalesce
[ ] cloud.provider = AZURE; cloud.service omitted; raw provider in event.type (not source_type)
[ ] unknown record -> GOCORTEX_UNMODELLED; proven with verify_rule.py
```
