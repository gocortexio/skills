<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Walkthrough 13 -- AWS CloudTrail, many API actions through one rule

Vendor / product: Amazon / AWS CloudTrail. Dataset: `aws_cloudtrail_raw`,
JSON management-plane audit events.

What this walkthrough shows: CloudTrail emits one record shape for thousands of
API actions, so the mapping is driven by the DERIVED action verb, not a
per-action lookup. One rule classifies each record on the cloud model from
[cloud-mapping.md](../cloud-mapping.md): `xdm.event.type` = the service
(`eventSource`), `xdm.event.original_event_type` = the raw `eventName`,
`xdm.event.operation` = the verb derived from the `eventName` naming convention,
and `xdm.event.tags` = CLOUD (plus AUTHENTICATION for a console login). A
`ConsoleLogin` is the authentication story on a cloud plane (it takes the auth
mandatory set); a management call is CLOUD; an unrecognised record gets the
catch-all. This mapping is authored from AWS's own action conventions and the
XDM schema -- not from any content pack.

## The full rule

```
[MODEL: dataset = aws_cloudtrail_raw]
filter
    _raw_log != null
| alter
    tmp_event   = json_extract_scalar(_raw_log, "$.eventName"),
    tmp_source  = json_extract_scalar(_raw_log, "$.eventSource"),
    tmp_id      = json_extract_scalar(_raw_log, "$.eventID"),
    tmp_region  = json_extract_scalar(_raw_log, "$.awsRegion"),
    tmp_account = json_extract_scalar(_raw_log, "$.recipientAccountId"),
    tmp_ip      = json_extract_scalar(_raw_log, "$.sourceIPAddress"),
    tmp_ua      = json_extract_scalar(_raw_log, "$.userAgent"),
    tmp_error   = coalesce(json_extract_scalar(_raw_log, "$.errorCode"), json_extract_scalar(_raw_log, "$.errorMessage")),
    tmp_console = json_extract_scalar(_raw_log, "$.responseElements.ConsoleLogin"),
    tmp_uid_type = json_extract_scalar(_raw_log, "$.userIdentity.type"),
    tmp_uid_name = coalesce(
        json_extract_scalar(_raw_log, "$.userIdentity.userName"),
        json_extract_scalar(_raw_log, "$.userIdentity.sessionContext.sessionIssuer.userName"),
        json_extract_scalar(_raw_log, "$.userIdentity.arn"))
| alter
    tmp_is_auth = if(tmp_event = "ConsoleLogin", "y", tmp_event ~= "^AssumeRole", "y")
| alter
    xdm.event.type = tmp_source,
    xdm.event.id = tmp_id,
    xdm.event.original_event_type = coalesce(tmp_event, "GOCORTEX_UNMODELLED"),
    xdm.event.operation = if(
        tmp_event = "ConsoleLogin", XDM_CONST.OPERATION_TYPE_AUTH_LOGIN,
        tmp_event ~= "^AssumeRole", XDM_CONST.OPERATION_TYPE_AUTH_LOGIN,
        tmp_event ~= "^(Create|Add|Register|Allocate|Provision|Run|Launch)", XDM_CONST.OPERATION_TYPE_CREATE,
        tmp_event ~= "^(Delete|Remove|Deregister|Release|Terminate|Revoke)", XDM_CONST.OPERATION_TYPE_DELETE,
        tmp_event ~= "^(Get|Describe|List|Lookup|Search|Query|Head|BatchGet)", XDM_CONST.OPERATION_TYPE_READ,
        tmp_event ~= "^(Update|Modify|Set|Put|Attach|Detach|Associate|Disassociate|Enable|Disable|Start|Stop|Reboot)", XDM_CONST.OPERATION_TYPE_UPDATE),
    xdm.event.tags = if(
        tmp_is_auth = "y", arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION, XDM_CONST.EVENT_TAG_CLOUD),
        tmp_event != null, arraycreate(XDM_CONST.EVENT_TAG_CLOUD),
        null),
    xdm.event.outcome = if(
        tmp_error != null, XDM_CONST.OUTCOME_FAILED,
        tmp_console = "Success", XDM_CONST.OUTCOME_SUCCESS,
        tmp_console = "Failure", XDM_CONST.OUTCOME_FAILED,
        tmp_event != null, XDM_CONST.OUTCOME_SUCCESS),
    xdm.event.outcome_reason = tmp_error,
    xdm.event.description = concat(coalesce(tmp_event, "?"), " on ", coalesce(tmp_source, "aws")),
    xdm.source.cloud.provider = XDM_CONST.CLOUD_PROVIDER_AWS,
    xdm.source.cloud.region = tmp_region,
    xdm.source.cloud.project_id = tmp_account,
    xdm.source.ipv4 = if(tmp_ip ~= "^\d+\.\d+\.\d+\.\d+$", tmp_ip, null),
    xdm.source.ipv6 = if(to_string(tmp_ip) ~= ":", tmp_ip, null),
    xdm.source.port = to_integer(0),
    xdm.target.ipv4 = coalesce("", ""),
    xdm.target.port = to_integer(0),
    xdm.target.resource.name = if(tmp_is_auth = "y", tmp_source),
    xdm.network.ip_protocol = XDM_CONST.IP_PROTOCOL_TCP,
    xdm.source.user.username = tmp_uid_name,
    // Identity mirror (recommended tier): same derivations, appended beside user.* -- never instead of it.
    xdm.source.identity.username = tmp_uid_name,
    xdm.source.user.upn = if(
        tmp_uid_name contains "@", tmp_uid_name,
        tmp_uid_name != null and tmp_account != null, concat(tmp_uid_name, "@", tmp_account, ".aws"),
        tmp_uid_name != null, concat(tmp_uid_name, "@aws")),
    xdm.source.identity.upn = if(
        tmp_uid_name contains "@", tmp_uid_name,
        tmp_uid_name != null and tmp_account != null, concat(tmp_uid_name, "@", tmp_account, ".aws"),
        tmp_uid_name != null, concat(tmp_uid_name, "@aws")),
    xdm.source.user.identity_type = if(
        tmp_uid_type contains "Service", XDM_CONST.IDENTITY_TYPE_MACHINE,
        tmp_uid_type = "Root", XDM_CONST.IDENTITY_TYPE_BUILTIN,
        tmp_uid_name != null, XDM_CONST.IDENTITY_TYPE_USER,
        XDM_CONST.IDENTITY_TYPE_UNKNOWN),
    xdm.source.identity.identity_type = if(
        tmp_uid_type contains "Service", XDM_CONST.IDENTITY_TYPE_MACHINE,
        tmp_uid_type = "Root", XDM_CONST.IDENTITY_TYPE_BUILTIN,
        tmp_uid_name != null, XDM_CONST.IDENTITY_TYPE_USER,
        XDM_CONST.IDENTITY_TYPE_UNKNOWN),
    xdm.source.user.user_type = if(
        tmp_uid_type contains "Service", XDM_CONST.USER_TYPE_MACHINE_ACCOUNT,
        XDM_CONST.USER_TYPE_REGULAR),
    xdm.source.identity.user_type = if(
        tmp_uid_type contains "Service", XDM_CONST.USER_TYPE_MACHINE_ACCOUNT,
        XDM_CONST.USER_TYPE_REGULAR),
    xdm.auth.service = if(tmp_is_auth = "y", "IDP"),
    xdm.source.user_agent = tmp_ua,
    xdm.observer.vendor = "Amazon",
    xdm.observer.product = "CloudTrail"
;
// REVIEW UNMODELLED -- list records this rule could not classify and
// grow it to cover them:
//   datamodel dataset = aws_cloudtrail_raw
//   | filter xdm.event.original_event_type = "GOCORTEX_UNMODELLED"
//   | fields xdm.event.original_event_type, aws_cloudtrail_raw._raw_log
//
// RAISE SKILL ISSUES -- report a mis-mapping (include the REVIEW
// UNMODELLED output above): https://github.com/gocortexio/skills/issues
```

## Key decisions worth copying

- The verb is DERIVED from the eventName convention. `Create*`->CREATE,
  `Delete*`->DELETE, `Get/Describe/List*`->READ, `Update/Put/Set/Attach*`->UPDATE,
  `ConsoleLogin`/`AssumeRole*`->AUTH_LOGIN. One convention chain covers thousands
  of actions correctly; the raw action is preserved in
  `xdm.event.original_event_type` so nothing is lost. This is the improvement
  over hardcoding a handful of sample actions.
- Console login is the auth story on a cloud plane. `ConsoleLogin` /
  `AssumeRole*` carry BOTH `EVENT_TAG_AUTHENTICATION` and `EVENT_TAG_CLOUD` and
  the auth mandatory set (the transport tuple is padded -- a console login has no
  L4 flow); a management API call is CLOUD only.
- Outcome precedence. An `errorCode` / `errorMessage` means FAILED regardless of
  action; otherwise the `responseElements.ConsoleLogin` verdict, otherwise a
  successful action. `errorCode` is preserved in `xdm.event.outcome_reason`.
- The sourceIPAddress guard. CloudTrail puts an AWS service DNS name
  (`s3.amazonaws.com`) in `sourceIPAddress` for service-initiated calls, so the
  IPv4 map is gated on a dotted-quad shape -- the service name can never land in
  `xdm.source.ipv4`.
- Cloud entity. `xdm.source.cloud.provider = CLOUD_PROVIDER_AWS`,
  `region` = `awsRegion`, `project_id` = `recipientAccountId`. `xdm.source.cloud.service`
  is deliberately NOT set (the CLOUD_SERVICE_TYPE enum is not completable), and the
  raw service name (`eventSource`) is carried in `xdm.event.description` rather than a
  String field -- `xdm.source.cloud.source_type` is a banned XCloud asset field
  (lint ERR-029). See [cloud-mapping.md](../cloud-mapping.md) and
  [banned-fields.md](../banned-fields.md).
- Identity from the nested userIdentity. `userName`, then the assumed-role
  session issuer, then the ARN -- via `coalesce` over the deep paths.

## NOT MAPPED, with reasons

```
NOT MAPPED
  requestParameters.* / responseElements.* (beyond ConsoleLogin) -- per-service
                      free-form; map a specific field only when a worked target
                      exists (e.g. a bucket name -> xdm.target.resource)
  resources[] -- an array of acted-on resources; reach an element with
                      arrayindex(json_extract_array(...), N), map the ARN to a
                      target field when a single clear resource applies
  additionalEventData / tlsDetails -- session / TLS metadata with no primary
                      XDM home; retain in the raw record
  cloud.service (CLOUD_SERVICE_TYPE) -- not completable; raw service (eventSource)
                      kept in xdm.event.description (never xdm.source.cloud.source_type,
                      a banned XCloud asset field)
```

## Checklist

```
[ ] only filter is _raw_log != null (nothing dropped)
[ ] operation DERIVED from the eventName convention (not a sample subset)
[ ] event.type = eventSource; original_event_type = eventName; tags cloud/auth per record
[ ] ConsoleLogin/AssumeRole -> AUTHENTICATION + CLOUD, auth mandatory set padded
[ ] outcome: errorCode -> FAILED first, then ConsoleLogin verdict, then success
[ ] sourceIPAddress gated on a dotted-quad shape (service DNS name never in ipv4)
[ ] cloud.provider set; cloud.service omitted; raw service in event.description (not source_type)
[ ] unknown record -> GOCORTEX_UNMODELLED; proven with verify_rule.py
```
