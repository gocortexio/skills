<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Walkthrough 12 -- Windows logon and Kerberos (4624 / 4625 / 4768)

Vendor / product: Microsoft / Windows Security auditing. Dataset:
`microsoft_windows_raw`, JSON-bodied Windows event records.

What this walkthrough shows: unlike the endpoint process / registry events
(walkthroughs 9 and 10, which carry no story tag), Windows LOGON events ARE the
authentication story. 4624 (success), 4625 (failure) and 4768 (a Kerberos TGT
request) each take `EVENT_TAG_AUTHENTICATION` and the full 15-field
authentication mandatory set from
[authentication-mapping.md](../authentication-mapping.md), classified PER
RECORD by `event_id`. It also shows the two Windows-specific enums: the
`LogonType` integer mapped across the complete `LOGON_TYPE` closed list, and the
Kerberos ticket encryption type / error code mapped to their `KERBEROS_*`
constants.

A note on the Kerberos fields: Windows logs `TicketEncryptionType` and `Status`
as HEX (`0x12`, `0x18`). XQL `to_number` does not parse hex, so this rule
matches the hex strings directly for the common values. For a pipeline that
presents the code as a decimal integer, render the COMPLETE chain instead with
`python3 scripts/kerberos_map.py --render --group encryption_type` (and
`--group error_code`) over the cast integer -- the full crosswalk lives in
[../../assets/kerberos_crosswalk.json](../../assets/kerberos_crosswalk.json).

## The full rule

```
[MODEL: dataset = microsoft_windows_raw]
filter
    _raw_log != null
| alter
    tmp_channel   = json_extract_scalar(_raw_log, "$.channel"),
    tmp_computer  = json_extract_scalar(_raw_log, "$.computer"),
    tmp_eid       = to_integer(to_number(json_extract_scalar(_raw_log, "$.event_id"))),
    tmp_svcname   = json_extract_scalar(_raw_log, "$.event_data.ServiceName"),
    tmp_user      = json_extract_scalar(_raw_log, "$.event_data.TargetUserName"),
    tmp_domain    = json_extract_scalar(_raw_log, "$.event_data.TargetDomainName"),
    tmp_ip        = json_extract_scalar(_raw_log, "$.event_data.IpAddress"),
    tmp_ipport    = json_extract_scalar(_raw_log, "$.event_data.IpPort"),
    tmp_logonproc = json_extract_scalar(_raw_log, "$.event_data.LogonProcessName"),
    tmp_package   = json_extract_scalar(_raw_log, "$.event_data.AuthenticationPackageName"),
    tmp_elevated  = json_extract_scalar(_raw_log, "$.event_data.ElevatedToken"),
    tmp_status    = json_extract_scalar(_raw_log, "$.event_data.Status"),
    tmp_etype     = json_extract_scalar(_raw_log, "$.event_data.TicketEncryptionType"),
    tmp_lt        = to_integer(to_number(json_extract_scalar(_raw_log, "$.event_data.LogonType")))
| alter
    tmp_is_auth = if(tmp_eid = 4624, "y", tmp_eid = 4625, "y", tmp_eid = 4768, "y")
| alter
    xdm.event.type = tmp_channel,
    xdm.event.id = to_string(tmp_eid),
    xdm.event.original_event_type = if(
        tmp_eid = 4624, "An account was successfully logged on",
        tmp_eid = 4625, "An account failed to log on",
        tmp_eid = 4768, "A Kerberos authentication ticket (TGT) was requested",
        "GOCORTEX_UNMODELLED"),
    xdm.event.tags = if(tmp_is_auth = "y", arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION), null),
    xdm.event.operation = if(tmp_is_auth = "y", XDM_CONST.OPERATION_TYPE_AUTH_LOGIN),
    xdm.event.outcome = if(
        tmp_eid = 4624, XDM_CONST.OUTCOME_SUCCESS,
        tmp_eid = 4625, XDM_CONST.OUTCOME_FAILED,
        tmp_eid = 4768 and tmp_status = "0x0", XDM_CONST.OUTCOME_SUCCESS,
        tmp_eid = 4768, XDM_CONST.OUTCOME_FAILED),
    xdm.event.description = concat("windows ", to_string(tmp_eid), " for ", coalesce(tmp_user, "?")),
    xdm.auth.service = "IDP",
    xdm.auth.auth_method = tmp_logonproc,
    xdm.source.ipv4 = if(tmp_ip = "-", null, to_string(tmp_ip) ~= ":", null, tmp_ip),
    xdm.source.ipv6 = if(to_string(tmp_ip) ~= ":", tmp_ip, null),
    xdm.source.port = coalesce(to_integer(to_number(tmp_ipport)), to_integer(0)),
    xdm.target.ipv4 = coalesce("", ""),
    xdm.target.port = to_integer(0),
    xdm.target.resource.name = if(
        tmp_eid = 4768, tmp_svcname,
        tmp_is_auth = "y", tmp_computer),
    xdm.network.ip_protocol = XDM_CONST.IP_PROTOCOL_TCP,
    xdm.source.host.os_family = XDM_CONST.OS_FAMILY_WINDOWS,
    xdm.source.user.username = tmp_user,
    // Identity mirror (recommended tier): same derivations, appended beside user.* -- never instead of it.
    xdm.source.identity.username = tmp_user,
    xdm.source.user.domain = tmp_domain,
    xdm.source.identity.domain = tmp_domain,
    xdm.source.user.upn = if(
        tmp_user contains "@", tmp_user,
        tmp_user != null and tmp_domain != null, concat(tmp_user, "@", tmp_domain),
        tmp_user != null, concat(tmp_user, "@localhost")),
    xdm.source.identity.upn = if(
        tmp_user contains "@", tmp_user,
        tmp_user != null and tmp_domain != null, concat(tmp_user, "@", tmp_domain),
        tmp_user != null, concat(tmp_user, "@localhost")),
    xdm.source.user.identity_type = if(
        tmp_user contains "$", XDM_CONST.IDENTITY_TYPE_MACHINE,
        tmp_user != null, XDM_CONST.IDENTITY_TYPE_USER,
        XDM_CONST.IDENTITY_TYPE_UNKNOWN),
    xdm.source.identity.identity_type = if(
        tmp_user contains "$", XDM_CONST.IDENTITY_TYPE_MACHINE,
        tmp_user != null, XDM_CONST.IDENTITY_TYPE_USER,
        XDM_CONST.IDENTITY_TYPE_UNKNOWN),
    xdm.source.user.user_type = if(
        tmp_user contains "$", XDM_CONST.USER_TYPE_MACHINE_ACCOUNT,
        lowercase(to_string(tmp_user)) ~= "^svc[-_.]|service", XDM_CONST.USER_TYPE_SERVICE_ACCOUNT,
        XDM_CONST.USER_TYPE_REGULAR),
    xdm.source.identity.user_type = if(
        tmp_user contains "$", XDM_CONST.USER_TYPE_MACHINE_ACCOUNT,
        lowercase(to_string(tmp_user)) ~= "^svc[-_.]|service", XDM_CONST.USER_TYPE_SERVICE_ACCOUNT,
        XDM_CONST.USER_TYPE_REGULAR),
    xdm.logon.type = if(
        tmp_lt = 2, XDM_CONST.LOGON_TYPE_INTERACTIVE,
        tmp_lt = 3, XDM_CONST.LOGON_TYPE_NETWORK,
        tmp_lt = 4, XDM_CONST.LOGON_TYPE_BATCH,
        tmp_lt = 5, XDM_CONST.LOGON_TYPE_SERVICE,
        tmp_lt = 6, XDM_CONST.LOGON_TYPE_PROXY,
        tmp_lt = 7, XDM_CONST.LOGON_TYPE_UNLOCK,
        tmp_lt = 8, XDM_CONST.LOGON_TYPE_NETWORK_CLEARTEXT,
        tmp_lt = 9, XDM_CONST.LOGON_TYPE_NEW_CREDENTIALS,
        tmp_lt = 10, XDM_CONST.LOGON_TYPE_REMOTE_INTERACTIVE,
        tmp_lt = 11, XDM_CONST.LOGON_TYPE_CACHED_INTERACTIVE,
        tmp_lt = 12, XDM_CONST.LOGON_TYPE_CACHED_REMOTE_INTERACTIVE,
        tmp_lt = 13, XDM_CONST.LOGON_TYPE_CACHED_UNLOCK),
    xdm.logon.package_name = tmp_package,
    xdm.logon.is_elevated = if(to_string(tmp_elevated) contains "1842", true, to_string(tmp_elevated) contains "1843", false),
    xdm.auth.kerberos_tgt.encryption_type = if(
        tmp_etype = "0x3", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_DES_CBC_MD5,
        tmp_etype = "0x11", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_AES128_CTS_HMAC_SHA1_96,
        tmp_etype = "0x12", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_AES256_CTS_HMAC_SHA1_96,
        tmp_etype = "0x17", XDM_CONST.KERBEROS_ENCRYPTION_TYPE_RC4_HMAC),
    xdm.auth.kerberos_tgt.error_code = if(
        tmp_status = "0x0", XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_NONE,
        tmp_status = "0x6", XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_C_PRINCIPAL_UNKNOWN,
        tmp_status = "0x12", XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_CLIENT_REVOKED,
        tmp_status = "0x18", XDM_CONST.KERBEROS_ERROR_CODE_ERR_KDC_PREAUTH_FAILED)
;
// REVIEW UNMODELLED -- list records this rule could not classify and
// grow it to cover them:
//   datamodel dataset = microsoft_windows_raw
//   | filter xdm.event.original_event_type = "GOCORTEX_UNMODELLED"
//   | fields xdm.event.original_event_type, microsoft_windows_raw._raw_log
//
// RAISE SKILL ISSUES -- report a mis-mapping (include the REVIEW
// UNMODELLED output above): https://github.com/gocortexio/skills/issues
```

## Key decisions worth copying

- Logon is the authentication story. 4624 / 4625 / 4768 take
  `EVENT_TAG_AUTHENTICATION`, `operation OPERATION_TYPE_AUTH_LOGIN`, and the
  full 15-field mandatory set -- unlike a Sysmon process event, which has no
  story tag. Classification is still per record (an unknown EventID falls to the
  catch-all).
- LogonType over the COMPLETE list. `xdm.logon.type` maps the Windows
  `LogonType` integer across all twelve `LOGON_TYPE` members (2 -> INTERACTIVE,
  3 -> NETWORK, 10 -> REMOTE_INTERACTIVE, ...), not just the couple the sample
  showed -- see the derivation table in
  [authentication-mapping.md](../authentication-mapping.md).
- Kerberos codes are hex in the raw log. `to_number` cannot parse `0x12`, so the
  encryption type and error code match the hex string directly for the common
  values; the complete decimal-keyed chain is available via
  `scripts/kerberos_map.py` for integer-normalised pipelines. Both consts come
  from [xdm-const.md](../xdm-const.md) (KERBEROS_ENCRYPTION_TYPE /
  KERBEROS_ERROR_CODE).
- Outcome per record. 4624 -> SUCCESS, 4625 -> FAILED, 4768 -> SUCCESS when
  `Status = 0x0` else FAILED. The account that logged on (`TargetUserName`) is
  the source user; `upn` is always UPN-shaped.
- Mandatory-field padding. Windows logon carries the client IP / port but not a
  target transport endpoint, so `xdm.target.ipv4` / `xdm.target.port` and the
  `ip_protocol` take the documented auth-story pads rather than being invented.

## NOT MAPPED, with reasons

```
NOT MAPPED
  event_data.LogonGuid / TargetLogonId -- session correlation ids; map to
                      xdm.auth.kerberos_tgt.* only when correlating TGT->TGS
  event_data.WorkstationName -- source workstation label; add to
                      xdm.source.host.hostname when the sample carries it
  event_data.SubStatus (4625) -- the granular failure sub-code; the primary
                      Status already drives outcome, keep SubStatus in the raw
  event_data.ServiceSid (4768/4769) -- the SID form of the requested service
                      principal; ServiceName carries the readable form and is
                      mapped to xdm.target.resource.name, so the SID adds
                      nothing until a 4769 (TGS) branch needs it
```

## Checklist

```
[ ] only filter is _raw_log != null (nothing dropped)
[ ] logon events tagged EVENT_TAG_AUTHENTICATION; all 15 mandatory fields mapped/padded (WARN-042)
[ ] classified per event_id; unknown EventID -> GOCORTEX_UNMODELLED
[ ] LogonType mapped over the COMPLETE LOGON_TYPE list (not a partial subset)
[ ] Kerberos encryption/error mapped (hex-string match; full chain via kerberos_map.py)
[ ] outcome per record (SUCCESS/FAILED); upn always UPN-shaped
[ ] proven with verify_rule.py on 4624, 4625 and 4768 records
```
