// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fixture: an authentication event (auto-detected via the
// EVENT_TAG_AUTHENTICATION tag) that maps all 15 mandatory fields, so
// WARN-042 has nothing to report for the missing set, but PADS
// xdm.target.resource.name with the empty string instead of deriving the
// entity the principal authenticated to. lint_rule.py should raise
// exactly one WARN-055. Advisory only -- the exit code stays 0.
//
// This is the shape an inverted authentication rule takes: every
// mandatory field assigned, the linter silent, and no record anywhere of
// what was actually logged into.
//
// ALERT / EVENT FIELD MAPPING
//   user   -> xdm.source.user.upn
//   action -> xdm.event.original_event_type

[MODEL: dataset=acme_idp_raw]
filter
    _raw_log != null
| alter
    tmp_user = json_extract_scalar(_raw_log, "$.user"),
    tmp_src = json_extract_scalar(_raw_log, "$.src_ip"),
    tmp_action = json_extract_scalar(_raw_log, "$.action"),
    tmp_result = json_extract_scalar(_raw_log, "$.result")
| alter
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION),
    xdm.event.type = "authentication",
    xdm.event.operation = XDM_CONST.OPERATION_TYPE_AUTH_LOGIN,
    xdm.event.original_event_type = tmp_action,
    xdm.event.outcome = if(tmp_result = "success", XDM_CONST.OUTCOME_SUCCESS,
        tmp_result != null, XDM_CONST.OUTCOME_FAILED),
    xdm.auth.service = "IDP",
    xdm.logon.package_name = "Kerberos",
    xdm.source.user.upn = if(tmp_user contains "@", tmp_user,
        tmp_user != null, concat(tmp_user, "@localhost")),
    xdm.source.user.identity_type = XDM_CONST.IDENTITY_TYPE_USER,
    xdm.source.user.user_type = XDM_CONST.USER_TYPE_REGULAR,
    xdm.source.ipv4 = tmp_src,
    xdm.source.port = to_integer(0),
    xdm.target.ipv4 = "",
    xdm.target.port = to_integer(0),
    xdm.target.resource.name = "",
    xdm.network.ip_protocol = XDM_CONST.IP_PROTOCOL_TCP
;
