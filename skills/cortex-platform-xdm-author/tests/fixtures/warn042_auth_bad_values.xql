// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fixture: an authentication event (auto-detected via the
// EVENT_TAG_AUTHENTICATION tag) that maps all 15 mandatory fields but
// assigns several of them values the authentication story forbids --
// the wrong const, a static source address, and a list where a string
// is required. lint_rule.py should raise WARN-042 (value conformance)
// for each non-conformant literal while raising none for the missing
// set, since every mandatory field is present. Advisory only -- the
// exit code stays 0.
//
// ALERT / EVENT FIELD MAPPING
//   user   -> xdm.source.user.upn
//   action -> xdm.event.original_event_type

[MODEL: dataset=acme_idp_raw]
filter
    _raw_log != null
| alter
    tmp_user = json_extract_scalar(_raw_log, "$.user"),
    tmp_app = json_extract_scalar(_raw_log, "$.target_app"),
    tmp_action = json_extract_scalar(_raw_log, "$.action")
| alter
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION),
    xdm.event.type = "login",
    xdm.event.operation = XDM_CONST.OPERATION_TYPE_CREATE,
    xdm.event.original_event_type = tmp_action,
    xdm.event.outcome = XDM_CONST.OUTCOME_UNKNOWN,
    xdm.auth.service = "Kerberos",
    xdm.source.user.upn = tmp_user,
    xdm.source.user.identity_type = XDM_CONST.IDENTITY_TYPE_USER,
    xdm.source.user.user_type = XDM_CONST.USER_TYPE_REGULAR,
    xdm.source.ipv4 = "203.0.113.9",
    xdm.source.port = to_integer(0),
    xdm.target.ipv4 = arraycreate("10.0.0.1"),
    xdm.target.port = to_integer(0),
    xdm.target.resource.name = tmp_app,
    xdm.network.ip_protocol = 6
;
