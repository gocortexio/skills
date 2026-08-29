// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fixture: an authentication event whose identity mirror is present but
// DIVERGED. xdm.source.user.username maps the account name while
// xdm.source.identity.username maps the display name, so one fact is
// written twice from two derivations and both fields are populated --
// nothing downstream can tell which is the account. WARN-057 reports it
// as a QUESTION, since a deliberate difference is conceivable.
// Advisory -- exit code stays 0.
//
// ALERT / EVENT FIELD MAPPING
//   account -> xdm.source.user.username
//   display -> xdm.source.identity.username (the divergence)

[MODEL: dataset=acme_idp_raw]
filter
    _raw_log != null
| alter
    tmp_account = json_extract_scalar(_raw_log, "$.account"),
    tmp_display = json_extract_scalar(_raw_log, "$.display_name")
| alter
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION),
    xdm.source.user.username = tmp_account,
    xdm.source.identity.username = tmp_display
;
