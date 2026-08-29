// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fixture: an authentication event that assigns the identity mirror
// INSTEAD of its user twin. xdm.source.identity.upn carries the
// principal and xdm.source.user.upn is absent, so the rule has moved a
// MANDATORY field onto the recommended surface to satisfy a
// recommendation. WARN-042 reports the missing mandatory upn; WARN-057
// reports the reason it went missing. Advisory -- exit code stays 0.
//
// ALERT / EVENT FIELD MAPPING
//   user -> xdm.source.identity.upn (the defect: should be BOTH)

[MODEL: dataset=acme_idp_raw]
filter
    _raw_log != null
| alter
    tmp_user = json_extract_scalar(_raw_log, "$.user")
| alter
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION),
    xdm.source.identity.upn = if(tmp_user contains "@", tmp_user,
        tmp_user != null, concat(tmp_user, "@localhost"))
;
