// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
// Fixture: WARN-051 an account captured from qualifier-bearing prose
// with an unquoted group directly after the qualifier word, and no guard
// against the qualifier itself being captured. On a masked line --
// "Failed password for invalid user Masked(xxxxx) from ..." -- this
// yields 'invalid', which is not an account.

[MODEL: dataset=acme_sshd_raw]
filter
    _raw_log != null
| alter
    tmp_actor = arrayindex(regextract(_raw_log, "password for (\S+)"), 0)
| alter
    xdm.source.user.username = tmp_actor,
    xdm.source.user.upn = if(tmp_actor != null, concat(tmp_actor, "@localhost"))
;
