// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
// Fixture: WARN-052 a capture whose only qualifier is an uppercase
// character class, reached positionally with no literal anchor. XQL folds
// case, so [A-Z] also matches lowercase and this captures whatever token
// sits in that position -- a function name, a word -- leaving the field
// populated with a plausible but wrong value.

[MODEL: dataset=acme_device_raw]
filter
    _raw_log != null
| alter
    tmp_tag = arrayindex(regextract(_raw_log, "\s+\S+\s+([A-Z][A-Z0-9_]{3,}):"), 0)
| alter
    xdm.event.original_event_type = tmp_tag
;
