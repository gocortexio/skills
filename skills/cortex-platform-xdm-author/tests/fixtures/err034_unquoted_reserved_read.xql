// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fixture: a MODEL rule that READS a raw column named for a query-language
// construct without backticks. lint_rule.py should raise ERR-034 at the
// read, with error severity so the exit code is 1.
//
// This is the live-tenant bisection case, two uploads differing by exactly
// one line: `tmp_v = api_key_id` installed, and adding `tmp_view = view`
// failed the whole pack install with an opaque 101704 naming no field and
// no line. Note that tmp_view is correctly tmp_-prefixed -- the prefix
// protects the name a rule CREATES, and this is the name it READS.
//
// The backticked reads below are the CORRECT form and must stay silent:
// that is how all 328 shipped upstream rules read these columns.
//
// ALERT / EVENT FIELD MAPPING
//   view -> xdm.event.operation_sub_type

[MODEL: dataset=acme_demo_raw]
filter
    _raw_log != null
| alter
    tmp_v = api_key_id,
    tmp_view = view,
    tmp_tags = arraycreate(`tag`),
    tmp_t = `target`,
    tmp_ts = timestamp
| alter
    xdm.event.id = tmp_v,
    xdm.event.operation_sub_type = tmp_view,
    xdm.event.tags = tmp_tags,
    xdm.target.host.hostname = tmp_t,
    xdm.event.original_event_type = tmp_ts
;
