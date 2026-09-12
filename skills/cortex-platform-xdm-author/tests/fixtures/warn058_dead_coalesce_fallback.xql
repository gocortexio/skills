// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fixture: WARN-058. A temp given a literal default by one coalesce is
// never null, so a LATER coalesce on it can never take its fallback.
//
// tmp_role and tmp_type_name are defaulted, so both fallbacks below are
// unreachable -- and the tmp_type_name one discards a real column rather
// than a placeholder. tmp_name is NOT defaulted, so its fallback is live
// and must not be reported: that pair is the discriminator.
//
// The if(tmp_x = "", ...) comparisons are here on purpose. XQL spells
// assignment and equality the same way, so a check that reads them as
// re-assignments loses every finding after them.

[MODEL: dataset=acme_demo_raw]
filter
    _raw_log != null
| alter
    tmp_name = json_extract_scalar(_raw_log, "$.name"),
    tmp_type = json_extract_scalar(_raw_log, "$.type"),
    tmp_role = coalesce(json_extract_scalar(_raw_log, "$.role"), ""),
    tmp_type_name = coalesce(json_extract_scalar(_raw_log, "$.typeName"), "")
| alter
    xdm.observer.vendor = "Acme",
    xdm.event.type = "ALERT",
    xdm.target.resource.sub_type = if(tmp_role = "", null, tmp_role),
    xdm.event.description = concat(
        "Acme account ", coalesce(tmp_name, "unknown"),
        " at role ", coalesce(tmp_role, "none"),
        " of type ", coalesce(tmp_type_name, tmp_type))
;
