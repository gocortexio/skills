// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Nokia NFM-P (NSP) management-plane application log carried over syslog.
[MODEL: dataset = nokia_nfmp_raw]
filter
    _raw_log != null
| alter
    // Stage 0 -- syslog envelope, relay-aware and prepend-robust
    tmp_pri = to_integer(to_number(arrayindex(regextract(_raw_log, "^.*<(\d{1,3})>[A-Za-z]{3}\s+\d+\s+[\d:]+"), 0))),
    tmp_host_3164 = arrayindex(regextract(_raw_log, "^.*<\d{1,3}>[A-Za-z]{3}\s+\d+\s+[\d:]+\s+(\S+)\s"), 0)
| alter
    tmp_syslog_host = if(tmp_host_3164 != "-", tmp_host_3164)
| alter
    tmp_pri_facility = if(tmp_pri != null, to_integer(divide(tmp_pri, 8)))
| alter
    tmp_pri_sev = if(tmp_pri != null, to_integer(subtract(tmp_pri, multiply(tmp_pri_facility, 8))))
| alter
    // Stage 1 -- the application's OWN header, each field on its real delimiter
    tmp_app_comp = arrayindex(regextract(_raw_log, "NFM-P-(\w+):"), 0),
    tmp_app_sev = arrayindex(regextract(_raw_log, "\d{2}:\d{2}:\d{2}\s+\d+\s+[+\-]\d{4}><([IWE])>"), 0),
    tmp_app_thread = arrayindex(regextract(_raw_log, "><[IWE]><[^>]*><([^>]*)>"), 0),
    tmp_app_class_raw = arrayindex(regextract(_raw_log, "><[IWE]><[^>]*><[^>]*><([^>]*)>"), 0)
| alter
    // an EMPTY class field is not a value -- null it so the catch-all applies
    tmp_app_class = if(tmp_app_class_raw != "", tmp_app_class_raw)
| alter
    // Stage 2 -- classify on the CLASS, never on the message prose
    tmp_is_audit = if(tmp_app_class contains "sysact.ActivityTask", "y"),
    tmp_is_mediation = if(tmp_app_class contains "server.mediator", "y"),
    tmp_is_continuation = if(tmp_app_sev = null, "y")
| alter
    // the audit record: named actor, verb, target object, outcome
    tmp_audit_user = arrayindex(regextract(_raw_log, "User Activity for User:\s+(\S+)"), 0),
    tmp_audit_type = arrayindex(regextract(_raw_log, "\sType:\s+(.*\S)\s+ObjectId:"), 0),
    tmp_audit_object = arrayindex(regextract(_raw_log, "\sObjectId:\s+(\S+)"), 0),
    tmp_audit_state = arrayindex(regextract(_raw_log, "\sState:\s+(\w+)"), 0),
    // the management address: bound on the CONTENT, not on the bracket --
    // the vendor writes "[198.51.100.28 ]" with the space inside it
    tmp_mgmt_ip = arrayindex(regextract(_raw_log, "management IP Address \[\s*(\d{1,3}(?:\.\d{1,3}){3})\s*\]"), 0),
    tmp_ne_ip = arrayindex(regextract(_raw_log, "\bNE:\s*(\d{1,3}(?:\.\d{1,3}){3})"), 0)
| alter
    tmp_target_ip = coalesce(tmp_mgmt_ip, tmp_ne_ip)
| alter
    xdm.observer.vendor = "Nokia",
    xdm.observer.product = "NFM-P",
    xdm.observer.name = tmp_syslog_host,
    xdm.event.log_level = if(
        tmp_app_sev = "E", XDM_CONST.LOG_LEVEL_ERROR,
        tmp_app_sev = "W", XDM_CONST.LOG_LEVEL_WARNING,
        tmp_app_sev = "I", XDM_CONST.LOG_LEVEL_INFORMATIONAL,
        tmp_pri_sev != null and tmp_pri_sev <= 3, XDM_CONST.LOG_LEVEL_ERROR,
        tmp_pri_sev != null and tmp_pri_sev = 4, XDM_CONST.LOG_LEVEL_WARNING,
        tmp_pri_sev != null, XDM_CONST.LOG_LEVEL_INFORMATIONAL),
    xdm.event.type = if(
        tmp_is_audit != null, "nfmp_user_activity",
        tmp_is_mediation != null, "nfmp_mediation",
        tmp_is_continuation != null, "nfmp_continuation",
        "nfmp_platform"),
    // the CLASS is the per-event identity; the prose never is
    xdm.event.original_event_type = coalesce(tmp_app_class, "GOCORTEX_UNMODELLED"),
    // the thread records the access channel a privileged operation arrived on
    xdm.source.process.name = tmp_app_thread,
    xdm.source.application.name = tmp_app_comp,
    // the audit trail is a COMMAND EXECUTION, not a login
    xdm.source.user.username = tmp_audit_user,
    xdm.target.process.command_line = if(
        tmp_is_audit != null,
        concat(coalesce(tmp_audit_type, "?"), " ", coalesce(tmp_audit_object, "?"))),
    xdm.event.operation = if(tmp_is_audit != null, XDM_CONST.OPERATION_TYPE_AUDIT),
    xdm.event.outcome = if(
        tmp_audit_state = "Success", XDM_CONST.OUTCOME_SUCCESS,
        tmp_audit_state != null, XDM_CONST.OUTCOME_FAILED,
        tmp_app_sev = "E", XDM_CONST.OUTCOME_FAILED),
    xdm.target.ipv4 = tmp_target_ip,
    // NO xdm.event.tags: this source carries no authentication and no
    // transport flow, so no story tag applies (see the walkthrough)
    xdm.event.description = tmp_app_class
;
