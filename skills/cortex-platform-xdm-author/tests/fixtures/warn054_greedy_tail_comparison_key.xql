// WARN-054 fixture: a comparison key captured to the end of the line.
//
// tmp_cmd runs to end-of-line, so a device that emits a trailing space
// after the command puts that space into command_line. The field looks
// correct everywhere except an exact comparison, where it silently
// matches nothing. tmp_note is deliberately greedy too and must NOT be
// flagged: a description is displayed, not compared.
[MODEL: dataset = acme_cli_raw]
alter
    tmp_cmd_raw = arrayindex(regextract(_raw_log, ":\s+\S*[#>]\s+(.+)$"), 0),
    tmp_note = arrayindex(regextract(_raw_log, "reason=(.+)$"), 0)
| alter
    tmp_cmd = tmp_cmd_raw
| alter
    xdm.target.process.command_line = tmp_cmd,
    xdm.event.description = tmp_note,
    xdm.event.type = "cli",
    xdm.event.operation_sub_type = "execute",
    xdm.event.outcome = XDM_CONST.OUTCOME_SUCCESS
