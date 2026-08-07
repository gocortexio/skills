<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Walkthrough 11 -- Linux sudo command execution over syslog

Vendor / product: Linux / `sudo` (the same shape applies to `su` and cron).
Dataset: `linux_syslog_raw`, RFC 3164 syslog text.

What this walkthrough shows: a local Linux command execution modelled on the
endpoint model from [process-mapping.md](../process-mapping.md), and how the
endpoint model composes with the syslog prepend-robust HARD RULE from
[syslog-envelope.md](../syslog-envelope.md). The executed command goes to
`xdm.target.process.command_line`, the invoking user to `xdm.source.user.*`,
the run-as user to `xdm.target.user.*`, and the operation is
`XDM_CONST.OPERATION_TYPE_EXECUTION`. Because every body field is anchored on a
payload token (`COMMAND=`, `USER=`, the `sudo:` tag) rather than on a fixed
offset, the SAME rule extracts identically whether the record arrives direct off
the host or behind a relay that prepends its own header.

## The full rule

```
[MODEL: dataset = linux_syslog_raw]
filter
    _raw_log != null
| alter
    tmp_prog = arrayindex(regextract(_raw_log, "([A-Za-z0-9._/-]+)\s+(?:sudo|CROND|su)(?:\[\d+\])?:"), 0),
    tmp_tag = arrayindex(regextract(_raw_log, "\s((?:sudo|su|CROND))(?:\[\d+\])?:\s"), 0),
    tmp_invoker = arrayindex(regextract(_raw_log, "(?:sudo|su)(?:\[\d+\])?:\s+(\S+)\s+:"), 0),
    tmp_runas = arrayindex(regextract(_raw_log, "USER=(\S+)"), 0),
    tmp_tty = arrayindex(regextract(_raw_log, "TTY=(\S+)"), 0),
    tmp_pwd = arrayindex(regextract(_raw_log, "PWD=(\S+)"), 0),
    tmp_command = arrayindex(regextract(_raw_log, "COMMAND=(.*\S)"), 0)
| alter
    xdm.event.type = coalesce(tmp_tag, "linux"),
    xdm.event.original_event_type = if(
        tmp_command != null, "sudo command",
        "GOCORTEX_UNMODELLED"),
    xdm.event.operation = if(
        tmp_command != null, XDM_CONST.OPERATION_TYPE_EXECUTION),
    xdm.event.tags = null,
    xdm.source.host.os_family = XDM_CONST.OS_FAMILY_LINUX,
    xdm.observer.name = tmp_prog,
    xdm.source.host.hostname = tmp_prog,
    xdm.source.user.username = tmp_invoker,
    xdm.target.user.username = tmp_runas,
    xdm.target.process.command_line = tmp_command,
    xdm.target.process.name = arrayindex(regextract(to_string(tmp_command), "([^\s/]+)(?:\s|$)"), 0),
    xdm.event.description = concat(
        coalesce(tmp_invoker, "user"), " ran ", coalesce(tmp_command, "?"),
        " as ", coalesce(tmp_runas, "?"),
        if(tmp_tty != null, concat(" on ", tmp_tty), ""),
        if(tmp_pwd != null, concat(" in ", tmp_pwd), ""))
;
// REVIEW UNMODELLED -- list records this rule could not classify and
// grow it to cover them:
//   datamodel dataset = linux_syslog_raw
//   | filter xdm.event.original_event_type = "GOCORTEX_UNMODELLED"
//   | fields xdm.event.original_event_type, linux_syslog_raw._raw_log
//
// RAISE SKILL ISSUES -- report a mis-mapping (include the REVIEW
// UNMODELLED output above): https://github.com/gocortexio/skills/issues
```

## Key decisions worth copying

- Prepend-robust by construction. `COMMAND=`, `USER=` and the host-before-tag
  captures are all anchored on payload tokens, never on a fixed column, so a
  relay that prepends `<190>... forwarder: ` in front of the original record
  changes nothing -- the origin host (`web01`, the token before `sudo:`) and
  the command are still recovered. Verify against both a direct and a
  relay-prepended copy of the line.
- Actor vs target. The invoking user (`alice`) is `xdm.source.user.*`; the
  command ran AS root, so `root` is `xdm.target.user.*`; the command itself is
  `xdm.target.process.command_line` (the process the event acts upon).
- The verb is EXECUTION. A bare command run with no create/terminate semantics
  is `OPERATION_TYPE_EXECUTION`. An auditd `SYSCALL execve` (a distinct source)
  would instead be `OPERATION_TYPE_PROCESS_CREATE`.
- Blank tags, catch-all only for chatter. A recognised `sudo` command carries
  no story tag but is fully modelled; unrelated syslog (a `systemd` line with no
  `COMMAND=`) falls through to `GOCORTEX_UNMODELLED`, so the datamodel row count
  equals the raw count.
- Command name from the path. The first whitespace-delimited token of the
  command, stripped to its last path segment, gives a short
  `xdm.target.process.name` (`apt`).

## NOT MAPPED, with reasons

```
NOT MAPPED
  TTY= / PWD= -- session context; retained in the description, no dedicated
                 process leaf on this shape
  the RFC 3164 timestamp -- Cortex sets _time at INGEST (WARN-018)
  the syslog PRI -- decode to xdm.event.log_level only when the sample carries
                 a meaningful severity; a sudo COMMAND line does not
```

## Checklist

```
[ ] only filter is _raw_log != null (nothing dropped)
[ ] body fields token-anchored (COMMAND= / USER= / sudo:), not offset-anchored
[ ] verified on BOTH a direct and a relay-prepended copy -- identical output
[ ] invoker -> source.user; run-as -> target.user; command -> target.process.command_line
[ ] operation = OPERATION_TYPE_EXECUTION; event.tags blank
[ ] non-sudo chatter -> GOCORTEX_UNMODELLED with the REVIEW UNMODELLED query
[ ] os_family = LINUX
```
