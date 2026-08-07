<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Endpoint, process and command-execution mapping

Endpoint telemetry describes what happened on a host: a process starting or
stopping, a command being run, an image / DLL / shared object loading, a file
created / written / deleted, or a registry key / value changing. This covers
local Linux commands (shell, `sudo`, auditd), Windows Security events
(4688 process creation, etc.), Sysmon (EventID 1/3/7/11/12/13/22/...), and EDR
process telemetry. These map to the `xdm.*.process.*`, `xdm.target.file(_before).*`,
`xdm.target.registry(_before).*` and `xdm.target.module.*` families.

This is a RECOMMENDED mapping set, not a mandatory story. There is no process
`EVENT_TAG`, so there is no mandatory-field gate here -- the linter raises the
advisory WARN-044 to suggest companion fields, never to block. Map what the log
provides.

## The endpoint classification model (channel / semantic / verb)

Endpoint sources do not fit the story-tag model. Classify each record on three
independent fields, not by stuffing a label into `xdm.event.type`:

- `xdm.event.type` = the raw channel or source label -- the Windows channel
  (e.g. `Security`, `Microsoft-Windows-Sysmon/Operational`), the syslog
  program / tag, or a stable source label. It is NOT a hand-written semantic
  string like `"process creation"`.
- `xdm.event.original_event_type` = the per-record semantic name -- the vendor
  action / task / event name (`coalesce(tmp_action, tmp_task, tmp_event_name)`),
  e.g. `Process Create`, `Registry value set`, `execve`.
- `xdm.event.operation` = `XDM_CONST.OPERATION_TYPE_<verb>` -- the precise verb.
  This is where the meaning lives (see the derivation table below).
- `xdm.event.tags` = blank. The six `EVENT_TAG` story markers (authentication,
  network, cloud, saas, onprem, vpn) have NO process / file / registry member,
  so an endpoint event legitimately carries no tag.

Important: a Sysmon process-create event is fully modelled (operation + process
fields are set) even though it has no tag, so it does NOT get the
`GOCORTEX_UNMODELLED` catch-all. That sentinel is only for a record you cannot
classify at all -- see [record-classification.md](record-classification.md). A
record you understood but which simply has no story tag is modelled, not
unmodelled.

An `event_id` is only meaningful WITHIN its channel / provider. The same number
means different things in different providers: Sysmon EventID 12 / 13 are
registry create / value-set, but in `Microsoft-Windows-Kernel-General` EventID
12 / 13 are OS startup / shutdown. So never key `xdm.event.operation` or
`xdm.event.original_event_type` on `event_id` alone -- scope the `if()`-chain to
one provider per dataset (or gate it on the channel / provider as well as the
id) so a colliding number from another provider cannot be mis-classified.

## Actor vs target

- The process that ACTED (the running program, the session issuing the command)
  is the source: `xdm.source.process.*`.
- The process being ACTED UPON (a child that was terminated, a target of process
  access / remote-thread injection) is the target: `xdm.target.process.*`.
- For a local endpoint / EDR process, the command the process ran is
  `xdm.source.process.command_line`. Use `xdm.target.process.command_line` for a
  process the event acts upon (a child launched or terminated).

## Process family (map when present)

| XDM target | Notes |
| --- | --- |
| `xdm.source.process.name` | Short process / image name (`sshd`, `powershell.exe`). |
| `xdm.source.process.pid` | Process id. Number: `to_integer(to_number(...))`. |
| `xdm.source.process.parent_id` | Parent process id. String. |
| `xdm.source.process.command_line` | Full command line the process ran. |
| `xdm.source.process.executable.path` | Full path to the image on disk. |
| `xdm.source.process.executable.filename` | Image filename only. |
| `xdm.source.process.executable.directory` | Directory of the image. |
| `xdm.source.process.executable.md5` | Image MD5 hash. |
| `xdm.source.process.executable.sha256` | Image SHA-256 hash. |
| `xdm.source.process.executable.signer` | Code-signing signer. |
| `xdm.source.process.executable.is_signed` | Boolean. |
| `xdm.source.process.executable.signature_status` | `XDM_CONST.SIGNATURE_STATUS_*`. |
| `xdm.source.process.integrity_level` | Number 0..4 (see integrity level below). |
| `xdm.source.process.is_injected` | Boolean (Sysmon 25 process tampering). |
| `xdm.source.user.username` / `xdm.source.user.domain` | The acting user. |

The target family mirrors the source family; use `xdm.target.process.*` for the
process acted upon.

Guardrail: never assign a value to `xdm.source.process.executable` (or
`xdm.target.process.executable`) directly -- that path is typed Number, a parent
node, not the image name. Map the leaves (`executable.path`,
`executable.filename`, ...) instead.

## Operation verb: derive the precise OPERATION_TYPE

`xdm.event.operation` is a closed `XDM_CONST.OPERATION_TYPE_*` enum with 56
members (see [xdm-const.md](xdm-const.md)). For an endpoint event, map the most
specific verb the record supports -- do NOT leave the field blank when a member
fits. Pick from the vendor action / EventID:

| Record kind (vendor / EventID) | `xdm.event.operation` |
| --- | --- |
| Process creation (Sysmon 1, Windows 4688, Linux `execve` SYSCALL) | `OPERATION_TYPE_PROCESS_CREATE` |
| Process start where create semantics are not distinguished | `OPERATION_TYPE_PROCESS_START` |
| Process terminated (Sysmon 5) | `OPERATION_TYPE_PROCESS_TERMINATE` |
| Image / DLL loaded (Sysmon 7), driver loaded (Sysmon 6) | `OPERATION_TYPE_IMAGE_LOAD` |
| Image unloaded | `OPERATION_TYPE_IMAGE_UNLOAD` |
| File created (Sysmon 11) | `OPERATION_TYPE_FILE_CREATE` |
| File written / stream-hash (Sysmon 15) | `OPERATION_TYPE_FILE_WRITE` |
| File deleted (Sysmon 23 / 26) | `OPERATION_TYPE_FILE_REMOVE` |
| File renamed | `OPERATION_TYPE_FILE_RENAME` |
| Registry key created (Sysmon 12 CreateKey) | `OPERATION_TYPE_REGISTRY_CREATE_KEY` |
| Registry key deleted (Sysmon 12 DeleteKey) | `OPERATION_TYPE_REGISTRY_DELETE_KEY` |
| Registry value deleted (Sysmon 12 DeleteValue) | `OPERATION_TYPE_REGISTRY_DELETE_VALUE` |
| Registry value set (Sysmon 13) | `OPERATION_TYPE_REGISTRY_SET_VALUE` |
| Registry key / value renamed (Sysmon 14) | `OPERATION_TYPE_REGISTRY_RENAME_KEY` |
| A bare interactive / shell command with no finer semantics | `OPERATION_TYPE_EXECUTION` |
| A configuration command on a device | `OPERATION_TYPE_CONFIG_CHANGE` (read the caution below) |
| AAA / network-device command accounting (`cmd=`) | `OPERATION_TYPE_AUDIT` |

Caution on device configuration commands: a `set` verb is not by itself a
configuration change. On Junos, `set cli screen-width 200` and
`set cli screen-length 0` are TERMINAL PREFERENCES for the current
session -- they change nothing on the device -- and they can account for
every `set` in a feed that contains no `commit` at all. A
configuration change on Junos is a `commit`, or a `set` against a
configuration hierarchy other than `cli`. Keying a config-change
detection on the bare verb produces a detection that fires constantly on
operators resizing their terminal. The same caution applies to any
platform with a session-scoped settings namespace: classify on the
hierarchy or the commit, never on the verb alone.

Rule of thumb: choose the most specific verb the record supports; fall back to
`OPERATION_TYPE_EXECUTION` only for a plain command run with no create / terminate
semantics; leave `xdm.event.operation` unset ONLY when nothing in the enum
applies. (Earlier guidance said to leave it unmapped because "no command-
execution member exists" -- that was wrong; `OPERATION_TYPE_EXECUTION` and the
`PROCESS_*` verbs exist.)

## Terminate a capture on CONTENT, not on the end of the line

A capture that runs to end-of-line inherits whatever the device put
there. Devices commonly emit a trailing space after a CLI command, and
the natural greedy tail keeps it:

```
// WRONG -- (.+) takes the trailing space the device emitted
tmp_cmd = arrayindex(regextract(_raw_log, ":\s+\S*[#>]\s+(.+)"), 0)

// RIGHT -- greedy up to a REQUIRED final non-space character
tmp_cmd = arrayindex(regextract(_raw_log, ":\s+\S*[#>]\s+(.*\S)"), 0)
```

`(.*\S)` needs no trim function: the `\S` forces the match to end on
content, so the whole command is captured and the trailing whitespace is
not.

This matters far more than it looks, because the failure is invisible
everywhere except the one place it counts. The field is populated,
non-empty, not the sentinel, and reads correctly in any sample or table.
It differs from the same command written without the space only under
exact comparison -- so a `comp count() by ...command_line` shows the
command, and a filter written the obvious way against those same records
returns NOTHING:

```
| filter xdm.target.process.command_line = "admin display-config"     -> 0 rows
```

A correlation keyed on a specific command is then structurally incapable
of matching, and it fails as an empty result set rather than an error.
Nobody investigates an empty result set.

Apply the rule wherever the extracted value will be COMPARED rather than
merely displayed. `xdm.target.process.command_line` and
`xdm.event.original_event_type` are the two that bite hardest, because
both are natural correlation keys. A free-text description field is the
legitimate exception: there the tail is the point.

## File family

For a file event, map `xdm.target.file.*` (the file acted upon):
`path`, `filename`, `directory`, `extension`, `md5`, `sha256`, `signer`,
`is_signed`, `signature_status`, `size`. For a rename, put the prior name in
`xdm.target.file_before.*` (e.g. `xdm.target.file_before.filename`).

## Registry family

For a registry event, map `xdm.target.registry.*`: `key`, `value`, `data`,
`value_type` (`XDM_CONST.REGISTRY_VALUE_TYPE_*`). On a value change / rename,
the prior state goes in `xdm.target.registry_before.*` (e.g.
`xdm.target.registry_before.value`). The Sysmon `TargetObject` maps to
`xdm.target.registry.key`, and `Details` to `xdm.target.registry.value`.

## Module / image family

For an image / DLL / driver load (Sysmon 6 / 7), map `xdm.target.module.*`:
`path`, `filename`, `directory`, `md5`, `sha256`, `signer`, `is_signed`,
`signature_status`.

## signature_status and is_signed

Map the vendor signing status word to `XDM_CONST.SIGNATURE_STATUS_*` (see
[xdm-const.md](xdm-const.md)): Valid -> `SIGNED_VERIFIED`;
Expired / Revoked / mismatched -> `SIGNED_INVALID`; an explicitly unsigned image
-> `UNSIGNED`; Unavailable / anything else -> `STATUS_UNKNOWN`. Set the
`is_signed` boolean companion when the log provides it.

## integrity_level (Number, not a constant)

`xdm.*.process.integrity_level` is typed Number. Map the Windows integrity word
to an integer -- do NOT emit an `XDM_CONST.INTEGRITY_LEVEL_*` token:

```
tmp_il = lowercase(to_string(tmp_integrity_word)),
xdm.source.process.integrity_level = if(
    tmp_il contains "untrusted", 0,
    tmp_il contains "low", 1,
    tmp_il contains "medium", 2,
    tmp_il contains "high", 3,
    tmp_il contains "system", 4)
```

## Deriving common endpoint fields (recipes)

Hashes from a Sysmon `Hashes` blob (`MD5=...,SHA256=...`), which is one field:

```
xdm.source.process.executable.sha256 = arrayindex(
    regextract(to_string(tmp_hashes), "SHA256=([0-9A-Fa-f]{64})"), 0),
xdm.source.process.executable.md5 = arrayindex(
    regextract(to_string(tmp_hashes), "MD5=([0-9A-Fa-f]{32})"), 0)
```

`DOMAIN\user` split (guard the `-` / null empty markers first):

```
xdm.source.user.username = arrayindex(
    regextract(to_string(tmp_user), "\\\\([^\\\\]+)$"), 0),
xdm.source.user.domain = arrayindex(
    regextract(to_string(tmp_user), "^([^\\\\]+)\\\\"), 0)
```

Process name from an image path (works for Windows `\` and Linux `/`):

```
xdm.source.process.name = arrayindex(
    regextract(to_string(tmp_image), "([^\\\\/]+)$"), 0)
```

Single-field IPv4 vs IPv6 split (Sysmon 3 `SourceIp` / `DestinationIp`):

```
xdm.source.ipv4 = if(to_string(tmp_ip) ~= ":", null, tmp_ip),
xdm.source.ipv6 = if(to_string(tmp_ip) ~= ":", tmp_ip, null)
```

Numbers vs strings: `pid` is a Number (`to_integer(to_number(...))`);
`parent_id` is a String.

## Linux commands

- auditd `EXECVE`: reconstruct the command from the `a0 a1 a2 ...` argv fields
  (or the `proctitle`), map it to `xdm.source.process.command_line`, `exe=` to
  `xdm.source.process.executable.path`, `pid=` to `xdm.source.process.pid`, and
  the `auid` / `uid` to `xdm.source.user.username`. A `SYSCALL execve` is a
  process creation (`OPERATION_TYPE_PROCESS_CREATE`); a bare command is
  `OPERATION_TYPE_EXECUTION`.
- `sudo` / shell / PAM: a `USER=root ; COMMAND=/bin/sh` line -- the command being
  run goes to `xdm.target.process.command_line`, the invoking user to
  `xdm.source.user.username`, operation `OPERATION_TYPE_EXECUTION`.
- Linux endpoint logs usually arrive over syslog, so the syslog envelope HARD
  RULE applies: parse the envelope relay-aware and anchor every payload field on
  its own token (see [syslog-envelope.md](syslog-envelope.md)).

## AAA / network-device command accounting

A TACACS+ / RADIUS / network-device feed carries authentication, authorization,
and accounting records. They do NOT all belong to the authentication story --
discriminate by record kind:

- authentication (AUTHEN, a login attempt) -> the authentication story.
- authorization (AUTHOR, a permit / deny decision) -> authentication story; the
  outcome carries the decision.
- accounting with a command (`cmd=`, `CmdSet`, `Command=`) -> a COMMAND
  EXECUTION event, not authentication. Set `xdm.event.type` to the source label,
  map the executed command to `xdm.target.process.command_line`, keep operation
  `XDM_CONST.OPERATION_TYPE_AUDIT` (an audit trail of what was run) with no
  outcome, put the operator on `xdm.source.user.*` and the administered device on
  `xdm.target.*`, and do NOT tag it `EVENT_TAG_AUTHENTICATION`.
- accounting with no command (a session Start / Stop) -> a session-audit record:
  operation `OPERATION_TYPE_AUDIT`, no outcome, and `elapsed_time` ->
  `xdm.event.duration` (seconds to milliseconds, see
  [authentication-mapping.md](authentication-mapping.md)).

See [authentication-mapping.md](authentication-mapping.md) (AAA gateways).

## Worked shape (Sysmon process creation, EventID 1)

The running program is the source process; map the image to a leaf (never the
`executable` parent, which is a Number), set the precise operation verb, and
put the channel in `event.type` with the semantic name in `original_event_type`.

```
[MODEL: dataset=microsoft_sysmon_raw]
filter
    _raw_log != null
| alter
    tmp_channel = json_extract_scalar(_raw_log, "$.channel"),
    tmp_eid = json_extract_scalar(_raw_log, "$.event_id"),
    tmp_image = json_extract_scalar(_raw_log, "$.event_data.Image"),
    tmp_cmd = json_extract_scalar(_raw_log, "$.event_data.CommandLine"),
    tmp_pid = json_extract_scalar(_raw_log, "$.event_data.ProcessId"),
    tmp_user = json_extract_scalar(_raw_log, "$.event_data.User"),
    tmp_hashes = json_extract_scalar(_raw_log, "$.event_data.Hashes")
| alter
    xdm.event.type = tmp_channel,
    xdm.event.id = to_string(tmp_eid),
    xdm.event.original_event_type = "Process Create",
    xdm.event.operation = XDM_CONST.OPERATION_TYPE_PROCESS_CREATE,
    xdm.source.host.os_family = XDM_CONST.OS_FAMILY_WINDOWS,
    xdm.source.process.executable.path = tmp_image,
    xdm.source.process.name = arrayindex(regextract(to_string(tmp_image), "([^\\\\/]+)$"), 0),
    xdm.source.process.command_line = tmp_cmd,
    xdm.source.process.pid = to_integer(to_number(tmp_pid)),
    xdm.source.process.executable.sha256 = arrayindex(regextract(to_string(tmp_hashes), "SHA256=([0-9A-Fa-f]{64})"), 0),
    xdm.source.user.username = arrayindex(regextract(to_string(tmp_user), "\\\\([^\\\\]+)$"), 0),
    xdm.source.user.domain = arrayindex(regextract(to_string(tmp_user), "^([^\\\\]+)\\\\"), 0),
    xdm.event.description = concat("process ", to_string(tmp_cmd))
;
```

## Cisco IOS-XE: the command and configuration corpus

Most estates model network-device commands only through TACACS+ command
accounting. The device also emits them locally, and the local record is
available whether or not AAA accounting is configured.

### Per-command auditing

```
PARSER-5-CFGLOG_LOGGEDCMD    User:U logged command:C
PARSER-3-CFGLOG_INCONSISTENT User:U command:C
PARSER-3-CFGLOG_NOUSER       Command:C
```

`CFGLOG_LOGGEDCMD` is the local equivalent of TACACS+ command
accounting, emitted by the configuration logger. It takes the same
treatment: the command to `xdm.target.process.command_line`,
`xdm.event.operation = XDM_CONST.OPERATION_TYPE_AUDIT`, `xdm.event.type`
a process value, and NO authentication tag. It is a command execution,
not a login.

`CFGLOG_NOUSER` is the same event with the actor missing. Map the command
and leave the identity NULL. Padding a user here would attribute a
configuration change to nobody in particular, which is worse than an
absent field because it looks answered.

### Configuration changes

```
SYS-5-CONFIG_I     Configured from SOURCE by USER
SYS-5-CONFIG       Configured from SOURCE
SYS-5-CONFIG_NV_I  Nonvolatile storage configured from SOURCE by USER
SYS-5-CONFIG_P     Configured programmatically by process P from SOURCE as NAME
SYS-5-CONFIG_R     Config Replace is STATE
```

The `_I` suffix is the discriminator across SYS: it means the record
carries the actor. `CONFIG_I` is the single most useful configuration
record on the platform because it names who and from where. Bare
`CONFIG` is the same event without attribution, and the two must not be
merged into one branch that pretends both carry a user.

`CONFIG_P` is a programmatic change -- automation, NETCONF, a controller.
Its actor is a PROCESS, not a person, so it maps to
`xdm.source.process.name` rather than to a username, and conflating the
two hides exactly the distinction an investigation needs.

### Commands that are themselves the finding

```
PARSER-5-HIDDEN     Warning!!! ' CMD' is a hidden command. Use of this command is not recommended/supported ...
PARSER-5-INTERNAL   Warning!!! ' CMD' is an internal command. Use of this command is not recommended/supported.
PARSER-2-INTDISABLE Interrupts disabled in mode MODE by command 'CMD'
```

A hidden or internal command being run is a signal in its own right --
these are undocumented commands, and their use is either troubleshooting
by someone who knows the platform very well or an intruder who does.

Note the vendor's own leading space inside the quotes: `' [chars]'`. A
capture written `'([^']+)'` returns the command WITH a leading space, and
that value never compares equal to the same command written without it.
This is the trailing-whitespace defect in mirror image; bound the capture
on content:

```
// WRONG -- keeps the vendor's leading space
tmp_cmd = arrayindex(regextract(_raw_log, "'([^']+)'"), 0)

// RIGHT -- starts on content, ends on content
tmp_cmd = arrayindex(regextract(_raw_log, "'\s*(\S.*?\S)\s*'"), 0)
```

### Session, privilege and logging state

```
PARSER-6-CSLOCKCLEARED       Configuration session lock is cleared by process 'P' user 'U' from terminal 'N'
SYS-6-TTY_EXPIRE_TIMER       TIMER expired tty N ADDR user U
SYS-5-LOGGING_START          Logging enabled - REASON
SYS-5-LOGGING_STOP           Logging disabled - REASON
SYS-6-LOGGINGHOST_STARTSTOP  Logging to host H STATE
SYS-5-RELOAD                 Reload requested REASON
```

`LOGGING_STOP` and `LOGGINGHOST_STARTSTOP` deserve explicit modelling
rather than falling to the catch-all. A device being told to stop
logging, or to stop shipping to its collector, is the last thing the
estate will see from it -- the record announcing the blind spot is the
only evidence the blind spot exists. `RELOAD` has the same property.

Map these to the process family with the operation verb that matches
(`OPERATION_TYPE_STOP` / `OPERATION_TYPE_START` where the enum has a
member), and keep the reason string, which is where "requested by
console" versus "requested by user X" is recorded.

