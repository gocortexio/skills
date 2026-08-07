<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Walkthrough 8 -- Cisco TACACS+ AAA, nine event shapes through one rule

Vendor / product: Cisco / Secure ACS TACACS+ (the same structure applies
to any tac_plus-style daemon, and the guidance generalises to RADIUS and
Cisco ISE syslog -- see the Cisco ISE syslog reference for the full ISE
message catalogue). Dataset: `cisco_tacacs_raw`, RFC 3164 syslog.

What this walkthrough shows: an AAA gateway emits MANY event shapes from
one daemon family -- structured key=value, legacy freeform prose, and
pure diagnostic chatter -- and one MODEL rule normalises all of them
through a single shared assignment stage while classifying PER RECORD.
It applies the AAA topology and vocabulary rules from
[authentication-mapping.md](../authentication-mapping.md) (AAA gateways
section), the Stage 0 envelope from
[syslog-envelope.md](../syslog-envelope.md), the full 15-field
authentication mandatory set, and the record-level classification and
catch-all from
[record-classification.md](../record-classification.md). Not every
record is authentication: the login, authorization and session shapes
carry `EVENT_TAG_AUTHENTICATION` (no network tag -- these hold no
transport flow), a command-accounting record is a PROCESS event with no
tag, and any line the rule cannot classify gets the catch-all so the
datamodel row count still equals the raw count.

## The shape census

One day of records from this daemon family falls into nine groups:

| # | Shape | Discriminator | Treatment |
| --- | --- | --- | --- |
| 1 | AUTH PERMIT (structured kv) | `type=AUTHENTICATION action=PERMIT` | login success |
| 2 | AUTH DENY (structured kv) | `type=AUTHENTICATION action=DENY` | login failure + reason |
| 3 | Command accounting | `type=ACCOUNTING action=Stop` with `cmd=` | PROCESS event; `cmd` -> `target.process.command_line`; no auth tag |
| 4 | Session accounting Start | `type=ACCOUNTING action=Start` | auth story; session lifecycle, NO outcome |
| 5 | Session accounting Stop | `type=ACCOUNTING action=Stop`, no `cmd=` | auth story; duration from elapsed_time |
| 6 | Legacy authorization permitted | `Authorization permitted for` | auth story; audit success |
| 7 | Legacy authorization denied | `Authorization denied for` | auth story; audit failure |
| 8 | Legacy login | `Logged in Successfully` / `Login Failure` | login success / failure |
| 9 | Diagnostic chatter | parser hooks, key errors | CATCH-ALL: `original_event_type = "GOCORTEX_UNMODELLED"`, blank tags |

Two structural decisions follow:

- Never drop a record. The only filter is `_raw_log != null`; there is
  no discriminator filter. Every record produces a row, so a
  `datamodel` search returns the same count as the raw dataset. The
  classification `if()`-chains recognise each shape by its own
  discriminator and let the diagnostic chatter fall through to the
  catch-all (`xdm.event.original_event_type = "GOCORTEX_UNMODELLED"`,
  blank tags) rather than being discarded.
- One pipeline, shared drain. The shape families converge on the same
  identities (`coalesce()` over the per-shape temps) and the same
  assignment stage, so nothing drifts between duplicated drains. The
  alternative -- one `;`-terminated pipeline per family inside the one
  MODEL block -- is equally valid and better when the shapes share
  little; here they share almost everything.

## The AAA topology

Three parties, not two. The principal (`user=`) is the source; the
principal's workstation (`src_ip=`) is the source address; the network
device being accessed (`dvc_ip=` / `at <ip>`) is the target; and the
AAA server that validates the request is the observer (its name comes
from the Stage 0 envelope host). `xdm.auth.service = "Universal"`: the
field carries the ROLE, and TACACS+ is not a known IdP provider, so
neither `"SP"` nor `"IDP"` describes this flow (see
[../house-conventions.md](../house-conventions.md)). The AAA protocol
is a mechanism, not a role: it goes to `xdm.auth.auth_method`, and to
`xdm.network.application_protocol` as well, because on this feed the
TACACS+ transaction IS the session being logged.

TACACS+ principals (`svc_nms1`, `alice.admin`) are not UPN-shaped,
but `xdm.source.user.upn` is the mandatory correlation key and cannot
be empty: map the raw principal to it anyway, mirrored into
`xdm.source.user.username`.

## The full rule

```
[MODEL: dataset = cisco_tacacs_raw]
filter
    _raw_log != null
| alter
    tmp_pri        = to_integer(to_number(arrayindex(regextract(_raw_log, "^<(\d{1,3})>"), 0))),
    tmp_host_5424  = arrayindex(regextract(_raw_log, "^<\d{1,3}>\d+\s+\S+\s+(\S+)\s"), 0),
    tmp_host_3164  = arrayindex(regextract(_raw_log, "^<\d{1,3}>[A-Za-z]{3}\s+\d+\s+[\d:]+\s+(\S+)\s"), 0)
| alter
    tmp_syslog_host_raw = coalesce(tmp_host_5424, tmp_host_3164)
| alter
    tmp_syslog_host = if(tmp_syslog_host_raw != "-", tmp_syslog_host_raw)
| alter
    tmp_pri_facility = to_integer(divide(tmp_pri, 8))
| alter
    tmp_pri_severity = to_integer(subtract(tmp_pri, multiply(tmp_pri_facility, 8)))
| alter
    tmp_pri_log_level = if(
        tmp_pri_severity <= 2, XDM_CONST.LOG_LEVEL_CRITICAL,
        tmp_pri_severity = 3,  XDM_CONST.LOG_LEVEL_ERROR,
        tmp_pri_severity = 4,  XDM_CONST.LOG_LEVEL_WARNING,
        tmp_pri_severity = 5,  XDM_CONST.LOG_LEVEL_NOTICE,
        tmp_pri_severity != null, XDM_CONST.LOG_LEVEL_INFORMATIONAL)
| alter
    tmp_kv_type = arrayindex(regextract(_raw_log, "type=(\w+)"), 0),
    tmp_kv_action = arrayindex(regextract(_raw_log, "action=(\w+)"), 0),
    tmp_kv_user = arrayindex(regextract(_raw_log, "user=\"([^\"]+)\""), 0),
    tmp_kv_dvc_ip = arrayindex(regextract(_raw_log, "dvc_ip=([\d.]+)"), 0),
    tmp_kv_src_ip = arrayindex(regextract(_raw_log, "src_ip=([\d.]+)"), 0),
    tmp_kv_reason = arrayindex(regextract(_raw_log, "reason=\"([^\"]+)\""), 0),
    tmp_kv_rule = arrayindex(regextract(_raw_log, "rule=\"([^\"]+)\""), 0),
    tmp_kv_task = arrayindex(regextract(_raw_log, "task_id=(\d+)"), 0),
    tmp_kv_priv = arrayindex(regextract(_raw_log, "priv_lvl=(\d+)"), 0),
    tmp_kv_cmd = arrayindex(regextract(_raw_log, "cmd=\"([^\"]+)\""), 0),
    tmp_kv_elapsed = arrayindex(regextract(_raw_log, "elapsed_time=(\d+)"), 0),
    tmp_az_result = arrayindex(regextract(_raw_log, "Authorization (permitted|denied) for"), 0),
    tmp_az_user = arrayindex(regextract(_raw_log, "Authorization (?:permitted|denied) for ([A-Za-z0-9._-]+)"), 0),
    tmp_az_ip = arrayindex(regextract(_raw_log, "Authorization (?:permitted|denied) for \S+ at ([\d.]+)"), 0),
    tmp_az_group = arrayindex(regextract(_raw_log, "group ([^,.]+)"), 0),
    tmp_lg_result = arrayindex(regextract(_raw_log, "(Logged in Successfully|Login Failure)"), 0),
    tmp_lg_user = arrayindex(regextract(_raw_log, "user=(.+?) from "), 0),
    tmp_lg_from_ip = arrayindex(regextract(_raw_log, "from ([\d.]+) to "), 0),
    tmp_lg_to_ip = arrayindex(regextract(_raw_log, " to ([\d.]+)"), 0)
| alter
    tmp_user = coalesce(tmp_kv_user, tmp_az_user, tmp_lg_user),
    tmp_src_ip = coalesce(tmp_kv_src_ip, tmp_lg_from_ip),
    tmp_dvc_ip = coalesce(tmp_kv_dvc_ip, tmp_az_ip, tmp_lg_to_ip),
    tmp_outcome_token = coalesce(tmp_kv_action, tmp_az_result, tmp_lg_result),
    tmp_oet_kv = if(tmp_kv_type != null, concat(tmp_kv_type, " ", tmp_kv_action)),
    tmp_oet_az = if(tmp_az_result != null, concat("Authorization ", tmp_az_result))
| alter
    tmp_oet = coalesce(tmp_oet_kv, tmp_oet_az, tmp_lg_result)
| alter
    xdm.observer.vendor = "Cisco",
    xdm.observer.product = "Secure ACS TACACS+",
    xdm.observer.name = tmp_syslog_host,
    xdm.event.log_level = tmp_pri_log_level,
    xdm.event.type = if(
        tmp_kv_cmd != null, "process",
        tmp_oet != null, "authentication",
        "GOCORTEX_UNMODELLED"),
    xdm.event.tags = if(
        tmp_kv_cmd != null, null,
        tmp_oet != null, arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION),
        null),
    xdm.event.original_event_type = coalesce(tmp_oet, "GOCORTEX_UNMODELLED"),
    xdm.event.operation = if(
        tmp_kv_type = "ACCOUNTING", XDM_CONST.OPERATION_TYPE_AUDIT,
        tmp_az_result != null, XDM_CONST.OPERATION_TYPE_AUDIT,
        tmp_oet != null, XDM_CONST.OPERATION_TYPE_AUTH_LOGIN),
    xdm.event.operation_sub_type = if(
        tmp_kv_type = "AUTHENTICATION", "password",
        tmp_lg_result != null, "password"),
    xdm.target.process.command_line = tmp_kv_cmd,
    xdm.event.outcome = if(
        tmp_outcome_token = "PERMIT", XDM_CONST.OUTCOME_SUCCESS,
        tmp_outcome_token = "permitted", XDM_CONST.OUTCOME_SUCCESS,
        tmp_outcome_token = "Logged in Successfully", XDM_CONST.OUTCOME_SUCCESS,
        tmp_outcome_token = "DENY", XDM_CONST.OUTCOME_FAILED,
        tmp_outcome_token = "denied", XDM_CONST.OUTCOME_FAILED,
        tmp_outcome_token = "Login Failure", XDM_CONST.OUTCOME_FAILED),
    xdm.event.outcome_reason = if(
        tmp_kv_reason = "Bad Password", "bad_credentials",
        tmp_kv_reason = "No such user", "user_does_not_exist",
        tmp_kv_reason != null, tmp_kv_reason),
    xdm.event.duration = to_integer(multiply(to_number(tmp_kv_elapsed), 1000)),
    xdm.event.description = concat("TACACS+ ", tmp_oet, " for ", tmp_user),
    xdm.auth.service = "Universal",
    xdm.auth.auth_method = "TACACS+",
    xdm.network.application_protocol = "tacacs-plus",
    xdm.auth.privilege_level = if(
        tmp_kv_priv = "15", XDM_CONST.PRIVILEGE_LEVEL_ADMIN,
        tmp_kv_priv != null, XDM_CONST.PRIVILEGE_LEVEL_USER),
    xdm.source.user.upn = if(
        tmp_user contains "@", tmp_user,
        tmp_user != null, concat(tmp_user, "@localhost")),
    xdm.source.user.identity_type = if(
        tmp_user != null, XDM_CONST.IDENTITY_TYPE_USER,
        XDM_CONST.IDENTITY_TYPE_UNKNOWN),
    xdm.source.user.user_type = if(
        tmp_user = null, XDM_CONST.USER_TYPE_REGULAR,
        tmp_user contains "$", XDM_CONST.USER_TYPE_MACHINE_ACCOUNT,
        lowercase(tmp_user) ~= "^svc[-_.]|service|gserviceaccount",
            XDM_CONST.USER_TYPE_SERVICE_ACCOUNT,
        XDM_CONST.USER_TYPE_REGULAR),
    xdm.source.user.username = tmp_user,
    xdm.source.user.groups = if(tmp_az_group != null, arraycreate(tmp_az_group), null),
    xdm.source.ipv4 = tmp_src_ip,
    xdm.source.port = to_integer(0),
    xdm.target.ipv4 = coalesce(tmp_dvc_ip, ""),
    xdm.target.port = to_integer(0),
    xdm.target.resource.name = tmp_dvc_ip,
    xdm.network.ip_protocol = XDM_CONST.IP_PROTOCOL_TCP,
    xdm.network.session_id = tmp_kv_task,
    xdm.network.rule = tmp_kv_rule
;
// REVIEW UNMODELLED -- list records this rule could not classify and
// grow it to cover them:
//   datamodel dataset = cisco_tacacs_raw
//   | filter xdm.event.original_event_type = "GOCORTEX_UNMODELLED"
//   | fields xdm.event.original_event_type, cisco_tacacs_raw._raw_log
//
// RAISE SKILL ISSUES -- report a mis-mapping (include the REVIEW
// UNMODELLED output above): https://github.com/gocortexio/skills/issues
```

## Key decisions worth copying

- Classify per record, never drop. The `xdm.event.type` / `xdm.event.tags`
  if-chains recognise each shape by its own discriminator: a
  command-accounting record (`tmp_kv_cmd` present) is a PROCESS event with no
  tag, the login / authorization / session shapes (`tmp_oet` present) are the
  authentication story, and everything else -- the Inconsistent-lengths /
  PostSearchHook / createreturnattrs chatter -- falls through to the
  catch-all (`xdm.event.original_event_type = "GOCORTEX_UNMODELLED"`, blank
  tags). Nothing is filtered out, so the datamodel row count matches raw.
- Command accounting is a command execution, not authentication: the
  executed `cmd=` goes to `xdm.target.process.command_line` with
  `xdm.event.type = "process"`, `operation OPERATION_TYPE_AUDIT` and no
  outcome, and NO `EVENT_TAG_AUTHENTICATION`.
- Outcome only on conclusive events. PERMIT / permitted / Logged in
  Successfully -> `OUTCOME_SUCCESS`; DENY / denied / Login Failure ->
  `OUTCOME_FAILED`; accounting Start / Stop is session lifecycle and
  the if-chain deliberately has no default, so outcome stays null there.
- `xdm.event.operation` splits AUTH_LOGIN (authentication + legacy
  login) from AUDIT (command / session accounting + authorization). The
  auth method is `"password"` on the login shapes; the final AUTH_LOGIN
  branch is gated on `tmp_oet != null` so unrecognised chatter gets no
  operation.
- Reason normalisation with passthrough: `Bad Password` ->
  `bad_credentials`, `No such user` -> `user_does_not_exist`, and
  any unrecognised vendor reason passes through unchanged rather than
  being forced to a placeholder.
- The async guard: every address capture is `([\d.]+)`, so the legacy
  placeholder token `from async` can never land in an IPv4 field -- it
  simply fails the capture and the temp stays null.
- Bounded username capture: `user=(.+?) from ` survives principals
  with embedded spaces (`user1 line1.co`); the structured shapes use
  the quoted capture instead.
- The upn is ALWAYS UPN-shaped: a bare principal gets
  `concat(tmp_user, "@localhost")`, and an identity that already
  carries `@` passes through unchanged. The raw principal stays in
  `xdm.source.user.username`.
- `priv_lvl` maps to the closed list: `15` ->
  `PRIVILEGE_LEVEL_ADMIN`, anything else present ->
  `PRIVILEGE_LEVEL_USER`. `group` becomes a one-element
  `xdm.source.user.groups` array.
- `task_id` -> `xdm.network.session_id` correlates the Start / Stop /
  command records of one shell session; `elapsed_time` is SECONDS and
  `xdm.event.duration` is MILLISECONDS, so the mapping multiplies by
  1000 (function-form, ERR-012 safe).

## NOT MAPPED, with reasons

```
NOT MAPPED
  port=            -- TTY / line name (vty0, /dev/pts/7, rest_http), not a TCP
                      port; the mandatory integer ports take to_integer(0)
  client=          -- policy network-match classifier (CIDR), not an endpoint
  timezone=        -- session-local display detail
  start_time= / stop_time= -- Cortex sets _time at INGEST (WARN-018);
                      duration already carries elapsed_time
  disc_cause= / disc_cause-ext= -- vendor disconnect taxonomy with no XDM
                      home; retain in the raw record
  service=         -- TACACS service selector (shell / ppp); not an
                      application protocol observation
```

## Checklist

```
[ ] only filter is _raw_log != null (no discriminator filter; nothing dropped)
[ ] type/tags classified per record; chatter -> GOCORTEX_UNMODELLED catch-all
[ ] command accounting -> event.type "process", cmd -> target.process.command_line, no auth tag
[ ] REVIEW UNMODELLED query present with the real dataset
[ ] Stage 0 envelope: PRI-anchored host + priority decode (WARN-040/041)
[ ] all 15 authentication mandatory fields mapped or padded (WARN-042)
[ ] auth shapes carry EVENT_TAG_AUTHENTICATION only -- no network tag without a transport flow
[ ] outcome null on accounting lifecycle rows; SUCCESS / FAILED elsewhere
[ ] upn ALWAYS UPN-shaped: contains-@ passthrough, else concat(tmp_user, "@localhost")
[ ] address captures restricted to [\d.]+ (the async guard)
[ ] proven with verify_rule.py across one line from every shape group
```
