<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Walkthrough 16 -- Nokia NFM-P, a management plane with no logins

Vendor / product: Nokia / NFM-P (Network Functions Manager - Packet, now
NSP), the management system for a Nokia SR OS estate. Dataset:
`nokia_nfmp_raw`, RFC 3164 syslog.

What this walkthrough shows: a source where the interesting decisions are
all about what NOT to claim. It is a Java application log carried over
syslog, so every line has TWO headers -- the syslog envelope and the
application's own. It contains no human authentication at all, and the
phrase that looks like a login means something else entirely. Handling
it correctly is mostly a matter of resisting three plausible mappings.

It applies Recipe 14 from [extraction-recipes.md](../extraction-recipes.md)
for the nested header, the Stage 0 envelope from
[syslog-envelope.md](../syslog-envelope.md), the per-record
classification and catch-all from
[record-classification.md](../record-classification.md), and the
command-execution treatment from
[process-mapping.md](../process-mapping.md).

Contrast this with the SR OS event token in extraction-recipes Recipe 7.
That is the same vendor's NETWORK ELEMENT, and it is the opposite case:
structured event codes, real user logins, a clear authentication story.
The element and its manager need entirely different rules.

## The record shape

One invariant shape, and everything hangs off it:

```
<PRI>Mmm DD HH:MM:SS <host> NFM-P-<COMPONENT>: <YYYY.MM.DD HH:MM:SS mmm +ZZZZ><SEV><host><thread><java.class.method> message
|________ syslog envelope ________|_________________ application header _________________|_ message _
```

Severity is a single letter, `I` / `W` / `E`. The inner fields are
`<>`-delimited, so they are captured on that delimiter and nothing else
-- thread names legitimately contain colons, parentheses and addresses.

## The shape census

| # | Class family | Discriminator | Treatment |
| --- | --- | --- | --- |
| 1 | Outward SNMP failure | `DiscoveryResponseConsumerSnmpV3`, `SnmpResyncScoper` | mediation failure, NOT authentication -- see below |
| 2 | User activity audit | `server.sysact.ActivityTask` | PROCESS event, `OPERATION_TYPE_AUDIT`, no tag |
| 3 | Mediation / file transfer | `server.mediator.*` | outcome from the severity letter; target from the management address |
| 4 | Trap destination change | `TrapDestAsyncSnmpSet` | mediation; redirects where a device sends telemetry |
| 5 | Config backup | `server.rsync.*` | device identity is inside a PATH, not a field |
| 6 | Poller telemetry | `PollerWorkerTask`, `SysUpTimeTask` | the bulk of the volume; NE and management addresses differ |
| 7 | Platform internals | JVM memory, ZooKeeper | classified, no story |
| 8 | Continuation line | no application header at all | catch-all sentinel |

## Three things not to claim

### There is no authentication story

Not one human login appears in this source. The only thing resembling authentication is the management system
authenticating OUTWARD to a managed element, and the vendor's own wording
makes it unusable as an outcome:

```
It is NOT responding or SNMP V3 Authentication failed: 198.51.100.86 : attempt 4 of 5 Probable Cause: SAM_SNMP_ERR_REQUEST_TIMEOUT(-1)
```

The message says "or". The probable cause says timeout. The record cannot
distinguish a credential rejection from an unreachable device, so a rule
that tags it `EVENT_TAG_AUTHENTICATION` and sets `OUTCOME_FAILED` is
asserting something the source did not say. It is mapped as a mediation
failure instead. This is the partial-story test from
record-classification: a record that cannot answer the questions the
story exists to answer does not belong to the story.

There is also no source address to map. Every record carries exactly one
address and it is the peer being managed, so the entity-padding gate
applies -- do not pad a source that does not exist.

### `logged in` is a false friend, and it is everywhere

In this source every occurrence is:

```
EXCEPTION logged in java.net.ConnectException: Connection timed out
```

Logged as in written to a log. A keyword-built authentication rule would
tag thousands of connection timeouts as logins, and the result would pass
every mechanical check -- populated, non-null, not the sentinel. The same
file also carries `Could not login` inside a ZooKeeper Kerberos advisory.
Meanwhile the SAME phrase on the SR OS element IS a genuine login. The
class name says what a record is; the prose never does.

### The audit trail is a command execution, not a login

It has a named actor, a verb, a target object and an outcome:

```
User Activity for User: 4008225 RequestId: 3436 Type: Deployment Deletion ObjectId: network:203.0.113.226:router-1:ip-interface-75:BFDConfiguration ObjectType: Bfd Config State: Success
```

That is the AAA command-accounting shape: it maps to the process family
with `OPERATION_TYPE_AUDIT` and no authentication tag. The THREAD is
load-bearing here -- `http_8080 task-11` is the web interface while
`DeployCleanWorker [1]` is an internal worker, so the log records the
access channel a privileged change arrived on, which is worth keeping.

## The rule

```
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
```

## What the traps cost, concretely

- `divide()` returns a float, so the priority severity needs
  `to_integer(divide(...))` before it is multiplied back. Without the
  coercion every record decodes as severity 0 and every log level comes
  out `ERROR`. The mapping looks fully populated while being uniformly
  wrong.
- The vendor writes `management IP Address [198.51.100.28 ]`, with the
  space INSIDE the bracket. `\[([^\]]+)\]` captures the space with it,
  and that address never compares equal to the same address written
  without it. The capture is bounded on the octet quad instead.
- An empty class field arrives as `><>` on the JVM memory record.
  `([^>]+)` would fail to match the whole header and silently drop every
  field it was extracting, so the capture uses `([^>]*)` and the empty
  result is nulled explicitly -- an empty string is not a value, and
  `coalesce` will happily keep one.

## What stays NOT MAPPED

```
NOT MAPPED
  application timestamp  -- no XDM home; Cortex sets _time at INGEST and a MODEL rule must not assign it (WARN-018).
                            Its space-separated millisecond token is a real parsing problem, but a PARSING-rule one.
  RequestId              -- an internal correlation id with no XDM home; retain only if a downstream rule needs it
  SNMP probable cause    -- vendor diagnostic string; the severity letter already carries the outcome
  backup path            -- the managed device address is embedded in the path; recoverable but not a field
```

## Checklist

```
[ ] Stage 0 envelope is relay-aware and prepend-robust; --prepend-check passes
[ ] every inner header field captured on its <> delimiter, with * not +
[ ] classification keyed on java.class.method, never on message prose
[ ] no EVENT_TAG_AUTHENTICATION anywhere in this rule
[ ] no source entity padded -- the source does not exist on these records
[ ] audit records carry OPERATION_TYPE_AUDIT and no story tag
[ ] continuation lines reach the GOCORTEX_UNMODELLED catch-all
[ ] every address capture bounded on content, not on a delimiter
[ ] to_integer() wraps divide() before the quotient is multiplied back
```

## Class families represented

The fixture (`tests/fixtures/nokia_nfmp.jsonl`) carries one record per
family in the census above, drawn from a week of production traffic
covering 35 distinct `java.class.method` values. It is a representative
sample of the families, not an exhaustive catalogue of the classes.
