<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Extraction recipes (syslog / text / CEF / LEEF)

Verified starting points for the hardest extraction case: a syslog or
text `_raw_log` where fields are not addressable by a JSON path. For
JSON, use Pattern A (`json_extract_scalar`) -- it is exact and needs no
recipe. These recipes exist to raise confidence in field LOCATION and
give clean, well-formed extraction for the shapes that recur across
vendors.

These are advisory, not mandatory. They do NOT replace judgement: copy
the closest recipe, then adapt the regex and the field names to the
actual sample in front of you. Every recipe below is a complete MODEL
rule that lints clean and is checked end-to-end by
`tests/test_extraction_recipes.py` (the sample line in "Yields" is the
verified input/output), so you start from something known-correct rather
than an invented pattern.

General rules that keep extraction clean:

- `regextract(_raw_log, "...(group)...")` returns the FIRST capture
  group as an array; wrap it in `arrayindex(..., 0)` to get the scalar.
- Anchor the value, not the noise: capture `([^\s]+)` (or a typed shape
  like an IPv4 octet quad) rather than greedy `.*`.
- Coerce numerics: `to_integer(to_number(tmp_port))`; wrap an array leaf in
  `arraycreate(...)`.
- For a `<NNN>` priority syslog envelope, decode the header once with the
  canonical Stage 0 idiom in [syslog-envelope.md](syslog-envelope.md)
  first, then apply a payload recipe below. Do not anchor a header regex
  on a vendor literal (WARN-040).

## Recipe 1 -- key=value pairs (unquoted and quoted)

When: the payload is `key=value` tokens, values either bare or
double-quoted (the most common syslog/kv shape).

```
[MODEL: dataset=vendor_kv_raw]
filter
    _raw_log != null
| alter
    tmp_user = arrayindex(regextract(_raw_log, "\buser=([^\s]+)"), 0),
    tmp_msg = arrayindex(regextract(_raw_log, "msg=\"([^\"]*)\""), 0)
| alter
    xdm.source.user.username = tmp_user,
    xdm.event.description = tmp_msg
;
```

Yields, for `ts=2026-07-09 user=alice.admin action=login msg="Login succeeded"`:
`xdm.source.user.username = "alice.admin"`,
`xdm.event.description = "Login succeeded"`.

### The doubled-quote trap (verify before trusting a quoted capture)

A delimiter-anchored capture like `"([^"]*)"` is correct only while the
payload is quoted exactly once. A forwarding chain that CSV-escapes the
line doubles every quote, and the delimiter-anchored form then fails
SILENTLY:

```
// the payload arrives doubly quoted
... type=AUTHENTICATION action=PERMIT user=""acct_name"" rule=""rule_name""
```

| Pattern | Matches | Captures |
| --- | --- | --- |
| `user="([^"]+)"` | nothing | nothing |
| `user="([^"]*)"` | every record | the empty string |
| `user=[^A-Za-z0-9]*([A-Za-z0-9_.@\-]+)` | every record | `acct_name` |

The `*` quantifier is the dangerous one: it matches the zero-length gap
BETWEEN the two quotes, so the capture succeeds on every record and a
coverage count declares the mapping healthy while every value is empty.
The `+` variant fails loudly, which is safer but still wrong. Writing
the quote as `\x22` or `\042` changes nothing -- the quantifier is the
problem, not the escape. (An escaped `\"` does work in an XQL regex;
that is not the issue here.)

Prefer the delimiter-agnostic form as the default for any kv source that
might pass through a forwarder. It handles bare, single-quoted and
doubly-quoted values with one pattern:

```
// single-word value
key=[^A-Za-z0-9]*([A-Za-z0-9_.@\-]+)
// value that may contain spaces
key=[^A-Za-z0-9]*([A-Za-z0-9_.@\- ]*[A-Za-z0-9_.@\-])
```

Use `([^\s]+)` for a bare value and the agnostic form when quoting is
uncertain. Whichever you pick, confirm it by printing real captured
VALUES, not a match count -- see "Prove a capture with values" below.

### Spelling variants of one field

A long-lived product accumulates spellings across releases, and one
dataset can carry several at once. A single TACACS feed can emit
`priv_lvl=`, `priv-lvl=` and `privilege=` side by side, so capturing
only the spelling the sample happened to show silently loses the rest.
Put every variant in one alternation:

```
tmp_priv = arrayindex(regextract(_raw_log, "priv(?:_lvl|-lvl|ilege)=\s*(\d+)"), 0)
```

### Prove a capture with values

A match count is not evidence that a capture works. Each of these
matches a large share of records while capturing nothing usable:

```
rule="([^"]*)"     matches, every value empty
rule=.(.*?).\s     matches, values truncated ("IPN" from ""IPNE ngtt"")
user="([^"]*)"     matches, every value empty
```

Any coverage query passes all three. When verifying an extraction,
print the captured VALUES, and include at least one multi-word value so
a non-greedy quantifier that truncates is caught.

## Recipe 2 -- transport tuple (src=IP:port dst=IP:port)

When: a firewall / flow line carries endpoints as `src=`/`dst=` with an
optional `:port` suffix.

```
[MODEL: dataset=vendor_fw_raw]
filter
    _raw_log != null
| alter
    tmp_src_ip = arrayindex(regextract(_raw_log, "src=(\d{1,3}(?:\.\d{1,3}){3})"), 0),
    tmp_src_port = arrayindex(regextract(_raw_log, "src=\d{1,3}(?:\.\d{1,3}){3}:(\d{1,5})"), 0),
    tmp_dst_ip = arrayindex(regextract(_raw_log, "dst=(\d{1,3}(?:\.\d{1,3}){3})"), 0)
| alter
    xdm.source.ipv4 = tmp_src_ip,
    xdm.source.port = to_integer(to_number(tmp_src_port)),
    xdm.target.ipv4 = tmp_dst_ip
;
```

Yields, for `action=accept src=10.0.0.5:51000 dst=93.184.216.34:443 proto=tcp`:
`xdm.source.ipv4 = "10.0.0.5"`, `xdm.source.port = 51000`,
`xdm.target.ipv4 = "93.184.216.34"`. The IP is captured by the octet
quad, so it is well-formed even amid noise.

## Recipe 3 -- CEF header + extension

When: the line is `CEF:0|vendor|product|version|sig|name|severity|ext`.
The header is pipe-delimited; the extension is key=value (use Recipe 1).

```
[MODEL: dataset=vendor_cef_raw]
filter
    _raw_log != null
| alter
    tmp_cef_name = arrayindex(split(_raw_log, "|"), 5),
    tmp_suser = arrayindex(regextract(_raw_log, "suser=([^\s]+)"), 0)
| alter
    xdm.event.original_event_type = tmp_cef_name,
    xdm.source.user.username = tmp_suser
;
```

Yields, for `CEF:0|Acme|Box|1.0|100|User login|5|src=10.0.0.5 suser=alice`:
`xdm.event.original_event_type = "User login"`,
`xdm.source.user.username = "alice"`. Header indices: 1 vendor, 2
product, 3 version, 4 signature id, 5 name, 6 severity; the extension is
index 7 onward.

## Recipe 4 -- LEEF header + extension

When: the line is `LEEF:2.0|vendor|product|version|eventid|<key=value ...>`.
Header is pipe-delimited; the eventid is index 4.

```
[MODEL: dataset=vendor_leef_raw]
filter
    _raw_log != null
| alter
    tmp_leef_evt = arrayindex(split(_raw_log, "|"), 4),
    tmp_usr = arrayindex(regextract(_raw_log, "usrName=([^\s\t]+)"), 0)
| alter
    xdm.event.original_event_type = tmp_leef_evt,
    xdm.source.user.username = tmp_usr
;
```

Yields, for `LEEF:2.0|Acme|Box|1.0|4624|usrName=alice src=10.0.0.5`:
`xdm.event.original_event_type = "4624"`,
`xdm.source.user.username = "alice"`. LEEF extension pairs may be tab- or
space-delimited, so stop the value at `[^\s\t]+`.

## Recipe 5 -- Unix syslog process / host (prepend-tolerant, PRI optional)

When: `Mon DD HH:MM:SS host proc[pid]: message`. The same source can
arrive three ways -- direct with a PRI (`<134>Mon DD ...`), direct with
the PRI stripped by a relay (`Mon DD ...`), or relay-prepended with a
second header in front. The host is captured with a greedy `^.*` prefix
and an optional `(?:<\d{1,3}>)?` PRI, so all three yield the origin
host; the `proc[pid]:` process/pid are token-anchored and so are already
position-independent (see the HARD RULE in syslog-envelope.md).

```
[MODEL: dataset=vendor_nix_raw]
filter
    _raw_log != null
| alter
    tmp_host = arrayindex(regextract(_raw_log, "^.*(?:<\d{1,3}>)?[A-Za-z]{3}\s+\d+\s+[\d:]+\s+(\S+)\s"), 0),
    tmp_proc = arrayindex(regextract(_raw_log, "(\w+)\[\d+\]:"), 0),
    tmp_pid = arrayindex(regextract(_raw_log, "\[(\d+)\]:"), 0)
| alter
    xdm.observer.name = tmp_host,
    xdm.source.process.name = tmp_proc,
    xdm.source.process.pid = to_integer(to_number(tmp_pid))
;
```

Yields, for `Jun 19 09:51:59 host01 sshd[1234]: Accepted password for alice`:
`xdm.observer.name = "host01"`, `xdm.source.process.name = "sshd"`,
`xdm.source.process.pid = 1234`. The `<134>Jun 19 09:51:59 host01 ...` and
relay-prepended `<190>... relay01 <134>Jun 19 09:51:59 host01 ...` forms
yield the identical origin `host01` / `sshd` / `1234`.

## Recipe 6 -- clean scalars from a free-text line

When: the message is prose but contains well-formed tokens (an IP, a MAC,
an email/UPN). Capture the token shape, not its position.

```
[MODEL: dataset=vendor_text_raw]
filter
    _raw_log != null
| alter
    tmp_ip = arrayindex(regextract(_raw_log, "\b(\d{1,3}(?:\.\d{1,3}){3})\b"), 0),
    tmp_mac = arrayindex(regextract(_raw_log, "\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b"), 0),
    tmp_email = arrayindex(regextract(_raw_log, "\b([\w.+-]+@[\w.-]+\.\w+)\b"), 0)
| alter
    xdm.source.ipv4 = tmp_ip,
    xdm.source.host.mac_addresses = arraycreate(tmp_mac),
    xdm.source.user.upn = tmp_email
;
```

Yields, for `Login from 10.0.0.5 (aa:bb:cc:dd:ee:ff) by alice@corp.example.com`:
`xdm.source.ipv4 = "10.0.0.5"`,
`xdm.source.host.mac_addresses = ["aa:bb:cc:dd:ee:ff"]`,
`xdm.source.user.upn = "alice@corp.example.com"`. Token-shape capture is
what makes free-text extraction clean and position-independent.

## Recipe 7 -- structured event token (app-severity-event)

When: a network appliance writes a positional line whose payload carries
a compound event token
`<router-instance> <APPLICATION>-<SEVERITY>-<eventName>-<eventID> [<subject>]: <msg>`
(Nokia SR OS is the canonical case; other structured appliance logs share
the shape).

```
<187>Jul 30 23:25:19 172.25.127.224 host-c9e773f1: 7539824 vprn170 SECURITY-MINOR-ssh_user_login-2009 [user_575b9419]:  User user_575b9419 from 172.30.18.99 logged in
```

Read the line as: PRI, timestamp, HOSTNAME (an address here), syslog TAG,
sequence number, router instance, the event token, the bracketed subject,
then the message. Note the third token is the TAG, not the device name --
it varies (`host-<id>`, `ALUCE`, `TMNX`) and a rule that reads it as the
hostname gets a constant on a large share of records.

```
[MODEL: dataset=vendor_sros_raw]
filter
    _raw_log != null
| alter
    // Anchor on the SEVERITY, a closed documented vendor enum. Anchoring
    // on the router instance instead (a literal "Base ") silently drops
    // every event inside a named VPRN, which is where the customer-VPN
    // traffic is.
    tmp_sros_app  = arrayindex(regextract(_raw_log, "\s([A-Z][A-Z0-9_]{1,15})-(?:CLEARED|CRITICAL|MAJOR|MINOR|WARNING|INDETERMINATE)-"), 0),
    tmp_sros_sev  = arrayindex(regextract(_raw_log, "\s[A-Z][A-Z0-9_]{1,15}-(CLEARED|CRITICAL|MAJOR|MINOR|WARNING|INDETERMINATE)-"), 0),
    tmp_sros_evt  = arrayindex(regextract(_raw_log, "\s[A-Z][A-Z0-9_]{1,15}-(?:CLEARED|CRITICAL|MAJOR|MINOR|WARNING|INDETERMINATE)-([A-Za-z0-9_]+)-\d+"), 0),
    tmp_sros_evid = arrayindex(regextract(_raw_log, "\s[A-Z][A-Z0-9_]{1,15}-(?:CLEARED|CRITICAL|MAJOR|MINOR|WARNING|INDETERMINATE)-[A-Za-z0-9_]+-(\d+)"), 0),
    tmp_sros_rtr  = arrayindex(regextract(_raw_log, "\s\d+\s(\S+)\s[A-Z][A-Z0-9_]{1,15}-(?:CLEARED|CRITICAL|MAJOR|MINOR|WARNING|INDETERMINATE)-"), 0),
    // The subject is only an account when it is a single token: the
    // command events also fire for script-driven CLI, where it names the
    // mechanism. A SHAPE test, never an allowlist -- an account of
    // "${jndi" is an injection attempt and must stay visible.
    tmp_sros_subject  = arrayindex(regextract(_raw_log, "-\d+\s\[(\S+)\]"), 0),
    tmp_sros_body_usr = arrayindex(regextract(_raw_log, "\bUser (\S+)"), 0)
| alter
    // The body names the user on some applications and writes a bare
    // "User from <ip>" on others, where the account is ONLY in the
    // subject bracket. Guard the literal, then prefer the subject on the
    // user-authentication events.
    tmp_sros_body_user = if(tmp_sros_body_usr != "from", tmp_sros_body_usr),
    tmp_sros_is_userevt = if(tmp_sros_evt ~= "^(cli|ssh|ftp|grpc|netconf)_user_(login|logout)", "y")
| alter
    tmp_sros_user = if(
        tmp_sros_is_userevt = "y", coalesce(tmp_sros_subject, tmp_sros_body_user),
        tmp_sros_body_user)
| alter
    xdm.event.original_event_type = concat(tmp_sros_app, "-", tmp_sros_evt),
    xdm.event.id = tmp_sros_evid,
    xdm.source.user.username = tmp_sros_user,
    // DERIVE the UPN rather than padding it: the device carries an
    // account and no domain, and @localhost states that the account is
    // local to the device, which is true for an appliance login.
    xdm.source.user.upn = if(
        tmp_sros_user contains "@", tmp_sros_user,
        tmp_sros_user != null, concat(tmp_sros_user, "@localhost")),
    xdm.observer.name = tmp_sros_rtr,
    xdm.event.log_level = if(
        tmp_sros_sev = "CRITICAL", XDM_CONST.LOG_LEVEL_CRITICAL,
        tmp_sros_sev = "MAJOR", XDM_CONST.LOG_LEVEL_ERROR,
        tmp_sros_sev = "MINOR", XDM_CONST.LOG_LEVEL_WARNING,
        tmp_sros_sev = "WARNING", XDM_CONST.LOG_LEVEL_WARNING,
        tmp_sros_sev = "CLEARED", XDM_CONST.LOG_LEVEL_INFORMATIONAL,
        tmp_sros_sev = "INDETERMINATE", XDM_CONST.LOG_LEVEL_INFORMATIONAL)
;
```

### The principal is written two ways, and one of them is a trap

The message body names the account on some applications:

```
SECURITY-MINOR-ssh_user_logout-2010 [user_575b9419]:  User user_575b9419 from 172.25.220.157 logged out
```

and on others writes a bare `User from <ip>`, with the account ONLY in
the bracketed subject:

```
USER-MINOR-cli_user_login-2001 [user_575b9419]:  User from 172.25.220.157 logged in
```

A plain `\bUser (\S+)` captures the literal string `from` on every record
of the second shape. That is the fourth failure state: not null, not
empty, not the catch-all, lints clean, and it survives every count-based
check -- while a "failed logins by user" correlation groups the whole
family under one fictional account called `from`, hiding a real
credential attack underneath it. Guard the literal explicitly.

Prefer the subject bracket for the user-authentication events, and gate
it: the subject is a general-purpose field that elsewhere holds
`[Equipment]`, `[Card A]`, `[Port 1/1/c3]`, `[tacplus server 2]`, an
address, or `[]`. Reading it unconditionally into a username field is the
same bug wearing different clothes.

Gating on the event name is necessary but not sufficient, because the
command-accounting events also fire when a SCRIPT rather than a person
drives the CLI, and the subject then names the mechanism -- often with
whitespace in it. Validate the SHAPE before using the value: an account
is a single token.

```
    tmp_sros_subject_ok = arrayindex(regextract(tmp_sros_subject, "^(\S+)$"), 0)
```

It matters that this is a shape test and not an allowlist of known-good
account names. The same field carries hostile input: a login attempt
with an account of `${jndi` is a real injection attempt at the login
prompt, it is a single token, and it must stay visible in the data. A
shape test accepts it and rejects prose; an allowlist would discard
precisely the record worth seeing.

Keep it a test of SHAPE only. Tightening it into a character allowlist
such as `[A-Za-z0-9._@\-]` would flag every Active Directory machine
account, because `WIN-DC01$` legitimately ends in a dollar sign. The
shape test decides whether this FIELD is the account on this record; it
must never decide whether the VALUE is acceptable. See
[authentication-mapping.md](authentication-mapping.md) "An identity
field records what was PRESENTED, not what is valid".

### The event key is the pair, never one half

The token carries both a name and an id, and NEITHER is unique alone.
The id collides across applications, and so does the name:

| Application | Event name | Event id |
| --- | --- | --- |
| USER | cli_user_io | 2009 |
| SECURITY | ssh_user_login | 2009 |
| SYSTEM | tmnxConfigModify | 2006 |
| SECURITY | tmnxConfigModify | 2206 |

So a correlation filtering on the id alone matches two unrelated events,
one a login and one command I/O. Map the composite
(`concat(app, "-", eventName)`) to `xdm.event.original_event_type` and
keep the id in `xdm.event.id`, so downstream content can key on the pair.

### Never classify on the application token

The application names the subsystem that spoke; only the event name says
what happened. On this vendor the SECURITY application's largest members
are not authentication at all:

- `tacplusInetSrvrOperStatusChange` -- a TACACS+ server status change,
  no user anywhere in the record.
- `tmnxMD5AuthFailure` -- a routing-protocol MD5 digest mismatch. The
  name contains `AuthFailure`, so a keyword classifier grabs it too, but
  the record names a peer address and no principal
  (`Incoming packet from source address ... dropped due to MD5 digest mismatch`).

Classifying on the application would tag device-status and routing
records as user authentication. Under the story hard rule neither may
take `EVENT_TAG_AUTHENTICATION`, because neither can populate an actor --
see [record-classification.md](record-classification.md).

### Command I/O is command accounting, not authentication

`cli_user_io` and `cli_config_io` carry the CLI command after the prompt
terminator, with the configuration context in the prompt itself:

```
USER-WARNING-cli_config_io-2011 [user_7a0224ca]:  User from 198.51.100.142: host-f43b299e>config>system#  ptp
```

Route these to the process family exactly as a TACACS+ `cmd=` record is
routed: the command to `xdm.target.process.command_line` with
`XDM_CONST.OPERATION_TYPE_AUDIT`, no outcome, and NO authentication tag.
Capture the command after the `#` or `>` prompt terminator, and keep the
prompt's context path if it is useful.

```
    tmp_sros_cmd = arrayindex(regextract(_raw_log, ":\s+\S*[#>]\s+(.*\S)"), 0)
```

Severity bands to an `XDM_CONST.LOG_LEVEL_*` via an if-chain over the
closed enum above. `from (\S+)` gives the origin -- a console / session
label or an address, so map it to `xdm.source.ipv4` ONLY when it is an
address. Keep `xdm.event.type` the story value, never the raw token.

## Recipe 8 -- bracketed [key: value] fields (Cisco IOS-style)

When: a positional line carries `[key: value]` bracketed fields after a
`%FACILITY-SEVERITY-MNEMONIC:` token (the Cisco IOS / IOS-XE Catalyst
`%SEC_LOGIN-*` auth line is the canonical case; many IOS mnemonics use
this bracket shape). Capture the compound mnemonic and each bracketed
value.

```
[MODEL: dataset=vendor_ios_raw]
filter
    _raw_log != null
| alter
    tmp_ios_event = arrayindex(regextract(_raw_log, "%([\w]+-\d-\w+):"), 0),
    tmp_ios_user = arrayindex(regextract(_raw_log, "\[user: ?([^\]]+)\]"), 0),
    tmp_ios_src = arrayindex(regextract(_raw_log, "\[Source: ?(\d{1,3}(?:\.\d{1,3}){3})\]"), 0)
| alter
    xdm.event.original_event_type = tmp_ios_event,
    xdm.source.user.username = tmp_ios_user,
    xdm.source.ipv4 = tmp_ios_src
;
```

### The MNEMONIC is the identity; the FACILITY is not

In a `%FACILITY-SEVERITY-MNEMONIC` token the facility looks like the
natural discriminator and it is not stable. On Juniper Junos one event
arrives under two different facilities from the same daemon on the same
estate:

```
%USER-6-UI_LOGIN_EVENT: User 'root' login, class 'super-user' ...
%INTERACT-6-UI_LOGIN_EVENT: User 'root' login, class 'super-user' ...
```

`UI_AUTH_EVENT`, `UI_LOGOUT_EVENT` and `UI_CMDLINE_READ_LINE` behave the
same way. Keying classification on the facility therefore splits one
event type across branches, and writing the facility into
`xdm.event.operation` collapses login, logout and command execution into
one indistinguishable value.

The vendor's own model says the same thing. Juniper documents the message
TAG (`UI_LOGIN_EVENT`) as the unique identifier of a system log message,
while a facility is defined as a GROUP of messages that share a
generating process or a similar condition, and facility plus severity
together are merely the message "priority". A grouping is not an
identity, so classify on the tag
(https://www.juniper.net/documentation/us/en/software/junos/network-mgmt/topics/topic-map/system-logging.html).

So: classify on the MNEMONIC. Use the facility only as a fallback
identity for a record that carries no mnemonic at all, and never as the
operation verb. See
[record-classification.md](record-classification.md).

The facility can also be two-part, which a single-facility pattern
misses entirely:

```
%SECURITY-SSHD_SYSLOG_PRX-6-INFO_GENERAL
%LICENSE-SMART_LIC-3-COMM_FAILED
```

Capture both shapes with one pattern, taking the mnemonic as the last
component:

```
tmp_mnemonic = arrayindex(regextract(_raw_log, "%(?:[\w]+-)+?\d-(\w+)"), 0),
tmp_facility = arrayindex(regextract(_raw_log, "%([\w]+?)-"), 0)
```

Yields, for `<190>Jun 30 12:00:04 sw1 %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin] [Source: 10.0.0.5] [localport: 22] at 12:00:04 UTC`:
`xdm.event.original_event_type = "SEC_LOGIN-5-LOGIN_SUCCESS"`,
`xdm.source.user.username = "admin"`, `xdm.source.ipv4 = "10.0.0.5"`. The
`: ?` in each bracket capture tolerates the spaced and unspaced IOS
variants (`[user: x]` and `[user:x]`); the `%FACILITY-SEV-MNEMONIC`
severity digit also bands to a `XDM_CONST.LOG_LEVEL_*`. Keep
`xdm.event.type = "authentication"` for the `SEC_LOGIN` mnemonics.

## Recipe 9 -- parenthesised comma-delimited key=value (Huawei VRP-style)

When: a positional line ends with a `(Key=Value, Key=Value)` trailer
where values are delimited by commas or the closing paren, after a
`%%<ver><MODULE>/<severity>/<BRIEF>` token (the Huawei VRP AAA / SSH /
SHELL log is the canonical case). Recipe 1's `([^\s]+)` would grab the
trailing comma, so anchor the value on `[^,)]+` instead.

```
[MODEL: dataset=vendor_vrp_raw]
filter
    _raw_log != null
| alter
    tmp_vrp_event = arrayindex(regextract(_raw_log, "%%\d*\w+/\d/(\w+)"), 0),
    tmp_vrp_user = arrayindex(regextract(_raw_log, "UserName=([^,)]+)"), 0),
    tmp_vrp_ip = arrayindex(regextract(_raw_log, "IPAddress=([^,)]+)"), 0)
| alter
    xdm.event.original_event_type = tmp_vrp_event,
    xdm.source.user.username = tmp_vrp_user,
    xdm.source.ipv4 = tmp_vrp_ip
;
```

Yields, for `<190>Jun 30 12:00:04 rtr1 %%01SSH/4/SSH_FAIL(l):Failed to login through SSH. (UserName=admin, IPAddress=10.0.0.5)`:
`xdm.event.original_event_type = "SSH_FAIL"`,
`xdm.source.user.username = "admin"`, `xdm.source.ipv4 = "10.0.0.5"`. The
`[^,)]+` capture stops at the comma or the closing paren, so each value
is clean. Classify per record: a VRP `SHELL/.../CMDRECORD` line is a
command execution (process), while `SSH` / `AAA` login lines are
authentication -- see [record-classification.md](record-classification.md).

## Recipe 10 -- Combined Log Format access line (Apache / Tomcat / Nginx)

When: a web access line in Common / Combined Log Format --
`%h %l %u [%t] "%r" %>s %b "%{Referer}i" "%{User-Agent}i"` -- as emitted
by the Tomcat AccessLogValve and Apache httpd / Nginx. This is a network
(HTTP) event; map the request line and user-agent, and classify it
`network` (add `authentication` only when the app genuinely authenticates,
not merely because the URL path contains "login").

```
[MODEL: dataset=vendor_clf_raw]
filter
    _raw_log != null
| alter
    tmp_clf_ip = arrayindex(regextract(_raw_log, "^(\d{1,3}(?:\.\d{1,3}){3})"), 0),
    tmp_clf_method = arrayindex(regextract(_raw_log, "\"(\w+) \S+ HTTP/\d"), 0),
    tmp_clf_url = arrayindex(regextract(_raw_log, "\"\w+ (\S+) HTTP/\d"), 0),
    tmp_clf_ua = arrayindex(regextract(_raw_log, "\"([^\"]*)\"\s*$"), 0)
| alter
    xdm.source.ipv4 = tmp_clf_ip,
    xdm.network.http.method = tmp_clf_method,
    xdm.network.http.url = tmp_clf_url,
    xdm.source.user_agent = tmp_clf_ua
;
```

Yields, for `10.0.0.5 - alice [30/Jun/2025:12:00:04 +0000] "GET /app/login HTTP/1.1" 200 1234 "https://portal.example.com/" "Mozilla/5.0 (Windows NT 10.0)"`:
`xdm.source.ipv4 = "10.0.0.5"`, `xdm.network.http.method = "GET"`,
`xdm.network.http.url = "/app/login"`,
`xdm.source.user_agent = "Mozilla/5.0 (Windows NT 10.0)"`. The status
(`HTTP/\d\.\d" (\d{3})`) bands to `xdm.event.outcome` (2xx/3xx ->
SUCCESS, 4xx/5xx -> FAILED) and, cast to an integer, maps to
`xdm.network.http.response_code` via the COMPLETE crosswalk chain
(`python3 scripts/http_status_map.py --render` -- all 60 codes, never a
hand-listed subset; the linter flags a partial map as WARN-048); the
byte count after it maps to `xdm.target.sent_bytes`; the `%u` field (3rd
token, `-` when absent) is the authenticated user when present.

## Recipe 11 -- prepend-robust syslog (Cisco WLC exemplar)

When: any syslog source that arrives both direct off the box and behind an
intermediate relay that prepends its own `<PRI> ts host tag:` header. This
is the HARD RULE for all syslog (see syslog-envelope.md): capture the
envelope relay-aware (greedy `^.*` prefix -> origin host), and capture
every body field on its own token so it matches with or without the
prefix. A Cisco Wireless LAN Controller line shows both -- direct it is
`*task: Mon DD HH:MM:SS.mmm: %FAC-SEV-MNEMONIC: ... for mobile <mac>`; via
a relay it gains `<PRI>Mon DD HH:MM:SS relay-host wlc:` in front.

```
[MODEL: dataset=cisco_wlc_raw]
filter
    _raw_log != null
| alter
    tmp_wlc_host     = arrayindex(regextract(_raw_log, "^.*<\d{1,3}>[A-Za-z]{3}\s+\d+\s+[\d:]+\s+(\S+)\s"), 0),
    tmp_wlc_mnemonic = arrayindex(regextract(_raw_log, "%(\w+-\d-\w+):"), 0),
    tmp_wlc_mac      = arrayindex(regextract(_raw_log, "for mobile ([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})"), 0)
| alter
    xdm.observer.name = tmp_wlc_host,
    xdm.event.original_event_type = tmp_wlc_mnemonic,
    xdm.source.host.mac_addresses = arraycreate(tmp_wlc_mac)
;
```

Yields, for the relay-prepended
`<134>Jul 14 15:41:24 wlc-mgmt.example.net wlc01: *apfReceiveTask: Jul 14 15:41:24.640: %APF-6-USER_NAME_CREATED: [SS]apf_ms.c:9003 Username entry (3E-A8-8D-20-D1-1E) with length (17) created for mobile 3e:a8:8d:20:d1:1e`:
`xdm.observer.name = "wlc-mgmt.example.net"`,
`xdm.event.original_event_type = "APF-6-USER_NAME_CREATED"`,
`xdm.source.host.mac_addresses = ["3e:a8:8d:20:d1:1e"]`. The direct line
`*apfReceiveTask: Jul 14 15:41:24.640: %APF-6-USER_NAME_CREATED: ... for mobile 3e:a8:8d:20:d1:1e`
yields the identical mnemonic and MAC (host is null off the box, sourced
from a payload field when needed). The `%FAC-SEV-MNEMONIC` token and the
`for mobile <mac>` phrase are the position-independent anchors -- neither
depends on the header being present.

## Recipe 12 -- one value split across repeated tokens

When: a source expresses one logical value as a lead token plus N
repeated continuation tokens. The canonical case is a TACACS+
authorisation record, where the command is one `cmd=` followed by any
number of `cmd-arg=` tokens. This is protocol-defined, not a vendor
quirk: RFC 8907 section 8.2 states that multiple `cmd-arg` arguments may
be specified and that they are ORDER DEPENDENT, so the reconstruction
must preserve the order in which they appear
(https://www.rfc-editor.org/rfc/rfc8907.html).

```
... args service=shell cmd=show cmd-arg=running-config cmd-arg=ipv4 cmd-arg=access-list cmd-arg=SNMPv3-ACL cmd-arg=| cmd-arg=utility cmd-arg=wc cmd-arg=<cr>
```

Mapping `cmd=` alone yields `show`, which is useless for a detection --
and `arrayindex(..., 0)` silently keeps only the first continuation
token. `regextract` returns EVERY match, so rebuild the value with
`arraystring()` over the multi-match and join it to the lead token:

```
[MODEL: dataset=vendor_tacacs_raw]
filter
    _raw_log != null
| alter
    tmp_cmd = arrayindex(regextract(_raw_log, "args service=\S+ cmd=(\S+)"), 0),
    tmp_args = arraystring(regextract(_raw_log, "cmd-arg=(\S+)"), " ")
| alter
    tmp_command = trim(concat(tmp_cmd, " ", tmp_args))
| alter
    xdm.target.process.command_line = tmp_command,
    xdm.event.operation = XDM_CONST.OPERATION_TYPE_AUDIT
;
```

Yields `show running-config ipv4 access-list SNMPv3-ACL | utility wc <cr>`.
Command accounting is an audit trail of what was run, so the operation is
`OPERATION_TYPE_AUDIT` with no outcome -- see
[authentication-mapping.md](authentication-mapping.md) (AAA gateways).

The idiom generalises to any repeated-key shape -- `arg1= arg2=`,
repeated header pairs, a multi-valued attribute emitted once per value.
Whenever a token can legitimately repeat, ask whether the value is the
first match or the join of all matches; taking the first is the common
silent defect.

## Recipe 13 -- the identity is in the prose, not a structured field

When: an authentication record appears to have no actor because the
structured `key=value` fields do not carry one. Before concluding the
source cannot supply an identity, READ THE MESSAGE BODY. Two common
cases put the account in a sentence.

Case one, relayed sshd and PAM text. Many appliances embed or relay the
operating system's own authentication line verbatim, so one alternation
serves many vendors:

```
Accepted password for user_bbb25420 from 10.226.66.61 port 55145 ssh2
Failed password for user_bbb25420 from 10.252.92.167 port 60430 ssh2
Failed password for invalid user someone from 172.31.63.155 port 34037 ssh2
LOGIN ON tty1 BY user_9eca11b6
FAILED LOGIN 1 FROM tty1 FOR admin, Authentication failure
Consecutive login failures for user user_24353f58 account temporarily locked
```

```
tmp_actor_raw = arrayindex(regextract(_raw_log,
    "(?:password for(?:\sinvalid\suser)?|LOGIN ON \S+ BY|LOGIN \d+ FROM \S+ FOR|failures for user)\s+([A-Za-z0-9_.@\-]+)"), 0)
```

Without this, only the records that happen to carry a structured
account field resolve an identity, and the CLI and SSH login codes --
often the majority -- resolve none.

Case two, vendor prose that states account, address and line together:

```
Successfully authenticated user 'user_b39a79ea' from '198.51.100.142' on 'vty0'
Failed authentication attempt by user 'user_575b9419' from '172.30.18.99' on 'vty2'
User 'user_715d72db' from '172.30.18.99' logged out on 'vty20'
```

```
tmp_actor_raw = arrayindex(regextract(_raw_log,
    "(?:Successfully authenticated user|Failed authentication attempt by user|User)\s+'([^']+)'\s+from"), 0),
tmp_src_ip = arrayindex(regextract(_raw_log,
    "'[^']+'\s+from\s+'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'"), 0)
```

Reading these matters beyond field coverage. Failure records that
resolve to many distinct accounts from a handful of source addresses are
a password-spraying signature, and a rule that never reads the body
discards it entirely.

### Require the FOLLOWING delimiter when a field is optional in prose

The strongest form of guard is one that cannot produce the wrong answer
in the first place. Where a value sits BETWEEN two fixed tokens and is
sometimes absent, require the token that must follow it:

```
// the value is optional: "User alice from 10.0.0.1" or "User from 10.0.0.1"
"\sUser\s(\S+)\sfrom\s"
```

On the first shape this captures `alice`. On the second it cannot match
at all, because after consuming `from` as the group it would need a
second ` from `. The capture is structurally incapable of the wrong
answer, rather than guarded against it after the fact.

Prefer this to a negative lookahead (`(?!from\b)`). It is more portable,
since lookahead support in the tenant regex engine is not something to
assume, and it generalises to any "optional value between two fixed
tokens" shape. Where no following token is fixed, fall back to an
explicit comparison guard, as below.

### Suppress redaction and qualifier tokens, never map them

A prose capture can succeed and still return something that is not an
account. Taking the first word after `for` in
`Failed password for invalid user Masked(xxxxx) from ...` yields
`invalid`; skipping the qualifier yields `Masked`.

Neither is a principal, and the consequence is worse than a null: a
correlation keyed on the account collapses unrelated attempts from
different hosts onto one fictional user.

Guard the capture against the qualifier and redaction vocabulary, and
let the field stay null when it matches:

```
tmp_actor = if(
    tmp_actor_raw != "invalid" and tmp_actor_raw != "Masked"
    and tmp_actor_raw != "unknown" and tmp_actor_raw != "UNKNOWN",
    tmp_actor_raw)
```

A null actor is the truth. A plausible fictional one is a correlation
defect that survives review precisely because it looks like data.

Lint WARN-051 flags this shape: an unquoted capture group directly after
a qualifier word, with no guard anywhere in the rule. It is advisory,
because a source may be known never to emit a qualifier. A
quote-delimited capture (`User '(\S+)'`) and a `key=` capture are both
bounded and are not flagged.

## Recipe 14 -- the application writes its OWN header inside the syslog message

When: a platform application (commonly Java) logs through syslog, so the
line carries TWO headers -- the syslog envelope, then the application's
own delimited header before the message text. Nokia NFM-P is the
canonical case; any application logging via syslog with its own
formatter shares the shape.

```
<182>Jul 30 13:41:12 host-a NFM-P-APP: <2026.07.30 13:41:02 728 +1000><I><host-a><DeployCleanWorker [1]><server.sysact.ActivityTask.ActivityTask> User Activity for User: 4008225 RequestId: 3436 Type: Deployment Deletion ObjectId: network:198.51.100.226:router-1:ip-interface-75:BFDConfiguration ObjectType: Bfd Config State: Success
|_________ syslog envelope _________|_______ application header _______|_ message _
```

Parse it in two stages. Stage 0 handles the envelope exactly as any
other syslog source (see [syslog-envelope.md](syslog-envelope.md)); a
second stage reads the application header. Do NOT try to do both in one
pattern -- the envelope must stay prepend-robust, and mixing the two
couples an origin-host capture to an application format that can change
independently.

```
| alter
    // the application component, before the inner header
    tmp_app_comp  = arrayindex(regextract(_raw_log, "NFM-P-(\w+):"), 0),
    // each inner field on its OWN delimiter -- see the two traps below
    tmp_app_sev   = arrayindex(regextract(_raw_log, ">\s*<([IWE])><"), 0),
    tmp_app_thread = arrayindex(regextract(_raw_log, "><[IWE]><[^>]*><([^>]*)>"), 0),
    tmp_app_class = arrayindex(regextract(_raw_log, "><[IWE]><[^>]*><[^>]*><([^>]*)>"), 0)
```

### Trap one: capture on the REAL delimiter, never a hand-rolled stop set

The fields are `<>`-delimited, so `[^>]*` is the correct capture and any
guess about what the content may contain is wrong. Thread names legitimately
carry colons, parentheses and addresses:

```
<regserv-zkconnect_1914537103_10.0.0.241:2181-SendThread(10.0.0.153:2181)>
```

A capture that stops at the first `:` or `(` truncates that to nonsense.
The delimiter is stated by the format; the content is not yours to
predict.

### Trap two: `*` not `+`, because a field can be legitimately empty

Some records carry an empty class field, written `><>`:

```
<2026.07.30 16:16:37 107 +1000><I><host-a><MemoryMonitorPrintTimer><> JVM MEMORY: ...
```

`([^>]+)` requires one character and so fails to match the WHOLE header,
which does not merely null that one field -- it silently drops every
field the pattern was extracting, and the record classifies as
unrecognised. Use `([^>]*)` and let the empty value become null.

### Trap three: a delimiter is not a bound

A vendor may write whitespace INSIDE its own delimiter:

```
management IP Address [172.21.61.28 ] ERROR [java.net.ConnectException: ...]
                                    ^ the space is inside the bracket
```

```
// WRONG -- takes "172.21.61.28 " with the trailing space
tmp_mgmt_ip = arrayindex(regextract(_raw_log, "management IP Address \[([^\]]+)\]"), 0)

// RIGHT -- bound the capture on the CONTENT it must contain
tmp_mgmt_ip = arrayindex(regextract(_raw_log, "management IP Address \[\s*(\d{1,3}(?:\.\d{1,3}){3})\s*\]"), 0)
```

This is the WARN-054 class reaching a field through a delimiter that
LOOKS safe, so the linter does not flag it: an address differing by one
trailing space is populated, non-empty, not the sentinel, and never
compares equal to the same address written without it. Where the capture
feeds anything that will be matched exactly -- an address, an identifier,
a command -- bound it on the content rather than trusting the delimiter.

### A record with no application header is a CONTINUATION line

```
<182>Jul 31 06:52:16 host-b NFM-P-APP: #011at java.lang.Thread.run(Thread.java:748)
<182>Jul 26 13:58:58 host-b NFM-P-APP: DbConnection{username='null', dbInstance='nspdb', host='198.51.100.159', port=6432}
```

These are the second and later lines of something multi-line -- a stack
trace, a connection dump, a statistics table. They carry no severity, no
class and no self-contained meaning, and they must NOT be guessed at:
give them the `GOCORTEX_UNMODELLED` catch-all so the datamodel row count
still equals the raw count. (`#011` is rsyslog's escaping of a tab, not a
tab character; do not match a literal tab expecting to find one.)

The application timestamp inside the header stays NOT MAPPED. Cortex
sets `_time` at INGEST and a MODEL rule must never assign it (WARN-018),
and there is no XDM field for an application-emitted time. Its
space-separated millisecond token (`16:16:37 107`) is a real parsing
problem, but it is a PARSING-rule concern and out of scope here.

## Recipe 15 -- the Cisco %FACILITY-SEVERITY-MNEMONIC token, correctly

When: any Cisco IOS, IOS-XE or WLC source. The token is the per-event
identity and the only stable classifier the platform offers, so getting
it right decides whether the rest of the rule can classify at all.

Cisco documents the structure as:

```
%FACILITY-SUBFACILITY-SEVERITY-MNEMONIC: Message-text
```

Three things about it defeat the obvious pattern.

### SUBFACILITY is optional, and it is one OR two extra codes

On Catalyst 6500 / 7600 distributed systems the emitting component is
inserted between facility and severity. `%DIAG-SP-STDBY-6-RUN_MINIMUM`
is `%DIAG-6-RUN_MINIMUM` arriving from the switch processor in standby.

A pattern that assumes exactly three parts does not merely mis-parse
these -- it fails to match at all, so every distributed-system message
lands on the catch-all and is never classified.

### A card-prefixed message wraps a SECOND complete token

```
%CARD-SEVERITY-MSG:SLOT %FACILITY-SEVERITY-MNEMONIC: Message-text
```

The card is one of CIP, CIP2, ECPA, ECPA4, FEIP, PCPA, VIP. The wrapper
looks exactly like a real token, so a left-anchored pattern captures
`VIP-3-MSG` -- which is not an event -- and reports it as the event type.
Populated, non-empty, not the sentinel, wrong. Cisco's guide notes the
prepended portion is not shown in the message listings, so an author
working from the catalogue never learns the form exists.

### Continuation parts carry no token at all

A message longer than the syslog buffer is split, each incomplete section
ending `**MSG XXXXX TRUNCATED**` and each later part beginning
`**MSG XXXXX CONTINUATION #YY` (up to 99 parts). Older releases truncate
instead and emit `%Log packet overrun, PC [hex], format: [chars]`. A
continuation part has no facility, no severity and no self-contained
meaning.

### The pattern

```
[MODEL: dataset=cisco_ios_raw]
filter
    _raw_log != null
| alter
    // Prefer the LAST token on the line. A card wrapper PRECEDES the
    // real token, so greedy already skips it -- no exclusion needed.
    tmp_cisco_fac  = arrayindex(regextract(_raw_log, ".*%([A-Z][A-Z0-9_]*(?:-[A-Z][A-Z0-9_]*)*)-\d-[A-Z0-9_]+"), 0),
    tmp_cisco_sev  = arrayindex(regextract(_raw_log, ".*%[A-Z][A-Z0-9_]*(?:-[A-Z][A-Z0-9_]*)*-(\d)-[A-Z0-9_]+"), 0),
    tmp_cisco_mnem = arrayindex(regextract(_raw_log, ".*%[A-Z][A-Z0-9_]*(?:-[A-Z][A-Z0-9_]*)*-\d-([A-Z0-9_]+)"), 0),
    tmp_cisco_cont = arrayindex(regextract(_raw_log, "\*\*MSG \d+ (TRUNCATED|CONTINUATION)"), 0)
| alter
    xdm.event.original_event_type = coalesce(
        concat(tmp_cisco_fac, "-", tmp_cisco_mnem), "GOCORTEX_UNMODELLED"),
    xdm.event.log_level = if(
        tmp_cisco_sev <= "3", XDM_CONST.LOG_LEVEL_ERROR,
        tmp_cisco_sev = "4", XDM_CONST.LOG_LEVEL_WARNING,
        tmp_cisco_sev != null, XDM_CONST.LOG_LEVEL_INFORMATIONAL)
;
```

Verified against every arrival form:

| Input | facility | mnemonic |
| --- | --- | --- |
| `%LINK-3-UPDOWN:` | `LINK` | `UPDOWN` |
| `%DIAG-SP-6-RUN_MINIMUM:` | `DIAG-SP` | `RUN_MINIMUM` |
| `%DIAG-SP-STDBY-6-RUN_MINIMUM:` | `DIAG-SP-STDBY` | `RUN_MINIMUM` |
| `%VIP-3-MSG:SLOT5 %LINK-3-UPDOWN:` | `LINK` | `UPDOWN` |
| relay-prefixed, card-wrapped | `LINK` | `UPDOWN` |
| `%VIP-3-MSG:SLOT5` alone | null | null |
| `**MSG 00042 CONTINUATION #02` | null | null |

The subfacility stays attached to the facility deliberately: `DIAG-SP-STDBY`
names the component that emitted the record, which is information, not
noise. Splitting it into its own field is fine; discarding it is not.

A card wrapper with no inner message is the one case this does not
resolve: greedy has only the wrapper to match, so it returns `VIP-3-MSG`.
That was previously excluded with a negative lookahead, which is REMOVED
-- this engine does not support lookaround and does not say so, it simply
never returns (see below). The residual exposure is small: a wrapper with
no inner message contains no event, so what is lost is a null, not a
correct value.

A continuation part still yields null, because it has no `%` token at
all.

### This engine has NO lookahead or lookbehind

Not "discouraged" -- unsupported, and silently so. A pattern containing
`(?=`, `(?!`, `(?<=` or `(?<!` does not raise: the query HANGS. Measured
back to back on one dataset, same limit: the control returned in about
ten seconds, the lookahead version was still running twelve minutes later
with no result and no error.

That failure mode is worse than a rejection, because a caller sees a
timeout and reads it as a crash in whatever ran the query rather than as
a rejected pattern -- and the stall appears to belong to whatever ran
BEFORE it. Lint ERR-033 blocks it.

Express the constraint positionally instead: capture what IS there and
guard it in a later `alter` stage, or require the delimiter that must
follow the value.

Cisco's severity is 0-7 with LOWER meaning more serious, and level 5 is
`notification` in Cisco's wording rather than the `notice` of RFC 3164.

### Do not match the documentation's placeholders

The guides write variable fields as `[chars]`, `[dec]`, `[int]`, `[hex]`,
`[hec]`, `[enet]` (a MAC), `[node]`, `[address]`, and in places fall back
to printf tokens (`%s`, `%d`, `%u`, `%i`). None of these appear in an
emitted message. Worse, the placeholder syntax collides with the
message's own literal brackets: `SEC_LOGIN-5-LOGIN_SUCCESS` is documented
as `Login Success [user: [chars]] [Source: [chars]] [localport: [node] at
[chars]`, where `[localport: [node]` looks unbalanced only because the
placeholder swallowed the closing bracket. The emitted text is
`[localport: 22]`. Infer bracket structure from a real record, never from
a template.

## Choosing the target

A recipe extracts a value cleanly; the field-anchor index
(`scripts/lookup_anchor.py`) tells you which `xdm.*` path it belongs to.
Use them together: recipe for the extraction, anchor lookup for the
location. When a value has no confident XDM home, document it in the
NOT MAPPED block rather than forcing it.
