<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Network-event mandatory mapping

Network / traffic events feed the XDM network story and network
analytics. The story only forms when a fixed set of XDM fields is
mapped. A mandatory field left unmapped drops the event from the story,
so this reference is the authoritative checklist for any rule that
models a firewall, flow, proxy, IDS/IPS, DNS, or other
traffic-between-endpoints event.

Classification is PER RECORD. A firewall or gateway feed mixes flows
with VPN logins, admin commands and status chatter, so decide the
network tag and the mandatory set on each record from its own
discriminators, not as one constant across the feed. Records that are
not network events take their own treatment, and unrecognised records
take the catch-all rather than a forced network tag. See
[record-classification.md](record-classification.md).

This guidance is host-agnostic and format-agnostic. Extraction differs
per source format (syslog RFC 3164 / RFC 5424, JSON, JSONL, CEF, LEEF,
key=value), but the XDM target fields and their requirement level are
identical in every case. Map them in the MODEL rule after extraction.
On a syslog source, parse the Stage 0 envelope first
([syslog-envelope.md](syslog-envelope.md)); its targets (observer.name,
log_level, severity) do not overlap the network set, so the two layers
compose cleanly.

## Network is the foundational layer

Network is an underlying, foundational log type: most security profiles
sit ON TOP of a network flow rather than beside one. An IDS or IPS
alert, a WAF block, a proxy decision, a DNS-security verdict -- each of
these describes a network connection first and a security judgement
second, so the rule maps the network mandatory set below IN ADDITION to
its primary alert / threat mapping, not instead of it. The same logic
runs upward: an authentication event that carries the full transport
flow (both endpoint addresses, a port, and a protocol -- a VPN login,
an SSH session, a captive-portal sign-in) is ALSO a network connection,
and takes both mandatory sets with the union of the story tags (see the
dual-events section below).

## When this applies (auto-detection, conservative)

Network transport fields (an IP, a port) appear in almost every log, so
a bare source IP is never enough. Treat a sample as a network event only
on a distinctive signal:

- Field names or values carrying traffic vocabulary: `flow`, `firewall`,
  `traffic`, `connection` / `conn`, `session` combined with transport
  fields, `bytes_sent` / `bytes_received`, `packets`.
- Action values from the allow / deny family: `allow`, `allowed`,
  `permit`, `deny`, `denied`, `drop`, `dropped`, `block`, `blocked`,
  `reset`.
- Protocol-name values: `tcp`, `udp`, `icmp`.
- A complete transport 5-tuple: both endpoint addresses, a port, and a
  protocol all present in the same record.

The converse matters as much: a record from a networking device is not a
network event just because a networking device emitted it. An interface
transition has no peer and is a device status change, not a flow.
Confirm the record can supply the story's defining entity -- a peer
address -- before tagging it NETWORK, and audit it after deploying with
the ratio test:

```
datamodel dataset = <vendor>_<product>_raw
| filter array_any(xdm.event.tags, "@element" = XDM_CONST.EVENT_TAG_NETWORK)
| comp count() as claimed,
       sum(if(xdm.source.ipv4 != null, 1, 0)) as with_peer
```

A large gap between the records claiming the story and the records
carrying a peer means the classification is too broad. Interface
transitions never carry one; SSH transport records do only when the line
names a client. Keeping only the records with a peer leaves a smaller
network story in which every record can supply the address the story is
queried on. See
[record-classification.md](record-classification.md) "Claim a story only
where its mandatory set can be populated".

One precision rule: the allow / deny action family is not proof on its
own when the sample is ALSO an authentication event. An AAA gateway
(TACACS+, RADIUS, Cisco ISE) logs PERMIT / DENY as the authentication
outcome, with no transport flow behind it -- so when permit / deny
vocabulary is the only network evidence (no traffic field names, no
transport 5-tuple, no protocol token), the event stays
authentication-only. Any real flow evidence lifts this -- a protocol
token, traffic vocabulary in the field names, or both connection
endpoints quoted as `IP:port` pairs in one record.

`scripts/profile_log.py` reports this signal in a `network` block of the
worksheet so the detection is deterministic. It is independent of the
`authentication` block -- a VPN login carries both signals and gets both
blocks.

When detected, `scripts/scaffold_rule.py` pre-populates the mandatory
set: it pads every field that has an official placeholder, sets
`xdm.event.type` to a network value, and lists the fields that must come
from the raw log as TODOs rather than inventing values.

Enforcement is advisory. `scripts/lint_rule.py` raises WARN-043 (warning
severity, never an error) for each mandatory field that a network rule
leaves unmapped. The linter treats a rule as a network rule only when it
carries a definitive marker: `XDM_CONST.EVENT_TAG_NETWORK` in the
`xdm.event.tags` assignment, or an `xdm.event.type` value containing
`network`. The exit code stays 0; the author decides.

## Mandatory fields (all 17 must be mapped)

Where the log simply does not carry a value, pad with the type-valid
placeholder so the mandatory status is met. The three
`xdm.network.http.*` leaves are NOT in this set -- they are mandatory
only for a network event that carries an HTTP layer, covered in the
section below.

| XDM target | Type | Mapping / placeholder |
| --- | --- | --- |
| `xdm.event.outcome` | enum | Map the vendor action: allow / permit -> `XDM_CONST.OUTCOME_SUCCESS`, deny / drop / block -> `XDM_CONST.OUTCOME_FAILED`. Pad `XDM_CONST.OUTCOME_UNKNOWN`. |
| `xdm.event.type` | string | Resolve to a value that contains `network`; pad the literal `"network"`. |
| `xdm.event.tags` | array | Must include `XDM_CONST.EVENT_TAG_NETWORK` on the network records. Assign per record via one `if()` so non-network records in the same feed get their own tags (or blank). On a dual authentication + network event emit ONE merged `arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION, XDM_CONST.EVENT_TAG_NETWORK)` -- add `EVENT_TAG_VPN` for a VPN tunnel -- never two tags assignments. See [record-classification.md](record-classification.md). |
| `xdm.network.ip_protocol` | enum | Map the protocol via `XDM_CONST.IP_PROTOCOL_*`; pad `XDM_CONST.IP_PROTOCOL_IP` (the neutral network-layer default when the log carries no protocol). |
| `xdm.network.protocol_layers` | array | `arraycreate(...)` over the known layers, highest last (content-pack idiom, e.g. the application protocol). Pure pad `arraycreate("IP")`, consistent with the `IP_PROTOCOL_IP` protocol pad. |
| `xdm.source.host.device_id` | string | Map the stable client device id; otherwise `""`. |
| `xdm.source.ipv4` | string | Map the observed client address; pad `""` only when the source is IPv6-only. |
| `xdm.source.ipv6` | string | Map the observed client address; pad `""` when the source is IPv4-only. |
| `xdm.source.is_internal_ip` | boolean | Derive from the mapped IP via `incidr()` over RFC 1918 (see the worked shape); pure pad `false`. |
| `xdm.source.port` | integer | Map the value; otherwise `to_integer(0)`. |
| `xdm.source.sent_bytes` | integer | Bytes sent by the source; otherwise `to_integer(0)`. |
| `xdm.target.host.device_id` | string | Map when known; otherwise `""`. |
| `xdm.target.ipv4` | string | Map the observed address; pad `""`. |
| `xdm.target.ipv6` | string | Map the observed address; pad `""`. |
| `xdm.target.is_internal_ip` | boolean | Derive via `incidr()` as for the source; pure pad `false`. |
| `xdm.target.port` | integer | Map the value; otherwise `to_integer(0)`. |
| `xdm.target.sent_bytes` | integer | Bytes sent by the target (bytes received by the source); otherwise `to_integer(0)`. |

Placeholder policy for the mandatory set:

- Numbers (ports, byte counts) -> `to_integer(0)`.
- Strings (device ids) -> the empty string `""`.
- The IPv4 / IPv6 pair -> map the observed family, pad the other with `""`.
- Booleans -> prefer the `incidr()` derivation; the pure placeholder is
  `false`.
- Enum constants -> a real member of the closed list (`OUTCOME_UNKNOWN`,
  `IP_PROTOCOL_IP`, `URL_CATEGORY_UNKNOWN`) -- never a quoted string.
- Arrays -> `arraycreate(...)` with at least one valid element.
- The event time (generated time) is mapped automatically; do not set it
  manually.

## The HTTP set: mandatory only where there IS an HTTP layer

These three fields complete the network story for an HTTP-bearing event
-- a proxy, web gateway, WAF, CASB or DNS-over-HTTPS record. They are
NOT required of a network event with no HTTP layer.

| XDM target | Type | Mapping / placeholder |
| --- | --- | --- |
| `xdm.network.http.http_header.header` | string | The HTTP header name. Map when the source logs headers; otherwise `""`. (The bare `xdm.network.http.http_header` is a container node, not a mappable field -- some data models reject it -- and `xdm.network.http.response_headers` does not exist; map these two leaves.) |
| `xdm.network.http.http_header.value` | string | The HTTP header value. Map when the source logs headers; otherwise `""`. |
| `xdm.network.http.url_category` | enum | Map the vendor category via an `XDM_CONST.URL_CATEGORY_*` if-chain; pad `XDM_CONST.URL_CATEGORY_UNKNOWN`. Closed list in [xdm-const.md](xdm-const.md). |

The rule is all-or-nothing, and it is self-declared: claim an HTTP layer
and the set must be complete; claim none and the leaves are not
required. A rule claims an HTTP layer when it maps any other
`xdm.network.http.*` field, maps a URL, or names HTTP among its protocol
layers. Lint WARN-043 applies the same test.

Do NOT pad these onto a router SSH login, an SNMP failure or a
control-plane record. Padding a header name, a header value and a URL
category onto a record with no HTTP anywhere asserts a protocol the
source never saw. That is the semantically-empty pad the placeholder
policy exists to prevent, not an instance of it: a placeholder stands in
for a value the event HAS but the log did not carry, and a router SSH
login does not have a URL category at all.

A requirement that no honest router rule can satisfy is worse than no
requirement, because a permanently unsatisfiable advisory trains authors
to mute the checker that raises it -- and a muted checker protects
nothing, including in the cases where it was right.

## Deriving the enum fields

Always DERIVE the specific member before falling back to a placeholder.

`xdm.event.outcome` (see the mandatory table): allow / accept / permit
-> `OUTCOME_SUCCESS`; deny / drop / block / reject -> `OUTCOME_FAILED`;
no conclusive action -> `OUTCOME_UNKNOWN`.

`xdm.network.ip_protocol` -- match the vendor protocol token, then fall
back to `IP_PROTOCOL_IP`:

| Protocol value | Member |
| --- | --- |
| tcp, 6 | `XDM_CONST.IP_PROTOCOL_TCP` |
| udp, 17 | `XDM_CONST.IP_PROTOCOL_UDP` |
| icmp, 1 | `XDM_CONST.IP_PROTOCOL_ICMP` |
| (other named protocols) | the matching `XDM_CONST.IP_PROTOCOL_*` |
| absent / unrecognised | `XDM_CONST.IP_PROTOCOL_IP` (neutral default) |

`xdm.network.http.url_category` -- there is no portable value
dictionary: the category vocabulary differs per vendor (PAN-DB,
Zscaler, FortiGuard, Cisco Umbrella each name categories differently).
Map the vendor's category to the closest `XDM_CONST.URL_CATEGORY_*`
member with an `if()` chain keyed on the vendor value (the closed list
is in [xdm-const.md](xdm-const.md)); when the log carries no category,
or the vendor value has no clear XDM equivalent, use
`XDM_CONST.URL_CATEGORY_UNKNOWN`. Do not invent a category.

## Worked shape (JSON source)

A complete MODEL rule that maps all 17 mandatory fields. This is a
firewall flow with no HTTP layer, so it does not claim one and the three
`xdm.network.http.*` leaves are correctly absent -- padding them here
would assert a protocol the source never saw. The extraction stage
changes per format; the assignment stage does not. (On a syslog
source, insert the Stage 0 envelope between the null guard and the
extraction -- see [syslog-envelope.md](syslog-envelope.md).)

```
[MODEL: dataset=vendor_fw_raw]
filter
    _raw_log != null
| alter
    tmp_action = json_extract_scalar(_raw_log, "$.action"),
    tmp_proto = json_extract_scalar(_raw_log, "$.protocol"),
    tmp_src_ip = json_extract_scalar(_raw_log, "$.src_ip"),
    tmp_src_port = json_extract_scalar(_raw_log, "$.src_port"),
    tmp_dst_ip = json_extract_scalar(_raw_log, "$.dst_ip"),
    tmp_dst_port = json_extract_scalar(_raw_log, "$.dst_port"),
    tmp_bytes_out = json_extract_scalar(_raw_log, "$.bytes_sent"),
    tmp_bytes_in = json_extract_scalar(_raw_log, "$.bytes_received")
| alter
    xdm.event.type = "network",
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_NETWORK),
    xdm.event.outcome = if(
        tmp_action = "allow", XDM_CONST.OUTCOME_SUCCESS,
        tmp_action != null, XDM_CONST.OUTCOME_FAILED,
        XDM_CONST.OUTCOME_UNKNOWN),
    xdm.network.ip_protocol = if(
        tmp_proto = "tcp", XDM_CONST.IP_PROTOCOL_TCP,
        tmp_proto = "udp", XDM_CONST.IP_PROTOCOL_UDP,
        tmp_proto = "icmp", XDM_CONST.IP_PROTOCOL_ICMP,
        XDM_CONST.IP_PROTOCOL_IP),
    xdm.network.protocol_layers = if(
        tmp_proto != null, arraycreate(uppercase(tmp_proto)),
        arraycreate("TCP")),
    xdm.source.ipv4 = tmp_src_ip,
    xdm.source.ipv6 = "",
    xdm.source.is_internal_ip = if(
        incidr(tmp_src_ip, "10.0.0.0/8"), true,
        incidr(tmp_src_ip, "172.16.0.0/12"), true,
        incidr(tmp_src_ip, "192.168.0.0/16"), true,
        false),
    xdm.source.port = to_integer(to_number(tmp_src_port)),
    xdm.source.sent_bytes = to_integer(to_number(tmp_bytes_out)),
    xdm.source.host.device_id = "",
    xdm.target.ipv4 = tmp_dst_ip,
    xdm.target.ipv6 = "",
    xdm.target.is_internal_ip = if(
        incidr(tmp_dst_ip, "10.0.0.0/8"), true,
        incidr(tmp_dst_ip, "172.16.0.0/12"), true,
        incidr(tmp_dst_ip, "192.168.0.0/16"), true,
        false),
    xdm.target.port = to_integer(to_number(tmp_dst_port)),
    xdm.target.sent_bytes = to_integer(to_number(tmp_bytes_in)),
    xdm.target.host.device_id = ""
;
```

## Dual events -- authentication AND network

`xdm.event.tags` is an array, so one event can belong to both stories.
A VPN login is the canonical case: it is a credential validation (the
authentication story) carried over a network session (the network
story), so it also earns `XDM_CONST.EVENT_TAG_VPN`.

Rules for a dual event:

- Emit ONE merged tags assignment:
  `xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION, XDM_CONST.EVENT_TAG_NETWORK)`
  (add `XDM_CONST.EVENT_TAG_VPN` for a VPN tunnel). Two
  `xdm.event.tags` assignments is a defect (the second overwrites the
  first). When the feed also carries records that are neither story,
  make this the branch of a per-record `if()` and let the others fall
  through to their own tags or the blank catch-all
  ([record-classification.md](record-classification.md)).
- Map BOTH mandatory sets. The transport fields (`xdm.source.ipv4`,
  `xdm.target.ipv4`, the ports, `xdm.network.ip_protocol`) appear in
  both sets, so one mapping satisfies both.
- `xdm.event.type` is a single string; use the authentication value
  (the tags array already carries the network marker, and the linter's
  network detection keys on the tag).
- WARN-042 (authentication) and WARN-043 (network) fire independently:
  a dual rule missing fields from both sets receives both advisories.

## Optional fields (map when the source provides them)

| XDM target | Notes |
| --- | --- |
| `xdm.network.dns.dns_question.name` | Queried domain for DNS traffic. |
| `xdm.network.http.url` | Full requested URL. |
| `xdm.network.tls` | TLS summary. The detailed leaves `xdm.network.tls.protocol_version` and `xdm.network.tls.cipher` are also available. |
| `xdm.source.user.username` | Source-side display name. |
| `xdm.target.file.extension` | File transfer: extension. |
| `xdm.target.file.filename` | File transfer: name. |
| `xdm.target.file.md5` | File transfer: MD5. |
| `xdm.target.file.sha256` | File transfer: SHA256. |
| `xdm.target.host.fqdn` | Target host FQDN. |
| `xdm.target.host.hostname` | Target host name. |
| `xdm.target.user.username` | Target-side display name. |

Constants used above live in [xdm-const.md](xdm-const.md); every target
path is defined in [xdm-schema.md](xdm-schema.md).

## Cisco IOS-XE: which messages actually carry a flow

Access-list logging is the traffic source, and the mnemonic SUFFIX
declares which fields are present. One pattern cannot serve all six:

| Mnemonic | Shape | Has ports | Has destination |
| --- | --- | --- | --- |
| `SEC-6-IPACCESSLOGP` | `list N ACTION PROTO SRC(SPORT) -> DST(DPORT), C packet(s)` | yes | yes |
| `SEC-6-IPACCESSLOGDP` | `list N ACTION PROTO SRC -> DST (TYPE/CODE), C packet(s)` | no (ICMP type/code) | yes |
| `SEC-6-IPACCESSLOGNP` | `list N ACTION PROTONUM SRC -> DST, C packet(s)` | no | yes |
| `SEC-6-IPACCESSLOGRP` | `list N ACTION PROTO SRC -> DST, C packet(s)` | no | yes |
| `SEC-6-IPACCESSLOGS` | `list N ACTION SRC, C packet(s)` | no | NO |
| `SEC-6-IPACCESSLOGRL` | `access-list logging rate-limited or missed C packet(s)` | no | NO |

`IPACCESSLOGS` has a source and nothing else. A rule that assumes the
full tuple pads a destination that the record never carried -- the
semantically-empty pad the placeholder policy exists to prevent.

`IPACCESSLOGRL` is NOT a traffic record. It reports that ACL logging
itself dropped records: a visibility gap, not a flow. Mapping it as a
flow invents a connection. Route it to a diagnostic branch or the
catch-all, and treat a rising count as a monitoring alarm, because every
packet it counts is a flow the estate never saw.

The IOS-XE data plane emits the same six events under
`FMANFP-6-IPACCESSLOG*` (the forwarding manager). Both prefixes can
appear in one estate depending on platform and whether the ACL is
punted to the route processor, so a rule that handles only `SEC-6-*`
silently loses the hardware-switched majority.

### Zone-based firewall sessions carry the byte pair

```
FW-6-SESS_AUDIT_TRAIL_START  Start PROTO session: initiator IP:PORT -- responder IP:PORT
FW-6-SESS_AUDIT_TRAIL        Stop PROTO session: initiator IP:PORT sent N bytes -- responder IP:PORT sent N bytes
FW-6-LOG_SUMMARY             C packet(s) ACTION from POLICY SRC:PORT => DST:PORT target:class-C:C
```

`initiator` and `responder` are the vendor's words for source and target.
The Stop record is the only one carrying `sent_bytes` in both directions,
so it is the only one that can populate the network story's byte pair
honestly. On the Start record leave both byte counts unmapped rather than
padding zero, which would assert a session that transferred nothing.

### Firewall messages that are findings, not flows

```
FW-5-IMAP_NON_SECURE_LOGIN          LOGON IMAP command from initiator IP:PORT: TEXT
FW-5-POP3_NON_SECURE_LOGIN          LOGON POP3 command from initiator IP:PORT: TEXT
FW-3-FTP_SESSION_NOT_AUTHENTICATED  Command issued before the session is authenticated -- FTP client IP, FTP server IP
FW-4-TCP_MAJORDOMO_EXEC_BUG         Majordomo Execute Attack - from IP to IP
```

The two NON_SECURE_LOGIN records are cleartext-credential exposure
observed on the wire. They are network events that also carry an
authentication meaning, but the account is in the captured command TEXT
and is attacker-visible by definition -- map the flow, and treat the
credential as an alert rather than an identity.


## FortiGate: the native key=value dialect

FortiOS emits two unrelated dialects and the field names do not overlap.
CEF carries `FTNTFGT`-prefixed extension keys (`ftntfgtlogid`,
`ftntfgtappcat`); the native syslog and key=value formats carry short
unprefixed names (`logid`, `appcat`). A rule written against one dialect
maps nothing when the collector is configured for the other, so confirm
which one the tenant actually receives before mapping.

The native line is `key=value` with quoted strings, usually behind a
bare priority token and no RFC 3164 header:

```
<189>date=2026-08-28 time=14:16:41 devname="FW01" devid="FG5H0E9845800432" vd="root" logid="0000000013" type="traffic" subtype="forward" srcip=10.1.1.5 srcport=55434 srcintf="port1" dstip=10.2.2.9 dstport=443 dstintf="port2" proto=6 action="close" policyid=13 service="HTTPS" sentbyte=92 rcvdbyte=132 sentpkt=2 rcvdpkt=3 appcat="unscanned"
```

A relay in front of the firewall prepends its own RFC 3164 header, so the
same event arrives as a syslog envelope wrapping a key=value body. Anchor
every body field on its own token, never on `^` and never on a fixed
offset from the header -- see [syslog-envelope.md](syslog-envelope.md).

### `type` and `subtype` are the record discriminator

A FortiGate dataset is NOT uniformly network. `type` names the family and
`subtype` the specific record, and only two families carry a flow:

| `type` | Typical `subtype` | Story |
| --- | --- | --- |
| `traffic` | `forward`, `local`, `multicast`, `sniffer` | network -- the flow record, carries the byte pair |
| `utm` | `webfilter`, `ips`, `virus`, `app-ctrl`, `dns`, `ssl` | network, plus an alert; `webfilter` is the only one with an HTTP layer |
| `event` | `system`, `vpn`, `user`, `admin` | usually authentication or management, NOT a flow |
| `anomaly` | `anomaly` | an alert about traffic, not a flow record |

Branch on `type` per record with the CLASSIFY-ONCE idiom in
[record-classification.md](record-classification.md). Modelling the whole
dataset as network invents a flow on every admin login.

### The action vocabulary is wider than allow / deny

The outcome rule in the mandatory table above covers allow / deny / drop
/ block. FortiGate traffic records frequently carry none of those -- a
normal completed session closes, and a refused one is reported as a TCP
reset. Neither word appears in the generic vocabulary, so a rule that
only tests for allow / deny sends the common cases to
`OUTCOME_UNKNOWN`:

| `action` | Meaning | `xdm.event.outcome` |
| --- | --- | --- |
| `accept` | the policy permitted the session | `OUTCOME_SUCCESS` |
| `close` | the session completed and closed normally | `OUTCOME_SUCCESS` |
| `timeout` | the session expired without a clean close | `OUTCOME_SUCCESS` -- it was permitted; expiry is not a policy denial |
| `server-rst` / `client-rst` | one end sent a TCP reset | `OUTCOME_SUCCESS` -- the policy permitted it; the peer refused it |
| `deny` | the policy blocked the session | `OUTCOME_FAILED` |
| `start` | session opened, no verdict yet | `OUTCOME_UNKNOWN` |
| `ip-conn` | a failed IP-level connection attempt | `OUTCOME_FAILED` |
| `dns` | a DNS session record | derive from the record, not the verb |

The distinction that matters: `xdm.event.outcome` on a flow describes
whether the FIREWALL permitted it, not whether the application
succeeded. A `server-rst` is a policy success and an application
failure, and mapping it to `OUTCOME_FAILED` makes every ordinary refused
connection look like a blocked one on the dashboard.

### Field inventory (native key=value)

| Native key | XDM target |
| --- | --- |
| `srcip` / `srcport` | `xdm.source.ipv4` / `xdm.source.port`; the IP also drives `xdm.source.is_internal_ip` via `incidr()` |
| `dstip` / `dstport` | `xdm.target.ipv4` / `xdm.target.port`; drives `xdm.target.is_internal_ip` |
| `proto` | `xdm.network.ip_protocol` -- an IANA NUMBER, not a name; `6` is TCP |
| `sentbyte` / `rcvdbyte` | `xdm.source.sent_bytes` / `xdm.target.sent_bytes` (bytes received by the client are bytes sent by the target) |
| `sentpkt` / `rcvdpkt` | `xdm.source.sent_packets` / `xdm.target.sent_packets` |
| `devname` / `devid` | `xdm.observer.name` / `xdm.observer.unique_identifier` -- see below |
| `srcintf` / `dstintf` | `xdm.source.interface` / `xdm.target.interface` |
| `srcintfrole` / `dstintfrole` | `xdm.source.zone` / `xdm.target.zone` |
| `srccountry` / `dstcountry` | `xdm.source.location.country` / `xdm.target.location.country` |
| `policyid` / `poluuid` | `xdm.network.rule` |
| `appcat` | `xdm.network.application_protocol_category` |
| `catdesc` | `xdm.network.http.url_category` (webfilter records only) |
| `logid` | `xdm.event.id` |
| `utmaction` | `xdm.observer.action` |
| `trandisp` / `tranip` / `tranport` | `xdm.intermediate.is_nat` / `xdm.intermediate.ipv4` / `xdm.intermediate.port`; `trandisp="noop"` means NO translation occurred |

Fields with no XDM home: `date`, `time`, `timestamp` and `eventtime` are
the event time and belong in the dataset's own `_time`, not an `xdm.*`
path. `tz` is the device's timezone offset, not a location. `vd` is the
virtual domain -- a FortiGate tenancy construct with no XDM equivalent;
carry it in the dataset name rather than forcing it into a user or
identity domain field, which it is not.

### `devid` is the firewall, not the client

`devid` is the appliance's own serial and `devname` its own hostname.
Both describe the OBSERVER, so they belong under `xdm.observer.*`.
Putting `devid` in `xdm.source.host.device_id` conflates the firewall
with one end of the flow it is reporting, and every flow through that
appliance then claims the same source device.

`xdm.source.host.device_id` is nonetheless in the mandatory set, and a
FortiGate traffic record carries no client device id at all. The honest
answer is the documented `""` placeholder -- not the appliance serial
borrowed to fill a required slot.
