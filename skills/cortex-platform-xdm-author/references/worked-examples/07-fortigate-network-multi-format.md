<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Walkthrough 7 -- FortiGate network traffic, one event in two formats, plus a dual story

Vendor / product: Fortinet / FortiGate. Datasets: `fortinet_fortigate_json_raw` (REST log export, native JSON) and `fortinet_fortigate_syslog_raw` (the same events over RFC 3164 syslog).

What this walkthrough shows: the network story is created only when the full mandatory field set from [network-mapping.md](../network-mapping.md) is mapped -- padded with type-valid placeholders where the log has no value -- and that mapping is identical no matter which wire format the event arrives in. The syslog branch composes with the Stage 0 envelope from [syslog-envelope.md](../syslog-envelope.md). A third branch models an SSL-VPN login, which is authentication, VPN and network at once: `xdm.event.tags` carries the union of the three markers in one `arraycreate(...)`, and both mandatory sets are mapped. Each of these rules targets a single-purpose dataset and filters only `_raw_log != null`, so no record is dropped (the datamodel row count equals the raw count); a MIXED feed instead classifies per record and catches the rest with a sentinel -- see [record-classification.md](../record-classification.md). `scripts/profile_log.py` flags each sample deterministically; `scripts/lint_rule.py` raises advisory WARN-043 (and WARN-042 on the dual branch) for anything left unmapped -- warnings only, the exit code stays 0.

## The single canonical event

One allowed outbound web session: client `10.20.30.40:51544` reaches `203.0.113.9:443` over TCP, sends 1220 bytes, receives 8480. Both traffic formats below describe exactly this session, so both rules must produce the same XDM output.

## Format 1 -- native JSON (`fortinet_fortigate_json_raw`)

```json
{
  "eventtime": "1782648001",
  "devid": "FGT60E1234567890",
  "action": "accept",
  "proto": "tcp",
  "srcip": "10.20.30.40",
  "srcport": 51544,
  "dstip": "203.0.113.9",
  "dstport": 443,
  "sentbyte": 1220,
  "rcvdbyte": 8480,
  "catdesc": "Business and Economy",
  "policyname": "outbound-web"
}
```

### Field inventory (JSON)

| JSON path | Type | XDM target |
| --- | --- | --- |
| `$.action` | enum string | `xdm.event.outcome` (accept -> SUCCESS, deny -> FAILED) |
| `$.proto` | string | `xdm.network.ip_protocol`, drives `xdm.network.protocol_layers` |
| `$.srcip` / `$.srcport` | string / int | `xdm.source.ipv4` / `xdm.source.port`; the IP also drives `xdm.source.is_internal_ip` via `incidr()` |
| `$.dstip` / `$.dstport` | string / int | `xdm.target.ipv4` / `xdm.target.port`; drives `xdm.target.is_internal_ip` |
| `$.sentbyte` / `$.rcvdbyte` | int | `xdm.source.sent_bytes` / `xdm.target.sent_bytes` (bytes received by the client are bytes sent by the target) |
| `$.devid` | string | `xdm.observer.unique_identifier` -- the appliance's OWN serial describes the observer, not either end of the flow. `xdm.source.host.device_id` is mandatory and takes `""`: the record carries no client device id. |
| `$.catdesc` | string | `xdm.network.http.url_category` via the URL_CATEGORY if-chain |

Gaps: FortiGate traffic logs carry no IPv6 pair, no HTTP header, and no target device id. Those mandatory fields take their documented placeholders (`""`) rather than being dropped.

### The full rule (JSON)

```
[MODEL: dataset = fortinet_fortigate_json_raw]
filter
    _raw_log != null
| alter
    tmp_action = json_extract_scalar(_raw_log, "$.action"),
    tmp_proto = json_extract_scalar(_raw_log, "$.proto"),
    tmp_src_ip = json_extract_scalar(_raw_log, "$.srcip"),
    tmp_src_port = json_extract_scalar(_raw_log, "$.srcport"),
    tmp_dst_ip = json_extract_scalar(_raw_log, "$.dstip"),
    tmp_dst_port = json_extract_scalar(_raw_log, "$.dstport"),
    tmp_sent = json_extract_scalar(_raw_log, "$.sentbyte"),
    tmp_rcvd = json_extract_scalar(_raw_log, "$.rcvdbyte"),
    tmp_devid = json_extract_scalar(_raw_log, "$.devid"),
    tmp_catdesc = json_extract_scalar(_raw_log, "$.catdesc")
| alter
    xdm.observer.vendor = "Fortinet",
    xdm.observer.product = "FortiGate",
    xdm.event.type = "network",
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_NETWORK),
    xdm.event.outcome = if(
        tmp_action = "accept", XDM_CONST.OUTCOME_SUCCESS,
        tmp_action = "close", XDM_CONST.OUTCOME_SUCCESS,
        tmp_action = "timeout", XDM_CONST.OUTCOME_SUCCESS,
        tmp_action = "server-rst", XDM_CONST.OUTCOME_SUCCESS,
        tmp_action = "client-rst", XDM_CONST.OUTCOME_SUCCESS,
        tmp_action = "deny", XDM_CONST.OUTCOME_FAILED,
        tmp_action = "ip-conn", XDM_CONST.OUTCOME_FAILED,
        XDM_CONST.OUTCOME_UNKNOWN),
    xdm.network.ip_protocol = if(
        tmp_proto = "tcp", XDM_CONST.IP_PROTOCOL_TCP,
        tmp_proto = "udp", XDM_CONST.IP_PROTOCOL_UDP,
        tmp_proto = "icmp", XDM_CONST.IP_PROTOCOL_ICMP,
        XDM_CONST.IP_PROTOCOL_IP),
    xdm.network.protocol_layers = if(
        tmp_proto != null, arraycreate(uppercase(tmp_proto)),
        arraycreate("TCP")),
    xdm.network.http.http_header.header = "",
    xdm.network.http.http_header.value = "",
    xdm.network.http.url_category = if(
        tmp_catdesc = "Business and Economy", XDM_CONST.URL_CATEGORY_BUSINESS_AND_ECONOMY,
        tmp_catdesc = "Search Engines", XDM_CONST.URL_CATEGORY_SEARCH_ENGINES,
        XDM_CONST.URL_CATEGORY_UNKNOWN),
    xdm.source.ipv4 = tmp_src_ip,
    xdm.source.ipv6 = "",
    xdm.source.is_internal_ip = if(
        incidr(tmp_src_ip, "10.0.0.0/8"), true,
        incidr(tmp_src_ip, "172.16.0.0/12"), true,
        incidr(tmp_src_ip, "192.168.0.0/16"), true,
        false),
    xdm.source.port = to_integer(to_number(tmp_src_port)),
    xdm.source.sent_bytes = to_integer(to_number(tmp_sent)),
    xdm.observer.unique_identifier = tmp_devid,
    xdm.source.host.device_id = "",
    xdm.target.ipv4 = tmp_dst_ip,
    xdm.target.ipv6 = "",
    xdm.target.is_internal_ip = if(
        incidr(tmp_dst_ip, "10.0.0.0/8"), true,
        incidr(tmp_dst_ip, "172.16.0.0/12"), true,
        incidr(tmp_dst_ip, "192.168.0.0/16"), true,
        false),
    xdm.target.port = to_integer(to_number(tmp_dst_port)),
    xdm.target.sent_bytes = to_integer(to_number(tmp_rcvd)),
    xdm.target.host.device_id = ""
;
```

## Format 2 -- RFC 3164 syslog (`fortinet_fortigate_syslog_raw`)

The same session as a syslog line. Stage 0 parses the envelope first
(PRI-anchored host capture + priority decode, from
[syslog-envelope.md](../syslog-envelope.md)); the key=value payload is
then extracted with Pattern C regextracts. The XDM assignment stage is
the same 17-field block as the JSON rule.

```
<134>Jun 30 12:00:01 fw01 fortigate: action="server-rst" proto=6 srcip=10.20.30.40 srcport=51544 dstip=203.0.113.9 dstport=443 sentbyte=1220 rcvdbyte=8480 devid="FGT60E1234567890"
```

### The full rule (syslog)

```
[MODEL: dataset = fortinet_fortigate_syslog_raw]
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
    tmp_action = arrayindex(regextract(_raw_log, "action=\"?([\w-]+)"), 0),
    tmp_proto = arrayindex(regextract(_raw_log, "proto=\"?(\w+)"), 0),
    tmp_src_ip = arrayindex(regextract(_raw_log, "srcip=([\d.]+)"), 0),
    tmp_src_port = arrayindex(regextract(_raw_log, "srcport=(\d+)"), 0),
    tmp_dst_ip = arrayindex(regextract(_raw_log, "dstip=([\d.]+)"), 0),
    tmp_dst_port = arrayindex(regextract(_raw_log, "dstport=(\d+)"), 0),
    tmp_sent = arrayindex(regextract(_raw_log, "sentbyte=(\d+)"), 0),
    tmp_rcvd = arrayindex(regextract(_raw_log, "rcvdbyte=(\d+)"), 0),
    tmp_devid = arrayindex(regextract(_raw_log, "devid=\"?(\w+)"), 0)
| alter
    xdm.observer.vendor = "Fortinet",
    xdm.observer.product = "FortiGate",
    xdm.observer.name = tmp_syslog_host,
    xdm.event.log_level = tmp_pri_log_level,
    xdm.event.type = "network",
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_NETWORK),
    xdm.event.outcome = if(
        tmp_action = "accept", XDM_CONST.OUTCOME_SUCCESS,
        tmp_action = "close", XDM_CONST.OUTCOME_SUCCESS,
        tmp_action = "timeout", XDM_CONST.OUTCOME_SUCCESS,
        tmp_action = "server-rst", XDM_CONST.OUTCOME_SUCCESS,
        tmp_action = "client-rst", XDM_CONST.OUTCOME_SUCCESS,
        tmp_action = "deny", XDM_CONST.OUTCOME_FAILED,
        tmp_action = "ip-conn", XDM_CONST.OUTCOME_FAILED,
        XDM_CONST.OUTCOME_UNKNOWN),
    xdm.network.ip_protocol = if(
        tmp_proto = "6", XDM_CONST.IP_PROTOCOL_TCP,
        tmp_proto = "17", XDM_CONST.IP_PROTOCOL_UDP,
        tmp_proto = "1", XDM_CONST.IP_PROTOCOL_ICMP,
        XDM_CONST.IP_PROTOCOL_IP),
    xdm.network.protocol_layers = if(
        tmp_proto = "6", arraycreate("TCP"),
        tmp_proto = "17", arraycreate("UDP"),
        tmp_proto = "1", arraycreate("ICMP"),
        arraycreate("IP")),
    xdm.source.ipv4 = tmp_src_ip,
    xdm.source.ipv6 = "",
    xdm.source.is_internal_ip = if(
        incidr(tmp_src_ip, "10.0.0.0/8"), true,
        incidr(tmp_src_ip, "172.16.0.0/12"), true,
        incidr(tmp_src_ip, "192.168.0.0/16"), true,
        false),
    xdm.source.port = to_integer(to_number(tmp_src_port)),
    xdm.source.sent_bytes = to_integer(to_number(tmp_sent)),
    xdm.observer.unique_identifier = tmp_devid,
    xdm.source.host.device_id = "",
    xdm.target.ipv4 = tmp_dst_ip,
    xdm.target.ipv6 = "",
    xdm.target.is_internal_ip = if(
        incidr(tmp_dst_ip, "10.0.0.0/8"), true,
        incidr(tmp_dst_ip, "172.16.0.0/12"), true,
        incidr(tmp_dst_ip, "192.168.0.0/16"), true,
        false),
    xdm.target.port = to_integer(to_number(tmp_dst_port)),
    xdm.target.sent_bytes = to_integer(to_number(tmp_rcvd)),
    xdm.target.host.device_id = ""
;
```

Differences versus the JSON rule, all in the transport layer: Stage 0
adds `xdm.observer.name` and the priority-derived `xdm.event.log_level`,
and the payload regexes replace `json_extract_scalar`.

This line carries no web layer -- no `catdesc`, no URL, no header -- so
the rule does not claim one, and the three conditional HTTP fields are
absent rather than padded. That is what the all-or-nothing rule in
[network-mapping.md](../network-mapping.md) requires. Format 1 maps
`catdesc` and therefore genuinely has the layer, which is why its HTTP
block is complete and this one has none.

Two captures are deliberately quote-tolerant, and this is not cosmetic:
native FortiOS quotes its string values and its actions are hyphenated,
so a bare `action=(\w+)` matches NOTHING against `action="server-rst"`
and truncates the unquoted form to `server`. `proto` arrives as the IANA
number, so `protocol_layers` maps it to a name explicitly rather than
reusing the raw value -- `uppercase("6")` would have written "6" as a
protocol layer. The mapping is repeated rather than hoisted into a temp
because an `alter` stage evaluates its targets in parallel, so a temp
cannot read a sibling temp assigned beside it (ERR-024). The 17-field network block itself is unchanged.

## Format 3 -- the dual story: SSL-VPN login (authentication AND network)

A FortiGate SSL-VPN login is one event in THREE tags: a credential
validation (authentication) carried over a VPN tunnel (VPN) on a network
session (network). `xdm.event.tags` is an array over the closed six-member
enum, so the rule emits the UNION of the markers in a single
`arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION, XDM_CONST.EVENT_TAG_VPN, XDM_CONST.EVENT_TAG_NETWORK)`
-- never two tags assignments -- and maps both mandatory sets. The overlapping transport
fields (addresses, ports, protocol) are mapped once and satisfy both.
`xdm.event.type` is a single string: the authentication value wins, and
the network story keys on the tag.

```json
{
  "eventtime": "1782648020",
  "devid": "FGT60E1234567890",
  "logdesc": "SSL VPN login",
  "eventtype": "ssl-login",
  "user": "alice@example.com",
  "remip": "198.51.100.23",
  "remport": 51820,
  "tunnelip": "10.212.134.200",
  "result": "success"
}
```

```
[MODEL: dataset = fortinet_fortigate_vpn_raw]
filter
    _raw_log != null
| alter
    tmp_event = json_extract_scalar(_raw_log, "$.eventtype"),
    tmp_user = json_extract_scalar(_raw_log, "$.user"),
    tmp_rem_ip = json_extract_scalar(_raw_log, "$.remip"),
    tmp_rem_port = json_extract_scalar(_raw_log, "$.remport"),
    tmp_devid = json_extract_scalar(_raw_log, "$.devid"),
    tmp_result = json_extract_scalar(_raw_log, "$.result")
| alter
    xdm.observer.vendor = "Fortinet",
    xdm.observer.product = "FortiGate",
    xdm.event.type = "authentication",
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION, XDM_CONST.EVENT_TAG_VPN, XDM_CONST.EVENT_TAG_NETWORK),
    xdm.event.original_event_type = tmp_event,
    xdm.event.operation = XDM_CONST.OPERATION_TYPE_AUTH_LOGIN,
    xdm.event.outcome = if(
        tmp_result = "success", XDM_CONST.OUTCOME_SUCCESS,
        XDM_CONST.OUTCOME_FAILED),
    xdm.auth.service = "Universal",
    xdm.target.application.name = "SSL-VPN",
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
    xdm.network.ip_protocol = XDM_CONST.IP_PROTOCOL_IP,
    xdm.network.protocol_layers = arraycreate("IP"),
    xdm.source.ipv4 = tmp_rem_ip,
    xdm.source.ipv6 = "",
    xdm.source.is_internal_ip = if(
        incidr(tmp_rem_ip, "10.0.0.0/8"), true,
        incidr(tmp_rem_ip, "172.16.0.0/12"), true,
        incidr(tmp_rem_ip, "192.168.0.0/16"), true,
        false),
    xdm.source.port = to_integer(to_number(tmp_rem_port)),
    xdm.source.sent_bytes = to_integer(0),
    xdm.source.host.device_id = "",
    xdm.target.ipv4 = "",
    xdm.target.ipv6 = "",
    xdm.target.is_internal_ip = true,
    xdm.target.port = to_integer(443),
    xdm.target.sent_bytes = to_integer(0),
    xdm.target.host.device_id = tmp_devid,
    xdm.target.resource.name = tmp_devid
;
```

Dual-branch decisions worth copying:

- ONE merged tags assignment carrying all three markers
  (`EVENT_TAG_AUTHENTICATION`, `EVENT_TAG_VPN`, `EVENT_TAG_NETWORK`, from
  the closed six-member enum). A second `xdm.event.tags` would overwrite
  the first and silently drop a story (WARN-043 flags the duplicate).
- `xdm.event.outcome` uses SUCCESS / FAILED only -- the authentication
  story forbids the network padding value OUTCOME_UNKNOWN, and the
  stricter story wins on a dual event.
- `xdm.auth.service = "Universal"`: the FortiGate validates the credential itself and no known IdP provider is involved, so neither `"SP"` nor `"IDP"` describes it (see house-conventions.md). The portal name is not a role and moves to `xdm.target.application.name`, and
  the target side carries the appliance: `xdm.target.host.device_id`
  from `devid`, `xdm.target.port` 443 (the SSL-VPN listener),
  `xdm.target.is_internal_ip = true`. The login event logs no byte
  counts, so both `sent_bytes` take `to_integer(0)`.
- The client address comes from `remip` -- the pre-NAT remote peer, the
  best representation of the actual source.
- The SSL-VPN login record carries no protocol field, so
  `xdm.network.ip_protocol` takes the fail-safe `XDM_CONST.IP_PROTOCOL_IP`
  and `xdm.network.protocol_layers` the matching `arraycreate("IP")` --
  the neutral network-layer default, not a guessed transport.

## Checklist

```
[ ] every field in the 17-item network mandatory set assigned in every branch
[ ] placeholders are type-valid: to_integer(0), "", false, OUTCOME_UNKNOWN,
    IP_PROTOCOL_IP, URL_CATEGORY_UNKNOWN, arraycreate("IP")
[ ] is_internal_ip derived via incidr() when the IP is mapped
[ ] syslog branch parses the Stage 0 envelope first (PRI-anchored, never
    a vendor literal)
[ ] dual branch: ONE merged xdm.event.tags arraycreate carrying
    AUTHENTICATION + VPN + NETWORK; event.type keeps the authentication
    value; outcome is SUCCESS / FAILED only
[ ] single-purpose datasets, filter _raw_log != null only (no records dropped);
    a mixed feed classifies per record + catch-all (record-classification.md)
[ ] lint clean: no WARN-042, no WARN-043, exit 0
```
