<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Record-level classification and the catch-all

Two rules govern how a MODEL rule labels events. Both are about the
INDIVIDUAL record, not the feed as a whole.

1. Classify per record. One dataset almost always carries several
   record kinds -- a firewall feed mixes traffic, VPN logins and admin
   commands; an AAA feed mixes logins, authorizations and command
   accounting. Decide `xdm.event.type` and `xdm.event.tags` from EACH
   record's own discriminators, never as one constant stamped across the
   whole feed.
2. Never drop a record. A `datamodel dataset = X` search must return the
   same row count as the raw `dataset = X`. A MODEL rule that filters
   records out shrinks that count and hides data. The only record a rule
   may drop is a genuinely empty one (`_raw_log = null`); everything
   else must produce a row, and anything the rule cannot classify gets a
   CATCH-ALL row (see below).

## Classify per record with a no-default if()-chain

`xdm.event.tags` is an Array over the closed six-member `EVENT_TAG`
enum (see [xdm-const.md](xdm-const.md)). Assign it ONCE, with an
`if()` whose branches test each record's discriminators and which ENDS
WITH NO DEFAULT -- so a record matching no known kind falls through to
blank tags rather than a guessed marker:

```
    xdm.event.tags = if(
        tmp_is_login != null,   arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION),
        tmp_is_vpn != null,     arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION, XDM_CONST.EVENT_TAG_VPN, XDM_CONST.EVENT_TAG_NETWORK),
        tmp_is_flow != null,    arraycreate(XDM_CONST.EVENT_TAG_NETWORK),
        tmp_is_saas != null,    arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION, XDM_CONST.EVENT_TAG_SAAS),
        null)
```

The final bare `null` is deliberate: an unrecognised record carries no
tag. This mirrors the skill's existing idiom of ending a categorical
if-chain without a default when null is the correct value (as with
`xdm.event.outcome` on session-lifecycle rows).

`xdm.event.type` follows the same per-record shape -- it is a free
String, so branch it to the kind each record actually is:

```
    xdm.event.type = if(
        tmp_is_flow != null,  "network",
        tmp_is_cmd != null,   "process",
        tmp_is_login != null, "authentication",
        "GOCORTEX_UNMODELLED")
```

The discriminator temps (`tmp_is_login`, `tmp_is_flow`, ...) are extracted in
an earlier `alter` stage from the record's own markers (a `type=` field,
a `cmd=` token, an action verb, a transport tuple), exactly as the
worked examples do.

### Pick a discriminator that is stable, not one that merely looks structural

A discriminator is only useful if the same event kind always presents the
same value. Test that before building the chain on it, because a field
can look authoritative and vary underneath you.

The syslog FACILITY in a `%FACILITY-SUBFACILITY-SEVERITY-MNEMONIC` token
(see extraction-recipes Recipe 15 -- the SUBFACILITY is optional) is the
common trap. On Juniper Junos, several security-relevant mnemonics
arrive under TWO different facilities from the same daemon on the same
estate:

```
%USER-6-UI_LOGIN_EVENT: User 'root' login, class 'super-user' ...
%INTERACT-6-UI_LOGIN_EVENT: User 'root' login, class 'super-user' ...
```

Keying on the facility splits one event kind across branches. Worse, a
rule that writes the facility into `xdm.event.operation` collapses every
`UI_*` event to `operation=INTERACT`, leaving login, logout and command
execution indistinguishable.

Classify on the MNEMONIC, which is stable, and treat the facility only
as a fallback identity for a record with no mnemonic. The general rule:
when two candidate discriminators disagree, prefer the one closest to
the event's semantics (the mnemonic, the action verb, the event id
scoped to its provider) over the one describing the transport or the
subsystem. See
[extraction-recipes.md](extraction-recipes.md) for the capture.

## Claim a story only where its mandatory set can be populated

A story tag is a PROMISE that the story's mandatory fields mean
something on that record. Downstream content queries those fields as
though they are populated, so tagging a record into a story it cannot
fill does not enrich the record -- it pollutes the story.

This is the single most expensive class of error the linter cannot see.
Every mandatory field can be assigned, the rule lints completely clean,
and the rule is still wrong about what the record IS. The typical shape
is a rule that types a large share of a feed as `authentication` while
only a small fraction of those records carry an account. Nothing reads
as 0-of-n, because padding fills the mandatory set.

Before tagging a record into authentication or network, confirm the
source can supply that story's DEFINING ENTITY for that record kind:

| Story | Defining entity the record must be able to supply |
| --- | --- |
| authentication | an actor -- `xdm.source.user.username` or `upn` |
| network | a peer -- `xdm.source.ipv4` (or the target address) |

Two records from the same subsystem can differ here. An interface
transition and an SSH socket close both arrive on a router's system log
and look adjacent, but only one has a peer:

| Record kind | Carries a peer address |
| --- | --- |
| Interface transitions (`LINK-UPDOWN`, `LINEPROTO-UPDOWN`) | never |
| SSH transport (socket close, handshake error) | only when the line names a client |

An interface going down is a device status change, not a flow. Splitting
on whether a peer exists leaves a smaller network story in which every
record can supply the address the story is queried on.

### The outlier: an event BELOW the identity layer

One family of records is genuinely a story event, genuinely cannot fill
the story's mandatory set, and should KEEP its tag anyway. Cisco IOS SSH
transport failures are the clearest case:

```
%SSH-3-NO_MATCH: No matching mac found: client hmac-md5,... server hmac-sha2-256,...
%SSH-4-DH_RANGE_FAIL: ...
%SSH-4-SSH_COMPLIANCE_VIOLATION_HOSTK_ALGO: ...
```

These are algorithm negotiation failures. They happen BEFORE any
principal exists -- there is no username, no UPN, and often no peer
address, because the session failed before authentication could begin.
They will not pass the story gate above, and that is the correct outcome
rather than a modelling error.

The discriminator is not "is a principal present" but:

> could this event, BY ITS NATURE, ever have had a principal?

A negotiation failure never could: the layer that names a principal was
never reached. A login that merely lost its username to a bad capture
always could, and that is the case the gate exists to catch.

So the gate is evidence of two different things depending on the answer.
Where the event could have had a principal and does not, the rule tagged
the wrong thing or the capture is broken -- fix it. Where the event could
never have had one, the empty mandatory set is the honest record of a
session that failed below identity, and stripping the tag would hide a
real authentication failure from the story that exists to hold it.

State the choice in the MAPPED header NOTES, because the ratio test will
show the gap and the next reader needs to know it was decided rather than
missed.

### The partial case: can the record ANSWER the story's questions?

The clear cases are "can populate" and "cannot populate". The real
decision is usually in between: a routing, policer or digest event
carries a genuine peer address, so `xdm.source.ipv4` is real -- and there
is no port, no protocol, no direction and no byte count. One field of a
twenty-field story is available.

The test is NOT "does this record have a field from the story". It is:

> can this record ANSWER the questions the story exists to answer?

A flow story exists to answer who talked to whom, over what, in which
direction, and how much. A record that cannot say who talked to whom
over what is not a flow, however real its single address is. Tagging it
NETWORK puts device telemetry where every flow query returns it and none
can use it -- the story gets bigger and less true at the same time.

So: a partial record takes the honest classification, not the story tag,
and keeps its real values in their real fields. The peer address still
belongs in `xdm.source.ipv4`; what it does not get is the NETWORK tag
asserting that the record is a flow.

When a record cannot fill a story, give it an honest classification
(`system`, `status`, the subsystem name) and a descriptive
`xdm.event.description`. That is more useful than a story claim you
cannot back, and it keeps the record modelled rather than dropped.

This is broader than the padding gate in
[authentication-mapping.md](authentication-mapping.md): that governs
whether to PAD a field, this governs whether to CLAIM the story at all.

### Never gate a story on a facility or subsystem flag

The stable-discriminator rule above says the mnemonic is the identity
and the facility is a fallback. Extend it: a facility must never gate
`xdm.event.type`, `xdm.event.tags`, or any mandatory story field. A
facility names the SUBSYSTEM THAT SPOKE; only the mnemonic says what
happened.

```
// WRONG -- one branch sweeps a whole subsystem into the auth story
tmp_is_ssh = if(tmp_facility = "SECURITY-SSHD", "y", ...),
xdm.event.type = if(tmp_is_ssh != null, "authentication", ...)
```

A single branch like that sweeps in terminal-window errors, handshake
errors, socket closes and AAA reachability changes -- none of them an
authentication -- and stamps an authentication operation on all of them.

### An operation chain must not end in a broad subsystem flag

The same defect in the verb. The skill already forbids blind-defaulting
to `AUTH_LOGIN`; the argument is identical for the generic
`OPERATION_TYPE_AUTHENTICATION`:

```
// WRONG -- the final branch keys on a subsystem, not an event
xdm.event.operation = if(
    tmp_is_sshauth != null, XDM_CONST.OPERATION_TYPE_AUTH_LOGIN,
    tmp_is_ssh != null,     XDM_CONST.OPERATION_TYPE_AUTHENTICATION)
```

The last branch of an `xdm.event.operation` chain must key on a SPECIFIC
event. If nothing specific matches, leave the field unset -- an absent
verb is honest, a wrong one is not.

### Prefer the most exact discriminator the source offers

In order of preference:

1. A numeric vendor event code, where the vendor emits one. A product
   that assigns each event kind its own code gives an exact key, and one
   code maps to exactly one meaning.
2. The mnemonic or message tag.
3. The facility, as a fallback identity only, and never to gate a story.
4. Message text -- never. Matching English prose is how a classifier
   silently misses variants: a rule keyed on `authentication succeeded`
   recognises neither `A SSH CLI user has successfully logged in` nor
   `A CLI user has logged in from SSH`, and every login phrased the
   other ways goes unclassified.

Group codes by what they MEAN (success, failure, logout, account
management, configuration) so that a new code in a known family does not
inherit the wrong outcome.

### A keyword is a FALSE FRIEND in both directions

Missing variants is the mild failure. The severe one is the opposite: a
phrase that means something else entirely in the source you are actually
holding, so the classifier fires confidently on records that are not the
event at all.

The same phrase, from ONE vendor's estate, decides opposite ways:

| Source | Line | `logged in` means |
| --- | --- | --- |
| Nokia SR OS (the network element) | `SECURITY-MINOR-ssh_user_login-2009 [user_x]: User user_x from 198.51.100.99 logged in` | a real SSH login |
| Nokia NFM-P (the manager) | `EXCEPTION logged in java.net.ConnectException` | written to a log |

On the management system every occurrence of the phrase is the second
sense -- thousands of them, and not one is an authentication event. A
rule that gated its authentication story on the keyword would tag them
all, and the result would pass every mechanical check: the tag is
populated, the fields are non-null, nothing is the catch-all sentinel.
Only reading what the records actually are reveals it. The same source
also carries `Could not login` inside a Kerberos configuration advisory,
which is a second false friend in the same file.

The lesson is not "beware these two phrases". It is that a keyword
classifier inherits whatever a developer happened to write in an
exception message, in a library the vendor did not author, in a language
where the same verb has two unrelated senses. The structured token --
the event code on the element, the `java.class.method` on the manager --
says what the record IS, and it is the only thing that does.

Where a source genuinely offers no structured discriminator, say so in
the MAPPED header and leave the records on the catch-all. Unclassified
is a state a reviewer can see and fix; wrongly classified is not.

## The catch-all: keep the datamodel row count honest

Give every record a home. Filter only the empty ones, then let the
if()-chains label what they recognise and sentinel the rest:

```
[MODEL: dataset = vendor_x_raw]
filter
    _raw_log != null                       // the ONLY record we drop
| alter
    tmp_is_login = ... , tmp_is_flow = ... , tmp_is_cmd = ...   // per-record discriminators
| alter
    xdm.event.type = if(
        tmp_is_flow != null,  "network",
        tmp_is_cmd != null,   "process",
        tmp_is_login != null, "authentication",
        "GOCORTEX_UNMODELLED"),            // catch-all type
    xdm.event.tags = if(
        tmp_is_login != null, arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION),
        tmp_is_flow != null,  arraycreate(XDM_CONST.EVENT_TAG_NETWORK),
        null),                             // catch-all: blank tags
    xdm.event.original_event_type = coalesce(tmp_vendor_event_type, "GOCORTEX_UNMODELLED")
;
```

The sentinel `"GOCORTEX_UNMODELLED"` lands in `xdm.event.original_event_type`
(a plain String) ONLY when the record carried no vendor event-type of
its own. Recognised records keep their real vendor type there, so the
sentinel and the real values coexist in one column -- which is what
makes the review query work.

## Always leave the review query in the rule

Every rule carries a commented query so the author can see what did not
classify and grow the rule to cover it:

```
// REVIEW UNMODELLED: list records this rule could not classify --
//   datamodel dataset = vendor_x_raw
//   | filter xdm.event.original_event_type = "GOCORTEX_UNMODELLED"
//   | fields xdm.event.original_event_type, vendor_x_raw._raw_log
```

Replace `vendor_x_raw` with the real dataset. Run it after deploying the
rule; each distinct raw shape it returns is a record kind to add a
branch for.

## Checklist

```
[ ] only filter is _raw_log != null (no discriminator filter that drops rows)
[ ] xdm.event.type and xdm.event.tags assigned per record via if()
[ ] tag if-chain ends with no default -> blank tags on unrecognised records
[ ] only closed EVENT_TAG members used (AUTHENTICATION/NETWORK/CLOUD/SAAS/ONPREM/VPN)
[ ] one xdm.event.tags assignment (never two -- the second overwrites)
[ ] unclassified records carry xdm.event.original_event_type = "GOCORTEX_UNMODELLED"
[ ] the commented REVIEW UNMODELLED query is present with the real dataset
```

### A facility names the feature OWNER, not the event emitter

The facility is an unstable classifier (above). The stronger form: on a
mature product the facility name tells you which subsystem OWNS a
feature, and the event you want is frequently emitted somewhere else.

One wireless controller supplies three instances:

| Facility | What the name promises | What it actually logs |
| --- | --- | --- |
| SSHPM | SSH logins | SSH POLICY -- IPsec, certificates, L2TP. No logins at all. |
| CIDS | IDS detections | Its own sensor plumbing. Every message is a failure; no successful shun exists. |
| WPS (Wireless Protection System) | wireless IDS detections | Signature FILE PARSING. 52 of 57 messages. |

The enforcement those facilities exist to perform is emitted by the
MOBILITY manager (`MM-1-CLIENT_SHUNNED`) and the policy layer
(`APF-*` rogue and exclusion records) instead.

So: find an event by reading TEMPLATES, never by reading facility names.
A facility list tells you what a product can do. Only the templates tell
you what it says.

The failure mode is quiet and expensive. A rule keyed on the plausible
facility lints clean, classifies records, and reports zero detections
forever -- because the facility it modelled genuinely never emits any.
Nothing looks wrong; a story simply stays empty.

Worth modelling anyway, for the opposite reason: a security facility that
logs only its own failures is telling you the control is not working.
`CIDS-1-SHUN_LIST_ENTRY_CREATE_FAIL` means a sensor asked for an
enforcement and the controller could not apply it -- the client stayed
connected. That is a control failure, and it is more urgent than most of
the detections it sits beside.

### An event split across two records

Some events are emitted as a pair, with the SUBJECT in the second record:

```
WPS-4-SIG_ALARM_OFF       AP MAC : Alarm OFF, TYPE sig NAME, track=T preced=N hits=N slot=N channel=N
WPS-4-SIG_ALARM_OFF_CONT  ...continue, source mac= MAC
```

The first carries the detecting AP, the signature, the track mode, the
precedence, the hit count, the slot and the channel -- everything except
who did it. The continuation carries the offending station.

Model only the first and you produce a detection with a detector and no
subject. The continuation carries no classifiable identity of its own, so
it takes the catch-all unless the rule correlates the pair on adjacency.

Two related shapes have appeared already: the Cisco
`**MSG XXXXX CONTINUATION #YY` split and the Nokia NFM-P header-less
continuation line. The check is the same in all three -- before mapping a
record, ask whether the event is CONTAINED in it, and where a
`_CONT`-style mnemonic or a leading `...` exists in the catalogue, assume
it is not.
