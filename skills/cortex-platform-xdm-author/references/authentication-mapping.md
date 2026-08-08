<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Authentication-event mandatory mapping

Authentication events feed the XDM authentication story and identity
analytics. The story is only created automatically when a fixed set of
XDM fields is mapped. A mandatory field left unmapped drops the event
from the story and from identity analytics, so this reference is the
authoritative checklist for any rule that models a login, logon, MFA,
SSO, or other credential-validation event.

Classification is PER RECORD. A feed rarely holds only logins, so decide
the authentication tag and the mandatory set on each record from its own
discriminators, not as one constant across the feed. Records in the same
dataset that are not authentication (a command execution, a bare flow, a
line the rule does not recognise) take their own treatment and, if
unrecognised, the catch-all -- never a forced authentication tag. See
[record-classification.md](record-classification.md).

This guidance is host-agnostic and format-agnostic. Extraction differs
per source format (syslog RFC 3164 / RFC 5424, JSON, JSONL, CEF, LEEF,
key=value), but the XDM target fields and their requirement level are
identical in every case. Map them in the MODEL rule after extraction.

## When this applies (auto-detection)

Treat a sample as an authentication event whenever its field names or
values carry a login / logon / sign-in / MFA / SSO / credential signal,
regardless of vendor. Common signals:

- Field names containing `login`, `logon`, `signin`, `auth`, `authn`,
  `mfa`, `2fa`, `otp`, `sso`, `saml`, `oauth`, `kerberos`, `ntlm`,
  `credential`, `password`, `upn`, `idp`.
- Event-type or action values such as `user.authentication.sso`,
  `microsoft.login.success`, `LOGIN_FAILED`, `logged in`, `mfa challenge`.

`scripts/profile_log.py` reports this signal in an `authentication`
block of the worksheet so the detection is deterministic rather than a
judgement call. When detected, apply the mandatory set below.

Network is the foundational layer beneath this one: when the
authentication log also carries the full transport flow (both endpoint
addresses, a port, and a protocol -- a VPN login, an SSH session, a
gateway sign-in), the event is ALSO a network connection. Apply the
mandatory set in [network-mapping.md](network-mapping.md) on top of
this one, with the union of the story tags in ONE
`xdm.event.tags = arraycreate(...)`. Add the deployment / transport
markers the record earns: `XDM_CONST.EVENT_TAG_VPN` for a VPN login,
`XDM_CONST.EVENT_TAG_SAAS` for a SaaS IdP (Okta, Entra ID, Ping),
`XDM_CONST.EVENT_TAG_CLOUD` for a cloud-provider console, or
`XDM_CONST.EVENT_TAG_ONPREM` for on-premises directory auth. The tag set
is closed to six members ([xdm-const.md](xdm-const.md)).

When detected, `scripts/scaffold_rule.py` pre-populates the mandatory
set. It pads only the fields whose placeholder is semantically EMPTY --
`xdm.network.ip_protocol`, the transport ports, `xdm.target.ipv4`, and
the account-class pair `identity_type` / `user_type` -- and sets
`xdm.event.type` to `authentication`.

Everything else is listed as a must-extract TODO rather than seeded:
`xdm.auth.service`, `xdm.event.operation`, `xdm.source.user.upn`,
`xdm.source.ipv4`, `xdm.event.original_event_type`,
`xdm.event.outcome` and `xdm.target.resource.name`. Two of those moved
out of the paddable set deliberately. `xdm.target.resource.name` is
never padded because a padded target is the state an inverted rule
passes the linter in (WARN-055). `xdm.auth.service` followed it in
1.9.0: a ROLE decided per event type cannot be seeded with a default
without asserting a flow shape the scaffolder cannot know, and the
`"Login"` pad it used to carry is gone entirely.

Enforcement is advisory. `scripts/lint_rule.py` classifies a MODEL rule
as authentication either from an explicit XDM marker (the
`EVENT_TAG_AUTHENTICATION` tag, an `OPERATION_TYPE_AUTH_*` operation, or
`authentication` in `xdm.event.type`) or from a broader auth literal
(`login`, `logon`, `signin`, `mfa`, `sso`, ...) in an event-classification
field such as `xdm.event.original_event_type = "user.login"`, so a rule
that models authentication without ever using an explicit marker is still
caught. It raises WARN-042 (warning
severity, never an error) for each mandatory field that an auto-detected
authentication rule leaves unmapped, and also for each mapped mandatory
field whose value violates the closed vocabulary the story demands (the
wrong const, a static source address, or a list where a string is
required). Value conformance is conservative: only a definitively wrong,
self-contained literal is flagged, so a value resolved from a temp, an
xdm read, or a const expression is never second-guessed. The linter never
blocks on this and the exit code stays 0. The author decides; the warning
is a reminder.

## Mandatory fields (all 15 must be mapped)

| XDM target | Type | Notes |
| --- | --- | --- |
| `xdm.source.ipv4` | string | External source IP the IdP / SaaS observed. Map from the raw field that best represents the real client (prefer pre-proxy `client_ip` / `source_ip` / `original_client_ip`). Never static, empty, or a list. |
| `xdm.source.port` | integer | Map the real value; otherwise `to_integer(0)`. |
| `xdm.target.ipv4` | string | Map a real value if present; otherwise the empty string `""`. Do not map a list. |
| `xdm.target.port` | integer | Map the real value; otherwise `to_integer(0)`. |
| `xdm.target.resource.name` | string | The device, application or service the principal is authenticating TO -- its name, or its address when the log carries no name. Set it IN ADDITION to the type-correct target field (`xdm.target.host.hostname` for a named host, `xdm.target.application.name` for an application, `xdm.target.ipv4` for an address), never instead of it. NEVER pad this field. Derive it from the raw log, or let it resolve null on a record that genuinely has no target -- an empty-string placeholder satisfies the checker while leaving the event targetless, which is the exact defect this field exists to expose. See "Deriving xdm.target.resource.name" below. |
| `xdm.network.ip_protocol` | integer (enum) | Assign the appropriate `XDM_CONST.IP_PROTOCOL_*` (interactive auth over TCP -> `IP_PROTOCOL_TCP`; pad `IP_PROTOCOL_IP` when absent). |
| `xdm.event.type` | string | Resolve to a value that contains `authentication`. |
| `xdm.event.tags` | array | Must include `XDM_CONST.EVENT_TAG_AUTHENTICATION` on the authentication records. Assign per record via one `if()` so non-auth records in the same feed get their own tags (or blank); add `EVENT_TAG_VPN` / `EVENT_TAG_SAAS` / `EVENT_TAG_CLOUD` / `EVENT_TAG_ONPREM` when earned. See [record-classification.md](record-classification.md). |
| `xdm.event.operation` | enum | Derive the specific `XDM_CONST.OPERATION_TYPE_*` from the event: `OPERATION_TYPE_AUTH_LOGIN` (password login), `OPERATION_TYPE_AUTH_MFA` (involves MFA), `OPERATION_TYPE_AUDIT` (authorization / accounting). There is NO neutral member, so NEVER blind-default to `AUTH_LOGIN` -- when the event kind is genuinely unclear, leave the field unmapped (or `""`) rather than asserting an operation the log does not describe. |
| `xdm.event.original_event_type` | string | The raw vendor event name exactly as logged (e.g. `user.authentication.sso`, `microsoft.login.success`). |
| `xdm.event.outcome` | string (enum) | Only `XDM_CONST.OUTCOME_SUCCESS` or `XDM_CONST.OUTCOME_FAILED`, and only on conclusive events. Do not set on intermediate steps. |
| `xdm.auth.service` | string | The ROLE this system played in the authentication flow, decided PER EVENT TYPE: `"IDP"` (it validates the credential), `"SP"` (it initiates the request and relies on another to validate), or `"Universal"` (the source is not a known IdP provider). NEVER a service name -- `"Kerberos"`, `"SSH"`, `"TACACS+"` and `"Login"` are the values this field most often wrongly carries. The protocol or mechanism belongs in `xdm.auth.auth_method`, `xdm.network.application_protocol` or `xdm.logon.package_name`. See "Deriving xdm.auth.service" below. |
| `xdm.source.user.upn` | string | The authenticated identity, ALWAYS UPN-shaped (`jane.doe@company.com`). Cannot be empty. This is the central correlation key across IdPs -- it is `upn`, not `username`. When the raw identity may be bare, synthesise the shape: `if(tmp_username contains "@", tmp_username, tmp_username != null, concat(tmp_username, "@localhost"))`. |
| `xdm.source.user.identity_type` | string (enum) | The nature of the authenticated principal. Derive the `XDM_CONST.IDENTITY_TYPE_*` member: `IDENTITY_TYPE_USER` for a human principal (the common case -- anytime a real UPN is present), `IDENTITY_TYPE_MACHINE` for a computer account (name ends `$`), `IDENTITY_TYPE_BUILTIN` for a well-known OS account, `IDENTITY_TYPE_VIRTUAL` for a managed / virtual account. Fall back to `IDENTITY_TYPE_UNKNOWN` only when no principal resolves. See "Deriving xdm.source.user.identity_type" below. |
| `xdm.source.user.user_type` | string (enum) | The account class. Derive the `XDM_CONST.USER_TYPE_*` member: `USER_TYPE_REGULAR` is the default (~90% of principals), `USER_TYPE_MACHINE_ACCOUNT` when the account name ends `$`, `USER_TYPE_SERVICE_ACCOUNT` for a service-account naming convention (`svc_` / `svc-` prefix, `service` in the name, a GCP `*.iam.gserviceaccount.com` identity). ALWAYS emit the derivation (defaulting to `USER_TYPE_REGULAR`), keyed on an explicit account-type field when the log carries one, otherwise on the principal name. See "Deriving xdm.source.user.user_type" below. Distinct from `xdm.source.user.identity_type`. |

### An identity field records what was PRESENTED, not what is valid

An identity field carries what the authenticator was given. It does not
carry what a valid account looks like. So do NOT sanitise, normalise,
trim or reject an odd value at model time, and never replace an
unparseable identity with the catch-all sentinel.

A value that is not a plausible account IS the finding. A login attempt
whose account is `${jndi` is a template-injection probe typed at the
authentication prompt, and it is detectable only because the rule
preserved it verbatim. Any of these would have destroyed the evidence:

- dropping values that fail an account-shape test
- trimming or stripping metacharacters
- substituting the sentinel for an unparseable identity
- declining to map the field unless the value looked like a name

The distinction that resolves this against the gating rules elsewhere in
this file: SHAPE decides whether to read the SOURCE; it must never
decide whether to keep the VALUE.

- Reading a field that is NOT an identity into an identity field is a
  defect -- gate on whether the field is, on this event, where the
  authenticator recorded the principal.
- Reading a field that IS the identity, whose value happens to be
  hostile, is correct -- keep it exactly as presented.

State the consequence plainly rather than leaving it implicit: a
faithfully modelled identity field can carry arbitrary
attacker-controlled text into every downstream consumer. That is the
right trade, because the alternative is silently discarding attack
evidence -- but it is a trade, and it matters most where a pack ships
publicly and the consumers are not the author's own.

### Define what a field can NEVER contain, never what a valid value looks like

When a check over identity values is needed, express it as a closed set
of things that are always wrong, not as a pattern of what is right. The
first is universal and shippable; the second is estate-specific,
unbounded, and cannot survive contact with another customer's naming
convention.

The worked failure: excluding any character outside
`[A-Za-z0-9._@\-]` looks like a reasonable definition of a valid
account, and it flags EVERY Active Directory machine account, because
`WIN-DC01$` legitimately ends in a dollar sign (see the
`IDENTITY_TYPE_MACHINE` derivation below). Worse, it presents as a
tuning problem rather than a design error, so the likely repair is
adding exclusions rather than correcting the premise.

Never match a bare metacharacter when the pattern of concern requires a
PAIR. The bare form is exactly where the legitimate collisions live:

```
// WRONG -- the bare $ is a valid trailing character on a machine account
[^A-Za-z0-9._@\-]

// RIGHT -- paired delimiters, none of which occur in a real account
(\$\{|\{\{|\$\(|\.\./|&#|%[0-9A-Fa-f]{2}|[<>|;])
```

### Three branches, in order: MAP, then DERIVE, then pad

An unmapped mandatory field has three possible treatments, and they are
ordered. Padding is the LAST of them, not the alternative to mapping:

1. The source carries the value -> MAP it.
2. The source does not carry it, but it can be CONSTRUCTED from a field
   the record does carry -> DERIVE it.
3. Neither -> pad only if the placeholder asserts nothing, otherwise
   leave the field unset and accept the advisory.

Branch 2 is the one that gets skipped, because the question an author
naturally asks is "does the source contain this value" when the question
that matters is "can this value be constructed from what the source
does contain". `xdm.source.user.upn` is the canonical case: a device
that carries an account and no domain can always produce a UPN, and
`<account>@localhost` is the conventional construction. That is not an
invented fact -- it states that the account is local to the device,
which is exactly true for a router or appliance login.

```
xdm.source.user.upn = if(
    tmp_account contains "@", tmp_account,
    tmp_account != null,      concat(tmp_account, "@localhost"))
```

A bare account plus a synthesised realm is the expected shape for ANY
device-local identity source: network-device syslog, AAA, appliance
administration. Leaving the UPN empty is correct only when the record
carries no account either -- and in that case the authentication story
should not be claimed at all, per the story-claim rule.

The failure this ordering prevents is quiet. An empty-string UPN is not
null, so a null check passes; not missing, so WARN-042 stops warning;
populated on every record, so a population ratio passes -- while the
account sits in the record, twice, and no operator pivoting on a UPN can
find it, and the identity cannot be joined to any source that does carry
one. A field can be complete and useless at the same time.

Note the asymmetry with the empty port and empty target address in the
policy below: those sit correctly in branch 3 because nothing in the
record can produce them. An empty UPN does not.

Placeholder policy for the mandatory set, reached only after branches 1
and 2 are exhausted. Read the entity-field gate below before padding
anything:

- Integer fields with no source value -> `to_integer(0)` (`xdm.source.port`,
  `xdm.target.port`).
- `xdm.target.ipv4` is a string here -> a real value, or the empty
  string `""`. Never a list.
- `xdm.source.ipv4` must always come from the raw log -- never a static
  string, list, or empty string.
- `xdm.event.outcome` resolves to `XDM_CONST.OUTCOME_SUCCESS` or
  `XDM_CONST.OUTCOME_FAILED` only.
- The event time (generated time) is mapped automatically; do not set it
  manually.

### The entity-field gate: never pad your way past a topology error

Padding satisfies WARN-042 completely, so a rule can assign every
mandatory field, lint clean, and still carry the WRONG entity -- or no
entity at all -- in an entity field. The classic shape: `xdm.target.ipv4`
is the empty string on every SSH login record of a router pack, the
linter reports nothing, and the real defect is an inverted topology (see
"Device-local authentication" below), not a missing value.

An empty ENTITY field is indistinguishable from a mapping the author
never considered. So before padding one of the entity fields --
`xdm.source.ipv4`, `xdm.target.ipv4`, `xdm.*.host.hostname`,
`xdm.source.user.*` -- confirm the source genuinely cannot supply it:

1. Check the whole record for the value under another name. A device
   logging a login to itself usually carries its own address in the
   syslog header or the payload even when no field is called
   `target_ip`.
2. Check the topology. If the entity looks absent, the more common cause
   is that it was mapped to the wrong side. Re-read
   "Device-local authentication" before padding.
3. Only if the source truly lacks it, pad per the policy above AND state
   in the NOT MAPPED block why the source cannot supply it.

Padding remains correct for scalars the source genuinely lacks. It is not
a way to close an advisory on an entity.

### Pad only where the placeholder is semantically EMPTY

The padding advice and the hard rule against inventing values pull in
opposite directions on some fields, and the rule is: pad where the
placeholder asserts NOTHING, and leave the field unset where the pad
would assert something, accepting the advisory.

| Pad | Because |
| --- | --- |
| `xdm.source.port = to_integer(0)` | zero is transparently a placeholder, not a port |
| `xdm.target.ipv4 = ""` | the empty string asserts no address |

`xdm.network.ip_protocol` shows where the line falls, and this file
used to place it on the wrong side. The pad is
`XDM_CONST.IP_PROTOCOL_IP`, which names the parent protocol rather than
a transport, so it is semantically empty in the same way `""` is: it
asserts an IP record and nothing more. Pad it, as the mandatory table
above and `scripts/scaffold_rule.py` both do.

What is barred is padding a SPECIFIC protocol. Where the administrative
transport is TCP for an SSH session and something else for a console
login, and the record does not say which, `IP_PROTOCOL_TCP` is a
plausible falsehood written into every record -- and unlike a null it
is invisible, because the field is populated and type-valid. Derive the
specific member where the log says so, fall back to `IP_PROTOCOL_IP`
where it does not, and never guess between them.

After deploying, count each mandatory field's POPULATION over real
records, not just its presence in the rule. A field populated on 0 of n
records is usually a topology error, and the count is the only thing
that reveals it -- the linter cannot.

Count THREE states per field, not two. A field has three ways to read as
populated, and only one of them is a working mapping:

| State | What it means |
| --- | --- |
| a real, correct value | the mapping works |
| the empty string | a pattern matched but captured nothing |
| the catch-all sentinel | the extraction failed and the field fell back |
| a plausible but WRONG value | the pattern matched the wrong token |

The fourth is the hardest, because no count reveals it: the field holds a
real-looking string, so it passes the null, empty and sentinel checks
together. It arises when a capture is qualified by something that does not
actually constrain it -- most commonly letter case, since XQL folds case
and an uppercase class matches lowercase text (see
[xql-language.md](xql-language.md) "Case can never qualify a capture").
Catching it means reading the DISTINCT values, not counting them: pull
`comp count() by <field>` and look at whether the values are the kind of
thing the field is supposed to hold.

The sentinel is the one that defeats every other check. `GOCORTEX_UNMODELLED`
IS a value, so a field defaulting to it is non-null, non-empty, and
reports full population while carrying no information:

```
| comp count() as n,
       sum(if(xdm.event.description = "GOCORTEX_UNMODELLED", 1, 0)) as sentinel,
       sum(if(xdm.event.description = "", 1, 0)) as empty
```

`scripts/verify_rule.py --coverage` reports all three offline and flags a
field whose values are predominantly empty or predominantly the sentinel.

A zero test is not enough on its own. Because padding fills the
mandatory set, no field reads as 0-of-n even when most records do not
belong in the story at all. Run a RATIO test as well: compare the
records CLAIMING the story against the records carrying the story's
defining entity.

```
datamodel dataset = <vendor>_<product>_raw
| filter xdm.event.type contains "authentication"
| comp count() as claimed,
       sum(if(xdm.source.user.username != null, 1, 0)) as with_actor
```

A large gap is usually NOT a missing extraction. It usually means the
classification is too broad, and the fix is upstream in
`xdm.event.type`, not another regex. Narrowing the classification so
only genuine authentications carry the story typically cuts the claimed
count sharply and takes actor and outcome coverage close to complete --
the story becomes smaller and true. See
[record-classification.md](record-classification.md) "Claim a story only
where its mandatory set can be populated".

Note on identity: `xdm.source.user.upn` is the mandatory key. The
human-readable display name is the optional `xdm.source.user.username`
below -- do not substitute one for the other.

The upn value must ALWAYS be UPN-shaped (`user@domain`). A direct
mapping (`xdm.source.user.upn = tmp_upn`) is allowed ONLY when the source
field is a UPN by definition -- `userPrincipalName`, an email address,
an IdP login id. For every other identity source, or whenever there is
any doubt, use the shape-guard idiom: pass a value that already carries
`@` through unchanged, and synthesise a domain for a bare principal.

```
    xdm.source.user.upn = if(
        tmp_username contains "@", tmp_username,
        tmp_username != null, concat(tmp_username, "@localhost"))
```

When the source is known to be bare (a TACACS principal, a Windows
`TargetUserName`, an sshd user), the short form
`if(tmp_username != null, concat(tmp_username, "@localhost"))` is equivalent.
Never emit `xdm.source.user.upn = tmp_username` for a possibly-bare
identity -- the linter raises an advisory WARN-042 for a bare
identifier whose name does not itself indicate a UPN source. The same
shape rule applies to `xdm.target.user.upn` when a rule maps it.

## Deriving xdm.event.operation

`xdm.event.operation` is an `XDM_CONST.OPERATION_TYPE_*` enum with no
neutral member, so always DERIVE the right member from the event before
considering a fall-back. Match the event signal (in the vendor event
name / action / sub-type) to the operation:

| Event signal (name / action / value) | Operation |
| --- | --- |
| login, logon, log-on, sign-in, sign-on, sso, interactive logon, password login | `XDM_CONST.OPERATION_TYPE_AUTH_LOGIN` |
| mfa, 2fa, otp, push, verify, second factor, step-up | `XDM_CONST.OPERATION_TYPE_AUTH_MFA` |
| authorization, authorisation, accounting, command accounting, audit, policy evaluation | `XDM_CONST.OPERATION_TYPE_AUDIT` |
| none of the above can be determined | leave unmapped (or `""`) -- never guess |

The match is on the event's classification field, not on a field name
alone. Prefer an `if()` chain keyed on the vendor event value, for
example `if(tmp_factor != null, XDM_CONST.OPERATION_TYPE_AUTH_MFA, tmp_event
contains "login", XDM_CONST.OPERATION_TYPE_AUTH_LOGIN)`. Only when the
event kind is genuinely ambiguous does the field stay unmapped -- the
advisory WARN-042 then reminds, which is correct.

## Deriving xdm.source.user.identity_type

`xdm.source.user.identity_type` classifies the nature of the
authenticated principal. It is a scalar `XDM_CONST.IDENTITY_TYPE_*`
enum, and unlike `xdm.event.operation` it HAS a neutral member
(`IDENTITY_TYPE_UNKNOWN`), so a safe fall-back always exists. Even so,
derive the specific member: an authentication event carries a mandatory
UPN, so the principal is almost always a human user.

The derivation is on the principal value (and any explicit account-type
field), not on the log format -- the same logic applies to JSON and to
a syslog payload once the account has been extracted into a temp. Check
the signals in order:

| Principal / account signal | identity_type |
| --- | --- |
| An explicit vendor account-type field says machine / computer / device | `XDM_CONST.IDENTITY_TYPE_MACHINE` |
| Account name ends with `$` (AD computer account, e.g. `WIN-DC01$`) | `XDM_CONST.IDENTITY_TYPE_MACHINE` |
| Managed / virtual identity: `NT SERVICE\...`, gMSA, IIS app-pool | `XDM_CONST.IDENTITY_TYPE_VIRTUAL` |
| Well-known OS account: `SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, `ANONYMOUS LOGON`, `root` | `XDM_CONST.IDENTITY_TYPE_BUILTIN` |
| A human principal -- a UPN, email, or ordinary username (the common case) | `XDM_CONST.IDENTITY_TYPE_USER` |
| No principal resolves / genuinely indeterminate | `XDM_CONST.IDENTITY_TYPE_UNKNOWN` |

When the log carries an explicit account-type field, key on it first --
it is more reliable than name-shape heuristics. Otherwise derive from
the principal name. A representative if() chain over an extracted
`tmp_principal` temp:

```
    xdm.source.user.identity_type = if(
        tmp_principal = null, XDM_CONST.IDENTITY_TYPE_UNKNOWN,
        tmp_principal contains "$", XDM_CONST.IDENTITY_TYPE_MACHINE,
        tmp_principal contains "NT SERVICE", XDM_CONST.IDENTITY_TYPE_VIRTUAL,
        lowercase(tmp_principal) ~= "^(system|local service|network service|anonymous logon|root)$",
            XDM_CONST.IDENTITY_TYPE_BUILTIN,
        XDM_CONST.IDENTITY_TYPE_USER)
```

When every principal in the source is a human login (a typical IdP or
SaaS feed), the short form is enough: `if(tmp_principal != null,
XDM_CONST.IDENTITY_TYPE_USER, XDM_CONST.IDENTITY_TYPE_UNKNOWN)`.

Note: `xdm.source.user.identity_type` (the nature of the account --
USER / MACHINE / BUILTIN / VIRTUAL) is distinct from
`xdm.source.user.user_type` (the account class -- REGULAR / SERVICE /
MACHINE), the next mandatory field. Map both.

## Deriving xdm.source.user.user_type

`xdm.source.user.user_type` is a scalar `XDM_CONST.USER_TYPE_*` enum
with three members: `USER_TYPE_REGULAR` (a normal interactive account),
`USER_TYPE_SERVICE_ACCOUNT` (an account a program runs as), and
`USER_TYPE_MACHINE_ACCOUNT` (a computer / host account). There is no
UNKNOWN member, so `USER_TYPE_REGULAR` is the default -- it is correct
for the ~90% of authentication events that are human logins.

A log rarely states the account class outright, so ALWAYS emit the
derivation rather than a bare default: key on an explicit account-type
field when the vendor provides one, otherwise match the principal name
against the well-known service- and machine-account conventions, and
fall through to `USER_TYPE_REGULAR`.

Explicit account-type field first. Our anchor dictionary records these
vendor field names for the account class: `user_type`, `usertype`,
`type`, `cloud_account_type`, and `event_useridentity_type` (AWS
CloudTrail `userIdentity.type`). When one is present, map its value:
`AWSService` / a value containing `service` -> `USER_TYPE_SERVICE_ACCOUNT`;
a value containing `machine` / `computer` -> `USER_TYPE_MACHINE_ACCOUNT`;
otherwise `USER_TYPE_REGULAR`.

Name-convention fallback (real-world patterns, not invented):

| Principal / account-name signal | user_type |
| --- | --- |
| Name ends with `$` (AD computer account; a gMSA is treated as a computer account and also ends `$`) | `XDM_CONST.USER_TYPE_MACHINE_ACCOUNT` |
| `svc_` / `svc-` prefix (Microsoft-recommended service-account convention, e.g. `svc_backup`, `svc-HRDataConnector`) | `XDM_CONST.USER_TYPE_SERVICE_ACCOUNT` |
| `service` anywhere in the name (`service_`, `tmp_service`, `*service*`) | `XDM_CONST.USER_TYPE_SERVICE_ACCOUNT` |
| GCP service account (`*.iam.gserviceaccount.com`; service agents are prefixed `service-`) | `XDM_CONST.USER_TYPE_SERVICE_ACCOUNT` |
| Unix daemon accounts (`www-data`, `nobody`, `daemon`, and similar) | `XDM_CONST.USER_TYPE_SERVICE_ACCOUNT` |
| Anything else (a human principal -- the default) | `XDM_CONST.USER_TYPE_REGULAR` |

A representative if() chain over an extracted `tmp_principal` temp
(machine before service, so a gMSA `$` account is classed as a machine
account; `~=` is a regex match, so one alternation covers the service
conventions):

```
    xdm.source.user.user_type = if(
        tmp_principal = null, XDM_CONST.USER_TYPE_REGULAR,
        tmp_principal contains "$", XDM_CONST.USER_TYPE_MACHINE_ACCOUNT,
        lowercase(tmp_principal) ~= "^svc[-_.]|service|gserviceaccount|^www-data$|^nobody$|^daemon$",
            XDM_CONST.USER_TYPE_SERVICE_ACCOUNT,
        XDM_CONST.USER_TYPE_REGULAR)
```

These are heuristics: a real user whose name happens to contain
"service" is misclassified, but the cost is low and `USER_TYPE_REGULAR`
catches everything the patterns miss. Only extend the service-account
pattern list from real vendor conventions -- never invent a prefix.

## Deriving xdm.auth.service

`xdm.auth.service` is the ROLE the logging system played in the
authentication flow. It is NOT the protocol, the mechanism or the
service name. The official page "XDM fields for mapping authentication
events" states it directly:

> This field defines the role the system played in the authentication
> flow, such as identity provider or relying party, and should reflect
> event-specific context.

| Value | Use when |
| --- | --- |
| `"IDP"` | This system VALIDATES the credential -- an IdP (Okta, Entra, Duo), a domain controller, an IdP-backed access gateway. |
| `"SP"` | This system INITIATES the request and relies on another to validate -- a relying-party application consuming SSO. |
| `"Universal"` | The source is NOT a known IdP provider: local accounts, TACACS+, RADIUS, SSH onto a device, network-equipment AAA. |

The role is decided PER EVENT TYPE, not per data source. The published
page says so explicitly: "The same system could be an IDP in one event
and an SP in another." A single rule may emit all three across its
branches.

### Decision procedure

The subject of the role is the LEG OF THE FLOW THE EVENT TYPE NAMES, not
the system that emitted the log. This distinction is load-bearing and is
easy to get backwards: on an Okta feed Okta emits every record and Okta
validates every credential, yet upstream maps
`eventType = "user.authentication.sso"` to `"SP"`, not `"IDP"`
(`OktaModelingRules_2_0.xif:97`). The SSO record documents the
relying-party leg; the credential-validation records on the same feed
are `"IDP"`. One feed, both values, decided per event type.

1. Read the EVENT TYPE, not the data source. What leg of the flow does
   this particular record document?
2. Does the record carry the outcome of a credential check? Candidate
   `"IDP"`.
3. Does it document the relying-party leg -- an assertion issued to or
   consumed by a service, an SSO hand-off? Candidate `"SP"`.
4. Is a KNOWN IdP provider involved at all (SAML / OIDC / OAuth
   federation, an IdP-backed access gateway)? If NO -- local accounts,
   TACACS+, RADIUS, device SSH -- the answer is `"Universal"` regardless
   of steps 2 and 3.
5. Repeat per event type. A rule that classifies records into
   authentication and non-authentication kinds sets the role ONLY on the
   authentication branch: a command-accounting or authorisation record
   typed as a process event carries no role at all.

### On `"Universal"`

`"Universal"` is GoCortexIO house law and is deliberately NOT sourced
here. The published page lists only `"SP"` and `"IDP"`. DO NOT REMOVE
`"Universal"` ON THE STRENGTH OF THAT PAGE LISTING TWO VALUES -- the
page has been checked (three independent fetches), the omission is
known, and the value is required. It is registered in
[house-conventions.md](house-conventions.md).

This warning exists because the inverse mistake has already been made.
Between 2026-07-08 and 1.9.0 this file asserted that `"SP"` / `"IDP"`
were a "retired misconception" with "no such XDM values", reasoning from
the schema's plain `String` type to the absence of a vocabulary. A
String-typed field can still carry a documented closed vocabulary. The
claim was wrong, it was recorded as schema fact, and every rule authored
against it carries a service name in a role field.

### Where the displaced detail goes

The old normalisation table below is retained, repointed: these are the
values that used to be forced into `xdm.auth.service`, and where each
one actually belongs. The governing distinction is WIRE versus
MECHANISM -- if the value names the layer-7 protocol carrying the
session it is `application_protocol`; if it names how the credential was
checked it is `auth_method`. They coincide only when the AAA protocol IS
the session, and then set both.

| Vendor value contains | Correct XDM field | Value |
| --- | --- | --- |
| `ssh` | `xdm.network.application_protocol` | `"ssh"` |
| `telnet` | `xdm.network.application_protocol` | `"telnet"` |
| `snmp` | `xdm.network.application_protocol` | `"snmp"` / `"snmpv3"` |
| `kerberos` / `krb` | `xdm.logon.package_name` (authentication-package field) else `xdm.auth.auth_method` | `"Kerberos"` |
| `ntlm` | `xdm.logon.package_name` else `xdm.auth.auth_method` | `"NTLM"` |
| `oauth` / `saml` / `wsfed` | `xdm.network.application_protocol` | `"oauth2"` / `"saml"` |
| `radius` | `xdm.auth.auth_method` (+ `application_protocol` on an AAA-server record) | `"RADIUS"` |
| `tacacs` | `xdm.auth.auth_method` (+ `application_protocol` on an AAA-server record) | `"TACACS+"` |
| `ldap` | `xdm.auth.auth_method` (+ `application_protocol` on the bind itself) | `"LDAP"` |
| `sso` | `xdm.event.operation_sub_type` | `"Generic SSO"` (closed-list member) |
| CLI / GUI / Dashboard / API / Console | `xdm.target.application.name` | the named interface |
| an IdP connection name | `xdm.auth.auth_method` | the connection name |
| no service field in the log | nothing | the role is always derivable; there is nothing to pad |

Note `xdm.event.operation_sub_type` is BARRED from taking CLI / GUI /
Dashboard / API. Its vocabulary on an authentication event is the closed
list `hardware_token`, `password`, `application`, `email`, `sms`,
`voice`, `trusted_login`, `"Generic SSO"`, `null`; writing an access
channel there corrupts the story's own `auth_method` field.

Representative idiom -- role on `xdm.auth.service`, mechanism and wire
split out. This is the shape upstream `IBMSecurityVerify` uses:

```
    xdm.auth.service = if(
        tmp_is_aaa != null, "Universal",
        tmp_is_local != null, "Universal",
        "Universal"),
    xdm.auth.auth_method = if(
        tmp_svc = null, null,
        lowercase(tmp_svc) contains "tacacs", "TACACS+",
        lowercase(tmp_svc) contains "radius", "RADIUS",
        lowercase(tmp_svc) contains "ldap", "LDAP",
        tmp_svc),
    xdm.network.application_protocol = if(
        tmp_is_ssh != null, "ssh",
        tmp_is_telnet != null, "telnet",
        tmp_is_snmp != null, "snmp"),
```

And for a federated source, where the role genuinely varies by event:

```
    xdm.auth.service = if(
        tmp_event contains "sso", "SP",
        tmp_event != null, "IDP"),
    xdm.auth.auth_method = tmp_connection,
    xdm.event.operation_sub_type = if(
        lowercase(tmp_factor) contains "push", "application",
        lowercase(tmp_factor) contains "sms", "sms",
        tmp_is_federated != null, "Generic SSO"),
```

## Deriving xdm.target.resource.name

An authentication event has a direction: a principal authenticates FROM
somewhere TO something. `xdm.source.user.upn` is the mandatory record of
who; `xdm.target.resource.name` is the mandatory record of what they
authenticated to. Without it the direction is unstated, and an inverted
rule looks identical to a correct one.

That is not hypothetical. A shipped rule once mapped a router to
`xdm.source.host.hostname` on 764 SSH login records. On a login the
router is what is being logged INTO and the source is the
administrator's workstation, so every record was inverted. All fourteen
mandatory fields were assigned, the linter was silent, and the fault
surfaced only when someone counted the population of
`xdm.target.ipv4` and found it empty on every row. Naming the target
entity explicitly is the step at which that mistake becomes visible.

Derivation precedence -- take the first that the log actually carries:

| Precedence | Source | Example |
| --- | --- | --- |
| 1 | An explicit target / resource / application field | Okta `$.target[0].displayName`, Entra `$.appDisplayName` |
| 2 | The requested service principal | Kerberos `ServiceName` on a 4768 / 4769 |
| 3 | The accessed device's NAME | a TACACS+ `dvc_name=`, a syslog device label |
| 4 | The accessed device's ADDRESS | a TACACS+ `dvc_ip=`, an `at <ip>` clause |
| 5 | The portal or service the vendor names | a FortiGate `SSL-VPN` portal, an `AWS Console` sign-in |

Two rules govern the assignment.

Set it IN ADDITION to the type-correct target field, never instead of
it. A named host still takes `xdm.target.host.hostname`, an application
still takes `xdm.target.application.name`, an address still takes
`xdm.target.ipv4`. Dual-mapping costs nothing, preserves asset
correlation, and makes `xdm.target.resource.name` the one field that is
reliably populated across every authentication source regardless of what
shape the target happens to take.

NEVER pad it. The general padding rule in this file applies with unusual
force here: pad only where the placeholder is semantically EMPTY. An
empty string in `xdm.target.ipv4` honestly says "this IdP record has no
target address". An empty string in `xdm.target.resource.name` says "the
target of this authentication is known and it is nothing", which is
never true. On a record that genuinely has no target -- a Kerberos
AS-REQ with no service principal, a pre-authentication failure -- let an
`if()` resolve it to null. A null is visible in a population count; a
pad is not.

## Worked shape (JSON source)

A complete MODEL rule that maps all 15 mandatory fields. The extraction
stage changes per format; the assignment stage does not.

```
[MODEL: dataset=vendor_idp_raw]
filter
    _raw_log != null
| alter
    tmp_event = json_extract_scalar(_raw_log, "$.eventType"),
    tmp_upn = json_extract_scalar(_raw_log, "$.actor.alternateId"),
    tmp_src_ip = json_extract_scalar(_raw_log, "$.client.ipAddress"),
    tmp_src_port = json_extract_scalar(_raw_log, "$.client.port"),
    tmp_result = json_extract_scalar(_raw_log, "$.outcome.result"),
    tmp_factor = json_extract_scalar(_raw_log, "$.authenticationContext.method"),
    tmp_svc = json_extract_scalar(_raw_log, "$.authenticationContext.authenticationProvider"),
    tmp_app = json_extract_scalar(_raw_log, "$.target[0].displayName")
| alter
    xdm.event.type = if(tmp_event != null, "authentication", ""),
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION),
    xdm.event.original_event_type = tmp_event,
    xdm.event.operation = if(
        tmp_factor != null, XDM_CONST.OPERATION_TYPE_AUTH_MFA,
        tmp_event != null, XDM_CONST.OPERATION_TYPE_AUTH_LOGIN),
    xdm.event.outcome = if(
        tmp_result ~= "[Ss]uccess", XDM_CONST.OUTCOME_SUCCESS,
        tmp_result != null, XDM_CONST.OUTCOME_FAILED),
    xdm.auth.service = if(
        lowercase(tmp_event) contains "sso", "SP",
        tmp_event != null, "IDP"),
    xdm.auth.auth_method = if(
        tmp_svc = null, null,
        lowercase(tmp_svc) contains "kerberos", "Kerberos",
        lowercase(tmp_svc) contains "ntlm", "NTLM",
        lowercase(tmp_svc) contains "ldap", "LDAP",
        tmp_svc),
    xdm.network.application_protocol = if(
        lowercase(tmp_svc) contains "oauth", "oauth2",
        lowercase(tmp_svc) contains "saml", "saml"),
    xdm.source.user.upn = tmp_upn,
    xdm.source.user.identity_type = if(
        tmp_upn != null, XDM_CONST.IDENTITY_TYPE_USER,
        XDM_CONST.IDENTITY_TYPE_UNKNOWN),
    xdm.source.user.user_type = if(
        tmp_upn = null, XDM_CONST.USER_TYPE_REGULAR,
        tmp_upn contains "$", XDM_CONST.USER_TYPE_MACHINE_ACCOUNT,
        lowercase(tmp_upn) ~= "^svc[-_.]|service|gserviceaccount",
            XDM_CONST.USER_TYPE_SERVICE_ACCOUNT,
        XDM_CONST.USER_TYPE_REGULAR),
    xdm.source.ipv4 = tmp_src_ip,
    xdm.source.port = to_integer(to_number(tmp_src_port)),
    xdm.target.ipv4 = "",
    xdm.target.port = to_integer(0),
    xdm.target.resource.name = tmp_app,
    xdm.network.ip_protocol = XDM_CONST.IP_PROTOCOL_TCP
;
```

Note the asymmetry in the target block, which is deliberate.
`xdm.target.ipv4` is padded `""` because an IdP record genuinely has no
target address and the placeholder is semantically empty.
`xdm.target.resource.name` is NOT padded: it carries the identity of the
thing being logged into, so a placeholder there would assert that the
event has a known target when it does not.

## Optional fields (map when the source provides them)

These enrich the story but are not required for it to be created. Map
them when present; omit them otherwise.

| XDM target | Notes |
| --- | --- |
| `xdm.event.outcome_reason` | Normalise provider error strings into one supported reason value (`user_does_not_exist`, `bad_credentials`, `account_locked`, `mfa_failure`, and similar). |
| `xdm.event.description` | Deterministic `concat()` summary; see [transformation-patterns.md](transformation-patterns.md). |
| `xdm.event.operation_sub_type` | The auth method, from a CLOSED list: `hardware_token`, `password`, `application`, `email`, `sms`, `voice`, `trusted_login`, `"Generic SSO"`, `null`. Distinct from the mandatory `xdm.event.operation`. An access CHANNEL (`CLI`, `GUI`, `Dashboard`, `API`) is NOT a member and must not be written here -- it belongs in `xdm.target.application.name`. |
| `xdm.source.user.identifier` | Persistent canonical id (GUID / SID). |
| `xdm.source.user.username` | Human-readable display name. NOT the identity key. |
| `xdm.source.user_agent` | Full user-agent string of the client. |
| `xdm.auth.privilege_level` | `XDM_CONST.PRIVILEGE_LEVEL_GUEST` / `PRIVILEGE_LEVEL_USER` / `PRIVILEGE_LEVEL_ADMIN` / `PRIVILEGE_LEVEL_SYSTEM`. |
| `xdm.logon.type` | `XDM_CONST.LOGON_TYPE_INTERACTIVE` / `LOGON_TYPE_SERVICE`. |
| `xdm.source.host.device_id` | Stable per-device id; fall back to source IP when absent. |
| `xdm.source.host.hostname` | Device name. |
| `xdm.source.host.device_category` | Client class (`Computer`, `Mobile`, `Tablet`, `IOT`). |
| `xdm.source.host.os_family` | `XDM_CONST.OS_FAMILY_WINDOWS` / `OS_FAMILY_MACOS` / `OS_FAMILY_LINUX`. For a mobile OS with no listed constant, omit the constant and keep the raw string in `xdm.source.host.os`. |
| `xdm.source.host.os` | Raw OS string. |
| `xdm.source.application.name` | Browser vendor. |
| `xdm.source.application.version` | Browser version. |
| `xdm.target.resource.id` | Accessed resource / app id. The companion `xdm.target.resource.name` is MANDATORY and is in the table above. |
| `xdm.source.location.city` | Geo of the source. The companion geo leaves are `xdm.source.location.country`, `xdm.source.location.region`, `xdm.source.location.continent`, `xdm.source.location.timezone`, `xdm.source.location.latitude`, `xdm.source.location.longitude`. |
| `xdm.network.session_id` | Aggregates multiple actions across a session window. |
| `xdm.session_context_id` | Correlates the events of a single auth request / transaction (narrower than `xdm.network.session_id`). |

## AAA gateways (TACACS+, RADIUS, Cisco ISE)

Network-device AAA logs are authentication events with their own
topology and vocabulary. The full worked treatment (nine event shapes
from one daemon family, including legacy freeform lines) is
[worked-examples/08-cisco-tacacs-aaa-multi-shape.md](worked-examples/08-cisco-tacacs-aaa-multi-shape.md).

Topology -- three parties, not two:

| Party | Raw evidence | XDM home |
| --- | --- | --- |
| Principal (the human or service account) | `user=` | `xdm.source.user.upn` (and `.username`) |
| Principal's workstation | `src_ip=` | `xdm.source.ipv4` |
| Network device being accessed | `dvc_ip=` / `at <ip>` | `xdm.target.ipv4` AND `xdm.target.resource.name` (the device name when the log carries one, otherwise its address) |
| AAA server (validates) | syslog envelope host | `xdm.observer.name` (Stage 0); `xdm.auth.service` = `"Universal"` (AAA is not a known IdP provider); the AAA protocol goes to `xdm.auth.auth_method` (`"TACACS+"` / `"RADIUS"`), and to `xdm.network.application_protocol` as well when the record IS the AAA transaction |

Rules specific to this family:

- Non-UPN identities: AAA principals (`svc_nms1`, `alice.admin`) are
  rarely `user@domain`, but `xdm.source.user.upn` is the mandatory
  correlation key, cannot be empty, and must ALWAYS be UPN-shaped --
  synthesise the shape with
  `if(tmp_user contains "@", tmp_user, tmp_user != null, concat(tmp_user, "@localhost"))`
  and carry the raw principal in `xdm.source.user.username`.
- PERMIT / DENY is the AUTHENTICATION outcome, not a network action.
  Do not tag `XDM_CONST.EVENT_TAG_NETWORK` unless the record carries a
  real transport flow (protocol, ports, byte counts); the profiler
  applies the same rule automatically.
- Accounting Start / Stop is session lifecycle, not success or failure:
  leave `xdm.event.outcome` unset there (the outcome if-chain
  deliberately has no default, so it stays null on lifecycle rows), use
  `XDM_CONST.OPERATION_TYPE_AUDIT` for the operation, and map
  `task_id` -> `xdm.network.session_id` and `elapsed_time` ->
  `xdm.event.duration`. `elapsed_time` is SECONDS and
  `xdm.event.duration` is MILLISECONDS, so multiply by 1000 in function
  form: `to_integer(multiply(to_number(tmp_elapsed), 1000))` (never infix
  `* 1000`). On the authentication shapes, the operation is
  `OPERATION_TYPE_AUTH_LOGIN` and the auth method is `"password"`.
- Command accounting is a COMMAND EXECUTION, not an authentication
  event. An accounting record carrying a command (`cmd=`, `CmdSet`) is
  its own event: set `xdm.event.type` to a process value (for example
  `"process"` -- it must NOT contain "authentication"), map the executed
  command to `xdm.target.process.command_line`, keep operation
  `XDM_CONST.OPERATION_TYPE_AUDIT` with no outcome, put the operator on
  `xdm.source.user.*` and the administered device on `xdm.target.*`, and
  do NOT tag it `EVENT_TAG_AUTHENTICATION`. Only the AUTHEN (login) and
  AUTHOR (authorization) shapes are authentication; see
  [process-mapping.md](process-mapping.md). This is the one AAA record
  kind that leaves the authentication story.
- `xdm.event.outcome_reason`: normalise the known vendor reasons
  (`Bad Password` -> `bad_credentials`, `No such user` ->
  `user_does_not_exist`) and pass unknown reasons through unchanged --
  never force them to a placeholder.
- The vendor `port=` is a TTY / line name (`vty0`, `/dev/pts/7`,
  `rest_http`), never a TCP port: the mandatory integer ports take
  `to_integer(0)` and the line name is documented NOT MAPPED.
- `priv_lvl` -> `xdm.auth.privilege_level`. Band it from the levels the
  TACACS+ protocol defines (RFC 8907 section 9): `0` is
  `TAC_PLUS_PRIV_LVL_MIN`, an UNAUTHENTICATED session, so it bands to
  `XDM_CONST.PRIVILEGE_LEVEL_GUEST`, not to a user level; `1` is
  `TAC_PLUS_PRIV_LVL_USER`, a regular authenticated session; `15`
  (`0x0f`) is `TAC_PLUS_PRIV_LVL_ROOT`, a highly privileged user. The
  levels are ordered and each is a superset of those below it, so band
  rather than enumerate:

  ```
  xdm.auth.privilege_level = if(
      tmp_priv_num >= 15, XDM_CONST.PRIVILEGE_LEVEL_ADMIN,
      tmp_priv_num >= 1, XDM_CONST.PRIVILEGE_LEVEL_USER,
      tmp_priv_num != null, XDM_CONST.PRIVILEGE_LEVEL_GUEST)
  ```

  Capture every spelling in one alternation
  (`priv(?:_lvl|-lvl|ilege)=`) -- one dataset can carry `priv_lvl`,
  `priv-lvl` and `privilege` at once. `group` ->
  `xdm.source.user.groups` via `arraycreate()`.
- Filter diagnostic chatter FIRST (parser hooks, key errors, internal
  bookkeeping lines): keep the event shapes in with an explicit filter
  rather than letting non-events produce near-empty XDM rows.
- Freeform legacy lines: capture addresses with `[\d.]+` only, so a
  placeholder token such as `from async` can never land in an IPv4
  field, and bound the username capture (up to ` from `) so principals
  with embedded spaces survive.

## A logout takes an outcome but no operation

The `OPERATION_TYPE` enum has `AUTH_LOGIN` and no logout member. A
logout is not an unclear event -- it is conclusive -- so the general
"leave the verb unset when the event kind is unclear" guidance does not
quite cover it, and the decision should not be re-made per rule.

The convention: a logout takes `xdm.event.outcome = OUTCOME_SUCCESS`
(the logout succeeded) and NO `xdm.event.operation`. The event identity
lives in `xdm.event.original_event_type`.

Asserting `AUTH_LOGIN` on a logout inflates every login count that
filters on the verb, which is a silent error in exactly the metric an
authentication story exists to produce.

## One login, two records

Some products log a single authentication twice, from two layers, under
two different event codes -- for example an operating-system record and
an application record for the same SSH login. Both are genuine, and both
should be modelled.

The consequence is for anything COUNTING logins: the count doubles
unless it deduplicates. When a source is known to double-log, say so in the MAPPED
header NOTES so a reviewer building a login metric knows to dedupe on
the session or the timestamp-plus-account pair rather than counting
rows.

## Device-local authentication (the device logs a login to ITSELF)

The AAA-gateway topology above has three parties: an operator, an AAA
server that observes, and an administered device. A device authenticating
a user INTO ITSELF has only two, and the entity assignment is different
enough that getting it wrong inverts every record. A router mapped to
`xdm.source.host.hostname` becomes the source of a login into itself,
across the whole feed, with the linter clean because every mandatory
field was assigned.

```
<190>Jul 29 02:02:26 172.25.173.229 ... ssh_syslog_proxy[1194]: %SECURITY-SSHD_SYSLOG_PRX-6-INFO_GENERAL : sshd[10419]: Accepted authentication for user6759abe9 from 10.119.97.109 port 24097 ssh2
```

State the rule plainly and apply it before mapping any entity:

- The device that WROTE the log is `xdm.observer.*` (`observer.name`,
  `observer.vendor`, `observer.product`). This is always true.
- If the authentication was INTO that device, the device is ALSO the
  target: `xdm.target.host.hostname` and `xdm.target.ipv4`. An observer
  and a target can be the same box; that is normal, not a duplication
  error.
- The remote end is the source: `xdm.source.ipv4` (`from 10.119.97.109`),
  `xdm.source.port`, and the authenticated principal on
  `xdm.source.user.*`.
- The device is `xdm.source.*` only when IT initiated the
  authentication -- a device logging in to a RADIUS server, a switch
  authenticating upstream.

The quick test: ask which end would appear in a "who logged in to what"
question. The answer names the target. If the device that emitted the
log is the thing being logged into, it cannot also be the source.

Because a device-local login usually carries the device address in the
syslog header rather than a named field, this is exactly the shape where
padding `xdm.target.ipv4` hides the defect -- see "The entity-field
gate" above.

## AAA and network-device field crosswalk

The vendor field names an AAA or device source actually emits, in one
place. The derivation notes above give the detail; this table is for
finding the target quickly.

| Vendor field | XDM target |
| --- | --- |
| `user=`, `username`, `User` | `xdm.source.user.username` + `xdm.source.user.upn` (UPN-shaped) |
| `priv_lvl`, `priv-lvl`, `privilege` | `xdm.auth.privilege_level` (band to `PRIVILEGE_LEVEL_ADMIN` / `_USER`) |
| `dvc_ip`, `nas-ip`, `nas-ip-address` | `xdm.target.ipv4` |
| `src_ip`, `rem_addr`, `from <addr>` | `xdm.source.ipv4` |
| `cmd=` plus repeated `cmd-arg=` | `xdm.target.process.command_line` (join, see Recipe 12) |
| `service=` | `xdm.auth.auth_method` (NOT `xdm.auth.service`, which carries the role) |
| `task_id`, `session-id`, `AcsSessionID` | `xdm.network.session_id` |
| `group`, `rule` | `xdm.source.user.groups` via `arraycreate()` |
| `port=` (a TTY / line name) | NOT MAPPED -- not a TCP port; see the note above |

All spellings of one field must be captured in a single alternation --
one dataset can carry `priv_lvl`, `priv-lvl` and `privilege` at once. See
[extraction-recipes.md](extraction-recipes.md) "Spelling variants of one
field".

Constants used above live in [xdm-const.md](xdm-const.md); every target
path is defined in [xdm-schema.md](xdm-schema.md).

## Windows logon and Kerberos (4624 / 4625 / 4768 / 4769)

Windows Security logon events are the authentication story: 4624 (success),
4625 (failure), 4634 / 4647 (logoff), and the Kerberos 4768 (TGT request) /
4769 (service ticket) / 4771 (pre-auth failed). Classify per `event_id` within
the `Security` channel, apply the full 15-field mandatory set, and tag
`EVENT_TAG_AUTHENTICATION`. The account that logged on (`TargetUserName` /
`TargetDomainName`) is the source user; `IpAddress` / `IpPort` is the source
endpoint; the DC / target host has no transport endpoint in the record, so the
target tuple takes the auth-story pads. See
[worked-examples/12-windows-logon-kerberos.md](worked-examples/12-windows-logon-kerberos.md).

Logon type. Map the Windows `LogonType` integer to `xdm.logon.type` over the
COMPLETE `LOGON_TYPE` closed list (see [xdm-const.md](xdm-const.md)):

| LogonType | `xdm.logon.type` |
| --- | --- |
| 2 | `LOGON_TYPE_INTERACTIVE` |
| 3 | `LOGON_TYPE_NETWORK` |
| 4 | `LOGON_TYPE_BATCH` |
| 5 | `LOGON_TYPE_SERVICE` |
| 6 | `LOGON_TYPE_PROXY` |
| 7 | `LOGON_TYPE_UNLOCK` |
| 8 | `LOGON_TYPE_NETWORK_CLEARTEXT` |
| 9 | `LOGON_TYPE_NEW_CREDENTIALS` |
| 10 | `LOGON_TYPE_REMOTE_INTERACTIVE` |
| 11 | `LOGON_TYPE_CACHED_INTERACTIVE` |
| 12 | `LOGON_TYPE_CACHED_REMOTE_INTERACTIVE` |
| 13 | `LOGON_TYPE_CACHED_UNLOCK` |

Companion logon fields (map when present): `xdm.logon.package_name` =
`AuthenticationPackageName` (this is where `Kerberos` / `NTLM` /
`Negotiate` belong -- the field's description is literally "The
authentication package used", and upstream
`MicrosoftWindowsEvents_1_3.xif:165` already fills it from exactly this
column); `xdm.auth.auth_method` = `LogonProcessName`;
`xdm.logon.is_elevated` from `ElevatedToken` (`%%1842` -> true, `%%1843`
-> false). `xdm.auth.service` on a domain controller is `"IDP"` -- the DC
validates the credential -- and is never the package name.

Kerberos tickets (4768 / 4769). The ticket encryption type and the failure /
error code map to `xdm.auth.kerberos_tgt.*` (4768) or
`xdm.auth.kerberos_tgs.*` (4769). Both are const-typed over large enums whose
COMPLETE code -> constant crosswalk ships as
[../assets/kerberos_crosswalk.json](../assets/kerberos_crosswalk.json); render
the full if-chain with `python3 scripts/kerberos_map.py --render --group
encryption_type` (and `--group error_code`). Windows logs `TicketEncryptionType`
and `Status` as HEX (`0x12`, `0x18`) and `to_number` does not parse hex, so
either match the hex string directly (for the common values) or strip `0x` and
convert before mapping the decimal chain. Derive `xdm.event.outcome` from the
Kerberos `Status` (`0x0` -> SUCCESS, else FAILED) -- a 4771 or a non-zero 4768
Status is a failed pre-authentication.

## Cisco IOS-XE and WLC: the authentication message families

Anchor on the token (extraction-recipes Recipe 15), then map by family.
These are the vendor's documented mnemonics, so they are a closed set per
release and safe to enumerate -- unlike message prose.

### Administrative login (IOS-XE), the management-plane story

```
SEC_LOGIN-5-LOGIN_SUCCESS       Login Success [user: U] [Source: S] [localport: N] at TIME
SEC_LOGIN-4-LOGIN_FAILED        Login failed [user: U] [Source: S] [localport: N] [Reason: R] at TIME
SEC_LOGIN-5-WEBLOGIN_SUCCESS    Login Success [user: U] [Source: S] at TIME
SEC_LOGIN-4-WEBUI_LOGIN_FAILED  Login failed [user: U] [Source: S] [Reason: R] at TIME
```

| XDM target | From |
| --- | --- |
| `xdm.source.user.username` | the `[user: ...]` value |
| `xdm.source.ipv4` | the `[Source: ...]` value, when it is an address |
| `xdm.target.port` | the `[localport: ...]` value |
| `xdm.event.outcome` | the mnemonic, never the prose |
| `xdm.auth.auth_method` | absent from the record; derive from the port or leave null |

The WEB variants carry no `localport`, which is the discriminator
between a CLI session and a web-UI session -- record it in
`xdm.event.type` rather than inventing an auth method.

The device is authenticating its own operator, so the device-local
topology applies: the device is the TARGET, the operator's address is the
SOURCE, and there is no third party.

Two records are the brute-force signal and must not be dropped as noise:

```
LOGIN-3-TOOMANY_AUTHFAILS  Too many Login Authentication failures ... on the line N
SEC_LOGIN-1-QUIET_MODE_ON  ... [user: U] [Source: S] [localport: N] [Reason: R] [ACL: A] at TIME
```

QUIET_MODE_ON is the lockout that follows repeated failure, and it names
the ACL that admitted the attempt. Severity 1 -- the most serious
authentication record the platform emits.

### Privilege escalation (IOS-XE)

```
SYS-5-PRIV_AUTH_PASS  Privilege level set to N by U on LINE
SYS-5-PRIV_AUTH_FAIL  Authentication to Privilage level N failed by U on LINE
SYS-5-PRIV_I          Privilege level set to N by U on LINE
```

This is authentication to a higher privilege, not a login. Map it with
`OPERATION_TYPE_ELEVATE_PRIVILEGE` where the record succeeded, keep the
level as a queryable value, and tag it AUTHENTICATION -- a privilege
change is exactly what a reviewer needs to correlate against the login
that preceded it. `Privilage` is the vendor's spelling in the FAIL
mnemonic; match it as written.

### Port-based network access (IOS-XE)

Three facilities share one template pair, so the FACILITY is the method
and the MNEMONIC is the outcome:

```
DOT1X-5-SUCCESS / DOT1X-5-FAIL      Authentication {successful|failed} for client C on Interface I
MAB-5-SUCCESS   / MAB-5-FAIL        Authentication {successful|failed} for client C on Interface I
AUTHMGR-5-SUCCESS / AUTHMGR-5-FAIL  Authorization {succeeded|failed or unapplied} for client [enet] on Interface I
```

DOT1X and MAB report AUTHENTICATION. AUTHMGR reports AUTHORIZATION of the
same session. Mapping all three to one outcome conflates two decisions
that can disagree -- a client can authenticate and then fail
authorization, and that pair is the interesting case.

`xdm.auth.auth_method` is the facility: 802.1X for DOT1X, MAC
authentication bypass for MAB.

The client is identified by MAC, not by name. The station MAC IS the
identity on these records: map it to `xdm.source.host.mac_addresses` and
leave `username` null rather than padding it.

`AuditSessionID`, present on AUTHMGR, DOT1X_SWITCH and EPM records, is
the only key that ties a session start, its policy application and its
stop together. Map it; without it the three records cannot be correlated.

Security-significant despite their modest severity:

```
AUTHMGR-5-SECURITY_VIOLATION  Security violation on the interface I new MAC address [enet] is seen.
AUTHMGR-4-UNAUTH_MOVE         MAC address [enet] from I to I
AUTHMGR-5-MACMOVE             MAC address [enet] moved from Interface I to Interface I
AUTHMGR-5-MACREPLACE          MAC address [enet] on Interface I is replaced by MAC [enet]
```

MACREPLACE carries TWO MAC addresses and they are not interchangeable --
the second replaces the first.

### WLC 8.0: admin and network users are separate populations

The controller states the population in the mnemonic, which is the
cleanest identity-class signal in any source covered here:

```
AAA-5-AAA_AUTH_ADMIN_USER    Authentication OUTCOME for admin user 'U'
AAA-5-AAA_AUTH_NETWORK_USER  Authentication OUTCOME for network user 'U'
```

ADMIN is a management-plane operator; NETWORK is a wireless client. They
take different `xdm.source.user.user_type` values and must not be merged
-- an estate cannot tell an operator login from a client association if
the rule collapses them.

Both templates put the OUTCOME in the middle of the prose, between two
fixed words, and the username SECOND on the same line:

```
// WRONG -- "the first variable" is the OUTCOME, not the account
tmp_user = arrayindex(regextract(_raw_log, "Authentication (\S+)"), 0)

// RIGHT -- each value bounded by the literals that surround it
tmp_outcome = arrayindex(regextract(_raw_log, "Authentication (\S+) for (?:admin|network) user"), 0),
tmp_user    = arrayindex(regextract(_raw_log, "for (?:admin|network) user .([^']+)."), 0)
```

The richest WLC record carries a server, a station and an account at once:

```
AAA-4-RADIUS_RESPONSE_FAILED  RADIUS server IP:PORT failed to respond to request(ID N) for STA MAC / user 'U'
```

Here the RADIUS server is the TARGET (the controller was asking it), the
station is the subject, and the failure is the SERVER's, not the user's
-- do not map it as a credential rejection. It is an authentication
service outage, and `xdm.event.outcome` should reflect that the attempt
could not be decided rather than that it was denied.

### SSHPM is not SSH login

`SSHPM` is the WLC's SSH Policy Manager -- IPsec policy, certificates,
credential stores, L2TP, application gateways. It is 237 of the 302
messages in its chapter and NOT ONE is a user login. A rule that maps it
to the authentication story on the strength of the name is wrong on every
record.

This is the facility-name version of the keyword false friend in
[record-classification.md](record-classification.md): the name of the
producing subsystem is no more a classifier than the message prose is.
Genuine SSH login on a controller arrives through AAA.

### WLC wireless client sessions: three facilities, one session

APF, MM and PEM are three coupled state machines over ONE client session,
not three subsystems that happen to mention clients. The controller says
so itself: `PEM-3-BADWLANID2` prints the PEM state, the APF state and the
MM state for a single mobile in one record.

- APF is the 802.11 and policy layer (association, WLAN/SSID, exclusion).
- PEM is policy enforcement (web authentication, RADIUS policy, the
  session in/out record).
- MM is mobility (roaming and anchoring between controllers).

There is no `AuditSessionID` here. The STATION MAC is the correlation key
across all three, and it is the only thing that joins them, so it must be
mapped on every record that carries it -- including records where it is
the ONLY identity.

The lifecycle, which spans five facilities:

| Stage | Record |
| --- | --- |
| 802.11 auth fails at the radio | `APF-1-AUTH_FAILED` (carries the 802.11 status code) |
| association rejected | `APF-4-ASSOCREQ_PROC_FAILED` (WLAN id and SSID) |
| 802.1X / EAP | `DOT1X-*` |
| RADIUS exchange | `AAA-*` |
| web authentication fails | `PEM-1-WEBAUTHFAIL` |
| rejected on Service-Type | `PEM-1-SERVTYPE` (names the user) |
| already logged on | `PEM-1-SETNAME` |
| SESSION IN | `PEM-6-GUESTIN` |
| IP assigned | `APF-6-GUEST_ASSIGNED_IP` |
| roam / anchor | `MM-*` |
| SESSION OUT | `PEM-6-GUESTOUT` |

Only three records bind an ACCOUNT to a MAC and an ADDRESS. Everything
else on the client path is MAC-only, so these are what make a wireless
session attributable to a person:

```
PEM-6-GUESTIN            Guest user logged in with user account (U) MAC address MAC, IP address IP
PEM-6-GUESTOUT           Guest user logged out with user account (U) MAC address MAC, IP address IP
APF-6-GUEST_ASSIGNED_IP  Guest User (U) with MAC Address (MAC) assigned IP Address (IP)
```

GUESTIN and GUESTOUT are the only matched login/logout pair on the
controller, so they are the only pair that yields a session duration. Map
GUESTOUT with `OUTCOME_SUCCESS` and no operation, per the logout
convention above.

Two cautions on the pair. The capitalisation differs between the
facilities (`Guest user` in PEM, `Guest User` in APF), so a
case-sensitive literal will match one and miss the other -- and XQL folds
case anyway, so anchor on structure. And the delimiters differ: PEM
writes the MAC bare while APF brackets all three values. They describe
the same binding in the same product and cannot share a capture.

`MM-1-EXPORT_FOREIGN_DOWN` states it is cleaning up client entries, so
one record ends many sessions with no per-client GUESTOUT. Any
session-duration analysis that assumes a matched pair must account for
it, or it will report every session on a failed controller as open
forever.

### WLC records that are a security finding, not an error

```
MM-1-CLIENT_SHUNNED                    Adding client MAC to exclusion list as a result of an IDS shun event for IP
APF-3-APF_WIRED_GUEST_EXCLUDED_CLIENT  Received a packet from excluded wired guest client MAC.
PEM-1-SETNAME                          Unable to allow user U into the system - perhaps the user is already logged onto the system?
APF-1-CHANGE_ORPHAN_PKT_IP             Changing orphan packet IP address for station MAC from IP ---> IP
MM-6-MEMBER_ADDED                      Adding Mobility member (Index:N, MAC:MAC, IP: IP) in CONTEXT.
```

`CLIENT_SHUNNED` is an IDS-driven enforcement -- a sensor decided and the
controller acted -- carrying the MAC, the triggering address and the
cause in one line.

`APF_WIRED_GUEST_EXCLUDED_CLIENT` is an excluded client STILL SENDING.
The exclusion being tested is worth more than the exclusion itself.

`SETNAME` is a concurrent-session rejection: read it as possible
credential sharing rather than as a failure.

`CHANGE_ORPHAN_PKT_IP` carries the old AND the new address. Map both --
the pair is the finding, and mapping only the new one discards it.

`MEMBER_ADDED` extends the trust boundary: a mobility member is a peer
controller trusted to receive client state including PMK cache material.
It is a configuration change with security weight, not infrastructure
chatter.
