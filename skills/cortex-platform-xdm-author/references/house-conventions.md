<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# House conventions

A register of the places where this bundle deliberately requires MORE
than the Cortex XDM schema does, or narrows a field the schema leaves
open. Everything here is a GoCortexIO decision, not a platform rule.

## Why this file exists

Most of what this bundle says about XDM is a report of what the platform
requires. A few things are not: they are choices we made because the
unmodified schema left something unstated that our correlation rules,
dashboards and analytics depend on. Both kinds of statement read the
same way once they are written down as "map this field like this", and
that is the problem this file solves.

The cost of not separating them is on record, and the example is
`xdm.auth.service`. This file used to tell that story the wrong way
round: it said an `"SP"` / `"IDP"` role reading had been a house
inference mistaken for schema fact. It was not. `"SP"` / `"IDP"` is
what the official page documents, and always was.

What actually happened is the sharper lesson. In 1.8.x a "correction"
was recorded declaring the role reading a myth -- "no such XDM values
exist" -- reasoning from the schema's plain `String` type to the absence
of a vocabulary. That inference does not hold: a String-typed field can
carry a documented closed vocabulary, and this one does. The claim was
written as schema fact, a linter check was built to enforce it, nine
shipped packs were authored against it, and the corpus-mining gates were
taught to discard the upstream evidence that would have refuted it. Each
of those steps was carried out carefully, in good faith, on a statement
nothing marked as a claim.

The direction of the error is not the point. The point is that an
unmarked inference reaches code, tests and shipped content faster than
anyone re-checks the source.

So an entry here states four things: what we require, what the schema
alone says, why we diverge, and what evidence would retire the entry. An
author who disagrees with a convention has what they need to argue with
it. An author who agrees has the reason, not just the instruction.

A convention is not weaker than a schema rule -- the linter enforces
these -- it is just accountable.

## Register

### The identity mirror beside user.* (append, never replace)

WHAT WE REQUIRE: a rule that maps `xdm.<side>.user.<X>` for X in
{upn, identity_type, user_type, username, identifier, domain} is
strongly encouraged to also assign `xdm.<side>.identity.<X>` from the
character-identical derivation, and `identity.*` is only ever written
BESIDE its user twin, never instead of it. The user assignment is never
removed, renamed or rewritten to make room for the mirror.

WHAT THE SCHEMA ALONE SAYS: `user.*` and `identity.*` are two
independent families documented side by side, with no stated
relationship, no cross-reference and no deprecation notice either way.

WHY WE DIVERGE: the families are field-for-field twins (measured
2026-08-25 against all six vendor pages), and the Identity data model
reads the `identity.*` surface. Mirroring costs one assignment per pair
from a temp the rule already derives, populates identity analytics,
and leaves every existing consumer of `user.*` -- the mandatory set,
correlation content, dashboards -- untouched. The tier is recommended
rather than mandatory because an absent mirror loses enrichment only,
while a wrong or diverged one corrupts two surfaces at once.

WHAT WOULD RETIRE THIS: a vendor deprecation notice on either family
(which turns the mirror into a migration, a separate and
separately-registered release), or tenant evidence that modeler writes
to `identity.*` are rejected at install or overwritten by
auto-enrichment. See the tenant-verification record in
[authentication-mapping.md](authentication-mapping.md).

### xdm.target.resource.name on authentication events

WHAT WE REQUIRE: on any record classified as an authentication event,
`xdm.target.resource.name` is MANDATORY and carries the device,
application or service the principal authenticated TO. It is set in
addition to the type-correct target field, never instead of it, and it
is never padded. Enforced by WARN-042 (presence) and WARN-055 (no
placeholder). See
[authentication-mapping.md](authentication-mapping.md).

WHAT THE SCHEMA SAYS: `xdm.target.resource.name` is an optional String
described only as "The resource name". No enum, no required flag, and
nothing restricting it to cloud resources.

WHY WE DIVERGE: an authentication event has a direction, and until this
field was mandatory nothing recorded it. A shipped rule mapped a router
to `xdm.source.host.hostname` across 764 SSH logins -- the router is
what is being logged INTO -- so every record was inverted with all
fourteen then-mandatory fields assigned and the linter silent. The fault
surfaced only when someone counted the population of `xdm.target.ipv4`.
Requiring the target to be named is the step at which that mistake
becomes visible, and requiring it to be DERIVED rather than padded is
what stops the check being satisfiable without answering the question.

A second effect: because the concept had no home, it had been leaking
into `xdm.auth.service`. Entra sign-ins put `appDisplayName` there,
CloudTrail put `"AWS Console"`, FortiGate put `"SSL-VPN"`. None of those
is a role, which is what that field carries. Giving the target its own
field removes the pressure that caused that drift.

Note that this SUPERSEDES the cloud-only reading of
`xdm.target.resource.*` in [pitfall-traps.md](pitfall-traps.md), which
still governs non-authentication events. That reading was itself a house
convention rather than schema truth; the anchor corpus disagrees with
it, carrying `devicename` and `applicationname` among the observed
synonyms for this field.

WHAT WOULD RETIRE IT: a platform change that gives the authentication
target its own dedicated XDM field, or evidence that populating
`xdm.target.resource.name` on non-cloud authentication events degrades
an analytics behaviour that depends on the cloud-only reading. Neither
is true as of this bundle version.

### "Universal" as a third value for xdm.auth.service

WHAT WE REQUIRE: on an authentication event whose source is NOT a known
IdP provider -- local device accounts, TACACS+, RADIUS, SSH onto a
network device, network-equipment AAA -- `xdm.auth.service` is
`"Universal"`. `"SP"` and `"IDP"` are reserved for flows where a known
IdP provider is genuinely involved. Enforced by WARN-042, which accepts
exactly these three literals.

WHAT THE SCHEMA SAYS: the schema types the field as a plain String, "The
authentication service name". The official page "XDM fields for mapping
authentication events" documents the field as a ROLE and lists exactly
two supported values, `"SP"` and `"IDP"`. It carries no third value, and
it gives no guidance at all for non-federated single-system login.

WHY WE DIVERGE: the two documented values describe a two-party flow --
the page's own gloss is "identity provider or relying party". A router
validating its own console credential has no counterparty: it is not
relying on anyone, and calling it an identity provider asserts a
federation role it does not hold. Most of our estate is exactly this
shape, so the majority of our authentication records would otherwise be
forced into a binary that does not describe them. `"Universal"` marks
that case explicitly rather than picking the less-wrong of two values.

The value comes from a source that is not reproduced here. That is a
deliberate omission, not an oversight, and it is the reason this entry
exists: the published page shows two values, so the next author to check
the source will find an apparent contradiction. DO NOT REMOVE
`"Universal"` ON THAT BASIS. The page has been fetched three times and
the omission is known.

Recording it here rather than in
[authentication-mapping.md](authentication-mapping.md) as schema fact is
the whole point of this file. The counter-evidence is real and is stated
so it can be argued with: upstream maps
`eventType = "user.authentication.auth_via_radius"` to `"IDP"`
(`OktaModelingRules_2_0.xif:97`), which is RADIUS validation classified
under a documented value rather than a third one; and the vendor's own
example terminates its role chain with `null`, so leaving the role unset
on an unclassifiable record is demonstrably permitted. An author who
finds this entry unconvincing has both of those to hand.

WHAT WOULD RETIRE IT: vendor guidance covering non-federated
single-system login under `"SP"` / `"IDP"`; or evidence that the
Authentication Story or identity analytics branch on the value and treat
an unrecognised literal differently from the two documented ones. The
consumer is closed and cannot be inspected from outside, so the second
would have to come from a tenant measurement -- a population count of
authentication-story rows for a `"Universal"` source against an `"IDP"`
one -- rather than from review.
