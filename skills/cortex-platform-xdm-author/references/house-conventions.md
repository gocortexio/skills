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

WHAT THE SCHEMA SAYS: `user.*` and `identity.*` are two
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

WHAT WOULD RETIRE IT: a vendor deprecation notice on either family
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

### "VIRTUALIZATION" as a bare-string event tag

WHAT WE REQUIRE: the VIRTUALIZATION story marker is written as a bare
quoted string inside `arraycreate(...)`, never as a constant:
`xdm.event.tags = arraycreate("VIRTUALIZATION")`. Mixing forms in one
call is correct where a record carries both stories --
`arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION, "VIRTUALIZATION")`.
The spelling is upper case, singular, no underscore. Enforced by
NOTHING, which is stated below rather than glossed.

WHAT THE SCHEMA SAYS: `EVENT_TAG` is a closed constant group and
[xdm-const.md](xdm-const.md) lists its six members. None of them is a
virtualization marker. Read strictly, a field typed to that group takes
only members of that group, so on the schema alone this story has no
marker at all and cannot be tagged.

WHY WE DIVERGE: because we were never diverging from the platform. The
premise that this is odd came from our own error, and correcting that
dissolves most of the entry's difficulty.

`xdm.event.tags` IS NOT A CLOSED FIELD. What is closed is the
`EVENT_TAG` constant GROUP -- a compile-time namespace you
cannot invent a member of. The FIELD is an ordinary array of strings,
and upstream packs assign runtime values to it: vendor tag arrays,
policy labels, a concatenated CVE list, a bare `execution_name`. Three
of our own pages called the FIELD "an Array over the closed six-member
enum", and reading it that way is what forced the conclusion that a
seventh story marker had to be a seventh CONSTANT. It could not be.
Those pages are corrected; this paragraph is why.

THE VENDOR WRITES THE STRING, in the canonical sources for this very
story. `Packs/VMwareESXi/ModelingRules/VMwareESXi_2_9/VMwareESXi_2_9.xif`
and
`Packs/VMwareVCenter/ModelingRules/VMwareVcenter_2_9/VMwareVcenter_2_9.xif`
both assign `xdm.event.tags = arraycreate("VIRTUALIZATION")`, and the
vCenter block is headed "Virtualization Story general field mapping".
That is the citation this entry lacked when it was first written, and it
is also the source for the SPELLING -- upper case, singular, no
underscore -- which the mapping page calls the whole specification and
which no check can enforce.

`XDM_CONST.EVENT_TAG_VIRTUALIZATION` appears in NO upstream modelling
rule. Treat that as corroboration, not proof: `EVENT_TAG_ONPREM` appears
in none either and demonstrably resolves, so absence upstream is not an
oracle for the namespace. The load-bearing measurement is the tenant
bisect -- a MODEL rule carrying the symbol fails the pack install with
an opaque 101704 that names nothing.

That is MEASURED, not inferred, and it is the strongest evidence behind
any entry in this file. A consuming pack bisected it on a live tenant in
BOTH directions, holding the story's field assignments fixed: with the
constant and without the assignments it FAILS; with the assignments and
without the constant it INSTALLS; swapping the constant for the literal
INSTALLS. So the failure is the symbol and not the story's fields, which
are accepted. That is a bisect that clears the dimension it varied
(LAW A65), and it is why the pack's own rule carries the string with a
comment explaining it.

Note what that pack could not know: its comment reasons that the constant
is documented in the vocabulary the rule was written against, so the
PLATFORM must be behind the vocabulary. The vocabulary was this bundle's
`xdm-const.md`, and it had invented the member. The platform was never
behind anything. A correct workaround reached for the wrong reason still
reads as a platform defect in the record, which is the second cost of
inventing a constant.

WHAT IS STILL NOT ESTABLISHED, because this entry should not claim more
than was measured: whether the platform RECOGNISES a bare-string tag as
story membership or merely STORES it. The bisect varied SYMBOL FORM
against INSTALL OUTCOME and cleared exactly that (LAW A65); the read-back
that would have settled recognition returned a 504. "The literal
installs" is measured. "The literal works" is not. The vendor shipping it
in their own Virtualization Story rules is the strongest evidence we have
and it remains circumstantial.

So this entry does NOT rest on the string being strictly better than the
constant. It rests on the constant being measured to FAIL and the string
being what the vendor WRITES. The asymmetry runs both ways and the second
direction is the uncomfortable one: the constant fails LOUDLY at install
with a procedure attached, while a MISSPELLED string fails SILENTLY and
forever -- `"virtualization"`, `"VIRTUALIZATIONS"` or `"VIRT"` pass every
control this bundle owns, install cleanly, and produce a record that
looks tagged and is not a member.

This entry exists because the string looks wrong. Every other story
marker this bundle prescribes is a constant, so an author who meets
`"VIRTUALIZATION"` beside `XDM_CONST.EVENT_TAG_AUTHENTICATION` in the
same `arraycreate` will read it as an oversight and tidy it. This
bundle did exactly that to itself: 2.8.0 documented the constant, and
2.10.0 taught the linter to accept it after a consuming session
reported that the linter and the reference disagreed. The session's
report was right and the diagnosis was backwards -- the reference was
the wrong copy, not the linter -- and 2.11.0 reverted both. Do not
re-derive that conclusion from the shape of the other six.

ENFORCEMENT, stated as it behaves rather than as it was first described
here. The constant is refused TWICE on a MODEL rule: ERR-031 blocks it at
ERROR severity, so the lint EXITS 1, because `EVENT_TAG` is a closed
constant family and this reference does not list the member; and WARN-045
flags it as an advisory. Both carry the same fix text, held once in
ERR-031's registry entry so there is no second copy to fall behind. Two
things the first wording of this entry got wrong: the refusal is an ERROR
and not merely a warning, and BOTH checks are gated on `_is_model`, so
the symbol inside an `[INGEST:...]` parsing rule is refused by nothing.

ERR-031's gate is DERIVED FROM this reference's member list. Restoring
the member to `xdm-const.md` would silently disarm ERR-031 as a side
effect, so if the retirement condition below is ever met, check that
WARN-045 and ERR-031 move together rather than assuming the enum edit is
the whole change.

The gap that remains is the string itself. Both checks match
`EVENT_TAG_*` TOKENS and a quoted string carries none, so the prescribed
form is the one form no check can see, and the spelling above is the
whole specification.

WHAT WOULD RETIRE IT: a tenant install ACCEPTING a MODEL rule that names
`XDM_CONST.EVENT_TAG_VIRTUALIZATION`, which is the bisect above re-run
and coming back the other way. That is a cheap test and it is the only
one that counts: the member appearing in vendor documentation would not
be enough on its own, because documentation is what put the member in
this bundle in the first place. Should it ever install, both copies of
the enum gain the member together and WARN-045 begins checking this tag
for the first time.

Separately, a tenant measurement showing the analytic does not read a
bare-string tag -- a population count of story rows for a string-tagged
source -- would retire the convention by retiring the TAG, not by
replacing it with a constant.
