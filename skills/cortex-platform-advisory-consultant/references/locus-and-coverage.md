<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Where a finding sits, and what the answer did not cover

Read this when a consultation's spread looks wrong, when `LOCUS_ABSENT` needs explaining to
a caller, or before changing how the locus quota picks what to show.

Criticality ranking returns whatever the corpus is densest in. Measured on a Cisco
firewall: the pure top twelve was **eleven `MANAGEMENT` findings and one `CONTROL`**,
which reads as a complete answer and is a monoculture. `LOCUS` is the axis that makes
that visible, and the quota is what stops it.

| locus | what it means |
|---|---|
| `CONTROL` | the subject's own decisioning: routing, signalling, session establishment, forwarding, orchestration, policy and trust evaluation |
| `MANAGEMENT` | administration of the subject: admin access, config change, admin credentials, console, SSH, SNMP, API, firmware |
| `DATA` | what traverses or is held: user traffic, payload, files, mail, business data |
| `ENDPOINT` | execution on a host, where the subject is an OS or agent with no plane decomposition |
| `SUPPLY` | build, update, dependency, vendor and integrator paths |
| `ORGANISATION` | posture, process, people and trust relationships; an inventory or advice question rather than an event on a device |

**The three planes alone were measured against this corpus and do not fit it.** 72 per
cent of records carry no network or telecom class, and a hand-read sample put 54 per
cent of detection blocks outside any plane. The last three values exist because forcing
a service desk or a dependency into "management plane" produces a label that fires on
everything and therefore says nothing. Distribution over all 771 how-blocks: `CONTROL`
196, `MANAGEMENT` 154, `DATA` 131, `ORGANISATION` 114, `ENDPOINT` 93, `SUPPLY` 83.

**`control plane` means the network sense here.** A cloud provider's control-plane API
is administration and lands in `MANAGEMENT`. The corpus used the phrase both ways until
0.18.0; `telecom.core` is the one place it was already right.

The label is computed by the ladder in `corpus/schema/locus-map.json`, never guessed,
and `LOCUS_BASIS` prints every signal including the ones that lost. `attack_surface`
outranks `product_class` where it commits; the class list is read first-listed rather
than by vote, because half of all records name products from more than one plane. A
`how` block may set `locus` to override the derivation, and almost none should.

`LOCUS_SPAN` always leads with the primary, so splitting on `", "` yields one or two
values and never a sentinel. It carries a second locus only where another signal is
unanimous and different -- a class list split across loci is a bag, not a second
opinion, and is never reported.

The header then states the spread rather than leaving it to be inferred:

- `MATCH_TIERS` -- how the match set was reached, by tier, before `--limit`.
- `LOCUS_MATCHED` and `LOCUS_SHOWN` -- the distribution before and after `--limit`.
- `LOCUS_ABSENT` -- every locus the match set could not fill. See rule 8.
- `LOCUS_DISPLACED` and `LOCUS_RESERVED` -- the quota reserves one slot per populated
  locus, and both sides of what that cost are named. They are always the same length.
- `LOCUS_UNDERSERVED` -- fires when `--limit` is below the populated locus count, and
  names which loci got no slot.

`--no-locus-spread` restores pure criticality order **and still prints the
distribution**, which is how the eleven-of-twelve above is visible without re-running.
