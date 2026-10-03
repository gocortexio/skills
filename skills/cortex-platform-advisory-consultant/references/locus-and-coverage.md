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

| locus | what it means, quoted from `corpus/schema/vocab.json` |
|---|---|
| `CONTROL` | The subject's own decisioning: routing, signalling, session establishment, forwarding, orchestration and scheduling, policy and trust evaluation |
| `MANAGEMENT` | Administration of the subject: admin access, configuration change, admin credentials, console, SSH, SNMP, API and firmware, and a cloud provider's administrative API whatever that provider calls it |
| `DATA` | What traverses or is held: user traffic, payload, files, mail, business data |
| `ENDPOINT` | Execution on a host, being process, file, registry and memory, where the subject is an operating system or agent with no plane decomposition |
| `SUPPLY` | Build, update, dependency, vendor and integrator paths |
| `ORGANISATION` | Posture, process, people and trust relationships; the finding is an inventory or advice question rather than an event located on a device |

The table is the vocabulary's own wording, and `tests/test_skill_conformance.py` fails when
the two differ. A paraphrase here is how SKILL.md's rule 9 once came to define the planes
differently from the label every finding prints.

**The three planes alone were measured against this corpus and do not fit it.** 72 per
cent of records carry no network or telecom class, and a hand-read sample put 54 per
cent of detection blocks outside any plane. The last three values exist because forcing
a service desk or a dependency into "management plane" produces a label that fires on
everything and therefore says nothing. Distribution over all 770 how-blocks: `CONTROL`
206, `ENDPOINT` 190, `MANAGEMENT` 155, `ORGANISATION` 89, `DATA` 79, `SUPPLY` 51, with
354 carrying a span. The 894 exposure records place as `CONTROL` 266, `DATA` 264,
`ENDPOINT` 148, `MANAGEMENT` 131, `SUPPLY` 79, `ORGANISATION` 6. 89 of them carry
`what.identifier_signals` and 24 are placed by it. `validate.py` prints both
lines on every run, and a third counting what each per-block rule placed: 45 blocks placed
without their record's surface, 30 of them on a supply surface and 1 by their host evidence;
20 placed by a cloud administrative operation; 64 placed as a posture question; 2 placed off
an administrative API class they never read; 2 placed by an administrative API class listed
after the first; 7 placed by an endpoint class listed after the first; 15 patterns declaring
a locus.

**`control plane` means the network sense here.** A cloud provider's control-plane API
is administration and lands in `MANAGEMENT`. The corpus used the phrase both ways until
0.18.0; `telecom.core` is the one place it was already right.

## Heading an answer by locus, and asking for it by role

SKILL.md's rule 9 heads an answer by the six `LOCUS` values the script printed, and puts
each finding under its own. Until 0.43.0 it defined the planes instead by a technology's
relationship to the attack: CONTROL the appliance attacked, MANAGEMENT the thing
administered, and DATA "the thing that sees", its traffic and threat telemetry. That is
not what `LOCUS` measures -- no telemetry-source block derives DATA, and a Check Point
firewall question matched ENDPOINT, SUPPLY and ORGANISATION findings that had no heading
at all -- so an answering model either re-bucketed findings against their printed label or
dropped the ones with nowhere to go.

The relationship is `what.role`, and it runs across the loci rather than along them. It is
also where the ranking is lopsided. Measured on 2026-09-30, 147 records carry a firewall,
VPN gateway or proxy class and 133 of them are `role: victim`, most of those exposures. Of
the 62 observations among them, 48 are victims; the 14 that are not are 6
`control_bypassed`, 5 `inline_tool`, 2 `telemetry_source` and 1 `lateral_path`. When this
was first measured, on "I have a Palo Alto firewall", the top of the criticality ordering
was almost entirely the appliance as target, while the non-victim records, the patterns
readable from the firewall's own telemetry and the remote-access authentication family sat
below the cut and went unmentioned; the caller had to ask for what the ranking had buried.
The counts move with the corpus, and the shape has held at every size it has been.

Two flags reach what the ranking buries. `--per-locus N` reserves up to N findings per locus
rather than one, so `--per-locus 3 --limit 18` gives several under each heading; where the
question named a product or vendor, those are findings naming it (`LOCUS_SUBJECT`).
`--role` keeps only records whose `what.role` is one of the roles named:
`--role control_bypassed,inline_tool,telemetry_source,lateral_path` on "Palo Alto firewall"
keeps 8 of its 32 matched observation records, each still printed under its own `LOCUS`.
`what.role` is one value per record, not one per product or class the record names, so it
says what the record's technology did, and on a record naming several it may be another
technology's than the one asked about. Two of the records that question keeps as
`control_bypassed` name a directory and a firewall among their classes, and their own
summaries say the perimeter held and that no actor was found: the role is the record's, and
a kept record is not proof that the firewall was bypassed. `ROLE_FILTER` says so.

## How the primary is chosen

The label is computed by the ladder in `corpus/schema/locus-map.json`, never guessed,
and `LOCUS_BASIS` prints every signal, including the ones that lost. The file's
`tier_order` is the ladder `consult.py` runs, and `validate.py` refuses a corpus whose map
lists it differently, names a supply surface or non-product class the ladder cannot look
up, or both maps and defers one value. `attack_surface` outranks `product_class` where it
commits and reaches the block; the class list is read first-listed rather than by vote,
because over half of all observation records name products from more than one plane.

The tiers, in order: `declared`, `surface_supply`, `class_nonproduct`, `posture`,
`surface`, `host_evidence`, `operation`, `admin_api_unread`, `admin_api_listed`,
`host_listed`, `identifier`, `class_first`, `default`. `default` is the floor
for an input carrying no mapped class, which `validate.py` refuses in the corpus, so it never
fires on what ships; every other tier decides at least one block or pattern, and a test holds
it to that. A `shape` tier sat after `class_first` until the 2026-10-01 third validation and
could never fire; `posture` is what it was meant to be. Five inputs are held back from deciding
where they once decided while describing something else:

- **A non-product class decides only as the primary subject.** `cross_sector` and
  `process.service_desk` place a block on `ORGANISATION` when listed first, or when
  nothing else is listed. Authors also use `cross_sector` as a sector tag, and read from
  anywhere in the list it called 90 blocks "an inventory or advice question", among them
  device events read from EDR and authentication logs. Listed after a product class, it
  is a span source, and the basis says `nonproduct-signal=ORGANISATION (cross_sector
  listed, not primary)`. `ORGANISATION` fell from 114 blocks to 28, 3.6 per cent, still
  above the 2 per cent floor every value was held to when the axis was introduced, and to
  25, 3.2 per cent, once an `insider` surface stopped placing the host blocks of its record.
  It rose to 89 when posture questions were placed by what they are (below).
- **A span-only surface never decides.** `email_flow` and `remote_access_service` name the
  way in, not the plane the detection reads: mail delivery put a Chrome renderer breakout
  read from EDR on `DATA`, and an operator's remote access put a shadow-copy deletion on
  `MANAGEMENT`. `watering_hole`, the web form of the same vector, is deferred for the same
  reason. Each still commits a locus, and it is carried as the span.
- **A generated exposure's surface is not read.** The KEV, ZDI, PSIRT and database
  generators assign `attack_surface` from a class table, so reading it re-encoded the
  class through a remap that sends firewalls and hypervisors to `MANAGEMENT`. An exposure
  carrying a tag in `untrusted_surface_tags` is placed by its class and the basis prints
  its surface as `generator-assigned ..., not read`. What stands in for it is what each
  identifier's own text names: the same generators write `what.identifier_signals` from
  `identifier_reading` in the locus map, a `MANAGEMENT` entry for an identifier whose
  catalogue description, advisory title or database description names an administrative
  component, and a `network.vpn_gateway` entry for a VPN feature on a network device, never
  for a provider VPN's VRF or MPLS wording. The
  **`identifier`** tier places the record on a locus every identifier reads, where it is not
  the class's: 24 records, NX-OS and BIG-IP's Configuration Utility among them, sit on
  `MANAGEMENT` with their class's plane as the span. Where some identifiers read another
  plane and not all, that plane is the span (below), and a class read this way never decides.
  A record listing an `ENDPOINT` class or `dev.library` first is not read: the vocabulary
  gives `ENDPOINT` no plane decomposition, and a library has no administration of its own.
  A hand-written exposure's surface was read from its advisory and is kept. `validate.py` refuses an exposure whose
  generator tag and `where.source_type` disagree, so a generator that forgets its tag
  cannot pass its surface off as authored.
- **A supply surface places only the supply path.** `supply_chain_update` and
  `third_party_access` are per record, and placed every block of their record: a delivered
  miner's pool traffic and the IAM workload creation that followed sat on `SUPPLY` with the
  container images they arrived in, and so did every SolarWinds block, Golden SAML included.
  73 blocks were placed that way and 43 had a first-listed class on another plane. The surface
  now decides only a block citing the technique its vector is filed under
  (`surface_vector_techniques`: Supply Chain Compromise, or Trusted Relationship, with their
  sub-techniques) or reading `integrity_check`. Every other block is placed as any block is,
  with the supply surface as its span, and the basis says `set aside for this block`. The
  signed-update block of the SolarWinds record stays on `SUPPLY`; the other nine sit on
  `MANAGEMENT` with `SUPPLY` as their span.
- **Any other committing surface stops at the way in.** `internet_facing_management` put
  every block of a Siemens PLC record on `MANAGEMENT`, operator-display manipulation and S7
  data-block writes read from industrial protocol and process telemetry included, so no
  Siemens finding reached `CONTROL`. The surface now decides a block unless the block has gone
  past the way in: it cites no technique ATT&CK files under initial-access
  (`way_in_techniques`, held equal to the shipped reference), reads no evidence on the
  surface's own plane, and its evidence reads its first-listed class's plane, only posture
  (`asset_inventory`, `vuln_scan`), or only host evidence, which places it on `ENDPOINT`
  (`host_evidence`, below). The burden runs the other way from supply, because on a device
  most of what follows a management login is still its administration; a device
  administration block read from `auth_log`, which maps to `CONTROL`, cites the way in and
  keeps the surface. Evidence on any other single plane does not set it aside: measured, that
  moved an SNMP-probe block read from flow records to `DATA`, though the vocabulary names SNMP
  as `MANAGEMENT`, so the S7 record's controller sweep, read from flow and IDS records, keeps
  the management interface. `process_telemetry` takes no part in this test, as in every other
  evidence test: until the fourth validation it could set a surface aside, or keep one, on a
  reading the locus map calls contested. No corpus block depended on it.

One tier reads a typed marker. **`operation`**: a block whose every typed marker is a
`cloud_operation`, its only live test an operation in a cloud or SaaS audit trail, sits on
`MANAGEMENT`, because the vocabulary places a cloud provider's or tenant's administrative API
there whatever the provider calls it. So does a block that reads only the provider's audit
trail (`cloud_audit` its only deciding evidence) and tests an administrative operation there
beside other typed markers, because on such a block those are fields of the same audit event.
0.43.0 kept the Bedrock model-access block, its operations beside a user-name pattern and an
HTTP client agent, on `CONTROL` from `app.ai_platform`; the fourth validation read both as
CloudTrail fields, and it now sits on `MANAGEMENT`, a reversal of that recorded outcome. A
process name beside host evidence is not such a field, and keeps the class. Six blocks sat on `CONTROL` or `DATA` from an MFA,
container, AI-platform, directory or SaaS class listed first. A block whose every operation is
a use of the service rather than its administration, listed in `non_administrative_operations`
(reading mail, invoking a model, reading a stored object), is left to the ladder, which is how
an Exchange Online block testing `MailItemsAccessed` stays on `DATA`. A regex, substring,
prefix or suffix names a family of operations and is never read as listed. A record's block is
read with its own markers only: a block with none prints its pattern's live test in
`emit_xql.py`, and the one such block this placed on `ENDPOINT` declares its locus.

Five tiers let a block's own evidence outrank a record-level input, each on a narrow test met
only where the block reads nothing on the plane it displaces, and each leaving out
`contested_evidence` (`process_telemetry`, whose mapping the locus map documents as
contested), so a contested type neither decides nor stops a decision:

- **`host_evidence`**: a block past its record's committing surface whose evidence reads only
  host evidence (`edr_process`, `edr_file`, `registry`, `memory`, `file_artefact`) and nothing
  on its first-listed class's plane sits on `ENDPOINT`, the one locus the vocabulary defines by
  the evidence that reads it. The Siemens S7 library-artefact block, read from EDR alone on a
  host that is not an engineering workstation, printed the record's management interface, and
  both Siemens answers named `ENDPOINT` absent. It places 1 block, with the surface as its
  span. A surface on the class's own plane always reaches, so a VPN appliance's host-only
  blocks keep its `CONTROL` portal.
- **`posture`**: a block whose `rule_shape` is `inventory` and whose evidence reads only
  posture (`vuln_scan`, `asset_inventory`) is an inventory question, the vocabulary's
  `ORGANISATION`. The `shape` tier that was meant to say so sat below `class_first` and never
  fired, so the known-exploited catalogue join, captioned as a vulnerability management
  process and not a detection, sat on five loci across its 13 citing blocks by the order its
  records listed classes, and the copy on a web-server-first record filled the `DATA` slot on
  firewall and VPN questions. Shape alone still decides nothing, and neither does posture
  evidence beside anything else. It places 64 blocks and outranks a non-supply surface: a
  posture question about the way in is still a posture question, and the surface travels as
  its span. A supply surface that reaches the block outranks it, so a contract question on
  the supply path itself stays `SUPPLY`.
- **`admin_api_unread`**: a first-listed class in `administrative_api_classes` -- `cloud.iaas`,
  defined as an administrative API and console -- does not place a block that never reads that
  API: no `cloud_operation` marker, nothing read on `MANAGEMENT` or from inventory, and its
  deciding evidence on one other locus. A certificate issued for an owned hostname, read from
  DNS and TLS metadata, and a workload's mining-pool traffic, read from flow and DNS records,
  sat on `MANAGEMENT` because an AWS record lists `cloud.iaas` first, and the AWS answer named
  `DATA` absent while both read it. They are the two blocks it places. `cloud.identity` is
  defined the same way and deliberately not listed: the locus map gives the reason and the
  four blocks listing it would move.
- **`admin_api_listed`**: the mirror. A record listing a class in `administrative_api_classes`
  after its first names the provider whose API it is, and a block reading that API's audit
  trail or configuration (`cloud_audit`, `config_diff`) and nothing on the first-listed
  class's plane sits on `MANAGEMENT`. The AWS Kubernetes node-credentials record lists
  `cloud.container` first, and its metadata credential request paired with the node role's
  first cloud API call printed `CONTROL`, the only Amazon-named `CONTROL` finding. It places 2
  blocks, both on that record. A block whose operations are all uses of a service is never
  moved. Taking any later-listed `MANAGEMENT` class instead moved 9, Exchange Online and
  Office 365 mail and configuration blocks off `DATA` among them.
- **`host_listed`**: the same for the host. A record listing an operating system, browser or
  agent class (one `by_class` places on `ENDPOINT`) after its first names the host the incident
  ran on, and a block reading only host evidence, so nothing on the first-listed class's plane,
  sits on `ENDPOINT`. It places 7 blocks, every one host execution: an NTDS.dit copy in a temp
  path that sat on `CONTROL` from `identity.directory`, a credential file read at a Unix shell,
  AI client artefacts on disk and model-store ransomware that sat on `CONTROL` from
  `app.ai_platform`, an Office script-engine spawn and an in-browser skimmer that sat on `DATA`.
  Without the listed class it moved 23, about half onto products with a plane decomposition
  (ActiveMQ, TeamCity, a PBX), which the vocabulary's `ENDPOINT` excludes; those 16 keep their
  class.

Both `*_listed` tiers read a record's class list, which names the products the incident ran
through, never a pattern's `applies_to_classes`, which says only where it applies: applied to
library patterns they moved 18, four CI/CD supply-path patterns onto `MANAGEMENT` among them,
and lowered the agreement between a pattern's locus and its citing blocks' from 481 to 478 of
755 pairs, where reading blocks alone raised it from 479. Evidence outranking any record-level
plane it contradicts, the tier the locus map rejects, was measured once more against these
five: it moved 129 blocks and 67 patterns and took `DATA` from 81 blocks to 143.

The primary never depends on the question. `validate.py`, `emit_xql.py` and `advise.py`
place a block with no question at all, and all of them print the `LOCUS` a consultation
prints for it.

**A pattern in `advise.py`** has no block of its own, so its `LOCUS` is the ladder run on
its `applies_to_classes`, with its own `markers`, `rule_shape` and `evidence_type` standing
in for a block's, and `LOCUS_BASIS` says `input=applies_to_classes` where a class decided.
That is where the pattern applies. Until the 2026-10-01 third validation only the classes
were read, so `pat-mailbox-delegation-or-role-granted`, whose one live test is an Exchange
role or permission grant, derived `DATA` from `server.mail` while its citing block sat on
`MANAGEMENT`, and `advise.py` named `MANAGEMENT` absent for a selection holding it; reading
the pattern's own markers moved seven patterns onto `MANAGEMENT` and its shape and evidence
twenty-four onto `ORGANISATION`. Ten posture patterns stated no `rule_shape` while every citing
block said `inventory`, and now state it. A network device's administration has no class of
its own, so "SNMP queries from anything but the monitoring system" derived `CONTROL` from
`network.router`; a pattern whose detection is administration of the device it applies to
declares `locus` with a `locus_reason` naming what in the vocabulary makes it so, and
`LOCUS_BASIS` reads `tier=declared; input=locus declared on the pattern, <reason>`. Fourteen
declare `MANAGEMENT` that way: SNMP, a management channel open before authentication, input
to a management endpoint, scripted configuration capture, device administration from outside
the management network, configuration and routing change, configuration export, firmware and
bootloader replacement, a firmware rollback, a boot-image implant, edited command output, a
changed controller credential, vendor default accounts and a renamed device. One declares
`DATA`: the mailbox property sweep, whose markers are mailbox audit actions that would place
it by the operation tier while what it reads is mail held. `validate.py` refuses one the class
derivation already gives, one with no reason, and a reason carrying a semicolon. A declared
pattern locus never reaches a block. Making every pattern's primary the locus its citing
blocks share was measured and not taken: it moved 49 patterns onto `MANAGEMENT`, 41 of them
on a single citing block, ransomware encryption and mining pool traffic among them. The primary
can differ from where the pattern was seen: when first measured, 147 of the 441 cited patterns
printed a locus none of their citing blocks sits on, and at 0.44.0 101 do, among them
`pat-audit-policy-tampering`, `ENDPOINT` from `endpoint.os` listed first, whose one citing
record is a CloudTrail incident on `MANAGEMENT`. `LOCUS_OBSERVED` counts the citing blocks
per locus, each placed exactly as a consultation places that finding, or reads `none - no
citing record`. When every citing block agrees on a locus other than the primary, that locus
is the span, ahead of the class list's own span source, as `span-source=observed span: N
citing how-block(s)`, and `LOCUS_BASIS` ends `observed-signal=`. A split is never a span. The
header's `LOCUS_RETURNED` counts the primary over the patterns returned and `LOCUS_ABSENT`
names the loci none of them sits on, with the same caveat as a consultation's. There is no
quota: `advise.py` returns what was selected, and rebalancing it would answer a question
nobody asked.

A `how` block may set `locus` to override the derivation, and almost none should.
`validate.py` refuses a declared locus the derivation already gives, and one whose
record's `notes` do not give the reason naming `how[<n>].locus`.

## The span

`LOCUS_SPAN` always leads with the primary, so splitting on `", "` yields one to three
values and never a sentinel. The record's own span, where it has one, is the first of these
sources whose locus differs from the primary, in the order `span_order` lists and
`validate.py` holds to the code. None reads the question, so `emit_xql.py`, `advise.py` and
`validate.py` print the record's own span, and a consultation prints it straight after the
primary. Where the record has no span of its own, the question-free tools print the primary
alone, and a consultation's second value, if any, is the question's class appended below:

1. `surface_span_only` -- an `email_flow` or `remote_access_service` surface.
2. `surface` -- a committing surface that did not decide, including one set aside for the
   block.
3. `identifier` -- on a generated exposure, the class plane the `identifier` tier displaced,
   or, where it did not decide, the plane most of its identifiers' own text reads other than
   the primary, ties in `locus_order`. FortiOS's two super-admin bypasses beside two SSL-VPN
   flaws read `CONTROL, MANAGEMENT`. 69 exposures take their span this way, 24 of them the
   plane the tier displaced, and 76 exposures carry a span where 7 did.
4. `class` -- a class list that commits unanimously and did not decide. A class list
   split across loci is a bag, not a second opinion, and is never a span; the basis
   names what decided instead, as `class-signal=split(first=server.web:DATA; also
   CONTROL, MANAGEMENT)`.
5. `nonproduct` -- a non-product class listed after a product class.
6. `evidence` -- the block's `evidence_type` values, `syslog` excluded, when they agree
   on one locus. Evidence says where a detection is read, not where the attack sits, so
   it is never a tier on its own: it decides a primary only in the surface reach test and
   inside `host_evidence`, `posture`, `admin_api_unread`, `admin_api_listed` and
   `host_listed`, it is otherwise the last span source, and `evidence-signal=` is always
   printed.

A class on the record that the question resolved, whose locus is neither the primary nor the
record's own span, is then appended. A firewall question sees the KEV-harvest record, an
inventory question placed on `ORGANISATION`, as `ORGANISATION, CONTROL`, with
`span-source=class_matched span: network.firewall`: its class list is split and its evidence
agrees with the primary, so it has no span of its own, `emit_xql.py` prints `ORGANISATION`
alone, and the second value is the question's. It is the only input that
reads the question, and it only ever adds. Until the 2026-09-30 validation it was the first
span source and took the record's own slot: on "Fortinet FortiGate" 11 of 78 findings lost
their record's second locus to it, and across the corpus 238 (block, matched class) pairs
did, 134 of them `ORGANISATION`, so a consultation and `emit_xql.py` disagreed about where the
same block sits.

`LOCUS_BASIS` reads `tier=; input=; surface-signal=; class-signal=; nonproduct-signal=;
evidence-signal=; span-source=; declared=`, in that order; `advise.py` appends
`observed-signal=`, and an exposure carrying `what.identifier_signals` appends
`identifier-signal=`, each identifier with what it read and the words it read it from.

## What the header says

The header states the spread rather than leaving it to be inferred:

- `MATCH_TIERS` -- how the match set was reached, by tier, before `--limit`: `product`,
  `vendor`, `class` and `vendor-other-class`, then the free-text tiers. `ORDERING` groups
  findings by tier before the score, so the quota's representative of a locus is its first
  eligible finding in that order, not its highest scorer.
- `LOCUS_SPREAD` -- how the shown set was picked: `quota`, with the slots reserved per
  locus (`--per-locus`, default 1) and the record cap, or `off` under `--no-locus-spread`.
- `LOCUS_MATCHED` and `LOCUS_SHOWN` -- the distribution before and after `--limit`.
- `LOCUS_ELIGIBLE` -- per locus, the matched findings that keep it out of `LOCUS_ABSENT` and
  that a reserved slot may be filled from unless `LOCUS_SUBJECT` narrows it: a `product`,
  `vendor`, `class`, `vendor-other-class` or `tag` match whose criticality before any
  coverage demotion is 3.0 or more, the MODERATE floor. Until 0.43.0 any match counted, so
  "Fortinet FortiGate" reserved `ORGANISATION` for a geolocation-limits record at score 1.50
  and pushed out a record naming FortiGate, and "Check Point firewall" reserved two loci for
  records reached only by the word "point". Over 836 product questions, 143 reserved slots sat
  below the floor and 55 came from free text; neither can now. A tag match is eligible in
  every mode, because a tag hit on a named question can only come from a word the caller
  wrote beyond the name.
- `LOCUS_SUBJECT` -- per locus, the eligible findings naming what was asked, and the line says
  in which tier and naming what: tier `product` or `vendor`, except where the question named a
  product and a finding in tier `vendor` names that product's vendor (`question_subject()` in
  `scripts/consult.py`). Such a finding names the vendor in a class asked about and another of
  its products, as its `MATCH_BASIS` says, so the line counts tier `product` alone and says it
  leaves tier `vendor` out; or, where no finding names the product, tier `vendor` alone,
  naming the vendor and saying that nothing names the product, and that tier keeps the reserve
  it had. The narrowing is per vendor: a vendor the question named without a product of it is
  still what was asked, so "Cisco ASA and Fortinet firewall" counts Fortinet's records and not
  the management centre, and a product whose name is its vendor's own ("SimpleHelp", "Okta")
  names nothing narrower than the vendor. It is decided over the eligible findings, since one
  below the floor changes no count. Until the 2026-10-01 fourth validation both tiers counted
  for every question: "Cisco ASA" counted three Secure Firewall Management Center blocks as
  its `MANAGEMENT`, reserved the plane for them and left it out of `LOCUS_ANALOGUE_ONLY`,
  though the management centre administers Firepower Threat Defense and not ASA software. Over
  the 1,045 product questions among the alias keys, 95 hold such a finding beside one in tier
  `product` and change their counts, 76 of them gaining a plane in `LOCUS_ANALOGUE_ONLY`; 188
  that nothing names change only the lines' wording. The boundary is the alias table's: on
  "Windows", the Netlogon and Print Spooler records name "Windows Server", "Windows Netlogon"
  or "Windows Print Spooler", names the table does not join to Windows, so they are tier
  `vendor` and `CONTROL` is listed under `LOCUS_ANALOGUE_ONLY`, as their `MATCH_BASIS` already
  said;
  `product_families` is where that boundary moves. Where the question named a product or
  vendor and any finding names it, only these fill a reserved slot. Until the 2026-09-30
  validation any eligible finding did: "Fortinet FortiGate" reserved `DATA` and `ENDPOINT` for
  two other products' class analogues -- a known-vulnerability catalogue join placed on `DATA`
  by its first-listed web server, and a Zeppelin share-enumeration block placed on `ENDPOINT`
  by its first-listed `endpoint.os`, at score 3.71 -- and pushed out two FortiGate findings,
  one at 3.92, while the header counted both planes as represented. "Cisco ASA"
  `--per-locus 3` reserved the same two blocks, and so did the Palo Alto, Check Point, Juniper
  and Firepower questions. So a reserve never takes a slot for an analogue at the cost of a
  finding naming what was asked. Where no finding names it, the answer is analogues
  throughout, `CLASS_LEVEL_WARNING` says so, and the reserve spreads the analogues as before.
  A question naming neither prints `not applicable`.
- `LOCUS_ABSENT` -- every locus with no eligible finding. See rule 8. Each gets a bullet
  saying what did reach it: `matched` findings, split into `loose` (a free-text tier) and
  `below floor`; `span-only`, the findings placed elsewhere that carry this locus anywhere
  after the primary in `LOCUS_SPAN`, the question's matched class included; `exposures` and
  `library`, the `EXPOSURE` and `LIBRARY` blocks placed there before their limits, which
  never make a locus represented (`references/exposures.md`); the best ineligible
  finding's rank, score, tier and `FINDING_KEY`; and, where any is shown,
  `shown K, none eligible`, because `LOCUS_SHOWN` counts every shown finding and a locus
  counted there and named here read as a contradiction. Every count recounts from the whole
  match set in pure order, which `tests/test_locus_axis.py` does.
- `LOCUS_ANALOGUE_ONLY` -- every locus holding eligible findings of which none names the
  product or vendor asked about: each is a class analogue, another product line of the vendor,
  on a product question another of the vendor's products in a class asked about (tier
  `vendor`, which the line then names), or a tag match, about another product. Rule 9 asks the
  answer to name each such finding's own product from its `TECHNOLOGY` line. Such a locus is
  not absent, and it is not covered for what was asked; the line says so, the answer must too
  (rule 9), and no slot is reserved for it, so a finding there is shown on rank alone. Each
  gets a bullet counting its eligible findings by tier and naming the first, with its rank,
  score and `FINDING_KEY`, and how many are shown. Where no finding names what was asked,
  every eligible locus is listed and the line says the reserve spreads them; a question naming
  neither prints `not applicable`. Printed in every answer, under `--no-locus-spread` too,
  because it is a statement about the planes and not about which findings were shown.
- `LOCUS_DISPLACED` and `LOCUS_RESERVED` -- the quota reserves `--per-locus` slots (default
  1) per locus holding a finding that may fill one (`LOCUS_SUBJECT` where it applies, else
  `LOCUS_ELIGIBLE`), and both sides of what that cost are named. They are always the
  same length. Each bullet names the finding by its `FINDING_KEY`, `<record-id>#how<n>`,
  which every finding block also prints after `PATTERN_ID`, and the tier it matched on. The
  record and pattern together are not an identity: one record can cite one pattern from two
  blocks, so a check that matched bullets to findings on that pair could count a displaced
  block as still shown.
- `RECORD_CAP` -- no record takes more than 2 slots while another record's finding in its
  own match group is waiting. Findings are per how-block, and one record's blocks share
  recency, identifiers and role, so they sort together: "Atlassian Confluence" showed 6
  blocks of one PBX record in twelve, 8 in pure order, and 617 of 836 product questions gave
  one record 3 or more slots. The cap never crosses a match group: applied across groups it
  passed over a record naming the product for another vendor's class analogue, and 178 of
  848 product questions lost 566 such findings, "Check Point firewall" its rank-3 Check Point
  block for a Cisco VPN record at rank 10. A group's capped findings take any slot left at
  the end of the group, before a looser group is reached (`SLOT: backfill`), so a product
  with one record still leads with it: "SolarWinds Orion" shows 9 of its record's 10 blocks.
  266 of 836 questions show a record 3 or more times, 175 of them a record naming the
  product. The line counts every natural top-N finding the cap passed over and never
  showed: those balanced by a finding of the same group from below the cut are bulleted in
  the `LOCUS_DISPLACED` format, and those where a reserve had already cost the slot, so the
  cap only chose which finding left, are `LOCUS_DISPLACED` bullets saying so. A capped
  finding the fill reached nothing below cost nothing and is not counted. The cap also bows
  to a reserve whose locus holds no other record's eligible finding in its group. The value
  2 is a choice, not a measurement.
- `LOCUS_UNDERSERVED` -- fires when `--limit` is below the slots the reserve asks for, and
  names which reserved loci got fewer than theirs.
- `ROLE_FILTER` -- printed when `--role` keeps only records whose `what.role` is one of
  those roles. That is one value per record, not per product or class it names, and the line
  says so. It states how many of the matched observation records were kept and their
  roles, and how many of the exposure records naming the technology, which carry `what.role`
  too and are filtered the same way; `RESOLUTION`, `FINDINGS` and every tally after it describe
  the kept records only, and the RESOLUTION line says so. A claim that no observation names
  what was asked then reads "no observation --role kept", in `RESOLUTION` and
  `CLASS_LEVEL_WARNING` alike, and counts the observation records naming it that the filter
  dropped: "Palo Alto firewall" `--role telemetry_source,inline_tool,control_bypassed` said the
  corpus held none while the filter had dropped one. A filter that kept exposures and
  no finding lists them and exits 0. Filtered to nothing, it exits 1:
  `FINDINGS` and `NO_FINDINGS` both say what matched before the filter, `RESOLUTION`
  describes those findings and says none is shown, and nothing gives the advice for a name
  the corpus does not know.

Each finding block prints `RANK`, its position in the whole `ORDERING` order, the number
every header bullet cites, and `SLOT`, why it is in the shown set. Its first word is the kind
of slot: `natural`, inside the natural top N, with `natural - ...` where it fills a locus's
reserve while a higher-ranked finding leaves; `replacement - ...` below the cut, taking the
slot of a finding of its own group listed under `RECORD_CAP`; `reserved - ...` when the quota
took it from below the cut, naming the locus's own reserve, which is `--per-locus` only where
the locus holds that many eligible findings; `backfill - ...` when a capped finding took a
slot its group had no other record's finding for. Every block a record holds past the cap,
counted in `RANK` order, says why the record holds that many. `RANK` therefore gaps where the
quota skipped, and `=== FINDING i OF n ===` stays positional. For several findings under each
plane pass `--per-locus 3 --limit 18`.

`--no-locus-spread` restores pure `ORDERING` order, with no reserve and no record cap, **and
still prints the distribution**, which is how the eleven-of-twelve above is visible without
re-running.
