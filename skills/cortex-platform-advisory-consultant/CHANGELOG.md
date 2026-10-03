<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Changelog

## 0.44.0

Round four took the ten major defects the fourth validation of 0.43.0 left. Nine are fixed,
with the minor defects of the third and fourth validations that share their causes; the
paragraphs below are the batches in the order they landed, each with any fix its reviews
asked for, and the last closes the round. The tenth, planes-network major 0, is not: the
2025-26 campaign against the ASA and Threat Defense (CVE-2025-20333 with CVE-2025-20362) still
has no observation, so the ASA's catalogue record prints `EXPOSURE_DETECTION_HELD: none` and the
only ASA implant record is still seed. Two observations and four patterns were drafted from
CISA's ED 25-03 and its supplemental direction, AR26-113A, Cisco's event response and detection
guide and the Talos FIRESTARTER post, and a check of the draft against its saved sources
refused it on two claims, a date given the ASA campaign by adjacency to its disclosure and a
credential-monitoring instruction that dropped CISA's word "unauthorized", so no record ships
and nothing below depends on one. Also left, each in the maintainer's list with its reason:
`LOCUS_ANALOGUE_ONLY` still tells a PAN-OS or Check Point reader not to report `MANAGEMENT`
while the vendor's own exposures sit there, and `EXPOSURE_LOCUS` still counts tier
`vendor-class` on a product question, so the ASA's `MANAGEMENT=3` is the management centre's,
one split owed together; FortiGate identifiers whose catalogue text names no component the
identifier table reads, the FortiCloud SSO logins and CVE-2024-23113 among them; whether
PAN-OS, GlobalProtect and the other gateway aliases carrying one of the firewall and VPN
gateway classes should carry both; the Cloud Service Appliance's plane; the S7 controller
sweep, read from flow and IDS records, which keeps the management interface; and whether a
handset product alias lends its class.

A generated exposure's identifiers are read by their own words (scope-known major 1,
scope-alias major 0, scope-new-record major 0). A generated record's class is one value for
every identifier it carries and its surface is not read, so FortiOS's super-admin bypasses
printed CONTROL beside a finding placing the same CVE on MANAGEMENT, PAN-OS's management web
interface flaws printed CONTROL alone, and "Check Point VPN" listed none of the vendor's VPN
flaws. The KEV, PSIRT, ZDI and database generators (`_ingest/kev/generate.py`,
`_ingest/psirt/generate.py`, `nvd_generate.py` and `huawei.py`, `_ingest/zdi/generate.py`,
each backed up first and each now requiring `--corpus`) write `what.identifier_signals`: for an
identifier whose catalogue description or name, advisory title or database description names
an administrative component -- a management or administrative interface, console, portal or
page, the configuration utility or backup, a super-admin account, the CLI or SNMP -- a
`MANAGEMENT` entry, and for a VPN feature on a network device a `network.vpn_gateway` entry,
each with its rule, words and field. A rule's `unless` words put a text in another sense: the
VPN rule's are a provider VPN's (VRF, MPLS, L2VPN, L3VPN, EVPN, VPLS), because a review found a
NetEngine router's VRF hopping flaw, CVE-2015-8087, read as a VPN gateway's and listed under
"Huawei VPN"; regenerated, the Huawei record lost that one entry and nothing else, and over
the 9,915 texts the generators read it is the only VPN text naming them. The rule is the table
`identifier_reading` in the locus map and one reader in `scripts/query.py`, which the
generators load from the bundle and `validate.py` re-reads with every catalogue description
quoted by a known-exploited record the rule reads (900 across 515 records), both ways and
whether or not the record carries the key, so an entry the rule would not write, or a missing
one, fails until the record is regenerated.
A review found that re-read returning early on a record with no key, so it ran on 156 of the
900 and a record whose field was dropped passed while its exposure moved plane; an absent key
now reads as no entries. An advisory title or database description is quoted by no identifier
in a record, so those entries are held to the table only, and the field is refused on an
observation or a hand-written exposure. A record listing an `ENDPOINT` class or
`dev.library` first is not read. A locus every identifier reads decides the primary (an
`identifier` tier directly above `class_first`); otherwise the plane most of them read is the
span (an `identifier` span source after `surface`), so FortiOS's two super-admin bypasses
beside two SSL-VPN flaws, and PAN-OS's four management web interface flaws among twelve
(the TODO's fifth, CVE-2017-15944, is "multiple, unspecified vulnerabilities" in the
catalogue), print `CONTROL, MANAGEMENT`, the basis naming each identifier with its words, and
the exposure header gains `EXPOSURE_LOCUS_SPAN`, counting what the blocks print after their
primary. A class read this way never decides and widens only the vendor-class tier, for the
vendor the question named: "Check Point VPN" lists the three Check Point VPN flaws, its
`EXPOSURE_MATCH` naming the identifier whose text reads the class, and "VPN gateway" counts the
30 class-only exposures it did. 89 of 858 generated records carry the field (KEV 59, database
19, PSIRT 10, ZDI 1; 191 entries), regenerated and merged with no other field moved; 24 move
primary to `MANAGEMENT` (20 from `CONTROL`, 2 from `DATA`, 2 from `SUPPLY`) and 45 more gain a
span, across 24 vendors, and the exposures place `CONTROL` 266, `MANAGEMENT` 131, `DATA` 264,
`ENDPOINT` 148, `SUPPLY` 79, `ORGANISATION` 6, with 76 carrying a span where 7 did. Three
placements are judgements, stated rather than hidden: both Jenkins records move `SUPPLY` to
`MANAGEMENT`, their CLI being Jenkins's administration, with `SUPPLY` the span; NETGEAR's
CVE-2016-6277 and CVE-2016-1555 read "command-line interface" where the catalogue names the
sink their web pages inject into; Openfire and FortiMail move `DATA` to `MANAGEMENT` on admin
console and administrative portal flaws, with `DATA` the span. The 0.43.0 statement that a
device's own management interface stays in its class is retired for every identifier whose
text names one. J-Web, an unqualified "web UI" or "web interface", IKE, SSH and Telnet, and
authentication wording naming an administrator were measured and left out, each with its count
in the locus map's `_why_identifier_reading`, and text naming no component still sits on the
class's plane. No observation, pattern or how-block moves, the generated `attack_surface` is
still not read, and no record was corrected by hand. Also closed: 0.43.0 coverage minor 3,
scope-alias minor 3, locus-consistency minor 2 and scope-new-record minor 0 (Check Point
Multiple Products keeps `MANAGEMENT` by `app.rmm` and carries its gateway VPN identifier's
`CONTROL` as its own span, whatever the question asks).

One product, one set of classes, whichever name is typed (scope-known major 0).
`product_families` declared FortiGate and FortiOS one product while `fortigate` resolved
`network.firewall` and `fortios` `network.vpn_gateway`, so "Fortinet FortiGate" matched 78
findings, named DATA absent and never reached the AA26-222A Gunra record carrying FortiOS's own
catalogue identifiers, while "Fortinet FortiOS" matched 116 and dropped FortiManager from the
vendor tier. Both aliases now carry both classes, the union of what they carried, so no
question loses a class: the two answers match the same 154 findings and differ only in the
name they print, the Gunra record is a class analogue at ranks 20 to 22, and the twelve shown
for FortiGate are unchanged. With the identifier reading above, three of the vendor's
VPN-gateway exposures (FortiProxy, FortiSwitchManager, the FortiClient VPN) join FortiGate's
vendor-class tier, so it counts 12 exposures where it counted 9, its own seven first, and the
FortiGate header pin in `tests/test_identifier_signals.py` is re-measured to `CONTROL=9,
MANAGEMENT=3`. A family declares no classes of its own and the resolver unions nothing at run
time, which would have taken each of the Cloud Service Appliance's three names to 202 findings
on generator defaults the alias table copied. `tests/test_product_identity.py` now asks every
name of every family beside its vendor for its own product and one class set, and reads every
product the resolver joins by canonical equality for the same. Asked so, two families failed,
each mended by an alias for a name the family declared and the table never held: "Secure
Firewall Threat Defense" resolved no product, and "Firepower Management Center" resolved
Firepower Threat Defense, 216 findings where it now matches the management centre's 149.
"Firepower threat defense" is an alias too, since the full name left "threat" as free text and
added 46 findings by tag, pattern wording and summary. A sector alias is no longer matched
inside an admitted product name, so "defense" in Threat Defense no longer makes an FTD question
a defence-sector one: "Cisco Firepower Threat Defense" prints what "Cisco FTD" prints, and 13
other product aliases, "Ruby on Rails" and "Kerberos Key Distribution Center" among them, stop
naming a sector from their own words, while the same word outside a name still does
(planes-network minor 8). The SIMATIC S7 series is a family whose components are its five
lines, so on "Siemens S7" the AA26-231A record, which lists all five, is a product match at
ranks 1 to 6, where it sat below a multi-vendor record with `MATCH_TIERS` reading product=0
beside `RESOLUTION: product`; `s7` is gated, since a bare S7 is also a handset, and `s7comm`
names the series (planes-ot minor 3). "aws" and "amazon web services" name the vendor Amazon,
whose twelve records are all AWS services, so an AWS answer no longer calls its IAM, EC2, EKS
and Lambda findings another product than the one asked about; it shows the same 39 findings in
the same order on the same planes (planes-cloud minor 4). Of 3,124 questions formed from every
alias and every family name and component, bare and beside its vendor, 58 resolve
differently: 33 naming the products joined here, 21 whose only change is a sector a product's
own name supplied, and 4 asking for AWS. Asked of `consult.py` with every finding shown, those
58 and every Amazon alias (116 questions), no finding's plane moves on a block both answers
hold, and the lookup, advise, emit and validate outputs are unchanged. Six products are pinned
open in the tests with their reasons: the Cloud Service Appliance, classed three ways, which is
the maintainer's plane decision (scope-mgmt-plane minor 2), and Sentry (scope-mgmt-plane minor
1), Virtual Traffic Manager, Junos OS, Identity Services Engine and WebLogic, whose aliases
disagree outside any family; Policy Secure, which no alias names, is pinned in the family test.
PAN-OS and GlobalProtect keep `network.firewall` alone (scope-alias minor 4): the VPN class is
one case of a rule twelve other aliases would share, the ASA's, AnyConnect's, Threat Defense's
and Check Point's gateways among them, and is left for that decision. Three fixtures in
`tests/test_subject_tiers.py` that used FortiGate for a vendor named only inside a generic
record now use FortiManager, since FortiGate's VPN class makes that record a class analogue.

Block evidence against its record's plane (planes-cloud major 0, planes-ot major 0). A
record-level plane decided a block whose own evidence read none of it. The Siemens S7 record's
library-artefact block, read from EDR and file evidence alone, printed `MANAGEMENT` from the
record's management interface, so both Siemens answers named `ENDPOINT` absent; the AWS
Kubernetes node-credentials block, a container's metadata credential request paired with the
node role's first cloud API call, printed `CONTROL` from `cloud.container` listed first, the
only Amazon-named `CONTROL` finding, so the AWS answer claimed `CONTROL` coverage it does not
hold. Three tiers join the ladder and one widens, each placing a block only where its evidence
reads nothing on the plane it displaces, and every evidence test now reads one deciding set
(`deciding_planes` in `scripts/consult.py`). `host_evidence`, after `surface`: a committing
surface is set aside for a block past the way in that reads only host evidence, which sits on
`ENDPOINT` with the surface as its span. `admin_api_listed` and `host_listed`, before
`identifier` and `class_first`: a record's block reading nothing on its first-listed class's
plane sits on `MANAGEMENT` when the record lists a class in `administrative_api_classes` after
the first and the block reads that API for more than a use of the service, and on `ENDPOINT`
when the record lists an operating system, browser or agent class after the first and the
block reads only host evidence. `operation` also places a block whose only deciding evidence
is the provider's audit trail (`cloud_audit` its one `MANAGEMENT` type) and which tests an
administrative operation there beside other fields of the same event; 0.43.0 kept the Bedrock
model-access block on `CONTROL` for its user-name and agent markers, and the fourth validation
read them as fields of the same CloudTrail event, so that recorded outcome is reversed, and an
S3 caller-identity block changes tier only. A contested type now takes no part in whether a
surface reaches a block either; no corpus block depended on it. Eleven blocks move and no
pattern or exposure: `CONTROL` 214 to 206, `MANAGEMENT` 153 to 155, `DATA` 81 to 79, `ENDPOINT`
182 to 190, spans 360 to 354. AWS prints `LOCUS_SUBJECT: CONTROL=0` and `LOCUS_ANALOGUE_ONLY:
CONTROL, ENDPOINT`, and `LOCUS_ABSENT` names `ORGANISATION` alone; Siemens and "Siemens S7" no
longer name `ENDPOINT` absent, with the same twelve findings in the same order; "Microsoft
Exchange" changes header counts only; every other regression question is byte-identical. The
restricted-library Unix credential-file block and two AI-platform host blocks read `ENDPOINT`
in the "Linux kernel" listing, and `pat-credential-file-read-by-interactive-tool` is observed
on `ENDPOINT` alone, its span `ENDPOINT`. Wider rules were measured and not taken: evidence
outranking any record plane it contradicts moved 129 blocks and 67 patterns, 32 blocks of
endpoint records onto `DATA` among them; any single third plane setting a surface aside put
SNMP probes on `DATA` and a dropped table on `SUPPLY`, so the S7 controller sweep keeps the
management interface; the host rule without a listed endpoint class moved 23, about half onto
products with a plane decomposition; reading library patterns moved 18, four CI/CD patterns
onto `MANAGEMENT` among them, and lowered pattern-to-block agreement from 481 to 478 of 755
pairs. The audit-trail case requires `cloud_audit` to be the block's only `MANAGEMENT` evidence,
narrower than the design's any-`MANAGEMENT` reading, so that its basis words are true; the
corpus result is the same. 13 tests in `tests/test_locus_block_evidence.py`, every one but the
S7 must-not-move test failing before the change; 6 existing tests that pinned the old ladder
follow it, among them the 0.43.0 pin of the Bedrock block, whose host-evidence counter-case
now reads `edr_process` beside the audit trail. Also closed: 0.43.0 planes-ot minor 1,
query-kev-growth minor 3 and revoked-and-family minor 4.

A product question's subject is the product (planes-network major 1). `LOCUS_SUBJECT` counted
tier `vendor` beside tier `product` for every question, so "Cisco ASA" counted three Secure
Firewall Management Center blocks as its `MANAGEMENT` plane, reserved the plane for them and
left it out of `LOCUS_ANALOGUE_ONLY`, though the management centre administers Firepower Threat
Defense and not ASA software and each block printed "but not the product asked about"; rule 9
then headed the management centre as the ASA's management answer. `consult.py` now decides the
subject per vendor (`question_subject()`): a vendor-tier finding names what was asked only
where the question named that vendor without a product of it, so "Cisco ASA and Fortinet
firewall" still counts Fortinet's records and not the management centre, and "SimpleHelp", the
vendor's own name, still counts its vendor's records. Where nothing names the product, the
vendor tier keeps the reserve it had and the lines name it as the vendor's. The ASA reads
`LOCUS_SUBJECT` `MANAGEMENT=0` and `LOCUS_ANALOGUE_ONLY` lists `MANAGEMENT` with `vendor 3` in
its bullet; the same findings show. Over the 1,459 product and vendor alias keys, 1,176 answers
keep every header line and shown finding, every question naming only a vendor or nothing among
them; 188 naming a product nothing names change only those lines' wording, which no longer
names the product beside a `RESOLUTION` saying nothing does; 95 holding another of the vendor's
products beside the product change their counts, 76 gaining a plane in `LOCUS_ANALOGUE_ONLY`
and 5 their shown set, each by giving a vendor-tier reserve back, and no product-tier finding
leaves any answer. Some of the 95 are the same product under a name the alias table does not
join, "Windows" and the NetScaler keys among them, where the header now agrees with the
`MATCH_BASIS` those findings already printed; "AWS" left that set when it became a vendor alias
above. Inside group 0, such a finding now follows the findings naming what was asked
(`PRIORITY_BASIS` says "after what was asked"): the management centre took ranks 1 and 2 of
"Cisco ASA", FortiManager ranks 2 and 3 of "Fortinet FortiGate" and Outlook ranks 1 and 2 of
"Microsoft Exchange", and 66 of the 95 led with another product; now each leads with its own,
22 show 40 product-tier findings in place of 40 vendor-tier ones (5 under
`--per-locus 3 --limit 18`), and no product-tier finding leaves any answer. This reverses the
0.43.0 judgement that product and vendor share the group unordered; the vendor tier still
precedes every class analogue, so "Palo Alto Networks Panorama" keeps the GlobalProtect record
first. An absent locus that is shown says `shown K, none eligible` in its `LOCUS_ABSENT`
bullet, where `LOCUS_SHOWN` counted it beside the line naming it absent (0.43.0 planes-role
cosmetic 3): 101 of the 1,459 answers gain it, 31 of them naming nothing, and no shown set
moves. Under `--role`, `RESOLUTION` and `CLASS_LEVEL_WARNING` say "no observation --role kept"
and count the observation records naming what was asked that the filter dropped, where they
said the corpus held none (0.43.0 planes-role minor 0): "Palo Alto firewall"
`--role telemetry_source,inline_tool,control_bypassed` had dropped one. SKILL.md rule 9 asks
for each analogue-only finding's own product from `TECHNOLOGY`, paid for by moving the
`identity` tier's history, already in `references/resolution.md`, out of the card. Two quota
fixtures that leaned on a vendor-tier reserve, the ASA's and Windows', moved: underservice is
exercised on "Fortinet FortiGate", and `--per-locus` on "network firewall". Also closed: the
second half of the fourth validation's exposures-library cosmetic 10 ("none names Exchange
Server, Microsoft" over findings naming Microsoft).

A bare handset name is refused, and the handoff says which seed block is unconfirmed
(exposures-library major 0, locus-consistency major 0). Asked "iOS", "iPadOS", "watchOS" or
"iPhone", names that resolve nothing because the scope decision forbids a handset alias,
`consult.py` answered `UNRESOLVED` with `handset=0`, counted Apple's handset-only records
`prose-only`, said no record's prose carried the words over an `EXPOSURES_NOT_LISTED` counting
nine, and advised adding the alias. `corpus/schema/scope.json` gains `handset_names` (ios,
ipados, ipad, iphone, mali, snapdragon, watchos), the question side of the same decision: a
question that resolves nothing and carries one counts the handset records it names `handset=`
("iOS" 3, "iPadOS" 2, "watchOS" 1), gives the reason on `RESOLUTION`, still exits 1, and points
at the mobile management plane (`--as app.mdm`) instead of `aliases.json`; beside a resolved
vendor ("Apple iOS") the `EXPOSURES_ONLY` answer keeps its listing and points there too,
instead of at `--as endpoint.os` (the first two halves of 0.43.0 exposures-library minor 1).
`query.py` says the same where nothing matched, rule 7 no longer offers a handset alias, and
`validate.py` refuses a listed word an unambiguous alias would consume first. Counting any word
that stands in a handset product's name was measured and refused: "gpu" and "audio" read as
handset questions. The bare `UNRESOLVED` line no longer denies the exposures its own header
counts. `emit_xql.py` handed a rule author a block its own record calls unconfirmed at
confidence high with no status: every handoff now carries `status`, `seed_support` and
`provenance.disclosure`, `.retrieved` and `.verified`, and the 9 seed skeletons print the
consultation's own `STATUS` line. A re-read seed record now says per block whether its source
supports it (`how[].unconfirmed`), so `STATUS` names the meaning that applies rather than
pointing at notes nothing prints (0.43.0 contract minor 5), `advise.py`'s `OBSERVED` counts
which citing blocks a re-read source supports, and its `CONTRACT` names the `[SEED]` bracket it
prints rather than a `STATUS` key it never did. `validate.py` refuses the flag unset on a
re-read seed or set on a verified record, `status: verified` beside `where.verified: false`,
and `confidence: high` on any block `STATUS` calls NOT CONFIRMED; a blanket seed rule was
rejected, because four of the eight high seed blocks are the halves their re-read sources
support. Four hand-written records moved, each cited page fetched once on 2026-10-02 and read
for the block: obs-fortinet-product-family-breadth-and-management-reach how[1] (the watchTowr
post describes the CVE-2024-55591 authentication bypass, names FortiProxy only as the other
product the advisory lists, and describes no product of the family managing or monitoring
another), obs-generic-incident-response-trend-base-rates-2022-2026 how[0] (the Talos report
covers the second quarter of 2026, its logging base rate and its two remote management tools,
compares some figures with the quarter before, and reads no series back to 2022) and
obs-juniper-scheduled-release-cycle-and-web-management-exposure
how[0] (the watchTowr post describes the J-Web chain, calls the bulletin out of cycle and
states no release schedule) high to low, each the part the re-read source does not describe,
their supported blocks flagged and kept at high; obs-cisco-asa-vpn-webvpn-implant how[1] high
to medium, the Talos post supporting its new-file half, a file appearing on the appliance's
disk after the fixed release, and not its integrity-check half, which the post names only as
forensic practice the actor understood, and its title, a placeholder, is now the post's own.
That record was read for its title and that block only, as its notes now record, and stays
seed with `where.verified` false: confirming its CVE pairing and dates is planes-network major
0's re-read. The `_ingest` drafts that once
wrote three of the four predate their hand edits and were not touched. Over 4,679 questions
(every alias key, every vendor and product string and token, and the probes) 570 answers move
and no exit code: 20 handset refusals, 446 `UNRESOLVED` lines that were false, 3 mechanism
counts, 6 "Apple" handset answers, and 95 seed `STATUS` lines (34 with the ArcaneDoor title);
no ranking, order or locus moves anywhere. `emit_xql.py --all` gains 9 lines and nothing else;
over its 703 handoffs `confidence` moves on exactly those four blocks and `provenance.title` on
the two ArcaneDoor blocks. Of the 22 baseline consult probes 12 are byte identical, and the
validate output is. 28 tests fail before the change: 17 in `tests/test_consult_exposures.py`, 9
in `tests/test_emit_syntax.py`, `tests/test_support_line.py` and
`tests/test_advise_findings.py`, and the two updated `OBSERVED` and `CONTRACT` tests; 15 hold
either side, among them that "Apple" alone keeps its `--as endpoint.os` pointer and that
neither "Fortinet FortiGate" nor "Cisco ASA" moves a finding. `SKILL.md` rules 3 and 7, its
query paragraph and item 4 of Reading the result move, 2 words shorter.

A management product beside a handset name is a gap in the alias table, not a handset question
(the two independent reviews of the paragraph above: a major and seven minors). The bare
refusal caught every question that resolved no vendor, product or class and carried a handset
name, so "Kandji for iOS", "Mosyle iPad", "MaaS360 iOS", "Hexnode watchOS", "Jamf iOS" and "SOTI
MobiControl iPhone", which name the management plane the scope keeps in and whose products have
no alias, were called out of scope as handsets and told no alias was missing, where they had
been told to add one. A word of the question that reached no record and is no refused alias's
(`consult.unknown_names()`) now stops the refusal: `RESOLUTION` says the word reached no record
and still counts the handset records `handset=`, and the add-an-alias paragraph names it, says
never to add the handset name, and offers it, where it is written with a capital or a digit as
`MECHANISM_WARNING` requires, as the product managing the devices (`app.mdm`); `query.py` says
the same where nothing matched. "arm" in "Arm Mali", Arm's refused vendor alias, is a name the
table holds and does not stop it. A resolved sector stops it too, as the references said
anything resolved did: "banks in Mali" and "Mali government ministries" named a country and
were refused as Arm's GPU; beside a sector the paragraph says never to add the word and offers
`--as app.mdm` on the condition that it names a handset ("iOS in government"). The bare refusal
now prints in place of the class re-ask, which offered `endpoint.os` among all 61 classes
before saying handsets were out of scope; says the word "is listed in corpus/schema/scope.json
as a handset name", the table's word, where "snapdragon names a handset" overstated a record
that also lists laptop, vehicle and module parts; says "A handset name is never an alias to
add" where "No alias is missing" claimed more than it checked; and, for a bare "IOS", says ios
is also the alias of Cisco IOS, refused as `GATED` says, and to ask "Cisco IOS". The "Apple iOS"
`METHODOLOGY` reads "and ios names a handset", where "so" made the missing observation its
reason. ArcaneDoor's `STATUS` said "the source was not re-read" over a block this batch had
re-read and lowered: the unread seed text, `advise.py`'s `CONTRACT`, `SKILL.md` rule 3, the
schema, `references/emit-xql.md` and `corpus/README.md` now say "not fully re-read against its
source", which is what `where.verified: false` records, and obs-cisco-asa-vpn-webvpn-implant's
`notes` record the one-block read (the Talos post fetched again on 2026-10-02 with the sync user
agent, byte identical to the batch's copy); `seed_support` stays `unread`. Two of the four
justifications above overstated the batch's own fetched pages and are corrected there: the
FortiRekt post names FortiProxy as the advisory's other product, and the IR Trends report
compares figures with the quarter before; neither describes the block lowered, so no flag or
confidence moves. Over 4,703 questions (the 4,679 above and 24 handset probes) 80 answers move
against the paragraph above and no exit code: 21 bare refusals reworded, every one of the 4,679's
20 still a refusal; 19 refusals that are alias gaps again, all probes, 13 beside an unknown name
and 6 beside a sector; 6 "Apple" handset `METHODOLOGY` lines; and 34 ArcaneDoor `STATUS` lines.
No finding, rank, order or locus moves, and `EXPOSURES_NOT_LISTED` only on the five sector
questions, whose handset records count `prose-only` again ("banks in Mali", "iOS in
government"). `emit_xql.py --all` moves the two ArcaneDoor `// STATUS:` lines and its JSON
nothing; `advise.py --attack T1190` its `CONTRACT`. 23 tests fail before the change: 12 new
(`tests/test_consult_exposures.py`: the unknown name, the sector and both meanings of "IOS";
`tests/test_support_line.py`: ArcaneDoor) and 11 updated; the "Arm Mali" guard holds either
side. `SKILL.md` stays at 4,982 words.

A name beside a handset name is the word the plane turns on, and an ordinary word is no name
(the two independent reviews of the paragraph above: a major and four minors). The fix above
let any word that reached no record stop the refusal, not only a management product's name: 22
questions the paragraph before it refused, "iOS spyware", "iPhone spyware", "stalkerware on
iPhone" and "iOS jailbroken" among them, were told they were a gap in the alias table with the
ordinary word as the term to add, and "Pegasus iOS" and "iOS iMessage" offered a spyware family
and a handset app as the product managing the devices (`app.mdm`). `consult.unknown_names()`
now takes only a word written as a name, holding a letter and written with a capital or a
digit as `MECHANISM_WARNING` reads one, and no such word stops the refusal: nothing in "Kandji"
or "Pegasus" says whether it manages the devices or runs on them, so the two get one answer.
`RESOLUTION` reads "out of scope as a handset (corpus/schema/scope.json) unless kandji names the
product that manages these devices", and the refusal, headed "THE QUESTION NAMES A HANDSET,
BESIDE A NAME THIS CORPUS DOES NOT KNOW", says the plane turns on that word and gives both
conditions: the mobile management plane, in scope, with the name an alias to add under
`app.mdm`, or a handset question with nothing to add. `query.py` says the same, and a lower-case
"kandji ios" is refused as it was before that fix. A resolved sector no longer stops the refusal
for every handset name: `corpus/schema/scope.json` gains `handset_names_also_places` (mali), the
handset name that is also a place, which a sector reads as the place, so "banks in Mali" is
answered and "iOS in government", "iOS banking apps" and "iOS devices in hospitals" are refused
again with Apple's three handset records counted `handset=`; `validate.py` refuses a place that
is no handset name. Several handset names agree in number ("no exposure record names them").
The `SUPPORT` flag under ArcaneDoor's `STATUS` line still said `SOURCE_NOT_RE-READ`; it is
`SOURCE_NOT_FULLY_RE-READ`, what `where.verified: false` records, and `SKILL.md`'s Reading the
result and the schema's `unconfirmed` description say "not fully re-read" too. `validate.py`
refuses `how[].unconfirmed` on a seed not fully re-read, where `seed_support()` never reads it,
as the schema already said. Over 4,791 questions (the 4,703 above, the reviews' 38-word "iOS"
sweep and 50 handset probes) 85 answers move against the paragraph above and no exit code: 29
alias gaps are refusals again (21 sweep words, four sector questions, "iPhone spyware",
"stalkerware on iPhone", "iPad jailbroken" and "kandji ios"); 20 beside a name carry the refusal
and its two conditions (14 management product questions, "Pegasus" and "iMessage" twice each,
"checkm8", and "Spyware on iOS", whose sentence-case first word reads as a name); "Mali
government ministries" no longer names "ministries" as the word to add; "iPhone and iPad" agrees
in number; and 34 ArcaneDoor `SUPPORT` lines. No finding, rank, order or locus moves, and
`EXPOSURES_NOT_LISTED` only on the three "iOS" sector questions. `emit_xql.py --all`, its JSON,
`validate.py` and `query.py "Linux kernel"` are byte identical, and `advise.py --attack T1190`
moves nothing. 30 tests fail before the change, in `tests/test_consult_exposures.py`,
`tests/test_support_line.py` and `tests/test_emit_syntax.py`; the "iOS 18.1" and "Arm Mali"
guards hold either side. `SKILL.md` goes from 4,982 to 4,979 words.

Closing the round. Each major's exposing probe was re-run against this release from the bundle
root with `--today 2026-10-01`, and nine no longer reproduce as reported: "Fortinet FortiGate"
and "Fortinet FortiOS" match the same 154 findings; the FortiOS and FortiProxy exposure carries
`MANAGEMENT` in its span for CVE-2024-55591, beside the finding placing that identifier there;
"Check Point VPN" lists the vendor's three VPN flaws; both PAN-OS exposures read `CONTROL,
MANAGEMENT`; the ASA's `MANAGEMENT` is analogue-only; the AWS Kubernetes node-credentials block
sits on `MANAGEMENT` and the S7 library-artefact block on `ENDPOINT`; "iOS", "iPadOS",
"watchOS" and "iPhone" are refused as handsets; and the Fortinet seed record's unsupported block
hands off at confidence low with its status. planes-network major 0 reproduces as described
above. Shipped counts that had drifted are re-measured, all but the last before this round:
`SKILL.md`'s Portkey example matches 116 findings with four classes, not 119, and with one class
leaves `ORGANISATION` alone empty, not three loci; "prompt injection" reaches 95 findings, not
99; 89% of observations carry no `SUPPORT` flag, not 85%; the README's licence notes name
SigmaHQ in 443 patterns' `external_corroboration.sources` and Splunk in 432, not 444 each;
`references/exposures.md` dates its two measurements over 1,097 alias resolutions to 0.43.0,
since this release's alias changes moved the table; and `references/locus-and-coverage.md` says
101 of the 441 cited patterns print a locus none of their citing blocks sits on, 104 at 0.43.0,
where it gave 147, the figure when first measured. No code, record or test changes. `SKILL.md`
goes from 4,979 to 4,976 words.

## 0.43.0

THE PLANE ANSWER, MADE TRUE FROM THE RESOLVER TO THE HANDOFF. A validation pass on 2026-09-25 put
twelve probe questions to this skill and passed none of them: four failed and eight came back
degraded. Every cited id was real; what was wrong was ranking, labelling and code. `consult.py`
could not return an exposure for any question; it ranked a fresh class analogue above a record
naming the product and labelled both "named this technology"; ordinary words resolved as product
names; a sector tag or the way an attack arrived decided which plane a finding sat on; the locus
quota filled planes with off-topic filler; `advise.py` read a key no pattern carries;
`emit_xql.py` printed pseudo-code into live filters; and one record carried identifiers its
source never names. 0.43.0 fixes all of it, and the measurement behind each fix is in the detail
below. This entry gives, in order: every change a consumer of the output will see, the
decisions taken on the maintainer's behalf, what is left and why, and then the detail by area.

Against 0.42.0 the corpus holds 1,142 records rather than 1,158 -- two observations added and
one removed where a record was split, ten KEV records merged into their survivors, and seven
PSIRT records gone once an advisory is attributed only where its vendor marks a product
affected -- and 475 patterns. 110 observations, two hand-written exposures, 461 generated
exposures (ZDI 67, KEV 302, PSIRT 48, database 44) and 154 patterns changed. 2,235 tests pass,
against 759 at 0.42.0, and 2 are skipped; the validator reports no problems and `SOURCES.md` is
current. Figures in the detail were measured as each change landed, over the corpus and code as
they then stood, so a figure there describes that change rather than the release as a whole.

FOR CONSUMERS -- EVERY CHANGE TO WHAT THE SCRIPTS PRINT OR ACCEPT:

`consult.py`, the header (`references/answering-another-session.md` lists every key in order,
and a test holds the list to the output):
- `RESOLVED_TO` gains `| sectors=`, appended so the rest of the line keeps its shape.
  `RESOLVED_BY` follows it, naming the alias behind every value and what admitted an ambiguous
  one, and `GATED` prints when a word matched an alias and was refused, with the reason.
- `CLASSES_FROM_VENDOR` prints for a question naming only a vendor: the classes of the
  vendor's own observations, used for scoring only.
- `ROLE_FILTER` prints under the new `--role`, counting what the filter kept.
- `RESOLUTION` has two new modes, `VENDOR-LEVEL` and `EXPOSURES_ONLY` (exit 0, no findings,
  exposure blocks and an `--as` re-ask). `NAME_WITHOUT_RECORDS` is renamed
  `NAME_WITHOUT_OBSERVATIONS`: a consumer matching the old label must match the new one.
  `UNRESOLVED` now means no observation and no exposure names it, and has a handset form. Every
  mode text says "observation" where it said "record", and a line names the exposure records
  naming what was asked, by tier.
- `CLASS_LEVEL_WARNING` prints for every mode but `product` and `mechanism`, worded for the
  mode. It remains the one key to gate on; there is no second warning key.
- `UNMATCHED_TERMS` prints on every consultation. `MECHANISM_WARNING` and `CANDIDATE_CLASSES`
  print when a mechanism answer left a word that looks like a name unmatched.
- `MATCH_TIERS` reads `product=, vendor=, class=, vendor-other-class=, tag=, name-fragment=,
  pattern=, summary=`. `identity=` is gone rather than kept beside them, because the value it
  read was wrong: "PAN-OS" printed `identity=74` over 3 findings naming PAN-OS. A consumer that
  gated on `identity=0` gates on `product=0, vendor=0, class=0`.
- `ORDERING` describes the grouping by match tier, then a named sector, the question's leftover
  words, the platform fit and the score, and under `--rank-by gap` the demotion of what
  `--covered` says is implemented.
- `LOCUS_SPREAD` states the slots reserved per locus. `LOCUS_ELIGIBLE` is new, after
  `LOCUS_MATCHED`, in the same shape. `LOCUS_ABSENT` names the loci with no eligible finding,
  where it named those with no match, so it can only name more; its first line keeps its shape,
  and each absent locus gets a bullet: `  - DATA: matched 3 (loose 3, below floor 0);
  span-only 1; exposures 2; library 1; best ineligible rank R, score S, tier T, <FINDING_KEY> /
  <pattern>`, or `  - DATA: matched 0; span-only N; exposures E; library L`.
- `LOCUS_DISPLACED` and `LOCUS_RESERVED` bullets name the finding by `FINDING_KEY` and add
  `tier <tier>`; in gap mode a bullet's score is followed by its criticality before coverage. A
  displaced finding the record cap chose says so. The two lists stay the same length.
- `RECORD_CAP` is new on every consultation: `2 per record within a match group; <t>
  finding(s) from <r> record(s) passed over in the top <N>: ...`, with bullets in the same
  format, or `RECORD_CAP: off - ...` under `--no-locus-spread`. `LOCUS_DISPLACED` plus
  `RECORD_CAP` bullets are exactly what the shown set lost against `--no-locus-spread`.
- `LOCUS_UNDERSERVED` counts the loci a slot is reserved for, and the slots `--per-locus` asks
  for when it is above 1.
- `LOCUS_SUBJECT` is new, after `LOCUS_ELIGIBLE` and in its shape: per locus, the eligible
  findings in tier `product` or `vendor`. Where the question named a product or vendor and a
  finding names it, only these fill a reserved slot, and the aside says so; it reads `not
  applicable - ...` for a question naming neither. `LOCUS_ANALOGUE_ONLY` is new, after
  `LOCUS_ABSENT`'s bullets, on every consultation: the loci whose eligible findings are all
  analogues, with a bullet each, `  - DATA: eligible 1 (class 1); first rank R, score S, tier
  T, <FINDING_KEY> / <pattern>; shown N`, or `none - ...`, or `not applicable - ...`.
  `LOCUS_SPREAD` names which of the two a reserved slot is filled from, and `LOCUS_ELIGIBLE`'s
  aside says it keeps a locus out of `LOCUS_ABSENT`.
- `DECLARED_TELEMETRY_REJECTED` is new, naming every `--have` value refused.
- After the coverage lines and before `CONTRACT`: `EXPOSURES`, `EXPOSURE_KINDS`,
  `EXPOSURE_LOCUS`, `EXPOSURES_NOT_LISTED`, `EXPOSURE_ORDERING`, `EXPOSURE_DATA_GAP` (with
  `MISSING` and `RECOMMEND_ACQUIRE` bullets), `EXPOSURE_SCOPE`, `LIBRARY_PATTERNS`,
  `LIBRARY_LOCUS` and `LIBRARY_ORDERING`. Every count but `shown` is before the block's limit.
  An `UNRESOLVED` answer prints `EXPOSURES_NOT_LISTED` before `FINDINGS` when the question
  reached any exposure.
- `NO_FINDINGS` tests the match set rather than the shown set, names what resolved, says what
  matched before a `--role` filter, and counts the exposure records reached and not listed.
- `CONTRACT` adds that `EXPOSURE` and `LIBRARY` blocks are not findings and may not be
  presented as one.

`consult.py`, each finding (the key set grows by three keys, identically on every finding):
- `SLOT` follows `RANK`: `natural`, `replacement`, `reserved` or `backfill`, then why. `RANK` is
  the finding's position in the whole `ORDERING` order, the number the header's bullets cite,
  where it was the position in the shown set, so it gaps where the quota skipped;
  `=== FINDING i OF n ===` stays positional.
- `FINDING_KEY: <record-id>#how<n>` follows `PATTERN_ID`. It is unique, where `RECORD_ID` with
  `PATTERN_ID` is not, and `emit_xql.py` takes it.
- `MATCH_TIER` precedes `MATCH_BASIS`, and `MATCH_BASIS` names what matched: `PRODUCT - names
  the product asked about (PAN-OS)`, `VENDOR - ...`, `VENDOR, OTHER PRODUCT LINE - ...`,
  `CLASS-LEVEL - ...`. "named this technology" is never printed. A record naming the product
  by another of its names says how, `(FortiOS (as FortiGate))`, `(FortiGate SSL VPN (a
  component of FortiGate))` or `(FortiOS and FortiProxy (FortiOS, as FortiGate))`, and
  `EXPOSURE_MATCH` does the same. A tag match names its word: `tagged with a term from the
  question (edge)`. A block of a campaign record (filed under `any` or `Multiple`, listing an
  entry that does not name what was asked) adds what it concerns: `...; the record lists 4
  product entries, and this block concerns it: its own words read for server.hypervisor
  (hypervisor, ...), a class of what was asked (ESXi)` (its own words being its logic and
  caveat, never a path or string it matches), `... this block concerns it by kind: ...`, `...
  this is the record's only block, and the pattern it cites (...) is written for ...` or `...
  nothing else the record lists reads as a product, a vendor or a class ...`; where it
  concerns another product, or gives no reading either way, it falls to the record's class or
  a name fragment and reads `CLASS-LEVEL - the record names the product asked about (...) among
  its 3 product entries, but this block concerns another: ...` or `... but this block concerns
  the campaign, not it: ...`. No block keeps the tier by default. Where every block of the
  campaign records naming what was asked fell, `RESOLUTION` and `CLASS_LEVEL_WARNING` say so in
  a parenthesis, `(1 campaign record(s) list it among what a campaign reached, and every block
  of theirs concerns another product or the campaign, as MATCH_BASIS says)`, and say no
  observation is about it rather than that none names it.
- `PRIORITY_BASIS` prints `match=<tier>x<weight> (group <g>)`, or `(group <g> after
  coverage=yes)`, then `sector=`, `platform_fit=` and `refined_by=`. A finding at rank 2 can
  score below one at rank 3 in another group; within a group scores descend.
- `LOCUS` can differ from 0.42.0's for the same block (the ladder below). `LOCUS_SPAN`'s second
  value can come from a span-only surface, a surface set aside for the block, a trailing
  non-product class or the evidence, and 391 of 770 blocks now carry one; a class the question
  matched is appended after it, so `LOCUS_SPAN` holds one to three values where it held one or
  two, and its values after the primary begin with what `emit_xql.py` prints. `LOCUS_BASIS`
  gains `nonproduct-signal=`, `evidence-signal=` and `span-source=`, which reads `evidence, then
  class_matched span: network.firewall` where both give a value; a split class list reads
  `class-signal=split(first=server.web:DATA; also CONTROL, MANAGEMENT)`; a new tier,
  `operation`, can print; and a surface set aside for a block prints `surface-signal=MANAGEMENT
  (what.attack_surface=internet_facing_management set aside for this block, ...)`.
- `STATUS: SEED` says the source was not re-read or supports only part of the record, where it
  said "source not re-read" beside records re-read that day.
- `DERIVATION` is always `cited record`.
- `MARKERS` lines gain `xdm=` where the marker names its field, `event=` where it is labelled,
  and `combine=` on every line of a keyed list.
- `COUNTERMEASURES` takes one D3FEND control per tactic in turn, a control D3FEND maps directly
  before one it only infers, its header counts per tactic, and an indented `NOT_SHOWN:` line
  names the rest. Each shown control line gains a fourth field, `direct`, `inferred-narrower` or
  `inferred-broader`. The header adds `with D3FEND's direct mappings first in each (<d> of the
  <s> shown direct, <D> of the <n> reached)` after the tactic order, names every cited
  technique, adding `; every control also reached above: ...` and `; not mapped by D3FEND
  <version>: ...` after `; also mapped: ...`, and a revoked predecessor's label reads `(via
  revoked <id>: D3FEND 1.6.0 maps the revoked id, not its replacement)`. `RESPONSE_DOCTRINE`
  reserves the collect and contain rules and adds its own `NOT_SHOWN:` line.
- `DATA_GAP` can read `UNASSESSED - every --have value was rejected`.

`consult.py`, blocks, flags and exit codes:
- `=== EXPOSURE i OF n ===` and `=== LIBRARY i OF n ===` blocks follow the findings, every key
  prefixed `EXPOSURE_` or `LIBRARY_`, each block's key set fixed. `=== FINDING ` still counts
  findings only. `references/exposures.md` is the contract.
- New flags: `--per-locus N` (default 1), `--role ROLE[,ROLE...]`, `--exposure-limit N`
  (default 10) and `--pattern-limit N` (default 6). `--role` filters on the record's one
  `what.role`; `ROLE_FILTER` says so, and adds `asked for: <role> <n>, ...` inside its
  parenthesis, each role asked for counted, 0 included.
- `LIBRARY_MATCH` ends `derived from <the pattern's derived_from, as written>`, or says the
  pattern records none, where it ended in one fixed sentence; `LIBRARY_PATTERNS` counts those
  sources over every pattern matched, and `LIBRARY_REFERENCES` gains a `DERIVED_FROM` row for a
  source that is not already a `CORROBORATION` row.
- `--limit` below 1, `--exposure-limit` or `--pattern-limit` below 0, `--per-locus` below 1 and
  an unknown `--role` exit 2 with `ERROR: --<flag> ...` on stderr and nothing on stdout; for
  `--role` it names the values refused and, where they differ, the whole argument after them.
  `--have` refuses an off-vocabulary value and carries on.
- `RESOLUTION` and `METHODOLOGY` say the exposures are listed in the `EXPOSURE` blocks, where
  they sent the caller to `query.py`.
- A `vendor`-tier `EXPOSURE_MATCH` says the question "resolved" no product or class, where it
  said "named": "Apple iOS" named iOS, and the word was refused, not absent.
- `EXPOSURE_RANSOMWARE` reads `unknown - ...` where the catalogue's value is Unknown, where it
  read `no - ...`.
- `EXPOSURE_DETECTION_HELD` reads `<c> of <n> identifier(s) carried; <observation> (<vendor>)
  carries <ids>[ - FINDING k above]; ...; no observation carries <ids>`, or ends `every
  identifier is carried`, where it named each carrier and not what it carries. `none - ...` is
  unchanged.
- A catalogue entry filed under a catch-all product ("Multiple Products") can be in the
  `product` tier, and its `EXPOSURE_MATCH` then reads `product - PRODUCT - filed under
  <entry>, which names no product; the catalogue's own description names the product asked
  about for <k> of its <n> identifier(s): <spelling> in <ids>`, then which descriptions do not
  name it and how many identifiers the record does not describe.
- Exit 1 only when there is no finding, no listed exposure and no library pattern.
- Under `--rank-by gap` a finding `--covered` says is implemented drops one match group.

`query.py`:
- `resolved by:` and `gated:` lines; `--json` gains a `resolved` object.
- Ties are broken on the question's leftover words, then a record naming what resolved, then
  platform fit, then recency, then id; `--json` gains `tiebreak` on each observation.
- Exposures list by tier, then kind, then recency, with the tier on each line; `--json` gains
  `exposures_by_tier`, `exposure_tier` and `exposure_kind`, and `--full` prints both.
- Each line ends `loci=`, and a `LOCUS over shown:` line follows the counts; `--json` gains
  `loci` and `counts.loci_over_shown`.
- The library block's classes come from the whole match set and are named in its header;
  `--json` gains `library_classes` and `library_classes_basis`. A pattern written for another
  platform sinks, and the weight line says what the rule count measures.
- `--full` prints the actor type where a record names no actor, where it printed
  "unattributed" for state-nexus records.
- A record's free-text reasons are in a fixed order, where the order varied with the hash seed.
- The footer offers `emit_xql.py <observation-id>`.
- Each library pattern prints `  derived from: <its derived_from>` under its name.
- `--limit` below 1 and `--exposure-limit` or `--pattern-limit` below 0 exit 2.
- An exposure line is followed by `identifiers also carried by: <observation-id> (<ids>); ...`
  where observations carry its identifiers, and a handset exposure's line ends `<- handset
  record, out of scope (corpus/schema/scope.json)`; `--json` gains `carried_by` and `handset`
  on each exposure, and `--full` prints both. An observation reached through the identifiers
  of a `product`-tier exposure has the reason `identifier <ids> (in <exposure-id>)`, and its
  line ends `<- reached by identifier ...`. `OUTPUT CAPPED` names `--pattern-limit` when the
  library cap bites.
- For code importing it: `SUBJECT_TIERS`, `SENTINEL_VENDORS`, `product_matches()` and
  `exposure_tier()` are new, and `TIER_ORDER` begins with the four subject tiers. So are
  `product_hits()`, `product_labels()`, `product_parts()`, `product_forms()`,
  `product_families()`, `refused_terms()`, `identifier_carriers()`, `carried_by()`,
  `PRODUCT_PARTS`, `FORM_RELATIONS` and `IDENTIFIER_POINTS`, and `resolve()` returns
  `product_forms`, `refused_meanings` and `refused_names` as well. A `product ...` reason can
  carry the `(as ...)` labels above. `CATCH_ALL_PRODUCT`, `catch_all_record()`,
  `catalogue_descriptions()`, `description_subject()`, `catalogue_hits()`,
  `catalogue_labels()` and `product_identifiers()` are new.
- A catch-all catalogue entry in the `product` tier is followed by `catalogue description
  names the product: <spelling> in <ids>`, in the text listing and in `--full`, and `--json`
  gains `catalogue_names` on every exposure, empty outside that case. The identifier join takes
  only those identifiers from such an entry.

`advise.py`:
- Header, after `SELECTED_BY` and in this order: `PATTERNS_REJECTED`, one or more
  `ATTACK_REQUESTED`, any `ATTACK_RECORD_ONLY` and `ATTACK_PARENT_ONLY`, `SHAPES_EMPTY`,
  `DECLARED_TELEMETRY`, `DECLARED_TELEMETRY_REJECTED`, `LOCUS_RETURNED`, `LOCUS_ABSENT`.
  `SELECTED_BY` appends its ATT&CK breakdown after `shape(s) asked`.
- `FIDELITY`, `RULE_SHAPE`, `LOCUS`, `LOCUS_SPAN`, `LOCUS_BASIS` and the new `LOCUS_OBSERVED`
  are each on a line of their own, where two keys shared a line. `LOCUS_BASIS` reads
  `input=applies_to_classes`.
- `OBSERVED: yes, N record(s), M how-block(s)`, then up to six records newest first, with ids,
  whole titles and a `... N more record(s) not shown:` line.
- `MATCH_BASIS` has two new values, for a sub-technique of a requested parent and for MITRE's
  replacement of a revoked id; the free-text overlap is printed in the caller's words. A
  free-text guess can end `; kept for the behaviour the shape names: it cites <id> (<name>),
  which <words> names and no guess above it cites, it detects (<fidelity>), and its name, logic
  or classes meet <words>; <rank> of <n> on overlap alone - --attack <id> selects every pattern
  citing it`, before the VERIFY warning.
- Indented `SHAPE_RESULT` and `SUGGEST_ATTACK` lines in every shape's banner. `SHAPE_RESULT`
  appends `; <n> pattern(s) overlapped this shape, <k> cut by --per-shape <p>` or `none cut`.
- `ATTACK_RECORD_ONLY` prints wherever how-blocks cite a requested id under patterns it does
  not select, not only when it selected nothing, and ends by naming the records carrying them
  that cite no pattern returned; `ATTACK_REQUESTED` then ends `; <n> further how-block(s) cite
  it under patterns that do not list it, see ATTACK_RECORD_ONLY`. A pattern another selection
  returned is named after `; <k> of their pattern(s) returned here by another selection:`, not
  in the list to select with `--patterns`.
- `OBSERVED` appends `; <k> of the records seed, unconfirmed` where any is; `URL_LIVENESS`
  adds `<n> with no fresh verdict in the cache` before the cache path; `CONTRACT` says what
  SEED means; a free-text `NO_MATCH` over a typed ATT&CK id that patterns cite says it is not
  an absence.
- `--attack` includes a parent's sub-techniques and follows a revoked id; `--attack-exact`
  turns the expansion off. `--per-shape` below 1 exits 2.
- `RESPONSE_DOCTRINE` says whether impact came from citing records, and how many seed records
  it left out.

`emit_xql.py`:
- Text: the header gains `locus=` and `filter=complete|partial|none` before `key=`; `CAVEAT:`,
  `LOGIC:`, `COMBINE:`, `EVENT <label>:`, `REQUIRES`, `REQUIRES for EVENT <label>`, `UNBOUND`,
  `CLAUSE`, `CLAUSE (audit)`, `FIELD`, `NO LIVE FILTER` and `ABSENCE` lines are new or changed;
  pipelines open `datamodel dataset`; alternatives print joined by `or`; the threshold stage is
  `| bin _time span = <window>`; an outcome compares a string; a URL path is anchored inside the
  URL; `// GAP:` is gone; the tally gains its filter and no-how-block suffixes.
- Given a `FINDING_KEY` it emits that one block, and prints the key.
- `--json` gains `finding_key`, `combine_from_source`, `combine_from_pattern`,
  `marker_bindings`, `filter_status`, `fields_from_source`, `countermeasures_shown`,
  `countermeasures_total` and `countermeasures_not_shown`; `countermeasures` is the per-tactic
  selection, and each of its entries gains `mapping`. No key was removed.
- Exit 2 when `corpus/schema/xdm-fields.json` is absent.
- The header prints `pattern=-` for a block citing no pattern, where it printed `pattern=None`,
  and an inventory precondition over several identifiers prints them joined by commas, where
  it printed Python's list.

`validate.py` refuses more, and prints more: the locus map is checked before anything is derived
through it, the declared-locus rule, the span order and the generator tags; the alias gate
tables and the product families; KEV tags against the corpus's own KEV records; a product its
generators class differently; `scope.json`, with a `handset scope:` line; every marker binding
against the XDM snapshot, with `marker bindings: skipped` when it cannot check them; how markers
combine; a connection's port, address, zone or protocol beside a process acted upon; pattern
sketches against the schema; the locus map's technique lists against the ATT&CK reference; a
pattern's declared locus; and every identifier a record carries against the CISA pages it
cites, with a `cited advisory identifiers:` line. Its technique line splits live from withdrawn
ids, a second locus tally covers exposures, and a third, `locus derivation (per block):`, counts
what each per-block rule placed.

The corpus contract:
- `corpus/schema/locus-map.json` gains `surface_span_only`, `untrusted_surface_tags`,
  `span_order`, `surface_vector_techniques`, `way_in_techniques` and
  `non_administrative_operations`; the evidence tier leaves `tier_order` and `operation` joins
  it; `class_matched` leaves `span_order`.
- A pattern may carry `locus` with `locus_reason`, read only where it is placed with no block.
- `corpus/schema/scope.json` and `corpus/schema/xdm-fields.json` are new, and so is
  `corpus/reference/advisory-identifiers.json`, the CVE identifiers each of 305 CISA advisory
  and analysis report pages names.
- `corpus/reference/response-doctrine.json` gains `supports` on every source, the advisory's own
  words for what it is cited for, as one passage or a list, and a `supports_note` saying so.
  Three rules cite two advisories each, and the appliance-rebuild rule cites AA24-060B and
  AA25-022A where it cited AA25-239A.
- `corpus/schema/aliases.json` gains `ambiguous_vendor_aliases`, `ambiguous_class_aliases`,
  `_ambiguous_reviewed_keep`, `singular_only`, `vendor_spellings`, `vendor_families`,
  `product_families` and `platform_of`, and its entries change as the detail says.
- A KEV exposure whose identifiers an observation carries names the observations in its
  summary, where it said "an observation record ... which holds the detection logic", and its
  notes list every weakness type in numeric order, where they listed the first six in lexical
  order.
- A KEV exposure carrying two or more identifiers describes each in the catalogue's own words,
  newest first and at most six, and says how many more it leaves to the catalogue, where it
  only counted them: 230 summaries.
- Generated exposures change class where a generator had it wrong, and one product carries one
  class list whichever generator wrote its record: FortiSandbox `security.edr`, FortiWeb
  `network.proxy`, FortiClient EMS `app.rmm, security.edr`, ScreenConnect `app.rmm`, Kemp
  LoadMaster `network.load_balancer`, Langflow `app.ai_platform`, Outlook `app.office_suite`,
  MinIO `cloud.iaas`, and the ZDI records for FortiClient `security.edr` and ISE
  `identity.sso`. A product whose job is administering other devices lists `app.rmm` first and
  the class of what it manages second: FortiManager, FortiSwitchManager, SmartConsole, Check
  Point's two-product catalogue entry, both Cisco FMC entries, Expedition, SonicWall GMS,
  Catalyst SD-WAN Manager, VeloCloud Orchestrator, Versa Director and Prime DCNM. `aliases.json`
  follows, so a question naming one resolves the corrected classes, and `EXPOSURE_LOCUS` moves
  with them: the management platforms to MANAGEMENT, with CONTROL as the span under a firewall
  question.
- A PSIRT exposure carries an advisory only for a product its vendor marks affected: Cloud NGFW
  goes from 14 identifiers to 1, Prisma Access from 14 to 4, and seven records are gone. Palo
  Alto and Fortinet PSIRT records are dated by their newest advisory at day precision, where all
  carried the collection date at month precision, and a record summarising several advisories
  names each by the identifier its vendor files it under.
- The marker contract gains `combine` on a block or pattern and `event` on a marker, and an
  `xdm` binding must be a field of the snapshot.
- `status: seed` also covers a source re-read that supports only part of the record.
- `attack-techniques.json` entries carry `revoked` and `deprecated`, and a revoked one
  `replaced_by` and sometimes `successor_deprecated`. `d3fend-countermeasures.json` gains
  `by_attack_via`, `by_attack_via_attack_version`, `counts.attack_ids_via_revoked` and 20
  `by_attack` keys, then `by_attack_inferred` (every link D3FEND infers rather than states,
  as `narrower` or `broader`) and `counts.links_by_grade`; each `by_attack` list is ordered
  tactic, then grade, then name, where it was tactic then name, and holds the same ids.

SKILL.md rule 9 heads an answer by the six `LOCUS` values the script prints and quotes the
vocabulary for the three planes, where it defined them by a technology's relationship to the
attack; rule 6 says what `DERIVATION` is; rule 8 reads eligibility; the mode table has every
mode. New references: `references/resolution.md`, `references/exposures.md` and
`references/emit-xql.md`.

DECISIONS TAKEN ON THE MAINTAINER'S BEHALF. The maintainer asked for every defect the pass found
to be fixed and for the plane answer to be right for a production release, and delegated these
choices. Each is stated so it can be reversed on its own, and none reverses a standing decision:
LOCUS is still six values, a control plane is still the network sense with a cloud provider's
control-plane API on MANAGEMENT, handsets are still out of scope with the mobile management
plane (`app.mdm`) in, and a correlation may still read a raw dataset.
- `email_flow` and `remote_access_service` are span-only surfaces. Each names the way in, not
  the plane the detection reads, so neither decides a block's `LOCUS`; each is carried as the
  span. Taking `email_flow` alone would have moved 18 host-event blocks into MANAGEMENT through
  `remote_access_service`.
- The primary `LOCUS` never depends on the question, and neither does the span's second value.
  The class the question matched is appended to the span after the record's own, `class_matched
  span`. Relabelling the primary by the question was designed and not taken: it printed the EPMM
  record as CONTROL under an Okta question, against the standing `app.mdm` reading, and made
  `emit_xql.py`, `advise.py` and `validate.py` disagree with a consultation about the same
  block. Keeping one span value and reporting the question's class elsewhere was the alternative
  to appending; it would have taken the firewall relation off `LOCUS_SPAN`.
- A non-product class decides a block's plane only as its primary subject, first-listed or
  alone. Every misplaced block moved; the narrower option, keeping inventory-shaped
  `cross_sector` blocks on ORGANISATION, was not taken.
- Evidence is never a tier. A block's evidence types are the last span source only, and
  `evidence-signal=` always prints.
- Under `--rank-by gap` a finding `--covered` says is implemented drops one match group. It is
  demoted, never removed, and still outranks free-text leads.
- The record cap is 2 per record within a match group. The value is chosen, not measured.
- A vendor-only question derives classes from the vendor's own observations and prints them as
  `CLASSES_FROM_VENDOR`, the first-listed classes two or more of them share or the three most
  frequent, never a non-product class, for scoring only.
- `--per-locus` (default 1) and `--role` are new, so rule 9 can be carried out with the script
  rather than by filtering `--limit 500` by hand.
- Library patterns come in `LIBRARY` blocks of their own, and rule 6 is rewritten to match. The
  smaller fix, correcting rule 6 alone, was not taken.
- The ranking and quota judgement calls follow each design's own recommendation: a reserved
  slot needs criticality 3.0, the MODERATE band floor, before any coverage demotion; a tag match
  is eligible in every mode; product and vendor share the first group and class analogues and
  the vendor's other lines the second; within a group a named sector, the leftover words and the
  platform fit order findings before the score; a vendor named inside a generic record's
  products counts as `vendor` only where the record carries a class asked about; and the
  vendor's other lines alone never make `RESOLUTION: product`.
- Handset exposure records stay in the corpus and are refused from a consultation with a
  counted reason, `handset=`, rather than deleted.
- `advise.py` follows a revoked `--attack` id to MITRE's replacement automatically, under a
  `MATCH_BASIS` of its own, rather than only pointing at it.
- `advise.py` takes a pattern's impact for doctrine from its non-seed citing records, and its
  header says so.
- A pattern's primary `LOCUS` in `advise.py` stays class-derived, except where a pattern whose
  detection is administration of a device declares `MANAGEMENT` with its reason; fourteen do.
  `LOCUS_OBSERVED` says where its citing blocks sit, and a unanimous observed locus becomes the
  span. Switching the primary to the observed locus was the alternative, and was measured again:
  49 patterns would move onto `MANAGEMENT`, 41 of them on one citing block.
- A record's surface reaches a block, not a record. A supply surface places only the block
  citing its vector's technique or reading `integrity_check`; any other committing surface
  places every block but one past the way in. The burden runs opposite ways on purpose: after a
  management login most of what follows on a device is still its administration, and what
  follows a delivery is not the delivery. The way in is read from ATT&CK's own initial-access tactic,
  not a list chosen here, and a block past it goes to its first-listed class, not to
  `ORGANISATION` where its evidence reads only posture: 63 of the corpus's 65 inventory blocks
  reading only posture sit on a class or a surface, and these join them. Reading the pattern's
  classes as the block's was the alternative, and breaks the rule that `validate.py`, which
  places a block without its pattern, agrees.
- A block whose only live test is a cloud operation is `MANAGEMENT` by a tier, not by six
  overrides, with a list of operations that are a use of the service rather than its
  administration. One block with no markers of its own, whose live test is its pattern's,
  declares its locus instead of having the tier read its pattern.
- The ESX Admins group marker is bound to `xdm.target.user.username`, chosen here and not by the
  xdm-author bundle's owner. The group created is the event's target identity, and XDM's target
  identity object carries a Boolean `xdm.target.user.group` marking it a group, so its name sits
  in `xdm.target.user.username`; `xdm.target.user.groups` is the target's memberships and an
  array, and `xdm.target.resource.name` is kept for cloud and platform resources.
- An outcome is compared as the string its constant renders as, never as `XDM_CONST.OUTCOME_*`,
  because the correlation-author bundle records the constant failing a pack install.
- Smaller calls, each argued in its paragraph below: bare `s7` is not a PLC alias, and "siemens
  s7" and "simatic s7" are; `controller` is gated beside PLC words rather than deleted; 22
  dictionary-word product aliases stay ungated with their reasons, `windows` and `outlook` as
  pinned false positives; anchoring a gated word from anywhere in the question was refused for a
  two-word window; the `sd-wan` product alias keeps its records' `network.router`; `vmware` stays
  a Broadcom alias and `vendor_families` runs one way; a product matches by canonical equality,
  not by token containment; a class match alone never lists an exposure; `--have` refuses an
  off-vocabulary value leniently rather than exiting 2; a skeleton pipeline opens `datamodel
  dataset` as a preference; the Fortinet, Juniper and Talos theses are held as seed rather than
  cut; the two Cloudflare phishing-fronting records now read CONTROL on their first-listed
  `network.proxy`, which is arguable; and falling back to a record's platforms for a block with
  none of its own was measured and not taken.
- One product under several names is data, `product_families` in `corpus/schema/aliases.json`,
  with a reason on every entry, rather than a rule in code. A family's names match both ways; a
  component runs one way, so a question naming the FortiOS SSL-VPN or the kernel's KSMBD server
  does not reach the whole product. Ten families are recorded, each moving records the corpus
  holds; a general prefix rule was the alternative, and would have matched Endpoint Manager to
  Endpoint Manager Mobile, the defect canonical equality was adopted to end.
- An observation carrying an identifier of a `product`-tier exposure is reached by `query.py`
  and scores 6, what naming the product scores, even when it is filed under another product.
  `consult.py` names it on `EXPOSURE_DETECTION_HELD` and makes no finding of it, because its
  blocks are written for the product it is filed under. The value 6 is chosen, not measured.
- A product whose job is administering other network devices is classed `app.rmm` first and
  the class of what it manages second, on every generated record and alias naming it. On a
  generated record the class is the only plane there is, so the order is the answer: listed
  management first, a question asking the managed class adds that class's plane as the span;
  listed the other way round, no question could print MANAGEMENT for it. Check Point's "Multiple
  Products" entry, one management-server CVE and one gateway CVE, is listed management first
  for that reason. The rule is applied to every catalogue pair naming only a management
  platform, not only the ones the validation met. A device's own management interface stays in
  the device's class. Carrying a generated record's second class as its span was the
  alternative, a ladder change left to the locus work.
- FortiWeb is `network.proxy`, a web application firewall deployed as a reverse proxy, as the
  Cloudflare WAF records are, rather than the PSIRT table's `server.web` or the KEV and ZDI
  `network.firewall`. FortiSandbox is `security.edr`, the class two of its three generators
  gave it; the vocabulary has no sandbox class. FortiClient EMS is `app.rmm` with
  `security.edr` second: an endpoint manager, as Ivanti EPM and LANSCOPE are, and the console of
  the FortiClient agent. Prime DCNM's second class is `network.switch`, the data centre fabric it
  manages, where the Cisco vendor default said router.
- A Fortinet advisory is attributed to a product its summary names only where the advisory's
  version table marks a row of that product affected, or, where the table has no row for it,
  where the summary names it as the vulnerable product, before its "may allow". A product the
  table alone marks affected is not added (not done, below). FortiGate, named in two summaries
  as the device a flaw runs on, is left to the FortiOS record, which carried both identifiers
  already and which the product family makes FortiGate's.
- A KEV summary describes at most six identifiers, newest first. Six covers 200 of the 230
  records carrying more than one; the value is chosen, not measured.
- A catalogue entry filed under a catch-all product is matched on the subject of the
  catalogue's description of each identifier, read as a product entry is read: whole names,
  never words inside a name. Carrying each identifier's products as a record field was the
  alternative; it needs a schema field and a parse of free text at generation, and the summary
  already carries the text. A description opening another way names nothing, so the reading
  can only miss, never invent.
- A reserved slot is filled only from a finding naming the product or vendor asked about,
  wherever the question named one and a finding names it; a plane only analogues hold is named
  in `LOCUS_ANALOGUE_ONLY` and gets no reserve. Where no finding names what was asked, the
  analogues are the whole answer, `CLASS_LEVEL_WARNING` says so, and the reserve spreads them.
- A block of a campaign record (filed under `any` or `Multiple`, listing what it reached) keeps
  the record's tier only on a reading it states, and one with no reading either way falls. The
  first decision kept such a block, as describing the campaign as it reached every product
  listed, and the third review of the campaign-block change failed it: for blocks tied to
  another entry's platform the claim was false, and "Synacor Zimbra Collaboration Suite (ZCS)"
  drew its whole product tier from an IIS directory exclusion, an ASP.NET ViewState block and
  a block that is not a detection. A block naming nothing keeps the tier on the pattern it
  cites where that pattern is written for a class of what was asked and for no other kind the
  record's other entries hold, unless its markers commit to another platform than the asked
  product's; and a record whose other entries the resolver reads nothing in keeps every block.
  The remote-access broker record's post-access tradecraft, sticky keys and a tunnel client
  among it, now falls on the NetScaler and BIG-IP questions, saying its markers are Windows'.
- A name a campaign block mentions takes it from what was asked only where the block gives no
  reading of its own for the asked product and the pattern it cites is written for none of the
  asked product's classes; a product the record lists, named by that product's own name, takes
  it where the block reads for none of those classes. Demoting on any name the resolver found
  was the first reading, and it demoted the ESXi hypervisor block for "Windows hosts" and four
  other blocks the 2026-10-01 review counted as about what was asked.
- The FortiOS username-case MFA exposure is re-sourced to AA22-321A, which states its claim,
  rather than cut, and the identifier check decides only a record whose every cited source it
  holds; a record also citing another source is counted and not decided.

NOT DONE IN THIS RELEASE, AND WHY:
- Two tenant probes are owed before a skeleton is trusted in production: one single-backslash
  regex, to confirm the escaping, and one comparison of an enum other than outcome and
  operation type with its constant (`references/emit-xql.md`, Before production). They need a
  tenant.
- `xdm.target.registry.value` holds the value name in this bundle's bindings and the value data
  in the xdm-author bundle's Sysmon mapping. One modelled registry event on a tenant settles it,
  and nothing is rebound until one does.
- 49 pattern `xql_sketch` strings still read a vendor's columns beside `xdm.*` fields on a raw
  stage. Splitting each is a person's work, sketch by sketch.
- Whether a `combine: any` alternative is narrow enough is a content judgement for its author
  where the contract already prints it as partial, as on the trycloudflare record's second
  block and the Horizon record's fourth.
- Two false anchors inside the two-word window ("SharePoint project sites", "Active Directory
  and edge VPN appliances") and the class aliases `relay` and `switch` still resolve falsely.
  Tests pin each as failing; fixing them needs a signal the resolver does not have.
- Sector aliases have no gate. A sector only lifts a record that already matched, so it moves
  ranking and never a plane.
- A handset product named outright, "Android kernel" among them, still gets a class-level
  ENDPOINT answer from desktop and server records, with its handset exposures refused and
  counted. Whether it should get one at all is a scope decision nobody has taken.
- `corpus/schema/scope.json` catches only the vendors it lists; a handset record from another
  vendor is listed until it is added there.
- A VMware question is a Broadcom question and reaches Broadcom's Symantec and Brocade lines as
  the vendor's other lines. Separating them means re-filing 21 product aliases.
- The two Sonatype KEV records are one product line under two strings the merge guard cannot
  see.
- Six declared-locus reasons were written from the records' own text, because no commit
  recorded them, and want a reviewer's read.
- Three independent-research records carry no read date: the watchTowr index record and the
  FiGHT and ATLAS knowledge-base records. The Talos base-rate record stays seed until its series
  is cited quarter by quarter or the schema gains a series citation.
- Two content additions were left: typed command markers for the Juniper router campaign's
  configuration-change block, and the Ivanti chain block's response codes, which neither
  advisory settles.
- Where a supply surface no longer places a block, the block's first-listed class does, and for
  some the class is arguable: the Cloudflare Pages build-step blocks sit on `DATA` from
  `cloud.saas`, the lapsed-domain trust blocks on `DATA`, a model namespace re-registered on
  `CONTROL` from `app.ai_platform`, and the AWS miner's pool traffic on `MANAGEMENT` from
  `cloud.iaas`. Each carries `SUPPLY` as its span. Moving them means reordering a record's
  classes, which is content.
- "SolarWinds Orion" reports `SUPPLY` absent: the one block that detects the signed update sits
  there and scores 2.98, under the 3.0 floor, and the bullet says so with `span-only 9`.
- A class list split across planes is still never a span, so a PLC record whose first class is
  `ot.plc` loses its `CONTROL` relation where a later class is on another plane, and
  `CLASSES_FROM_VENDOR` still scores a vendor-only question without adding a span. The Siemens
  catalogue exposure sits on `CONTROL` by its class and the Siemens observations now sit on both
  planes, so the two agree more than they did and the answer still does not say where they
  differ.
- An inventory-shaped block whose evidence reads only posture still sits on its first-listed
  class wherever no surface decides it, the KEV-catalogue join on a firewall question among
  them. Promoting the shape with posture-only evidence was measured and not taken in this
  release; it would move 63 blocks, the Log4j embedded-component inventory off `SUPPLY` among
  them.
- `product_families` holds the renames and families the 2026-09-30 validation met and a sweep
  of known renames confirmed in the corpus. Other vendors' renames are added as they are found;
  the AWS services a question for "AWS" reaches as the vendor's other lines are parts of a
  platform rather than names of one product, and are not a family.
- `query.py` orders exposures within a tier by kind and date, never by platform, so a Linux
  question's class-only exposures still lead with Windows and macOS catalogue records.
- A device's own management interface in a generated record -- BIG-IP's Configuration Utility,
  IOS XE's Web UI, the PAN-OS management interface -- still sits on the device's plane. No class
  says "management interface of a load balancer", and the catalogue has no field separating a
  management-interface flaw from a data-path one.
- Two mixed catalogue entries keep the device class first: Catalyst SD-WAN Controller and
  Manager, whose controller is the SD-WAN control plane itself, and BIG-IP and BIG-IQ
  Centralized Management, whose one CVE is in both.
- A question naming only Check Point prints its two-product entry on MANAGEMENT with no CONTROL
  span, because a class list split across planes is never a span. That is the ladder's rule,
  and changing it for generated records is the locus work's, not a class.
- The PSIRT collector adds no product that only a version table marks affected: FortiProxy on
  FG-IR-24-452, FortiSASE on FG-IR-24-257, FortiManager on FG-IR-26-121, and the OpenSSH
  advisory FG-IR-25-122 across the products its table lists. Each is an attribution the vendor
  states and the corpus does not carry; adding them creates records, and is a collection pass.
- Nokia's listing dates each advisory in a column the collector does not read, and the cached
  page's dates run past the day it was read, so the Nokia PSIRT records keep the collection
  month.
- A PSIRT record's impact is still the constant `reconnaissance`, beside an advisory that
  deletes the root file system. A keyword table over advisory titles was the alternative, and
  would trade one wrong value for another.
- The ZDI FortiClient VPN record stays `network.vpn_gateway`; the vocabulary has no class for a
  VPN client. "Catalyst SD-WAN Manger", the catalogue's misspelling, is still a record apart
  from Catalyst SD-WAN Manager, classed the same.
- An `EXPOSURE` block prints neither a record's impact nor its weakness types, which the notes
  hold; the summary now names each flaw in the catalogue's words. "Check Point SmartEvent" still
  lists `smartevent` unmatched.
- The EPMM record still lacks the four checks AA23-213A gives in NCSC-NO's own words: a spike in
  directory query events from the device, a malicious web application deleting log lines keyed
  on a user agent, a TLS certificate on the tunnelling gateway that is not its own, and SOHO
  routers as sources. No pattern of the 475 fits any of them, and each is a new block that moves
  the shipped tallies, so they are content for a pass that writes blocks, not for a correction.
- The Zimbra campaign AA26-204A is about, with its own SOAP-request, application-passcode and
  browser-storage signals, has no record. It is a new record, and a collection pass.
- The Ivanti Cloud Service Appliance is still classed three ways by its three names: the
  observation and its alias `network.remote_access`, the two KEV records filed as "Cloud
  Services Appliance" `network.vpn_gateway` through the Ivanti vendor default, and the KEV
  record filed as "Endpoint Manager Cloud Service Appliance" `app.rmm`, which puts the last on
  MANAGEMENT. The three names are one product family now, so every record naming the appliance
  is a `product` match whichever name a question uses; what still differs by name is the class
  a question resolves, and with it the vendor-class exposures and the class analogues it
  reaches. Which one class the appliance takes is a plane decision across the KEV classifier
  and the aliases, and is left to the maintainer.
- The 2025 ASA and FTD campaign, CVE-2025-20333 chained with CVE-2025-20362, has no
  observation, so the ASA's catalogue record prints `EXPOSURE_DETECTION_HELD: none`, and the
  one ASA implant record, ArcaneDoor in 2024, is still SEED. It is a corpus gap, not a
  correction: the emergency directive, its hunt instructions, the FIRESTARTER and
  RayInitiator reports and Cisco's detection guide are in the maintainer's backlog to read, and
  no record was drafted from memory.
- A library a product embeds reads as another product. The AA22-257A record's catalogue join
  and outbound-lookup blocks concern VMware Horizon through Log4j, "a logging library reached
  through a virtual desktop product", and on a Horizon question both fall to the class: the
  catalogue join carries no identifier an exposure record holds as Horizon's (the corpus files
  the Log4j identifiers under Apache Log4j2), and the lookup names Log4j under a pattern
  written for web servers and libraries. Telling an embedded library from a separate product
  needs the record to say which entry embeds it, which no field does; each block's
  `MATCH_BASIS` names the holders and the name it read.
- A campaign block that concerns what was asked by a reading nothing here makes falls with
  the rest. The web-server campaign's ViewState block is ASP.NET's, and on "Progress Telerik
  UI for ASP.NET AJAX" it is the campaign's, because no alias or class reads "ViewState" or
  "MachineKey" as ASP.NET and the pattern it cites is written for web servers, middleware and
  collaboration suites, the IIS, Nacos and Zimbra entries' kinds. The captive-portal record's
  tenant blocks fall on "Microsoft 365" to the Entra ID entry the record lists beside it. A
  platform the classifier does not read in a block's markers -- Windows event identifiers, a
  share name, "Netlogon" -- reads as none, so the hive record's log-clearing block falls on
  "Windows endpoints" questions for not ruling out the Linux entry. Each needs a reading the
  alias table or `query.py`'s `PLATFORM_INDICATORS` does not hold, and each block says what
  its pattern is written for and whose kind that is.
- The `badiis` alias files the IIS module under the Telerik entry of the record it came from;
  `block_scope()` now reads it as a word the table sends there rather than that entry's name,
  and the alias itself is left for the alias table's own review.
- `LOCUS_SUBJECT` on "Microsoft Exchange" counts `CONTROL` from the AA22-257A catalogue-join
  block, which keeps the product tier on Exchange's own identifiers but sits on `CONTROL`
  through the record's first-listed class, `network.vpn_gateway`, Fortinet's: the block's
  plane is the locus ladder's, not the tier's.
- A block of a record that names only the vendor inside an entry, on a product question, stays
  a class analogue or a name fragment even where it carries the product's own identifier. The
  AA22-257A record's username-case bypass and catalogue-join blocks carry FortiOS identifiers on
  a FortiGate question; promoting them was built and measured, and put both 2022 blocks into
  FortiGate's top 12, one repeating the FortiOS record's own bypass detection, above the
  management-channel finding. Which of those leads is a ranking decision for the maintainer;
  the blocks' `MATCH_BASIS` now says what the record names.
- The ransomware share-encryption record's Windows share block keeps the vendor tier on
  "Linux". Its logic reads "Endpoint telemetry" for `endpoint.os`, the class the alias table
  files Linux's products under and the record's "Windows estates" entry holds, and its Windows
  reading sits only in the share names its marker matches and in "Netlogon", which neither the
  platform classifier nor the alias table reads as Windows. Refusing a class word another
  listed entry also holds would only move it to `neutral`, because the pattern it cites is
  written for `endpoint.os`; taking it needs a platform reading of a block, which is the
  platform classifier's change (`query.py`'s `PLATFORM_INDICATORS`) and a rule using it, not
  this one.
- A class word the near-word gate refuses in a block's prose stays unread: the PLC record's
  keyswitch block says "affected controllers" with no PLC word within two words, and the
  "plc" in its sibling's computed expression `device_class = plc` is not prose, as "ldap" in
  the Log4j block's expression is not. Its reading at e7cd54a came from the next string
  joined onto "programmable position". The tier does not turn on it now: on "Siemens" the
  keyswitch and module-tampering blocks keep the vendor tier by kind, and the display and
  exposure blocks fall because their patterns are also written for SCADA servers, which the
  record lists as "SCADA displays".
- On a question naming no product, "network firewall" among them, the reserve still fills
  `ENDPOINT` from the Zeppelin share-enumeration analogue and `DATA` from a second catalogue
  join of a pattern already shown: such a question has no subject to reserve from, and a test of
  whether an analogue's plane comes from the class asked about would empty most class answers'
  spread. `LOCUS_DISPLACED` still splits what the shown set lost between the reserve and the
  record cap by rank rather than by re-running without the reserve; on "Cisco ASA" no reserve is
  now taken, so the split is moot there.

THE DETAIL, AREA BY AREA.

A COUNT BELOW ITS FLOOR IS NOW REFUSED, NOT READ FROM THE END OF THE RANKING. Every cap in these
scripts is applied as a slice, and every count flag was a bare `type=int`, so an out-of-range
value produced an answer rather than an error:
- `consult.py "I have a Cisco ASA" --limit 0` printed "NO_FINDINGS: the resolver matched
  nothing." over 97 matched findings and exited 1.
- `--limit -1` showed 4 findings under `LOCUS_RESERVED: 4` and `LOCUS_DISPLACED: 0`, breaking
  the stated rule that the two are always the same length.
- `query.py "PAN-OS" --exposure-limit -1` listed 58 of 59 exposures.
- `advise.py --per-shape -1 shell` returned 23 patterns instead of 3, and `--per-shape 0` printed
  "no pattern overlapped any shape" over a shape that matched.

`--limit` on `consult.py` and `query.py`, and `--per-shape` on `advise.py`, must now be 1 or
more. `--exposure-limit` and `--pattern-limit` must be 0 or more, because 0 there lists none of
a secondary block and leaves the rest of the answer whole. Below the floor, each script prints
`ERROR: --<flag> must be <n> or more` on stderr, prints nothing on stdout and exits 2, the code
already used for bad input. One helper in `query.py` applies the rule for all three scripts.
`consult.py`'s NO_FINDINGS branch now tests the match set rather than the shown set, so it
cannot come back through another route. Every value inside the range answers exactly as before.
SKILL.md said `query.py` "exits 0 either way", and now says when it does not.

EVERY FINDING NOW PRINTS A KEY THAT IS UNIQUE. A finding is one how-block, and the pair consumers
used to name it, `RECORD_ID` with `PATTERN_ID`, is not unique. Five records cite one pattern from
two or more blocks, and ten blocks cite no pattern and print `PATTERN_ID: -`. The bundle's own
displacement test keyed on that pair. It passed only because none of its three questions
displaced one of the colliding blocks. For "Microsoft SharePoint", keyed on the pair, three
findings were lost against pure order while `LOCUS_DISPLACED` correctly reported four.
`FINDING_KEY: <record-id>#how<n>` now follows `PATTERN_ID` on every finding. Both header bullet
lists name findings by it. The `LOCUS_RESERVED` bullets also gain the pattern id they left out,
so a reserved block of a multi-block record can be identified from the header. `emit_xql.py`
takes the key and hands off that one block, matched exactly rather than as a substring. It also
prints the key in its text header and as `finding_key` in the JSON handoff. The key set grows by
one key, identically on every finding.

THE LOCUS MAP IS CHECKED BEFORE ANYTHING IS DERIVED THROUGH IT. `validate.py` checked the map
after deriving every block through it, and checked only part of it:
- A supply surface with no `by_surface` entry crashed the validator with a KeyError traceback,
  so the problem that would have explained the crash was never printed.
- `tier_order` was read by nothing. Reversing it in the file changed no output and failed no
  check.
- A value both mapped and deferred was caught by a test and not by the validator.

`consult.py` now names its ladder `LOCUS_TIERS`, and `validate.py` refuses a corpus whose
`tier_order` differs from it. It also refuses a supply surface the ladder cannot look up, a
non-product class with no `by_class` entry, and a value that is both mapped and deferred. The
map is checked first. When it has problems, the tally line says `locus derivation: skipped` and
gives the reason, instead of printing a distribution computed over a broken map. The
`class_nonproduct` tier now reads its locus from `by_class` rather than from a literal. Both
non-product classes map to ORGANISATION, so no label moves.

VALIDATE.PY NOW RUNS WITHOUT THE CONSULTATION SCRIPT, AS ITS IMPORT GUARD ALWAYS SAID IT COULD.
The import of `consult.py` is optional so that the validator can run alone. The tally then used
the module anyway, so the one situation the guard exists for failed with an AttributeError. The
validator now completes and prints `locus derivation: skipped - scripts/consult.py is not
importable`.

TWO BEHAVIOURS ARE PINNED BEFORE ANY LATER CHANGE CAN MOVE THEM. `tests/test_locus_derivation.py`
holds `consult.py` and `validate.py` to one derivation. It checks every how-block with and without
the cited pattern, checks that the validator's distribution line equals the loci the consultation
path computes, and checks that every block and every one of the 475 patterns derives by a tier the
map lists. The two scripts agreed before this release only because every record carries a class and
the evidence tier never fires. `tests/test_subject_tiers.py` pins gap ranking on a Fortinet
coverage fixture: on criticality, 8 of the top 12 findings are ones the caller says they have
built, and under `--rank-by gap` none are. Until now the only gap-mode test checked the key set, so
a sort key that grouped findings by match tier ahead of weight would have put the covered findings
back on top with the suite green.

The output of all five scripts was captured for ten questions before and after these changes.
The only differences are the new key, the bullet format and the `emit_xql.py` key: they moved no
record, pattern, count or locus.

SIX RECORDS CARRIED IDENTIFIERS AND PRODUCTS THEIR CITED POST NEVER NAMES, AND NOW CARRY ONLY WHAT
IT DOES. One-shot batch scripts in August wrote one watchTowr record per product group from
several posts and cited one. The Ivanti Connect Secure record cited the CVE-2025-22457 post and
carried six more identifiers, two further products and a second exploit chain; its 2026
identifiers were the EPMM and Sentry KEV records' own, copied next door. All six carried
`status: verified` with no read date, and an observed end that was the crawl date of the
publisher's index. Each post was fetched again on 2026-09-25 and each record cut to it:
- `obs-ivanti-connect-secure-recurring-preauth-memory-corruption`: 7 identifiers to
  1. Kept CVE-2025-22457; cut CVE-2023-46805, CVE-2024-21887, CVE-2025-0282, CVE-2026-1281,
  CVE-2026-1340 and CVE-2026-10520. Products Endpoint Manager Mobile and Sentry cut, with
  `app.rmm`, which came only from EPMM; impacts `auth_bypass` and `lateral_movement` cut with the
  chain they described. Observed 2023-12 to 2026-07 is now 2025-03 to 2025-04, the tag
  `recurring-fault-class` is gone, and the CVE-2023-46805/CVE-2024-21887 chain block moved to
  `obs-ivanti-connect-secure-chained-exploitation`, whose AA25-239A and AA24-060B both name the
  pair. The pattern keeps its three citing records. That record's first block already
  described the same chain, requests reaching an authenticated endpoint with no preceding
  authentication, under the post-disclosure scanning pattern, so an Ivanti answer printed one
  detection twice under two patterns. The duplicate is removed and its logging caveat joins the
  chain block's, so "Ivanti Connect Secure" shows the chain once, at rank 3.
- `obs-citrix-netscaler-recurring-memory-disclosure-from-auth-endpoint`: 5 to 2. Kept
  CVE-2023-4966 and CVE-2025-5777; cut CVE-2025-12101, CVE-2026-3055 and CVE-2026-8451. The
  summary now describes the two CitrixBleed instances the post covers, not "five identifiers
  across two years", and a caveat saying patched and vulnerable responses differ "by a few
  hundred bytes" is gone; the post's own examples are 668 and 1,962. Published 2025-07-01 is the
  post's 2025-07-04.
- `obs-fortinet-product-family-breadth-and-management-reach`: 6 to 1. Kept CVE-2024-55591; cut
  CVE-2022-42475, CVE-2024-23113, CVE-2024-47575, CVE-2025-25256 and CVE-2025-25257, the last two
  from posts published after the record's own date. Products FortiManager, FortiWeb and FortiSIEM
  cut, with `app.rmm`, `server.web` and `security.siem`. Impact `config_exfiltration` cut, since
  only the cut FortiManager identifier supported it. `lateral_movement` stays with the family
  thesis it belongs to (see below), and the notes now name it as part of the unconfirmed half.
- `obs-generic-managed-file-transfer-class-recurrence-across-vendors`: 5 to 1. Kept
  CVE-2025-10035; cut CVE-2024-5806, CVE-2025-54309, CVE-2024-50623 and CVE-2025-34299, and the
  "six unrelated vendors" sentence with them. Classes `cloud.saas` and `app.middleware` cut.
  Published 2025-09-19 is the post's 2025-09-24, and the summary now records that the
  researchers could not get past the object's signature check, although the vendor rated the
  flaw critical. Impacts `data_exfiltration` and `supply_chain` cut: the post shows an
  authentication bypass reaching a deserialisation sink and says nothing of data taken or of a
  supply chain, so both went with the class argument. `rce` and `auth_bypass` stay. Its
  findings lose the two response doctrine entries `data_exfiltration` selected, the
  communications plans for an attacker publishing and for direct contact with third parties.
- `obs-generic-security-monitoring-platform-as-the-objective`: 2 to 1. Kept CVE-2022-26377; cut
  CVE-2025-25256, a FortiSIEM flaw the QRadar post never mentions. Classes `security.edr`,
  `security.vuln_mgmt` and `app.rmm` cut, with the claims that monitoring products "recur as
  targets across this research" and hold integration secrets. Impacts `lateral_movement` and
  `supply_chain` went with that claim, their only support; the post shows credentials read from
  the ingested logs, incident records open to tampering and the defenders watched, so
  `credential_theft`, `defence_evasion` and `reconnaissance` stay. The record said 2023-05-01;
  the post is dated 2024-04-12 and describes work from October 2023, so it is observed 2023-10
  to 2024-04.
- `obs-juniper-scheduled-release-cycle-and-web-management-exposure`: CVE-2026-21902 cut, and
  CVE-2023-36845 and CVE-2023-36846 added, because the post analyses both. Product Junos OS
  Evolved cut, since it came only with CVE-2026-21902, and `network.router` cut; the post is
  about SRX firewalls and EX switches.

The Fortinet and Juniper records are now `status: seed`. Their theses, that the vendor's
products manage one another so a management flaw reaches the enforcement devices, and that the
vendor fixes on a fixed quarterly schedule, are in none of the posts they cite; the Juniper post
calls its bulletin out of cycle. Cut to their posts they would argue nothing, so the thesis
stays, `consult.py` halves their score and prints `STATUS: SEED`, and their notes say which half
the post supports. The Talos base-rate record below joins them for the same reason. Every one of
the six now records `retrieved: 2026-09-25` and `verified: true`. The posts that would carry the
cut identifiers back with a citation are listed maintainer-side. Seed had been defined as
"written from general knowledge, source not re-read", which none of the three fits, so the
schema's `status` description, SKILL.md's two rules and `corpus/README.md`'s authoring rule now
also admit a source that was re-read and supports only part of the record, with the notes naming
the part. The authoring rule had said to set `verified` whenever the source was read, which
would have kept all three verified; it now asks for a source that supports all of the record,
and a read date. `consult.py`'s seed banner said
"source not re-read" beside their `verified=yes`, and now says a seed record's source was not
re-read or supports only part of it; `SUPPORT` says which.

NINE KEV RECORDS STOPPED COUNTING IDENTIFIERS AN OBSERVATION NO LONGER CARRIES. The KEV
generator says how many of an exposure's identifiers an observation already covers "which holds
the detection logic", and that count was taken against the syntheses. It was re-run, unchanged,
against the corrected corpus and its output merged by id: EPMM 4 to 2, Sentry 1 to none, Citrix
NetScaler, Cleo, CrushFTP, FortiWeb and Fortinet Multiple Products 1 to none, F5 BIG-IP
Configuration Utility 1 to none (see below), and Juniper Junos OS 4 to 5, because the Juniper
record now carries CVE-2023-36846. The `also-in-observation-record` tag follows the count. No
other field of the 709 KEV records moved. `tests/test_generated_claims.py` recomputes the
overlap from the shipped corpus, so an observation corrected without re-running the generator
fails the suite.

THREE RECORDS CARRIED CONTENT FROM A SECOND SOURCE THEY DO NOT CITE. The F5 record cited
AA21-200B, which names CVE-2020-5902, and also carried from a later ransomware advisory
CVE-2023-46747, a summary clause about ransomware operators and, as its only actor, RansomHub,
with a state nexus and high confidence, so `query.py --full` printed "who2 RansomHub" under a
summary about Chinese state-sponsored actors. All three are cut, and it is observed to 2021-07.
AA21-200B names no group, so the actor
is now the advisory's own description, "Chinese state-sponsored cyber actors", which is how eight
other CISA records name an unnamed state actor; the state nexus and high confidence are the
joint assessment's own. The sectors stay: besides military, educational and critical
infrastructure targets, the advisory names semiconductor companies, the defence industrial base,
universities and medical institutions, which are its manufacturing, defence, education and
healthcare. `config_exfiltration` is cut, because the advisory never says it; `rce`,
`credential_theft` and `lateral_movement` are its stated remote code execution, credential
access and lateral movement. It was read again on 2026-09-25. `tests/test_citation_support.py`
now pins the record's actor, sectors, identifier and impacts, and holds generally that a
state-nexus record names at least one actor no other record types as criminal, which fails on
this record alone before the repair. The Juniper J-Web
record cited AA24-317A with AA22-158A as corroboration, and carried CVE-2020-1631 and "an earlier
path traversal flaw chained by state actors" from a third advisory neither names; both are cut.
The Cloudflare tunnel record, sourced from a 2023 post, was observed to 2026 and now ends in
2023.

The J-Web record's corroboration was the same shape one step removed. A corroboration is a
second account of the same thing, and AA22-158A is not an account of the 2023 routinely
exploited list: it is a 2022 campaign that dumped a RADIUS server's credentials and scripted
logins to Cisco and Juniper routers to take their configurations, then tunnelled and mirrored
traffic out. Half the record came from it: two of its four blocks, `config_exfiltration`,
`lateral_movement` and `reconnaissance`, `network.router`, the state attribution, the
telecommunications and government sectors and the 2020 start. Its `energy.electric` sector is
in neither advisory and is gone. The record is split. The AA24-317A
half is `obs-juniper-junos-jweb-routinely-exploited-web-management`, with the two J-Web
identifiers, `rce` and `auth_bypass`, the EX and SRX classes, no attribution because the list
makes none, and observed 2023-08 to 2023-12. The AA22-158A half is
`obs-juniper-router-config-harvested-with-stolen-radius-credentials`, verified against the
advisory on 2026-09-25, with the harvesting and configuration-change blocks moved unchanged
and no identifiers, because the advisory names no Juniper one. Its sector is
`communications` alone: the campaign ran against telecommunications companies and network
service providers, and the advisory names government as an audience and public and private
sector organisations as targets of the wider exploitation its identifier list covers, which the
record does not carry, so `government` and `cross_sector` did not come across. Its actor is the
advisory's own "PRC state-sponsored cyber actors". Both blocks declare
`MANAGEMENT`, with the reason in the record's notes: a credentialed attacker commits to no
surface, so without the declaration the ladder would read the router class alone and call
scripted secure shell administration `CONTROL`. They keep the label and the `CONTROL` span they
had. On their own 2022 advisory with no identifiers they rank 44 and 54 for "Juniper Junos" in
pure criticality order, where they ranked 6 and 10 on the J-Web record's 2024 date and
identifiers; the old rank was borrowed. The record count is now 1,159.

A STATE ACTOR THE SOURCE DID NOT NAME NO LONGER READS AS UNATTRIBUTED. `query.py --full` printed
"unattributed" for every record whose `actors` list was empty, so 36 state-nexus records read as
unattributed, 8 of them beside `attribution_confidence: high`, the AA21-200B managed service
provider record among them: a joint advisory can attribute to a state without naming a group.
The line now falls back to the record's own type, as `no actor named; actor_type state_nexus,
attribution high`, and prints "unattributed" only for a record that says so.
`tests/test_query_ranking.py` holds every such record to its type.

TWENTY-TWO PUBLIC CITATIONS CARRIED A DESCRIPTION WHERE THE PUBLISHER'S TITLE BELONGS. The
2026-09-13 restoration matched "research on", "commentary on" and "analysis of", and missed
"research across", "investigation into", "Joint advisory X on", "<Publisher> on <topic>",
"combined from three published assessments" and "parts 1 to 3". Each page was fetched and its
title restored where two of `og:title`, `<title>` and the headline agree. Where a site's
`<title>` is an SEO rewrite, as at Wiz, Horizon3, Zscaler and Elastic, the record cites the
article's headline, which is how the corpus already cited Wiz and Horizon3. Nine government
titles that had been shortened or had lost their quotation marks, and one that had been
paraphrased, were restored with them. Where a title described a synthesis, the record's content
was checked against the one URL it cites:
- The DMZ record's "two separate red team assessments" are AA24-326A and AA24-193A, whose first
  findings match, so AA24-193A is now its corroboration. The forged-ticket and outbound records
  took their missed-opportunity list and proxy block from AA24-326A, which is now theirs. The
  forged-ticket record's date is AA23-059A's 2023-02-28, not 2023-03-01.
- The red team records' years and sectors were still the union of the three advisories. A
  sector is now one that an advisory the record cites assessed, and a start year is one that
  such an advisory gives. AA23-059A assessed a critical infrastructure organisation in 2022,
  AA24-326A a critical infrastructure organisation it does not date, and AA24-193A a federal
  civilian executive branch organisation from early 2023. The legacy-host record cites
  AA24-326A alone and was observed from 2022, AA23-059A's year. It now has no observed range,
  only its November 2024 publication, and its sector is `cross_sector` without `government`.
  Its note called the assessed organisation "a general enterprise", and now calls it a critical
  infrastructure organisation. The DMZ record now starts in 2023, AA24-193A's year, and keeps
  `government` from that federal assessment of the same first finding. The forged-ticket
  record keeps 2022 and drops `government`, because both its advisories assessed critical
  infrastructure organisations.
- The Cloudflare Pages record cites part 1 of a three-part series, and its container escape and
  rebuilt-platform findings are in parts 2 and 3. Cloudflare's own account of the same reports
  covers both and is now its corroboration.
- The prose of the partner-trust and legacy-host records, and of the Phobos record with its
  Rhysida corroboration, says what their advisories say; the Phobos record's note named a field the
  schema retired in 0.19.0 and now names `where.corroborations`.
- The Talos base-rate record now carries its cited post's title, and is `status: seed`. It
  summarised eighteen quarterly reports and cites the last, so a title fix alone made the
  citation look exact over content the page does not hold. The one series figure that page
  can check did not survive: insufficient logging "in eighteen to forty-two percent of
  engagements, every year" has as its two ends the page's own 42 percent against 18 percent
  the quarter before. The summary now gives the quarter's own figures and states the series
  argument as unconfirmed, the series figures are cut rather than held, the logging and
  remote management detections cite the quarter, it is observed April to June 2026 and read
  on 2026-09-25, and its notes say which half the page supports. Citing the series is still a
  decision: the schema holds one citation, and another quarter is not a corroboration.
The seven records that named a combined source in `source_id` now name their advisory.
`tests/test_citation_support.py` runs the wider detector and compares every cached page title,
and also holds that no hand-written record carries an identifier newer than its source, that no
single-source study observes past its own publication, and that verified independent research
says when it was read. Three records are listed there as owed a re-read, with the reason: the
watchTowr index record and the FiGHT and ATLAS knowledge-base records. It also pins, per record,
the impacts, actors, sectors and start years corrected above, because the identifier and date
checks cannot see any of them.

EIGHTEEN HOW-BLOCKS CITED A PATTERN THEY SHARE NO EVIDENCE WITH. The pattern link decides a
finding's ACTION line and half its COUNTERMEASURES, and advise.py counts every citing record as
OBSERVED. A CloudTrail enumeration of Lambda functions printed "Build a threshold rule: Application
configuration files read from the internet", with T1190 among its countermeasures. Five were
different mechanisms and are unlinked, so their ACTION falls back to the record id: Lambda #0 and
npm #3 (env-file harvesting), Okta #2 (banking-trojan browser hooking; a proxied fetch hook is an
adversary in the middle, not an operator watching keystrokes, so it was not re-pointed),
trycloudflare #1 (a startup shortcut) and Langflow #1 (C2 over a file service, for a crontab line).
The data-extortion record's block #3, an inventory of outdated remote access appliances, now cites
`pat-legacy-unpatched-exposed-service` rather than post-disclosure scanning. Four patterns had too
narrow an evidence list for blocks that are the same scenario: `cloud_audit` joins the
logging-coverage and audit-policy patterns, `file_artefact` and `edr_process` the autostart
pattern, and `edr_process` the ledger-resolved C2 pattern. Five blocks read the same scenario from
telemetry the pattern does not list, two of them from a database query log `vocab.json` has no type
for, and are written down with their reasons in `tests/test_pattern_attachment.py`. Records citing
a pattern moved: env-file harvesting 3 to 1, browser hooking 2 to 1, C2 over a file service 4 to 3,
post-disclosure scanning 8 to 6 (the data-extortion block here, and the Ivanti duplicate above),
legacy unpatched service 3 to 4. `pat-lnk-pointing-to-user-writable-path` lost its only citation,
so it now carries markers taken from its own sketch, because the library block skips a pattern with
none, and `corpus/README.md` says 34 patterns are uncited, not 33, which a test now checks.

THE ALIAS TABLE LOST FOUR ENTRIES THAT NAMED A VENDOR NOBODY IS, AND GAINED THE ROUTES THE
COMING GATES WOULD OTHERWISE CLOSE. The vendor aliases `msp` and `impacket` pointed at `any`, so
"we are an MSP" resolved `vendors=any` and consult called it product resolution; the class alias
`msp` still carries it. The product aliases `package manager` (npm, for any package manager) and
`cargo` (one crate, for the Rust build tool) are gone, `cargo` with its ambiguous entry. The
fuller names quantum security gateway, omnissa horizon, cursor ide, cursor editor, ivanti epm,
ivanti endpoint manager mobile and exchange online now resolve their products on their own, and
elastic stack and elastic nv the vendor, so gating the bare words in the resolver release costs
no route. "sd wan" now reaches `network.wan_edge`, where only "sdwan" did, and "siemens s7" and
"simatic s7" reach `ot.plc`, where "Siemens S7" resolved the vendor and left the control plane
absent. The design asked for a bare "s7", and a bare "s7" sent "Samsung Galaxy S7" to the PLC
class: a handset question, which the bundle keeps out of scope, answered from the industrial
control plane. Class aliases have no gate, so the alias carries the family's own word instead.
"S7 PLCs" and "an S7 controller" still reach the class through "plc" and "controller", and a
handset named S7 now resolves as "Samsung" alone does. `tests/test_class_aliases.py` holds both
directions. `tests/test_sentinel_vendor.py` holds the deletions; the resolver half, which stops
a product alias whose vendor is `any` putting `any` in `RESOLVED_TO`, is below.

These record corrections moved no primary locus on their own. The Ivanti duplicate took one
block out, so every locus tally is over 770 how-blocks rather than 771, and the router record
brought two declared overrides; the ladder changes below then moved the distribution. The new
tests were run against the corpus as it stood before the corrections: every one that asserts a
correction fails there, and the KEV overlap check passes there and fails on the corrected
observations until the generator is re-run.

ONE PRODUCT HELD TWO KEV RECORDS TEN TIMES OVER, AND NOW HOLDS ONE. The catalogue sometimes
repeats the vendor inside a product string, "Android Kernel" beside "Kernel" and "Drupal core"
beside "Core", and sometimes files a product under a former owner: "Pulse Secure", "Google" for
the Pixel handsets, "PHP Group". The generator's slug merge keys on vendor and product together
and could join none of them, so "Android kernel" listed the record holding the newest kernel
identifier, CVE-2024-36971, fourth, behind two other Android products. The generator now maps
the ten strings onto the name the alias table already resolves, and never onto a bare string
another vendor carries: "Kernel" is Linux's and "Core" is WordPress's, so the other direction
would have put Android identifiers into "Linux kernel" answers and Drupal ones into "WordPress
core" answers. The ten records left behind were deleted after checking that every identifier
each held is on its survivor, because the merge never deletes: Roundcube Webmail went from 4
identifiers to 11, Android Kernel and Drupal core from 2 to 5 each, Kentico Xperience from 1 to 4,
Pixel from 4 to 6, and IOS XE Web UI, Pulse Connect Secure, PHP and QNAP's Network Attached
Storage gained one each. The two Pixel identifiers filed under Google had been classed
`endpoint.browser` with a watering-hole surface by the Google vendor default; they now sit on
the Android Pixel record as `endpoint.os`, which places a handset record and brings no handset
into scope. A guard after the merge now refuses any run in which two surviving strings are one
product once the vendor goes through the corpus's own vendor aliases and a leading vendor name
is dropped from the product, unless a `DELIBERATELY_SEPARATE` entry gives the reason. Product
strings that several vendors share, such as core, kernel and ios, are printed for review rather
than refused, because they are usually different products. Six product aliases named a string
that went with its record and now name the survivor, and the vendor alias `php group` resolves
`PHP`. KEV records went from 709 to 699 and the corpus from 1,159 to 1,149.
`tests/test_generated_classes.py` holds that no two KEV records are one product, that the ten
are gone and their survivors carry every identifier, and that no repointed alias names a
product no record carries.

A KEV SUMMARY NO LONGER NAMES A YEAR IN WHICH NOTHING WAS ADDED. The generator wrote "added to
it in each year from A to B" for any three years or more. That was a correction for "2021 and
2026" said about identifiers added across six years, and it overcorrected: 32 of the 49
summaries using it named a year with no identifier. EPMM was added in 2023, 2025 and 2026 and
read "each year from 2023 to 2026". A span is now claimed only when it has no gap, and otherwise
the years are listed, so EPMM reads "2023, 2025 and 2026" and F5 BIG-IP "2021, 2022 and 2026".
The 32 summaries changed only in that clause. The merged survivors' years were recomputed with
their identifiers, and Android Kernel reads "2021, 2022 and 2024". The catalogue does not ship,
so `tests/test_generated_claims.py` pins those two records and holds every remaining span to
the bound the corpus can check: a span of Y years needs at least Y identifiers.

FOURTEEN GENERATED RECORDS WERE CLASSED BY THE WRONG WORD, AND THE ALIAS TABLE COPIED THEM. The
KEV classifier is a first-hit keyword ladder, and its errors were copied into `aliases.json`, so
a question's plane followed them. "nexus" is a Cisco switch line and fired before "nexus
repository", so both Sonatype repository records were `network.switch`. "exchange" caught
Internet Key Exchange as `server.mail`, "operating system" caught Arista's switch operating
system as `endpoint.os`, "ignition" caught Laravel's debug error page as `ot.scada_server`, and
"access control system" caught Cisco's TACACS+ and RADIUS server as a door controller. Vendor
defaults decided the rest: Microsoft's gave Partner Center and Forefront TMG `endpoint.os`, and
Broadcom's and ASUS's gave a Fibre Channel switch OS `server.hypervisor` and a Windows update
client `network.router`. The eleven KEV pairs are now explicit classifier entries: Laravel
Ignition `server.web`, both Sonatype records `app.cicd`, Arista EOS and Brocade Fabric OS
`network.switch`, Forefront TMG `network.firewall` then `network.proxy`, Streaming Service
Proxy, IKE Service Extensions and ASUS Live Update `endpoint.os`, Partner Center `cloud.saas`,
and Cisco ACS `identity.directory`. The Android Pixel pair is pinned as `endpoint.os` too, so the
Google default can never reach it again. Two ladder rules gained a guard, "nexus" not followed by
"repository" and "exchange" not preceded by "key", which decides where the next such product
lands. Run over all 726 catalogue pairs before and after, the change moved exactly the eleven
pairs above, and the guards alone moved three of them. The PSIRT table put Nokia's Single RAN,
BTS and ASIKA, a base station and its baseband software, on `network.wan_edge`, SD-WAN or
branch edge; they are `telecom.ran` now, which the vocabulary defines by base stations. Both
classes derive CONTROL, so no plane moves, but a radio access network question now reaches
them. Twenty-one product aliases now carry the corrected class. They name the products above,
except the two IKE aliases, which already said `endpoint.os`, and add WatchGuard's "firebox and
xtm" pair, which said router over two firewall records. The list also includes the four
Juniper aliases for SRX, EX and J-Web: they still said
`network.router` after the J-Web record split earlier in this release stopped carrying it, and
SRX is now `network.firewall`, EX `network.switch` and J-Web both. `tests/test_generated_classes.py`
pins all fourteen classes and the KEV tags that follow them, and a new test holds that an
alias's first-listed class is one the records naming its product carry. It checks the first
class only, because 0.26.0 deliberately gave the EPMM aliases `app.rmm` after `app.mdm` to keep
their fleet-management context. It exempts four aliases, each with its reason, for products
named among five on one hand-written record whose classes describe the incident. The Sonatype
pair is still two records, "Nexus Repository" and "Nexus Repository Manager", for one product
line: neither string contains the vendor, so the split guard does not see it, and merging it was
not part of this change.

THE ZDI RECORDS NOW SAY WHAT THEY CARRY, WHERE THEY SIT, WHETHER THE CATALOGUE HOLDS THEM, AND WHEN
THEY WERE READ.
- The lead sentence counted advisories and the record carried distinct CVEs, and 14 of 67 did not
  reconcile. 31 advisories have no CVE, and some share one: all 11 of EcoStruxure Power Build's
  advisories carry one CVE. Four records carried no identifier at all and passed validation only on
  a boilerplate `versions_affected`. An advisory with no CVE is now carried by its programme
  identifier, such as `ZDI-26-226`, which the schema's identifier pattern already admitted. That
  adds 31 identifiers across seven records: 15 on the Linux kernel, 6 on Docker Desktop, 3 on
  Windows, 2 each on Azure, Office and Qlib, and 1 on Olive. The sentence now splits the count.
  Docker Desktop reads "12 advisories ..., carrying 5 distinct CVE identifiers; 6 carry no CVE and
  are listed by programme identifier; 1 repeats a CVE another of these advisories already carries."
- `attack_surface` was `internet_facing_management` if any advisory was remote and
  `physical_or_console` otherwise, and the locus map commits both to MANAGEMENT. Every ZDI record
  therefore derived MANAGEMENT whatever the product, and two remote advisories out of forty put the
  Linux kernel there. The surface now follows the majority of ZDI's own attacker position, "allows
  remote, network-adjacent, local or physically present attackers", which every one of the 307
  advisories states. A remote or adjacent majority, or an even split, takes the KEV generator's
  class table, loaded from it rather than copied, so a ZDI record and a KEV record of one class
  agree. A local majority is `credentialed_user`, which the map defers, so the class decides, and a
  physical majority is `physical_or_console`. The kernel (36 of 40 local) and Windows (32 of 40)
  now derive ENDPOINT, and Exchange DATA. The position sentence gives all three counts, so the
  surface can be checked against it.
- The "none of them present in the catalogue" sentence and the `not-in-kev` tag were written
  without the generator ever reading the catalogue. Five records carried an identifier the
  catalogue already listed, the earliest since March: Secure Firewall Management Center
  CVE-2026-20316, Ivanti Endpoint Manager CVE-2026-1603, SharePoint CVE-2026-50522, PeopleSoft
  CVE-2026-35273 and Kemp LoadMaster CVE-2026-8037. `query.py "Kemp LoadMaster"` printed the KEV
  record and the denial three lines apart. The generator now reads `kev.json`, names what it holds
  and tags those records `in-kev`.
- The source block cited one advisory of up to forty under a title the generator wrote, labelled
  ZDI the affected vendor's own advisory, and never said when it was read. It now cites the 2026
  published listing every row comes from, by its own title "Published Advisories", as
  `vendor_research`, with a `source_id`, a read date of 2026-09-25 and `verified`. SOURCES.md lists
  Zero Day Initiative as `vendor_research`.

THE PSIRT AND DATABASE RECORDS HAD THE SAME THREE DEFECTS, AND TWO CORRECTIONS THEIR GENERATORS
WOULD HAVE UNDONE. All 55 PSIRT and 44 vulnerability-database records carried the constant
`internet_facing_management`, so FortiClient and the Nokia base stations were management-plane
findings by default. They now take the KEV class table. The Citrix NetScaler database record
said CVE-2026-8452 was not in the catalogue, which added it on 2026-08-26; the three generators
now check, and it is tagged `in-kev`. Their source blocks gain a `source_id`, a read date of
2026-08-01 and `verified`. Two corrections the corpus had received were never made in the
generators, so the next regeneration would have reverted them, which is the 0.38.0 failure
again: attribution confidence `none` rather than `low` on all 99 records, and the Ivanti
endpoint and mobile management record's `app.mdm` before `app.rmm` from 0.26.0. Both are in
the generators now. Regenerating needed the inputs, and they were gone: the PSIRT row store
held 17 rows of a later collection and the database one 25 Huawei handset rows, neither of which
produces the shipped records. The Huawei collector filters against the corpus it is given, and
the corpus now holds every identifier it would keep. The stores were rebuilt from the
collectors' own caches with the network refused, filtering against the corpus as it stood
before each ingest. The unchanged generators then reproduced the shipped database and Huawei
records byte for byte, and the PSIRT records in 54 of 55. The 55th, `exp-psirt-nokia-ont`,
carried six identifiers, five of them attached by a substring match of "ONT" inside "Control"
and "content". The collector documents that defect as fixed, but the records were never
regenerated. The record now carries CVE-2025-9974 alone. Four of the five are on their own
products' records, and CVE-2025-24937 leaves the corpus: its advisory names no product, and no
record is generated for a vendor alone. `huawei.py` now writes its kept rows to a store and
regenerates from it, so a KEV refresh can re-check those records.

A generated exposure's surface is no longer read for its locus at all (see the locus ladder
below), so these corrections move no printed locus: they make the field say what the advisories
say. The generator tags in `untrusted_surface_tags` record `vendor_research` as the ZDI
generator's `source_type`.

VALIDATE.PY NOW REFUSES A KEV TAG THE CORPUS CONTRADICTS. A record tagged `not-in-kev` that
carries an identifier a `known-exploited-catalogue` record holds is a problem, and so is a record
tagged `in-kev` that carries none. The check reads the corpus rather than a snapshot, so a KEV
refresh that is not followed by regenerating the other three families fails validation. Run
against the 0.42.0 corpus it reports the six records above. `corpus/README.md` describes the
four generated families and the refresh obligation. Its KEV count said 704 of 709, and says
699. `tests/test_generated_claims.py` holds the reconciled ZDI count, the attacker-position
surface, class-table surfaces for PSIRT and database records, the three planes above, the KEV
tags against the corpus's own KEV records, the source blocks, ZDI's source type and the
validator check. `tests/test_citation_support.py`'s descriptive-title check now reads the
generated families as well.

The generators live in a shared staging folder outside this repository, which has no history,
so every change is recorded here. Each file was copied to `<file>.pre-0925c` before it changed:
- `kev/generate.py`: ten `RENAMED_PAIRS` entries, the split guard with `DELIBERATELY_SEPARATE`,
  and the gap-aware year wording.
- `kev/classify.py`: twelve `PAIR` entries and the two ladder guards.
- `zdi/generate.py`: programme identifiers and the reconciled count, the attacker-position
  surface through the KEV table, the catalogue check and `in-kev` tag, and the listing source
  block with `RETRIEVED`.
- `psirt/generate.py`: the class-table surface, the catalogue check, the source fields, `none`
  attribution, and `telecom.ran` for three Nokia products.
- `psirt/nvd_generate.py`: the same four, and a class list for the Ivanti mobile family.
- `psirt/huawei.py`: the same four, and collection split from generation.
- `psirt.jsonl` and `nvd.jsonl`: rebuilt from cache, with `huawei.jsonl` new.

The regenerated set was compared with the corpus field by field before merging. KEV changed
only in the ten merges, 32 year clauses and the eleven classes with their tags and surfaces, and
no other field of a KEV record moved. ZDI, PSIRT and the database family changed only in the
fields named above.

`ANY` AND `MULTIPLE` ARE NO LONGER RESOLVED AS VENDORS. The alias corrections above removed the two
vendor aliases that named `any`. 23 product aliases still name `any` or `Multiple` as their
vendor -- git, npm, yarn, pypi, suricata, github actions, rust crate and others -- and each put
the sentinel into `RESOLVED_TO`. Every one of the 131 `any` records then scored as a vendor
match, and `consult.py` counted it as naming the technology: "npm supply chain" returned 512
findings under `RESOLUTION: product`, "git" 387, "Suricata IDS" 420 and "GitHub Actions
self-hosted runners" 436. `query.py` now holds `SENTINEL_VENDORS`. A sentinel is never a
resolved vendor, never a record's vendor match and never a corroborator; until now the gate
looked for the literal word "any" or "multiple" beside it. Such an alias still resolves its
product, recorded as naming no vendor, and matches that product under any vendor. The four
questions return 36, 24, 74 and 43 findings.
Suricata, which no observation names, is `CLASS-LEVEL (inferred)`, and "GitHub Actions" leads
with a GitHub Actions record. `rust crate` and `crates io` are deleted with `cargo`: each named
arrayref, one of the five crates on its record. A new class alias `crate` takes "Rust crate" to
`dev.library`, where the leftover "rust" puts the crate record first in `query.py`.
`tests/test_sentinel_vendor.py` holds the resolver half beside the data half.

THIRTY-FIVE MORE ORDINARY WORDS ARE GATED AS PRODUCT NAMES, AND A GATE NOW NEEDS A WHOLE NAME.
`ambiguous_aliases` held 41 words, and none of the 38 single-word product aliases that are
dictionary words and ungated. "Zorblax Quantum Edge Gateway 9000" resolved to Check Point's
Quantum Security Gateway at `RESOLUTION: product`, "key exchange appliance" to Exchange Server,
"x-ray of our estate over a 90 day horizon" to Ray and VMware Horizon, and "tracking pixel in a
phishing email" to the Android Pixel, a handset. Sixteen dictionary words are gated (quantum,
exchange, horizon, cursor, ray, dawn, ignition, amplify, triton, auditor, coherence, concerto,
counteract, expedition, eyesight and vigor), with pixel, airflow, superset, eos and epm, and
fourteen generic multi-word names such as security gateway, email server, network attached
storage, backup and replication, sd wan and endpoint manager. Each carries its reason. The other
22 dictionary words are listed in a new `_ambiguous_reviewed_keep`, each with the reason it is
kept, and a test fails on any dictionary-word alias in neither list. Two of them are recorded
false positives, pinned as still failing: "maintenance windows" resolves Windows and "threat
outlook" resolves Outlook, because gating either loses the commonest way of naming the
product. "veeam backup and replication" is new, because the "and" spelling is NAKIVO's gated
alias; the other fuller names came with the alias corrections above.

The gate itself admitted any single word of the vendor's display name. "An AV viewer on the
desktop" resolved Justice AV Solutions' Viewer on "av", "wan link routers" D-Link's on "link",
and "check the quantum readiness of TLS" would have resolved Check Point on "check". It never
read the vendor aliases, so "MS Word macro" lost Word. A corroborator is now the vendor's whole
name or any of its vendor aliases, as a complete word sequence within two words. An ordinary-word
product is also admitted within two words of an unambiguous product of the same vendor, so
"Ivanti EPMM and Sentry" names Sentry, which vanished silently before, and "Cisco ASA and IOS"
names IOS. Anchoring from anywhere in the question was measured and refused: Microsoft's 104
unambiguous aliases anchor its eight gated ones, 53 of the 76 gated product aliases had an
anchor somewhere, and "Cisco ASA VPN users on iOS and Android phones" resolved Cisco IOS, the
0.29.0 defect, while "edge devices ... domain controllers" resolved Microsoft Edge and the
browser class. Inside the window the words cannot tell a list from a compound, so "SharePoint
project sites" still resolves Microsoft Project and "Active Directory and edge VPN appliances"
Edge; a test pins both as still failing. A vendor alias does not anchor, which keeps the
Guardsquare question from meaning Android Runtime.

SEVENTEEN VENDOR ALIASES ARE ORDINARY WORDS, AND NONE NAMES A VENDOR ON ITS OWN. The vendor
table had no gate. "Beacon interval jitter of 500 ms" resolved Microsoft on `ms` and answered
`RESOLUTION: product` over 177 findings. "PAN data exfiltration from the cardholder environment"
resolved Palo Alto Networks, "a pulse of outbound DNS" Ivanti, "attack in progress on the storage
array" Progress and Array Networks, and "Microsoft Sentinel analytics rules" Thales. A new
`ambiguous_vendor_aliases` lists algo, ami, arm, array, checkbox, daemon, elastic, meta, ms,
nice, notepad++, pan, progress, pulse, quest, rails and sentinel, each with its reason. Such an
alias adds no vendor on its own, and is a no-op beside a product or fuller name of the same
vendor ("PAN Panorama", "Progress MOVEit Transfer"). It still corroborates that vendor's
ambiguous products. Bare "Progress" and "Elastic" therefore resolve no vendor, and "Progress
Software" and "Elastic Stack" do. "Quest KACE" resolved nothing, because `quest` is gated and
KACE had no alias of its own; `kace` is now a product alias, and names Quest through it. `akira`
is gone from the vendor table: it is a ransomware operation, and has no record as a vendor. The
jitter question is now a mechanism answer over 85 findings.

CLASS ALIASES HAVE A GATE, AND THE FOUR KNOWN SURVIVORS WERE NINETEEN. SKILL.md and the 0.30.0
entry said only ran, relay, ad and switch still set a false class. Measured on 2026-09-25:
- "which event IDs should I watch" and "block these IPs" resolved `network.firewall`;
- "limit the blast radius" resolved `identity.directory`;
- "Kubernetes ingress controller" and "baseboard management controller" resolved `ot.plc`;
- "Spring Boot actuator heapdump" resolved `ot.field_device`, and "an exposed API endpoint"
  `endpoint.os`;
- "deploy the content pack to our XSIAM tenant" resolved `cloud.identity`, "our detection
  library is thin" `dev.library`, and "Linux PAM module backdoor" `security.pam`;
- "Ivanti Endpoint Manager Mobile" reached `endpoint.os`, which made ENDPOINT its largest locus,
  against the standing decision that the mobile management plane is MANAGEMENT.

A new `ambiguous_class_aliases` gates nineteen aliases, each by one of three modes:
- `upper` admits ids, ips, radius, ad, ran, sim and ci only where the question writes them in
  capitals;
- `refuse_near` refuses actuator, endpoint, endpoints, tenant, library, pipeline, workflow,
  package, pam, udm and routing beside the words that make them something else;
- `require_near` admits controller only beside the words that make it a PLC.

Deleting controller outright was designed and not done. It is gated instead, because a test
holds "an S7 controller on the plant network" to `ot.plc` through it. `upper` depends on
casing, so a consumer that lower-cases its questions loses the IDS, IPS, RADIUS, AD, RAN, SIM and
CI routes, and SKILL.md says so. `ews`, bare `directory` and `teams` are deleted. Each collides
with a name (Exchange Web Services, directory traversal, red teams), and each class keeps other
routes; `ldap` is added. The ran and ad tripwires in `tests/test_class_aliases.py` are inverted,
as their docstring directed. Relay and switch stay pinned as still failing, and "switches" and
"switching" are pinned beside them. A new `singular_only` list stops ci matching CIS, ad matching
"ads", and hf, Hugging Face, matching Rejetto's HFS. `upper` reads the capitals at the word that
matched, not anywhere in the question. ad, ids, ips, ran and sim take the acronym's plural,
capitals and a lower-case s, so "ADs", which `singular_only` had taken away with "ads", resolves
again, and "SIMs" and "RANs", which never had, now do; ci does not, because "CIs" are
configuration items.

A LONGER NAME CLAIMS ITS WORDS. Product aliases never claimed their span, so a shorter alias
inside an admitted longer one also resolved. "Fortinet SD-WAN" named Cisco, "Barracuda email
security gateway" Check Point and Libraesva, "Veeam Backup and Replication" NAKIVO, and "Azure
Active Directory" on-premises Active Directory, on another plane. A shorter alias wholly inside a
longer admitted one no longer resolves when it names another vendor. Inside a longer name of the
same vendor it resolves only where it is a component of a composite ("apex one and officescan")
or the same product spelt another way ("junos os" inside "juniper junos os", "fta" inside
"accellion fta"). So "Ivanti Endpoint Manager Mobile" is EPMM and not EPM as well. Vendor aliases
follow the same rule, and an alias naming no vendor claims nobody's words. Asked as "<vendor>
<alias>", the 1,084 product aliases with a named vendor resolved a second vendor 70 times, 37 of
them outside the vendor's own family. Now 21 of 1,086 do, all within the family, and none loses
its product. Asked verbatim, 209 of 1,106 aliases resolved a second product, and 79 of 1,106 do
now. The gates can take a product from its own vendor's natural phrasing too: "Barracuda email
security gateway" had reached Barracuda's product only through Libraesva's alias, and with that
alias gated it resolved the vendor and the class alone, so `barracuda email security gateway`
is now Barracuda's own alias, as `quantum security gateway` is Check Point's. The test that asks
the whole table takes about a second, because each alias pattern is compiled once. The re module
caches 512 patterns against nearly two thousand aliases, so every call used to recompile them.

The design asked for the `sd-wan` product alias to carry `network.wan_edge`, and it still
carries `network.router`. That is the class of the Cisco SD-WAN KEV record it names, and of all
nine KEV records with SD-WAN in their product, set by a deliberate classifier rule.
`tests/test_generated_classes.py` holds an alias to its records' class, so moving it means
reclassifying those records in the generator. An SD-WAN question already reaches
`network.wan_edge` through the `sd wan` class alias, and both classes derive CONTROL.

`normalise()` now collapses runs of whitespace. 111 alias keys held a run of spaces, from
punctuation beside a space, and matched only text punctuated the same way: "Veeam
Backup&Replication" resolved no product and "Check  Point firewall" no vendor. One more pair of
keys normalises to one, `cpanel/whm` and `cpanel & whm`, which carry the same value.

WORDS A RESOLVED ALIAS ACCOUNTED FOR ARE NOT SEARCHED AGAIN. Every word of the question was a
free-text term, so once Check Point resolved, "check" and "point" were searched through every
other record's prose. "Check Point firewall" matched 267 findings, 188 of them on "entry point",
"integrity check" and the like, and reported no locus absent. "Palo Alto Networks firewall"
matched 220 while "PAN-OS firewall" matched 97, so the plane answer depended on how the vendor
was spelt. Every admitted span now consumes its words, classes and sectors included, and a
gated alias consumes nothing. An admitted vendor or product is searched as its whole phrase, in
names only. Both firewall questions now match the same 74 findings with the same locus counts,
"Fortinet FortiGate in a water utility" matches 78 rather than 166, and "Trend Micro Apex One" 53
rather than 493. A question that resolves nothing consumes nothing, so mechanism answers are
unchanged: "phishing" still matches 78. `score()` now also tries free-text terms in sorted
order, so `query.py --json` lists a record's reasons in a fixed order, where the order varied
with Python's hash seed from one run to the next.

With nothing left to search, a vendor name that no observation carries reaches no finding, and
31 vendor-only questions went from `NAME_WITHOUT_RECORDS`, over loose prose on "networks",
"server" and "systems", to `UNRESOLVED`: Hewlett Packard Enterprise, Red Hat, Trend Micro, TP-Link
and others. The `UNRESOLVED` line said nothing in the question matched a vendor under a
`RESOLVED_TO` naming one, which it did for 230 of the same 1,396 questions, and the advice below
it said to add an alias that exists. Where a name resolved, the line now says so, "Hewlett Packard
Enterprise (HPE) resolved against the alias table, but no observation in the corpus names it",
and the advice reads "THE ALIAS EXISTS AND NO OBSERVATION CARRIES IT", a gap in the records to
report. `NO_FINDINGS` said "the resolver matched nothing" under "ServiceNow", which resolves a
vendor and `app.itsm`, and now names what resolved. The exit code and the `RESOLUTION:
UNRESOLVED` prefix are unchanged; a name held only by exposure records reads `EXPOSURES_ONLY`
instead (see the resolution modes below).

The words left over after the technology resolved were never tested against a record that
matched by name. "Fortinet FortiGate boot image implant" listed the Fortinet records in exactly
the order of "Fortinet FortiGate". Those words are now tested against the tags, pattern wording
and summary of such a record, reported as `refine term <word>`, and score nothing, so
`query.py`'s scores are unchanged. They break ties in `query.py`, where the boot-image implant
record now comes first of the two Fortinet records scoring 13. In `consult.py` they order the
findings of a match group ahead of the weight (see the ordering below), and print as
`refined_by=` at the end of `PRIORITY_BASIS`.

A VENDOR NAMED INSIDE A GENERIC RECORD'S PRODUCTS IS THAT VENDOR. Where a record covers a class,
its makers are listed in `who.products`, which the vendor match never read. Eleven observations
name GitHub there, and "GitHub" was answered `NAME_WITHOUT_RECORDS` with `identity=0`. A resolved
vendor whose name or alias stands as whole words in a product entry of an `any` or `Multiple`
record is now a vendor match, reported as `vendor GitHub (named in product GitHub)`. "GitHub" is
answered from 16 findings reached by name, with SUPPLY present. Such a match counts toward
`RESOLUTION: product` only when the record carries a class the question resolved, or the
question resolved none, and never when the question named a product. The Guardsquare question
resolves the Android vendor and two build-pipeline classes. A botnet record listing "Android TV
boxes" would otherwise have made that class-level answer a product one, which is the 0.29.0
defect again. Five generic endpoint records list "Linux servers" or "Linux endpoints", and
counted, they moved "Linux kernel" to `RESOLUTION: product` without `CLASS_LEVEL_WARNING` over
twelve findings none of which named Linux; it stays `CLASS-LEVEL (inferred)`. `consult.py` names
the rule `names_what_was_asked()`. Where it does not count, the match is weighed and labelled as
the record's `class` match, or as `name-fragment` where the record carries no class the question
resolved (see the match tiers below): at full weight the botnet record reached the Guardsquare
top 12 labelled as naming the technology, and a remote-access record listing Pulse Connect
Secure did the same for "Ivanti EPMM". The `name-fragment` label now reads "the record was not
reached as the technology you named", which is true of both kinds of match. A sector reason
decides no tier. It is structured, and the tightest reason decided the tier, so naming a sector
undid the demotion: with "Fortinet FortiGate" the Fortinet-appliances record was
`name-fragment`, and with "in healthcare" or "in a water utility" added it counted as naming the
technology, moving four findings between tiers. A sector says where a record's victims were,
never whether it names the technology, and the tally no longer moves with it.

A PRODUCT NAMES A RECORD UNDER ITS OWN VENDOR, AS THE RECORD SPELLS IT. The product test was
exact string equality with no vendor check, and it failed both ways. Twelve products that have
observations were missed, because the alias table spells them as the catalogue does and the
records as the vendor does: "ESXi" against "VMware ESXi", "Endpoint Manager Mobile" against
"Endpoint Manager Mobile (EPMM)". And a string two vendors carry gave the other vendor's record
product weight: "Desktop" is Docker's and TeamViewer's, "Multiple Products" eighteen vendors'.
One helper, `product_matches()`, now serves `score()` and the new `exposure_tier()`. A product
names a record only under the alias's own vendor, and it matches by canonical equality: bracketed
segments and the vendor's own name removed, and a trailing s optional. Token containment was
measured as the alternative and rejected, because it matched Endpoint Manager (EPM) to EPMM. A
product whose alias names no vendor, such as git, matches under any vendor, which is what keeps
those products reachable after the sentinel fix. A record whose own vendor is `any` or
`Multiple` has no vendor to test, and the first form of the matcher let any of its entries
match under the question's vendor. "Sophos Firewall" was answered `RESOLUTION: product` without
`CLASS_LEVEL_WARNING` from two records listing "firewalls", and "D-Link routers", "QNAP network
attached storage" and "SonicWall firewall appliances" the same way, though no observation names
any of the four vendors. Such an entry now names a product only where it names the product's vendor
("VMware ESXi", "Google Chrome"), or stands as one of the product's aliases without it: an
unambiguous one ("Zimbra Collaboration Suite", "Active Directory"), or a gated one whose words
do not read as a class. "firewall", "routers" and "network attached storage" are gated because
they are every vendor's, and a record naming no vendor never puts the vendor beside them; "Cursor"
is gated for the text cursor, and in a list of coding agents it is Anysphere's editor.
`network attached storage` is a new class alias, to `security.backup` with `nas`, and bare
"network attached storage" now resolves that class where it resolved nothing. The four questions
are `CLASS-LEVEL (inferred)` again, as before the matcher, and across 1,396 vendor and product
questions nothing else changed mode but three more spellings of the QNAP one.
`tests/test_sentinel_vendor.py` lists every gated entry of an `any` or `Multiple` record and how
it was decided, so a new one fails until it is. A record's vendor string now matches through
the vendor's alias keys and two new tables. 18 exposures are filed under VMware while "VMware"
resolves to Broadcom, and the corpus also files lines under VMware Tanzu, Symantec, Telerik,
Hewlett Packard, Barracuda, QNAP Systems and Rockwell. `vendor_spellings` holds one company
filed under two names, Barracuda, QNAP and Rockwell, which match both ways. `vendor_families`
maps a parent to the lines it acquired, VMware, VMware Tanzu and Symantec under Broadcom,
Telerik under Progress and Hewlett Packard under Hewlett Packard Enterprise, and runs one way.
A question naming the parent reaches a member's records, reasoned `vendor VMware (as
Broadcom)`. A question naming a member reaches neither the parent's other lines nor a
sibling's. Read as a flat set, the table answered bare "Symantec" from 41 VMware ESXi findings
under `RESOLUTION: product`, and "Symantec Endpoint Protection" led with ESXi ransomware
labelled as naming the technology; both are now what they were before, unresolved and
class-level. A record the corpus files under the parent is the member's where one of its
products names the member, reasoned `vendor Symantec (filed under Broadcom)`, so the Broadcom
record on Symantec Messaging Gateway answers a Symantec question and the Brocade one does not.
`validate.py` refuses a family table that is not a map with one parent per line. `vmware` stays
a Broadcom alias, so a VMware question is a Broadcom question and still reaches Broadcom's
Symantec and Brocade lines as the vendor's other lines; separating them means filing the
Broadcom product aliases under their own lines, which is not done here.

`exposure_tier()` places an exposure relative to the question: `product`, `vendor-class`,
`vendor`, then `other-products-of-vendor` (the vendor's other lines, when the question also
named a product or class), `product-name-other-vendor`, `class-only` and `prose-only`.
`query.py` orders its listing by them, and a consultation's exposure blocks list the first three
(see below).

QUERY.PY BREAKS A TIE ON WHAT WAS ASKED, AND LISTS EXPOSURES BY HOW THEY RELATE TO IT. 67 of 73
"Linux kernel" observations tied at score 3 on class
alone, and the id broke every tie, so none of the 20 shown named Linux and 11 carried
Windows-only markers or names. Ties now go to the record carrying more of the question's leftover
words, then to one naming what resolved, then to one whose markers fit the platform the question
names, then to the newer, and only then to the id. The platform comes from marker content,
through an indicator table in `query.py` in which generic unix counts for Linux and macOS both
and curl commits to nothing, and for the question from a new curated `platform_of` table. The
first 6 of 20 now name Linux, and none is Windows-only. The library block had the mirror defect:
it ranked patterns on public rule counts that are per technique and platform-blind, so 4 of the 6
patterns shown for "Linux kernel" were written for Windows. A pattern written for another
platform now sinks below every neutral or fitting one. The six shown are host discovery, Linux
privilege escalation, directory permission change, local account creation, command history
cleared and control service stopped. (As first released here the list held indirect command
execution in place of the last, a Windows-only pattern that "bash.exe" made read as Unix; see
the product-identity entry below.) The weight line now reads "N Sigma/Splunk rule(s) tag a
technique this pattern cites (any platform)", not "corroborated by N external detection rules".

Exposures were listed by score and then by id, so a Cisco firewall catalogue record tied a
Check Point one at 3 on class alone, and 6 of the 10 shown for "Check Point firewall" were
Cisco's. The EPMM catalogue record ranked third for "Ivanti EPMM", behind two EPM records that
won the tie on their id. Exposures are now listed by tier, then exploited before advised before
disclosed, read from the identifiers, then newest first. Each line prints its tier, the header
prints a count per tier, and `--json` carries `exposures_by_tier`. "Check Point firewall" lists
its four Check Point records before any other vendor's, and "Ivanti EPMM" leads with the EPMM
catalogue record. `--json` also gains `tiebreak` on each observation, and `exposure_tier` and
`exposure_kind` on each exposure; `--full` prints both on the match line.

THE HEADER SAYS WHICH WORDS RESOLVED AND WHICH WERE REFUSED. Nothing tied Check Point to the
word "quantum" that produced it, so SKILL.md's instruction to read `RESOLVED_TO` against your own
words could not be carried out, and a refused word left no trace. `consult.py` now prints
`RESOLVED_BY:` after `RESOLVED_TO:`, naming the alias behind every vendor, product, class and
sector and what admitted an ambiguous one: `ios -> product Cisco / IOS (beside cisco)`. It prints
`GATED:` when a word matched an alias and was refused, with the reason. A refusal of a word that
another alias accounted for is not printed: "firewall" is refused as Sophos's product and
resolved as a class on every firewall question. `query.py` prints both, as `resolved by:` and
`gated:`, and its `--json` gains a `resolved` object with the vendors, products, classes,
sectors, terms, `resolved_by` and `gated`. These are header lines only: `RESOLVED_TO` keeps its
shape and the key set of a finding is unchanged, apart from the value appended to
`PRIORITY_BASIS`.

`validate.py` now checks the alias tables. It refuses a gate on a key no table holds, a gate
with no reason, a class gate mode `resolve()` does not know, which would silently switch the
alias off, a vendor alias naming a sentinel, and a `platform_of` value outside the closed list.
It also refuses a class alias naming a class the vocabulary lacks.

SKILL.md's resolver narrative moved to a new `references/resolution.md`, which has the order
aliases resolve in, what `RESOLVED_BY` and `GATED` say, every gate table and what it fixed, and
the matching rules. SKILL.md keeps a paragraph and a pointer. `corpus/README.md` says that
`any` is never matched as a vendor and how the gate tables are read. The 0.30.0 entry's
statement that four class aliases still misfire is superseded by the measurement above, and is
left as written. The resolver is held by `tests/test_ambiguous_aliases.py`,
`tests/test_class_aliases.py`, `tests/test_sentinel_vendor.py`,
`tests/test_mechanism_lookup.py`, `tests/test_subject_tiers.py`, `tests/test_class_fallback.py`
and the new `tests/test_query_ranking.py` and `tests/test_consult_exposures.py`, and
`tests/test_header_counts.py` checks the validator's alias checks.

THE LOCUS LADDER PLACES A BLOCK BY WHAT IT IS ABOUT, NOT BY A SECTOR TAG OR THE WAY IN. The
change is in `locus_for()`, `corpus/schema/locus-map.json` and `validate.py`. Three inputs
decided a block's plane while describing something else:
- A non-product class anywhere in the class list made the block ORGANISATION, "an inventory or
  advice question rather than an event located on a device". Authors use `cross_sector` as a
  sector tag, so the tier fired on 113 blocks, among them the Hive record's shadow-copy deletion
  and event-log clearing, read from EDR, and `emit_xql.py` handed the label to rule authors. It
  now fires only when the first-listed class is a non-product class, or every class is: 23
  blocks. Listed later, the class is a span source, and the basis says
  `nonproduct-signal=ORGANISATION (cross_sector listed, not primary)`.
- `email_flow` decided DATA for 64 blocks, most of them over a first-listed class on another
  plane. The Chrome records' renderer-breakout detections, read from EDR process events, printed
  DATA, and both Okta records printed DATA with no finding on CONTROL, the sign-in gate they
  abuse. `remote_access_service` did the same for host events, into MANAGEMENT. Both are in a
  new `surface_span_only` list: they name the way in, not the plane, which is why
  `watering_hole`, the web form of the same vector, was already deferred. Each still commits a
  locus, carried as the span, and the basis reads `surface-signal=DATA (email_flow is the way
  in, not the plane: span only)`.
- A generated exposure's `attack_surface` was read as though a source had said it. The KEV
  generator assigns it from a table keyed on the class, and the ZDI, PSIRT and database
  generators import the same table, so the surface tier re-encoded the class through a remap
  that sends firewalls, routers and hypervisors to `internet_facing_management`, and so to
  MANAGEMENT. A new `untrusted_surface_tags` map names the four generator tags and the
  `source_type` each generator writes. An exposure carrying one is placed by its class, and its
  basis prints the surface as `generator-assigned ..., not read`. The 36 hand-written exposures
  keep their authored surface, so the vCenter record stays MANAGEMENT on
  `internet_facing_management`. A consultation's `EXPOSURE` blocks print the result.

Over the 770 how-blocks, 155 move. The distribution goes from CONTROL 195, MANAGEMENT 154,
DATA 131, ENDPOINT 93, SUPPLY 83, ORGANISATION 114 to CONTROL 224, MANAGEMENT 162, DATA 84,
ENDPOINT 189, SUPPLY 83, ORGANISATION 28. ORGANISATION is 3.6 per cent, above the 2 per cent
every value was held to when the axis was introduced, so all six values stay. Over the 901
exposures, 261 move: MANAGEMENT 265 to 90, CONTROL 105 to 306, DATA 257 to 268, ENDPOINT 145 to
149, SUPPLY 123 to 82, ORGANISATION 6. The Check Point and FortiGate catalogue records read
CONTROL, the Linux kernel ENDPOINT, EPMM MANAGEMENT as the app.mdm reading requires, and Ivanti
EPM (app.rmm) MANAGEMENT rather than SUPPLY through its generated `third_party_access`. 28
library patterns leave ORGANISATION in `advise.py`'s LOCUS, among them
`pat-browser-api-hooking-for-transaction-fraud`, now ENDPOINT. Per question, at `--limit 500`:
"Google Chrome" LOCUS_MATCHED goes from DATA 38 and ENDPOINT 21 to DATA 6 and ENDPOINT 57, and
CONTROL is no longer absent; "Okta" CONTROL 13 to 19; "Microsoft Windows" ORGANISATION 73 to 11
and ENDPOINT 85 to 179; the firewall questions gain ENDPOINT and lose ORGANISATION, which is now
the locus LOCUS_ABSENT names. The two Cloudflare phishing-fronting records move from DATA to
CONTROL on their first-listed `network.proxy`, which is arguable. Outputs
for fifteen questions were captured before and after: at `--limit 500` only the LOCUS lines
differ, so no match set, score, order or count moved. The pure Cisco top twelve is still eleven
MANAGEMENT and one CONTROL.

THE QUESTION ADDS A SECOND LOCUS AND NEVER MOVES THE FIRST. A multi-product record is placed by
the class its author listed first, so a firewall question's only DATA finding was a
KEV-harvest inventory join placed by its first-listed web server, and nothing on it said the
firewall, CONTROL, was on the record too. Placing the record by the class the question named
would have made LOCUS depend on the question: the EPMM record reached by an Okta question would
print CONTROL against the standing reading that app.mdm is MANAGEMENT, and `emit_xql.py` and
`advise.py`, which place a block with no question, would print a different LOCUS for the same
block. Instead the class the question matched is the first span source. The harvest record
prints `LOCUS: DATA` and `LOCUS_SPAN: DATA, CONTROL`, with `span-source=class_matched span:
network.firewall` in its basis, and the EPMM record under Okta prints MANAGEMENT with a CONTROL
span. `locus_for()` takes the question's classes, `--as` included, as an optional argument only
the span reads; a test holds every block's primary unchanged under every class set, so
`validate.py`, `emit_xql.py` and `advise.py` still print the LOCUS a consultation prints.

LOCUS_SPAN HAS ONE SOURCE ORDER, AND LOCUS_BASIS NOW PRINTS EVERY SIGNAL IT SAID IT DID. The
evidence signal was never printed, and the evidence tier, between `class_first` and `shape`,
could never fire: every record carries a class and every class is mapped. Evidence says where a
detection is read, not where the attack sits, so it is not promoted. The tier is removed from
`LOCUS_TIERS` and `tier_order`, and evidence is the last span source, taken when the block's
evidence types, `syslog` excluded, agree on one locus. The order is fixed once, as
`LOCUS_SPAN_SOURCES` in `consult.py` and `span_order` in the map, and `validate.py` holds the two
equal as it does `tier_order`: the class the question matched, a span-only surface, a committing
surface that did not decide, a unanimous class list that did not decide, a non-product class
listed later, then evidence. The first whose locus differs from the primary wins. Blocks
carrying a span go from 151 to 370, 135 of them from evidence. The basis gains
`nonproduct-signal=`, `evidence-signal=` and `span-source=`, and a split class list names what
decided and what else it reaches, as `class-signal=split(first=server.web:DATA; also CONTROL,
MANAGEMENT)` where it said `split`. The key set of a finding is unchanged. The figures written
into the locus map's comments (markers, inventory-shaped blocks, a line number in `consult.py`)
and into `tests/test_locus_axis.py`'s docstring had gone stale; they are removed, and a new test
holds the two distributions `references/locus-and-coverage.md` states to the ladder.

A DECLARED LOCUS MUST CHANGE THE ANSWER, AND SAY WHY. The schema has always said to set
`how[].locus` only where the derivation is provably wrong, and to give the reason in notes,
because a hand-set value that agrees with the derivation silently stops agreeing when the
derivation changes. `validate.py` checked only that the value was in the vocabulary. It now
refuses a declared locus the derivation already gives, and one whose record's notes do not name
`how[<n>].locus`. Run after the ladder changes above, three of the fourteen restated the
derivation and are removed: the captive portal record's `how[0]` (CONTROL), the Rust backdoor's
(ENDPOINT) and the signed-commit record's (SUPPLY). The other eleven now carry their reasons in
`notes`, where until now only commit messages, which do not ship, held any. The forge-token
record's three come from the commit that set them, and the Juniper record already explained its
two and now names them. The reasons for the captive portal record's other two, the media-device
botnet's two, the coding-agent record's and the phishing kit's were in no commit message and are
written from the records' own text, so they are worth a reviewer's read. No label moved; the
tally reads 11 declared overrides where it read 14.

`validate.py` prints a second tally, `locus derivation (exposures): 901 records -> ...; 865
generator-tagged, placed with their assigned attack_surface not read`. It refuses an exposure
whose generator tag and `source_type` disagree, and an untagged exposure carrying a generated
`source_type`, so a generator that forgets its tag cannot have its assigned surface read as
authored. It also refuses a span-only surface that is unmapped, deferred or a supply surface, a
generator tag naming a `source_type` outside the vocabulary, and a `span_order` that differs from
the code. `references/locus-and-coverage.md` gives the new distributions, the three limits, the
span order and the declared-locus rule. `corpus/README.md` gains "Where a record sits (LOCUS)"
for authors: class order picks the plane, `cross_sector` is a subject and not a sector tag, the
override-and-notes rule, and exposures placed by class; its layout line for `locus-map.json`
says what the file holds.

`tests/test_locus_derivation.py` and `tests/test_header_counts.py` hold the ladder, the span
order and the validator's new checks. Eight records changed, in `notes` and `how[].locus` only.

A RECORD NAMING THE PRODUCT NOW OUTRANKS A CLASS ANALOGUE, AND EVERY FINDING SAYS WHICH IT IS.
Every structured match was one tier, `identity`, at full weight and labelled "named this
technology", and the order was criticality times recency alone, so a fresh class analogue always
beat an older record naming the product. "Fortinet FortiGate" put a Cisco FMC record at rank 1 and
showed 2 Fortinet findings in twelve; "PAN-OS" led with the same Cisco record and showed 1 of its
3; "Microsoft Windows" led with Google Chrome and showed 1 Microsoft finding. Asked as questions,
the 1,454 vendor and product alias keys left 2,259 findings naming the product or vendor out of
their natural top twelve while class analogues filled it, in 406 questions. The tier is now four:
- `product` -- names the product asked about.
- `vendor` -- names the vendor asked about, in a class asked about, or with none asked.
- `class` -- shares a class asked about and is about another product: an analogue.
- `vendor-other-class` -- names the vendor in none of the classes asked about, which is the
  vendor's other product lines.

A vendor named inside a generic record's products is `vendor` exactly where it counts toward
the mode, and otherwise the record's `class` match or `name-fragment`, so the
Guardsquare and "Linux kernel" pins hold. `ORDERING` groups before it scores: product and
vendor, then class and vendor-other-class, then free text. The vendor's other lines share the
analogues' group because below them the PAN-OS record fell to rank 70 for "Palo Alto
Panorama", and product shares vendor's because product-first put ASA ahead of FMC for "Cisco
ASA" on dates alone. Within a group, records seen in a sector the question named come first,
then records carrying more of the question's leftover words, then the score. The shortfall is
now 0: FortiGate shows 9 Fortinet findings in twelve, PAN-OS its 3 at ranks 1 to 3, Windows 9
Microsoft, and the EPMM record leads "Ivanti EPMM". "Fortinet FortiGate boot image implant"
puts the boot-image implant record first, which the qualifying words only broke ties for
before.

Grouping would have inverted the coverage question. The gap multiplier lives inside the
weight, which now only orders within a group, so on the Fortinet coverage fixture twelve
covered Fortinet findings, at weights 0.9 to 1.9, filled the top twelve above uncovered
analogues at 3.6 to 6.1. Under `--rank-by gap` a finding `--covered` says is implemented now
drops one group: it competes with the analogues on weight, where the multiplier sinks it, and
still outranks free-text leads. A test pins it, and the demotion is printed.

THE RESOLUTION LINE NOW SAYS WHAT KIND OF ANSWER THIS IS, AND COUNTS THE EXPOSURES THAT NAME IT.
One tally decided the mode, a finding naming the vendor or product, and it could not tell a
product from its vendor's other lines or see an exposure. Over the same 1,454 questions, 196
printed `RESOLUTION: product` with no finding naming the product, "FortiSandbox" and "IOS XR"
among them, and no warning; 129, "FortiMail" and "Panorama" among them, printed "no vendor or
product the corpus holds records for" over findings naming the vendor; and 234 names held
only as exposures, Sitecore and Zoho among them, exited 1 as `UNRESOLVED`. `resolution_mode()`
now reads the tier counts and the exposures naming what was asked:
- `product` needs a finding naming the product, or, for a vendor-only question, naming the
  vendor in an asked-for class. The vendor's other lines alone never make it, so the Guardsquare
  question stays class-level.
- `VENDOR-LEVEL` is new: findings name the vendor and none the product, or only its other
  lines. 325 questions land here, 196 from `product`.
- `NAME_WITHOUT_RECORDS` is renamed `NAME_WITHOUT_OBSERVATIONS`. A consumer matching the old
  label must match the new one.
- `EXPOSURES_ONLY` is new: no observation and no class, but exposure records name it. It exits
  0, prints no findings, and names the classes those exposures carry for an `--as` re-ask.
  All 234 are here.
- `UNRESOLVED` now means no observation and no exposure names it; 61 remain.

An exposure names what was asked when it is the product, or the vendor's in an asked-for
class, or any of the vendor's when only the vendor was named; the other-products, other-vendor
and class-only tiers `query.py` lists never count. The RESOLUTION line says how many, by tier:
"Linux kernel" reads `exposure records: 2 name Linux Kernel, 1 name Linux in endpoint.os`
where it read "The corpus holds no record naming it". Every mode text says "observation" where
it said "record". `CLASS_LEVEL_WARNING` now prints for every mode but `product` and
`mechanism`, worded for the mode, because it is the one key consumers gate on; there is no
second warning key for the vendor-level case. A consultation exits 1 only when there is no
finding and no exposure naming the technology: 249 of the 1,454 questions go from exit 1 to
exit 0, the 234 and 15 class-level answers with no finding whose exposure records name the
product, ManageEngine ServiceDesk Plus among them; three of the 249, Qualcomm, MediaTek and Code
Aurora, return to exit 1 under the handset refusal below. The exposures are listed in
`EXPOSURE` blocks, and a handset record never counts as naming what was asked.

A NAME THE CORPUS DOES NOT KNOW IS NO LONGER ANSWERED AS A CONFIDENT MECHANISM ANSWER. "Zorblax
Edge Gateway 9000" printed `RESOLUTION: mechanism` over 246 findings about other vendors' edge
devices, reached by "edge" and "gateway", while "Zorblax" and "9000" reached nothing and
nothing said so. `UNMATCHED_TERMS:` now follows RESOLUTION on every consultation, listing the
question's words, after the ones a resolved alias consumed, that no record's reasons show it
reached or was refined by. A mechanism answer whose unmatched words include one written with
a capital or a digit adds `MECHANISM_WARNING:`, saying no finding is about that name, and
`CANDIDATE_CLASSES:` for an `--as` re-ask. "phishing", "prompt injection" and "ransomware
against hospitals" print `UNMATCHED_TERMS: none` and no warning, and a qualifying word that
reordered a named answer counts as reached.

A QUESTION NAMING ONLY A VENDOR NOW REACHES THE CLASS ITS RECORDS ARE ABOUT. A vendor alias
carries no class, so "Fortinet", "Cisco", "Citrix" and "Siemens" reached no class analogue and
left four or five loci absent each, which is the class-level transfer the Scope section
promises, not delivered for the commonest way people name what they run. Such a question now
derives classes from the observations filed under the vendor: the first-listed product classes
two or more of them share, or the three most frequent where none is, never a non-product
class. They are printed as `CLASSES_FROM_VENDOR:` (or `none` with the reason) and used for
scoring only: `RESOLVED_TO` still reads `classes=-`, the vendor's own findings stay `vendor`
and lead, the analogues arrive as `class` saying where their class came from, and the mode
stays `product`. 45 of 312 vendor-only questions derive classes, and their absent loci fall
from 195 to 87: Fortinet 4 to none, Cisco 4 to 1, SolarWinds 5 to 2, Siemens 5 to 4 (it now
reaches `ot.plc` and CONTROL). A vendor named only inside generic records' products, GitHub,
derives nothing from them.

SKILL.md's mode table has the new modes and a `mechanism` row, and the new
`tests/test_resolution_modes.py` holds every label `consult.py` can print to it; its tier
paragraphs describe the four subject tiers and the grouping. `references/resolution.md` gains
"What kind of answer it is", with the tier table, the order and the mode rules, and
`references/locus-and-coverage.md` says the quota's representative is a locus's first finding in
`ORDERING` order. Every test that read `identity` now reads the tier it meant. Two tests are
skipped: two of the sampled vendor names are gated on their own and resolve nothing.

A RESERVED SLOT IS FILLED ONLY FROM A FINDING ABOUT THE SUBJECT, AND AN ABSENT LOCUS SAYS WHAT DID
REACH IT. The locus quota and its header are rewritten once, in `consult.py`. The quota took the
first finding of every locus with any match at all, with no floor and no relevance test, and
counted a locus as represented on the same terms. Even with the resolver's filler removed at
source, "Zorblax Edge Gateway 9000" still reserved ENDPOINT at rank 49 for a ClearFake loader
reached by pattern wording and ORGANISATION at rank 79 for a phishing kit reached by the fragment
"gateway", under `LOCUS_ABSENT: none`; "npm" reserved CONTROL for a QNX runtime-library record
scoring 2.48, and "phishing" reserved SUPPLY for a Twilio console record scoring 2.88. A finding is
now eligible when its tier is `product`, `vendor`, `class`, `vendor-other-class` or `tag` and its
criticality before any coverage demotion is 3.0 or more, the MODERATE floor, so a locus the caller
already covers is not reported absent in gap mode. Only an eligible finding fills a reserved slot
or makes its locus represented. A tag match is eligible in every mode: once a resolved name's words
are no longer searched, a tag hit on a named question comes from a word the caller wrote beyond the
name, and leaving tags out left "helpdesk social engineering" with four of its six loci absent
where it now has two. Over the 836 product-alias questions holding findings, run as of 2026-09-25,
reserved slots below the floor fell from 143 to 0 and slots reserved from free text from 55 to 0,
and 208 more loci are reported absent because only filler reached them.

ONE RECORD NO LONGER FILLS THE ANSWER. Findings are per how-block, and one record's blocks share
recency, identifiers and role, so they sort together: "Atlassian Confluence" showed 6 blocks of
one PBX record in twelve, 8 in pure order, "SolarWinds Orion" 9 of one record, and 617 of the
836 questions gave one record 3 or more of their twelve slots. No record now takes more than 2
slots while another record's finding in its own match group is waiting (`RECORD_CAP`, a chosen
value, not a measured one). The cap never crosses a group. Applied across groups, as it was
first built, it passed over findings naming the product for other vendors' class analogues: over
848 product questions, 178 lost 566 findings naming the product or vendor that way, "Check
Point firewall" its rank-3 Check Point block for a Cisco VPN record at rank 10, "Ivanti EPMM"
two EPMM blocks for N-central and SimpleHelp analogues, and "SolarWinds Orion" showed 2 of its
only record's 10 blocks. A group's capped findings now take any slot left at the end of their
group, before a looser group is reached, and print `SLOT: backfill`: "SolarWinds Orion" shows 9
of the 10, the tenth displaced by a reserved slot, and over the 848 the cap now passes no
finding over for one of a looser group, at `--limit` 12 or 25. 266 of the 836 questions still
show a record 3 or more times, 175 of them a record naming the product, each only where its
group, or a locus's reserve, held no other record's finding. Distinct records in the twelve
rose from
5,855 to 6,278 over the 836, 7.0 to 7.5 an answer, and findings naming the product or
vendor from 2,217 to 2,249. `--no-locus-spread` turns the cap off with the reserve, so pure
order stays pure and shows all ten.

RULE 9 CAN NOW BE CARRIED OUT WITH THE SCRIPT. It asks for several findings under each plane and
for the relationships other than victim, and the quota reserved exactly one slot per locus with
no way to ask for more, and no flag reached a record's role: the only route was `--limit 500`
and filtering by hand, which the block contract forbids. `--per-locus N` (default 1, 1 or more)
reserves up to N eligible findings per locus, round by round in `ORDERING` order, so "Fortinet
FortiGate" `--per-locus 3 --limit 18` shows all three eligible SUPPLY findings where the default
shows one. `--role ROLE[,ROLE...]` keeps only records whose `what.role` is one of those roles,
checked against `vocab.json` (an unknown value exits 2); the role is one per record, not per
product or class it names (corrected below, under batch V5). "Palo Alto firewall" matches 32
observation records, 24 of them victim; `--role telemetry_source` keeps the one that is not, and
`--role control_bypassed,inline_tool,telemetry_source,lateral_path` the eight. Filtered,
`RESOLUTION`, `FINDINGS` and every tally describe the kept records, and the RESOLUTION and
CLASS_LEVEL_WARNING lines say so. Exposure records carry a role too and are filtered with the
rest. Filtered to nothing, it exits 1 with a `NO_FINDINGS` line naming the filter rather than
the advice for a name the corpus does not know, and `FINDINGS`, `NO_FINDINGS` and `RESOLUTION`
say what matched before `--role`. The mode is decided on the scoring view of the question, whose
classes include any derived from a vendor's own records, so a filter keeping only "Fortinet"'s
class analogues is not answered `UNRESOLVED` over the findings it has; without `--role` that
changes no RESOLUTION line, checked on 56 questions.

The quota changes what is shown and nothing about what matched. Checked on 56 questions,
`RESOLVED_TO`, `RESOLUTION`, `CLASS_LEVEL_WARNING`, `UNMATCHED_TERMS`, `MATCH_TIERS`,
`LOCUS_MATCHED` and the `FINDINGS` count did not move with it, and nor did any pure-order block
apart from its new `SLOT` line. SKILL.md rule 8 reads eligibility, and
`references/locus-and-coverage.md` describes the new lines, the cap and `SLOT`. In
`tests/test_locus_axis.py` the absent, displacement, underserved and spread tests read
`LOCUS_ELIGIBLE` and the cap, the underserved fixture is read at 2026-09-25, and new tests pin
the floor and tier of every reserved slot, recount every absent-locus bullet from the whole
match set, tie each reserved block to the rank its bullet cites, hold the cap inside a match
group on the eight questions a cross-group cap failed, place the reason on the blocks past the
cap in `RANK` order, and exercise `--per-locus` and `--role`, the filtered exposures and the
emptied answer included; `tests/test_header_counts.py` refuses `--per-locus 0`.

A CONSULTATION NOW RETURNS THE EXPOSURES NAMING WHAT WAS ASKED, IN BLOCKS OF THEIR OWN.
`consult.py` built findings from how-blocks and printed nothing else, and 901 of the 1,149 records
are exposures with none, so no question could return one: "Check Point firewall" never showed
CVE-2026-85102 and CVE-2026-93616, which CISA added on 09-22 and which sit only in
`exp-kev-check-point-multiple-products`, and `corpus/README.md` said the lookup returns exposures
as a separate block when only `query.py` did. They now follow the findings in `=== EXPOSURE i OF n
===` blocks, under a header group of their own, and never enter `FINDINGS`:
- What is listed is decided by `query.exposure_tier()`, the helper `query.py` already orders its
  own listing by: the `product` and `vendor-class` tiers, and `vendor` when the question named no
  product and no class. A class match alone never lists one, because a CVE in another vendor's
  firewall carries no detection logic to transfer, where an observation about it does. The rest are
  counted by tier on `EXPOSURES_NOT_LISTED`, and `query.py` lists them.
- The order is fixed and printed on each block, as `EXPOSURE_ORDER_BASIS`: tier, then kind, then
  newest first with the undated last, then id. `EXPOSURE_KIND` is `EXPLOITED`, `ADVISORY` or
  `DISCLOSED`, computed from the identifiers against those the corpus's own catalogue records
  carry, with the KEV snapshot named on `EXPOSURE_ORDERING`, so a generator's stale `not-in-kev`
  tag cannot make an exploited CVE read as merely disclosed; each block says how many of its
  identifiers the catalogue holds, and prints every identifier.
- `EXPOSURE_LOCUS` comes from the ladder the findings use, with a generated record's assigned
  surface not read, so the probes place by class: Check Point and FortiGate on CONTROL, the Linux
  kernel on ENDPOINT and EPMM on MANAGEMENT. The header's `EXPOSURE_LOCUS` counts every locus,
  zeros included.
- `EXPOSURE_DETECTION_HELD` names the observations carrying any of the record's identifiers, with
  their vendor, and `FINDING k above` where one is shown: the CVE-2024-24919 record points at the
  Check Point observation shown as finding 1.
- `EXPOSURE_DATA_GAP` assesses what acting on an exposure needs, `asset_inventory` and `vuln_scan`,
  once against `--have`, and `EXPOSURE_SCOPE` says how many exposures the corpus holds from each
  feed and that it is not a vulnerability feed.

On the five probes: "Check Point firewall" lists 4 and counts 45 class-only; "PAN-OS" lists 4,
2 of them the product; "Ivanti EPMM" 8, the EPMM catalogue record first; "Linux kernel" 3;
"Fortinet FortiGate" 10 of 11. Over the 1,097 distinct vendor and product resolutions of the
alias table, 988 list at least one exposure, 6,450 listings in all, where every one listed none.
`--covered` and `--rank-by` do not apply to an exposure and `--as` alone lists none; `--role`
filters them as it filters findings, and a filter that keeps exposures and no finding now lists
them and exits 0, where it exited 1.

THE HANDSET RECORDS ARE HELD, AND REFUSED FROM A CONSULTATION WITH A COUNT. Handsets stay out of
scope and the mobile management plane stays in. The catalogue generators write handset records
all the same, and listing exposures would have brought them into a consultation.
`corpus/schema/scope.json` is new and names them by vendor and platform term: an exposure is
refused when its vendor is listed and every platform its products name matches one of that
vendor's terms. 16 records are refused -- Android's five, the three Apple records naming only
iOS, iPadOS or watchOS, two Arm Mali, the Qualcomm and MediaTek chipsets, Samsung Mobile
Devices, Chrome for Android and Code Aurora's Android audio driver -- while "iOS and macOS" and
its two kin are macOS exposures as well and stay listable. Nothing is deleted: `validate.py`
checks the records, `query.py` lists them, and a consultation counts each as `handset=` on
`EXPOSURES_NOT_LISTED`. The refusal sits in the one function the listing and the resolution
mode share, so "Qualcomm", held only as two handset records, is not offered an `--as
endpoint.os` re-ask as `EXPOSURES_ONLY` would: it reads `UNRESOLVED`, says the two records
naming it are handset records, exits 1, and prints `THE ALIAS EXISTS AND WHAT CARRIES IT
IS OUT OF SCOPE` in place of the advice to report a gap. MediaTek and Code Aurora go the same
way. 47 of the 1,097 resolutions refuse at least one record, "macOS" three iOS-only records
among them, and a class-level answer to a handset product, "Android kernel", says on its
RESOLUTION line that five handset records naming it were held back. `validate.py` refuses a
`scope.json` entry naming a vendor or a term no exposure carries, and prints `handset scope: 16
of 901 exposure records ...` on every run. A handset record from a vendor the table does not
name is not caught, and is added there when it arrives.

LIBRARY PATTERNS NOW REACH A CONSULTATION, AND RULE 6 SAYS WHAT DERIVATION IS. A library pattern
is one no record cites, so it was derived from somewhere other than an incident this corpus
holds: 25 of the 34 from the public rule corpora, 3 from ATT&CK, 3 from CISA's malware analysis
reports and 1 from FiGHT, and 2 record no `derived_from` (this sentence said "from technique
space" of all of them until batch V5's review measured it). `consult.py` built findings only
from how-blocks, so none of the 34 ever reached a consultation, and the
`DERIVATION: library pattern` value rule 6 described could never be printed: over 24 probe
questions, 19 had library patterns `query.py` showed and `consult.py` never did, among them
three CONTROL patterns for SCADA and, for Kubernetes, a MANAGEMENT pattern while `LOCUS_ABSENT`
named MANAGEMENT. They now follow the exposures in `=== LIBRARY i OF n ===` blocks: the
uncited patterns with markers whose `applies_to_classes` meets the classes the question
resolved, `--as` included, or a vendor-only question's `CLASSES_FROM_VENDOR`, whose class
matches are analogues already. They are ordered as `query.py` orders its library block, a
pattern whose markers are written for another platform last, then Sigma plus Splunk
corroboration, then id, and `--pattern-limit` (default 6) caps them. Each block carries the
pattern's locus, fidelity, shape, techniques, markers, telemetry and data gap, the caveat
verbatim, countermeasures and doctrine, with `LIBRARY_CORROBORATED` and `LIBRARY_OBSERVED` kept
as separate claims. 606 of the 1,097 resolutions reach at least one. A finding's `DERIVATION` is
now the fixed `cited record`, the key kept so the finding key set does not move, and rule 6
says that patterns no record cites come in the `LIBRARY` blocks and exposures in the `EXPOSURE`
blocks, and that neither is a finding. A pattern's `LOCUS_BASIS` reads `input=applies_to_classes
first-listed=...` where it said `product_class`, in `advise.py`'s output as in the new blocks,
because a pattern's classes are what it applies to.

NEITHER BLOCK TAKES A SLOT, COUNTS AS A FINDING OR CLEARS AN ABSENT LOCUS. `FINDINGS`,
`MATCH_TIERS`, `LOCUS_MATCHED`, `LOCUS_ELIGIBLE` and `LOCUS_SHOWN` describe findings and nothing
else, and tests hold them byte-identical whatever either block's limit is. An absent locus's bullet
counts both, as `; exposures N; library M`, so a locus held only by an exposure or a library
pattern is visible as such and stays absent: Kubernetes's MANAGEMENT reads `matched 0; span-only 1;
exposures 0; library 1`. Checked on 40 questions at the default limit and at 500, adding the blocks
changed no finding block and no line from `RESOLVED_TO` to `LOCUS_UNDERSERVED` beyond the bullets'
new counts, and moved one resolution mode, "Qualcomm"'s, above.

`corpus/README.md` now says both scripts return exposures as a separate block with its own limit,
which is true, lists `scope.json`, and says an exposure may be written by hand from a joint
government advisory. SKILL.md names the four feeds and the hand-written records, rewrites rule 6,
adds the blocks after the finding table, the flags and exit code to the script list, and
`references/exposures.md` to further reading. `references/resolution.md` and
`references/locus-and-coverage.md` describe the listing, the handset mode and the bullet counts.
`tests/test_consult_exposures.py` holds the block, header counts, key set, order, kind, locus,
detection-held, handset refusal, scope check and `--role`, and the new
`tests/test_consult_library.py` the library block; `tests/test_locus_axis.py` recounts the
bullet counts from the blocks printed whole, and `tests/test_header_counts.py` refuses a
negative `--exposure-limit` or `--pattern-limit` on `consult.py` and accepts 0.

THE ATT&CK REFERENCE NOW SAYS WHICH IDS ARE WITHDRAWN, AND WHAT REPLACED THEM. The generator,
`_ingest/mitre-attack/build_reference.py`, kept six fields and dropped the `revoked` and
`deprecated` flags its own harvest records, so `attack-techniques.json` listed T1562.001,
T1070.001 and 209 other revoked ids as ordinary entries, and 37 deprecated ones likewise. Every
entry now carries `revoked` and `deprecated`. A revoked entry also carries `replaced_by`: MITRE's
revoked-by relation followed hop by hop to the first live id, because the chains are multi-hop
(T1073 -> T1574.002 -> T1574.001). Of the 211 revoked ids, 202 reach a live replacement. Eight
mobile chains end at a deprecated id, which is named in `successor_deprecated` (T1455 -> T1477).
T1454 has no revoked-by edge at all and carries `replaced_by: null`. The fix is in the generator,
not the file. It was checked byte for byte first: with the new `--no-lifecycle` flag it still
reproduces the previous file exactly. The file was then regenerated for all three domains; no
other field moved. The generator lives in the shared, unversioned `_ingest` folder, and its
pre-change copy is kept beside it as `build_reference.py.pre-0925c`.

`validate.py` counted any key in the reference as resolving, so a reintroduced revoked id would
have read as fine. The line now splits the two: `technique ids resolving against the shipped
reference: 407/407; to a live id 407, to a REVOKED or DEPRECATED id 0`. Any withdrawn citation is
named with where it went, as `T1562.001 -> T1685`. It stays non-fatal, for the upgrade-day reason
its comment gives. `tests/test_attack_reference.py` holds the shipped corpus to zero withdrawn
citations, so the split is still a release gate. `consult.load_attack()` is new and reads the
reference for `advise.py`.

D3FEND IS JOINED THROUGH THE SAME MIGRATION, SO T1685 HAS ITS COUNTERMEASURES AGAIN. D3FEND 1.6.0
is keyed on ATT&CK ids from before 19.2, and the corpus cites 19.2 ids. T1685 (Disable or Modify
Tools) therefore joined to nothing, while its revoked predecessor T1562.001 carried 19
countermeasures. 13 patterns printed "gap in D3FEND coverage" over a mapping that existed. The
corroboration join already counted a revoked id for its replacement, so the two joins disagreed
on the same migration. `_ingest/d3fend/harvest.py` now reads the regenerated ATT&CK reference
(`--attack-reference`, by default the file beside `--out`) and refuses one that carries no
`replaced_by`. After building `by_attack`, it gives each live replacement that has no mapping of
its own the union of its predecessors' lists. The new `by_attack_via` names the predecessors, and
`by_attack_via_attack_version` names the ATT&CK release whose relation keyed them. 20 ids gain
lists this way, 8 of them ICS (T0803 -> T1691.001 among them). No existing entry changed.
`licence`, `licence_note`, `licence_text`, `attribution`, `version`, `tactic_order` and
`countermeasures` were compared with the file before the change and are byte-identical, and
`tests/test_attack_reference.py` pins the MIT notice. The file's `note` no longer says that a
truncated answer loses only the tail, which was true of one technique's list and false of
several joined together. It now says that entries under `by_attack_via` are MITRE's relation,
not a D3FEND mapping. A countermeasure reached this way is labelled `T1685 (via revoked
T1562.001: D3FEND 1.6.0 predates ATT&CK 19.2)`. Coverage of the 407 cited ids rises from 210 to
222. Claims of a D3FEND gap fall from 73 patterns to 60, and from 97 how-blocks to 80. The gap
sentence now reads "maps no countermeasure to ..., even through a revoked predecessor".
`harvest.py.pre-0925c` is kept beside the generator.

COUNTERMEASURES ARE CHOSEN ONE PER TACTIC IN TURN, AND THE REST ARE NAMED. `countermeasures()`
concatenated each technique's list in citation order and took the first six. For LSASS dumping
that meant six Isolate controls, with its five Evict and four Detect controls cut. Across the 475
patterns, 191 dropped every Evict entry, 205 every Detect, 177 every Restore and 296 every
Harden, and 131 showed one tactic of several. The header's "from" also named techniques none of
whose controls was shown. Selection is now round-robin across `tactic_order`, one control per
tactic per pass, displayed in tactic order. None of those five stages is now dropped on any
pattern. The header reads `COUNTERMEASURES: 6 shown of 20 (Isolate 2/11, Evict 2/5, Detect
2/4), ordered isolate-evict-restore-detect-harden-model-deceive, from T1003.001`. It names only
the techniques that own a shown control and adds `; also mapped: ...` for the others. An
indented `NOT_SHOWN:` line lists every control not shown, by id. `consult.py` shares the
function, so its findings change too: the selection moves on 605 of the 770 how-blocks. Outside
`COUNTERMEASURES`, `RESPONSE_DOCTRINE` and the new `DECLARED_TELEMETRY_REJECTED` line, its output
is identical on 20 questions checked against the output before this change. `emit_xql.py`'s JSON
handoff takes the same selection (see the handoff below).

ADVISE.PY'S RESPONSE DOCTRINE READS THE KEY PATTERNS HAVE, AND NO LONGER DROPS COLLECT OR CONTAIN.
It passed `pattern.get("product_class")`, a key no pattern carries, along with no impact. So all
475 blocks printed "0 matched on this finding's class or impact", and the appliance and OT rules
never fired, under a comment saying they did. It has been wrong since 2026-08-08. It now passes
`applies_to_classes` and the union of the impact of the pattern's distinct non-seed citing
records. `doctrine_for()` takes a `basis` keyword, so the header says where both came from:
`matched on this pattern's applies_to_classes or the impact of its N citing record(s)`, or `(no
citing record, so impact is not assessed)`. This is a policy choice, and the header states it,
because ransomware doctrine on a pattern is a property of the incidents behind it, not of the
detection. 386 patterns now carry at least one specific rule: 164 gain
`doc-appliance-rebuild-not-factory-reset` and 123 `doc-emergency-plan-names-degraded-states`.
Passing impact exposed a truncation defect `consult.py` already had. Specific rules filled the
limit of six before any always-on rule, so 62 of the 770 consultation how-blocks had already lost
`doc-containment-assumes-adversary-watching`, and 5 `doc-collect-before-mitigate`, the two steps
whose order decides whether a response works. Those two always-on rules are now reserved. The
remaining slots go to specific rules, class matches before impact matches: the class is what the
subject is, while a pattern's impact is borrowed from its citing records. An OT pattern therefore
keeps its degraded-states rule ahead of a second communications-plan rule. Anything cut is named
on an indented `NOT_SHOWN:` line, and the header's "N shown of M" is unchanged in form. With no
`basis`, `consult.py`'s header wording is unchanged.

A PARENT ATT&CK ID SELECTS ITS SUB-TECHNIQUES, AND A REVOKED ONE IS FOLLOWED TO ITS REPLACEMENT.
`advise.py --attack` matched by string equality:
- `--attack T1003` selected 2 of the 8 patterns citing the family.
- T1684, where ATT&CK 19.2 moved Impersonation, and T1565 each selected nothing.
- T1078 selected 46 of 86.
- T1562.001, T9999 and T1070.001 all printed the same "nothing was selected", with nothing
  naming T1685, and nothing on either stream about an ATT&CK id.

A parent now also selects the patterns citing its sub-techniques, under a new basis: `MATCH_BASIS:
selected by T1003.001, a sub-technique of requested T1003 - the pattern does not cite the parent
itself`. `--attack-exact` turns the expansion off. A revoked id is followed to MITRE's replacement
under a third basis, `selected via T1685, MITRE's replacement for revoked T1562.001`. That is
MITRE's own relation, not a guess, and it is never expanded further. `SELECTED_BY` keeps its
columns, and the "exact ATT&CK id" column now counts all three bases. The line appends `; of the
ATT&CK selections, N cite a requested id, M cite a sub-technique of a requested parent, K cite
MITRE's replacement for a revoked id`. Every basis is counted explicitly, where free text had
been the remainder, and MATCH_BASIS dispatches on the basis, where a string basis would have
printed character by character.

The header also accounts, on stdout, for every id it was given:
- One `ATTACK_REQUESTED: <id> (<name>) -> ...` line per requested id: live with its direct and
  sub-technique counts, `REVOKED in ATT&CK 19.2, replaced by ...: followed, N pattern(s)`,
  `DEPRECATED in ATT&CK 19.2, no replacement`, or `not an id in the shipped ATT&CK 19.2
  reference`.
- `ATTACK_RECORD_ONLY`, where an id selects nothing but how-blocks cite it (widened by batch
  V5, below, to any how-block under a pattern the id does not select). It names their
  patterns so `--patterns` can reach them: T1550.002 points at pat-credential-dump-lsass-access
  and pat-impacket-protocol-tooling.
- `ATTACK_PARENT_ONLY`, where a requested sub-technique leaves patterns citing only its parent.
- `PATTERNS_REJECTED`, which names an unknown pattern id or an ATT&CK id passed to `--patterns`.
  These went to stderr only, under a clean `FINDINGS`.

`NO_MATCH` keeps "by exact id" and points at these lines rather than at stderr.

FREE TEXT READS THE PATTERN'S ID, STEMS, AND NO LONGER MATCHES ON A HYPHEN FRAGMENT. A search for
lsass, dcsync, kerberoasting, impacket or "helpdesk impersonation" returned nothing, although a
pattern exists for each, because 150 words occur only in pattern ids. "web server spawning a
shell" ranked a print-spooler pattern first. "pre-auth RCE on VPN appliances" matched "pre", and
so every pre-X compound. "edge appliance" and "edge appliances" disagreed. "credential" alone
returned three patterns at score 0.8.

The identity haystack is now the name, the description and the id's own words. The body is the
logic plus the ATT&CK names of the pattern's techniques. Rarity is computed over those haystacks,
and `consult.build_rarity`, which drives COVERAGE, is untouched. A light stemmer applies to both
sides. It leaves a word ending in "ss" whole, so "lsass" survives. A hyphenated compound is kept
joined, and its parts only at four characters or more. A candidate whose only overlap is one word
carried by more than a tenth of the patterns is dropped. The overlap is printed in the caller's
words, rarest first, with `(+N more)` past six. Each of the probes above now ranks its pattern
first.

An ATT&CK id typed as text, or a live technique named by its ATT&CK name, prints `SUGGEST_ATTACK:
T1003.001 (LSASS Memory) - --attack T1003.001 -> 1 pattern(s): 1 cite it` inside the shape's
banner. It never selects anything: 117 live names belong to more than one id. The free-text
`NO_MATCH` adds `try --attack <ids>` when a shape named one.

Every shape asked now gets a banner, with an indented `SHAPE_RESULT: no pattern overlapped this
shape` or `SHAPE_RESULT: N new, M already shown above (pat-...)`. A shape that matched nothing
used to vanish from the answer, and a match already shown was dropped without a word to the
later shape. The header adds `SHAPES_EMPTY: k of n`. SKILL.md no longer says free text returns
"a single token-overlap guess".

ADVISE.PY PRINTS ONE KEY PER LINE, AND SAYS WHERE A PATTERN WAS SEEN AS WELL AS WHERE IT APPLIES.
`LOCUS` and `FIDELITY` each carried a second key on the same line, so `^LOCUS: (.*)$` read
`ENDPOINT   LOCUS_BASIS: tier=...` in this script only. No block printed `LOCUS_SPAN`.
`FIDELITY`, `RULE_SHAPE`, `LOCUS`, `LOCUS_SPAN` and `LOCUS_BASIS` are now separate lines, in
`consult.py`'s order, and the key set is identical on all 475 patterns. `LOCUS` stays the class
derivation, question-independent. The new `LOCUS_OBSERVED` counts the citing how-blocks per
locus, each placed exactly as a consultation places that finding, as `MANAGEMENT=1 (over 1
citing how-block(s) in 1 record(s), placed as consult.py places them)`, or `none - no citing
record`. It counts how-blocks rather than one modal locus per record, so a record split across
loci hides nothing and the counts sum to the blocks. When every citing block agrees on a locus
other than the primary, that locus becomes the span, `span-source=observed span: N citing
how-block(s)`. A split is never a span. `LOCUS_BASIS` ends `; observed-signal=`.

pat-audit-policy-tampering now reads `LOCUS_SPAN: ENDPOINT, MANAGEMENT`, where it printed ENDPOINT
alone over a CloudTrail incident. 147 of the 441 cited patterns print a locus none of their
citing blocks sits on, and 131 now carry the observed locus as their span, 49 of them MANAGEMENT.
The header adds `LOCUS_RETURNED`, the primary over the findings, and `LOCUS_ABSENT` with
`consult.py`'s caveat. There is still no quota. `CONTRACT` adds that `LOCUS` and
`LOCUS_OBSERVED` are separate claims.

OBSERVED COUNTS RECORDS, NAMES EVERY ONE, AND NEVER CUTS A TITLE. `OBSERVED` counted how-blocks as
records. One record citing a pattern from three blocks printed "3 record(s)" above the same line
three times, and 16 patterns were over-counted. It printed the first four in file order, with no
record id and no word about the rest: 23 patterns have more, and for 21 of them the four shown
were not the newest. It cut every title at 74 characters, including the three restricted titles
the line tells a caller to cite as given.

It now reads `OBSERVED: yes, N record(s), M how-block(s)` and lists up to six records newest
first, as `[STATUS] <record id> | <date or undated> | LOCUS <locus> | <title> | <url or
RESTRICTED>`. A `... N more record(s) not shown: <ids>` line accounts for the rest, and titles
are whole. URL liveness is checked for the records printed rather than every citing record.

--have IS CHECKED AGAINST THE 21 EVIDENCE TYPES, IN BOTH SCRIPTS. `--have T1486` is an ATT&CK id,
and it was accepted silently. Every `DATA_GAP` then turned from UNASSESSED into a confident
MISSING/ACQUIRE list, and a typo, `WEB_SERVER` in capitals or a lone comma did the same. The two
scripts also disagreed on `--have ''`.

`consult.parse_have()`, shared by both scripts, normalises case, spaces and hyphens. It refuses
any other value with a reason: an ATT&CK id is pointed at `--attack` or `--covered`, and several
values without commas are told to separate them. When nothing is accepted, the answer is
UNASSESSED and never MISSING. `DATA_GAP` then reads `UNASSESSED - every --have value was
rejected; see DECLARED_TELEMETRY_REJECTED`, and each refused value is named on stderr.

Both headers print `DECLARED_TELEMETRY` and a new `DECLARED_TELEMETRY_REJECTED`. `advise.py`
printed neither. The refusal is lenient rather than an exit 2, because callers really do pass
dataset names. A caller who passed junk will see different DATA_GAP counts, which is intended.
The SKILL.md description said coverage is ranked against what the caller "collects". It is
ranked against what they implement, `--covered`. Rule 5 and the `--have` paragraph now name the
vocabulary, and say a word off it is refused.

SKILL.md names the vocabulary for `--have`, the parent, revoked and banner behaviour of
`advise.py`, `--attack-exact` and `LOCUS_OBSERVED`, and the new D3FEND coverage and selection.
`references/answering-another-session.md` lists the advise key set and
header, `references/locus-and-coverage.md` gains the advise section, and `corpus/README.md` names
the lifecycle fields and the D3FEND re-keying.

New tests:
- `tests/test_attack_reference.py`: lifecycle fields, replacements and chains, live
  replacements, no withdrawn citation shipped, the validate split, the `by_attack_via` union and
  the MIT notice.
- `tests/test_advise_selection.py`: free-text reach, stemming, the hyphen fragment, common words,
  suggestions, parent expansion, `--attack-exact`, revoked, deprecated and unknown ids, rejected
  pattern ids, record-only ids, banners and explicit tallies.
- `tests/test_advise_findings.py`: one run over every pattern for doctrine, countermeasures,
  OBSERVED, restricted titles, the LOCUS key set, LOCUS_OBSERVED and LOCUS_RETURNED, plus
  `--have` in both scripts.
- `tests/test_advise_header.py` gains the placement test for a pattern's locus basis.

EMIT_XQL.PY PRINTS XQL OR A COMMENT, AND NEVER PSEUDO-CODE IN A FILTER. The skeleton
is still a skeleton -- this bundle does not write rules -- but under `fidelity=alert` it printed
XQL that was wrong in shape or wrong in meaning, and no test read what it printed. Measured over
the corpus as it stood before this change:
- 574 of the 703 emitted blocks, 320 of them at alert fidelity, pasted a computed marker's
  expression into the live `| filter`: 60 carried an aggregate, 302 English connectives, and 35
  threshold or absence blocks a second threshold above the skeleton's own.
- A computed marker valued `false` was appended to a compound expression, so the Citrix
  session-hijack block read `all_sessions_terminated and credentials_reachable_via_hijacked_
  sessions rotated = false`, which binds to the last word rather than negating the whole.
- A strict clause grammar rejected 1,108 of the 1,669 live clause lines.

One typed renderer now replaces `quote()` and `predicate()`. A computed marker is never live: it
prints as `// REQUIRES (computed, not a field test): ...`, as the expression for `true`, as `NOT
(...)` for `false`, and with `(source bound; measure locally)` for `gt` and `lt`. A marker with no
field, or a field that cannot take it, prints as `// UNBOUND: <type> <match> <value> -- <why>`,
with the value it used to lose. Every header gains `locus=`, the question-independent `LOCUS` a
consultation prints for the block, and `filter=complete|partial|none`: complete when every
marker is in the live filter, partial when conditions are left as comments, none when there is
no live filter. Every block prints its `CAVEAT` and `LOGIC`, which the text form, the one SKILL.md
tells a reader to eyeball, never carried, and one banner says the skeleton is not a rule. The
comp and bound lines print only under a live filter, so a block never carries two thresholds; an
absence skeleton no longer prints `filter hits = 0`, which comp over events can never produce,
and says to compare an inventory of expected reporters instead; an `inventory` block never prints
a pipeline. Every pipeline opens `datamodel dataset =`, because every live clause names an
`xdm.*` field and a raw `dataset =` stage does not expose one, and the two dataset hints no longer
print as a Python list. That is a preference, not the retired raw-dataset prohibition. The tally
appends `; filter: <n> complete, <n> partial, <n> none`, and `<n> matched record(s) carry no
how-blocks` when the match held an exposure: `emit_xql.py exp-kev-linux-kernel` accounted for
nothing. `query.py`'s footer now offers `emit_xql.py <observation-id>`.

Over the corpus as it ships, 76 blocks are complete, 247 partial and 380 none, and at alert
fidelity 61, 203 and 162. 480 live clause lines are printed and none fails the grammar. The drop in
live lines is the honest figure: most blocks carry a computed condition no field test expresses,
and the old skeleton looked complete only because it pasted those into the filter.

EVERY FIELD A MARKER IS BOUND TO IS CHECKED AGAINST THE XDM SCHEMA. `DEFAULT_XDM` was written
without reference to it, nothing compared a binding with the schema, and six defaults and 46
explicit bindings named a field XDM does not have or an enum that cannot hold the value:
- `group_name` defaulted to `xdm.source.user.groups`, the groups of the account doing the creating,
  so the ESX Admins block tested the actor and missed the group creation it exists to catch; the
  field is also an array, where `=` and `in` do not test membership. The default is gone, and an
  array field is never given a scalar test.
- `protocol` defaulted to `xdm.network.ip_protocol`, the layer-4 enum. The Log4j block tested
  `xdm.network.ip_protocol = "ldap"`, which matches nothing, because `ldap` is not a member. The
  default is gone: a protocol marker names its field.
- `cloud_operation` defaulted to `xdm.event.operation`, the derived OPERATION_TYPE enum (CREATE,
  READ), and 38 markers were bound there explicitly with raw API names -- StopLogging,
  ConsoleLogin, CreateAccessKey -- which it never holds, so management-plane skeletons could never
  match. The default and all 38 are now `xdm.event.original_event_type`, where the raw action
  lives.
- `user_agent` defaulted to `xdm.network.http.user_agent` and `registry_value_name` to
  `xdm.target.registry.value_name`, and `service_name` to `xdm.target.service.name`: none is an XDM
  field. They are now `xdm.source.user_agent`, `xdm.target.registry.value` and no default. Four
  markers bound to `xdm.target.file.name` are now `xdm.target.file.filename`, and two bound to
  `xdm.target.registry.value_name` are now `xdm.target.registry.value`, with the five legacy
  `fields` entries carrying the same paths.
- HTTP status numbers were quoted against `xdm.network.http.response_code`, an enum. A literal on
  an enum field is now written as its constant, unquoted: 200 is `XDM_CONST.HTTP_RSP_CODE_OK`,
  `udp` is `XDM_CONST.IP_PROTOCOL_UDP`. `xdm.event.outcome` is the exception, compared as the
  string its constant renders as, because comparing it to the constant fails a pack install (see
  below): `FAILURE`, which names no outcome, is `"FAILED"`. A literal that names no member, or an
  enum whose members are not enumerated, as `NXDOMAIN` on the DNS response code is, prints as
  UNBOUND rather than as an invented constant. `event_outcome`, `http_status` and `content_type`
  gain the defaults their fields make obvious.

The bundle cannot read another bundle's files, so it ships its own copy of what it needs:
`corpus/schema/xdm-fields.json`, the 39 fields the corpus and the defaults bind, each with its
type from the published XDM schema, and the members of the six XDM_CONST groups those fields
take, copied from the `cortex-platform-xdm-author` bundle's schema and constant references and
checked against them field by field when it was built. `emit_xql.py` renders every value by
that type and refuses to run without the file. `validate.py` asks the emitter's own binder about
every marker, on records and on patterns, which it never checked at all, and refuses one bound
to a field the snapshot lacks, or given a literal that is not a member of an enumerated enum,
whether the marker names the field or takes the default.

THE CONTENT FIXES THE BINDINGS NEEDED. The ESX Admins marker is bound to
`xdm.target.user.username`. The xdm-author bundle's owner did not choose it: it was chosen here,
under the maintainer's delegation, and the reasoning is the schema's: the group created or renamed
is the event's target identity, and XDM's target identity object carries a Boolean
`xdm.target.user.group` that marks it as a group, so its name sits in `xdm.target.user.username`.
`xdm.target.user.groups` is the target's memberships and an array; `xdm.target.resource.name` is
kept, in that bundle's references, for cloud and platform resources and authentication targets. The
block is now complete: `xdm.event.operation_sub_type in ("group_create", "group_modify") and
xdm.target.user.username in ("ESX Admins")`. The two account-creation username markers, on the
helpdesk-impersonation and CLFS records, name the account created and are bound to
`xdm.target.user.username`, where they tested the creator. The Log4j block's protocol marker is
bound to `xdm.network.application_protocol`, and the block gains the computed requirement its logic
states, a destination outside the estate's own ranges; with the server-role restriction that lived
only in its `fields`, it prints as partial, and its three constraints are all on screen. The five
other application-protocol markers -- two `http`, `s7comm`, `stratum`, and `smb` with `webdav` --
are bound to the same field. One pattern regex used a negative lookahead, which RE2, the engine
behind `~=`, does not have: the MBR pattern's exclusion of imaging tools is now the computed
exclusion its own note described, valued `false`.

A REGEX IS WRITTEN ONCE, AND A LITERAL IS ESCAPED ONCE. `quote()` doubled every backslash, so
`nc\.exe` became `nc\\.exe`, a literal backslash followed by any character, and `\s` a literal
backslash and an s. The xdm-author bundle records that XQL passes a string's backslashes through
to the regex engine, so both returned a clean zero that reads as a true negative. 140 markers
carrying a backslash were affected, across 116 blocks. A regex is now written as the engine
should receive it, with a double quote as `\x22`, and a pattern ending in an escaped backslash
ends in `[\\]` so that no backslash sits before the closing quote. `prefix` and `suffix` values
are escaped as literals before they are anchored: `.workers.dev` was `~= ".workers.dev$"`,
where the dot matches any character, across 14 markers. A value that cannot sit between quotes,
because it holds a double quote or ends in a directory separator, is written as the equivalent
regex, which XQL matches case-folded as it does `=` and `contains`. A number against a String
field is quoted, so `xdm.event.id in (4720, 4732)` is `in ("4720", "4732")`. A pattern RE2 cannot
run is refused. One tenant probe of a single-backslash pattern should confirm the escaping before
a skeleton is trusted in production.

MARKERS NOW SAY HOW THEY COMBINE. The marker contract never said whether a block's markers are
conditions on one event or alternatives, and the skeleton joined them all with `and`: the Bluemoon
block tested two paths on one file event, although its own marker note says the second is a
separate, earlier event, and a router record required a registry key and a netcat process in one
event. Two optional keys, documented in `corpus/README.md` under "How markers combine" and in the
observation schema: `combine` on a block or pattern, `all` or `any`, and `event` on a marker, a
label grouping the markers tested on one event. Under `any` the skeleton prints the alternatives
joined with `or`, one per line; under `all` with labels it prints one pipeline per event and a
line relating them, the order for a sequence and the join for a correlation. `validate.py`
refuses labels on some markers and not others, and labels with no `combine`. Without the key the
skeleton joins clauses unless it can see they are two events, and prints those as `CLAUSE`
comments under `NO LIVE FILTER`: clauses from two event families (process, file, registry, DNS,
HTTP), or one field tested twice. What it cannot see, and the content keyed for it, is below. 78
blocks and patterns carry the key, set from their own logic and caveats: 49 `any` and 29 `all`,
20 patterns among them.
The Windows host firewall pattern is one: netsh with its command line, or a firewall log event.
13 blocks whose logic does not settle it are left without the key and print their clauses as
comments.

THE HANDOFF CARRIES WHAT IT USED TO DROP. The JSON handoff never read `how.fields`, so a constraint
written only there, the Log4j server-role restriction among 231 such items across 146 blocks,
reached no consumer; it is now `fields_from_source`, verbatim, and the text form prints each item
no marker represents as a `FIELD (legacy fields[])` line. `marker_bindings` gives one entry per
marker in both lists, with the field and a status from a closed list -- `bound`, `computed`,
`state`, `unbound`, `not_an_xdm_field`, `enum_literal`, `array_field`, `unrenderable` -- so a
consumer reads the emitter's decision rather than re-deriving a default binding, and
`filter_status` carries the text form's status. The countermeasures were each technique's list
concatenated and cut at twelve with no count. Counted against the pool the old handoff drew on, the
block's techniques or else its pattern's, 549 of the 703 handoffs held more than twelve entries,
the cut dropped every Evict control from 229 and every Restore control from 230, and 14 repeated an
id. The handoff now takes the selection a consultation's finding prints, from the same function, at
twelve: deduplicated, one control per D3FEND tactic in turn, shown in tactic order, with
`countermeasures_shown`, `countermeasures_total` and `countermeasures_not_shown`.
`consult.countermeasures()` was split so that `select_countermeasures()` is that one function; the
split changes no line `consult.py` or `advise.py` prints.

QUERY.PY'S LIBRARY NO LONGER MOVES WITH THE DISPLAY CAPS, AND EVERY LINE SAYS WHERE IT SITS.
- The library block's classes were inferred from the capped listing, so its scope, and the M in
  "N of M shown", moved with `--limit` and `--exposure-limit`: "Oracle" matched 3 library patterns
  at the default caps and 30 uncapped, "Fortinet" 9 and 25, and "Splunk" lost its block at
  `--exposure-limit 0`. Over the 311 vendor alias values, 6 printed a different count capped
  than uncapped. The classes now
  come from the whole match set, and only from records matched by name, class or sector; free-text
  matches lend theirs only when nothing matched by name, because one weak Adobe match added a
  class worth twenty patterns. The header names the inferred classes and how many records they
  came from, and `--json` adds `library_classes` and `library_classes_basis`. "Oracle" now
  matches 30 at every cap, "Adobe" 6, "Linux servers" 29 and "Splunk" 2.
- Nothing on this path said which plane a record sat in, though SKILL.md sends a caller here
  first. Each line now ends `loci=`, the distinct question-independent `LOCUS` of the record's
  blocks, or of the record where it has none; a `LOCUS over shown:` line after the counts gives
  records per locus over what is listed, with the absent ones named; `--json` adds `loci` to each
  record and `loci_over_shown` to `counts`; and `--full` adds it to the match line. "Cisco ASA"
  reads `CONTROL=21 MANAGEMENT=6 DATA=2 ENDPOINT=0 SUPPLY=1 ORGANISATION=0; ABSENT=ENDPOINT,
  ORGANISATION`.

A WINDOWS HOST FIREWALL PATTERN IS NO LONGER A NETWORK FIREWALL PATTERN. `pat-host-firewall-rule-
modification` is netsh and the platform's own firewall log, and listed `network.firewall` among its
classes, so it reached every FortiGate, PAN-OS and Check Point question's library. It now applies
to `endpoint.os` and `ot.hmi`. `network.firewall` keeps two library patterns of its own.

`references/emit-xql.md` is new and holds the skeleton's contract, so SKILL.md's paragraph on
the script is shorter; SKILL.md also says what `loci=` is.
`corpus/README.md` documents the combination key, the binding rules and the forwarded fields.

New tests:
- `tests/test_emit_syntax.py`: the clause grammar over every live line, no computed expression
  live, the NOT group, one threshold, the status against what was printed, the group and
  account-creation bindings, array fields, the Log4j block, caveat and logic on every block, the
  header locus against a consultation's, unbound values, regex values verbatim, escaped prefixes
  and suffixes, quoted event ids, the trailing-backslash and quote forms, every live field in the
  snapshot, default bindings, enum constants, the raw cloud action, the snapshot's own shape,
  `validate.py` refusing a bad field, a raw action on the enum, a lookaround and an incoherent
  combination, the Bluemoon events, an unkeyed block left unjoined, `or` alternatives, inventory
  and absence, the handoff's fields, bindings and countermeasures, and `datamodel dataset`.
- `tests/test_header_counts.py`: the filter tally in both modes, records with no how-block, the
  missing snapshot, and the library count at four caps for four questions.
- `tests/test_query_ranking.py`: `loci=` on every line, the `LOCUS over shown:` line, `loci` in
  `--json`, and each listed locus against the ladder.

53 observation records and 25 patterns changed for the renderer, all hand-written: no generator
writes a marker these changes touched.

TWO ALERT-FIDELITY CLAUSES COULD NEVER MATCH, AND NOW CAN. Nothing printed under
`fidelity=alert` should be wrong XQL or say the wrong thing, and two blocks were:
- The AV-exclusion registry key was stored as `Windows Defender\\Exclusions\\Paths`, the JSON
  escape applied twice, in the record's marker and legacy field and in
  `pat-av-exclusion-written-for-a-server-module-directory`. The renderer wrote both backslashes
  faithfully, so `obs-generic-ai-orchestrated-intrusion-of-internet-facing-web-servers#how1`,
  alert and `filter=complete`, looked for a pair of backslashes no registry key contains: the
  silent zero the escaping fix exists to remove; 0.42.0 printed four. The values now
  hold one backslash per separator, and so does the pattern's `xql_sketch`. `validate.py`
  refuses a doubled backslash in any literal that is not a regex, in markers and legacy fields
  alike, except at the start of a UNC path. They were the only two markers holding one.
- `file_hash` defaulted to `xdm.target.file.sha256` whatever it held, and the renderer never read
  the SHA256 type its own snapshot gives that field. Six MD5s on the state-sponsored ransomware
  record (`how[2]`, alert, `filter=complete`) and on `pat-regional-or-sector-niche-software-
  supply-chain`, and two SHA-1s listed beside two SHA256s on the wiper record (`how[0]`, alert),
  were tested live against a field they can never match. A file hash now binds by its digest: 32
  hexadecimal digits to `xdm.target.file.md5`, which the snapshot gains, and 64 to
  `xdm.target.file.sha256`. The snapshot holds 39 fields, each checked again against the
  xdm-author bundle's schema. XDM gives a file no SHA-1 field, so the wiper's two SHA-1s are a
  marker of their own, kept, and printed as UNBOUND with that reason; its hash sets are
  alternatives, so the block now says `combine: any`. A digest of the wrong length for the
  field it names, and a marker mixing digest lengths, are refused by the binder and by
  `validate.py`.

Four smaller gaps:
- A list on `equals` or `contains` printed as one quoted Python list in 0.42.0, and a binder that
  printed one value and called the marker bound would have kept only its first. The one shipped
  instance, the four URL paths of `pat-appliance-internal-handler-requested-directly`, sits on a
  pattern no record cites. `equals` now prints `in (...)`, `contains` the regex alternation of the
  escaped values, and `prefix` and `suffix` the same alternation inside their anchor; `regex`, `gt`
  and `lt` take one value and refuse a list.
- The RE2 check looks for a named backreference, `(?P=name)`, which Python compiles, a possessive
  quantifier, which Python 3.11 compiles, conditional and comment groups, and inline flags other
  than `i`, `m` and `s`, by name, before Python's compiler. No shipped pattern uses any of them,
  and a test runs every shipped regex through the check.
- `validate.py` refuses an enum literal that is not a member whether the marker names its field or
  takes the default, so a default-bound `event_outcome` of `DENIED` is refused. Every refusal the
  binder marks as the marker's own fault is now refused too, from a `fault` flag on the binding
  that the handoff does not carry, while a limit of the skeleton, such as a range on an address
  field, still prints as UNBOUND.
- The threshold skeleton printed `| comp count() as hits by <grouping_key>, bin(_time, <window>)`.
  `bin` is a stage, not a function, so the line was wrong whatever filled its placeholders. The 25
  threshold blocks with a live filter now print `| bin _time span = <window>` and then `| comp
  count() as hits by <grouping_key>, _time`.

The MD5 block stays complete and can now match, and the wiper block stays partial. A live digest
clause may name `xdm.target.file.md5`, a SHA-1 marker's `marker_bindings` status is `unbound`, and
a list on `contains` prints as `~=`. New tests, in `tests/test_emit_syntax.py`: no literal holds a
doubled separator, digests bind by length, a list keeps every value, RE2 refuses and accepts by
construct, every shipped regex runs under RE2, `validate.py` refuses each of the six new cases and
accepts a SHA-1, and the threshold stage. Two observation records and one pattern changed, all
hand-written.

THREE MORE ALERT-FIDELITY SKELETONS WERE WRONG IN MEANING:
- An outcome is never compared to `XDM_CONST.OUTCOME_*`, which 17 blocks, 12 at alert fidelity,
  would otherwise print live. The `cortex-platform-correlation-author` bundle records that
  comparison failing the whole pack install with a 101704 that names no file and no field, proven
  on three rules across two packs, and lints it as `ERR-CORR-OUTCOME-CONST`; the xdm-author
  bundle's "never quote them" is about assignment in a modelling rule, not comparison in a query.
  An outcome is compared as the string its constant renders as, `"SUCCESS"` or `"FAILED"`, on the
  union that linter checks: the field, or the OUTCOME group. `PARTIAL` and `UNKNOWN` print as
  UNBOUND, because nobody has read their strings off a modelled dataset.
  `XDM_CONST.OPERATION_TYPE_*` is recorded installing in a query; the HTTP status, method and IP
  protocol constants are not, and a tenant probe is owed (`references/emit-xql.md`, Before
  production).
- A `url_path` matched with `equals` or `in` took the default `xdm.network.http.url`, which holds
  the whole requested URL, so `= "/beacon"` and `= "/.lockd"` could never match, and neither could
  the Kubernetes metadata block's whole filter. A path on a whole-URL field
  (`xdm.network.http.url`, `xdm.target.url`) is now matched where it sits: after an optional scheme
  and authority, and up to a query, a fragment or the end, with `prefix` dropping the tail and
  `suffix` the head. A value that is not a path, and a regex anchored `^/`, are refused. The
  metadata block's credentials path is followed by the role's name, so its marker is now `prefix`.
  `api_path` keeps no default, now with its reason printed.
- `obs-broadcom-vmware-esxi-credential-reset-and-direct-hypervisor-encryption#how0`, alert and
  `filter=complete`, joined a password reset in the management audit, an SSH port and a VMFS file
  write in one filter no event satisfies, though its logic names three stages. It is `combine: all`
  with the events reset, ssh and encrypt, printed as three pipelines in that order. The unkeyed
  check had counted the audit action as neutral. In a `sequence` or a `correlation` without the
  key, a `cloud_operation` clause and a process, file, registry or DNS clause are now two events,
  printed as `CLAUSE (audit)` and `CLAUSE (<family>)`. The two broader rules the review offered
  were measured first and not taken: making `xdm.event.original_event_type` a family of its own
  would split a storage audit's single read that names its object as a file, and refusing to join
  every unlabelled sequence or correlation would unjoin 13 blocks whose markers sit on one event.

Five smaller corrections:
- Two alternatives are held to their own logic, where each would have fired on the act alone
  under `filter=complete`: the Defender exclusion cmdlet, and any write to the Run dialog history
  key. The cmdlet's alternative also requires `inetsrv` on its command line, the path the
  caveat says carries the fidelity. The history alternative requires the recorded entry to hold
  an encoded, hidden or invoke-expression interpreter, the test `pat-run-dialog-encoded-command`
  applies to a command line, on `xdm.target.registry.data`, through a new `registry_data` marker
  type; the snapshot gains that field from the xdm-author schema and holds 40 typed fields.
  `pat-command-history-cleared` had the same shape, and its registry and history-file
  alternatives now require the removal (`OPERATION_TYPE_REGISTRY_DELETE_KEY` or `_VALUE`,
  `OPERATION_TYPE_FILE_REMOVE`), not a write to a key and a file that every Run dialog use and
  every shell command writes.
- The Rust crate block tested `%TEMP%\rust-setup.ps1` for equality, which no event holds. The path
  is a regex on its last two components, and the build tool, the parent of the process that
  writes the file and not its writer, is an event of its own, `spawn` before `write`. The binder
  refuses a variable in a file path, process path or file name, and `validate.py` refuses one in
  a legacy field too. The same search found extensions written with their dot, which
  `xdm.target.file.extension` never holds, on two blocks and a pattern: `.locked`, five shortcut
  and script types and nineteen model formats. They lose the dot, and a dotted extension is
  refused. The first of those blocks also joined a renamed file's extension, a ransom note's name
  and the encryptor's hash in one filter; it is `combine: all` with the events rename, note and
  binary.
- The nacos block joined the backdoor account's name, as actor, with the INSERT that created it,
  which someone else ran. Its own logins are an event of their own: `combine: all` with the
  events login and write.
- Every construct where RE2 and Python's engine differ is handled by name rather than left to
  Python's compiler, which under Python 3.9 refused `\z`, `\p{L}` and a flag in mid-pattern as
  the marker's fault and passed `a{,3}` with a meaning RE2 does not give it. RE2's own constructs
  are rewritten to their Python equivalent for the syntax check, and the `U` flag is accepted.
  `{,n}`, `(?<name>...)` (only RE2 releases from 2023 take it), `\u`, `\N`, `\C` and a counted
  repeat above 1000 are refused with the construct named.
- Pattern `xql_sketch` strings, undocumented and read by no script, carried the defects the
  skeleton was fixed for. 94 of the 185 sketches changed: 22 `bin()` calls became the stage;
  ten sketches' fields moved to XDM's (`xdm.target.file.name` to `filename`, `value_name` to
  `value`, the signature fields to `signer` and `is_signed`, a value size to the data's length);
  three string tests on `xdm.event.operation` moved to `original_event_type` or
  `operation_sub_type`; an event id list was quoted and an HTTP 500 became its constant; and the
  80 whose pipeline reads only `xdm.*` fields outside a join's own subquery open on `datamodel
  dataset`. `corpus/README.md` now documents the key as pseudo-code, and `validate.py` refuses
  those classes in a sketch, against `schema_field_names`, every field path of the XDM schema,
  which the snapshot gains. 49 sketches still read a vendor's columns beside `xdm.*` fields on a
  raw stage; splitting each is a person's work, and it is owed.

The ESXi block stays complete as three pipelines, and the other blocks that moved stayed in
their filter class. `registry_data` is a new marker type, `marker_bindings` reports
`enum_literal` for an outcome whose string is not recorded, the snapshot gains
`xdm.target.registry.data` and `schema_field_names`, and `validate.py` refuses a variable in a
path, a dotted extension, a URL path that is not a path, the RE2 constructs above and the
sketch defects above. New tests, in
`tests/test_emit_syntax.py`: outcome strings and no outcome constant in any live line, URL
paths probed against URLs, the ESXi events in order, the audit split and where it does not
apply, each alternative carrying its fidelity, the nacos events, expanded paths and bare
extensions, RE2 by name both ways, `validate.py` on each new refusal and on legacy fields, and
every sketch against the schema. Eight observation records and 96 patterns changed, all
hand-written.

AN EVENT IDENTIFIER HID TWO EVENTS IN ONE FILTER. Without a combination key the skeleton joins
clauses unless it can see they are two events, and it counts an event identifier, type or raw
action as neutral, because one sits on every event. So an unkeyed block joining one with an
artefact of another event printed a filter no single event satisfies:
- `obs-generic-hive-ransomware-as-a-service-with-log-and-recovery-destruction#how1`, alert and
  `filter=complete`, joined the log-cleared identifiers 1102 and 104 with the command line of
  the utility that clears logs. The log-cleared record carries no command line, and the block's
  logic says clearing a log is itself a logged event.
- `#how5` of the same record, alert and complete, joined a key file in the drive root with the
  ransom note dropped into each directory: two files of one family, which no structural check
  can tell apart.
- `obs-cisco-asa-vpn-webvpn-implant#how0` joined a reload message with the configuration write
  its logic says follows it, and
  `obs-generic-impacket-toolkit-and-long-term-multi-actor-access#how0` joined three checks its
  logic lists as independent. Both were hunt and complete.
- Four alert-fidelity library patterns had the shape "the events, and the utilities":
  `pat-windows-event-log-cleared`, `pat-local-account-created-on-endpoint`,
  `pat-directory-object-permission-modified` and `pat-container-image-or-workload-introduced`.
  The first three joined a Windows security event identifier with a command line.

The fix is content, found by reading against its own logic and caveat every unkeyed marker list
with more than one live clause, 126 of them, and three more the check below refuses that
printed no filter at all. 17 now say their markers are alternatives or several events, and 12
say they are one:
- `combine: any`, each alternative what the logic names: the Hive log-clear (the event, or the
  command) and marker files (the key, or the note); the impacket block's three checks, each
  labelled and each carrying the qualifier its logic or its `fields` note gives it, a client
  that does not behave like the built-in utilities, no local administrative parent, a host with
  no development role; and eleven patterns: the four above, `pat-audit-policy-tampering`, which
  had the same shape and the review did not list, the WinRM handler, session and enabling
  command, the DCOM spawn and endpoint mapper connection, the renamed utility's running image
  and its copy command, the host-discovery utilities and command forms, the BITS utility, user
  agent and client log, and the COM hijacking server keys and redirection key.
- `combine: all` with events: the ASA reload and configuration write, now a `sequence`, as its
  logic says "then"; `pat-hypervisor-credential-reset-then-ssh-encryption` (reset, ssh, encrypt,
  as its record already was) and `pat-access-injected-into-running-cloud-instance` (the push
  and the authorised-key file), which printed no live filter at all.
- `combine: all` where the list is one event and now says so: the seven Defender driver blocks,
  each a Sysmon event whose identifier is the event its path or key is on, the state-file read,
  the Bedrock invocation and the root console sign-in, and two patterns, the network device's
  configuration-change record and the state-file read.

The other 99 of the 126, apart from the negation below, are one event each: a parent and its
child, a file's path and extension, a URL and its response code, a port and the protocol on
it. `references/emit-xql.md` and `corpus/README.md` say what the skeleton cannot see.

Three alternatives were unreachable inside the conjunction, not only wrong. The local-account
pattern's process list held three Windows images, so its `useradd`, `dscl` and `sysadminctl`
command forms could never match; the list now names those utilities. The host-discovery
pattern let only four of its fifteen utilities through its account-discovery regex, under a
requirement of more than four distinct utilities, so it could never fire; the utilities and the
command forms are now alternatives, each under the parent-process test. And the COM hijacking
pattern tested the redirection key, which its logic lists on its own, against a component path
the key's value never holds; it is now its own alternative.

A requirement can now name the event it qualifies. Under `any` the qualifier of one alternative
is no condition on the others, and a computed marker was a requirement of the whole list: the
container pattern's "actor not an authorised image publisher" read as a condition on `nsenter`.
A computed marker carrying an `event` label prints `REQUIRES for EVENT <label>`, and
`validate.py` refuses one naming an event no marker in the list carries. Where no field test
carries an alternative's fidelity, the requirement says what does: the endpoint mapper
connection requires the dynamic port that follows it, and the container pattern's execution arm
gains a command-line test for `nsenter` or an `exec` subcommand, from its own caveat, where it
had matched `docker` and `kubectl` running at all.

`validate.py` refuses an unkeyed list joining an event identifier, type or raw action with a
process, file, registry, DNS or HTTP marker, because the identifier names which event it is and
not whether the others sit on it. Against the corpus before the sweep it refused 22 lists, every
one of them among those above. Two files of one family no check can see; the sweep keyed the one it
found.

A NEGATION PRINTED AS ITS POSITIVE, LIVE. `pat-device-admin-from-unexpected-source` held
`zone equals management` with the note "the rule is the negation", and the skeleton printed
`xdm.source.zone = "management"` under fidelity=alert for the IOS XE block that inherits the
pattern: sessions from the management network, the inverse of the detection. The marker is now
`source_in_management_network` valued false, the corpus's own idiom for it, and prints as
`REQUIRES ... NOT (source_in_management_network)`. The other route to it is closed too: the
binder read a `match` it did not know as equality, so `not_equals` printed the clause it
negates, and `validate.py` checked a pattern's markers only through that binder. The binder now
refuses a match outside the eight the schema names, as the marker's fault, and `validate.py`
holds a pattern's markers to the observation schema's definition of a marker and to the
vocabulary: the type, the match, a non-empty value, `in` with a list, `expr` only on a computed
marker, no unknown key. The response-plan check stays with records: six inventory patterns ask
whether a response plan exists, and there the plan is the subject of the question. No shipped
marker had an unknown match.

A URL WITHOUT A SCHEME IS A URL. The whole-URL anchor made the authority optional only after a
scheme, so a URL recorded as `host/path` or `host:port/path`, which the xdm-author bundle's own
proxy mapping extracts a host from, never matched `/beacon`, `/.lockd` or the metadata prefix.
The head is now an optional scheme and an authority that holds no `/` and may be empty:
`203.0.113.10:4444/beacon` and `evil.example/beacon?id=1` match, and `/x/beacon`,
`http://h/x/beacon` and `/beacons` still do not.

A CONSULTATION PRINTS HOW MARKERS COMBINE. `MARKERS` and `LIBRARY_MARKERS` printed type,
match, value and expr, so a keyed list read as one conjunction, and the ESX Admins group lost
the target field it is bound to. Each line now carries `xdm=` when the marker names its field,
`event=` when it is labelled, and `combine=` on every line of a keyed list, with the expression
last; a finding prints the block's own markers with its own key, else the pattern's with the
pattern's, as `emit_xql.py` renders them. The key set is unchanged. `advise.py` prints no marker
list, so it had nothing to drop.

THE FINDINGS ORDER HAS A PLATFORM TERM. `query.py` and the LIBRARY block ordered by platform
fit and the findings did not, so "Linux kernel" led with a Chrome-on-Windows record's extension
and DLL search-order blocks. Within a group, after the sector and the leftover words, findings
now sort by the fit of the block's markers, or its pattern's, to the platform the question
names, read by `query.py`'s classifier through the `platform_of` table: +1, then 0, then -1.
It is a key and never a weight. `PRIORITY_BASIS` prints `platform_fit=` with the platforms it
read, before `refined_by`, and the ORDERING line names it. "Linux kernel" now leads with four
blocks written for Unix, and the DLL search-order block, rank 2 before, sits below every
neutral or fitting block of its group. The findings of "Fortinet FortiGate", "PAN-OS", "Ivanti
EPMM", "Check Point firewall", "Okta", "SCADA" and the unknown gateway are in exactly the order
they were, since those name no platform; "Microsoft Windows", "Linux servers" and "macOS"
reorder with "Linux kernel". Falling back to the record's platforms for a block whose markers
commit to none was measured and not taken: it lifted every neutral block of a record holding one
Unix path over the neutral blocks of records holding none, which is not evidence about the block.

The impacket block is partial now that its three checks print their qualifiers. The ASA block's
`RULE_SHAPE` is `sequence`, the device-admin zone test is a requirement, and `marker_bindings`
reports an unknown match as `unrenderable`. New tests: in `tests/test_emit_syntax.py`, no unkeyed
list joining an event identifier with an artefact, the reviewed blocks printing their events apart,
each pattern's identifier an alternative of its own, every form an alternative names reachable,
labelled requirements, the refusals, an unknown match never printed as equality, every contract
match bound, a pattern marker held to the record contract, the negation, and the scheme-less URLs;
in `tests/test_consult_library.py`, the marker line and the combination in a consultation; in
`tests/test_query_ranking.py`, the platform order, the fit read from the printed markers, and an
unchanged order where no platform is named. The ORDERING-key reconstructions in
`tests/test_locus_axis.py` and `tests/test_subject_tiers.py` gain the fit, and the shape tally test
names the ASA record's new sequence. Seven observation records and 16 patterns changed, all
hand-written: no generator writes a marker these changes touched.

THE ANSWER IS HEADED BY THE LOCUS THE SCRIPT PRINTS, AND THE REFERENCES LIST EVERY KEY. SKILL.md's
rule 9 defined three planes by a technology's relationship to an attack: CONTROL the appliance
"as a reachable service", MANAGEMENT the thing administered, DATA "the thing that SEES", its
telemetry. That is not what `LOCUS` measures -- no telemetry-source block derives DATA -- and
every finding prints one of six loci, so a model following the rule either re-bucketed findings
against their printed label or dropped the ENDPOINT, SUPPLY and ORGANISATION findings that had
no heading. Rule 9 now heads the answer by the six `locus` values in `corpus/schema/vocab.json`,
puts each finding under the `LOCUS` it prints, always heads MANAGEMENT, CONTROL and DATA and
each other locus `LOCUS_ELIGIBLE` populates, quotes the vocabulary for the three planes, keeps a
heading for an absent locus, and asks for the non-victim relationships with `--role`, which is a
`what.role` and runs across the loci. Its measurement of the victim-heavy ranking moved to
`references/locus-and-coverage.md`, re-measured: 147 records carry a firewall, VPN gateway or
proxy class and 133 are victims, most of them exposures; of the 62 observations, 48 are. That
page's locus table now quotes the vocabulary word for word, where it paraphrased it.
`references/answering-another-session.md` lists every header and finding key `consult.py`
prints, in order, which it did not list at all, and every header and pattern key `advise.py`
prints.
`tests/test_skill_conformance.py` holds rule 9 to the vocabulary and the table to its wording,
and runs without a YAML parser for everything but the frontmatter tests; the new
`tests/test_reference_key_lists.py` holds both key lists to real output, in both directions.
SKILL.md's body is 4,939 words against the 5,000 ceiling.

A PRODUCT IS NAMED BY EVERY NAME IT HAS, A CATALOGUE ENTRY BY EACH PRODUCT IT LISTS, AND A REFUSED
WORD STAYS REFUSED. A second validation on 2026-09-30 found the resolver's idea of "the same
product" too narrow three ways and too wide one way.

One product under several names. FortiOS is the operating system every FortiGate runs, and a
"Fortinet FortiGate" consultation tiered 9 of its 10 listed exposures and 5 of its own findings
as the vendor's other lines, printing "but not the product asked about (FortiGate)" beside
`TECHNOLOGY: Fortinet / FortiOS; FortiGate SSL VPN`. The catalogue's FortiOS SSL-VPN record,
exploited and ransomware-linked, sat in `network.vpn_gateway` and was held back as
other-products-of-vendor at any `--exposure-limit`, and so was the hand-written FortiOS
MFA-bypass exposure. "Ivanti EPMM" called its own former name, MobileIron Core, another
product, and listed the combined EPMM and MobileIron Core catalogue record below three EPM
records. The new `product_families` table records one product the vendor ships, or the
catalogues file, under several names, each with its reason: FortiGate and FortiOS, with the
SSL-VPN as a component; Endpoint Manager Mobile and MobileIron Core; Connect Secure and Pulse
Connect Secure; Policy Secure and Pulse Policy Secure; the Cisco ASA, Threat Defense and
Management Center lines under their Firepower and Secure Firewall names; Exchange and Exchange
Server; and the Linux kernel with KSMBD, its in-kernel SMB server, as a component. A product is
also spelt by every alias the table resolves to it: "Exchange" resolved to Exchange Server, the
resolver held that form, and `product_matches()` never read it for a record filed under
Microsoft, so "Microsoft Exchange" answered VENDOR-LEVEL, "no observation names Microsoft
Exchange Server", over a record listing Microsoft Exchange with five of its catalogued flaws.

One entry naming several products. The catalogue writes "Adaptive Security Appliance (ASA) and
Firepower Threat Defense (FTD)" as one string and it was compared whole, so a Cisco ASA question
called three ASA records "not the product asked about" and put the ArcaneDoor record sixth,
behind three management-centre records. A record filed under a vendor now names each product
its entry lists. A record about a class of product is read whole, because "Windows and Linux
estates" describes what it covers and split, read as the product Windows.

Another vendor's record is compared with the product's own name, whole. Read with Ivanti's
names stripped, "MobileIron Core" was "core", and a MobileIron question counted WordPress's
Core as its product under another vendor.

Measured over the 1,086 vendor-qualified alias questions, the matcher loses no product match
it made and adds 252 across 127 questions, each read by hand. In consultations, the exposure
product tier went from 1 to 7 for FortiGate, 1 to 4 for Cisco ASA, 1 to 3 for EPMM, 3 to 5 for
Exchange, 1 to 5 for Ivanti Connect Secure and Pulse Secure, 1 to 5 for Cisco IOS, 2 to 5 for
VMware ESXi, 3 to 6 for Citrix NetScaler Gateway, 1 to 7 for Trend Micro Apex One, 1 to 4 for
Adobe Acrobat and Apple macOS, and 2 to 3 for the Linux kernel; FortiGate's findings read
`product=11, vendor=2` where they read `product=5, vendor=8`, and "Microsoft Exchange" reads
`RESOLUTION: product`.

A refused word stays refused. A word gated as a product stayed a free-text term and reached, by
name, the product it was refused as: "quantum", refused as Check Point's gateway, ranked the
Check Point record first of 70 for "Zorblax Quantum Edge Gateway 9000" and counted as reaching
a record, so `UNMATCHED_TERMS` left it out; "Apple iOS" refused Cisco IOS and was answered with
twelve Cisco router findings, eight of them HIGH, reached through the same word, while the
exposure path called the same records off-subject. `resolve()` now keeps what each refusal
meant, and `score()` stops a refused word reaching a record filed under the vendor it was
refused as, a record about a class of product whose entries name that vendor, or, for a class
refusal, a record carrying the class. "Zorblax ..." lists `quantum` unmatched and the Check
Point record falls to 11th at the score every other record has; "Apple iOS" answers
`EXPOSURES_ONLY` with Apple's six exposures and no Cisco finding; "key exchange appliance"
drops from 10 name-fragment findings to 3. `edge`, refused as Microsoft Edge, still reaches the
records tagged about edge devices, and a tag finding's `MATCH_BASIS` now names the word.

A Windows binary named like a Unix command is Windows's. The unix indicator's `\bbash\b` matched
"bash.exe", because the dot is a word boundary, so `pat-indirect-command-execution`, whose
markers are Windows binaries only, was shown for "Linux kernel" as fitting Linux, and this
release's query.py tie-break paragraph first listed it among the six shown. A Unix word
followed by a Windows extension no longer counts; of 2,617 markers scanned it was the only
false hit, and control service stopped takes the sixth slot. The regression list in
`tests/test_query_ranking.py` gains the pattern, and a scan of every marker naming a Windows
file is what catches the next one.

An exposure says which observation carries its identifiers, and the lookup reaches it. The one
observation about an exploited Linux kernel flaw is a GeoServer intrusion that escalated
through it; it scored 0 for "Linux kernel", and the kernel's catalogue record said only that
"an observation record in this corpus, which holds the detection logic" carried the
identifier. That record's kernel step has no markers. `query.py` now lists the carriers under
each exposure, from the same map `consult.py`'s `EXPOSURE_DETECTION_HELD` reads, and reaches an
observation carrying an identifier of a `product`-tier exposure: the GeoServer record and one
other now list sixth and seventh for "Linux kernel", reasoned `identifier CVE-2016-5195 (in
exp-kev-linux-kernel)`. The KEV generator names the carriers in the 95 summaries with an overlap
and no longer says they hold the detection logic, and lists every weakness type in numeric
order in the notes, where it listed the first six in lexical order and 15 records lost some:
the kernel's carries eighteen. The regenerated set was diffed against the corpus field by
field and differs only in those two fields; `tests/test_generated_claims.py` now checks the
named carriers as well as the count.

`query.py` also labels a handset exposure it lists as out of scope, since SKILL.md starts a
caller there and a Pixel record was listed fourth for "Linux kernel" with nothing saying so,
and its `OUTPUT CAPPED` line names `--pattern-limit` when the library cap bites, as SKILL.md
said it did; SKILL.md's worked example of the capped header is brought up to date. `validate.py`
refuses a product family with no vendor, fewer than two names and components, or no reason. The
new `tests/test_product_identity.py` holds every case above; three expectations elsewhere moved
with it: the Linux kernel names three exposures, the FMC record's reason carries its Firepower
name, and the Windows-only list gains its fifth pattern. `references/resolution.md` and
`references/exposures.md` document the matcher, the refusal and the join. SKILL.md's body is
4,949 words.

A GENERATED RECORD SAYS WHAT ITS PRODUCT IS, SITS WHERE ITS PRODUCT SITS, AND SAYS WHAT EACH
IDENTIFIER IS. The same 2026-09-30 validation found four defects in the generated exposures, each
made in a generator outside this repository and copied into `aliases.json`.

Four Fortinet product lines were firewalls. The KEV classifier's Fortinet vendor default classed
FortiSandbox, FortiClient EMS, FortiWeb and FortiManager `network.firewall`. A "Fortinet
FortiGate" consultation listed the first three as "VENDOR IN A CLASS ASKED ABOUT ... in
network.firewall", three of its ten exposure slots, while the PSIRT and ZDI records for the same
products, classed otherwise, were held back as the vendor's other lines; so whether a product
was listed depended on which generator had written the record the question met. `EXPOSURE_LOCUS`
read CONTROL=11, MANAGEMENT=0, and the FortiManager catalogue record for CVE-2024-47575 printed
CONTROL in the same answer as a MANAGEMENT finding for the same CVE on the same product. A
"Fortinet FortiClient EMS" question resolved the firewall class. Now the FortiGate answer lists
nine exposures, `product=6, vendor-class=3` -- the Fortinet two-or-more-product entry and the
FortiManager catalogue and PSIRT records -- and reads CONTROL=7, MANAGEMENT=2, with FortiManager
on MANAGEMENT and CONTROL beside it. The product tier is 6, not the 7 the product-identity entry
above measured, because the PSIRT record naming FortiGate alone is folded into FortiOS's
(below). "Fortinet FortiClient EMS" resolves `app.rmm, security.edr` and reads MANAGEMENT=6,
ENDPOINT=5 where it read CONTROL=11.

On a generated record the class is the plane. A generated exposure's surface is not read (the
locus ladder, above), so its class is the only plane it has, and the KEV classifier's own note
that "the class is the TECHNOLOGY and LOCUS carries the plane" was false for exactly these
records. Check Point's newest catalogue entry, filed as "Multiple Products", carries a path
traversal letting an unauthenticated attacker upload and run scripts on the Security Management
Server, Log Server and SmartEvent, and a certificate-validation flaw in the Security Gateway's
VPN; it printed CONTROL alone, and so did SmartConsole's, both Cisco FMC entries' and the ZDI FMC
record. Each management platform now lists `app.rmm` first and the class of what it manages
second, in the KEV classifier, the ZDI class table, the PSIRT class table and the aliases, and
the rule is applied to every catalogue pair naming only a management platform: the Catalyst
SD-WAN Manager under both its spellings, VeloCloud Orchestrator, Versa Director and Prime DCNM
as well as the firewall managers. "Check Point firewall" now reads `EXPOSURE_LOCUS: CONTROL=2,
MANAGEMENT=2`, with the two-product entry and SmartConsole on `MANAGEMENT, CONTROL` and the two
gateway records on CONTROL. Over the whole corpus the exposures place CONTROL 286, DATA 266,
ENDPOINT 148, MANAGEMENT 107, SUPPLY 81, ORGANISATION 6, where they placed CONTROL 306, DATA 268,
ENDPOINT 149, MANAGEMENT 90, SUPPLY 82, ORGANISATION 6 over 901.

One product, one class. Grouping every generated record by the vendor the alias table resolves
and the product name without case or punctuation found three more products two generators
classed apart: Kemp LoadMaster, a managed file transfer product in its KEV record through the
Progress vendor default and a load balancer in its ZDI record; ISE, `identity.sso` in the KEV
classifier's explicit pair and `identity.directory` in the ZDI table; and FortiClient, the
endpoint agent in its PSIRT record and a VPN concentrator in its ZDI record, whose one advisory
is a local flaw in the agent. Each takes the class its other records and its alias carry.
ScreenConnect, a remote support tool the alias table and both observations naming it class
`app.rmm`, reached the remote-access class because that keyword rule is read first. Expedition,
which migrates firewall configurations and holds the devices' credentials, was a firewall
through the Palo Alto vendor default. `validate.py` now refuses a product its generators class
differently and names every record; run against the corpus as it stood before this change it
reports seven. A catalogue record should also sit on a plane the observations naming its product
reach: of the 31 products a KEV record and an observation both name, five did not with no
question asked -- FortiManager and ScreenConnect above, and Langflow, Outlook and MinIO, each
classed by a vendor default or a keyword rule against the class its alias and its observation
carry. Langflow is an AI agent and workflow platform, `app.ai_platform`, not a library; Outlook
is a mail client, `app.office_suite`, not the operating system; MinIO takes the corpus's
`cloud.iaas`. None is apart now, and a test holds it.

What each identifier is. A KEV record carrying one identifier quoted the catalogue's description;
one carrying two or more only counted them, so 230 of 699 said nothing about any flaw, and the
Check Point entry never said that one of its two is on the management and log servers. The
generator's `summarise()` now describes each identifier in the catalogue's words, newest first
and at most six, and says how many more it leaves to the catalogue; 200 of the 230 are described
in full.

A PSIRT advisory belongs to a product its vendor marks affected. The collector took every product
an advisory mentioned. Palo Alto's feed lists each product its status table covers, affected or
not, so Cloud NGFW carried 14 PAN-OS advisories and its row reads "None" on 12 and "None on AWS,
None on Azure" on the thirteenth; Prisma Access carried 14 and is affected by 4; Panorama's two
and GlobalProtect UWP App's one read "None" on every row; and an informational bulletin whose one
row reads "None" made a Prisma SD-WAN ION record. The feed also lists a product once per platform
row, so Prisma Access Agent's summary counted 8 advisories for 4 and Cortex XSOAR's 2 for 1.
Fortinet's collector took every Forti word in the summary, so a FortiOS capwap flaw "an attacker
controlling an authenticated FortiAP FortiExtender or FortiSwitch" could exploit was filed under
all three, "FortiClient EMS" under FortiClient, the endpoint agent, "FortiSwitch Manager" under
FortiSwitch, and the vendor's own misspelling FortiSanbox under a record of its own. `collect.py`
now attributes a Palo Alto advisory to a product with a status row that is a version bound or
"All", and a Fortinet advisory as the decision above says, reading the advisory's version table;
`collect.py --reattribute` re-derives the 118 rows of the existing store from the cache it was
built from, with the network refused, because collecting again would filter every row out
against a corpus that now holds them. Cloud NGFW carries CVE-2026-0287 alone and Prisma Access
four; FortiClientEMS gains CVE-2026-59836 from FortiClient, FortiSwitchManager gains two from
FortiSwitch, FortiSandbox gains the misspelt record's one, and FortiAP loses the capwap
identifier. Seven records are removed: `exp-psirt-palo-alto-networks-panorama`,
`-globalprotect-uwp-app` and `-prisma-sd-wan-ion`, and `exp-psirt-fortinet-fortiextender`,
`-fortiswitch`, `-fortigate` and `-fortisanbox`. Every identifier the Fortinet four held is still
carried by the record of a product the vendor names affected. The "PAN-OS" answer no longer lists
Cloud NGFW as a second copy of the PAN-OS record.

Every Palo Alto and Fortinet PSIRT record carried 2026-08-01, the collection date, at month
precision, so a June advisory read as August and 60 days old; each is now dated by its newest
advisory's own date, from the feed or the advisory page, at day precision. A record summarising
several advisories cited the first and gave the reader no way to the rest; its summary now names
each by the identifier its vendor files it under. The class table gives the PSIRT records the
classes above, and a class value may be a list in the PSIRT and ZDI generators as it already
could in the KEV classifier.

`EXPOSURE_RANSOMWARE` printed a bare "no" for the catalogue's value Unknown, which read as a
negative finding; it prints `unknown`.

The generators live in the shared staging folder, which has no history, so each changed file was
copied to `<file>.pre-0930` first (the KEV generator already had one): `kev/classify.py`,
nineteen `PAIR` entries and the four tail entries they supersede; `kev/generate.py`, the
per-identifier description; `zdi/generate.py`, five classes and list classes;
`psirt/collect.py`, the two attribution readers, the advisory dates and `--reattribute`;
`psirt/generate.py`, the classes, list classes, dates and advisory identifiers; and
`psirt/psirt.jsonl`, re-attributed. Each regenerated set was diffed against the corpus field by
field before merging: KEV differs in 230 summaries, in class and tag on 19 records and in
surface on 18; ZDI in class on five and surface on three; PSIRT in the fields above on 40 and by
the seven removals, which were made by hand because the merge never deletes.
`tests/test_generated_classes.py` pins every class, checks one class per product across
generators and one shared plane with the observations, the validator check, the
management-platform placement in both consultations, every multi-identifier summary, the
attribution and the dates; the product-identity tests that named the folded FortiGate record now
use a fixture, and the FortiGate tally reads 6.

A CITATION CARRIES ONLY WHAT ITS SOURCE SAYS, AND A CONNECTION'S PROCESS IS ITS ACTOR. The same
2026-09-30 validation found hand-written content its own citations do not support, and two
skeletons no single event could satisfy. Every advisory named below was fetched on 2026-09-30
and read before its record or rule changed.

Response doctrine. `doc-appliance-rebuild-not-factory-reset`, printed on 10 of the 12 findings
of an unknown-edge-appliance question and on every network finding, cited AA25-239A, which has no
word of a factory reset, a rebuild or a reimage in it. The reset survival is AA24-060B's: CISA's
lab research found that an actor holding root on the gateway could keep persistence through
factory resets and appliance upgrades while deceiving the integrity checker. AA25-022A's three
victims replaced the compromised virtual machines with clean, upgraded ones. The rule now cites
both, and its detail no longer says implants were observed surviving a reset, which was lab
research. The containment rule's second half, act simultaneously rather than gradually, is
AA25-239A's and was cited to AA22-264A, which carries the Albania escalation and nothing on
simultaneity; it now cites both, AA25-239A under its full title, where the rebuild rule's copy
had dropped "Worldwide". The offline-backup rule cited only the Albania advisory, which says
nothing of backups; it now cites AA22-040A's offline, tested backups as well, and says the
ordering is this corpus's reading. The remediation-scope rule called the handing-on of victims
"the agencies' stated reason" attribution is unreliable; AA22-040A gives the ecosystem's networks
of developers, affiliates and freelancers, and the detail now says so. All twelve rules were read
against their sources; the other eight hold as written. Every source now carries `supports`, the
advisory's own words for the claim, and `tests/test_citation_support.py` holds a rule naming a
specific claim -- a factory reset, simultaneity, an offline backup, out-of-band coordination --
to a source whose words carry it, pins the advisories each rule cites, and checks each title
against the liveness cache and the records citing the same page.

Ivanti Cloud Service Appliance. `obs-ivanti-cloud-service-appliance-chained-exploitation` carried
Connect Secure as a product, `network.vpn_gateway` first, and CVE-2025-0282, CVE-2025-0283 and
CVE-2024-9381 among seven identifiers. AA25-022A says the first two, in Connect Secure, are
unrelated to it, and names the third only in the title of a vendor advisory it links. The record
now carries the four identifiers the advisory names as exploited, in its identifiers, its CVE
marker and its legacy field; the Cloud Service Appliance alone; and `network.remote_access`, a
remote access gateway, which fits the advisory's remote access framing where the VPN
concentrator class came with Connect Secure. Both classes are CONTROL, so no plane moves, and
the `cloud service appliance` alias follows the record. The alias's class is not only a plane,
though: it decided the exposure tier, and moving it lost the appliance's own catalogue records
from its answer, which the product family below restores. Its versions are the advisory's: 4.6
before patch 519 for all four, and 5.0.1 and below for two. Its government sector and United
States region, which the advisory does not give, are cut, and its observed end is 2024-10, the
vendor's October disclosure of exploitation, not the advisory's January publication. The KEV
record for Connect Secure, Policy Secure and ZTA Gateways named this record as carrying its
CVE-2025-0282; regenerated, it no longer does.

Ivanti EPMM. The URL marker on
`obs-ivanti-epmm-authentication-bypass-and-arbitrary-file-write-chain` read
`(?i)/mifs/(aa|rs)/api/v2/`: a segment one letter short of the `/mifs/aad/api/v2/` that
AA23-213A names three times, NCSC-NO's own hunt among them, joined to a route from a 2025 report
on a different chain. It matched neither path the advisory names, and `emit_xql.py` copied it into
a live filter. It is now `(?i)/mifs/aad/api/v2/`, with a note naming the hunt. The file-path
marker, `/mi/tomcat/webapps/` or `/opt/mi/`, came from the same 2025 report and from no source at
all; the advisory names no path, only that CVE-2023-35081 writes files with the operating system
privileges of the web application server, which is now the block's computed condition.

Session token theft. `obs-generic-session-token-theft-bypassing-authentication` cites AA26-204A,
an advisory about a Zimbra webmail campaign that recounts the group's earlier cloud-mail
campaigns. Its mailbox block printed four Microsoft 365 audit operations as literals from the
record, under a Microsoft licensing caveat; the advisory names neither. The block's markers, its
legacy field and that caveat are cut, and its logic now says what the advisory reports: bulk
exfiltration through the platform's legitimate interfaces, which names no operation. Left without
markers of its own, the block printed the pattern's, which the review of this change found and the
paragraph below corrects. The record also carried CVE-2025-66376, the Zimbra flaw, though its notes
call the access exploit-free; the identifier added 1.5 to its score and made it the only CRITICAL
finding of an Okta answer. It is cut, the notes say why, and the Zimbra KEV record, regenerated, no
longer names this record. Its only typed session marker, `now() - session_start > 0`, was true of
every session; it is now the logic's own test, one session identifier seen from more than one
address. "Deliberately", which the advisory does not say, is gone from the summary. In an Okta
consultation the record's two blocks sat at ranks 7 and 8, and sit at 14 and 19.

Log4j and Outlook. The Log4j block printed `xdm.target.port in (389, 636, 1099, 1389)` at
`fidelity=alert`, which matches every internal directory bind; the external destination its
caveat calls the signal was prose, and `filter=partial` came only from an unrelated legacy field.
The Horizon and state-affiliated blocks citing the same pattern carry it as a condition, and now
so does this one. The Outlook NTLM block had the same shape on ports 445 and 139, and its source,
AA25-141A, advises blocking and alerting on NTLM and SMB requests to external infrastructure; it
carries the condition too. `tests/test_emit_syntax.py` holds every block citing a pattern whose
sketch excludes the estate's address ranges to carrying it.

A connection's process is its actor. The tunnel-client block on
`obs-generic-remote-access-appliance-compromise-for-access-resale` printed its fixed port and its
image on `xdm.target.process` as one event, under `fidelity=alert` and `filter=complete`. The
process that opens a connection is the event's actor, `xdm.source.process`, in the platform's
own mapping and the xdm-author bundle's; `xdm.target.process` is a process acted upon, which a
connection does not carry. The emitter counts address, port and zone fields as neutral, so
nothing saw it. That block, and the water-treatment block that joined a remote access tool's
image with the control-network zone the same way, now bind the tool to
`xdm.source.process.name`; the water-treatment block's zone, bound here to `xdm.source.zone`, is an
inventory condition since the paragraph below. `validate.py` now refuses a connection's port,
address, zone or protocol beside `xdm.target.process` on one event, through
`emit_xql.acted_upon_process_on_a_connection()`, which reads each labelled event apart and an
unlabelled `combine: any` list as alternatives. Run over the corpus before this change it reports
four: the two blocks and two library patterns. `pat-windows-remote-management-execution` now binds
its session event's process to the actor, and `pat-control-service-stopped` holds the
control-network zone as a computed condition read from inventory, because a process event carries no
network zone.

Two printed forms. `emit_xql.py` printed `pattern=None` in the header of a block citing no
pattern, where `consult.py` prints `PATTERN_ID: -`, and an inventory precondition over several
identifiers as Python's list. Both print as text.

Over the corpus the skeleton gave 75 complete, 248 partial and 380 none after this change, and
at alert 60, 204 and 162, where it gave 76, 247, 380 and 61, 203, 162, and 479 live clause
lines, from 480; the paragraph below moves both. Against 0.42.0, 106 observations and 133
patterns have changed, from 102 and 132. The KEV set was regenerated against the corpus with its
generator unchanged, diffed field by field and merged, and differs in the two summaries above
and nothing else. No generator was edited. The regeneration did rewrite the KEV staging output,
`kev/kev-exposures.jsonl`, which already had a `.pre-0930` copy from before this release's first
regeneration, so the backup rule held; this paragraph said until the review below that no
staging file was edited.

ONE APPLIANCE UNDER THREE NAMES, AND A BLOCK THAT PRINTED ITS PATTERN'S OPERATIONS. The review of
the change above found that it lost a product's own records from its answer, and three smaller
things. NVD and the two advisories below were fetched on 2026-09-30 and read before anything
changed.

The Cloud Service Appliance. Moving the `cloud service appliance` alias to
`network.remote_access` left "Ivanti Cloud Service Appliance" with `EXPOSURES: 0 shown of 0` and
counted the appliance's two catalogue records, four exploited identifiers between them, among the
vendor's other product lines. Before the move the question reached them only as `vendor-class`,
through the VPN class the alias happened to share with the Ivanti vendor default, beside nine
records of the vendor's other lines; it never reached them as the product. AA25-022A spells the
appliance Cloud Service Appliance, the catalogue Cloud Services Appliance (CSA), and for its 2021
flaw Endpoint Manager Cloud Service Appliance (EPM CSA). "Service" and "Services" differ mid-name,
so canonical equality never joined them, and the alias table held the two spellings as two
products. NVD describes the 2021 flaw as one in the EPM Cloud Services Appliance (CSA) and lists
version 4.6 for it, the version the 2024 flaws and the advisory name, so the three are one
appliance: a `product_families` entry now says so, with that reason. Endpoint Manager, the product
the appliance serves, is not in it. "Ivanti Cloud Service Appliance" lists all three catalogue
records as `product`, `product=3`; "Ivanti Cloud Services Appliance" reads `product=3` where it read
2, and "Ivanti EPM CSA" `product=5` where it read 3, and both now say `RESOLUTION: product`, where
they said no observation named the appliance. Asked the way `references/resolution.md` measures
the matcher, the family adds 16 product matches, all on the six questions naming the appliance,
each read, and loses none. The alias keeps the record's class: the nine records of other lines
share only the VPN class the record dropped and are counted in `other-products-of-vendor`, and the
class analogues narrow with the class, 68 matched findings where the VPN class gave 121, with
`LOCUS_ABSENT` naming DATA, SUPPLY and ORGANISATION. That follows from the class, which stays the
maintainer's decision (not done, above). `tests/test_product_identity.py` asks all three spellings
for all three records and holds the singular answer to listing them.

The session-token mailbox block. With its Microsoft 365 markers cut, the block had none of its
own, so `consult.py` and `emit_xql.py` fell back to the pattern's and printed five Microsoft 365
operations as `MARKERS` and as the live filter, under the Zimbra advisory's citation and beside a
caveat saying the advisory names no operation. AA26-204A says the group's earlier campaigns
exfiltrated mail in bulk through legitimate programming interfaces, and gives no operation and no
volume. The block now carries that as its own condition: the mail one account reads or exports
through the platform's programming interfaces, per hour, against that account's own measured
baseline, the bound left unresolved. A consultation prints it as the block's one marker, and the
emitter prints no live filter for it, `filter=none`, where it printed a filter from the pattern.
A volume per window is counted, so the block's shape is `threshold`, the pattern's and that of
every other block testing a volume against a baseline, where it was `single_event`; its logic
loses a closing sentence calling bulk access a low-volume event to alert on individually, which
the advisory does not say and a volume test contradicts. The record's session block kept, as a
legacy field, the always-true test the change above cut from its markers, printed as
`session_age_hours gt 0` beside a note about sessions far beyond their lifetime; it is cut too.
`tests/test_citation_support.py` holds the block to its own marker and shape, the emitted block to
none of the operations, and the session block to no zero bound.

The water-treatment block. The change above bound the remote access tool's image to
`xdm.source.process.name` and the control-network zone to `xdm.source.zone` on one event, while it
moved `pat-control-service-stopped`'s zone to inventory because a process event carries no network
zone. The host's own events name the process and a network device's name the zone, so the block's
zone is now an inventory condition too, as the pattern's is. AA21-042A names desktop sharing
software, TeamViewer among it, and no zone; the zone values are this corpus's site vocabulary, as
they were. This is reasoned from which telemetry carries which field, as the pattern's note is,
and not measured on a tenant. `tests/test_emit_syntax.py` refuses a zone and a process tested on
one event anywhere in the corpus or the library; the water-treatment block was the only one.

The skeleton now gives 75 complete, 247 partial and 381 none, and at alert 60, 203 and 163, from
75, 248, 380 and 60, 204, 162, and prints 477 live clause lines, from 479: the mailbox block's
filter and the water-treatment block's zone line are gone. The two blocks' records had already
changed in this release, so the changed-record counts above stand. The staging sentence in the
paragraph above is corrected. No generated record and no staging file was touched.

THE PLANE A BLOCK SITS ON IS THE BLOCK'S, AND A QUESTION ONLY EVER ADDS TO IT. Batch V4-locus of
the 2026-09-30 validation: five major defects in plane placement, each re-run from its probe
before anything changed. None reverses a standing decision: LOCUS is six values, a control plane
is the network sense and a cloud administrative API is MANAGEMENT, handsets stay out with
`app.mdm` on MANAGEMENT, and a generated exposure's surface is still not read.

A surface reached every block of its record. `what.attack_surface` is one value per record and
the surface tier placed every block with it. `internet_facing_management` put all 25 blocks of
the records listing an OT class first that it decided on MANAGEMENT, a PLC's operator-display
manipulation and its S7 data-block writes, read from industrial protocol and process telemetry,
among them, so "Siemens" printed every finding naming Siemens on MANAGEMENT and "Siemens S7"
showed CONTROL 1 and MANAGEMENT 11. The surface now decides a block unless the block has gone
past the way in: it cites no technique the shipped ATT&CK reference files under initial-access,
reads no evidence on the surface's own plane, and its evidence reads its first-listed class's
plane or only posture. Such a block is placed by its class, with the surface as its span and
`set aside for this block` in its basis. The list of way-in techniques is `way_in_techniques`
in the locus map, the reference's own, and `validate.py` refuses it when the two differ. Twenty
blocks moved: sixteen from MANAGEMENT to CONTROL (the PLC display, keyswitch, data-block,
controller-access and posture blocks, the relay and covert-network blocks of compromised
routers, a network device used for industrial reconnaissance and a VPN affiliate's impacket
use), one to DATA (a database's native encryption), and three helpdesk-impersonation blocks,
account creation, ticket forgery and a remote access tool, from ORGANISATION to ENDPOINT. The
device-administration blocks the surface placed stay on MANAGEMENT: one read from `auth_log`,
which maps to CONTROL, cites the way in. "Siemens S7" now shows CONTROL 5 and MANAGEMENT 7, every
one of the five from a record naming Siemens and three from the S7 advisory's own record, and
"SCADA" CONTROL 10 where it showed 9.

A delivery vector decided the plane. `surface_supply` placed all 73 blocks of its records on
SUPPLY, 43 of them where the first-listed class is on another plane: the AWS miner's pool traffic
and the IAM workload creation that followed its container images, and nine of SolarWinds' ten
blocks, Golden SAML among them. A supply surface now places only a block citing the technique its
vector is filed under, Supply Chain Compromise (enterprise, ICS and mobile) or Trusted
Relationship, in `surface_vector_techniques`, or reading `integrity_check`. Thirty blocks moved,
each carrying SUPPLY as its span: twelve to MANAGEMENT, eight to CONTROL, seven to DATA, three to
ENDPOINT. "AWS" holds one SUPPLY finding, the CodeBuild webhook filter, where it held four;
SolarWinds' signed-update block stays on SUPPLY and the other nine sit on MANAGEMENT. The
firewall questions ("Palo Alto firewall", "I have a Cisco ASA", "Check Point firewall",
"Fortinet FortiGate") reserved SUPPLY for a resolver-bypass block on an appliance implanted where
monitoring is absent, which now sits on its firewall's CONTROL, and "Okta" reserved it for the
lapsed-domain trust record, which now sits on DATA; each reports SUPPLY absent, with its span
counted on the bullet. The class that decides some of these is arguable, and is listed under
not done.

A cloud administrative API sat on the first-listed class. Blocks whose only live test is a cloud
provider's or tenant's administrative operation printed CONTROL or ENDPOINT from a container,
AI-platform, directory or host class listed first. A new tier, `operation`, between the surface
and the first-listed class, places a block on MANAGEMENT when every typed marker on it is a
`cloud_operation` and not every operation is in `non_administrative_operations`, the uses of a
service that are not its administration: reading mail, invoking a model, reading a stored object.
A regex, substring, prefix or suffix names a family and is never read as listed. It places 17
blocks and moved seven: the organisation-tier policy change, SSH keys pushed into a running
instance, IAM users minted for model access, an Exchange role assignment and a Duo authenticator
enrolment from CONTROL, a Microsoft 365 admin role grant from DATA, and the miner's role and
workload creation from SUPPLY. An Exchange Online block testing `MailItemsAccessed` stays on DATA
and the Bedrock block testing `InvokeModel` beside a user name and agent stays on CONTROL. Only a
block's own markers are read, so validate.py, which places a block without its pattern, agrees;
the impacket record's mailbox block has none, prints its pattern's Exchange operations as its live
test, and declares `how[2].locus` MANAGEMENT with that reason in its notes. The note is a
derivation reason, not a claim about the incident, and no statement from AA22-277A changed.
"Kubernetes" now holds three MANAGEMENT findings where it reported MANAGEMENT absent. Six
overrides were the alternative.

The question's class displaced the record's own span. `LOCUS_SPAN` held one second value, and the
class the question matched was the first source tried, so on a firewall question it replaced the
record's own second locus. The code comment and the reference said it could only add a span and
the test module's docstring repeated it, while `test_span_source_order` pinned the replacement.
Across the corpus 238 (block, matched class) pairs lost a second locus that way, 134 of them
ORGANISATION; on "Fortinet FortiGate" 11 of 78 findings did, so a consultation and `emit_xql.py`
disagreed about where the same block sits by SKILL.md's own definition. `class_matched` leaves
`span_order`. The record's span is computed from the record alone and printed second, and the
question's class is appended after it where it differs from both, so `LOCUS_SPAN` holds one to
three values and its values after the primary begin with the JSON `locus_span` `emit_xql.py`
prints. The KEV-harvest record reads `DATA, ORGANISATION, CONTROL` on a firewall question.
`LOCUS_ABSENT`'s span-only count counts a locus anywhere after the primary, so FortiGate's
ORGANISATION reads `span-only 11` where it read 6. The code comment, the reference, the test
docstring, `corpus/README.md`, `references/exposures.md` and SKILL.md's table row say what it
does.

Patterns about administering a device printed CONTROL. A pattern placed with no block reads its
`applies_to_classes`, and a network or OT device's administration has no class of its own, so
SNMP from anything but the monitoring system, a management channel usable before authentication
completes and input executed through a management endpoint's log write printed CONTROL from the
network class listed first, and the "T1190" answer counted CONTROL 21 and MANAGEMENT 6. A pattern
may now declare `locus` with a `locus_reason`, read only where it has no block, and held by
`validate.py` to changing the derivation and to a reason with no semicolon. Fourteen declare
MANAGEMENT, each reason naming the vocabulary's administration item it is: SNMP, admin access,
admin credentials, configuration change, firmware or the console. "T1190" counts CONTROL 18 and
MANAGEMENT 9. Reordering `applies_to_classes` was the alternative, and would have said the
patterns apply first to management software they do not describe.

`validate.py` now prints `locus derivation: 770 how-blocks -> CONTROL=243 MANAGEMENT=164 DATA=91
ENDPOINT=194 SUPPLY=53 ORGANISATION=25; 12 declared override(s), 391 carrying a span`, from 224,
162, 84, 189, 83 and 28 with 11 and 370, and a new line, `locus derivation (per block): 50
block(s) past their record's surface placed without it, 30 of them on a supply surface; 17
placed by a cloud administrative operation; 14 pattern(s) declaring a locus`. Exposures place as
before. `references/locus-and-coverage.md` states both, and a test holds each figure to the
derivation. The skeleton's filter tally is unchanged, 75, 247 and 381.

Four tests had fixtures the change moved rather than broke, and each now says why: the library
test's absent MANAGEMENT for "Kubernetes" is absent ENDPOINT for "GitHub Actions"; the
below-floor fixture "npm" is "SolarWinds Orion"; the `--per-locus` test's "changed something"
half asks "Microsoft Windows"; and the Guardsquare test, which used ENDPOINT absent as a proxy
for no `security.edr` route, now checks the route itself, because a poisoned-update record's
Windows resolver bypass reaches ENDPOINT through `dev.library`. New tests pin each rule on the
records the probes named and on synthetic blocks, and fail on the code before this change.
Against 0.42.0, 106 observations and 142 patterns have changed, from 106 and 133. No generated
record, generator or staging file was touched.

WHAT A SELECTION LEAVES OUT IS NAMED, FREE TEXT READS WHERE A DEFENDER'S WORDS ARE, AND A
CONTROL SAYS WHETHER D3FEND STATES IT. Batch V5-advise-docs of the 2026-09-30 validation: six
major defects in `advise.py`, the countermeasure selection and what the documentation claims,
each re-run from its probe before anything changed. None reverses a standing decision. No
observation, exposure or pattern changed; the D3FEND reference was regenerated from its
generator, with its licence text byte-identical.

Evidence an ATT&CK selection passed over. `--attack T1190` returned the 50 patterns citing T1190
and said nothing of the 21 T1190 how-blocks under 12 patterns that do not list it: seven of
their records, four of them exploitation of a management interface (a BIG-IP management
interface, a firewall management centre's static credential, a router's web interface brute
forced at scale and an IOS XE router pivot), appeared nowhere in the answer.
`ATTACK_RECORD_ONLY` printed only when an id selected nothing, while
`references/answering-another-session.md` said it printed wherever an id reaches patterns
another way. It now prints whenever how-blocks cite a requested id under a pattern the id does
not select, a revoked id's replacement and an expanded parent's sub-techniques counting as
selected, counts a block citing two sub-techniques once, and ends by naming each record that
carries such a block and cites no pattern returned, since that record appears nowhere else.
`ATTACK_REQUESTED` says how many further blocks there are. `--attack T1190` now reads `21
further how-block(s)` and names the seven; `--attack T1003` names 2 blocks and 1 record, and
T1550.002, which selects nothing, keeps its line, which now also names its two records. The
earlier entry for the key above says it was widened here.

Free text read only what a pattern says about itself. "exploitation of edge network appliances"
returned three post-compromise patterns named for edge appliances and no T1190 pattern, with
nothing saying 84 more had overlapped. "webshell", "vishing" and "mimikatz" returned NO_MATCH
and called themselves a reportable finding, although seven patterns cite Web Shell, a Teams
vishing record cites the helpdesk impersonation pattern and a marker names mimikatz; "DC sync"
ranked three sync patterns over DCSync; "IIS spawning cmd.exe" and "w3wp spawns powershell"
ranked `pat-print-spooler-abuse` first on an alphabetical tie. The regression set in
`tests/test_advise_selection.py` held only the phrasings the matcher had been tuned on. Five
changes, each resolved against the corpus's own text and none against a list of synonyms:
- The stemmer takes derivational endings after the inflectional ones: `-ation`, `-ator`,
  `-ment`, `-at` with five characters kept, and `-ion` after `t` or `s`. "exploitation" meets
  "exploit" (30 and 69 patterns carried them apart), "impersonation" "impersonate", "escalation"
  "escalated", "injection" "inject". A stop word is refused after inflection too, so
  "executions" does not come back as "execut".
- A context haystack: the pattern's markers and caveat, and the title, summary and citing
  block's logic, caveat and markers of every record citing it, at half the weight of the logic,
  with its own rarity. A single word found only outside a pattern's name, description and id
  admits it only when no more than 2% of patterns carry the word anywhere.
- Compounds both ways: two adjacent words whose join the corpus holds are read joined ("DC sync"
  meets dcsync), and a word the corpus holds on no more than 2% of patterns is also split where
  both halves are words it holds ("webshell" meets "web shell"). The halves counted one at a
  time until the batch's review, below, which has them met only together.
- A score is scaled by the share of the caller's words the pattern met, half always kept, a word
  met only in context counting half; a tie goes to more words met, then more citing records,
  then the id.
- With `--per-shape` 3 or more, the last guess was kept for another reading of the shape: the
  best-scoring candidate whose name, description or id meets a word of the shape none of the
  guesses above it meets there. The batch's review, below, replaced it before release with a
  slot for the behaviour the shape names in ATT&CK's words: this one fired on words the shape
  was not about and filled the edge-appliance slot with an inventory pattern.
`SHAPE_RESULT` now counts the patterns that overlapped and how many `--per-shape` cut. Every
free-text guess keeps its VERIFY label. "exploitation of edge network appliances" returned the
two edge-appliance integrity and reboot patterns and, for the reading "exploitation",
`pat-repeat-offender-product-classes`, a T1190 inventory pattern, and reports 84 cut; after the
review its third is a T1190 detection instead. "webshell" reaches a
Web Shell pattern first, "DC sync", "IIS spawning cmd.exe" and "w3wp spawns powershell" their
pattern first, and "vishing" and "mimikatz" theirs among the three returned. A free-text
`NO_MATCH` over a typed ATT&CK id that patterns cite no longer calls it an absence. Every
phrasing the earlier regression set pins still ranks its pattern first. Measured on 38 phrasings
written for this change, which the design was checked against and so are no held-out score, the
three returned held the expected pattern or technique for 31, from 26; two lost theirs
("ransomware encryption" keeps safe-mode boot first and now returns two log patterns whose
descriptions name both words where it returned partial-file encryption, and "firmware implant on
a router" loses a firmware-downgrade pattern to an OT keyswitch pattern kept for "implant"; the
review, below, gives the first partial-file encryption back and takes the keyswitch out), and
five reach nothing useful either way ("pass the hash", "log4shell", "JNDI lookup", "impossible
travel", "new local administrator account"; "Pass the Hash" still prints `SUGGEST_ATTACK`). The
weights and shares are chosen, not measured.

Superclasses filled the countermeasure slots. The harvest read the mapping file's query
technique, which answers for the control D3FEND maps (`def_tech`) and for every class above and
below it, so a class that is not itself about the artefact was listed as mapped, and the lists
were in name order: Access Mediation, whose definition is about buildings and border crossings,
headed 21 of the 28 answers for T1685, and 75 of the 166 controls shown across the T1003.001 and
T1685 probes were not a direct mapping of any cited technique. The generator,
`_ingest/d3fend/harvest.py` (backed up first), now grades each link from the rows that reach it,
`direct` where the control carries the artefact edge itself, `narrower` where it inherits it
from a class above and `broader` where it reaches it only through a class below, reading the
ancestry from the ontology's `rdfs:subClassOf`; a re-keyed id takes its predecessors' best
grade. Of the 8,364 links 4,063 are direct, 1,950 narrower and 2,351 broader. The reference
gains `by_attack_inferred` and `counts.links_by_grade`, each list is ordered tactic, then grade,
then name, and every other key is unchanged: the regenerated lists hold the same ids, and
`licence`, `licence_note`, `licence_text`, `attribution` and the countermeasure table are
byte-identical to the file they replace, which the unchanged generator reproduced exactly before
the edit. `select_countermeasures` takes a control D3FEND maps directly to any cited technique
before one it only infers, within each tactic, and a block prints each control's grade. Over the
415 patterns with a control, 918 of 2,469 shown controls were inferred and 389 patterns showed
one while a direct control of the same tactic was cut; now 145, and none. T1685 shows 10
inferred of 160 where it showed 73, and Access Mediation heads none of its answers. A
consultation's selection moves on 678 of the 690 how-blocks with a control (inferred 1,499 of
4,119 shown to 213), and the handoff's at twelve on 686 (3,422 of 8,096 to 1,382), and each
handoff control carries `mapping`. Within a grade the order is still the name, which is D3FEND's
order and not a relevance judgement, so System Daemon Monitoring, a direct Detect mapping for a
disabled security service, is still cut on all 28 T1685 answers, behind two direct controls that
sort before it.

Two smaller countermeasure defects in the same lines. A cited technique D3FEND does not map, or
one whose every control an earlier technique reached, vanished from the header, so six host
controls for T1685 read as covering a router firmware implant whose T1601 has no mapping; the
header now names both. And the revoked-predecessor label said D3FEND 1.6.0 "predates ATT&CK
19.2", which revoked nothing: 19.1 already carried T1685. It now says D3FEND maps the revoked id
and not its replacement, in the label, the reference's note, the generator's docstring, SKILL.md
and `corpus/README.md`.

`--role` claimed more than it filters. The help, `references/locus-and-coverage.md` and the
entry for the flag above said it keeps "records where the technology played the roles named". It
keeps records whose `what.role` is one of them, and that is one value per record, not one per
product or class the record names. Two of the seven records "Palo Alto firewall" keeps under
`--role telemetry_source,inline_tool,control_bypassed` are `control_bypassed`, name a directory
and a firewall among their classes, and say in their own summaries that the perimeter held
(AA23-349A) and that no actor was found (AA25-212A). The help, the reference, `query.py`'s help,
SKILL.md rule 9 and the entry above now say exactly what is filtered, and `ROLE_FILTER` says it
on every filtered answer. Whether those two records' roles are right is a content question and
is not changed here. `ROLE_FILTER` also counts each role asked for, 0 included, where a role
matching nothing showed only by its absence, and an unknown `--role` names the values refused
rather than the whole argument. SKILL.md's two exit-code lists name the unknown `--role` and the
`--per-locus` floor.

The library provenance line was a template. Every `LIBRARY_MATCH` said the pattern was "derived
from technique space rather than from an incident and is about no one product". For
`pat-appliance-internal-handler-requested-directly` that is false: its `derived_from` is CISA's
malware analysis report series, its markers are one vendor's appliance paths, and its own caveat
says eighteen of the reports concern that product line. `consult.py` never read `derived_from`,
so SKILL.md's "say where they came from" could only be answered wrongly, and 3 of the 34 library
patterns, those from CISA's reports, carried the false line. `LIBRARY_MATCH` now quotes the
pattern's own `derived_from`, or says it records none (two do); `LIBRARY_PATTERNS` counts the
sources over every pattern matched; `LIBRARY_REFERENCES` gains a `DERIVED_FROM` row for a source
that is not already a `CORROBORATION` row; and `query.py`'s library listing prints `derived
from:`. SKILL.md, `corpus/README.md`, which said 33 of the 34 came from the public rule corpora
where 25 do, `references/exposures.md` and the library test's docstring say the same.

In the same area, from the same reports' minor items: `OBSERVED` says how many of its records
are seed, and `RESPONSE_DOCTRINE` how many seed records it left out of the impact match, where
one line called a seed-only pattern observed and the next called its record unassessable;
`URL_LIVENESS` counts the printed URLs with no fresh verdict in the cache, which print with no
marker under `--no-verify`, where it said "0 re-checked" and nothing of them; and `CONTRACT`
says what SEED means. Left, with the reason: the record-level locus of a block and three
classes' CONTROL placement are locus-map decisions for their own batch; the partial-date parser
is shared with the ranking; the doctrine ranking that lets one hidden record's impact displace
an always-on rule, the `--role` exit 1 that suppresses library blocks, and the class-level
wording under a partial `--role` filter are behaviour decisions the documents disagree on;
`SUGGEST_ATTACK`'s length floor keeps ordinary words ("Tool", "Server", "Proxy") from pointing
at techniques, and widening it needs a measured rule; a relative score floor would cut the
behaviour slot's pick, which ranks low on overlap by design; and the three verified records
lacking a read date are content.

New tests fail on the code before this change and pass after: record-only reporting when an id
also selected patterns, the derivational stemmer, the synonyms and defender's words above, the
edge-appliance reading and the counted cut, the typed-id `NO_MATCH`, every cited technique named
once on a countermeasure header, no direct control cut for an inferred one, the T1685 head, the
revoked label, the reference's grades and ordering, the handoff's `mapping`, the library origin
on every library pattern and in `query.py`, `ROLE_FILTER`'s wording, the seed split and the
unchecked URL count.

THE BATCH'S REVIEW: THE EDGE-APPLIANCE FIX WAS IN LETTER ONLY. An independent review of batch V5
passed five of its six majors and failed the sixth. "exploitation of edge network appliances"
returned a T1190 pattern only through the reading slot, and that pattern,
`pat-repeat-offender-product-classes`, is an enrich inventory of which product classes recur on
the exploited list; the patterns detecting exploitation of an appliance still ranked eighth to
fourteenth, and the test asked only that some returned pattern cite T1190. The ranking cannot
fix it from inside: "edge" is in 8 patterns' own text and "exploit" in 85, because this corpus
is about exploited edge devices, so the rare word naming the object outranks the subject.
Measured before choosing, on the pinned phrasings and 60 others: technique names read as
identity, class descriptions read into the ranking, logarithmic rarity, a steeper coverage
scale and complete matches ranked first each either left the three post-compromise patterns on
top or cost a pinned phrasing or another shape its pattern ("malicious browser extension", "rdp
brute force from the internet", "new domain admin added").

The reading slot is replaced by a behaviour slot, `Matcher.behaviour_slot`. A shape's words are
read against the ATT&CK names of the techniques patterns cite: "exploitation" names Exploit
Public-Facing Application and the other Exploitation techniques, and "edge" and "appliances"
name none; a shape spelling a whole name, "pass the hash", names that technique only. When no
guess above the last cites a technique the shape names, and the last is not itself such a
detection, the last slot goes to the highest ranked candidate that is detection-grade (alert or
hunt, since the caller is designing a rule), cites a technique the shape names, and meets every
other word of the shape in its name, description, id, logic or classes, a class read through
its `vocab.json` description ("Router or edge routing platform", "Perimeter or internal
firewall appliance"). Its `MATCH_BASIS` names the technique, the words, the fidelity, its rank
on overlap alone and the `--attack` that selects every pattern citing it, and keeps the VERIFY
label. Asking for one other word rather than every one was tried: it fired on the object words
ATT&CK names also carry ("device", "deploy", "copy") and displaced a network-device
configuration pattern.

"exploitation of edge network appliances", "edge appliance exploitation" and "exploiting edge
appliances" now return the integrity and reboot patterns and
`pat-management-channel-usable-before-authentication-completes`, a T1190 alert on firewall, VPN
and router classes and one of the patterns the validation named, 29th of 87 on overlap alone.
"ransomware encryption" gets `pat-partial-file-encryption` (T1486) back third, 5th of 82. Over
the 60 phrasings the old slot fired on 29 and the new one fires on those 4; "pass the hash" gets
its third place, local credential-store extraction, back, and "firmware implant on a router",
"cloud storage bucket made public" and "oauth consent phishing" are no longer labelled.

Three minors in the same lines. A split word's halves are met only together, so "helpdesk
impersonation" no longer fills its second and third places on "help (in helpdesk)" or "desk (in
helpdesk)" alone, and "webshell" is overlapped by 38 patterns rather than 55, its top three
unchanged; a half the caller also wrote as a word of its own stands alone. Under several
`--attack` ids, `ATTACK_RECORD_ONLY` told the caller to select with `--patterns` patterns another
id had already returned (`--attack T1190,T1078` did it four times each way); they are now named
after `returned here by another selection`. And the entry introducing library patterns, above,
said all 34 were derived from technique space; it now gives the measured sources: 25 from the
rule corpora, 3 from ATT&CK, 3 from CISA's reports, 1 from FiGHT and 2 unrecorded.

Left, with the reason: "firmware implant on a router" keeps `pat-snmp-from-unexpected-source`
third, where 0.42.0 had the firmware-downgrade pattern. The SNMP pattern meets "router" in its
name and "firmware" and "implant" in its citing records, which the context haystack counts, and
taking context out of the coverage scale was measured to cost "IIS spawning cmd.exe" its first
place. The weights are still chosen, not measured, and the 60 phrasings were written alongside
this change, so they are a check and not a held-out score.

New tests fail on the code before this review and pass after: the three edge phrasings with
their `MATCH_BASIS`, the slot staying out of six shapes, five of which the reading slot entered,
one spelled name naming one technique, ransomware encryption, the split word, and the
record-only list under two ids.

A RECORD CARRIES ONLY THE IDENTIFIERS ITS ADVISORY NAMES, AND AN EXPOSURE SAYS WHICH OF ITS
IDENTIFIERS ARE THE PRODUCT'S AND WHICH ARE COVERED. A third validation, 20 probes on
2026-10-01, found four defects in the exposures and their provenance. Every advisory named
below was fetched on 2026-10-01 and read before its record changed.

A citation that never carried its identifier. `exp-fortinet-fortios-mfa-bypass-username-case`
said CVE-2020-12812 was "used by ransomware actors for initial access" and cited AA22-011A,
which lists seventeen identifiers and not that one, names no ransomware and no second-factor
bypass, and was marked `verified` with a read date; its actor type, state-nexus, contradicted
its own summary. AA22-321A says it in these terms: Hive actors bypassed multifactor
authentication on FortiOS servers through CVE-2020-12812, logging in without the FortiToken
prompt by changing the case of the username. The record now cites AA22-321A, and takes that
advisory's actor (Hive, a ransomware affiliate, attributed with high confidence), its sectors,
its worldwide scope and its dates, June 2021 to November 2022, published 2022-11-17; its notes
say why. Nothing compared what a record carries with what its source names, so a check now
does: `corpus/reference/advisory-identifiers.json` lists the CVE identifiers each of 305 CISA
advisory and analysis report pages names, read from a maintainer-side copy of the page text
by a script kept with that copy, and `validate.py` refuses a record whose every cited source
is listed there and none of them names an identifier it carries, outside its notes and its
citation. Run against the corpus before this change it reports two: the MFA exposure and
`exp-papercut-mf-ng-improper-access-control`. AA23-131A names CVE-2023-27350 alone and reports
the Bl00dy Ransomware Gang exploiting it; the PaperCut record also carried CVE-2023-27351, "a
state-sponsored group" and `credential_theft`, none of them in the advisory, and all three are
cut, with a note. Of the 1,142 records, 176 cite only listed pages and are checked; 2 cite a
CISA page with no local copy and are counted, not decided. `SOURCES.md` moves one record from
"CISA, FBI and NSA" to "FBI, CISA and HHS".

A catalogue entry naming no product. The catalogue files some identifiers under a catch-all
product, "Multiple Products" for eighteen vendors, and the tier read `who.products` alone, so
"Fortinet Multiple Products", whose catalogue text names FortiOS for CVE-2022-40684,
CVE-2024-23113, CVE-2025-25249, CVE-2025-59718 and CVE-2026-24858, printed "not the product
asked about (FortiGate)" and sat seventh of nine in a FortiGate answer, below a PSIRT record
none of whose fifteen identifiers is exploited. `query.exposure_tier()` now reads such an entry
by the catalogue's description of each identifier, which the generator quotes in the summary:
the subject before the first verb is matched as a product entry is, so a record is in the
`product` tier where a description names the product asked about, and `EXPOSURE_MATCH` says
for which identifiers, which descriptions do not name it, and how many identifiers the record
does not describe. The FortiGate answer lists it first, `product=7, vendor-class=2`. A
possessive and "A B & C" are read as the catalogue means them, so "Ivanti MobileIron's Core &
Connector" names MobileIron Core, EPMM's former name, and the EPMM answer no longer carries
CVE-2020-15505 at product tier from a hand-written record and as "not the product asked about"
from the catalogue's; its tally reads `product=4, vendor-class=4`. The identifier join takes
only the identifiers whose descriptions name the product, so "VMware vRealize Automation" does
not reach the two state-actor vulnerability lists through a Workspace ONE flaw. `query.py`
prints the identifiers under the line and `catalogue_names` in `--json`. Of the 1,117 questions
formed from each product alias and its vendor, 37 move one of six catch-all records into the
tier, and each was read against the description it rests on.

A union read as coverage. `EXPOSURE_DETECTION_HELD` named an observation if it carried any of
the exposure's identifiers, and said nothing of which. The EPMM catalogue record's field named
the 2023 chain's observation as FINDING 1, and that observation carries two of the seven
exploited identifiers; CVE-2025-4427, CVE-2025-4428, CVE-2026-1281, CVE-2026-1340 and
CVE-2026-6973 are carried by nothing, which only a sentence of the prose summary said, and the
field is the one SKILL.md says a consumer can parse without reading prose. It now reads `2 of 7
identifier(s) carried; <observation> (Ivanti) carries CVE-2023-35078, CVE-2023-35081 - FINDING
1 above; no observation carries ...`, and `references/exposures.md` gives the grammar.

A campaign with no observation. The Cisco ASA answer's catalogue record carrying CVE-2025-20333
and CVE-2025-20362 holds no detection, and the one ASA implant record is SEED. That is a gap in
the corpus, and it is left as one (not done, above).

`tests/test_citation_support.py` holds every checked record to its pages, the check to the old
MFA record as a fixture, both corrected records and the validator's line;
`tests/test_consult_exposures.py` holds every catalogue summary to the two forms the reading
depends on, the catch-all tier for six questions and against three, the match text, the
undescribed count, the join, and the detection line for EPMM and, parsed back, for every
exposure against `query.py`'s carrier map. Each fails on the code and corpus before this
change. The FortiGate tally expectation in `tests/test_product_identity.py` moves to 7.

Left, with the reason: the MobileIron catalogue record still sits on `CONTROL` beside the
hand-written MobileIron Core record's `MANAGEMENT`, because the catalogue entry names Sentry, a
gateway, and the locus map lists the gateway class first for it; the Cloud Service Appliance's
three classes are the maintainer's decision above; and the class-analogue reserve slots, the
ORGANISATION-shaped blocks placed by their first class, a record's ACTION line taken from its
pattern's name, and six verified records with no read date are other batches' or content.

A RESERVED SLOT NAMES WHAT WAS ASKED, A PLANE ONLY ANALOGUES HOLD SAYS SO, AND A CAMPAIGN
RECORD'S BLOCK IS TIERED BY WHAT IT CONCERNS. The same third validation found three defects in
how a consultation fills and labels its planes. Each probe below was re-run with `--today
2026-09-30` before and after.

A plane counted as covered by another product's analogue. The locus quota reserved a slot per
locus holding any eligible finding, and a class analogue was eligible, so "Fortinet FortiGate"
reserved `DATA` for a known-vulnerability catalogue join at rank 24 (class, 5.63) and `ENDPOINT`
for a Zeppelin share-enumeration block at rank 44 (class, 3.71), whose `ENDPOINT` comes from its
first-listed `endpoint.os` and whose firewall is a SonicWall. Both pushed out FortiGate
findings: the boot-image persistence block at rank 11 (3.93) and the pre-authentication
management-channel block at rank 12 (3.00). The header counted both planes as represented and
`LOCUS_ABSENT` named neither, so rule 9 had the answering model head `ENDPOINT` for a firewall
with a Windows ransomware rule under it. "Cisco ASA" `--per-locus 3 --limit 18` reserved the
same two blocks, as did the Palo Alto, Check Point, Juniper and Firepower questions, and the
Firepower one filled `DATA` from a MySQL extortion record reached by the word "threat". Where
the question named a product or vendor and any finding in the match set names it, a reserved
slot is now filled only from an eligible finding in tier `product` or `vendor`, which
`LOCUS_SUBJECT` counts per locus; a locus whose eligible findings are all class analogues, the
vendor's other product lines or tag matches is named on a fixed line, `LOCUS_ANALOGUE_ONLY`,
with a bullet giving its eligible count by tier, its first finding and how many are shown, and
gets no reserve. Where no finding names what was asked, the answer is analogues throughout, its
`CLASS_LEVEL_WARNING` says so, no finding naming it can be displaced, and the reserve spreads
the analogues as before; a question naming neither prints `not applicable` on both lines.
FortiGate now shows twelve findings naming FortiGate or Fortinet with nothing displaced, the
management-channel block among them; the boot-image block is passed over by the record cap, its
record already holding two slots, and replaced by a FortiGate finding from below the cut; and
the header reads `LOCUS_ANALOGUE_ONLY: DATA, ENDPOINT`. The ASA answer is the validation's
counterfactual exactly: ranks 1 to 14, 16, 19, 20 and 21, with 15, 17 and 18 passed over by the
record cap. Over the 847 questions formed from each product alias and its vendor, the 324 whose
answer holds a finding naming what was asked reserved 789 slots, 725 of them for analogues in
268 questions, and in 144 of those an analogue's reserve displaced a finding naming the product
or vendor; they now reserve 63, every one naming what was asked, and 302 of them name 877 loci
in `LOCUS_ANALOGUE_ONLY`. The 511 whose answer holds none reserve exactly as before. SKILL.md's
rule 9 says a locus in `LOCUS_ANALOGUE_ONLY` says under its heading that nothing there names
what was asked.

A campaign record's blocks all took its tier. A record filed under `any` or `Multiple` lists
what a campaign reached, and a product reason put the whole record in the `product` tier. The
"Microsoft Exchange" answer drew its whole product tier from the AA22-257A record, listing
Fortinet appliances, Exchange and VMware Horizon, and two of the four blocks it showed detect
another product: the outbound directory lookup for the logging-library flaw, whose caveat calls
it the durable Log4j detection, and the FortiOS username-case second-factor bypass, whose one
identifier is CVE-2020-12812. Both printed "names the product asked about", and the ProxyShell
exposure pointed at the Log4j block as the detection it holds. A block of such a record is now
read on its own -- its logic, caveat and the strings its markers and fields carry, never the
record's summary or identifiers -- and concerns the product where it names it (a form
`product_forms()` holds, or a product the resolver admits in that text) or carries an identifier
an exposure record holds as the product's own. It concerns another where it names another
product the resolver admits or carries identifiers none of which is the product's, and then
takes the tier the record's other reasons give, its class or else a name fragment, with a
`MATCH_BASIS` saying so: `CLASS-LEVEL - the record names the product asked about (Microsoft
Exchange (as Exchange Server)) among its 3 product entries, but this block concerns another: it
carries CVE-2020-12812 (held here under Fortinet FortiOS), ...`. A block naming no product and
carrying no identifier keeps the tier and says it describes the campaign as it reached every
product listed (decisions, above). A vendor named inside such a record's entries is read the
same way, with the identifiers exposure records file under the vendor: "Fortinet" printed the
Log4j block as naming Fortinet, and no longer does; "SonicWall firewall" still holds its only
findings naming SonicWall through a Zeppelin record listing SonicWall firewalls fourth, whose
blocks name no product and keep the tier, saying so. Only a record that lists an entry not
naming what was asked is read this way; a record filed under a vendor, and one whose every entry
names the product, keep their tier on every block. The Exchange answer reads `product=2` where
it read 4, the catalogue-join block carrying CVE-2021-31207, CVE-2021-34473 and CVE-2021-34523
and the campaign block, and is still a `product` answer. Over the 1,158 questions formed from
each vendor alias and each product alias, 120 question-block pairs leave the tier: 94 reached as
the product concern another product (81 fall to the class, 13 to a name fragment) and 26 reached
as a vendor named inside an entry fall to a name fragment; 47 are shown to concern what was
asked, and 349 name nothing and keep it. Four questions, each naming Laravel or a Laravel
component, lose their only finding naming it: the one campaign block reaching them reads exposed
`.git` and `.env` paths, and names Git. `EXPOSURE_DETECTION_HELD` points at the first shown
block of a campaign record whose own text carries one of the exposure's identifiers, and where
none of its shown blocks does it says `its record is shown above (FINDING k), in a block
carrying none of them`; the ProxyShell exposure now points at the catalogue-join block.

Two smaller defects in the same answers. A record naming only the vendor inside an entry, on a
product question, printed "is about another product than yours" or "the record was not reached
as the technology you named"; it now says `the record names the vendor asked about (Fortinet
(named in product Fortinet appliances)) among what it lists, but not the product asked about`.
And "Apple iOS", answered `EXPOSURES_ONLY`, refused three handset records with the refusal
counted only in `EXPOSURES_NOT_LISTED`, while every `EXPOSURE_MATCH` said every exposure filed
under the vendor was listed: the `RESOLUTION` line now carries the refusal, as every other mode
did, and `EXPOSURE_MATCH` says `listed except 3 handset record(s), which are refused`.

`tests/test_locus_axis.py` holds the reserve to `LOCUS_SUBJECT` on nine named questions, the
firewall planes to `LOCUS_ANALOGUE_ONLY` with the Zeppelin block unshown, every analogue-only
bullet and `LOCUS_SUBJECT` to a recount of the whole match set in pure order, the class-level
reserve, and the lines on questions naming nothing; the quota tests that read `LOCUS_ELIGIBLE`
as the reserve now read the basis the header names. `tests/test_subject_tiers.py` holds the
Exchange and Fortinet campaign blocks, `block_scope()` on synthetic records, the exposure
pointer, the vendor-inside sentence and the handset refusal. Each fails on the code before this
change. `tests/test_class_fallback.py` reads the "Fortinet" analogues from the match set and
`LOCUS_ANALOGUE_ONLY`, since they no longer take a slot from Fortinet's own findings, and the
key-list probe for `LOCUS_UNDERSERVED` asks for `--limit 1`.

Left, with the reason: promoting a block that carries the product's identifier in a record
naming only the vendor, the remaining reserve on questions naming no product, and the rank-based
`LOCUS_DISPLACED` split (not done, above); the GitHub question deriving no classes, because its
records name GitHub inside their entries and `classes_from_vendor()` excludes them, which would
add class analogues and a library to a vendor answer; the web-shell pattern read as
Windows-only, the Office persistence pattern reached through `server.mail`, the hypervisor block
on `CONTROL`, the `GATED` reason for "ios" and the ZDI summary's truncated flaw list, which
belong to the platform classifier, the content, the locus map, the resolver and the ZDI
generator; the `PRIORITY` band ignoring the match group, a cosmetic only a change to what the
band means would settle; and the ASA's 2025 campaign, which is a corpus gap.

A CAMPAIGN BLOCK IS TAKEN FROM WHAT WAS ASKED ON A READING OF ITS OWN, NOT FOR A NAME IT
MENTIONS. The review of the change above failed it for one new defect. `block_scope()` demoted a
campaign block whenever the resolver found any other product in its text -- a passing mention,
an alias the table files under another entry, a regex path fragment -- without asking whether
the block was about the product asked. Re-run with `--today 2026-09-30`: "VMware ESXi" lost the
share-encryption record's hypervisor block (markers `/vmfs/volumes/`, `vmdk`, `vmx`, `vswp`)
because its logic says one intrusion "covers Windows hosts, Linux servers and the
virtualisation layer", and the same record's directory-enumeration block took its place at
product tier; "npm registry" lost the install-hook worm block for a passing "self-hosted
runner"; "GitHub Actions" and "GitHub" lost the rogue-runner block (`Runner.Listener`,
`actions-runner`) for "self-hosted runners", an entry of the same record, and "GitHub" the
forge-token reconnaissance block for "git client"; "Microsoft IIS" lost the appcmd, inetsrv and
BadIIS block, printed as Telerik's because the table files `badiis` under the record's Telerik
entry; "Progress Telerik UI for ASP.NET AJAX" printed "it names Progress Telerik UI for ASP.NET
AJAX, and neither names Telerik UI for ASP.NET AJAX", a pair compared to its own product under
another vendor; and "Laravel" lost its only finding naming it, and its `RESOLUTION: product`,
for a `/\.git/` fragment in the record's only block.

A block is now read for evidence that it concerns what was asked before anything it names is
read against it (`BLOCK_RULES`, in order). It keeps the tier where it names the product or
vendor; where it carries an identifier an exposure record holds as the product's own or files
under the vendor; and where its own words, through a class alias and never through another
product's alias, read for a class of what was asked that no other entry it names by name
shares -- ESXi's hypervisor block reads `server.hypervisor (hypervisor, virtual machine,
virtualisation)`. It falls to the record's class or a name fragment where it carries only
identifiers exposure records hold under another product (the FortiOS bypass, on Exchange,
Horizon, ESXi and Linux); where it names another product the record lists by that product's
own name and reads for none of the asked product's classes (the integrity block's NetScaler
paths, on F5); or where it names a product the record does not list, or one it does by a word
that is not its name, while the pattern it cites is written for none of the asked product's
classes (the Log4j lookup, written for web servers and libraries, on Exchange and Fortinet).
For a vendor whose entries resolve no class, "Fortinet appliances" among them, the classes are
those the alias table files the vendor's products under. A block reading for a class of what
was asked that another entry it names shares keeps the tier and says the class is theirs and
yours (the crate block naming arrayref and proc-macro1, on internment); a record's only block
keeps it, being the record's whole account of how the campaign reached what it lists; and a
block with none of these readings keeps it and names what it does name. An entry's pairs
include any the alias table files under the entry's own spelling, so the `badiis` pair is the
Telerik entry's and not "a product the record does not list", and a key is that product's
name only where its words sit inside the product's or the entry's own name. `MATCH_BASIS`
gives the reading; a vendor's name is printed once (`names it (GitHub)`, where it read
`GitHub, github`). Over the 1,155 questions formed from each vendor alias and each product
alias, the 374 reaching a campaign record by name: the change above moved 105 question-block
pairs out of the product and vendor tiers, and now 56 move (47 to the class, 9 to a name
fragment), 49 restored and none added. Of the campaign pairs, 41 keep the tier by name, 7 by
identifier, 84 by their own class words, 2 by a shared class, 6 as a record's only block and
276 on no reading either way; 10 fall on identifiers, 11 on another entry's name and 35 on a
name under a pattern written for another kind. No question now loses its every finding naming what
it asked, where three Laravel questions did. Every block the review listed is restored, each
saying why, and the original defect stays fixed: Exchange's Log4j and FortiOS blocks, and
Fortinet's Log4j block, are still class analogues. "Fortinet FortiGate", "Cisco ASA", "Okta",
"Ivanti EPMM", "PAN-OS", "Check Point firewall" and "network firewall" print exactly what they
printed before it, and "Fortinet" and "Siemens" keep every tier, differing only in
`MATCH_BASIS`: one Fortinet and two Siemens campaign blocks now say they read for
`network.vpn_gateway` or `ot.plc` where they said they named nothing, and the Log4j block gives
its new reason.

Two cosmetic defects in the new header lines. Under `--no-locus-spread`, where nothing names
the subject, `LOCUS_ANALOGUE_ONLY` said "the reserve spreads them" beside `LOCUS_SPREAD: off`,
and `LOCUS_SUBJECT` that a slot was filled from `LOCUS_ELIGIBLE`; both now say no slot is
reserved. An answer with no finding, "Apple iOS" among them, said a reserved slot was filled
from `LOCUS_ELIGIBLE`, and now says no finding matched.

`tests/test_subject_tiers.py` holds each block the review listed to its tier, its reading and
a `MATCH_BASIS` that does not say "concerns another"; ESXi's hypervisor block to the product
tier, with the Netlogon and FortiOS blocks still taken; the Telerik answer to no block called
another's for naming Telerik; and, over every campaign entry that resolves to a product, a
block taken away to a reason that never names the product asked. The `block_scope()` unit
test passes the pattern a block cites, and holds a name under a pattern written for the asked
class to the tier. `tests/test_locus_axis.py` holds the header wording. Each fails on the code
before this change. Left, with the reason: a library a product embeds, the directory block
naming nothing, the `badiis` alias and Exchange's `CONTROL` (not done, above).

A CLASS IS READ IN WHAT A BLOCK SAYS, NOT IN WHAT IT MATCHES. The second review of the
R2-quota-tiers batch failed the change above for a false keep in its own defect class. The
class reading took its words from everything a block carries, marker and field strings
included, and the access-resale record's integrity block matches three NetScaler paths, one of
them `/var/vpn/themes/imgs/`: the class alias `vpn` read that path for `network.vpn_gateway`,
the class of the Connect Secure entry and not of the Citrix one (`network.load_balancer`), so
the block kept the product tier on "Ivanti Connect Secure", "Pulse Connect Secure" and four
other Connect Secure and Pulse questions, and the vendor tier on "Ivanti", each printed as "this
block concerns it". On "Ivanti Connect Secure" it was FINDING 8 of 12, and a consumer gating on
`MATCH_TIER` product took a NetScaler file-path rule as Connect Secure's. No test caught it:
every test of the change above held a block to not being taken away.

A block's class is now read in its own sentences, its logic and caveat (`block_prose()`); its
names and identifiers are still read in everything it carries, so `/netscaler/` still names the
Citrix entry, and the block falls to the class on all seven questions under `other-entry`, as
it already did on F5. Re-run with `--today 2026-09-30` over the 374 alias questions reaching a
campaign record by name, each with `--no-locus-spread --limit 2000`: exactly those seven
question-block pairs move (six from product, one from vendor, all to class) and no other tier
moves. 21 `MATCH_BASIS` lines change their reading only: the Siemens, Rockwell and Schneider
PLC blocks, GitHub's fork-token log block and Active Directory's directory-enumeration block
now say they name none of the record's products, where they read `plc`, `controller`,
`pipeline` or `ldap` out of a marker expression, and the npm worm and GitHub Actions blocks
cite fewer words for the same class; 11 `other-entry` lines now say the block "reads in its own
sentences for none of its classes". "Ivanti Connect Secure" prints the findings and tiers it
printed at 668299e (`MATCH_TIERS` product=18). "Fortinet FortiGate", "PAN-OS", "Ivanti EPMM",
"Check Point firewall", "Okta", "Cisco ASA" (and with `--per-locus 3 --limit 18`), "Microsoft
Exchange", "VMware ESXi", "F5 BIG-IP", "Linux" and "Alibaba Nacos" print exactly what they
printed before, and so does `advise.py --attack T1190 --no-verify`. Read directly, as both the
product and the vendor, `block_scope()` would also have kept the Log4j lookup block on four
Microsoft directory questions for "ldap" in its lookup expression; `consult.py` reaches none of
them as the vendor, so no answer moved.

`obs-generic-remote-access-appliance-compromise-for-access-resale`: the integrity block's
caveat said its paths were "specific to two products". AA20-259A, fetched on 2026-10-01, gives
every one of them -- the two web shells' and the tunnel binary's -- for the NetScaler flaw,
CVE-2019-19781, and none for the Pulse Secure or F5 appliances. The caveat now says the
advisory gives them only for that flaw and none for the other two appliances, and names
neither, so it reads for no product the block is not about.

Cosmetic: under `--no-locus-spread`, a question naming a product printed `LOCUS_SUBJECT` as
"what a reserved slot is filled from", and one naming nothing that "a reserved slot is filled
from LOCUS_ELIGIBLE", beside `LOCUS_SPREAD: off`; both now say the spread is off and no slot is
reserved.

`tests/test_subject_tiers.py` holds the integrity block out of the product and vendor tiers on
"Ivanti Connect Secure", "Pulse Connect Secure" and "Ivanti", taken on `other-entry` and naming
the Citrix entry, with the record's tunnel-client block kept: the first test here of a false
keep. It also holds a synthetic block taken for a class word in its path and kept for the same
word in its logic, and, over every campaign entry that resolves to a product, every class word
a kept block cites to its logic or caveat. `tests/test_locus_axis.py` holds the `LOCUS_SUBJECT`
wording with the spread off, and `tests/test_citation_support.py` the caveat. Each fails on the
code and corpus before this change. Left, with the reason: the Windows share block on "Linux"
(not done, above), and the IIS exclusion block on Nacos and Zimbra, which the change below
takes.

NO CAMPAIGN BLOCK KEEPS A NAMING TIER BY DEFAULT. The third review of the R2-quota-tiers batch
failed it on the default the changes above left in place: a block naming none of the record's
products and carrying no identifier kept the product or vendor tier, as "the campaign as it
reached them all, yours among them". For a block tied to another entry's platform that was
false, and it reached the top of real answers. Re-run with `--today 2026-09-30`: "Synacor
Zimbra Collaboration Suite (ZCS)" had `MATCH_TIERS` product=3, all from the web-server
campaign -- an antivirus exclusion for IIS's module directory (`inetsrv`), the ASP.NET
ViewState block and a block that is not a detection -- and "Alibaba Nacos" the first two at
ranks 2 and 3. "VMware ESXi" took shadow-copy deletion (`vssadmin.exe`), domain account
creation and LDAP share enumeration at product tier, none of them in its top 12 before the
batch. "SonicWall firewall" kept the enclave-mapping block at vendor tier saying it named none
of the record's entries, when it names "cloud storage and network backups", two of them.

The decision is now written as a table above `BlockScope` in `consult.py`, first row that
holds, and no row keeps a block by default. A block keeps the tier where it names what was
asked, carries its identifier, or reads in its own sentences for a class of it (as before); as
the record's only block, now only where the pattern it cites is written for a class of what
was asked; where nothing else the record lists reads as a product, a vendor or a class
(`sole-product`: the forge-token record lists GitHub beside "personal access tokens" and
"private source repositories"); or by kind, where the pattern it cites is written for a class
of what was asked and for no other kind the record's other entries hold (`kind`: domain
account creation on "Microsoft Active Directory", beside Windows estates and ESXi; the BadIIS
block on "Microsoft IIS"; the build-log block on "GitHub Actions"; the tunnelling client on
"Cloudflare Tunnel"). An entry's kind is the classes its own words resolve, so the record-
derived `badiis` pair no longer makes the Telerik library a web server, and a class of what was
asked is not another kind: other manufacturers' PLCs beside Siemens's, or "CI/CD runners"
beside GitHub Actions. A block whose markers commit to another platform than the asked
product's, read by `query.py`'s classifier against the `platform_of` table and the entries'
own words, keeps nothing by kind, only-block or `sole-product`, and an entry on another
platform counts as another kind unless the block's markers commit to the asked one: on "Linux"
the hive record's shadow-copy block falls, saying its markers are written for windows and
Linux runs on linux. Every other block falls, as `silent` where it gives no reading either way,
and says what it names and carries, the classes its own sentences missed, what its pattern is
written for, which of the record's other entries hold that kind, and the platform its markers
commit to: `this block concerns the campaign, not it` or, where the pattern is also written for
the asked kind, `... and does not single it out from the other products the record lists`. An
entry naming no product is now named by its own words whatever it resolves, except one whose
every class is one of what was asked, so the enclave-mapping block falls on `other-entry`.

Where every block of the campaign records naming what was asked fell, the answer is class-level
or vendor-level, and its `RESOLUTION` said no observation names the product when one does.
`mode_counts()` now counts those records, and `RESOLUTION` and `CLASS_LEVEL_WARNING` say no
observation is about it, `(1 campaign record(s) list it among what a campaign reached, and
every block of theirs concerns another product or the campaign, as MATCH_BASIS says)`. Each
mode keeps the start of its line.

Measured with `block_scope()` itself over the 2,266 alias questions the review swept, 825 of
which a campaign record's entry names, as the product and as the vendor: of 7,730
question-block pairs, 3,233 leave the naming tiers (3,202 `silent`, 30 `other-entry`, and the
npm worm's only block on "GitHub", which resolves no class for its pattern to be written for),
72 blocks between them; 919 that kept the tier by default now keep it on a stated reading (517
`kind`, 402 `sole-product`); no pair gains a tier, and every pair decided by name, identifier
or class before is decided the same way. Through `consult.py` with
`--no-locus-spread --limit 2000`, over the review's 128 product questions and 33 more vendor
and probe questions, 524 findings on 108 questions move down (466 to the class, 58 to a name
fragment) and none moves up. "Synacor Zimbra Collaboration Suite (ZCS)", under three of its
names, becomes `CLASS-LEVEL (inferred)` saying its campaign record lists it, and "NETGEAR"
`NAME_WITHOUT_OBSERVATIONS` saying the same. "Fortinet FortiGate", "PAN-OS", "Ivanti EPMM",
"Check Point firewall", "Okta", "Cisco ASA" and "network firewall" print exactly what they
printed before; "Fortinet" changes one `MATCH_BASIS` line, the edge-appliance block now kept by
kind; and `advise.py --attack T1190 --no-verify` is unchanged. On "VMware ESXi" every
product-tier finding names ESXi or reads for its class, and "Microsoft Exchange" keeps the
AA22-257A record's ProxyShell block and takes its Log4j, FortiOS and ransom-operations blocks.

`tests/test_subject_tiers.py` holds the review's eight blocks out of the naming tiers on
Zimbra, Nacos and ESXi, each saying it concerns the campaign and, for the Windows ones, that
its markers are written for windows; Zimbra's `RESOLUTION` and warning to its campaign record;
the other direction, three blocks about what was asked kept by kind; the shadow-copy block out
of "Linux" for its platform; the enclave-mapping block taken for the entries it names; and,
over every campaign entry resolving to a product and every vendor such an entry names, a block
kept only on a reading in `KEEPING_RULES` and never on its pattern where its markers commit to
another platform. The `block_scope()` unit test holds every row of the table but
`shared-class` on a synthetic record. Each fails on the code before this change. The tests the change above wrote for its
default now hold the new one: the AA22-257A ransom-operations block, the ESXi
directory-enumeration block and the Telerik ViewState block fall, the forge-token and BadIIS
blocks keep the tier as `sole-product` and `kind`, and the access-resale record's resale block
keeps it on Connect Secure by kind where the tunnel client no longer does. Left, with the
reason: a block about what was asked by a reading no table here makes, and the class word the
near-word gate refuses (not done, above).

THREE PLACES A RECORD'S FIRST-LISTED CLASS OUTRANKED WHAT THE BLOCK SAYS. Batch R3-locus of the
third validation (20 probes, 2026-10-01): three major defects in plane placement, from the
contract, planes-cloud and locus-consistency probes, each re-run from its probe before anything
changed. None reverses a standing decision: LOCUS is six values, a control plane is the network
sense and a cloud administrative API is MANAGEMENT, handsets stay out and `app.mdm` stays on
MANAGEMENT in `by_class`, the raw-dataset correlation prohibition stays retired, and a generated
exposure's surface is still not read; the 894 exposures place exactly as before.

A library pattern read only its classes. `locus_for()` switched the operation tier off when no
record was given, so `pat-mailbox-delegation-or-role-granted`, whose one live test is an Exchange
role or permission grant and whose own logic calls the grant an administrative operation,
derived DATA from `server.mail` while the block citing it sat on MANAGEMENT through that tier.
`advise.py` then printed MANAGEMENT under `LOCUS_ABSENT` for a selection holding a role-grant
detection, and SKILL.md's rule 9 forbids the answering model to move it. A pattern placed with no
record now has its own `markers`, `rule_shape` and `evidence_type` read where a block's would be,
as its `applies_to_classes` already stood in for a `product_class`; a record's block is still read
with its own markers only, so `validate.py` and `consult.py` agree block by block as before. Seven
patterns move onto MANAGEMENT by the operation tier: the role grant, bulk mailbox access and
forwarding rules, a new federation trust, a password reset completed on a dormant account, model
enumeration and inference on a stolen key, a network function instantiated outside orchestration,
and build pipeline changes, which keeps SUPPLY as the span its citing block observes.
`pat-mail-item-property-scan` would have been an eighth, on the mailbox audit actions `Update`
and `UpdateInboxRules` beside `MailItemsAccessed`, and declares DATA with its `locus_reason`
instead: what it sweeps is properties of mail held, and the actions only locate the items. That
is the first declared pattern locus that is not a device's administration, and the reference and
`corpus/README.md` say so. The `advise.py` CONTRACT line says LOCUS comes from the pattern's
classes or its own markers, shape and evidence.

An administrative API class placed blocks that never read it. `cloud.iaas` is defined as an
infrastructure-as-a-service administrative API and console, and an AWS record listing it first
put every block on MANAGEMENT through `class_first`: a certificate issued for an owned hostname,
read from DNS and TLS metadata (`obs-amazon-elastic-ip-released-while-dns-still-points-at-it`,
how1), and a workload's sustained traffic to a mining pool, read from flow and DNS records
(`obs-amazon-cryptojacking-spread-across-uncommon-services`, how2). The AWS answer then printed
`LOCUS_ABSENT: DATA, ENDPOINT, ORGANISATION` with both findings in the match set, and
`references/locus-and-coverage.md` itself names mining-pool traffic on MANAGEMENT as a reason to
reject a design. A new tier, `admin_api_unread`, after `operation` and before `class_first`,
places a block by its evidence where its first-listed class is in the new
`administrative_api_classes` list, it carries no `cloud_operation` marker, and its deciding
evidence reads one locus that is neither the class's nor posture. Reading the API in any form
keeps the class: `cloud_audit` or `config_diff`, an operation marker beside other typed markers,
or the provider's inventory. `auth_log` is not taken as the API, because an IaaS provider writes a
console sign-in to its audit trail, which is `cloud_audit`. The new `contested_evidence` list,
`process_telemetry` alone, is left out of this test and the posture test below: the locus map
already documents its mapping as contested and says it never decides a primary, and read as
CONTROL it held the miner's pool traffic, whose process name is typed `process_telemetry`, on
MANAGEMENT. As a span source it is read as before. Two blocks move, both to DATA; on "AWS" DATA
now holds two eligible findings, both shown, and `LOCUS_ABSENT` reads `ENDPOINT, ORGANISATION`.
`cloud.identity` is defined the same way and is deliberately not listed: `_arguable_classes`
keeps it on MANAGEMENT against `identity.sso` on CONTROL, a tenant sign-in read from `auth_log`
is often the administrative credential's own use, and listing it would move four blocks (an
authentication-failure burst and a VPN scanning block to CONTROL, and two mail-delivery blocks on
the AWS console-phishing record to DATA). The locus map gives the reason and the four blocks.

A posture question could not reach ORGANISATION. The `shape` tier, an inventory-shaped block
with nothing else to go on, sat after `class_first` and fired on none of 770 blocks, 894
exposures and 475 patterns, the condition that had the evidence tier deleted, while `tier_order`
and the reference still advertised it. So the known-exploited catalogue join
(`obs-generic-broad-known-vulnerability-harvesting`, how0), reading only `vuln_scan` and
`asset_inventory` and captioned "a vulnerability management process, not a detection", printed
DATA from the web server its record lists first; its pattern's 13 citing blocks sat on five loci
by the order their records listed classes; and at validation the copy on a web-server-first
record filled the reserved DATA slot on five of the fourteen product questions sampled. A
new tier, `posture`, after `class_nonproduct` and before `surface`, places on ORGANISATION a
block whose `rule_shape` is `inventory` and whose deciding evidence reads only posture, which is
the vocabulary's "inventory or advice question rather than an event located on a device". Shape
alone still decides nothing, nor does posture evidence beside any other type, so the reason the
shape tier was kept below class, that the shape is a mode and promoted alone would swallow SUPPLY
and MANAGEMENT, still holds and is kept in `_why_posture`. It outranks a non-supply surface,
because a posture question about the way in is still a posture question, and that surface
travels as its span; a supply surface that reaches the block still outranks it, so the
managed-service-provider contract question stays SUPPLY. Of 267 inventory-shaped blocks, 67 read
only posture; `posture` places 64 (29 from CONTROL, 12 from DATA, 12 from ENDPOINT, 9 from
MANAGEMENT, 2 from SUPPLY), two sit on records listing a non-product class first and were
ORGANISATION already, and one is the supply case. The two SUPPLY blocks, Log4j's embedded-library
inventory and TeamCity's patch posture, keep SUPPLY as their span from a unanimous class list.
The EPMM record's patch-posture block moves with them; every EPMM detection block stays on
MANAGEMENT and none reaches ENDPOINT. The `shape` tier is removed; `default` stays as the floor for
an input with no mapped class, which `validate.py` refuses, and is the one tier the shipped corpus
never reaches. On "Fortinet FortiGate" `LOCUS_ABSENT` now reads `DATA, SUPPLY` (DATA: matched 0,
span-only 11) and `LOCUS_ANALOGUE_ONLY` names ENDPOINT and ORGANISATION, the seven catalogue and
end-of-life class analogues; it named DATA and ENDPOINT, and ORGANISATION absent.

Ten library patterns stated no `rule_shape`, so `posture` could place each citing block and not
the pattern: `advise.py` printed the catalogue join on DATA while all 13 of its citing blocks sat
on ORGANISATION. Each now states `rule_shape: inventory`, on its own logic and on its citing
blocks, every one of which that states a shape says `inventory`: the annual exploited-list review,
end-of-life devices with a reachable management interface, end-of-life versions with a live
vulnerability, the catalogue join, leak-site monitoring, exposed assets sorted by their oldest
unpatched flaw, out-of-band log aggregation, hunt risk findings without compromise, shared-service
dependency and the untested incident response plan. None cites a source for its shape; nothing
sourced changed. Twenty-four patterns move onto ORGANISATION by `posture`.

Over 770 how-blocks the distribution moves from CONTROL 243, MANAGEMENT 164, DATA 91, ENDPOINT
194, SUPPLY 53, ORGANISATION 25, with 391 carrying a span, to CONTROL 214, MANAGEMENT 153, DATA 81,
ENDPOINT 182, SUPPLY 51, ORGANISATION 89, with 360; ORGANISATION stays fourth of six. Blocks
placed without their record's surface fall from 50 to 44, the six being posture blocks now placed
before the surface is asked. `validate.py`'s per-block line counts both new tiers, and it refuses
an `administrative_api_classes` entry that `by_class` does not place on MANAGEMENT or that is a
non-product class, and a `contested_evidence` entry `by_evidence` does not map or that is
deferred. The locus map's `_tiers`, `_why_no_evidence_tier`, `_why_not_markers`,
`_why_non_administrative_operations` and `_note_process_telemetry` say what changed, and
`_why_shape_is_last` is replaced by `_why_posture`. `references/locus-and-coverage.md` states the
new ladder, distribution and per-block counts, and its span section no longer says the
question-free tools print the second value a consultation prints: where a record has no span of
its own they print the primary alone and the consultation's second value is the question's class,
as the KEV-harvest join on a firewall question now shows (locus-consistency, cosmetic).

`tests/test_locus_block_tiers.py` holds each major on the record or pattern its probe named and
on a synthetic input carrying only what the ladder reads: the role-grant pattern on MANAGEMENT by
`operation` and every pattern testing only administrative operations with it, the advise run's
`LOCUS_RETURNED` and `LOCUS_ABSENT`, the two AWS blocks on DATA and the miner's other two on
MANAGEMENT, "AWS" no longer naming DATA absent, the harvest join and every copy of it on
ORGANISATION, the pattern shapes, FortiGate printing the join by `posture`, `validate.py`
refusing the two lists' bad entries, and every tier but the floor deciding something. Each fails
on the code before this change but one, which pins that a record's block still never reads its
pattern's markers. Tests that pinned the old placement now hold the new one, each saying why: the
harvest join's span and on-screen LOCUS, the Siemens exploit-development posture block, the
Siemens vendor question's loci, the miner's pool traffic, the AWS supply-surface synthetic, the
firewall analogue-only loci, the Zorblax filler loci and `advise.py`'s pattern derivation.

Left, with the reason. planes-cloud minor 1, the mail-delivery blocks held off DATA on the AWS
console-phishing record: two of the four blocks `cloud.identity` would move, which is a decision
of its own. contract minor 6, the container escape that cannot show ENDPOINT: the span sources
are unchanged and still read `process_telemetry`, and taking contested evidence out of the span
too would change the evidence signal on twenty-two blocks outside this batch. locus-consistency minor 1, the
enclave-mapping block citing a documentation-reading pattern: a pattern attribution on a
hand-written record, outside the ladder. Minor 2, a multi-CVE exposure placed by its first class:
generated records, placed by class as decided. Minor 3, sibling appliance-integrity patterns on
CONTROL beside a declared MANAGEMENT boot-image one: the contract probe's judge read those two on
CONTROL as correct in the network sense, so the two judges disagree and neither is taken here.
Two posture-only blocks state no `rule_shape` (the OpenWrt LuCI inventory and the Lantronix
patch-diff timing block) and stay where their class puts them until an author states it.

WHAT TO DO ONCE FOUND, A FILTER THAT CANNOT MATCH, AND A REVOKED PARENT'S FAMILY. Batch R4 of
the third validation (20 probes, 2026-10-01): the three major defects left in `advise.py` and
`emit_xql.py`, from the d3fend, emit-xql and revoked-and-family probes, each re-run from its
probe before anything changed, then the minor and cosmetic defects in the same areas where the
change was small. No standing decision moves: six loci, network-sense CONTROL with a cloud
administrative API on MANAGEMENT, handsets out and `app.mdm` on MANAGEMENT, the raw-dataset
correlation prohibition retired, and a generated exposure's surface unread.

The eviction advice was to reboot the host. Within a tactic and grade the countermeasure order
was D3FEND's name order, so Host Reboot and Host Shutdown, which D3FEND maps to every
process-level technique through the same relation as Process Termination ("terminates
Process"), headed the Evict entries: over all 475 patterns Host Reboot was shown 38 times and
Host Shutdown 18, Process Suspension and Process Termination never, and the LSASS answer told a
responder to reboot or shut down the one host whose memory they collect first. Within a tactic
the order is now the control's fit to the finding: a direct mapping before an inferred one, then
the control more of the finding's cited techniques reach, then one acting on the artefact before
one D3FEND defines as acting on the whole host, and only then D3FEND's order. The D3FEND harvest
(`_ingest/d3fend/harvest.py`, outside the bundle) names the host-wide controls in `HOST_WIDE`
with the words of each one's definition ("terminate all running processes"), refuses a
definition that stops saying so, writes them as `host_wide` and orders each `by_attack` list the
same way; 22 of 412 lists reorder, and only those four controls move. Over all 475 patterns Host
Reboot and Host Shutdown are now shown 0 times, Process Suspension 38 and Process Termination 18,
and for T1003.001 the Evict pair is Process Suspension and Process Termination with both host
controls in `NOT_SHOWN`. Ordering by how few ATT&CK ids a control answers was measured as a
measure of specificity and rejected: it put Web Session Access Mediation, which reaches LSASS
memory only through the authentication service, at the head of the Isolate entries. The header
says what the order is, and no longer drops its verb ("6 of the 6 shown are direct, as are 12 of
the 20 reached"; d3fend cosmetic). A cited parent D3FEND does not map, whose sub-techniques it
does, now names them and says they are not joined, rather than reporting a gap in D3FEND over
T1542 while T1542.004 and T1542.005, the network-device boot persistence the pattern is about,
are mapped (contract minor 2).

A skeleton marked complete tested words no source writes. `event_type` and `zone` markers held
the corpus's own words, `integrity_check`, `group_create`, `account_create`, `file_create`, `dmz`,
`internal`, and the emitter printed them as live literals, so six `fidelity=alert` blocks marked
`filter=complete` (the FortiOS and GlobalProtect integrity checks, the ESXi group, the CLFS
account creation, the web-server file drop and the DMZ reachability block) could never match and
returned nothing on a tenant, which reads as a true negative. `vocab.json` now lists
`normalised_marker_types` (`event_type`, `zone`), the observation schema takes `normalised:
true` on such a marker, and `vocab.json` no longer defines `event_type` as normalised. 26 markers
carry the flag, 17 `event_type` and 9 `zone`, on 17 record blocks and 8 patterns; the
`OPERATION_TYPE` members and `git.clone` stay literals. The emitter prints a flagged marker as
`// REQUIRES (normalised, not a source literal): <field> = "<word>"` with the field to bind, never
as a live clause, and the JSON binding has status `normalised` and the would-be clause under
`requires`. `validate.py` refuses the flag on another type and on an XDM_CONST field, refuses an
unflagged marker holding a word another marker flags, and counts the flags. Seven blocks leave
`complete`, six of them at alert: the skeleton gives 68 complete, 243 partial and 392 none, at
alert 54, 199 and 173, from 75, 247, 381 and 60, 203, 163, and prints 458 live clause lines,
from 477; the reference, which still said 479, says 458 (emit-xql cosmetic 5). Under `combine: any` an
alternative left with no field test is now named rather than silently absent, and a labelled
sequence names every event, live or not. A cloud console action bound to `xdm.event.type`,
`ConsoleLogin` on the AWS cloned-sign-in block, is a `cloud_operation` on
`xdm.event.original_event_type`, as `corpus/README.md` requires; the block stays on MANAGEMENT,
now through the operation tier, which places 18 blocks (emit-xql minor 1). `emit_xql.py` refuses
a target beside `--all` instead of narrowing to the target silently (emit-xql cosmetic 4).

A revoked parent lost a third of its family. `advise.py` followed a revoked id to MITRE's
replacement and stopped there, so `--attack T1562` returned the 20 patterns citing T1685 and said
nothing of the 11 others in its family, among them event-log clearing, the host and cloud
firewall changes and the cloud audit coverage audit. A followed replacement is now answered as
`--attack <replacement>` would be, so a live parent reaches its sub-techniques, and a revoked
parent's own revoked sub-techniques are followed to theirs: its family read in the taxonomy the
id came from. `--attack T1562` returns 31 patterns and `--attack T1562.001` 28, each labelled by
what it cites, with the new basis `selected by T1685.005, a sub-technique of T1685, MITRE's
replacement for revoked T1562`. `SELECTED_BY` counts that route in a fourth column,
`ATTACK_REQUESTED` breaks a followed id down by route, `--attack-exact` follows the replacement
alone and says what it did not follow, and `ATTACK_RECORD_ONLY` covers the same reach. A parent's
`ATTACK_RECORD_ONLY` line names the ids its blocks actually cite, as T1003 and T1003.001, where
it said they all "cite it" (revoked-and-family minor 2).

Fixed in passing, each small. A date held to the year or the month (ten records) printed
"undated", sorted last and ranked as 3,650 days old; `consult.published()` reads it as the first
day it names and `advise.py` prints it as held (d3fend minor 3, contract minor 4,
revoked-and-family minor 3). `query.py --json` printed `tiebreak.published` as `2026-08-00`, a
date no parser reads, and consult's `EXPOSURE_ORDER_BASIS` printed the same padding; both print
the date as held (query-kev-growth cosmetic 6). A pattern stating no `rule_shape` says what its
citing blocks state after the word `unstated` (d3fend cosmetic 4); that 107 patterns state none
is left for their authors (advise-shape minor 3). An
uncited pattern's `OBSERVED` line names its `derived_from`, as consult's `LIBRARY_MATCH` does
(advise-attack-id minor 1). The `advise.py` CONTRACT says `LOCUS_OBSERVED` counts citing
how-blocks and no longer names a `SOURCE_DISCLOSURE` key nothing prints (advise-shape cosmetic 5,
contract cosmetic 9). `--have T1486` in `advise.py` names `consult.py --covered` beside
`--attack` (coverage cosmetic 6).

Every major has a test that fails on the code before this change and passes after:
`tests/test_advise_findings.py` holds the host-wide rule over every pattern, the LSASS Evict pair
and the reach order on a synthetic table; `tests/test_attack_reference.py` the harvest's
`host_wide` list and each list's order; `tests/test_emit_syntax.py` that every unflagged
`event_type` is a known source literal and no zone is unflagged, that no flagged marker is a live
clause and no block holding one is complete, the four probe blocks, the binding, the JSON row and
the three refusals; `tests/test_advise_selection.py` the T1562 family against the reference, the
replacement's sub-techniques for T1562.001, `--attack-exact` and the record-only ids. The minor
fixes carry their own tests. Tests that pinned the old output now hold the new one, each saying
why. 2,235 tests pass, 2 skipped; `validate.py` reports no problems; `SOURCES.md` is current.

Left, with the reason. d3fend minor 1 and advise-shape minor 2, response doctrine ranking a rule
borrowed from a citing incident's impact above the always-on rule that fits: an ordering decision
for the doctrine file, not the countermeasure join. d3fend minor 2, countermeasures chosen
without the pattern's classes or locus: a filter D3FEND gives nothing to drive. d3fend cosmetic
5, a pattern's logic saying "control plane" in the cloud sense, and revoked-and-family minor 1,
that pattern on CONTROL: the record citing it uses the phrase too, and moving the pattern is a
plane judgement on a block whose main signal is consumption, not administration. d3fend cosmetic
6, a revoked join's `| direct` meaning direct to the predecessor: the line's last field is parsed
as the grade. emit-xql minors 2 and 3, a runtime host detection on its record's product plane and
`fidelity=alert` blocks shaped `inventory`: content and plane judgements on hand-written records.
revoked-and-family minor 4, an observed span from a record's first-listed class: the ladder's.
Every minor and cosmetic defect of the round still reproducible is in the maintainer's TODO.

THE THIRD VALIDATION, CLOSED. The third validation put 20 probes to this release on 2026-10-01:
10 passed and 10 came back degraded, with 13 major, 99 minor and 44 cosmetic defects. Batches R1
to R4 fixed 12 of the 13 majors, each with a test that failed before it: the citation that did
not carry its CVE, the reserved slots filled by analogues, the multi-product catalogue record
tiered away from its product, the exposure's detection claim made per identifier, the campaign
blocks taken for a name they mention, the library pattern, administrative-class and posture
placements, the eviction order, the normalised event words and the revoked family. The
thirteenth, the 2025 ASA and FTD campaign with no observation, is a collection pass and stays
with the maintainer. Of the 143 minor and cosmetic defects, 23 no longer reproduce after the four
batches (14 of them fixed in R4); the other 120, re-run on 2026-10-01 against this branch, are
listed one per line, with probe and place, in the maintainer's TODO under "Left after the 0.43.0
validation".

## 0.42.0

152 PATTERNS SAID NO PUBLIC RULE LIBRARY SHIPS THEIR SHAPE, AND FOR EVERY ONE OF THEM THAT WAS
UNTRUE. Corroboration is a separate maintainer pass. It was last run on 2026-07-31, so every
pattern added after that date carried no `external_corroboration` block, and `advise.py` printed
"CORROBORATED: no - no public rule library ships this shape" over patterns whose techniques
hundreds of Sigma and Splunk rules implement. `corpus/README.md` admitted the pass had not been
run since. Re-running it against the rule index that was already held, before any upgrade, changed
156 patterns:
- 152 gained a block they should always have had.
- 4 moved because an earlier ATT&CK id migration had renamed their techniques and the join was
  never re-run. One pattern was still counting rules for T1562, an id it no longer cites.

SPLUNK SECURITY_CONTENT IS NOW V6.7.0, AND IT WAS NEVER V6.5.0. The maintainer-side record said the
corpus was built against v6.5.0. The rule checkout was in fact a development commit from
2026-07-29, 31 commits before the v6.5.0 tag. It is now the v6.7.0 tag itself, so the next upgrade
diffs from a named release. v6.7.0 has 2,176 detections against 2,117, and 9 technique ids appear
in Splunk's tags for the first time. SigmaHQ is unchanged.

A RULE THAT STILL TAGS A REVOKED ATT&CK ID NOW COUNTS FOR ITS REPLACEMENT. Rule libraries lag
ATT&CK. The corpus migrates a revoked id to ATT&CK's own replacement, so a rule still tagging the
old id is corroboration for the new one. Before this release it was silently dropped. Three
Splunk detections carry four tags on T1562, T1574.002 or T1070.001, and 25 patterns gain one or
two rules from them.

A RULE NOW COUNTS ONCE PER PATTERN. The count was a sum over the pattern's techniques, so a
rule tagging two of them counted twice, and "N rules" overstated N for 186 patterns, by up to 65.
It is now the number of distinct rules. The 6 detections v6.7.0 moved to deprecated are not
counted, migrations follow ATT&CK's revocation chains to the end, and a missing migration map
stops the run rather than silently counting without it. A block now names only the libraries
that contributed: 12 had named Splunk with a count of zero. `advise.py` says what the number
measures: rules that tag a technique the pattern cites, not rules that ship its shape.
`tests/test_external_corroboration.py` fails when a block disagrees with its pattern. Against
the 0.41.0 corpus it fails on the stale and missing blocks this release fixes.

The result is that 444 of 475 patterns carry corroboration, against 292 before. 31 carry none, and
22 of those 31 apply to an `ot.*` class. That restores the finding the July pass made: the public
rule corpora cover operational technology barely at all. The 0.40 prose, "41 of the 183", said the
opposite, and was an artefact of the stale blocks. Counts remain per technique, not per detection
shape, and that caveat stands as written. 759 tests pass, 446 of them the new per-block check,
and the validator is clean.

## 0.41.0

TWELVE CLASS CORRECTIONS THAT 0.38.0 SILENTLY UNDID ARE BACK, AND THIS TIME THEY ARE IN THE
GENERATOR. 0.26.0 moved the two EPMM records to app.mdm and gave MobileIron and Workspace One UEM
the class beside the one they had. Two later releases moved Ivanti Endpoint Manager, its Cloud
Service Appliance and LANSCOPE to app.rmm, and moved Sophos SFOS, CyberoamOS, SG UTM, Web
Appliance and Symantec Messaging Gateway out of security.edr. Every one of those corrections went
into the corpus and the alias table, and none into the classifier that generates these records. The
0.38.0 catalogue regeneration therefore put all twelve back. It printed nothing, and every test
passed, because no test named any of the twelve records. From then on an EPMM question pointed at
the ENDPOINT plane again, which is the one plane the handset rule declines to advise on.

The twelve are now explicit pairs in the classifier, so the next regeneration reproduces them.
The classifier can now carry two classes where a product genuinely has two. The generated tag
and attack surface now follow the corrected class as well, which the hand fixes never did: SFOS
was still tagged `security-edr` with a `local_network` surface. The root cause is gone too. An
EDR keyword matched "endpoint manager" ahead of the rule that already sends endpoint managers to
app.rmm, so the next product with that name will not arrive wrong. `test_generated_classes.py`
pins all twelve records. It fails on 23 of its 24 cases against the 0.40.2 corpus.

THE KEV AND ZDI DELTAS ARE TAKEN. The corpus goes from 1,151 to 1,158 records. All seven new
records are exposures, so observations (247), patterns (475) and every locus and marker figure are
unchanged. The KEV catalogue moves from 2026.09.11 to 2026.09.24, and from 1,709 to 1,723
identifiers:
- Five new records: Acronis Backup, Check Point Multiple Products, Cisco Secure Email Gateway, F5
  BIG-IP APM and Zyxel GS1900.
- Eight identifiers added across six records already held.
- One record changed only because CISA moved a TeamCity identifier's ransomware flag from Unknown
  to Known.

Every KEV record's source now names the 2026.09.24 catalogue. That is why all 709 KEV records sit
on changed lines although only five are new: the diff is a restamp, not a rewrite.

The Zero Day Initiative advisories ZDI-26-680 to ZDI-26-719 are also taken:
- Two new records: Cisco ThousandEyes and Linux Mint Xreader.
- 23 identifiers added across four held records.
- Microsoft Windows goes from 39 advisories to 40, and the new one is a 0-day.
- Three NoMachine advisories were not taken. The product has no class, and an unclassified pair
  is dropped rather than defaulted. Whether it belongs under remote access is an open scope
  question, not a gap.

Zyxel GS1900 first arrived as network.router. The switch keyword did not match the plural
"Switches", so the Zyxel vendor default decided. The keyword now takes the plural, which moves
no other pair in the catalogue. The ZDI generator was still writing attribution_confidence "low"
on records that name no actor, which the corpus had already corrected by hand. It now writes
"none", so the 65 ZDI records already held kept their corrected value, and the two new ones
arrived with it.

THE 2026-09-20 FRAMEWORK UPGRADES ARE RECORDED, BECAUSE THEY SHIPPED IN THE CORPUS WITHOUT A
RELEASE. ATT&CK 19.1 to 19.2 left the technique inventory identical across all three domains. The
work that was actually owed was migrating three revoked ids to ATT&CK's own replacements, which
changed 18 citations: T1562.001 to T1685, T1574.002 to T1574.001, and T1656 to T1684.001. D3FEND
1.5.0 to 1.6.0 is three upstream typo corrections, with 272 countermeasures before and after. The
MIT Licence text travels in the file, as the licence requires.

SKILL.md, README.md and corpus/README.md all still said ATT&CK 19.1 and D3FEND 1.5.0, and
README's licence attribution said so too. They now say 19.2 and 1.6.0. D3FEND coverage of the
cited technique ids, measured again after the migration, is 210 of 407, not 212 of 410. The worked
query example in SKILL.md was re-run: Cisco firewall exposures are now 94, up from 88.

THE URL LIVENESS CACHE WAS RE-CHECKED. 283 of its 292 URLs answered live on 2026-09-25. Nine
Sysdig URLs failed in transport and keep their earlier verdict, because a network failure is not a
statement about the source.

## 0.40.2

39 CITATIONS NOW CARRY THE TITLE THE PUBLISHER GAVE THE ARTICLE. The shipped citation rule says a
public source carries a real URL a reader can open and its own title; a paraphrased title is the
shape reserved for restricted sources, where abstraction is a licence condition. 39 public records
carried a paraphrase instead -- "watchTowr Labs research on recurring memory disclosure in Citrix
NetScaler" where the article is called "How Much More Must We Bleed? - Citrix NetScaler Memory
Disclosure (CitrixBleed 2 CVE-2025-5777)". A reader checking a citation found the right article
under a description rather than its name.

EVERY TITLE WAS FETCHED AND THEN SOMEBODY TRIED TO BREAK IT. One reader took the headline off the
page; a second re-fetched the same URL and compared the proposal to the publisher's wording
character by character. All 39 survived, five were spot-checked again by hand, and only site
furniture was stripped -- a trailing " | Mandiant" or " | Sysdig". Colon-subtitles, bracketed
qualifiers and CVE identifiers in a headline are title text and were kept.

ONE OF THE 40 CANDIDATES NEEDED NO CHANGE. "AppleJeus: Analysis of North Korea's Cryptocurrency
Malware" is a real title that reads like a paraphrase, and the pass was built to be able to say so
rather than to improve everything it was pointed at.

## 0.40.1

THE 34 COSMETIC FINDINGS FROM THE PRE-PUBLICATION AUDIT, SWEPT. None of them would have misled a
reader into a wrong action, which is why they were graded below the blocking three; several were
still wrong in ways a stranger could check in one command.

GENERATED PROSE HAD TWO GRAMMATICAL FAULTS AND ONE FALSE PRECISION. 74 records read "1 of these
identifier is already carried", a singular determiner against a noun that should have stayed
plural. 49 read "added to it in 2021 and 2026" about identifiers added across six separate years,
which states two dates where the truth is a span; they now read "each year from 2021 to 2026", and
the 34 records whose identifiers really were added in exactly two years keep the original wording,
because for them it was never wrong. Both fixed in the generator and the whole set regenerated, so
the cross-reference tags caught up with yesterday's nine observations at the same time.

197 RECORDS ASSERTED LOW CONFIDENCE IN AN ATTRIBUTION THAT DOES NOT EXIST -- `actor_type:
unattributed`, no actors, and `attribution_confidence: low`. The catalogue generator, written
later, already used `none` for exactly that state, so the corpus carried two conventions for one
fact and a consumer could not tell them apart. The 54 records that keep `low` all name an actor
class; their confidence is about something real.

AN UNRECOGNISED --sector SILENTLY FILTERED. `query.py "firewall" --sector notasector` dropped every
record lacking that sector, returned a smaller answer that read like the whole one, and printed
`sectors=-` while the filter was live. It now exits 2 and says where the known values are. Valid
vocabulary values and aliases are unaffected, `cross_sector` included.

A PATTERN WITH NO `rule_shape` PRINTED THE PYTHON LITERAL `None` -- 117 of 475 patterns -- where
the page documents a closed list of shapes. It prints `unstated`.

SEVEN MORE PROSE CLAIMS CORRECTED, each measured: a worked example over 138 records touching four
network classes, one of which does not exist (143 over three); a quoted output header matching no
query the page runs; a RASP measurement of 66 findings (59); a comment in the validator recording
425 of 425 techniques resolving (410); a layout listing four schema files where five ship; two
worked records described as one; a claim that the URL cache is the only file the bundle writes,
when the manifest generator writes `SOURCES.md` on every run without `--check`; and a derived-field
list naming two of three -- `what.attack_surface` is inferred from the derived class and was
declared nowhere.

THE SCHEMA DEMANDED ONE SENTENCE AND 942 OF 1,151 SUMMARIES ARE LONGER. That contract was never
enforced and never could have been without rewriting most of the corpus. It now describes what the
field is actually for -- brevity and plainness, no marketing, no hedging -- rather than a sentence
count nothing checks.

ONE FINDING IS RECORDED RATHER THAN FIXED: 38 public records carry a paraphrase where the citation
rule promises the source's own title. The cache holds the real title for 26 of them, which is what
makes it findable and also what makes a bulk rewrite wrong -- a cached `<title>` carries site
suffixes and taglines. It needs a measured pass, and it is in the maintainer backlog with the
method written down.

## 0.40.0

A PRE-PUBLICATION AUDIT, AND THE THREE THINGS IT FOUND THAT WOULD HAVE SHIPPED. Seven readers went
over this bundle as a stranger would -- every number recomputed, every documented command actually
run, leakage and licensing judged, a cold-start read of the card, and the corpus read as an
outsider -- and each of the 91 findings was then handed to a reader told to refute it. 66 survived:
3 blocking, 29 for review, 34 cosmetic.

THE D3FEND ATTRIBUTION WAS WRONG ABOUT ITS OWN LICENCE. The shipped reference file carried
"(c) 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The
MITRE Corporation", which is ATT&CK's Terms of Use wording, and a note claiming the designation was
verbatim from an upstream LICENSE.txt. D3FEND 1.5.0 ships LICENSE.md, which is the MIT Licence,
"Copyright (c) 2022 The MITRE Corporation" -- there is no LICENSE.txt, and the year was wrong by
four. MIT requires its copyright and permission notices to travel with every copy, so the full text
now ships in the file's own `licence_text`, and the README says so.

THE LICENCE SECTION WAS EXHAUSTIVE BY ITS OWN WORDING AND INCOMPLETE IN FACT. It said "Two shipped
reference files are other people's work" and named the two MITRE files. 36 patterns name
SigmaHQ/sigma (Detection Rule License 1.1) and splunk/security_content (Apache 2.0) in
`derived_from`, and 292 name them in `external_corroboration`. Neither corpus is shipped and no
rule text is reproduced, but derivation is not nothing, and both now appear in the section with
their terms and their counts.

A DOCUMENTED COMMAND HAD NEVER WORKED. `references/answering-another-session.md` told a reader to
run `advise.py --patterns pat-a,pat-b`; those ids do not exist, and the line exits 1 with two
warnings. It now names two real patterns and exits 0.

SEVEN NUMBERS IN SHIPPED PROSE WERE STALE, several by a wide margin: 42 uncorroborated patterns
(183), 689 catalogue-generated exposures (704), a locus distribution over 872 how-blocks (771, with
every value changed), 976 ATT&CK techniques (1,166), D3FEND covering 214 of 396 cited ids (212 of
410), two worked-example finding counts, and a claim that 60% of observations carry no flag (85%).
Each was recomputed from the artefact and each replacement was verified by running the command the
page documents.

The 27-uncited-patterns figure corrected at 0.39.1 was the first of this class to be found; these
are the rest. The lesson is the same one and it is now demonstrated seven more times: a number in
prose has no owner, and the wrong-total check only judges totality claims.

A GENERATED CLASS WAS WRONG ON FOUR FIREWALLS AND ONE BACKUP PRODUCT, and the bundle's own lookup
proved the cost -- `query.py "firewall"` resolves to `network.firewall` and returned none of the
WatchGuard Firebox or Zyxel records, which were classed `network.router`. Arcserve UDP was
`security.siem`. Corrected in the records, in the aliases, and in the generator that derived them,
so the next catalogue refresh does not reintroduce them.

A SHIPPED RECORD EMITTED A FILTER THAT CAN NEVER MATCH: one field ANDed against two different
literals, because a collection target had been recorded as a second indicator. The XQL handoff now
emits one satisfiable clause, and the collection path is stated in the marker's note where it
belongs.

A MISTYPED --covered PATH PRODUCED A CONFIDENT ANSWER COMPUTED AGAINST NOTHING. The argument was
accepted as literal coverage text, so the run exited 0 and reported the filename as one covered
item. A value shaped like a path must now be a path, or the run exits 2.

TWO CLASS ALIASES HAD NO TRIPWIRE AND THE CARD SAID ALL FOUR DID. `ad` and `switch` were not
pinned anywhere, so a class-alias gate landing would have changed them with the suite green -- the
exact outcome the tripwire exists to prevent. Both are now pinned, so the claim is true again. The
rationale beside it was also false: only `network.switch` has no other route into its class, while
the other three keep three or more unambiguous aliases each, verified live. Corrected in all three
places it appeared, including the test docstring that asserted it.

Also documented: where to run the commands from, which no page said, and that `--have` takes a
closed vocabulary that silently matches nothing when a word is not on it.

## 0.39.1

A SHIPPED PAGE STATED 27 UNCITED PATTERNS WHERE THE CORPUS HOLDS 33, and the control that exists
for exactly this class of error does not reach it. `corpus/README.md` explains that some patterns
are cited by no record because they are derived from technique space rather than from an incident,
and gives a figure. The figure was stale and had been for some time -- it is 33 at every commit in
recent history, so the drift predates this week's work and most likely dates to the release that
removed 103 patterns along with the licensed records that were their only citation.

The check added at 0.37 asserts that no shipped page states a corpus TOTAL that is wrong. It
matches totality claims about records -- "the corpus holds N records" -- and a count of a subset
with a property is not one, so this number was never judged. Recorded rather than patched over: the
figure is corrected here, and the gap in the control is noted in the maintainer record.

Found while refusing an article, not while looking for it. The refusal cited the README's sentence
as its authority, which is how the number came to be checked at all.

## 0.39.0

NINE HAND-WRITTEN OBSERVATIONS FROM TWELVE ARTICLES, and the three refusals are the part worth
reading. Each drafted record was handed to two adversarial readers with different jobs -- one
checking every literal against the source, one judging only whether the detection would work if
deployed -- then repaired, then decided by a third reader that had to read the record itself
rather than the reviews. Corpus 1,142 -> 1,151 records, patterns 433 -> 475, how-blocks 693 -> 771.

EVERY REFUSAL FAILED ON EXACTLY ONE AXIS, AND THE TWO READERS DISAGREED IN ALL THREE CASES. The
ChatGPT shared-clipboard record was sourced impeccably and refused on its logic. The Unit 42
pay-per-install record had working logic and failed on sourcing. The Cisco Secure Firewall
Management Center record had, in the deciding reader's words, a detection arm that should not be
touched again -- and was refused anyway. A single reader would have taken all three.

THE FMC REFUSAL IS THE ONE THAT CHANGES HOW THIS SHOULD BE RUN. Its repair pass removed all 11
sourcing findings and all 28 detection findings, verified mechanically rather than from the
reviews. While doing so it INTRODUCED a new false claim: that the article draws only one link
between the reverse shell infrastructure and the implant, when it draws a second under its own
heading -- something the record itself states two blocks away. The sentence did not exist before
the repair. So a repair that fixes two instances of a defect class can plant a third in the fresh
prose it writes, which means a repaired record needs re-reading whole rather than re-checking
against the findings list. That is now the rule.

WHAT THE SURVIVORS CARRY. Detections against a WebDAV loader chain executing a DLL by ordinal, a
browser-injected cryptocurrency theft using a Google-hosted service as command and control, SPIFFE
and SPIRE identity spoofing through cgroup metadata, a Chrome patch-gap chain to browser-process
injection, root-account sign-in attempts sprayed across unrelated tenants, prose that carries a
payload past a model's policy filter, an exploited Switchvox SQL injection, an exploit kit adopted
by multiple state-aligned actors, and a ClickFix chain into native tooling. 42 new patterns, no id
colliding with the corpus or with each other, and every cited URL fetched and confirmed live
before the records were routed -- one of which had to be corrected, the drafting task having been
given a URL that 404s.

## 0.38.0

THE CATALOGUE DELTA WAS TWICE THE REPORTED SIZE, BECAUSE TWO PASSES HAD REPORTED AND NEITHER HAD
INGESTED. The local KEV snapshot sat at 2026.08.21 with 1,674 identifiers while the recon pass
measured its delta against the 1,694 a later pass had seen and not taken, so the figure carried
forward was 15 when the ingest owed 35. Catalogue now 2026.09.11, 1,709 identifiers, 0 removed,
12 net-new exposure records.

THREE VENDOR AND PRODUCT PAIRS HAD NO CLASS AND THE GENERATOR REFUSED TO GUESS, which is the
behaviour worth keeping: an unclassified pair aborts the run rather than defaulting, because a
wrong class surfaces a record on the wrong lookup and quietly pollutes class-level answers.
Starlette takes server.web as the web framework it is, Ajax.NET Professional takes dev.library
beside the .NET Framework, and Kestra takes app.cicd as a job orchestrator in the absence of an
orchestration class. Each is an explicit pair override, not a keyword rule, because all three are
one-off names no rule should learn to guess.

FORENSICTRIAGE IS DELIBERATELY NOT CARRIED. CISA added the field to every catalogue row in
September 2026, 51 of them Yes. It is not taken, on the rule already applied to requiredAction and
dueDate: those are instructions to the agencies the catalogue binds, not properties of the
vulnerability. Every exposure record now says so in its own notes rather than the decision living
only in a maintainer file.

THE ZERO DAY INITIATIVE INGEST COULD NOT TAKE A DELTA WITHOUT DESTROYING HELD IDENTIFIERS, and the
near miss is the reason this release exists in the shape it does. A record here is one vendor and
product pair carrying every identifier published against it, and the router replaces a record by
id -- so generating from a slice emits a thinner record that overwrites the fuller one. Measured
before routing: an 8-record delta would have removed 39 identifiers and taken Microsoft Windows
from 18 to 3. Nothing downstream would have objected; the file is smaller, the records are well
formed, and the validator is content.

The collector now merges into its row store instead of overwriting it, the generator refuses any
record carrying fewer identifiers than the corpus record of the same id, and rows whose identifier
the corpus already holds are no longer dropped -- that last one is why the store could never have
been a superset in the first place. The guard earned itself on its first run by finding a
pre-existing instance nobody had noticed: four advisories share CVE-2026-8037 and all four had
been dropped across two earlier ingests, leaving a Kemp LoadMaster record the store could not
explain.

THE 2026 BACKLOG IS TAKEN. The listing carries 679 advisories, 277 of them in scope; the corpus
held 57 records against the 204 rows an earlier ingest had seen. Taking the year gives 65 records
and 217 identifiers, 0 lost. Most of the gain is in the prose rather than in identifiers: Microsoft
Windows goes from 18 identifiers to 29 but from a record covering a handful of advisories to one
covering 39, with the component sentence for each. Eight further pairs needed a class, every one
taken from what the corpus already gives that product or its nearest sibling rather than decided
afresh.

Corpus 1,121 -> 1,142 records. Exposures 883 -> 904, observations unchanged at 238, patterns
unchanged at 433. The scope alarm on the collector also reads the advisory title now, so the 107
competition entries in the 2026 listing are named as such instead of arriving as unexplained
drops.

## 0.37.1

A TITLE CARRYING AN ATTRIBUTE WAS READ AS AN ABSENT PAGE. The URL-liveness check searched for a
bare `<title>`, so a page serving `<title data-react-helmet="true">` was filed as
DEPRECATED-OR-EMPTY while answering 200 with 162 KB of content. The pattern now accepts attributes
on the open tag, and still requires whitespace before them so that `<titlebar>` is not a title.
Three parametrised cases and one negative case were watched failing first.

THE RECORDED DIAGNOSIS WAS WRONG, AND THE EVIDENCE FOR IT WAS DISAPPEARING. Seven verdicts across
three publishers were known to be wrong and were put down to titles rendered in JavaScript. That
holds for neither survivor: Okta serves the title in the markup it returns to curl. Five of the
seven cleared on their own when Wiz and Elastic changed their own pages, so the count was falling
towards zero while the cause went unfound, and the check would have lied again about the next
publisher to use a helmet library.

THE CACHE IS RE-DERIVED RATHER THAN HAND-EDITED. `corpus/reference/url-liveness.json` is refreshed
by running the bundle's own `liveness()` across all 228 URLs, so what ships is what the shipped tool
produces. Editing the seven entries directly would have been cosmetic and would have hidden the
defect, which is why it was not done when the wrong verdicts were first recorded.

## 0.37.0

THIRD-PARTY MATERIAL SHIPPED UNDER A BLANKET AGPL DECLARATION. Two reference files are MITRE's work
and carry MITRE's notice in their own `attribution` field, but no page a reader opens said so: the
README had no Licence section at all, so the only licensing statement reaching an installer was
this bundle's AGPL. A blanket declaration that silently covers someone else's material is wrong
even when the attribution is present somewhere in the tree, because the person deciding whether to
install reads the README and does not open a 545 KB JSON.

The README now carries a Licence section and names ATT&CK 19.1 and D3FEND 1.5.0 with their notices,
and says the AGPL covers this bundle's own work.

A banner pin of this bundle's own is added, for the same reason as the licence section: the only
pins lived in the harness and skip in a standalone install.

## 0.36.1

THE PRIVATE TREE NEVER SHIPS, AND NOW NEITHER DOES ITS NAME. Ten lines in files that DO ship named
the maintainer-side docs tree or the private content repository -- five changelog entries, two
`_comment` keys in `corpus/schema/aliases.json`, and three test docstrings. The directory was never
at risk; the strings were, and the bundle's own publication sweep classes them BLOCKING under "a
private tree or repository path", so the estate was carrying ten findings its own gate would have
refused had the gate ever read the whole tree instead of a diff.

Each is reworded, not deleted: "the maintainer-side docs tree", "a consuming content-pack session".
Every statement keeps its meaning and loses the identifier, which is the same treatment the
licensed-source lines got at 0.35.0.

ASCII-ONLY IS SATISFIED AS A SIDE EFFECT, AND THE DATA IS UNCHANGED. `aliases.json` carried a
U+202F NARROW NO-BREAK SPACE inside one alias key, the bundle's only non-ASCII byte. Rewriting the
file through `json.dumps(..., ensure_ascii=True)` to redact the two comments emitted it as a
`\u202f` escape, so the file is now pure ASCII while the parsed key is character-for-character what
it was. That distinction matters: a prior review established that REPLACING the character would be
a regression, because the matching alias value and the observation record carry it too and the
lookup depends on the pair agreeing. Nothing here replaces it. Verified by parsing both versions
and comparing every non-comment key.

## 0.36.0

The shared bundle-standard suite gains a resolving arm on
`test_no_instrument_cites_a_path_inside_another_bundle`, which had never matched anything. It
looked for a path prefixed with a bundle's own directory name, and nobody writes those thirty
characters before a filename -- an author writes `references/<page>.md`, which is the same shape
as a path into their own bundle. The new arm RESOLVES instead: a citation shaped like an
in-bundle reference that does not exist here is a path a standalone reader cannot open.

The arm is narrow because a looser one was measured first and would have shipped noise, flagging a
ratio, a URL path, a repository name and eighty-odd `../` links that resolve correctly against
their own directory. Only a bundle-relative prefix or an explicit `../` counts, globs are skipped,
relative links resolve against the citing FILE, and CHANGELOG.md is exempt because this project
does not rewrite history to keep a checker quiet.

A third arm -- refusing a path into the private content repository -- was measured and REFUSED,
with the reason recorded in the test: a private pack and a public one are the same seven
characters followed by a name, so the check would flag legitimate upstream evidence to catch one
line. That trade was already refused once over British English.

The suite stays byte-identical in all five bundles, so all five carry this release.

## 0.35.0

THIRD-PARTY LICENSED INTELLIGENCE NO LONGER SHIPS. 95 observations abstracted from one vendor's OT
intelligence subscription are removed, together with the 103 patterns reachable only from them.
The corpus goes from 1,216 records and 536 patterns to 1,121 and 433. `SOURCES.md` is regenerated
from the corpus, so the publisher disappears from the manifest without anyone editing it.

THE PATTERNS WERE THE POINT, and they were nearly missed. `disclosure: restricted` marked the
observations accurately and gated nothing -- it is a provenance label, not a publish flag. The
observation is a citation wrapper; the PATTERN holds the `logic`, `caveat` and `xql_sketch`
distilled out of the source. `patterns.jsonl` carries no disclosure field at all, so a filter keyed
on the observation's marker would have removed 95 citations and left 103 derivatives standing --
the half with operational value. Our own restricted library had the convention right all along:
all 7 of its patterns carry `derived_from`, and none of the 103 did. The convention existed and
was applied to 7 of 110.

WHAT STAYS, and why it is not an inconsistency. Three records from the estate's OWN restricted
detection library remain, with their 7 patterns. The rule is about WHOSE material it is, not how
sensitive it is: a subscription belongs to whoever pays for it, and abstracting a report does not
make its analysis ours to publish. `tests/test_sources_manifest.py` also asserts that restricted
records exist, so removing ours would have made a real check vacuous.

TWO CHANGELOG LINES REDACTED rather than deleted. A 0.2.0 entry named the commercial subscription
PRODUCT, and a later entry named the vendor while describing a defect. Both were hand-written
release history that no corpus filter, regeneration or test could ever reach -- the failure mode
worth naming, because every automated remedy this bundle has operates on the corpus. They now say
"a licensed OT intelligence subscription" and "a licensed intelligence subscription", which
preserves what happened and drops the identification. This is a redaction and is recorded as one.

TWO CONTROLS ADDED, both watched failing first (LAW N23).
`test_no_third_party_licensed_intelligence_ships` refuses any `licensed_intel` record whose
publisher is not our own library. `test_a_pattern_reachable_only_from_restricted_records_declares_it`
refuses a pattern whose only citations are restricted and which declares no provenance -- the exact
gap that let 103 unmarked derivatives exist.

One dangling cross-reference repaired: `pat-affiliate-model-detection-strategy` listed a removed
pattern in its `xql_sketch`. Validator reports 0 problems, 401/401 techniques resolving, and both
`consult.py` and `advise.py` answer as before.

## 0.34.2

Banners, and one path this bundle should never have cited.

`tests/test_skill_conformance.py` credited its origin by naming a sibling bundle's test file by path. The credit is worth keeping and the path is not: a skill ships alone, and a reader without that sibling installed cannot open it. It now names the bundle in prose.

- Added `references/console-output.md`: the STAGE, ACTION REQUIRED and KEY DECISION banners, with the squirrel, the rules for each and the test for when a banner is due. The page is identical in every instrument bundle and is complete on its own -- nothing on it needs another bundle installed. The art was lifted from the harness's own templates rather than retyped, because a hand-rendered banner loses the squirrel first.
- SKILL.md gains a short pointer at it. The templates stayed out of the card deliberately: they cost 486 words and this card had 171 words of headroom under the standard's ceiling.

## 0.34.1

Conformance with the project-wide bundle standard.

- `corpus/README.md` used five U+00B7 middle dots as separators. The house style is ASCII only, so they are semicolons now.
- SKILL.md now names its current version in prose, as the other bundles do, so a reader scanning the card does not have to parse the frontmatter.

- Added `tests/test_bundle_standard.py`, an identical copy of which every bundle in this project carries and runs. It checks the four required files, the frontmatter keys and their order, the declared name against the directory, the AGPL licence, a CHANGELOG entry for the declared version, the version named in prose, an SPDX header on every source file, ASCII-only text, and a ceiling on the SKILL.md body. The written standard is `references/bundle-standard.md` in `cortex-content-pack-go-again`, and a test there refuses any drift between the copies.
- A British English check was written, measured against every bundle, and rejected before it shipped. The estate is already British and an unrestricted match returns only `otherwise`, `size`, `premise` and the SPDX identifier. A check whose every finding is wrong advice does not ship.

## 0.34.0

0.33.0 shipped frontmatter that does not parse. Aligning with the xdm-author conformance pass
found it in one command.

- **The description broke the YAML.** 0.33.0 rewrote it to read
  `... MITRE ATT&CK: "I run this technology ...`. An unquoted colon-space inside a plain scalar
  makes YAML read a mapping, so the frontmatter stopped parsing **entirely**. It shipped
  because every check in this bundle read SKILL.md as text -- the audit that produced 0.33.0
  worked from the published prose guidance and never ran the enforcement code. It was also
  **1141 characters against a 1024 limit** nothing here measured. Rewritten to 888 characters
  with no colon-space in any plain value.

- **`quick_validate.py` is the authority and this repository had never run it.** It ships with
  the skill-creator plugin and gates `package_skill.py`; prose guidance is advisory and
  enforces nothing. Found by the `cortex-platform-xdm-author` audit of 2026-09-05.
  `tests/test_skill_conformance.py` now **runs that script** when it is present on the machine
  and asserts its only complaint is the declared `version` divergence, and restates its rules
  when it is absent. Restating alone would drift from the thing it restates.

- **`version` in frontmatter is a declared divergence, not a defect.** That validator's
  ALLOWED_PROPERTIES excludes it, so it exits non-zero on all four bundles here with the
  identical single line. The key stays -- the runtime schema defines it, every bundle declares
  it, and this repository publishes through a plugin marketplace rather than as a `.skill`
  archive. The test fails if any OTHER unexpected key appears **and** if `version` is removed,
  so the complaint cannot be quietly "fixed".

- **A bundle-level `.gitignore`.** `.pytest_cache/` was sitting in the bundle root, untracked
  only because pytest writes a self-ignoring `.gitignore` inside its own cache -- an
  implementation detail of pytest and no protection against a copy made with `cp`, `tar` or
  `rsync`. Adopted from xdm-author 2.7.0.

- **The reconciled standard is written down** in the maintainer-side docs tree, merging both
  audits so a third bundle need not rediscover either. It records what each pass missed: that
  one worked from prose and shipped invalid YAML, and that the other had no check for a
  redaction holding only while nobody regenerates.

## 0.33.0

Audited as a skill bundle rather than as a repository, and the difference mattered: this
publishes to a public repo, and 348K of it should never have gone.

- **A licensed report identifier shipped inside the rule that forbids it.** `corpus/README.md`
  stated "No report identifier anywhere in the record" and printed a real filing from a
  licensed intelligence subscription two lines below as the worked example. **Two independent defects held it there**: no validator
  pass opened a markdown file, and every identifier pattern carried a trailing `\b` -- an
  identifier is written inside the filename it was filed under, `_` is a word character, so
  the boundary never fired. The check could not have caught it even while looking, nor the
  same string inside a record. Both fixed, held by `tests/test_markdown_disclosure.py`,
  proved by mutation.

- **`SOURCES.md` and `TODO.md` moved to the maintainer-side tree.** 5,801 lines of internal operations
  record against 850 lines of documentation a user needs, and the bundle's own README already
  claimed they did not ship. They carried the quantified coverage profile of a detection
  library the same section labels confidential, the cloud operations this estate cannot see,
  named quality verdicts on ~30 third-party research vendors, and 65 references to an
  `_ingest/` tree in no clone.

- **What ships instead is derived.** `scripts/build_manifest.py` generates `SOURCES.md` from
  `observations.jsonl`: every publisher, its source type, whether its records are cited
  abstractly, and how many. 153 lines against 4,489. Built from the corpus rather than
  transcribed from the private record, because a manifest copied out of a document nobody
  outside the estate can read rots where nobody can check it -- the failure already paid for
  once here, in a gate comment whose hand-typed counts went stale and then decided something.
  `--check` makes it falsifiable by anyone holding the bundle.

- **Seven pointers into those files are now inlined**, because the corpus is the artefact
  people build on and a provenance note aimed outside the bundle is unverifiable by the reader
  holding it. One was already wrong: `locus-map.json` justified routing `app.mdm` to MANAGEMENT
  "under the rule in SOURCES.md section 15", and section 15 is Zero Day Initiative. Not
  renumbered -- inlined, since the sections are not even in file order.

- **`references/` added; SKILL.md 535 to 458 lines.** This was the only one of four skills here
  with no `references/`, and so the only one holding every level-3 document at level 2.

- **The description advertised one of the three questions the routing table lists.** A caller
  asking for a rule-design consult or a coverage review would not have fired the skill that
  answers them. Now names all three, with the LOCUS design rationale cut.

- **Three entry-point defects.** `advise.py --corpus` did not redirect the URL-liveness cache
  and the header printed a relpath that rendered the same either way, so it looked honoured.
  A transport failure overwrote the verdict and re-stamped `checked`, so **the first offline
  run after 2026-09-14** -- when the shipped cache goes stale -- would have turned 208
  known-live sources into 208 apparently dead ones for a fortnight. And `consult.py`'s
  unresolved dead-end sent the caller to `query.py --help` for a class list it does not
  contain, at the moment they are most stuck; it prints the 61 classes now.

## 0.32.0

A use-case answer has to cover all three planes, because the ranking will not do it for you.

- **Two rules added to the response contract: answer across MANAGEMENT, CONTROL and DATA, and
  carry the detail that makes a finding actionable.** Asked "I have a Palo Alto firewall, what
  should I focus on", this bundle returned six findings that were almost entirely the
  appliance-as-target, and the caller had to ask for the two planes the ranking had buried.

  **The ranked output is an input to the answer, not the answer.** Criticality ordering
  returns whatever the corpus is densest in, and density is not balance. Measured on that
  question: 156 records touch the firewall, VPN gateway, proxy and IDS classes and **133 are
  `role: victim`**, while **23 non-victim records** (9 `control_bypassed`, 6
  `telemetry_source`, 5 `inline_tool`, 3 `lateral_path`), **285 patterns readable from that
  firewall's own telemetry** and a **thirty-strong remote-access authentication family** sat
  below the cut and went unmentioned.

  So the contract now says to query the planes deliberately -- filter records by `what.role`
  for the non-victim relationships, filter patterns by `applies_to_classes` and by the
  `evidence_type` the technology actually emits -- and to name each plane as a heading with
  several findings under it, saying so in that plane's own words where it is genuinely thin.

- **And to carry the specifics.** A plane heading with no pattern ids under it is a topic
  list, not a consultation: name the pattern, what it detects, the telemetry it needs, its
  ATT&CK ids and the reference URLs. Say plainly when patterns are generic (`vendor: any`)
  mechanism patterns the caller's own logs can answer rather than incidents naming their
  product, because the two carry different weight.

## 0.31.0

The first records from Check Point Research, and five refusals that cost more than the two
records taken.

- **Two observations and three patterns, 1,214 records to 1,216.** The first figures this
  corpus has moved since 2026-08-22. `obs-microsoft-defender-btr-remediation-driver-as-kernel-
  primitive` -- Windows Defender's own signed repair driver staged with attacker instructions
  in an alternate data stream, seven how-blocks, two new patterns. `obs-microsoft-windows-
  attacker-root-ca-for-local-https-interception` -- JSCeal installing a generated root CA
  through `certutil -addstore -f root`, eleven how-blocks, one new pattern. Both derive
  ENDPOINT, which is the whole of the locus movement: 89 to 107, every other locus unchanged.

- **Seven records were drafted and five were refused.** That ratio is a property of the source
  and the method rather than an accident, and `SOURCES.md` section 29 records it as one.

- **The first review found 39 values the articles do not state, at least five in every one of
  the seven records.** The shape never varied: a drafter read one article well and then
  reached for a *nearby* fact to sharpen a detection -- an adjacent section, a sibling
  campaign, a plausible mechanism. **Every fabrication sat beside something true**, which is
  exactly why schema validation could not see it. `validate.py` passed records asserting
  things their sources do not say, because it checks shape and vocabulary, not fidelity.

  The sharpest case: one record built a detection from `ZoomWorkspace.bat` while its own logic
  was scoped to the `CVE-2025-8088` chain, and the article says of that script's campaign "we
  did not observe the use of the CVE-2025-8088 vulnerability". Wrong archive tool, wrong
  launcher, wrong password, all taken from a campaign the source explicitly separates.

- **Repairing the sourcing exposed a second, independent failure class.** On re-review
  provenance was strong -- 210 claimed quotes checked, 7 failures -- and three records were
  then refused on *detection logic* instead: markers ANDed on one field that can never both
  be true, bare process names compared against full-path fields, and one marker set that
  **excluded vulnerable instances including a Critical flaw**. Sound sourcing and a working
  detection are separate properties, and each needs its own reader.

- **A reviewer that accepts a record has not necessarily read it.** The accepted JSCeal record
  carries eleven how-blocks and its reviewer had been handed roughly five. Reviewing the tail
  found three structural defects and one unsourced claim -- and, checked against the article,
  **every literal in the unreviewed blocks was sound**. Two blocks declared `netflow` and
  `tls_metadata` while every clause was HTTP-layer, so under two of three declared telemetries
  no clause evaluated at all; one block asserted a campaign-varying domain the article never
  characterises; one was `single_event` while its own caveat said no single hit means anything.
  All fixed before the record was taken.

- **Two blocks deliberately carry no `pattern_id`.** Both are destination pivots on one named
  host and path rather than behaviours, and no shipped pattern describes that. Filing them
  under an interception or injection pattern would file them by subject rather than by
  mechanism, which this corpus says repeatedly is the wrong tidier answer. The record says so
  in its notes.

- **Routing normalised one unrelated record and the file is better for it.**
  `exp-nvd-ivanti-ivanti-endpoint-and-mobile-management` carried literal non-breaking spaces
  inside its prose; re-serialisation escaped them. The data is byte-identical as JSON, and
  `observations.jsonl` now carries **no** non-ASCII bytes where it previously carried one line
  of them -- a latent breach of the ASCII-only rule, closed as a side effect.

- **29 of the 36 candidate posts remain unread**, because the publisher's rate limiter answers
  HTTP 202 with an empty body and `Crawl-delay: 10` does not hold it off. Recorded in section
  29 with the reasons not to work around it.

## 0.30.0

An ordinary word in a question resolved as a product *class*, and a class decides which
plane the whole answer is about.

- **`sensor` resolved to `ot.field_device`.** A consuming content-pack session asked
  about "mobile application integrity: an in-app **sensor** reporting rooted or jailbroken
  devices, emulators, repackaged or tampered applications, sideloaded installs and
  certificate pinning failures" and got six well-formed findings -- GeoServer, Ivanti
  Connect Secure, Cisco FMC, Log4j -- none of them mobile. `RESOLUTION: CLASS-LEVEL
  (inferred)` was printed correctly, which is what let them catch it.

  This is the 0.29.0 defect in the third alias table. `class_aliases` has no gate, and it
  is the worst one to leave open: a wrong product name is a header line a reader can
  discount, while a wrong class means every finding underneath is confidently about
  somewhere else. An industrial field instrument and a consumer handset share almost no
  threat surface.

- **`sensor` and `instrumentation` are deleted, and only those two.** In a security
  question a sensor is a software agent and instrumentation is bytecode; both pointed at
  OT. Deletion costs nothing here because `ot.field_device` is still reached by `field
  device` and `actuator`. The reported question now resolves `classes=-` with
  `RESOLUTION: mechanism` and `identity=0`, which is the honest state and still returns a
  usable answer.

- **The general gate is filed, not built, and the four known survivors are pinned as
  failing.** Measured over thirteen ordinary sentences: six resolve falsely, three into
  OT. `the script ran overnight` reaches `telecom.ran`, `a relay of phishing mail` reaches
  `ot.protection_relay`. Those are the only alias for their class, so deleting them would
  buy honesty with coverage -- they need a gate, and `tests/test_class_aliases.py` holds
  them as *still failing* so the tripwire fires when it lands.

  **The rule cannot come from a word list.** 47 of the 201 single-token class aliases are
  dictionary words and most are correct, because a caller who writes "firewall" means the
  firewall. The false ones are where the ordinary meaning names something else. That is
  the same conclusion `_ambiguous_comment` reached for products, arrived at again.

- **Licel was missing from the route its fifteen siblings use.** The same report read as a
  second corpus gap for mobile app integrity and was not one. Guardsquare answers today
  -- `dev.library`, `app.cicd`, a labelled `CLASS-LEVEL` consultation -- and Licel
  answered nothing only because nobody had registered it. `licel` and `dexprotector` are
  in `class_aliases` now, and `Licel Alice` returns 143 findings, **58 of them SUPPLY**,
  with `LOCUS_ABSENT: ENDPOINT`.

  **Refused on its own measurement, not by resemblance.** Re-run over the library as it
  now stands, **1,350** packs: **zero files** for `licel` and `dexprotector`, the same
  result the thirteen returned. `SOURCES.md` section 28 records it. Nothing was read.

- **Alice is gated rather than omitted.** It is a real Licel product and the commonest
  given name in security writing, so it went into `product_aliases` under
  `ambiguous_aliases` -- resolving within two tokens of `licel` and nowhere else -- rather
  than beside its siblings in the table this release just proved has no gate. "alice in
  accounting clicked the link" resolves nothing.

- **The corpus carries Mobile ATT&CK; no pattern cites it.** Also raised in the same
  report, as "the corpus has no Mobile ATT&CK coverage". The reference has carried all
  three domains since 0.25.0 -- 1,166 techniques, 190 of them Mobile, and `validate.py`
  still reports 425/425. What is zero is Mobile techniques cited *by a pattern or a
  record*, and `advise.py --attack` selects on a pattern's own technique list, which its
  `NO_MATCH` line says. The distinction matters because `T1577` is a live in-scope item in
  `TODO.md` rather than something the corpus cannot reference.

## 0.29.0

An ordinary word in a question resolved as a product name, and the header said so
confidently.

- **`runtime` resolved to Android Runtime and `ios` to Cisco IOS.** A consultation on a
  mobile app-shielding vendor was reported as returning nothing. It was returning
  something worse: `consult.py "runtime application self-protection"` reported
  `RESOLUTION: product - the corpus holds records naming this technology`, `identity=259`,
  and an OSGeo GeoServer Java deserialisation record at rank 1 of 860 matched findings.
  Reported by a consuming content-pack session on 2026-08-28, reproduced on 0.27.0 and
  0.28.0, recorded in `TODO.md` as confirmed and unscheduled.

  `resolve()` accepted every alias hit anywhere in a question. The fix is corroboration
  rather than deletion, because `ios` is load-bearing -- it carries 16 records: the words
  under `ambiguous_aliases` in `corpus/schema/aliases.json` resolve only within two tokens
  of their owning vendor. `Cisco IOS` works, `iOS apps` does not.

  **The window is two tokens, and three was measured and rejected.** In the reported query
  "runtime" sits four tokens from "android", so a wider window left the bug open.

- **This was never a mobile defect.** Measured across the alias table: **90 vendor-
  qualified product questions were resolving a second vendor the caller never named, and
  none lost its own subject when the gate was added.** `Apple iOS and iPadOS` also returned
  Cisco. `Cisco Secure Firewall Management Center` also returned Sophos. `.NET Framework`
  also returned Android. `Cisco RV Series Routers` also returned D-Link. `SKILL.md`
  documented one of these -- "I have a Cisco firewall" resolving `vendors=Cisco, Sophos` --
  as intended behaviour, and that page is corrected with the code.

- **The gate matches a token sequence and fails closed.** The first version indexed by
  single-token equality, found nothing for a two-word alias and returned `True`: a gate
  that reads as protection and is a no-op. `web server` pointed at a Commvault *backup*
  product and `device management` at a Yealink phone; both are gated now, and both already
  had a `class_aliases` entry carrying the answer that was wanted.

- **`RESOLUTION` could claim the tight case with `identity=0` underneath it.** That is the
  self-inconsistency `SKILL.md` tells a consumer to gate on, printed as though it were the
  tight case. It is computed after the tier tally now, and it counts only identity reached
  through a vendor or product the caller actually named -- `Q.score()` labels its reasons
  by kind, so a class match no longer passes for a named product. A name that resolved
  against nothing the corpus holds reports the new `NAME_WITHOUT_RECORDS`.

- **The thirteen refused app-shielding vendors now resolve to a class.** Guardsquare,
  DexGuard, iXGuard, ThreatCast, AppSweep, Appdome, Promon, Build38, Approov, NowSecure,
  Verimatrix, Arxan, Digital.ai, Pradeo and Talsec map to `dev.library` and `app.cicd` --
  66 findings, **52 of them SUPPLY** -- so the question returns a labelled `CLASS-LEVEL`
  answer instead of exit 1. `SOURCES.md` section 28 refuses these as *sources* and that
  refusal is untouched: nothing was re-read and no record was taken. The alias makes a
  different claim, about compiling a third-party binary-rewriting SDK into a build
  pipeline.

  **`security.edr` fills two more loci and is deliberately absent.** It derives ENDPOINT,
  and the handset is the one plane this corpus declines to advise on -- aiming findings
  there is the mistake section 28 records having made once with `app.mdm`. `ENDPOINT` and
  `ORGANISATION` come back as `LOCUS_ABSENT`, which is the honest answer.

- **A recon pass on mobile app shielding took nothing, and found one thing.** NVD holds
  **0 relevant identifiers** across all thirteen vendors. The cached Zscaler mobile report
  was re-read asking whether any campaign defeats an in-scope control with tenant-side
  telemetry rather than whether it is handset-side, and produced zero again -- the control
  these trojans defeat is consumer banking SMS 2FA, on the device. What did survive:
  `T1577`'s fourth ATT&CK log source is `android:MDMLog`, not `MobileEDR`, so **a managed
  application whose signer lineage or installer source changes outside the approved channel
  is observable, in scope and unwritten**, needing no new vocabulary. In `TODO.md`.

- **113 tests added, 102 to 215 passing.** `tests/test_mechanism_lookup.py` pinned one
  string, "mobile app hardening"; the new `tests/test_ambiguous_aliases.py` is table-driven
  over the whole flagged set, so every entry is asserted inert alone and live beside its
  vendor. Corpus unchanged at 1,214 records and 533 patterns, 0 validator problems.

## 0.28.0

Five network appliances stop being classified as endpoint detection.

- **`security.edr` held a firewall operating system.** `exp-kev-sophos-sfos` is
  `network.firewall` now -- the KEV text calls it "Sophos Firewall operating system" in so
  many words -- along with `exp-kev-sophos-cyberoamos` and `exp-kev-sophos-sg-utm`.
  `exp-kev-sophos-web-appliance` is `network.proxy`, on the `FortiProxy` precedent, and
  `exp-kev-symantec-symantec-messaging-gateway` is `security.email_gateway`. The four
  product aliases that assigned the wrong class are fixed with them.

  A firewall was answering an EDR question and an EDR question was returning a firewall.
  `SFOS` went from 34 findings to 94; nothing shrank, and no locus moved, because all five
  are exposures carrying `how: []`.

- **The Symantec record settled itself, and the duplicate it resembles is not one.** Its
  own advisory twin `exp-broadcom-symantec-messaging-gateway-rce` already carried
  `security.email_gateway` for the same product, so the corpus was holding one product
  under two classes and one of them had to be wrong. Both records also share
  `CVE-2017-6327`, which looks like the acquisition trap section 3 documents -- it is not.
  **54 CVEs appear in both a KEV and a non-KEV exposure record**, so a catalogue record
  sitting beside an advisory record is the normal provenance pattern. Checked before
  touching either, because merging them would have destroyed a source.

- **What remains in `security.edr` is a definition, not a list.** Four records are security
  products that are not detection agents -- `FortiSandbox` three times, `FortiDeceptor`,
  and `FortiClientEMS`, which is the management server for FortiClient and so the identical
  error to the three consoles moved in 0.27.0. `vocab.json` has no `security.sandbox` and no
  `security.deception`, so this is a vocabulary decision: add the classes, or widen the
  description and say so. Recorded in `TODO.md`; moving records under an unchanged
  description is how the class filled up in the first place.

- **The pack session's resolver report is recorded.** Reported against 0.23.0, reproduced on
  0.27.0, answered CORRECTED on both items and now written into `TODO.md` because the reply
  said it would be. A question containing ordinary words that are also product names --
  "runtime protection", "iOS apps" -- resolves them as products and prints
  `RESOLUTION: product`, the tight case, on a false match. Neither `MATCH_TIERS` nor their
  own proposed class-overlap test would catch it, and fixing the `ios` alias alone returns
  an empty answer, since Apple iOS and Android hold twelve records between them with zero
  how-blocks. Not scheduled.

## 0.27.0

Three products that manage endpoints stop being classified as products that defend them,
and the two publishers section 28 registered are read.

- **`exp-kev-ivanti-endpoint-manager-epm`,
  `exp-kev-ivanti-endpoint-manager-cloud-service-appliance-epm-csa` and
  `exp-kev-motex-lanscope-endpoint-manager` are `app.rmm`, not `security.edr`.** They are
  desktop and endpoint *management* consoles rather than detection agents, and
  `security.edr` derives ENDPOINT while these belong to MANAGEMENT. Five product aliases
  carried the wrong class and are fixed with them -- the table is what assigns a record its
  class, so fixing records alone would have let the next one arrive wrong. `endpoint
  manager` went from 375 findings to 406; nothing shrank, and no locus moved, because all
  three are exposures carrying `how: []`.

  `epm`, `epm csa`, `ivanti endpoint manager`, `lanscope` and `motex lanscope` are added,
  because `EPM` and `lanscope` previously resolved to nothing and step 5 of the
  add-a-source procedure requires every product to be findable by name.

- **Reading the other 37 `security.edr` records -- which is what the item said this needed
  -- found a larger and separate error, deliberately not fixed.** Five records in that
  class are network appliances: Sophos SFOS (the KEV text calls it "Sophos Firewall
  operating system"), CyberoamOS, SG UTM, Web Appliance and Symantec Messaging Gateway. A
  firewall currently answers an EDR question. Three more are security appliances that are
  not EDR -- FortiSandbox, FortiDeceptor, and FortiClientEMS, which is the identical
  management-console error one vendor over. Fixing those needs a decision about whether
  `security.edr` means "EDR" or "endpoint security product", so it is its own pass and is
  recorded in `TODO.md`.

- **Zimperium zLabs and Lookout Threat Lab were read, and produced zero records.** That is
  the measured result, not a deferral. Zimperium's entire threat-research catalogue is
  handset-side -- ToxicPanda, GoldPickaxe, NGate, RedWing, quishing -- and its MDM material
  is product positioning, refused on the section 24 rule. Lookout is the same shape, and
  its deep report answers 403 unauthenticated, which is recorded so a later pass does not
  read the block as an absence.

- **The one management-plane case found belongs to a publisher not registered here**, and
  is still not a record. Check Point Research documented a breached corporate MDM used to
  install a Cerberus banking trojan on more than 75% of a company's devices -- the right
  plane and the right mechanism, but the corpus already holds that mechanism as
  `pat-device-management-platform-force-multiplier`, and the research analyses the malware
  on the handsets rather than the console, naming no identifier and no management-side
  artefact. A record from it would assert a detection nobody could implement.

- **The lesson section 28 asserted from one refusal now holds across three publishers.**
  The pack-library test picked the right class of vendor and the wrong publishers: an MTD
  vendor's telemetry *is* the handset, so its research is about the handset, and the pack
  test cannot see that. Weigh which plane a publisher can observe before weighing its
  packs. `security.mtd` stays gated, correctly, with no records to ship it alongside.

## 0.26.0

The mobile management plane gets a class, a locus and a declared scope. Handsets stay out.

- **`app.mdm` is a new product class, derived MANAGEMENT.** The console and the enrolment
  channel it pushes configuration profiles through -- never the enrolled handset. Eleven
  records for it were already in the corpus, arriving with the Ivanti and Omnissa passes
  under `app.rmm`, `security.edr` or `identity.sso` according to whichever alias happened
  to be written, and no section said whether the corpus advised on them. `SOURCES.md`
  section 28 declares it.

- **Two records were aimed at the wrong plane.**
  `exp-kev-ivanti-endpoint-manager-mobile-epmm` and its sibling carried `security.edr`,
  which derives ENDPOINT -- so an EPMM question pointed at the one plane the handset rule
  declines to advise on. Both are `app.mdm` now. **The locus tally does not move**, and
  that is not the fix failing: both are exposures carrying `how: []`, and the tally counts
  how-blocks. Worth knowing before checking for it.

  The alias table produced the mis-classification: three product aliases carried
  `security.edr` for EPMM, and a record takes its class from the alias that resolved it.
  Fixing the records without the table would have let the next one arrive wrong the same
  way.

- **Classes are appended, never substituted**, except on those two corrections. The four
  records genuinely both keep `app.rmm`; both are MANAGEMENT, so no locus moved.
  `exp-kev-ivanti-mobileiron-multiple-products` keeps `network.vpn_gateway` first, because
  Sentry genuinely is a gateway and first-listed drives the derivation.

- **An alias may now name more than one class -- product aliases as well as class
  aliases**, and the MDM family does both. The same failure appeared twice, one level
  apart: retargeting the *product* alias `epmm` to `app.mdm` alone took that question from
  **74 findings to 17**, because the MDM records arrived and the fleet-management context
  that had been carrying it left. Both are lists now, and both restore their baseline
  while still resolving to `app.mdm` specifically.

- **A class alias may now name more than one class**, and the MDM family does.
  Retargeting `mdm` to `app.mdm` alone took the question from **63 findings to 4** -- a
  thinner answer reading as a safer one, which is the failure this corpus exists to catch.
  `mdm`, `uem`, `emm` and the rest now resolve to `app.mdm` **and** `app.rmm`, restoring
  63 while `EPMM` still resolves to `app.mdm` specifically. `SKILL.md` has always told a
  caller to name every class the technology behaves as; the alias table can do it too.
  `device enrolment` stays `app.mdm` alone, being MDM-specific and not remote management.

- **Zimperium zLabs and Lookout Threat Lab registered**; thirteen app-shielding vendors
  refused with the measurement recorded -- **zero files across all 1,347 upstream packs**
  for guardsquare, dexguard, ixguard, threatcast, appsweep, appdome, build38, promon,
  approov, nowsecure, verimatrix, arxan and pradeo. A shielded binary's runtime
  attestation goes to the vendor's own SaaS, not a tenant dataset, so there is no
  `evidence_type` it could map to.

- **The Zscaler mobile report was read and refused**, which was not the expected result --
  it was meant to be the cheapest first record. Every mechanism it names is on the handset:
  overlay windows over banking apps, SMS interception for one-time passcodes, Accessibility
  Service abuse to approve transactions. That is the plane this change does **not**
  re-admit, and it fails collectability independently. Recorded in section 28 along with
  the general lesson: a mobile threat report is not a mobile-management source, and most
  published mobile research is handset research.

- **`security.mtd` is designed and deliberately not added.** An empty class makes
  `--as security.mtd` return `NO_FINDINGS` and exit 1 -- the "empty answer read as safety"
  failure `tests/test_class_fallback.py` exists to prevent. Add it with its first records
  or not at all.

- **Both mobile exclusions amended in place, verbatim-then-append**, so the record shows
  the line was refined and not reversed. The handset rule stands unchanged; what needed
  narrowing was the unstated half, that "mobile" and "handset" name the same scope.

## 0.25.0

The Mobile ATT&CK domain is carried, closing a scope decision open since 2026-08-06.

- **`T1451` and `T1430` were cited by four pieces of content and resolved against
  nothing.** `attack-techniques.json` carried Enterprise and ICS only, so no Mobile id
  could resolve; `validate.py` reported this and deliberately never failed on it. The
  reference now carries all three domains -- **1,166 techniques, 425/425 resolving**.

  What decided it was not the two citations but `emit_xql.py`, which **silently omits**
  an unresolved technique with no warning and no placeholder.
  `obs-generic-service-desk-social-engineering-mfa-bypass` cites `["T1451", "T1621"]` and
  the emitted handoff carried `T1621` alone. A rule author got a hole with nothing saying
  so, which is worse than a larger file -- and dropping the citations would have left the
  same hole and merely documented it. Renumbering to Enterprise-domain neighbours was
  never on the table.

  Cost: 976 -> 1,166 techniques, 431,786 -> 545,731 bytes, +26%. Paid by `emit_xql.py`
  per invocation and `validate.py` once per run; `consult.py` does not read the file. Of
  the 190 mobile techniques 119 carry `log_sources` and 81 carry `mutable_elements`.

- **The transform that builds the shipped reference is a script for the first time.**
  There was none: the file had been produced by an uncommitted one-liner and was
  reproducible by nobody. `_ingest/mitre-attack/build_reference.py` reconstructs it, and
  was verified **byte-for-byte** against the shipped file before the domain was widened
  -- `--domains enterprise,ics --legacy-attribution --out - | cmp -`. That flag is
  retained so the check stays runnable rather than being a thing done once.

- **Both shipped MITRE references now carry the copyright designation**, not just a
  pointer to it. `attack-techniques.json` and `d3fend-countermeasures.json` previously
  carried a short form; they now carry the designation from the upstream `LICENSE.txt`
  with the copyright symbol rendered `(c)`, plus `licence` and `licence_note` keys. The
  substitution is declared in the file rather than left to be noticed: this bundle is
  checked for ASCII and every shipped file passes, and a licence permitting reproduction
  of a designation is not plausibly defeated by the ASCII rendering of its own symbol.

- **ATT&CK Mobile will never join to D3FEND, and this is now written down in three
  places** -- `SOURCES.md`, `TODO.md` and beside `ATTACK_FRAMEWORKS` in the harvester --
  because the failure mode is someone rerunning the harvester and concluding it is
  broken. Measured over `d3fend-full-mappings-1.5.0.json`: 16,164 bindings, `framework_key`
  enterprise 13,387, ics 2,238, sparta 539, **mobile 0**. The ontology carries 166
  ATT&CK-Mobile ids but with `rdfs:subClassOf` only and no digital-artefact edges, and
  the join runs through a shared artefact. `by_attack` stays at 392 keys. The `"mobile"`
  in `ATTACK_FRAMEWORKS` is dead code, retained against the day upstream ships rows.

- **`validate.py`'s technique check stays non-fatal, for a new reason.** It was
  non-fatal because a Mobile id was out of scope. It is now non-fatal because ATT&CK
  renumbers and revokes between releases, so an id that stops resolving is a signal to go
  and look at the corpus rather than a broken build.

## 0.24.0

A word inside a product name was being reported as the caller having named that product.

- **`consult.py "mobile app hardening"` printed `RESOLVED_TO: vendors=- | products=- |
  classes=-` and then returned sixteen findings each saying `named this technology`.**
  Rank 1 was an Ivanti Connect Secure VPN gateway, reached because `Mobile` appears inside
  the product name `Endpoint Manager Mobile`; others came from `app` inside
  `web applications` and `hardening` inside an ICS-hardening record. The header and the
  findings contradicted each other and nothing on screen reconciled them.

  The cause was a name collision rather than a matching fault. `FREE_TEXT_TIERS[0]` was
  *called* `identity` and meant "matched the vendor/product/class haystack", while
  `match_basis` used the same token for a vendor the resolver actually resolved, and
  `emit` rendered both as "named this technology". Scoring had always separated them --
  a resolved product is worth 6 points, a free-text hit on that haystack 2 -- so only the
  label and its weight were wrong. The tier is now **`name-fragment`**, rendered `WEAK`,
  and weighted 0.85: below a curated tag, above pattern and prose. Reading all twelve
  such records for that query, six are genuinely about mobile management and six are not,
  which is worth more than prose and less than a tag.

  `WEAK` rather than `LOOSE` deliberately. `LOOSE` means "matched on prose" in this
  bundle and is grepped for; reusing it would have silently changed what an existing
  grep means.

- **`tag` now sorts above `name-fragment`.** The tier loop already claimed the first tier
  wins "at the tighter of the two", and a curated tag is tighter than an unresolved
  fragment of a name. Both are worth 2, so the reorder is points-neutral: measured over
  eight queries the corpus-wide score sum is identical either way. Four findings on the
  target query moved to the tighter tier.

- **`match_basis` no longer fails open.** An unrecognised reason shape fell into an else
  branch and was given `identity` at full weight -- the tightest tier, for a shape the
  function did not understand. It now goes to `summary`, and the tier ordering derives
  from `query.TIER_ORDER` rather than a hard-coded tuple, so a tier added in one file
  cannot be silently dropped in the other.

- **New header line `MATCH_TIERS:`**, counting the whole match set by tier before
  `--limit` truncates it -- the same discipline as `LOCUS_MATCHED`. `identity=0` beside
  `RESOLVED_TO: vendors=-` is now self-consistent, and a consumer can gate on it without
  parsing English. This is a tally rather than another sentence of prose because
  `RESOLUTION: mechanism` already said "nothing resolved by name"; what was missing was
  something machine-readable that the finding blocks could not contradict.

- **Consumer-visible:** `query.py --json` `matched_on` strings change from `(identity)`
  to `(name-fragment)`. Anything matching on the old string needs updating.

## 0.23.0

A source sync, and two claims in the corpus that the new material proved wrong.

- **`pat-deserialisation-failure-in-application-log` said a successful attack may raise no
  exception, so the pattern finds attempts and near misses rather than compromise.** True
  in general and **false for ASP.NET ViewState**, where a successful deserialisation raises
  `InvalidCastException` and a wrong MachineKey raises a MAC validation failure -- both
  HTTP 500, meaning opposite things. Talos documents the actor reading the difference to
  confirm stolen key material before executing anything. The caveat now scopes itself and
  points at `pat-viewstate-exception-distinguishes-key-validity`; a reader following the
  old wording would have treated the more visible case as the invisible one.

- **`pat-package-install-hook-executes-and-republishes` recommended disabling install
  scripts estate-wide as the control cheaper than detection.** That is an npm fact stated
  generally. Cargo runs build scripts at compile time and has no stable equivalent switch,
  so for Rust detection is the only option rather than the expensive one. The caveat now
  names the ecosystems it holds for.

- **CISA AA26-231A, an active threat to Siemens S7 PLCs.** Five agencies on tooling built
  from snap7 -- the same open-source S7comm library legitimate monitoring software uses --
  with AI assistance writing the scripts around it. Protocol-correct traffic by
  construction and no custom binary to recognise, so the host-side library artefact is the
  only distinctive stage, and it is a detection only where the approved engineering
  workstation list is maintained. Fills T1588.007, T1596.005, T0849, T0834 and T0893, all
  previously at zero observations and zero patterns.

- **The KEV acquisition trap fired again, three-way.** Catalogue 2026.08.21 filed
  CVE-2026-59310 under `("Broadcom", "VMware vCenter")` against two spellings already held.
  Both now map onto one record carrying all eleven identifiers. Two findings generalise
  from it: **`aliases.json` breaks the tie** on which name to map onto, because it is what
  a question resolves through; and **the merge router has no delete**, so a merge orphans a
  record and the failure is duplication rather than loss, with the record count, the
  validator and the identifier total all still looking correct. Section 3 carries the check.

- **StepSecurity's sitemap became diffable, and the distribution is why it was believed.**
  All 316 URLs now carry `lastmod`, which section 9 says is not automatically trustworthy.
  64 distinct dates with the busiest holding 24, against Unit 42's 99 of 99 on one day. It
  surfaced a second account of the arrayref crate hijack, taken as a **corroboration on the
  Wiz record** rather than a second record -- the first use of `where.corroborations` since
  0.21.0 created it.

- **Talos is now behind a Cloudflare block and the feed carries the whole post.** A direct
  fetch returns an interstitial at HTTP 200, so a collector checking status codes distils
  the block notice -- the cisa.gov defect of section 2 at a different source. The RSS
  `<content:encoded>` holds the full body, 54,000 characters for the post taken here.

- **Three routes failed and are recorded as unchecked rather than zero.** Unit 42 answered
  301, ACSC 404, a Hunt.io route 404 because it was guessed rather than taken from the
  register. A zero is a finding; a failed fetch is the absence of one, and the summary
  table distinguishes them. Four items read to their titles are named in `TODO.md` so the
  next pass does not rediscover them.

- Records 1,209 to 1,214, patterns 528 to 533, exposures 881 to 883 -- two rather than four
  because the vCenter merge removed two. KEV 2026.08.17 to 2026.08.21. Validator problems
  0, 96 tests passing.

## 0.22.0

Ask by mechanism, not only by technology.

- **`consult.py "phishing"` returned 0 findings from 1,209 records**, and so did `ransomware`,
  `worm` and `prompt injection`. The free-text fallback searched vendor, products and class
  suffixes only, so a word that is not a technology matched nothing anywhere. It now also
  searches record `tags`, the cited pattern's name and description, and `what.summary`.
  Measured over thirty mechanism terms: 33 record-hits before, 1,124 after, and terms
  reaching nothing fell from 22 of 30 to 6.

- **The reach is not free and the cost was accepted deliberately.** The same measurement
  found 31 records answering a vendor query they are not about -- Chromium records under
  Microsoft, Juniper under Cisco -- every one of them via prose, none via a tag. Tags alone
  would have bought 484 hits at zero such cost. The wider net was chosen for coverage, so
  the wrongness is mitigated rather than avoided:

  - **Tiered scoring.** A term scores once, at the tightest tier it appears in: identity and
    tag are worth 2, pattern wording and summary prose 1.
  - **Loose matches are demoted in ranking** by a `MATCH_WEIGHT` multiplier -- pattern 0.75,
    summary 0.6 -- so a prose coincidence cannot outrank a record that names the technology.
    Measured on a Cisco query: the known false hits land at rank 14 and below, behind 13
    genuine findings.
  - **`MATCH_BASIS:` on every finding** says which tier it arrived on and marks the loose
    ones `LOOSE - may be about something else`.

- **A fifth resolution mode, `mechanism`.** 0.20.0's UNRESOLVED path fired before findings
  were counted, so it would have hidden all 101 phishing findings behind advice to name a
  product class. Nothing-resolved and nothing-found were the same state until this release
  and are not any more.

- 8 tests added, 96 passing.

## 0.21.0

Every finding now says how well-backed it is.

- **`SUPPORT:` on every finding** -- publication date and age, when the source was last
  read, and whether it was verified. Ranking already weighed recency and 0.19.0's
  `CORROBORATION` already named independent accounts, but nothing said when anybody last
  confirmed the source still says what the record claims. A reader weighing twelve findings
  could not tell the well-attested from the never-revisited.

- **Flags mark the weak ones so they announce themselves**: `NO_READ_DATE` (30 observations,
  155 exposures), `VERIFICATION_UNSTATED`, `SOURCE_NOT_RE-READ`, `SEED`, and
  `NO_PUBLICATION_DATE:ranked-as-3650d`. 60% of observations and 82% of exposures carry no
  flag, which is the property that makes a flag worth reading.

- **Age is reported and deliberately never flagged.** A staleness flag restates
  `PRIORITY_BASIS days_since_published` and the recency decay, and the first version of it
  fired on 279 KEV exposures -- which are old by definition, because the catalogue is a
  history. Reporting age without judging it is the honest half.

- **It surfaced a ranking distortion nobody could see.** 99 observations, 30% of them, carry
  no publication date, and `age_days()` silently treats an undated record as 3,650 days old
  -- so those records sink in every consultation for want of a date rather than for want of
  relevance. The flag now says so on the finding, and `TODO.md` carries the fix.

- 7 tests added, 88 passing.

## 0.20.0

A product this corpus does not know by name now gets an answer instead of a blank.

- **`consult.py "Portkey"` returned `FINDINGS: 0 shown of 0 matched` and all six loci
  absent.** That is the normal case rather than the exceptional one -- 73% of a real
  integration library resolves to zero records here -- and it was throwing away an answer
  the corpus could give, because the product *class* almost always holds findings when the
  product name holds none.

- **Three labelled resolution modes**, printed on a `RESOLUTION:` line: `product`,
  `CLASS-LEVEL (inferred)` when only a class matched, and `CLASS-LEVEL (declared via --as)`
  when the caller asserted one. The mode is stated on its own line and never left to be
  inferred from `RESOLVED_TO`, because the difference between "this product was attacked"
  and "products of this kind are attacked" is the difference between intelligence and
  analogy.

- **`--as CLASS[,CLASS...]`** answers at class level for an unknown name, validated against
  `vocab.product_class` so a typo fails loudly instead of producing an empty answer
  indistinguishable from a real one. Declared classes are added to whatever resolved
  naturally rather than replacing it.

- **Name every class the technology behaves as.** Measured on an AI gateway:
  `--as app.ai_platform` alone matched 29 findings and left MANAGEMENT, DATA and
  ORGANISATION empty; adding `network.proxy`, `security.pam` and `cloud.saas` -- what it
  also is -- matched 129 and filled all six loci. A single class is usually an
  under-description, and the unresolved block now says so with those numbers.

- **Both class-level modes print a `CLASS_LEVEL_WARNING`.** The failure that matters here is
  not an empty answer but a class-level answer mistaken for product intelligence, so the
  warning names it and asks to be carried into whatever is written from the block.

- `UNRESOLVED` still exits 1. SKILL.md contracts that nothing-matched is distinguishable
  from a failure by exit code, and a richer message must not quietly promote it to success.

- 7 tests added, 81 passing.

## 0.19.0

Corroboration becomes a list, and the two items 0.18.2 left unread are read.

- **`where.corroborating_publisher` and `where.corroborating_url` are now
  `where.corroborations`, a list of `{publisher, url}`.** A third publisher on one mechanism
  had nowhere to go, and one was refused on 2026-08-18 for that reason rather than on its
  merits; it is now the third entry on the npm worm record alongside Elastic and Zscaler. A
  list of objects rather than two parallel lists, because parallel lists must be kept
  index-aligned by hand and eventually will not be. 29 records migrated.

- **Nothing had ever read those fields.** They were in the schema from early on, 29 records
  carried them, and no script consulted them, so a second independent account of a mechanism
  changed no output anywhere. `consult.py` now prints `CORROBORATION` on every finding and
  the contract records that single-source is a weight rather than a defect. On a
  `RESTRICTED` record it is the only citable route to the material -- which is what the
  field was for -- so the disclosure rule does not suppress it.

- `additionalProperties` already rejected the old keys, but "unknown key" does not tell
  anyone what to do, so `validate.py` names the migration and the version, and also rejects
  an entry missing either half: a corroboration that cannot be read claims more than it
  shows.

- **Signed commit hashes are malleable, and the scope of that needs stating carefully.**
  An actor without the signing key, and without attacking SHA-2, can re-encode a signed
  commit into a second one with an identical tree, identical metadata, a valid signature and
  a forge's verified marking, differing only in hash -- which cascades to every dependent
  commit. This does **not** permit substituting different content under a pinned hash, so
  pinning survives; what it removes is the unstated guarantee that a hash is a canonical
  name, and hash-based denylisting is the control that quietly stops working.
  `pat-action-tag-resolves-to-commit-on-no-branch` carries the amendment, and its own
  branch-membership check still fires.

- **An operator-driven phishing framework**, which keeps an encrypted channel open to a live
  operator, streams keystrokes as typed, and collects identity documents and one-time codes
  in the same flow. Recorded, like the captive portal record before it, as a control
  *satisfied* rather than bypassed: the code is answered correctly inside its validity
  window, so a stronger factor does not help and only an origin-bound credential does.

- Records 1,207 to 1,209, patterns 526 to 528. Validator problems 0, 74 tests passing.

## 0.18.2

The backlog the 0.18.1 sync deferred, cleared the same day -- and two of its ten items were
already in the corpus.

- **A third delta method was wrong, and the three failures share one cause.** The list of
  ten came from differencing Unit 42's live URL set against `unit42-index.jsonl`, an index
  the 2026-08-12 pass had distilled from without refreshing. Two posts already held came
  back as new. Taken with 0.18.1's stale cache and bulk-rewritten `lastmod`, the rule is
  that **a delta is only as good as the baseline it runs against, and the corpus is the
  only baseline that cannot go stale**. Difference against `where.url` and
  `where.corroborating_url`; section 2 already said so for CISA and it generalises.

- **The wrong-route mistake was repeated six days after being written up.** A sweep probed
  RSS paths for publishers whose registered route section 21 records as the sitemap, got
  404s, and nearly recorded three live sources as unreachable. Re-checked on the registered
  routes, all six answer and Hunt.io holds at 395, so 0 new.

- **Four records and three patterns taken.** Captive portal platforms compromised as shared
  infrastructure at hospitality venues, with the device code path recorded as *satisfying*
  multi-factor authentication rather than bypassing it -- the victim completes a genuine
  flow on the attacker's behalf, and calling it a bypass sends people to fix the wrong
  control. A Rust backdoor carrying command traffic over public code hosting, citing the
  existing pattern rather than restating it. An Android and set-top botnet resolving its
  controller through a ledger naming service and flooding with complete browser
  fingerprints, which needed a new pattern: when every request is well formed, the
  discriminator moves from the request to the population. And coding agents with shell
  access, whose actions endpoint tooling honestly attributes to the developer, written as a
  `control_bypassed` inventory because the coverage question is answerable before any
  detection is.

- **Three refused with reasons**: a third publisher on the npm worm, which the schema
  cannot hold and which `TODO.md` now carries as a schema decision; a SOC identity
  commentary piece; and a NetScaler pre-auth RCE analysis with no in-the-wild component,
  patch level under the standing rule.

- **Every remaining source re-checked.** PSIRT 121 collected and 0 net-new, so NVD did not
  run by its own rule rather than by omission; ZDI 0 net-new through its own collector;
  watchTowr 97 to 98. Two deferrals survive and are named: a Talos phishing-framework
  analysis and the arXiv paper `Git Hash Chain Malleability`.

- Records 1,203 to 1,207, patterns 523 to 526. Validator problems 0, 69 tests passing.

## 0.18.1

A source sync, and two collectors that reported a confident zero from stale data.

- **Wiz, Sysdig and Datadog were not re-read at all on the first attempt.**
  `cloud-native-research/collect.py` fetches through a `fetch()` that returns a cached
  file unconditionally -- no expiry, no force flag -- so the run examined sitemaps written
  six days earlier and reported 0 new for all three publishers. Clearing the three
  sitemaps by hand moved examined 1,626 to 1,633 and Wiz 76 to 78. Both hidden posts were
  real. Section 17 of `SOURCES.md` carries the manual procedure and `TODO.md` carries the
  fix.

- **Unit 42's sitemap `lastmod` no longer means publication.** `post-sitemap3.xml` returns
  99 URLs of 99 stamped 2026-08-17, all of them 2016 exploit-kit posts. The documented
  delta for that source would have reported about 149 new posts against 5 real ones.
  Differencing the URL set against `unit42-index.jsonl` is now the route, and section 9
  says so. This is the watchTowr caution from section 8 reaching the best-enumerated
  source here.

- **KEV 2026.08.11 to 2026.08.17.** One new identifier and a net-new vendor and product
  pair, Ray-Project Ray, classified `app.ai_platform` -- the first catalogue pair to carry
  that class. Eight further records changed with no new identifier behind them, because
  CISA re-flagged ten existing identifiers from `Unknown` to `Known` for ransomware use.
  **A pass that diffs KEV on identifiers alone will miss that**, which section 3 now
  records alongside the renamed-pair defect it already carried.

- **A gap the corpus did not know it had.** Every GitHub record here was about Actions and
  workflow abuse; `mass repository cloning` and `repository exfiltration` both returned
  zero observations. One record and three patterns now cover a valid employee token used
  to enumerate, rehearse and then bulk-clone private repositories across several
  organisations, and the credentials recovered from those repositories being used onward.
  No address or client-version markers: the reported campaign changed both between its
  stages and the volume did not.

- **The corpus's first three declared loci.** `app.version_control` derives to SUPPLY,
  which `locus-map.json` already lists as arguable. A stolen token cloning repositories
  poisons nothing downstream, so the three blocks declare DATA, MANAGEMENT and MANAGEMENT
  rather than take a SUPPLY slot in every consultation's locus quota. SUPPLY returns to
  92, and `validate.py` prints the override count.

- Records 1,201 to 1,203, patterns 520 to 523, exposures 880 to 881 -- the first exposure
  movement in five passes. Validator problems 0, 69 tests passing.

## 0.18.0

The top twelve for a Cisco firewall was eleven findings about management interfaces and
one about anything else, and nothing in the output said so. Ranking by criticality
returns whatever the corpus is densest in, which is a monoculture wearing the shape of a
complete answer.

- **The three planes are right for a quarter of this corpus and a metaphor for the
  rest.** The proposal was control, management and data. Measured first: 72.4 per cent
  of records carry no `network.*` or `telecom.*` class, purely-network records supply
  only 110 of 872 how-blocks, and a hand-read stratified sample put 28 per cent cleanly
  in one plane, 18 per cent spanning two and 54 per cent outside the taxonomy entirely.
  Control plane, the value a network corpus should fill, was the rarest at 4.5 per cent.
  `ENDPOINT`, `SUPPLY` and `ORGANISATION` exist because every `process.service_desk`
  detection -- SIM swap, push bombing, MFA enrolment -- would otherwise be labelled
  management plane, and a label that fires on everything is a constant, not a signal.
- **The axis it was built on was already there and read by nothing.**
  `what.attack_surface` is 15 closed values, populated on all 1,201 records and enforced
  at `validate.py:147`, and no script had ever read it. Its top two values are
  `internet_facing_management` at 29.4 per cent and `internet_facing_service` at 24.1
  per cent, which is most of the management/data split already, in words that survive a
  SaaS app and a CI pipeline. It now outranks `product_class` wherever it commits.
- **First-listed class, not a majority vote.** 442 of 869 blocks name products from two
  or more loci. Voting with a fixed tie-break collapses `ENDPOINT` to 7.0 per cent and
  pushes pattern-level `CONTROL` to 49.8 per cent, a fifth of a point under the ceiling.
  First-listed holds `ENDPOINT` at 9.9 per cent and is defensible on its own terms:
  authors write the primary subject first.
- **`rule_shape: inventory` was kept out of the ladder deliberately.** It reads like a
  mandate for `ORGANISATION` and is not one: 313 of 872 blocks are inventory-shaped, and
  reading them shows the shape is a mode rather than a locus. Promoting it takes
  `ORGANISATION` to 36 per cent by swallowing genuine `SUPPLY` and `MANAGEMENT`. Marker
  types were tried and dropped for the same class of reason -- 787 of 1,222 markers are
  `computed`, whose `expr` is free prose, so classifying them means pattern-matching
  English, which is the tautology `coverage()` already documents.
- **The quota prints both sides of what it costs.** One slot reserved per populated
  locus, filled by that locus's highest scorer. `LOCUS_DISPLACED` names every finding
  pushed out and `LOCUS_RESERVED` what took its place; they are always the same length,
  and a test differences the two runs rather than trusting the count. `--no-locus-spread`
  restores pure order and still prints the distribution, which is the only reason the
  eleven-of-twelve above is quotable at all.
- **`control plane` meant two things inside one bundle.** In cloud vocabulary the
  control plane is the management API; in network vocabulary that is the management
  plane. `vocab.json` defined `cloud.iaas` and `cloud.identity` as control plane and
  `consult.py` called `cloud_audit` a control-plane API log. The network sense now wins
  throughout and those three were reworded. `telecom.core` already had it right and was
  left alone.
- **`RESPONSE_DOCTRINE` held the stable-key-set rule by luck.** It was conditional in
  code and non-empty only because six of the twelve doctrine rules are always-on, so the
  contract `consult.py` states in its own docstring would have broken silently the day
  the reference file was slimmed. Now unconditional, with a gap line.
- **Two controlled lists nobody compared are now compared.** `check_locus_map` fails the
  corpus when a vocabulary value has no locus and is not explicitly deferred, in both
  directions, and additionally checks the schema `how[].locus` enum against `vocab.locus`
  and `CONNECTOR` against `vocab.evidence_type`. Both of those pairs are the `source_type`
  drift shape from 0.9.0, checked before it happens this time rather than after.
- **The first key-set assertion this bundle has had.** The output block was entirely
  untested: the suite asserted count invariants and nothing else, so a new block could
  ship without touching a test. It passes on the shipped output, which means it locks the
  contract rather than repairing it.

Known and unfixed: `process_telemetry` is "process values, alarms and operator actions
from the control system itself" in `vocab.json` and "host process telemetry (agent or
auditd-class)" in `CONNECTOR`, and the 71 blocks using it split across `endpoint.os`,
`app.cicd`, `ot.hmi` and `ot.scada_server` -- the corpus genuinely uses it both ways, so
a caller reading `RECOMMEND_ACQUIRE` is told to buy the wrong thing on roughly half of
them. The mapping takes the vocabulary side because that is the corpus contract, and
correcting the connector text either way would make it wrong for the other half. It is
close to inert here regardless: the evidence tier never fires in `consult.py`, because
every `product_class` carries a locus. Also unfixed and separate: `advise.py:313` passes
`product_class` to `doctrine_for` where patterns carry `applies_to_classes`, so every
class-keyed doctrine rule is unreachable through that script.

**1,201 records, 520 patterns, 0 validator problems.** Locus over 872 how-blocks:
CONTROL 259, MANAGEMENT 164, DATA 153, ORGANISATION 118, SUPPLY 92, ENDPOINT 86; 0
declared overrides, 153 carrying a span. Nothing under 2 per cent, nothing over 50.
Marker coverage 496/497 alert-fidelity blocks (99%), technique resolution 413/415 with
the two known Mobile gaps unchanged, 69 tests green, up from 32.

## 0.17.0

A theme arrived as thirty-two articles and resolved to nine mechanisms, which is the ratio
worth remembering the next time a list is handed over.

Measuring coverage before writing anything found the GitHub Actions and package-registry
theme far thinner than its article count implied: two generic observations and a handful of
KEV exposures, and every observation sourced from one publisher. reviewdog and Trivy were
present only as exposure records -- identifiers carried, detection logic absent. Five named
campaigns resolved to nothing at all.

- **Eleven records and nine patterns, written by mechanism rather than by article.** Six of
  the thirty-two items describe the same tag-rewriting class from different sides, and a
  defender acts on the class, not the incident. The single most valuable check in the area
  needs no telemetry: resolve every external action reference to a commit and test whether
  that commit is reachable from any branch of its source repository. Tag rewriting cannot
  avoid leaving that trace, and it survives the actor force-pushing the original back.
- **Provenance verified correctly throughout an attack it did not stop.** Nothing was forged;
  the pipeline honestly built and honestly signed what a commit that never passed review told
  it to build. The pattern says explicitly that provenance verification is not a control
  against this, because the failure mode here is a defender crediting a green check for an
  attack it does not address.
- **Two records were edited rather than duplicated, and one of those edits changed a story.**
  A second publisher on the tj-actions compromise supplies a root-cause chain the corpus
  lacked: an earlier action's tag rewritten days before, and the credential taken from it
  used to rewrite the more widely used one.
- **A pattern this corpus calls the decisive step in service desk social engineering carried
  an empty marker list.** It named the step without saying how to see it. Four markers added,
  led by enrolment immediately preceded by a failed authentication -- a genuine user enrolling
  a device does not usually fail first.
- **Three renamed catalogue pairs would have split three records.** A rename fragments a
  record exactly as an acquisition does, the slug merge catches neither, and the only signal
  is the record count rising when no new product appeared. Mapped; the count held at 689.
- **Several sources answer in ways that read as clean negatives**, and that shape is the
  lesson rather than any one of them. A category path that 404s, a `lastmod` pretty-printed
  across newlines that a single-line pattern misses entirely, an asset re-save under an
  article's path that looks like the article being updated, a month archive that 404s where
  the feed works, and a site that refuses a browser user agent but answers its own collector.
  None fails loudly.
- **The sharpest instances of that were self-inflicted, and both are worth stating plainly.**
  A hand-rolled probe reported Sysdig's sitemap as carrying no blog entries, and this release
  briefly recorded that Sysdig had no listing route at all. It has one and always did: the
  sitemap carries 1,867 blog URLs emitted under the content host, and `collect.py` has always
  rewritten them -- the probe filtered on the wrong host and drew the opposite conclusion from
  the collector's own code. Then a route check on the cloud-abuse publishers reported four of
  six as dead, having probed RSS URLs for publishers whose registered route is the sitemap
  *because* their RSS is absent or a stub -- a fact recorded three lines above the table it
  was checking. All six answer. Both corrected the same day, and both left in the record
  rather than edited out, because the wrong version was committed and the reasoning is the
  reusable part.
- **Four instances of one error in a single pass is a rule, not a run of bad luck.** Forescout,
  Sysdig, the cloud-abuse routes and the Datadog `lastmod` all failed the same way: a fresh
  request went around a collector or a registered route, got an answer that looked like a
  clean negative, and was believed. **Read the registered route before probing, and prefer
  the collector over a fresh request** -- it encodes what the site needs and its comments are
  the record of why.
- **`academic_research` added to `source_type`**, in both the vocabulary and the schema enum,
  because the two are enumerated separately and nothing compares them. A paper describes a
  class of attack rather than reporting one intrusion, and both new records say in their
  caveats that their runtime markers are reasoned rather than observed.
- **The ATT&CK audit caught a revoked id introduced in this pass.** Eight migrations applied;
  this is the fourth batch to reintroduce one after that migration, which is an argument for
  running the audit as part of routing rather than at the end.

**1,201 records, 520 patterns, 0 validator problems.** Alert-fidelity marker coverage 496/497
(99%), technique resolution 413/415 with the two known Mobile gaps unchanged, vendor-run
contiguity 0, 32 tests green.

## 0.16.0

Predicted to be the exception to 0.15.0's correction. It is not, and the way it fails
completes the rule.

0.15.0 found that a vendor's research feed does not cover that vendor's products, and
flagged Forescout Vedere Labs as the likely exception on the reasoning that a company
selling device visibility researches devices. Taking it settles the question.

- **Forescout gained 0 records about Forescout**, from 511 posts of which 86 name the
  company in the title. Sixteen per cent self-reference against Zscaler's four per cent,
  and the same result: `consult.py "Forescout"` returns class-level matches only.
- **The second half is where the value is.** A cloud-security vendor researches threats
  generally and its output lands on nobody in particular; a device-security vendor
  researches devices and its output lands squarely on other vendors' devices. Lantronix
  0 to 2, OpenWrt 0 to 1, `ot.protocol_gateway` 7 to 10, `network.router` 125 to 128. A
  publisher is worth taking for the class it studies and never for itself.
- **A claim this project made in 0.13.0 is withdrawn.** Forescout was recorded as "the
  honest route into the HP/Aruba zero". It is not: both still hold 0 records and nothing
  in the 36 posts read touches them. Section 10's two routes for that gap stand unchanged.
- **A fifth way `lastmod` fails, and the worst so far.** 467 of 511 posts, 91%, carry an
  identical `lastmod` of 2026-03-31 -- forty distinct dates across five hundred posts.
  After absent sub-sitemaps at Unit 42, all-identical values at Wiz, none at all at
  Sysdig and bulk re-saves at watchTowr, this one makes nine posts in ten look as though
  they changed on one day. Diff the cached URL set instead; the collector caches the
  sitemap under a predictable name for exactly that.
- **Three records and three patterns from two posts.** A serial-to-IP converter that
  executes its own failed-login log line as a shell command, exploited between the
  vendor's patch and the public detail; a configuration interface shared across thousands
  of devices from different vendors, brute-forced at scale and filed under the
  distribution rather than any badge; and a 90-day honeypot measurement in which 97% of
  sixty million events were fingerprinting probes, and classifying them out changed which
  device looked most attacked.
- **`pat-perimeter-device-noise-floor-hides-the-signal` is the one to read.** It is an
  analytical constraint rather than a detection: rank targets on the residue after the
  automated floor is classified out, and keep the floor's counts, because a change in its
  composition is an early sign that a botnet has added an exploit.
- **Two-axis slug scoring beat one axis decisively.** A research verb and a device noun
  together cut 511 posts to 29 and that shortlist was almost entirely right; research
  verbs alone added a further 77, mostly commentary. The title-level marketing filter
  caught only 15 of 511 and is not sufficient on its own.
- **1,187 records, 502 patterns, 0 validator problems.** Alert-fidelity marker coverage
  472/473 (99%), technique resolution 410/412 with the two known Mobile gaps unchanged,
  vendor-run contiguity 0, 32 tests green.

## 0.15.0

Taking a vendor's research feed does not cover that vendor's products, and 0.13.0 built
a shortlist on the assumption that it did.

Section 22 ranked eleven publishers against the demisto/content pack library, reasoning
that a vendor whose products appear as integrations is a vendor worth having research
from. This release takes the top two and the measurement says that conflated two
different questions.

- **Zscaler ThreatLabz was ingested in full and Zscaler went from 0 records to 0.**
  2 of its 50 posts name its own product and neither is about that product being
  attacked. `consult.py "Zscaler Internet Access"` returns 177 findings and not one is a
  Zscaler record; they are `network.proxy` class matches that were already there.
- **Okta Security went 1 to 2, because 33 of its 85 posts are about Okta.** That is the
  contrast that makes the point: a threat research arm writes about what its customers
  are attacked by, not about what its own products are attacked through. Section 23
  records it and the TODO entry that ranked the eleven has been corrected to say the list
  is a reading order for research value and not a plan for closing the 246-product gap.
- **Five records and four patterns**, all observations carrying detection logic. New
  vendors: Anthropic and Twilio. Okta 1 to 2, Cloudflare 4 to 5.
- **Four patterns the corpus had no word for**: a service-to-service RPC framework
  carrying a command channel, the operating system's own remote assistance utility
  invited by the victim, a one-time passcode legible in the console of the supplier that
  delivers it, and the chain of gates a mature phishing operation runs before it will
  serve you the page at all. Paste-and-run needed nothing new --
  `pat-page-written-clipboard-then-user-runs-it` already covered it.
- **The corpus now has two independent reports and one dataset agreeing on
  `workers.dev`.** A phishing-as-a-service platform used it as gatekeeper and lure
  loader, section 21 recorded a separate campaign fronted by the same provider, and the
  measurement of the public malicious-URL corpus put that namespace top at 78 of 150.
- **RSS is the route for both, which makes them the exception.** Sections 8, 17 and 22
  all record sitemaps beating feeds -- absent `lastmod`, all-identical `lastmod`,
  valid-but-empty feeds, 404s. These two publish working feeds with real dates.
- **New collector at `_ingest/zscaler/collect.py`**, handling both sources behind
  `--source`, routing every fetch through `curl` for the LibreSSL reason section 17
  records, and separating the cheap feed-only pass from the `--bodies` fetch so a delta
  check does not pay for article text.
- **1,184 records, 499 patterns, 0 validator problems.** Alert-fidelity marker coverage
  468/469 (99%), technique resolution 408/410 with the two known Mobile gaps unchanged,
  vendor-run contiguity 0, 32 tests green.

## 0.14.0

The research had been collected and licensed months ago and nobody had turned it into
records.

0.12.0 registered the staged cloud backlog and measured it: `cloud-native-research/` had
produced 5 records from 327 indexed posts, `offensive-research/` 3 from 207. This
release distils it. **18 records and 10 patterns, no new collection, no new licence
question, and no collector written.**

- **Three vendors go from nothing to something.** Amazon 0 to 10 records, Cloudflare 0
  to 4, Okta 0 to 1, and Microsoft 117 to 120 on the cloud identity plane. Every one is
  an observation carrying detection logic, so the exposure count is unchanged and the
  observation count moved for the first time in several passes: 281 to 299.
- **`consult.py "cloudflared"` resolves and answers.** `vendors=Cloudflare |
  products=Cloudflare Tunnel | classes=network.proxy`, 31 findings. Before this branch
  the word Cloudflare resolved to nothing at all and returned three findings, one of
  which mentioned it by accident inside a products list owned by vendor `any`.
- **51 aliases, and they landed before the records rather than after.** A vendor entry
  for Cloudflare and 50 product entries across the three platforms. The corpus had none
  for Cloudflare in any of its four tables, and AWS, Azure, Entra and M365 existed only
  as class aliases, which is the failure rule 5 of *Adding a new source* warns about.
- **The thin classes moved.** `cloud.iaas` 8 to 18, `cloud.identity` 11 to 20,
  `cloud.container` 7 to 10, `cloud.saas` 24 to 27.
- **The role balance barely moved, and that is the finding.** `inline_tool` 27 to 30
  against `victim` 1,082 to 1,093. Cloud research is still overwhelmingly written about
  the platform being attacked rather than the platform being used, and all three records
  that landed on the abuse axis are Cloudflare.
- **Ten patterns are new because the corpus had no word for them**, and the rest of the
  work reuses what was there: an API surface the audit log does not cover, privilege
  parked in a scoped container that resists review, compute abuse spread across services
  nobody watches, an infrastructure state file used as a credential store, a permission
  model spanning five planes with no joined view, a trust policy naming a wildcard
  principal, the directory synchronisation host as a bridge, a DNS record pointing at a
  released address, a managed build service running tenant code beside provider secrets,
  and a working TLS-terminated hostname the provider hands out with no account and no
  registration record.
- **Three quarters of the indexed cloud material produced no record.** Regrouped by class
  rather than by vendor, most of it corroborates what the corpus already held, and the
  Datadog Cloud Security Atlas entries are a misconfiguration catalogue rather than
  threat reporting. This is the section 17 rule applied and it is the expected outcome,
  not a shortfall.
- **The restricted library was left alone deliberately.** Its cloud slice holds match
  conditions the corpus does not have at all -- `GetSigninToken`, `CreateTrustAnchor` and
  `PutBucketPolicy` appear nowhere in it -- but placing them on public patterns either
  drops their provenance or names a source section 13 says must not be named. Parked in
  TODO.md as a disclosure decision with the measurement attached, and with the cheap
  option to try first.
- **1,179 records, 495 patterns, 0 validator problems.** Alert-fidelity marker coverage
  holds at 462/463 (99%), technique resolution at 404/406 with the two known Mobile gaps
  unchanged, vendor-run contiguity 0, 32 tests green.

## 0.13.0

Publishers had been picked because somebody had heard of them, never against a list of
what anyone actually runs.

Sections 8, 9, 16, 17 and 21 all chose their sources by reputation. Ask instead which
technologies a Cortex operator has deployed -- the demisto/content pack library is the
best proxy available, because a pack is evidence somebody runs that product and is
shipping its telemetry somewhere -- and the answer is different, larger, and measurable.
Section 22 picks eleven publishers that way.

- **902 of 1,234 live packs, 73%, resolve to zero records in this corpus**, and 891 of
  those resolve to no vendor at all. Narrowed to Palo Alto-supported packs in a security
  category it is **246 products this corpus can say nothing about**. Measured through
  `query.py`'s own `resolve()`, so the test is what a caller would actually experience,
  and the reproduction is in the section.
- **1,076 of 1,234, 87%, declare no `useCases`.** 668 of those are Palo Alto-supported.
  The integration library is a very large set of connections with no stated reason to
  connect them.
- **Zscaler ThreatLabz is the strongest find: 50 items, current to 2026-08-07**, and the
  run is campaign reporting with named tradecraft rather than product news. Two Zscaler
  packs sit at zero.
- **Okta Security is the more interesting shape: 85 items, much of it detection guidance
  rather than disclosure.** Identity is 47 packs and `identity.sso` holds 21 records.
  Okta is also the first link in the chain that reached Cloudflare in section 21.
- **Forescout Vedere Labs fixes a gap nothing else does.** 511 posts through
  `post-sitemap.xml`, because the blog RSS is empty. Its subject is OT, IoT and medical
  devices -- the class section 10 records as having almost no public compromise
  reporting, and the honest route into the HP/Aruba zero already tracked here.
- **A fourth failure mode, distinct from a bot challenge.** Trellix does not answer at
  all: `HTTP/2 stream 1 was not closed cleanly: INTERNAL_ERROR` over HTTP/2, and a clean
  25-second zero-byte timeout over HTTP/1.1, on the root as well as the blog. Akamai 403s
  every route over both protocols. Tanium 404s on feed and sitemap index alike. All
  recorded as unreachable, none as empty.
- **No PSIRT feed was registered, deliberately.** Every one of these vendors publishes
  one, and the corpus already runs 880 exposures to 281 observations. What is missing for
  these 246 products is what an attacker did with them and what it looked like in
  telemetry, which is in the research blog and not the bulletin.
- **Nothing ingested.** 1,161 records, 485 patterns, 0 validator problems, 32 tests, all
  unchanged.

## 0.12.0

Ask this corpus about the three largest cloud platforms and it has nothing to say.

`consult.py "Cloudflare"` prints `RESOLVED_TO: vendors=- | products=- | classes=-`. Not
a thin answer -- no answer, because the word resolves to nothing at all. `"AWS"` and
`"Azure"` each narrow to `cloud.iaas` and stop, and behind that class sit 8 records,
none of them AWS or Azure. `SOURCES.md` ran to 2,317 lines across 20 sections without
one occurrence of `cloudflare`, `aws`, `azure`, `amazon` or `entra`. Section 21
registers the sources that would fix it, with every route verified rather than named.

- **Zero records at `who.vendor` for Cloudflare, AWS and Amazon, across 300 vendors.**
  Cloudflare appears once in 1,161 records, as the string `Cloudflare Tunnel` inside a
  `who.products` list on a record owned by vendor `any`. The six Azure-flavoured records
  are filed under `Microsoft`.
- **The gap is an axis, not a vendor list.** `what.role` already separates the platform
  being hit from the platform being used, and the corpus is 1,082 `victim` against 27
  `inline_tool`, 25 `control_bypassed` and 19 `lateral_path`. Cloudflare is very nearly
  a pure `inline_tool` story, and that is the 27-record half.
- **Most of this was already collected and never distilled.** Four sources already in
  this file hold cloud material nobody turned into records: `offensive-research/` 3
  records from 207 indexed posts, `cloud-native-research/` 5 from 327,
  `detection-rules/` 3,137 rules used for corroboration only, and the restricted library
  at `Amazon/` 102 and `Microsoft/` 1,129. Registered and costed in TODO.md.
- **Six routes returned something a crawl would have accepted.**
  `aws.amazon.com/security/security-bulletins/rss` -- the widely cited path -- answers
  HTTP 200 with `text/html` and 317 KB of page shell; only `/feed/` is the feed, and it
  carries 96 items. The MSRC `/updates` index is sorted alphabetically by `ID`, so
  `value[-1]` is `2026-May` while the newest by date is `2026-Aug`. Netskope and
  Securonix serve valid, well-formed, empty RSS. Hunt.io's RSS 404s. Fortra 403s on both
  RSS and sitemap, which is unreachable and not empty. `cloudflare/advisories` looks
  maintained and has published nothing since 2023-09-07.
- **Patch-level feeds are recorded as the second priority, deliberately.** The corpus is
  already 880 exposures to 281 observations, and MSRC publishes 2,140 vulnerabilities in
  a single month. Ingesting it wholesale would worsen that ratio while saying nothing
  about how the platform is attacked.
- **abuse.ch URLhaus was measured and rejected as a class.** Of 14,605 URLs in the
  current dump, 150 sit on Cloudflare developer hostnames -- `workers.dev` 78, `r2.dev`
  56, `trycloudflare.com` 5, `pages.dev` 2. Volumetric indicator data decays and this
  corpus holds durable patterns, so it is recorded with its reason rather than taken.
  One finding survives the rejection: **R2 ranks second by volume and is named in almost
  none of the published research**, which is uniformly about Workers, Pages and Tunnels.
- **Nothing was ingested and no corpus file was touched.** 1,161 records, 485 patterns,
  0 validator problems, 32 tests, all unchanged. `consult.py "Cloudflare"` still resolves
  to nothing, which is the correct result for a registration pass and the proof that the
  TODO entry describes a live gap.
- **Two stale version claims fixed.** `SOURCES.md` said `Last updated: 2026-08-07` while
  its own table carried two 2026-08-08 syncs, and `README.md` said "Version 0.8.0"
  against a `SKILL.md` reading 0.11.3. The second is a recurrence of the defect 0.7.1
  fixed under the title *Three files, three different versions, none of them right*.

## 0.11.3

The third of the same defect, and the last one: `emit_xql.py` dropped blocks that no
counter admitted to.

0.11.2 recorded `--shape` filtering as accurate-but-incomplete and left it. It was the
same failure as the other two. `emit_xql.py <record> --shape correlation` over a record
holding two `single_event` blocks printed "0 block(s) emitted, 0 skipped for having no
markers": every number true, and together a description of nothing. The reader cannot
tell an empty record from a filter that matched no shape, and it is nearly always the
second, from a typo in the shape name.

- **The tally accounts for every candidate block.** `emitted + skipped + filtered` now
  equals every `how` block in the corpus, on both modes: 677 + 110 = 787 unfiltered, and
  375 + 110 + 302 = 787 under `--shape single_event`. The emitted figure agrees with the
  677 of 787 that `validate.py` reports for marker coverage, independently derived.
- **JSON mode never reported skipped blocks at all.** It counted only what it handed off,
  so a marker-less block vanished from the accounting entirely. Both modes now share one
  `tally()` and print the same three numbers.
- **An empty shape filter names the shapes that were there.** `--shape sngle_event` now
  answers with `2 filtered out by --shape sngle_event (shapes present: single_event)`,
  which is the whole diagnosis. `--shape` also gains help text; it is deliberately not a
  `choices=` list, because the vocabulary lives in the corpus and pinning it here would
  reject a shape the corpus legitimately gains.
- **Seven cases added to `tests/test_header_counts.py`**, five of which fail against the
  previous tally. The invariant is now arithmetic rather than a string comparison: what
  went in must equal what came out plus what was dropped, by reason.

## 0.11.2

The same audit, run across the other four scripts. One more was lying, in the opposite
direction.

0.11.1 fixed a header that counted the question instead of the answer. `query.py` had the
mirror of it: the count was of the full match set, printed above a listing capped to
twenty. `query.py "network.firewall"` announced 42 observations and printed 20, and
nothing said the other 22 existed.

- **`query.py` reports shown against matched.** `20 of 42 observation(s) and 10 of 40
  exposure(s) shown`, with an `OUTPUT CAPPED:` line naming the flag to raise, printed only
  when a cap actually bites.
- **The library block was the worse of the two.** It is capped at six and carried no count
  at all, so a Microsoft query showed 6 of 38 class patterns with nothing to suggest a 39th
  existed. It now reads `6 of 38 shown; raise --pattern-limit for the rest`.
- **`--json` ships a `counts` object.** A caller reading JSON cannot see a cap in the
  output the way a human sees a short listing, and these arrays are capped by default.
- **`consult.py`, `emit_xql.py` and `validate.py` were checked and are correct.**
  `consult.py` already tallies before truncating and says `shown of matched`, with a
  comment explaining why; `emit_xql.py` increments its counters at the point of emission;
  `validate.py` never truncates, verified by injecting faults and confirming the count
  matches the listing. Nothing was changed in any of the three.
- **New `tests/test_header_counts.py`** holds the invariant across all four scripts, so a
  cap added later cannot quietly acquire this defect. Four of its cases fail against the
  previous `query.py`.

## 0.11.1

The header denied the findings printed underneath it.

`advise.py` opened with `SHAPES: N`, where N was the number of free-text arguments passed.
Selecting exactly, which the bundle tells a caller to prefer, passes none: `advise.py
--attack T1190` returned 48 patterns under a header reading `SHAPES: 0`, and `--patterns
pat-webserver-spawns-shell` returned one. The caller contract added in 0.9.0 says to read
the header before the findings, so the first line read denied the answer below it.

- **The headline counts what came back.** `FINDINGS: N pattern(s) returned` replaces
  `SHAPES: N`, matching the key `consult.py` already prints. A new `SELECTED_BY:` line
  breaks that total down across exact pattern id, exact ATT&CK id and free-text guess, and
  still reports the argument count that used to be the headline.
- **Selection itself was never broken.** No pattern lookup, technique join or ranking path
  changed, and the corpus is untouched. This was one `print` reading the wrong variable,
  and it dates from before the exact-selection flags existed, when free text was the only
  way in and the two counts happened to agree.
- **`NO_MATCH` names the path that failed.** An exact selection returning nothing now says
  so, and says why an ATT&CK id can select nothing: it matches a pattern's own `technique`
  list, so a technique cited only by records selects no pattern. It previously reported
  "no pattern overlapped any shape" for an id that simply did not exist.
- **New `tests/test_advise_header.py`**, the bundle's first test. It holds the invariant
  that broke -- the header count and the number of `--- PATTERN_ID:` blocks below it cannot
  disagree, on any selection path -- plus the exit-1 contract. Eight of its eleven cases
  fail against the previous behaviour.
- **`SKILL.md` documents the header keys** and records that notes telling a caller to read
  `SHAPES:` predate this fix.

## 0.11.0

Response doctrine gets a home, and the twelve markers that had been standing in for one
are freed.

D3FEND answers which control applies to a technique. It does not answer the questions
that decide whether a response works: what order to act in, how widely to scope
remediation, and what not to do first. The corpus already knew those answers, written
from six government advisories, and had encoded them as prose inside `computed` marker
`expr` fields where nothing could query them and they reached a caller at `fidelity:
enrich`, the lowest tier.

- **New `corpus/reference/response-doctrine.json`**, 12 rules matched on a finding's
  product class and impact, each citing the advisory it came from. No new source was
  ingested: every rule was already in the corpus. `SOURCES.md` section 20 records it.
- **New `RESPONSE_DOCTRINE` block** in `consult.py` and `advise.py`. A Cisco ASA finding
  is now told that a factory reset is not eradication on a compromised appliance; an OT
  finding is told its emergency plan needs named degraded states.
- **Emission order is incident order, not lifecycle order.** Ordering by lifecycle put
  four PREPARE rules in front of the ASA reader and pushed the appliance-rebuild rule out
  of the shown set: the same truncation failure the D3FEND ordering exists to avoid.
  Preparation is read last because it is the part nobody can action during the incident.
- **Twelve markers removed from seven records.** Every emptied `how` block was
  `fidelity: enrich`, so no alert-grade block lost its markers and alert coverage held at
  438 of 439. One of the twelve was found only because the first pass left it behind:
  a second communications rule, about attackers contacting staff and customers directly,
  which is now its own entry.
- **`validate.py` gains `PLAN_ASSERTION`**, which fails a `computed` marker whose `expr`
  asserts a plan rather than computing over telemetry. The first version was inert:
  underscore is a word character, so `\bresponse_plan\b` never matched inside
  `response_plan_orders`. It now fires on every freed shape with zero false positives
  across all 1,161 records.
- **`TODO.md` records what was deliberately not done.** 485 boolean-true `computed`
  markers remain across 113 records. Most are defensible posture checks and the guard is
  narrow by design; whether `rule_shape: inventory` should carry its own marker type is
  a vocabulary question, and bulk-rewriting them would answer it by accident.

## 0.10.0

The consultation can now say what to do about a finding, not only how to see it.

Asked what to worry about with a Cisco ASA, the answer ran detection logic, markers,
telemetry, caveat, references, and stopped. Every finding already printed its ATT&CK
ids and D3FEND is keyed to the same identifiers, so the response half needed a
reference dataset and a lookup rather than a change to the record schema.

- **New source: MITRE D3FEND 1.5.0**, recorded in `SOURCES.md` section 19 with its
  licence. `corpus/reference/d3fend-countermeasures.json` ships 272 defensive
  techniques across 7 tactics, 392 ATT&CK ids mapped, 8,075 links, built by
  `_ingest/d3fend/harvest.py`.
- **New `COUNTERMEASURES` block** in `consult.py` and `advise.py`, and a
  `countermeasures` list in the `emit_xql.py` handoff. Entries carry the D3FEND id,
  tactic, name, definition and URL.
- **Ordered contain, eradicate, recover first**, which is not D3FEND's own order.
  D3FEND publishes Model, Harden, Detect, Isolate, Deceive, Evict, Restore, a
  defensive programme's order; this corpus is asked what to do once something is
  found. A truncated answer therefore loses the tail rather than the first step.
- **46% of findings join to nothing and say so.** D3FEND maps 214 of the 396
  technique ids this corpus cites. An unmapped finding reports the gap in D3FEND
  rather than printing an empty block, on the same rule as an empty resolve. The
  misses concentrate on network-device implants and container escape: `T1601`,
  `T1610` and `T1564` all return nothing.
- **SPARTA mappings dropped at ingest.** D3FEND also maps the space-system framework,
  whose ids look like `DE-0002`; 539 bindings had keyed 34 unreachable entries into a
  table only ever looked up by ATT&CK id.
- **Tactic resolution reads the OWL restriction, not the subclass chain.** Tactic
  membership is `enables some Harden` on an anonymous node, so walking
  `rdfs:subClassOf` alone left 58 of 272 techniques with no tactic. One remains,
  `D3-ARMA`, and one upstream label with no `D3-` node is dropped.
- `corpus/README.md` documents `reference/` for the first time, including that
  nothing in it is validated and that a missing file degrades rather than fails.
- Corpus counts in `SKILL.md` and the frontmatter description corrected to 1,161
  records and 485 patterns.

## 0.9.0

A caller-facing contract, and the selection reporting it depends on made honest.

The `cortex-content-pack-go-again` bundle reported that nothing here tells a calling
session that a free-text guess arrives in the same format as an exact match. It was right,
and checking the claim found the discriminator it named to be broken in a way that made the
report an understatement.

- **`MATCH_BASIS` could report a free-text guess as an exact selection.** `advise.py`
  distinguished the two by testing the overlap list against the sentinel `["exact"]`, and
  `"exact"` is itself a legal corpus token: it is five characters so it clears the length
  floor, and it is not a stopword. `advise.py "exact"` matched `pat-known-mutex-creation`
  on the word, then printed `MATCH_BASIS: selected exactly` under a
  `SELECTION: free-text-guess` banner, suppressing the VERIFY THIS IS THE RIGHT PATTERN
  warning in the one case it exists to serve. The basis is now carried as a string tag,
  which the token list can never equal.
- **`MATCH_BASIS` now says which exact selection was made**, `selected exactly by pattern
  id` or `selected exactly by ATT&CK id`. Both paths previously printed the same text, so
  the line a caller is told to read could not answer what it was being read for.
- **`--attack` with several ids labelled every pattern with all of them.** The banner
  joined the whole requested set, so `--attack T1211,T1059` announced `cites T1059, T1211`
  over a pattern citing one of the two, which is how a caller ends up citing a technique
  the corpus never connected to that pattern. Each pattern is now labelled with the ids it
  actually cites, and findings are grouped by that label.
- **New `## How to consult this skill` section in `SKILL.md`**, the first content in the
  bundle addressed to a calling session rather than to the session running the skill. It
  carries the in-session-only rule, which until now existed only in a caller's own notes;
  which script answers which question; `--have`; how to read `RESOLVED_TO` and
  `MATCH_BASIS` before reading a finding; and what to do when the corpus returns nothing.
- **Three conflicting claims about which script is "the default" are resolved by question
  rather than by precedence.** `consult.py` answers the technology question and resolves
  the term; `advise.py` answers the pattern question and selects. A caller took the
  scope-time question to `advise.py`, where it can only ever return a token-overlap guess.

## 0.8.0

A shipping review. Nothing was added to the corpus; what changed is what the bundle
claims about itself, what it carries, and what it checks.

- **`SKILL.md` told the reader to run a script that can never ship.** The maintenance
  section ended in `python3 _ingest/mitre-attack/audit.py --corpus corpus --apply`.
  `_ingest/` is staged outside the bundle by rule and is not tracked in this repository
  at all, so that command fails for everyone holding the bundle. The section is gone.
  A skill holder does not sync, ingest or re-audit anything: the corpus ships complete
  and a newer corpus arrives as a newer version. What remains is `validate.py`, which
  does ship and does run.
- **The bundle now discloses that it reaches the network.** `scripts/advise.py` shells
  out to `curl` to re-check cited URLs older than 14 days and writes the result back
  into `corpus/reference/url-liveness.json`. That is on by default and neither the
  network access, the `curl` dependency nor the write was mentioned anywhere, while
  `README.md` said "standard library only". Both files now state it and name
  `--no-verify` as the way to run offline and read-only.
- **The Detection Skills inventory is held as a source, not shipped as reference
  data.** `detection-skills-library.json` sat in `corpus/reference/` beside the ATT&CK
  technique file and the liveness cache, which are loaded at runtime. It is loaded by
  nothing: it is an upstream snapshot supporting a comparison nobody has run. It moves
  to the maintainer-side reference tree, which keeps it under version control and out of the
  bundle, and stops a third party's catalogue shipping inside this one.
- **`validate.py` resolves cited technique ids** against the shipped reference and
  prints `394/396`, with `--gaps` naming the two and the content citing them. Reported,
  never fatal, because the reference is deliberately Enterprise and ICS only and a
  Mobile id is out of scope rather than wrong. The count is derived, so the
  corpus-state table can no longer drift from it the way it did when it read 395 of 395.
- **`--gaps` did not work.** It was read from `sys.argv` while argparse rejected it as
  unrecognised, so the marker-coverage line had been recommending a flag that exited
  non-zero. It is a registered argument now.
- **Restricted-source rule 4 is enforced and three records were brought into line.**
  `corpus/README.md` requires month precision at finest on restricted records, because
  an exact date plus a subject line approaches a fingerprint. Nothing checked it, and
  three carried `2026-08-01`. They are now `2026-08`, and `validate.py` fails on any
  restricted record with day precision. The two records at `year` precision are
  coarser than the rule and were left alone.
- **Counts and headings corrected.** The frontmatter description and `README.md` both
  said 1,155 records and 483 patterns against an actual 1,161 and 485. `SKILL.md`
  promised "nine answers" above a ten-row table, and `corpus/README.md` promised
  "three rules" above four. `SOURCES.md` is no longer referenced from any shipped
  file, so the bundle reads coherently without it.

## 0.7.1

Advisory sync to 2026-08-05, and the router that would have corrupted it.

Six records, four patterns and one alias fix out of a four-day window, plus a
catalogue refresh. The corpus goes from 1,149 records and 480 patterns to 1,155 and
483, with the validator still reporting no problems and all 395 cited technique ids
resolving against ATT&CK v19.1.

- **The merge router was left behind by the 0.7.0 consolidation and is fixed.** It still
  wrote `observations/<vendor>.jsonl`, so the first ingest after 0.7.0 would have
  recreated all 276 vendor files; since every loader globs `observations/*.jsonl`,
  each record would then have been read twice. The 0.7.0 note that no code changed
  was right about the loaders and wrong about the writer. It now writes the one file,
  never sorts, and inserts a new record into its vendor's existing run so the
  grouping contract in `corpus/README.md` survives. Verified against a scratch copy
  before being run for real: same 1,149 ids in the same order, one file, nothing
  added.
- **CISA KEV refreshed**, catalogue 2026.07.29 to 2026.08.04. Four new identifiers,
  23 records changed. `RENAMED_PAIRS` in the generator stops an acquisition splitting
  one product across two records -- CVE-2026-9198 arrived filed under IBM while five
  earlier Langflow identifiers sat under Langflow, and the existing slug merge could
  not see it because that merge requires the vendor string to already match.
- **New records.** Water-sector PLC lockout by credential and address change (CISA);
  direct-to-IP command and control, carrying the base rate that makes the older
  no-DNS hunt practical, and attacks on synced passkeys, the corpus's first record on
  passkeys or WebAuthn (Unit 42); adversary use of AI assistants and the artefacts
  they leave on disk (Talos); Cisco Secure Firewall Management Center static
  credential (Horizon3); cPanel/WHM authentication bypass exploited through providers
  (ACSC).
- **New patterns**: controller credential changed to lock out the owner, a passkey
  assertion the user never approved, and AI assistant client artefacts recording
  operator intent. `pat-device-renamed-to-deny-owner-access` generalised from renaming
  to renaming or readdressing, now that a second source documents the same intent
  through the address field.
- **`cPanel` resolved to nothing**, because the catalogue files the product under
  WebPros and no alias bridged the two. Two of the new records upgrade an identifier
  the corpus held only as an exposure with no detection logic; this one also fixed the
  lookup. First attempt at the alias wrote plain strings into `product_aliases`, whose
  values are objects -- the validator passed and the resolver crashed, which is worth
  knowing about where those two disagree.
- **Two sources moved from `complete` to `active`.** CISA's joint advisories and the
  KEV feed both publish continuously; marking them complete meant they went unchecked
  beside genuinely finite sources. Complete now means only frameworks and archives
  that do not grow.
- Three enumeration traps recorded in `SOURCES.md`, each of which produced a
  confident wrong answer before being caught: a sitemap index parsed as a sitemap
  reads as "no new posts", a site that regenerates wholesale reports every URL as
  changed today, and cyber.gov.au writes hrefs unquoted so a quote-anchored pattern
  matches nothing on a page that rendered fine. Sysdig could not be reached at all and
  is recorded as unreachable rather than as empty.

## 0.7.0

One observations file instead of 299, because the upload has a file limit.

Packaging the bundle as a skill fails with "zip contains too many files (maximum
200)". It held 318 tracked files, 299 of them one-vendor-per-file observations, and
226 of those held one or two records each. Nothing else was close to a limit: 1.2 MB
zipped against a 50 MB ceiling, a 349-character description against 1,024, and a
244-line SKILL.md against a 500-line guideline. The count was the only thing over.

- `corpus/observations/*.jsonl` merged into `corpus/observations/observations.jsonl`.
  The bundle is now 20 files.
- No code changed to make this work. Every loader already globbed
  `observations/*.jsonl` and nothing keyed on the vendor filename, so one file in the
  same directory needs no new path handling and leaves sharding available later.
- Record order is preserved exactly: files in the sorted filename order the loaders
  used, records in their original order within each file. A first attempt sorted by
  vendor and id instead, which changed intra-vendor order and silently reordered the
  reference lists `advise.py` prints -- enough to change which references survive a
  truncation. Ordering that downstream output depends on is not free to improve.
- Verified rather than assumed: the canonicalised record set hashes identically
  before and after, and `query.py`, `consult.py` and `advise.py` produce byte-identical
  output. The only intended difference is the validator now reporting 1 file rather
  than 299.
- Validator problem locations now name the record: `observations.jsonl:601
  (exp-kev-ivanti-pulse-connect-secure-and-pulse-policy-secure)`. The vendor used to
  come free from the filename, and a line number in a 1,149-line file replaces it
  with nothing.
- `corpus/README.md` records the new contract: group by vendor within the one file,
  `grep '"vendor": "Cisco"'` to navigate, `who.vendor` is `any` for class-level records.

## 0.6.1

Documentation reconciliation. Four releases of work had shipped in `SKILL.md`
without reaching this file, and the three places that state a version disagreed:
frontmatter said 0.6.0, this file stopped at 0.2.1, `README.md` said 0.1.0.

- Entries for 0.3.0 through 0.6.0 written from the commits that made them.
- `README.md` status rewritten. It described a bundle whose corpus population was
  in progress and whose only scripts were the validator and the lookup, which has
  not been true since 0.2.0, and it did not mention `consult.py` or `advise.py` at
  all -- the two scripts a caller is now told to run.
- Corpus counts corrected wherever stated: 1,149 records across 299 vendor files
  and 480 patterns, against the 1,143 and 474 carried since 0.3.0. The six records
  and six patterns added since were the Talos CTIR trends distillation, the source
  control and CI/CD material, and the offensive research batch.

## 0.6.0

Answering another session's consult in one call instead of five to eight.

A rule-design consult was costing five to eight sequential tool calls, each a
hand-written search re-deriving the same three things. Measured first: the corpus
loads in 0.08s and `consult.py` runs in 0.14s, so none of the cost was compute.

- `scripts/advise.py` -- one invocation returns, per pattern, CORROBORATED (public
  rule-library counts) and OBSERVED (citing records with URLs) as separate claims,
  plus full logic, verbatim caveat, resolved ATT&CK links, telemetry and DATA_GAP.
  Cached runs are 0.06s.
- Free-text behaviour search was built first and demoted after testing. This corpus
  names patterns evocatively rather than descriptively, so a search for audit-trail
  destruction returned a cloud-network-exposure pattern whose logic contains the
  phrase "provider audit trail". Two scoring attempts did not fix it. Free text is
  kept, labelled `SELECTION: free-text-guess`; `--patterns` and `--attack` select
  exactly.
- URL liveness cached with a date in `corpus/reference/url-liveness.json`, re-checked
  after 14 days. The saving is about a second and a half per consult; the larger
  benefit is that a URL which was live and is now empty is a deprecated technique,
  which is how the T1562 family was caught.
- Three-letter function words passed the stopword floor in the shared matcher, so
  "the" appeared in MATCH_BASIS lines as though it were evidence.

## 0.5.0

Coverage matching: four defects, and richer input now helps instead of hurting.

Reported as one false positive -- a container-escape technique claiming a
rootkit-concealment pattern because both say "kernel" and "module" -- and found to
be four.

- Tautological overlap counted as a match. "CredentialsInFiles" claimed a repository
  scanning pattern on the tokens "credentials, files", which is the caller's own
  label restated. Per-token rarity did not catch it because both tokens are
  individually uncommon. A postings index and a selectivity test now require the
  overlapping tokens to narrow the corpus to three patterns or fewer.
- Ordinary English leaked in and inverted the point of the exercise. Requiring two
  overlapping tokens of which merely one was rare let "the", "and" and "for" carry
  matches, so supplying richer prose made the verdicts worse. Overlap now counts
  corpus-rare tokens only.
- Marker literals were tokenised into prose, so `.credentials$` and `config.sh`
  became words a caller's description could match. Computed marker expressions are
  prose and are kept; literal values are not.
- The separator shredded entries. Splitting on comma and newline together broke the
  rich "Name: description" form at every internal comma, and the fragments still
  matched. More than one non-empty line now means newline is the separator.
- `--covered` accepts a file, one entry per line, optionally
  "Name: what artefacts it produces".
- Residual stated rather than implied. Against a 78-item summary inventory: 436 no,
  36 partial, 8 yes, of which roughly half the yes verdicts are correct on review.
  Every yes prints its basis, coverage never removes a finding, and `SKILL.md` says
  to audit them rather than act on them.

## 0.4.0

Gap-aware ranking, because criticality and coverage are orthogonal.

`consult.py` ranked only by intrinsic criticality, which rewards prevalence, which
is highest exactly where a well-covered caller has already built something. Measured
against a tool with 78 registered techniques, all fourteen items assessed as genuine
gaps ranked outside the top 30.

- `--rank-by gap` adds a novelty term driven by `--covered`. `--rank-by criticality`
  stays the default, because most callers ask about a technology rather than about
  their own coverage.
- Coverage is matched on two axes with deliberately different weight: a hit on a
  pattern's name or description is coverage, a hit on its supporting prose is partial
  and labelled weak evidence.
- Identifier agreement alone is always partial, never yes. An ATT&CK id is coarser
  than a pattern, so a caller holding any T1611 technique would otherwise suppress
  every container-escape finding including the routes they have not built.
- Sibling identifiers matched in both directions, so a caller holding T1068.001, .002
  and .003 was treated as partially covering plain T1068. Only parent-covers-child
  survives.
- A fixed stopword list could not keep up -- "RunCMaskedPathEscape" claimed every
  pattern containing "path" and "run". Replaced with corpus frequency: a token
  appearing across more than 8% of patterns cannot discriminate.
- Four characters was too high a floor for a distinctive token, so "PamBackdoor"
  reduced to one token and could match nothing. pam, ssh, dns, suid and cron matter.
- The coverage tally counted findings surviving `--limit`, reporting the coverage of
  the output rather than of the match set.
- The demotion multiplier was softened from 0.2 to 0.3 after measuring it: at 0.2 a
  wrong yes buried a genuine gap 88 places down.
- `PATTERN_ID` added to every finding. Without it a consumer could read the detection
  logic but had no stable handle to cite back, since one record cites several
  patterns.

## 0.3.0

A fixed consultation format, emitted by a script rather than written by hand.

Consultations were going out as prose. The consumer is a detection engineer or
another agent writing rules in a language this skill does not know, and prose is not
parseable; the shape also changed with whoever answered.

- `scripts/consult.py` emits nine blocks per finding, always the same nine, in the
  same order: ACTION, RATIONALE, DETECTION_LOGIC, MARKERS, TELEMETRY_REQUIRED,
  DATA_GAP with RECOMMEND_ACQUIRE, CAVEAT_VERBATIM, REFERENCES, METHODOLOGY.
  Verified across thirty findings: every key appears exactly thirty times.
  `SKILL.md` now says to run it rather than compose the blocks by hand.
- Ordering is computed, not chosen. A scoring function applies "most critical and
  most recent" and every finding prints its PRIORITY_BASIS inputs.
- Telemetry the caller does not have is a finding, not a silence. `--have` declares
  what is collected; everything required and undeclared becomes a DATA_GAP naming
  the connector to acquire.
- References are built for code comments: publisher, title and URL, plus a resolved
  framework link per technique.
- CRITICAL was floored at 9.0 when the maximum achievable score is 8.5, so it was a
  band nothing could reach and every finding silently capped at MODERATE.
  Recalibrated against the achievable range, with the arithmetic documented.
- T0883 matched the generic ATT&CK pattern before the ICS one and was labelled
  enterprise. Order in the framework table is now load-bearing and says so.
- ATLAS identifiers had their dot rewritten as a path segment, producing
  `atlas.mitre.org/techniques/AML/T0051` for what should stay `AML.T0051`.
- `load_corpus` returns two values, not three.
- Added snort, suricata and IDS/IPS class aliases. There is no `security.ids` class
  in the vocabulary, so these resolve to `network.firewall` -- imprecise, but an
  answerable question beats an empty result that reads as absence of coverage.

## 0.2.1

Three resolver defects, all found by testing the skill against a vendor the corpus
does not cover.

- **202 aliases could never match.** Aliases are tested against normalised query
  text but the keys were stored raw, so any key holding a hyphen, bracket,
  ampersand or accent was unreachable -- `7-zip`, `d-link`, `serv-u`, `big-ip`,
  `pan-os` and 197 others. The failure hid because a few had a separately written
  normalised twin, so the table looked like it worked. Keys are now normalised at
  load in `normalise_alias_keys()`.
- **Free text matched as a substring, not a word.** `term in haystack` let short
  terms match inside longer words, so `app` hit `appliance` and `application`.
- **Class prefixes were free-text tokens.** `app.cicd` normalises to `app cicd`,
  making `app` match every `app.*` record. Classes now contribute their suffix,
  which carries the meaning; the prefix is taxonomy scaffolding and names nothing.
  A CI/CD class query returned 58 records, of which 1 genuinely held the class; it
  now returns 11, all genuine.
- Brief output marks a record that matched on free text alone, so a weak match is
  visible rather than ranked silently beside a vendor or class match.
- **A vendor-only query returned no patterns at all.** The library-pattern block
  keyed on classes resolved from the query text, so "SAP" and "Splunk" matched
  records and offered zero patterns. Classes now fall back to those the matched
  records declare, which is the class-level transfer the skill exists to do.
- **Four product aliases carried no `product_class`** -- `fortigate`, `okta`,
  `proficy`, `rclone` -- so they resolved to a vendor and product but could never
  reach a class. Okta returned nothing whatsoever despite 11 relevant records.
- Added `app.cicd` class aliases: CircleCI, Azure DevOps, Azure Pipelines, GitHub
  Actions, GitLab CI, Argo CD, Buildkite, Travis CI, Drone CI, Bamboo. Added
  class aliases for Snowflake, Databricks, Salesforce, ServiceNow, Tenable,
  Qualys, Rapid7, Nessus, Duo, Ping Identity, HashiCorp Vault, CyberArk, Thycotic.

## 0.2.0

Corpus populated and the rule-authoring handoff delivered.

- 960 records across 289 vendor files, 425 patterns, 0 validator problems.
- Two record types: `observation` carries detection logic, `exposure` is a
  vulnerability fact generated in bulk from the KEV catalogue so a product stays
  findable by name.
- Marker contract: typed `markers[]` against a closed vocabulary plus a
  `rule_shape`. Generic markers live on the pattern, source-specific literals on
  the record, and the handoff supplies both unmerged.
- `scripts/emit_xql.py` -- the handoff a rule-authoring skill consumes. It does not
  write rules; the XQL it prints is a skeleton for inspection.
- `corpus/reference/attack-techniques.json` -- 976 ATT&CK v19.1 techniques with log
  sources and locally-tunable elements, so a rule author needs no ATT&CK copy.
- `scripts/query.py` is now brief by default, one line per record, with `--full` for
  detail. A typical query cost roughly 9,700 tokens to read and now costs 2,200.
- `SOURCES.md` -- sync manifest for every upstream source. `TODO.md` -- scoped but
  deferred work.
- Sources ingested: a licensed OT intelligence subscription, CISA joint advisories,
  CISA KEV catalogue,
  CISA malware analysis reports, MITRE ATT&CK v19.1, SigmaHQ, Splunk
  security_content.

## 0.1.0

First cut of the bundle.

- Corpus format defined: one record per advisory-observation, JSON Lines, six top-level keys (who, what, how, where, who2, when).
- `corpus/schema/observation.schema.json` -- the record contract.
- `corpus/schema/vocab.json` -- closed vocabularies for product class, role, impact, attack surface, evidence type and actor type.
- `corpus/schema/aliases.json` -- maps ordinary words to a vendor, product or product class.
- `corpus/patterns/patterns.jsonl` -- shared detection scenarios, the mechanism by which overlapping records collapse.
- Restricted-source handling: abstract citation, no URL, no report identifier, wording written fresh. Enforced by the validator.
- `scripts/validate.py` and `scripts/query.py`, Python 3.9+ standard library only.
- One seed record, marked `seed` pending source verification.

XQL emission is not yet implemented.
