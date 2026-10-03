<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# How a question becomes a lookup

Read this when `RESOLVED_TO:` names something you did not ask about, when a `GATED:` line
needs explaining to a caller, or before adding an entry to `corpus/schema/aliases.json`.

Every later step amplifies what the resolver decides. A false product becomes a confident
product answer, a false class sets the plane the whole consultation is about, and a false
vendor pulls that vendor's history in as though you had asked for it. So the resolver is
conservative where a word is also an ordinary word, and it says what it did.

## What resolves, in what order

`scripts/query.py` `resolve()`, which `consult.py` shares rather than reimplements:

1. **Product aliases**, longest first. A shorter alias lying wholly inside an admitted longer
   one does not also resolve when it names another vendor: "prisma sd wan" is not Cisco's
   SD-WAN, and "barracuda email security gateway" is not Check Point's gateway. Inside a
   longer name of the same vendor it resolves only where the words say it is a separate
   product (a composite such as "apex one and officescan") or it is the same product spelt
   another way ("junos os" inside "juniper junos os"). Otherwise the longer name is a
   different product line: "ivanti endpoint manager mobile" is EPMM and not EPM as well, and
   "azure active directory" is Entra ID and not on-premises Active Directory, which sits on
   another plane.
2. **Vendor aliases**, with the same rule against a longer name of another vendor.
3. **Class aliases**, then **sector aliases**, each blanking what it matched so a shorter
   overlapping alias cannot also match. A sector alias is not matched inside an admitted
   product name (0.44.0): "Cisco Firepower Threat Defense" was a question about the defence
   sector and ordered its findings by it, and 13 product aliases, "Ruby on Rails" and "Kerberos
   Key Distribution Center" among them, named a sector from their own words. The same word
   outside the name still names the sector ("FortiGate in a defense contractor"). A class word
   inside a product name still reads as a class, and a vendor's name still names a sector:
   seven do, "NextGen Healthcare" among them.

Every word an admitted alias matched is **consumed**. Free-text search then uses only the
words left over. Until 0.43.0 every word of the question was searched as free text, so
"Check Point firewall" searched `check` and `point` through every record's prose and matched
188 findings on "entry point" and "integrity check", and the plane answer depended on how the
vendor was spelt. An admitted vendor or product is still searched, as its whole phrase and in
names only: a record naming "Fortinet appliances" is reached by "Fortinet", while `point` no
longer reaches "Access Point" or "point of sale".

A word left over after the technology resolved is what the caller asked *about* it: "boot
image implant" after "Fortinet FortiGate". It is tested against the tags, pattern wording and
summary of every record that matched by name, reported as `refine term <word>`, and scores
nothing. It breaks ties, and `consult.py` prints it as `refined_by=` on `PRIORITY_BASIS`.

## What the header says about it

- `RESOLVED_TO:` -- the vendors, products and classes the question was taken to mean.
- `RESOLVED_BY:` -- the alias behind each of them, and for an ambiguous one what admitted it:
  `ios -> product Cisco / IOS (beside cisco)`. Read this against the words you wrote.
- `GATED:` -- printed only when an alias matched the words and was refused, with the reason:
  `exchange (product Microsoft / Exchange Server: an ordinary word, with no name or
  unambiguous product of its vendor within two words of it)`. A refusal of a word some other
  alias accounted for is not printed: "firewall" is refused as Sophos's product and resolved
  as a class on every firewall question, and saying so each time would bury the refusals that
  matter.

`query.py` prints the same two lines as `resolved by:` and `gated:`, and its `--json` carries
a `resolved` object with `vendors`, `products`, `classes`, `sectors`, `terms`, `resolved_by`
and `gated`.

`consult.py` also prints `sectors=` on `RESOLVED_TO:`, `UNMATCHED_TERMS:` (the question's
words that reached no record, after the ones a resolved alias consumed), and, for a question
naming only a vendor, `CLASSES_FROM_VENDOR:`. A vendor alias carries no class, so "Fortinet",
"Cisco" and "Siemens" reached no class analogue and left four or five loci absent. The
classes are the first-listed product classes of the observations filed under the vendor,
those two or more of them list first, or the three most frequent where none is, never a
non-product class. They are used for scoring only: `RESOLVED_TO` still reads `classes=-`,
and the vendor's own findings stay `vendor` and lead.

## What kind of answer it is

Every finding prints `MATCH_TIER:`, one of the tiers `MATCH_TIERS:` counts:

| tier | the record | group |
|---|---|---|
| `product` | names the product asked about | 0 |
| `vendor` | names the vendor asked about, in a class asked about or with none asked | 0 |
| `class` | shares a class asked about and is about another product | 1 |
| `vendor-other-class` | names the vendor in none of the classes asked about: its other product lines | 1 |
| `tag`, `name-fragment`, `pattern`, `summary` | was reached by the question's words, not its names | 2 |

Where the question named a product, `vendor` is the vendor's other products in a class asked
about: `MATCH_BASIS` says "but not the product asked about", `RESOLUTION` reads `VENDOR-LEVEL`
when nothing else names it, and `LOCUS_SUBJECT` does not count it beside a `product` finding
(`references/locus-and-coverage.md`). A vendor the question named without a product of it is
still what was asked: "Cisco ASA and Fortinet firewall" counts Fortinet's records.

Until 0.43.0 the first four were one tier, `identity`, labelled "named this technology":
"PAN-OS" printed `identity=74` over 3 findings naming PAN-OS and 71 other vendors' firewalls.
`ORDERING` sorts by group before anything else, because no weight could promise that a record
naming the product outranks a fresher analogue: "Fortinet FortiGate" put a Cisco record at
rank 1 and Fortinet at ranks 7 and 9. Inside group 0, on a question naming a product, a
`vendor` finding about another of the vendor's products follows the findings naming what was
asked, and its `PRIORITY_BASIS` says "after what was asked": 0.43.0 left the two unordered,
and of the 95 product questions holding such a finding, 66 led with it, the management centre
at ranks 1 and 2 of "Cisco ASA" among them. It stays in group 0, ahead of every class
analogue, because a product nothing names is answered by its vendor's records first: "Palo
Alto Networks Panorama" keeps the GlobalProtect record at ranks 1 to 3. Within a group,
records seen in a sector the question named come first, then records carrying more of the
question's leftover words, then the platform fit, then the score. The fit reads the block's
markers, or its pattern's, with `query.py`'s classifier against the platform the question
names through the `platform_of` table: +1 written for it, 0 where either side names none, -1
written for another.
`PRIORITY_BASIS` prints it as `platform_fit=` with the platforms it read. It is a key and not
a weight, so it never lifts a finding over a stronger group; until 0.43.0 the findings had no
such term, though `query.py` and the LIBRARY block did, and "Linux kernel" led with a Chrome
record's Windows blocks. Under `--rank-by gap` a finding `--covered` says is implemented drops
one group, so the covered findings of the named group compete with the analogues, where the
gap multiplier sinks them; without that the grouping returned what the caller had already
built.

The `RESOLUTION:` mode is decided from the same tiers, in this order:

1. A class declared with `--as`: `CLASS-LEVEL (declared via --as ...)`.
2. A product resolved: `product` when a finding names it, otherwise `VENDOR-LEVEL` when a
   finding names its vendor. 245 of 846 product questions printed `product` with no finding
   naming the product, "Fortinet FortiMail" among them, answered from FortiOS and Outlook.
3. Only vendors resolved: `product` when a finding names the vendor in an asked-for class, or
   none was asked; `VENDOR-LEVEL` when every one is the vendor's other lines. Never `product`
   on those alone, or one record of Android's other lines would make the Guardsquare
   question's class-level answer a product one.
4. A class resolved: `CLASS-LEVEL (inferred)`.
5. A name resolved and nothing above held: `NAME_WITHOUT_OBSERVATIONS` when free text reached
   findings, `EXPOSURES_ONLY` when exposure records name it, else `UNRESOLVED`.
6. Nothing resolved: `mechanism` when free text reached findings, else `UNRESOLVED`.

An exposure is a vulnerability fact with no detection logic and never becomes a finding, but
it does name the technology, so the header counts it. "Linux kernel" was told the corpus
holds no record naming it over exposure records that do, and 195 of the 1,164 distinct
vendor and product resolutions of the alias table reached exposures naming them and exited 1
as `UNRESOLVED`, Sitecore and Zoho among them. An exposure names what
was asked when it is the product asked about, or the vendor's in a class asked about, or,
when the question named only the vendor, any of the vendor's. `EXPOSURES_ONLY` exits 0,
prints no findings, lists the exposures in `EXPOSURE` blocks and names the classes they carry
for an `--as` re-ask, or `--as app.mdm` where a handset name stands beside the vendor. A handset record `corpus/schema/scope.json` keeps out of scope is not
counted as naming it: a name held only by such records is `UNRESOLVED`, and says why, and so is
a bare handset name, which is never told to add an alias, though a name beside it that reached
no record is offered as one on the condition that it manages the devices
(`references/exposures.md`). A
consultation exits 1 only when there is no finding, no exposure naming the technology and no
library pattern of its class; `references/exposures.md` has the blocks' contract.

`CLASS_LEVEL_WARNING:` is printed for every mode but `product` and `mechanism`, worded for the
mode. It is the one key a consumer gates on, so a vendor-level answer uses it too rather
than a second key those consumers would never read. A mechanism answer whose unmatched words
include one written with a capital or a digit prints `MECHANISM_WARNING:` and
`CANDIDATE_CLASSES:` instead: "Zorblax Edge Gateway 9000" was answered from other vendors'
edge devices, reached by "edge" and "gateway", while "Zorblax" and "9000" reached nothing.

## Words that are names and ordinary words

**Product aliases.** `ambiguous_aliases` lists the product aliases whose ordinary meaning
competes with the product. One resolves only within two tokens of a name for its vendor --
the vendor's whole name or any vendor alias of it, never a single token of a longer name --
or within two tokens of an unambiguous product alias of the same vendor. So `Cisco IOS` and
`MS Word` resolve, "iOS apps", "an AV viewer" and "key exchange" do not, and "Ivanti EPMM and
Sentry" and "Cisco ASA and IOS" name Sentry and IOS although three words separate each from
its vendor. Anchoring from anywhere in the question was measured and refused: Microsoft's
hundred-odd unambiguous aliases anchored its eight gated ones, "Cisco ASA VPN users on iOS and
Android phones" resolved Cisco IOS, the 0.29.0 defect again, and "edge devices ... domain
controllers" resolved Microsoft Edge and the browser class. Inside the window the words cannot
tell a list from a compound, so two false anchors remain and a test pins them as still
failing: "SharePoint project sites" resolves Microsoft Project, and "Active Directory and edge
VPN appliances" resolves Edge. A vendor alias does not anchor: "Guardsquare ... Android and
iOS apps" names the Android vendor and must not mean Android Runtime.

The list held 41 words from 0.29.0 on. 0.43.0 added 35, after checking every single-word
product alias against a dictionary: 16 dictionary words (quantum, exchange, horizon, cursor,
ray, dawn, ignition, amplify, triton and seven more), five non-dictionary ordinary words
(pixel, airflow, superset, eos, epm) and fourteen generic multi-word names (security gateway,
email server, network attached storage, backup and replication, sd wan, endpoint manager and
others). Longer names keep each product reachable without its vendor: quantum security
gateway, omnissa horizon, cursor ide, ivanti epm, ivanti endpoint manager mobile, exchange
online, veeam backup and replication. A gate can also take a product from its own vendor's
natural phrasing: "Barracuda email security gateway" reached Barracuda's product only through
Libraesva's alias, and once `email security gateway` was gated it resolved the vendor and the
class alone, so `barracuda email security gateway` is Barracuda's alias now.
`_ambiguous_reviewed_keep` lists the 22 dictionary words reviewed and kept ungated, each with its
reason, and a test fails on any dictionary-word alias in neither list. Two of the kept words
are **known false positives**, kept because gating them would lose the commonest way of naming
the product: "maintenance windows" resolves Windows and "threat outlook" resolves Outlook. A
test pins both as still failing.

**Vendor aliases.** `ambiguous_vendor_aliases` lists vendor aliases that are ordinary words:
`ms` (milliseconds), `pan` (a card number), `progress`, `array`, `pulse`, `elastic`, `sentinel`
(Microsoft's SIEM, not Thales) and ten more. One never adds a vendor on its own; it is a no-op
beside a product or fuller name of the same vendor ("PAN Panorama", "Progress MOVEit"), and it
still counts as a name that corroborates that vendor's ambiguous products. Bare "Progress" or
"Elastic" therefore resolves no vendor: write "Progress Software" or "Elastic Stack". A gated
vendor word needs a product of its own to sit beside: "Quest KACE" resolved nothing until
`kace` became a product alias, and now names the KACE appliance and, through it, Quest.

**Class aliases.** `ambiguous_class_aliases` gates a class alias by one of three modes:

| mode | the alias resolves | examples |
|---|---|---|
| `upper` | only where the question writes that word in capitals | IDS, IPS, RADIUS, AD, RAN, SIM, CI |
| `refuse_near` | unless a listed word sits within two words | actuator (not beside spring boot), endpoint (not beside api or manager), tenant, library, pipeline, workflow, package, pam, udm, routing |
| `require_near` | only beside a listed word | controller (a PLC beside plc, s7, simatic, plant and similar; a domain, ingress or baseboard management controller everywhere else) |

`upper` depends on the caller's casing, and is read at the word that matched, never anywhere
else in the question. An `upper` rule with `acronym_plural` also admits the acronym's plural,
capitals and a lower-case s: "ADs", "SIMs", "RANs", "IDSs" and "IPSs". `ci` does not take it,
because "CIs" are configuration items. **A consumer that lower-cases its questions loses the
IDS, IPS, RADIUS, AD, RAN, SIM and CI routes**; name the class instead, or pass `--as`.
`ews`, bare `directory` and `teams` were deleted rather than gated, because each collides with
a name (Exchange Web Services, directory traversal, red teams) and each class keeps other
routes; `ldap` was added. `sensor` and `instrumentation` went in 0.30.0. Two words are known
to still resolve falsely and are pinned as failing by `tests/test_class_aliases.py`: `relay` (a
mail relay before a protective relay) and `switch` (a verb), with `switches` and `switching`.
When either is gated those tests fail, and the fix is to invert them.

**Plurals that are other words.** A trailing `s` is optional on every alias, except those in
`singular_only`: `ci` is not CIS, `ad` is not "ads" or an NTFS ADS, and `hf` (Hugging Face) is
not Rejetto's HFS. The lower-case plural singular_only refuses is not reported under `GATED:`,
since it is another word rather than a refused name.

**Whitespace.** Punctuation normalises to a space and runs of spaces collapse, so "Backup &
Replication", "Backup&Replication" and "Check  Point" match their aliases.

**A refused word stays refused.** A word gated as a vendor's product, or as a vendor, is still
a free-text term, and reaches every record except that vendor's: one filed under the vendor,
or a record about a class of product whose entries name it. A word gated as a class reaches
no record carrying that class. Until 0.43.0 the refusal held only at resolution: `quantum`,
refused as Check Point's gateway, then matched the gateway's product name and ranked the
Check Point record first of 70 for "Zorblax Quantum Edge Gateway 9000", and "Apple iOS"
refused Cisco IOS and was answered with twelve Cisco router findings reached through the same
word. `edge`, refused as Microsoft Edge, still reaches the records tagged about edge devices,
and `MATCH_BASIS` on a tag finding names the word it matched.

## Names that are not vendors

`who.vendor: any` marks a record about a class of product rather than somebody's, and
`Multiple` a catalogue entry spanning vendors. Neither is ever a resolved vendor, a vendor
match or a corroborator. 20 product aliases name `any` or `Multiple` as their vendor (git,
npm, yarn, pypi, suricata, github actions and others). They still resolve their product,
listed as naming no vendor, and match that product under any vendor. Until 0.43.0 each put
`any` into `RESOLVED_TO`, so all 131 `any` records scored as vendor matches: "npm supply chain"
returned 512 findings under `RESOLUTION: product`, and now returns 36. `rust crate` and
`crates io` went with `cargo`: each named arrayref, one crate of the five on the record, and a
new class alias `crate` takes a Rust crate question to `dev.library`, where the leftover word
"rust" puts the crate record first.

Where a record covers a class, the makers it covers are in `who.products`. A resolved vendor
whose name, or any alias of it, stands as whole words in one of those entries is a vendor
match, reported as `vendor GitHub (named in product GitHub)`. Eleven observations name GitHub
that way, and "GitHub" was told no record is about it. Such a match counts toward the
`product` resolution only when the record also carries a class the question resolved, or the
question resolved none, and never when the question named a product: a botnet record listing
"Android TV boxes" is Android's history, not an answer to a question about a build pipeline,
and five endpoint records listing "Linux servers" do not make "Linux kernel" a product answer.
Such a match is `MATCH_TIER: vendor` exactly where it counts; otherwise it is the record's
`class` match, or `name-fragment` where the record carries no asked-for class. It is never
`vendor-other-class`, which is kept for records filed under the vendor: the botnet record
is about TV boxes, not one of Android's product lines. A sector reason beside it changes
nothing: a sector says where a record's victims were, never whether it names the
technology, so it decides no tier.

## Matching a record's own spelling

- **Vendors** match exactly, or through the resolved vendor's alias keys ("VMware" is
  Broadcom's), its `vendor_spellings` (one company filed under two names: Barracuda and
  Barracuda Networks, QNAP and QNAP Systems, Rockwell and Rockwell Automation, both ways) and
  its `vendor_families`. A family runs one way, from a parent to the lines it acquired:
  VMware, VMware Tanzu and Symantec under Broadcom, Telerik under Progress, Hewlett Packard
  under Hewlett Packard Enterprise. A question naming the parent reaches a member's records,
  reasoned `vendor VMware (as Broadcom)`. A question naming a member reaches neither the
  parent's other lines nor a sibling's: read as a flat set, the table answered bare
  "Symantec" from 41 VMware ESXi findings. A record filed under the parent is the
  member's where one of its products names the member, reasoned `vendor Symantec (filed under
  Broadcom)`. Because `vmware` is a Broadcom alias, a VMware question is a Broadcom question,
  and Broadcom's Symantec and Brocade lines reach it as the vendor's other lines.
- **Products** match only under their own vendor, so "Kernel", "Core", "Desktop" and "Multiple
  Products" no longer give another vendor's record product weight. They match by canonical
  equality: bracketed segments and the vendor's own name removed, a trailing `s` optional on the
  last word. "ESXi" matches "VMware ESXi", "Endpoint Manager Mobile" matches "Endpoint Manager
  Mobile (EPMM)", "Quantum Security Gateway" matches "Quantum Security Gateways", and "Endpoint
  Manager (EPM)" does not match EPMM. Token containment was measured as the alternative and
  matched EPM to EPMM and ADFS to Active Directory.
- **A product has more than one spelling** (0.43.0). Under its own vendor a product is also
  spelt by every alias the table resolves to it ("Exchange" is Exchange Server), and by every
  name of its `product_families` entry: one product the vendor ships, or the catalogues file,
  under several names. FortiGate and FortiOS, Endpoint Manager Mobile and MobileIron Core,
  Connect Secure and Pulse Connect Secure, the Cisco ASA, Threat Defense and Management Center
  lines under their Firepower and Secure Firewall names, Exchange and Exchange Server,
  Ivanti's Cloud Service Appliance under its three advisory and catalogue names, and the
  SIMATIC S7 series are families, and a family matches both ways. A component (the FortiOS
  SSL-VPN, the kernel's KSMBD server, each line of the SIMATIC S7 series) runs one way: asking
  for the product reaches it, asking for the component reaches only the component.
  `MATCH_BASIS` says which: `FortiOS (as FortiGate)`, `FortiGate SSL VPN (a component of
  FortiGate)`. Another vendor's record is matched on the product's own name only, since with
  Ivanti's names stripped "MobileIron Core" is "core", which is WordPress's too. Measured over
  the 1,086 vendor-qualified alias questions, the change loses no match the resolver made and
  adds 252 across 127 questions, each read by hand. The Cloud Service Appliance family, added
  after that measurement and asked the same way, adds 16 more, all on the six questions naming
  the appliance, and loses none.
- **Every name of one product resolves one set of classes** (0.44.0). `fortigate` resolved
  `network.firewall` and `fortios` `network.vpn_gateway`, so a FortiGate answer matched 78
  findings and a FortiOS answer 116, and neither reached what the other did. Both now carry
  both, the union of what the two carried, so no question loses a class it had. The alias
  table stays the one place a product's classes are declared: a family carries no classes of
  its own, and the resolver unions nothing at run time, which would keep every generator
  default the table copied (the Cloud Service Appliance's three names would each match 202
  findings). `tests/test_product_identity.py` holds the table to it twice. It asks every name
  of every family beside its vendor for its own product and one class set, which is how
  "Firepower Management Center" was found resolving Firepower Threat Defense and "Secure
  Firewall Threat Defense" resolving no product; and it reads every product the resolver joins
  by canonical equality, family or not. Seven products are pinned open there with their
  reasons, and each pin fails once its product holds: the Cloud Service Appliance, classed
  three ways by its three names, which is the maintainer's plane decision; Policy Secure, which
  no alias names; and Sentry, Virtual Traffic Manager, Junos OS, Identity Services Engine and
  WebLogic, whose aliases disagree outside any family. A platform whose parts are sold as
  separate services is not a family: "aws" and "amazon web services" are vendor aliases of
  Amazon, whose twelve records are all AWS services, so an AWS question asks for the vendor in
  `cloud.iaas` and no AWS service is called another product than the one asked about.
- **An entry may name several products.** The catalogue writes "Adaptive Security Appliance
  (ASA) and Firepower Threat Defense (FTD)" and "iOS, iPadOS, and watchOS" as one string, and
  a record filed under a vendor names each part: a Cisco ASA question called three such
  records "not the product asked about" until 0.43.0. A record about a class of product is read
  whole, because "Windows and Linux estates" describes what it covers and is no product name.
- **A record about a class of product** (`any` or `Multiple`) has no vendor to match, so an
  entry in its `who.products` names a resolved product only where the entry names the
  product's vendor ("VMware ESXi", "Google Chrome"), or stands as one of the product's aliases
  without it: an unambiguous alias ("Zimbra Collaboration Suite", "Active Directory"), or a
  gated one whose words do not read as a class ("Cursor", in a list of coding agents). A gated
  alias that reads as a class is every vendor's in a record naming no vendor: until this was
  added, two records listing "firewalls" answered "Sophos Firewall" as `RESOLUTION: product`
  without `CLASS_LEVEL_WARNING`, and "D-Link routers", "QNAP network attached storage" and
  "SonicWall firewall appliances" did the same. `tests/test_sentinel_vendor.py` lists every
  gated entry of such a record and how it was decided, so a new one fails until it is.
- **A block of such a record is tiered by what it concerns** (`consult.py`'s `block_scope()`),
  where the record also lists an entry not naming what was asked. A block keeps the record's
  `product` or `vendor` tier where its own text names what was asked, it carries an identifier
  an exposure record holds as the product's own or files under the vendor, or its own
  sentences -- its logic and caveat, never the paths and strings it matches -- read, through a
  class alias, for a class of what was asked: the ESXi share-encryption record's hypervisor
  block reads "hypervisor" and "virtual machine" beside "Windows hosts". A class word inside a
  matched string is not read, because "vpn" in the NetScaler path `/var/vpn/themes/imgs/` kept
  the access-resale record's integrity block as Ivanti Connect Secure's; a product's name in
  one is, so that path names the NetScaler entry. A block naming none of these keeps the tier
  on the pattern it cites only: as the record's only block, where that pattern is written for
  a class of what was asked; or by kind, where it is written for a class of what was asked and
  for no other kind the record's other entries hold, so that within the record its detection
  is for products of the asked kind (the untrusted-fork record's build-log block on GitHub
  Actions, the BadIIS block on Microsoft). A block whose markers commit to another platform
  than the asked product's is not kept by kind: on "Linux" the hive record's shadow-copy block
  (`vssadmin.exe`) is Windows endpoints', both entries being `endpoint.os`. A record whose
  other entries the resolver reads nothing in ("personal access tokens", beside GitHub) lists
  no other product, and its blocks keep the tier. Every other block falls to the record's
  class, or else a name fragment: where it carries only identifiers held under another
  product, names another entry the record lists by that entry's own words ("cloud storage and
  network backups", beside SonicWall firewalls), names a product the record does not list
  while the pattern it cites is written for none of the asked product's classes, or gives no
  reading either way. No block keeps the tier by default: until the third review the last kept
  it as "the campaign as it reached them all, yours among them", and "Synacor Zimbra
  Collaboration Suite (ZCS)" drew its whole product tier from an IIS module-directory
  exclusion, an ASP.NET ViewState block and a block that is not a detection. Such a block now
  says what its pattern is written for and which other entries hold that kind. A word the
  alias table merely files under an entry ("badiis" under the Telerik entry, "actions runner"
  under "self-hosted runners") is not that entry's name. `MATCH_BASIS` gives the reading after
  the tier's sentence, and where every block of the campaign records naming what was asked
  fell, `RESOLUTION` and `CLASS_LEVEL_WARNING` say that those records list it and that no
  observation is about it.

`query.exposure_tier()` places an exposure relative to the question with the same matcher:
`product`, `vendor-class`, `vendor`, then `other-products-of-vendor` (the vendor's other lines
when the question also named a product or class), `product-name-other-vendor`, `class-only`
and `prose-only`. `query.py` lists exposures in that order, then exploited before advised
before disclosed, then newest first, and prints the tier on each line and a count per tier in
`--json`. `consult.py` lists the first three tiers only, in the same order, and counts the
rest. A catalogue entry filed under a catch-all product ("Multiple Products") is matched on
the subject of the catalogue's description of each identifier instead, by the same matcher,
and is `product` where any description names the product (`references/exposures.md`);
`query.py` prints `catalogue description names the product:` under such a line and
`catalogue_names` in `--json`. A generated exposure whose identifiers read a class by their own
text (`what.identifier_signals`) is `vendor-class` for that class when the question names its
vendor, and never `class-only` by it, so "Check Point VPN" lists the vendor's three VPN flaws
and "VPN gateway" reaches no exposure it did not reach before.

## Where these rules came from

- **`name-fragment` is its own tier** because until 2026-08-27 it was reported as though the
  caller had named the technology. "mobile app hardening" resolves nothing, and returned an
  Ivanti Connect Secure VPN gateway at rank 1 saying `named this technology`, because "Mobile"
  sits inside the product name "Endpoint Manager Mobile" and "app" inside "web applications".
- **The product gate** dates from 0.29.0. Until then any ordinary word resolved wherever it
  appeared: "runtime application self-protection" returned `RESOLUTION: product`, claimed
  Android Runtime and Cisco IOS, and put a GeoServer deserialisation record at rank 1 of 860.
  "I have a Cisco firewall" returned `vendors=Cisco, Sophos | products=Firewall`, because
  `firewall` is a product alias for a Sophos appliance: a second vendor the caller never
  named, which SKILL.md documented as intended behaviour.
  Measured across the alias table then, 90 vendor-qualified product questions stopped
  resolving a second vendor they never named, and none lost its own subject.
- **The class deletions** date from 0.30.0. "An in-app sensor reporting rooted or jailbroken
  devices" resolved `sensor` to `ot.field_device` and answered a handset question with
  industrial field instrumentation; `sensor` and `instrumentation` were deleted. That release
  named four class aliases as still misfiring; measured in 0.43.0 there were nineteen, and the
  class gate above is what followed.

## Measured

Every product alias whose vendor is named, asked as "<vendor> <alias>" (1,086 questions at
0.43.0, 1,089 at 0.44.0): before 0.43.0, 70 resolved a second vendor, 37 of them outside the
vendor's own family; now 21 do, all within the family, and none loses its own product. Asked
verbatim, 209 of 1,106 aliases resolved a second product; 79 of 1,109 do at 0.44.0.
`tests/test_ambiguous_aliases.py` asks the whole table on every run, which takes about a
second since each alias pattern is compiled once.
