<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# The EXPOSURE and LIBRARY blocks

Read this before relying on either block, before passing one on as part of an answer, or
when `EXPOSURES_NOT_LISTED` or `LIBRARY_PATTERNS` needs explaining to a caller.

A consultation prints three kinds of block, in this order: the findings, then the exposures
naming what was asked, then the library patterns of its class. Only the first are findings.
An exposure is a vulnerability fact with no detection logic; a library pattern is detection
logic with no incident behind it. Neither can be scored against a finding -- an exposure has
nothing to detect, and a pattern has no date, no citation and no identifier -- so each comes
in blocks of its own, under a header group of its own, and is never merged into `FINDINGS`.

Until 0.43.0 `consult.py` built findings from records' how-blocks and printed nothing else.
894 of the corpus's 1,142 records are exposures with no how-block, so no question could
return one: "Check Point firewall" never showed the two identifiers CISA added on 09-22, and
`corpus/README.md` said the lookup returned exposures as a separate block when only
`query.py` did. The 34 patterns no record cites were unreachable the same way, and rule 6
described a `DERIVATION` value that no output ever printed.

## What both blocks never do

- **Take a slot.** `FINDINGS`, `--limit`, the per-locus reserve and the record cap are about
  findings only. `--exposure-limit` (default 10) and `--pattern-limit` (default 6) cap the
  two blocks, 0 lists none, and a value below 0 exits 2.
- **Count in a finding tally.** `MATCH_TIERS`, `LOCUS_MATCHED`, `LOCUS_ELIGIBLE`,
  `LOCUS_SHOWN` and `COVERAGE_TALLY` describe the findings and nothing else. Tests hold these
  lines byte-identical whatever either limit is.
- **Clear `LOCUS_ABSENT`.** An absent locus's bullet counts them, as `; exposures N; library
  M`, over everything each block matched before its limit, so a locus held only by an
  exposure or a library pattern is visible as such. It stays absent: an exposure gives
  nothing to detect there, and a pattern no record cites says what the class could see, not
  what was seen.
- **Collide with a finding's keys.** Every key is prefixed `EXPOSURE_` or `LIBRARY_`, so a
  consumer scanning the whole output for `LOCUS:`, `RECORD_ID:`, `PATTERN_ID:` or
  `PRIORITY_BASIS:` sees findings only, and `=== FINDING ` counts findings only. Each
  block's key set is fixed whether or not a field is empty.

## Exposures

### What is listed

Every exposure record is placed in a tier by `query.exposure_tier()`, the one helper
`query.py` uses too, so the two scripts cannot disagree about how a record relates to a
question. The vendor test canonicalises through the vendor families (a VMware record under a
Broadcom question), and a product matches by canonical equality: parenthesised segments and
vendor names stripped, a trailing `s` optional, so "Endpoint Manager Mobile" names "Endpoint
Manager Mobile (EPMM)" and "Quantum Security Gateway" names "Quantum Security Gateways". Since
0.43.0 a product is also spelt by its aliases and its `product_families` names, and a
catalogue entry naming several products ("Adaptive Security Appliance (ASA) and Firepower
Threat Defense (FTD)") names each, so a FortiOS catalogue record is a FortiGate exposure and
the ASA-and-FTD record an ASA one (`references/resolution.md`). Before, a FortiGate question
held its catalogued, ransomware-linked SSL-VPN flaw back as the vendor's other lines.

A catalogue entry filed under a catch-all product -- "Multiple Products", "MobileIron Multiple
Products", "Multiple Routers", 33 records -- names no product in its product field, so the
catalogue's own description of each identifier is read instead, as the generator quotes it in
the summary: the description's subject, up to its first verb ("Fortinet FortiOS, FortiProxy,
and FortiSwitchManager contain ..."), is matched exactly as a product entry is. Where it names
the product asked about for any identifier, the record is in the `product` tier and
`EXPOSURE_MATCH` says for which: `PRODUCT - filed under Multiple Products, which names no
product; the catalogue's own description names the product asked about for 5 of its 6
identifier(s): FortiOS (as FortiGate) in CVE-...; its description of CVE-... does not name it`,
and, where the record carries more identifiers than its summary describes, how many were not
read. Only those identifiers are the product's own for the identifier join below. Until 0.43.0
"Fortinet Multiple Products", naming FortiOS for five of its six exploited identifiers, was
"not the product asked about" for FortiGate and listed after a PSIRT record none of whose
fifteen identifiers was exploited. The description's subject is read with a possessive dropped
and "A B & C" as "A B" and "A C", so "Ivanti MobileIron's Core & Connector" names MobileIron
Core, EPMM's former name. Of the 1,117 questions formed from each product alias and its vendor,
37 move one of six catch-all records into the tier, and each was read against the description
it rests on.

| tier | listed | when |
|---|---|---|
| `product` | yes | a resolved product names the record's product, under the vendor asked about, or, for a catch-all catalogue entry, the catalogue's description of one of its identifiers |
| `vendor-class` | yes | the vendor asked about, in a class the question resolved, or one an identifier's own text reads (`what.identifier_signals`) |
| `vendor` | yes | the vendor asked about, when the question named no product and no class |
| `other-products-of-vendor` | counted | the vendor asked about, when a product or class was named and this is another line |
| `product-name-other-vendor` | counted | the product's name under another vendor ("Multiple Products", "Kernel") |
| `class-only` | counted | another vendor's product in a class the question resolved; a class only an identifier's text reads never reaches this tier |
| `prose-only` | counted | reached by a word of the question in its prose |
| `handset` | counted | a listed tier, refused by the handset decision below; when the question resolved nothing, an exposure a word of it names by product, refused the same way |

A class match alone never lists an exposure. An observation about another vendor's firewall
carries detection logic that transfers; a CVE in another vendor's firewall carries nothing
that does. `query.py` still lists every tier, labelled, because it answers "what is there".

Measured at 0.43.0 over the 1,097 distinct vendor and product resolutions of the alias table,
988 listed at least one exposure, 6,450 listings in all, where every one had listed none
before. The alias changes of 0.44.0 moved the table, and the figures were not re-taken.

### The handset decision

Handsets are out of scope; the mobile management plane (`app.mdm`, `MANAGEMENT`) is in.
`corpus/schema/scope.json` names the handset exposures by vendor and platform term: an
exposure is refused when its vendor is listed there and every platform its products name
matches one of that vendor's terms. 16 records are refused: Android's five, Apple's iOS,
iPadOS and watchOS records, Arm Mali, Qualcomm and MediaTek chipsets, Samsung Mobile
Devices, Chrome for Android and Code Aurora's Android audio driver. "iOS and macOS" is a
macOS exposure as well and stays listable. The records stay in the corpus, `validate.py`
checks them, `query.py` lists them, and a refusal is counted as `handset=` on
`EXPOSURES_NOT_LISTED`, never silent. The refusal is applied where the listing is decided,
so the resolution mode counts the same set: "Qualcomm", whose two exposures are both
handset records, reads `UNRESOLVED` with a sentence saying so, exits 1, and is told the
records are out of scope rather than asked to report a gap. `validate.py` refuses a
`scope.json` entry naming a vendor or a term no exposure carries; a handset record from a
vendor the table does not name is not caught, and is added there when it arrives.

A bare handset name is refused as well. A question that resolves no vendor, product or class
names an exposure only by the words of its product name, so "iOS", "iPadOS" and "watchOS"
counted Apple's handset records `prose-only` with `handset=0`, said no record's prose carried
their words, and were told to add the alias the decision forbids. `scope.json`'s
`handset_names` (ios, ipados, ipad, iphone, mali, snapdragon, watchos) is the question side of
the table: when a question resolves no vendor, product or class (a sector spares only a place,
below) and one of its words is there, an exposure that word names by product, and the table refuses, is counted `handset=`
("iOS" 3, "iPadOS" 2, "watchOS" 1, "Mali" 2, "Snapdragon" 1), and a name no record carries is
refused all the same ("iPhone", "iPad"). Any word standing in a handset product's name was
measured and refused as the rule: "gpu", "audio" and "chipsets" read as handset questions.
`RESOLUTION` reads `UNRESOLVED`, says the word is listed in `scope.json` as a handset name (the
table's word, not a claim about every product carrying it: the one Snapdragon record also lists
laptop, vehicle and module parts), and the run exits 1. In place of the class re-ask, which
offered `endpoint.os` among every class, the answer prints the refusal and points at the mobile
management plane rather than at `aliases.json`; a handset word that is also a refused alias
says so ("IOS" is Cisco's too, and is told to ask "Cisco IOS"). Beside a vendor, product or
class nothing is refused: "Cisco ASA VPN users on iOS and Android phones", "iOS MDM" and the
Guardsquare question are answered for what they name. Beside a sector only a word
`handset_names_also_places` lists is spared, read as the place: "banks in Mali" is answered and
"iOS in government" refused. Beside a name that reached no record and is no refused alias's (a
word written with a capital or a digit, as `MECHANISM_WARNING` reads one) the refusal stands
and names it as the word the plane turns on: "Kandji for iOS" names a management product, in
scope, and "Pegasus iOS" spyware on the handset, out of scope, and nothing in the word tells
them apart. `RESOLUTION` reads "out of scope as a handset ... unless kandji names the product
that manages these devices", and the answer offers the name as an `app.mdm` alias to add only
on that condition. An ordinary word that reached nothing ("iOS spyware", "iPad jailbroken") is
no name, and changes nothing: once any such word stopped the refusal, and was named as the
alias to add. Where a handset name stands beside a sector and is not refused, the add-an-alias
paragraph says never to add it and offers `--as app.mdm` if the word names a handset. Beside a
resolved vendor, an `EXPOSURES_ONLY` answer ("Apple iOS") keeps its listing and is pointed at
`--as app.mdm`, not at the classes its exposures carry, which for Apple is the endpoint plane. `validate.py` refuses a `handset_names` word an
unambiguous alias would consume first.

### Kind, order and locus

`EXPOSURE_KIND` is `EXPLOITED` when any identifier is one the corpus's own catalogue
records carry, `ADVISORY` for a government advisory, otherwise `DISCLOSED`. It is computed
from the identifiers every run, never from a tag: the ZDI and NVD generators stamp
`not-in-kev` against the catalogue of the day, and six such records once denied an
identifier the catalogue records listed. `EXPOSURE_SUMMARY` is the generated text and can
predate a catalogue addition; the kind cannot.

The order is fixed, not scored, and printed on every block as `EXPOSURE_ORDER_BASIS`: tier,
then kind, then newest published first with the undated last, then id. `--covered` and
`--rank-by` do not apply, because an exposure has no detection to cover.

`EXPOSURE_LOCUS` comes from the same ladder as a finding's. A generated exposure's
`attack_surface` restates a class default, so its surface is not read (see
`references/locus-and-coverage.md`): the record sits where its class puts it -- the Linux
kernel on `ENDPOINT`, EPMM on `MANAGEMENT` -- unless its identifiers say otherwise in their
own words. The generators write `what.identifier_signals`: for each identifier whose own
catalogue description or name, advisory title or database description names an
administrative component -- a management or administrative interface, console, portal or
page, the configuration utility or backup, a super-admin account, the CLI or SNMP -- a
`MANAGEMENT` entry, and for a VPN feature on a network device a `network.vpn_gateway` entry
(not for a provider VPN: text naming VRF, MPLS, L2VPN, L3VPN, EVPN or VPLS is not read as one),
each with its rule, words and field. A locus every identifier reads decides the primary
(`tier=identifier`): BIG-IP's Configuration Utility record, both of whose identifiers name the
Configuration utility, reads `MANAGEMENT, CONTROL`. Otherwise the plane most of them read is the span,
`span-source=identifier`: FortiOS's two super-admin bypasses beside two SSL-VPN flaws, and
PAN-OS's four management web interface flaws among twelve, read `CONTROL, MANAGEMENT`.
`EXPOSURE_LOCUS_BASIS` then ends `identifier-signal=<k> of <n> identifier(s) read by their own
text:`, each identifier with what it read and the words in quotes. Text naming no component
-- "web UI", J-Web, a peering authentication -- leaves an identifier on the class's plane, and
a record listing an `ENDPOINT` class or `dev.library` first is not read. The question's
matched class can only append a value to the span, after the record's own, never move the
primary. An exposure has no block, so its authored surface decides for the record as a
whole: the rule that a surface stops at the way in is per block and does not apply. A product
whose job is administering other devices -- FortiManager, Cisco FMC, SmartConsole, an SD-WAN
manager -- lists `app.rmm` first and the class of what it manages second: it sits on
`MANAGEMENT`, and a question asking the managed class adds that class's plane as the span, so
a firewall question reads `MANAGEMENT, CONTROL`.

A class an identifier reads widens only the `vendor-class` tier, and only for the vendor the
question named: "Check Point VPN" lists the three Check Point identifiers the catalogue
describes as VPN flaws, though no Check Point exposure carries the VPN gateway class, and
`EXPOSURE_MATCH` says `in network.vpn_gateway (by the source's own text of <identifiers>, not
its product class)`, because `EXPOSURE_PRODUCT_CLASS` beside it does not hold the class. A
class question naming no vendor is not widened: "VPN gateway" counts the class-only exposures
it did.

### Header lines

Printed after the coverage lines, before `CONTRACT`. Every count but `shown` is over
everything listed or reached, before `--exposure-limit`.

- `EXPOSURES: <shown> shown of <n> naming what was asked (product=, vendor-class=, vendor=)`
- `EXPOSURE_KINDS: exploited=, advisory=, disclosed=  (over all n, ...)`
- `EXPOSURE_LOCUS: CONTROL=, MANAGEMENT=, DATA=, ENDPOINT=, SUPPLY=, ORGANISATION=  (...)`,
  every locus, zeros included.
- `EXPOSURE_LOCUS_SPAN: CONTROL=, MANAGEMENT=, ...  (exposures carrying the locus in
  EXPOSURE_LOCUS_SPAN after their primary, over all n)`: what the blocks print after their
  primary, counted once per exposure per locus. `EXPOSURE_LOCUS` alone read as though
  FortiGate had no management-plane exposure.
- `EXPOSURES_NOT_LISTED: <m> - other-products-of-vendor=, product-name-other-vendor=,
  class-only=, prose-only=, handset=. <why>`
- `EXPOSURE_ORDERING:` the rule, the KEV snapshot the kinds are read against, and what the
  block never does.
- `EXPOSURE_DATA_GAP:` what acting on an exposure needs, `asset_inventory` and `vuln_scan`,
  assessed once against `--have` in the `DATA_GAP` format, so rule 5 is honoured once per
  answer rather than per block.
- `EXPOSURE_SCOPE:` how many exposures the corpus holds from each feed. It is not a
  vulnerability feed, and an identifier absent here is not an absent vulnerability.

When the answer is `UNRESOLVED`, only `EXPOSURES_NOT_LISTED` is printed, and only when the
question reached something.

### Block keys

`=== EXPOSURE i OF n ===` ... `=== END EXPOSURE i ===`, where `n` is the number shown.

| key | holds |
|---|---|
| `EXPOSURE_RANK` | position in the fixed order |
| `EXPOSURE_ID` | the record id |
| `EXPOSURE_MATCH` | the tier, then ` - ` and a sentence naming what matched |
| `EXPOSURE_KIND` | the kind, then how many identifiers are in the catalogue |
| `EXPOSURE_ORDER_BASIS` | tier, kind and date, the inputs of the order |
| `EXPOSURE_LOCUS`, `_SPAN`, `_BASIS` | as on a finding; on a record carrying `what.identifier_signals` the basis ends `identifier-signal=` |
| `EXPOSURE_TECHNOLOGY`, `EXPOSURE_PRODUCT_CLASS` | as on a finding |
| `EXPOSURE_IDENTIFIERS` | every identifier, never truncated |
| `EXPOSURE_RANSOMWARE` | the catalogue's flag, `yes` for Known and `unknown` for Unknown, or `not stated - not a catalogue record` |
| `EXPOSURE_STATUS`, `EXPOSURE_SOURCE_DISCLOSURE`, `EXPOSURE_SUPPORT` | as on a finding |
| `EXPOSURE_DETECTION_HELD` | `<c> of <n> identifier(s) carried`, then each observation carrying any of them with its vendor, the identifiers it carries and `FINDING k above` where one is shown, then the identifiers no observation carries; or `none - ...` |
| `EXPOSURE_SUMMARY`, `EXPOSURE_REFERENCES` | the record's own text and citation |

`EXPOSURE_DETECTION_HELD` prints the observation's vendor because a campaign record can
cite a CVE as one link in a chain against another product. It names what each carrier holds
because a list of carriers overstates the one field telling a caller whether detection logic
exists: the EPMM catalogue record named the 2023 chain's observation, which carries two of its
seven exploited identifiers, and the 2025 and 2026 five are carried by nothing. The line reads
`2 of 7 identifier(s) carried; <observation> (Ivanti) carries CVE-..., CVE-... - FINDING 1 above;
no observation carries CVE-..., ...`, ending `every identifier is carried` when none is left.
A campaign record, filed under `any` or `Multiple` and listing what it reached, has blocks about
different products, so its `FINDING k` is the first shown block whose own text carries one of
the identifiers; where none of its shown blocks does, the carrier reads `- its record is shown
above (FINDING k), in a block carrying none of them`. The ProxyShell exposure on "Microsoft
Exchange" pointed at the AA22-257A record's Log4j block until the 2026-09-30 validation.

`query.py` names the same carriers, from the same map (`query.identifier_carriers()`), on an
`identifiers also carried by:` line under each exposure and as `carried_by` in `--json`, and
the catalogue generator names them in the summary it writes. It also reaches them: an
observation carrying an identifier of a `product`-tier exposure is listed with the reason
`identifier <id> (in <exposure>)`, scoring what naming the product scores, even when it is
filed under another product. Until 0.43.0 the one observation about an exploited Linux kernel
flaw, a GeoServer intrusion that escalated through it, could not be reached from a "Linux
kernel" lookup, and the kernel's catalogue record said only that "an observation record"
carried the identifier. `consult.py` names such a record on `EXPOSURE_DETECTION_HELD` and does
not make findings of it: a finding is one detection block, and the carrier's blocks are
written for the product it is filed under.

### The mode and the exit code

The resolution mode counts the listed exposures: a name no observation carries and no class
resolved, but exposures name, is `EXPOSURES_ONLY` and exits 0 with its blocks. `consult.py`
exits 1 only when there is no finding, no listed exposure and no library pattern. `--role`
filters exposures as it filters findings, since each carries `what.role`; a filter that kept
exposures and no finding lists them and exits 0.

## Library patterns

A library pattern is one no record cites, with markers, whose `applies_to_classes` meets the
classes the question resolved, `--as` included, or, for a vendor-only question, the classes
derived from the vendor's own records (`CLASSES_FROM_VENDOR`), whose class matches are
analogues in any case. Over the same 1,097 resolutions at 0.43.0, 606 reached at least one.

The order is `query.py`'s: a pattern whose markers are written for another platform than
the one the question names comes last, then Sigma plus Splunk rules tagging a technique it
cites, descending, then id. `--covered`, `--rank-by` and `--role` do not apply.

Header lines: `LIBRARY_PATTERNS: <shown> shown of <m> matched on class <classes>: ...`,
`LIBRARY_LOCUS` over all `m`, and `LIBRARY_ORDERING`. With no class, the first reads `0
shown of 0 matched on class - the question resolved no class ...`.

Blocks are `=== LIBRARY i OF n ===` ... `=== END LIBRARY i ===`, carrying `LIBRARY_RANK`,
`_PATTERN_ID`, `_NAME`, `_MATCH`, `_ORDER_BASIS`, `_CLASSES`, `_LOCUS`, `_LOCUS_SPAN`,
`_LOCUS_BASIS`, `_FIDELITY`, `_RULE_SHAPE`, `_ATTACK`, `_CORROBORATED`, `_OBSERVED`,
`_DETECTION_LOGIC`, `_MARKERS`, `_TELEMETRY_REQUIRED`, `_DATA_GAP`, `_CAVEAT_VERBATIM`,
`_COUNTERMEASURES`, `_RESPONSE_DOCTRINE` and `_REFERENCES`. `LIBRARY_MARKERS` lines carry
`xdm=`, `event=` and `combine=` as a finding's `MARKERS` lines do, so a pattern whose markers
are alternatives or several events never reads as one conjunction. `LIBRARY_LOCUS_BASIS` reads
`input=applies_to_classes first-listed=...` where a class decided, because a pattern's classes
are what it applies to, not a product's, and `input=pattern ...` where its own markers, shape
or evidence did, as `advise.py` places it. `LIBRARY_CORROBORATED` and `LIBRARY_OBSERVED` are separate
claims, as `advise.py` keeps them: public rules tagging a technique the pattern cites, and
records here citing it, of which a library pattern has none. `LIBRARY_CAVEAT_VERBATIM` is
reproduced exactly, like every caveat. `LIBRARY_MATCH` ends `derived from <the pattern's own
derived_from, as written>`, or says the pattern records none, and `LIBRARY_REFERENCES` adds a
`DERIVED_FROM` row for any source not already a `CORROBORATION` row; `LIBRARY_PATTERNS` counts
the sources over all `m`. Both once printed one template, "derived from technique space rather
than from an incident and is about no one product", which was false for the patterns drawn
from CISA's malware analysis reports, one of them naming a single vendor's appliance paths.

A finding's `DERIVATION` is always `cited record`. The library-pattern value it was written
to carry could never be printed, and the patterns it meant are the `LIBRARY` blocks.
