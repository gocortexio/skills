---
name: cortex-platform-advisory-consultant
description: Consult on what a vendor technology has historically been caught up in, what to detect as a result, and what to do about it once found. Answers three questions from a corpus of 1,151 threat advisory records joined to MITRE ATT&CK and D3FEND. One, scoping -- "I run this technology, what should I worry about" -- which works even when the corpus has never heard of the product. Two, rule design -- "here are the patterns or techniques I am considering, what does the corpus say". Three, coverage -- "what should I build that I have not got", ranked by gap against what the caller already collects. Answers cover the management, control and data planes, not only the plane the ranking favours. Use whenever someone names a firewall, VPN, EDR, cloud platform, OT device or any product they run and asks what to worry about, what to detect, what use cases to build, or where coverage is thin.
version: 0.40.2
license: AGPL-3.0-or-later
---

<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# cortex-platform-advisory-consultant

The current version is 0.40.2; the per-version change history lives in [CHANGELOG.md](CHANGELOG.md).


Somebody names a technology they run. This skill returns what that technology, its
product class, or its vendor has been observed caught up in, the detection logic that
goes with each case, and what to do about it once found.

**This skill does not write rules.** It supplies what a rule-authoring skill needs:
typed markers, the telemetry each one requires, an honest statement of whether a case
is alert-grade or hunt-grade, and the countermeasures D3FEND maps to the same
techniques, so an answer does not stop at the point the alert fires.

## Announcing, and stopping loudly

Print a STAGE banner on entering every stage of this skill's own workflow, and NEVER ask the
caller a question outside a `!` or `?` banner. A question in a paragraph is how a run sits idle
while everyone waits for the other one; a stage nobody announced is a stage nobody can see you
are in.

COPY the templates from [references/console-output.md](references/console-output.md), at the
boundary, and never render one from memory -- a typed banner loses the squirrel first, then the
rules, then the named sections. That page is identical in every bundle in this project and carries
the three fills, the art and the rules for each. The banner is the FIRST thing in the reply that
enters a stage, and the LAST thing in a reply that stops.

## How to consult this skill

Everything after this section is written for the session running the skill. This section is
for a session that wants an answer out of it.

**Consult it in session.** Invoke the skill, or run the script, in the session that needs the
answer. There is no cross-session route to a consultation. The answer is the script's output,
so a consultation relayed between sessions arrives as somebody's summary of a block format
that exists precisely so it never has to be summarised.

**Pick the script by the question being asked, not by precedence.**

| the question | run | supply |
|---|---|---|
| "I run this technology, what should I worry about" | `consult.py "<vendor> <product>"` | plain words; the resolver handles them |
| "...and the corpus has never heard of it" | `consult.py "<name>" --as <class>[,<class>]` | the normal case, not the exception; see the resolution modes below |
| "here are the patterns or techniques I am considering" | `advise.py --patterns <ids>` or `--attack <ids>` | exact ids |
| exploring or maintaining the corpus | `query.py "<term>"` | plain words |

Scope-time and design-time are different questions and take different scripts. A caller who
has a vendor and a product and no pattern ids yet wants `consult.py`: it resolves the product
against `corpus/schema/aliases.json` and returns everything the corpus holds for that class.
Handing the same words to `advise.py` returns a single token-overlap guess, because
`advise.py` selects and does not resolve.

**Pass `--have` with whatever telemetry you collect**, to either script. Without it every
`DATA_GAP` comes back `UNASSESSED`, which is not the same answer as "no gap".

**Read the echo before you read a finding.** Both scripts state what they did with the
request, because a guess is returned in the same confident format as an exact match:

- `consult.py` prints `RESOLVED_TO:` in its header. It can resolve wider than you asked:
  "I have a Cisco firewall" resolves to `vendors=Cisco | classes=network.firewall`, and the
  class is what carries the lesson across vendors. Until 0.29.0 it also returned
  `vendors=Cisco, Sophos | products=Firewall`, because `firewall` is a product alias for a
  Sophos appliance and any word in a question could resolve as a product name wherever it
  appeared. That was a second vendor the caller never named, and this page documented it as
  intended behaviour.
- `advise.py` prints a `### SHAPE:` banner per group and `MATCH_BASIS:` per pattern.
  `selected exactly by pattern id` and `selected exactly by ATT&CK id` mean you got what you
  named. `free-text overlap on <tokens> (score N) - VERIFY THIS IS THE RIGHT PATTERN BEFORE
  CITING IT` means the corpus ranked a guess for you. Nothing emits a line beginning
  `SELECTION:`; that text is the tail of the `### SHAPE:` banner.
- `advise.py` also prints `FINDINGS: N pattern(s) returned` and a `SELECTED_BY:` breakdown
  of that total across exact pattern id, exact ATT&CK id and free-text guess. `FINDINGS` is
  how many patterns are printed below, so it is the count to trust; the trailing `across N
  shape(s) asked` is only how many free-text arguments you passed. Before 0.11.1 the
  headline was that argument count under the key `SHAPES`, which read `0` on every exact
  selection. If you are working from notes that say to read `SHAPES:`, they predate the fix.

Skipping those lines is the failure this section exists to prevent. The blocks under a guess
are as complete, as specific and as citable as the blocks under an exact selection, and
nothing else in the output tells them apart.

**When the corpus does not know your technology by name, do not stop.** 73% of a real
integration library resolves to zero records here, so an unresolved name is the normal case,
not the exceptional one -- and the product *class* almost always holds findings when the
product name holds none. `consult.py` answers this in three labelled modes and prints which
one it used on a `RESOLUTION:` line:

| mode | when | what it means |
|---|---|---|
| `product` | a vendor or product matched | the corpus holds records naming this technology |
| `CLASS-LEVEL (inferred)` | only a class matched | answering on product class alone |
| `CLASS-LEVEL (declared via --as)` | you asserted the class | same, and you chose it |
| `NAME_WITHOUT_RECORDS` | a name resolved, no record is about it | every finding came from tag or prose; `identity=0` |
| `UNRESOLVED` | nothing matched | exits 1, and prints how to re-ask |

```bash
python3 scripts/consult.py "Portkey"                       # UNRESOLVED, tells you what to do
python3 scripts/consult.py "Portkey" --as app.ai_platform  # 32 findings
python3 scripts/consult.py "Portkey" \
  --as app.ai_platform,network.proxy,security.pam,cloud.saas   # 119, all six loci filled
```

**Name every class the technology behaves as.** The measurement above is the argument: one
class matched 32 findings and left MANAGEMENT, DATA and ORGANISATION empty; naming what the
thing also *is* -- a proxy, a credential store, a SaaS app -- matched 119 and filled all six
loci. A single class is usually an under-description.

Both class-level modes print a `CLASS_LEVEL_WARNING` and it must survive into whatever you
write. A class-level answer says what this *kind* of technology has been caught up in, and
passing it on as product intelligence is the one failure here worse than an empty answer.

**When the corpus has nothing at all**, say so and report the term back here.
`consult.py` exits 1 when nothing matched and 2 when `--rank-by gap` was asked for without
`--covered`, so an empty answer is distinguishable from a failure; `advise.py` exits 1 when
nothing was selected and says which path came back empty, since an id that does not exist is
a different problem from a guess that missed; `query.py` exits 0 either way. An empty consultation is far more often a term missing from `corpus/schema/aliases.json`
than a technology the corpus has never seen, so name the term you tried. That is a corpus gap
and it is fixable.

## The response contract

**You can ask by mechanism, not only by technology.** `consult.py "phishing"` reaches 78
findings and `"prompt injection"` 99; before 0.22.0 both returned nothing, because the
resolver only searched vendor and product names. A question that resolves to no vendor but
matches record wording is reported as `RESOLUTION: mechanism` rather than as unresolved.

**Every finding carries a `MATCH_BASIS:` line saying how it was reached** -- `identity`
(named the technology), `tag`, `name-fragment`, or `LOOSE` for a pattern-wording or prose
match. Loose matches are ranked below tight ones and are the ones that may be about
something else: the measurement behind this change found 31 records answering a vendor
query they are not about, all of them via prose. They are kept and demoted rather than
dropped, so treat a `LOOSE` finding as a lead rather than an answer.

**`name-fragment` means a word from the question sits inside a name nothing resolved.**
It is not `identity` and until 2026-08-27 it was reported as though it were. Asking
`"mobile app hardening"` resolves to no vendor, product or class, and yet returned an
Ivanti Connect Secure VPN gateway at rank 1 saying `named this technology` -- because
`Mobile` appears inside the product name `Endpoint Manager Mobile`, and `app` inside
`web applications`. Read the `TECHNOLOGY:` line before treating a `name-fragment` finding
as being about your technology; roughly half of them are about something else.

**A word in your question only names a product when it sits beside that product's vendor.**
Ordinary words are also product names -- `runtime` is an Android product, `ios` a Cisco one,
`web server` a Commvault one -- and until 0.29.0 any of them resolved wherever it appeared.
Asking about "runtime application self-protection" returned `RESOLUTION: product`, claimed
Android Runtime and Cisco IOS, and put a GeoServer deserialisation record at rank 1 of 860.
The words listed under `ambiguous_aliases` in `corpus/schema/aliases.json` now resolve only
within two tokens of their vendor, so `Cisco IOS` works and `iOS apps` does not. Measured
across the alias table: 90 vendor-qualified product questions stopped resolving a second
vendor they never named, and none lost its own subject.

**A class can still resolve falsely, and a class is the bigger claim.** That gate covers
product aliases only. `class_aliases` has none, and a wrong class sets the plane the whole
consultation is about rather than one line of the header. Asking about "an in-app **sensor**
reporting rooted or jailbroken devices" resolved `sensor` to `ot.field_device` until 0.30.0
and answered a handset question with industrial field instrumentation. `sensor` and
`instrumentation` are gone; `ran`, `relay`, `ad` and `switch` are known to still do it and
are kept rather than deleted, because deleting them is a coverage decision nobody has made:
only `network.switch` has no other route into its class, while the other three keep three or
more unambiguous aliases each. `tests/test_class_aliases.py` pins all four as still
failing, so the tripwire fires when a gate lands. **Read `RESOLVED_TO:` against the words you actually wrote.** If a class appears that
you did not mean, name your technology explicitly or pass `--as`, and treat everything under
`RESOLUTION: CLASS-LEVEL (inferred)` as the guess it is labelled as.

**The header's `MATCH_TIERS:` line is the check.** It counts the whole match set by tier
before `--limit` truncates, so `identity=0` beside `RESOLVED_TO: vendors=- | products=- |
classes=-` is self-consistent and a consumer can gate on it without parsing English. If
those two ever disagree -- nothing resolved by name, yet findings claiming `identity` --
the answer is wrong and the tally is how you see it.

**Every finding carries a `SUPPORT:` line** saying when the source was last read and
whether it was verified -- the axis ranking and `CORROBORATION` do not cover. Bracketed
flags mark findings backed more weakly than the rest: `NO_READ_DATE`,
`VERIFICATION_UNSTATED`, `SOURCE_NOT_RE-READ`, `SEED`, and
`NO_PUBLICATION_DATE:ranked-as-3650d`. Weigh a flagged finding accordingly rather than
discarding it; 85% of observations carry no flag at all, so a flag means something.
Age is reported but never flagged, because `PRIORITY_BASIS` already prints
`days_since_published` and the ranking already decays recency.

**A technology consultation is returned in the format `scripts/consult.py` emits, and
that output is always fed back to the calling session.** `scripts/advise.py` answers the
pattern question and emits its own block format; what holds for both is that the script's
output goes back, not a retelling of it. The consumer is a detection engineer or another
agent writing rules in a language this skill does not know, so the answer has to be
parseable without reading English prose.

```sh
python3 scripts/consult.py "I have a Cisco FW" --have netflow,edr_process,auth_log
```

For a coverage review -- "what should I build that I have not got" -- add what the
caller already implements and switch the ordering:

```sh
python3 scripts/consult.py "I have a Cisco FW" \
  --have netflow,edr_process --covered T1611,WebShellDeployment,SshLateralMovement \
  --rank-by gap
```

**These answer different questions and the default is deliberate.** Criticality ranking
rewards prevalence, so it surfaces the corpus's densest material -- which is exactly
what a well-covered caller has already built. Measured once against a tool with 78
registered techniques: every one of the fourteen items assessed as a real gap ranked
outside the top 30 under criticality. Use `--rank-by gap` whenever the question is
about coverage rather than about the technology.

**Supply the rich form of `--covered` whenever the caller has it.** `--covered` accepts
a file, one entry per line, where an entry may be `Name: description of the artefacts it
produces`. Matching a technique *name* against a pattern *name* compares two labels and
is why early verdicts were weak; matching what each side actually produces is a far
better signal. Measured on a five-item inventory it returns more decisive verdicts --
15 `yes` against 1 -- and the decisiveness is what has to be audited: on that run most
of the new `yes` verdicts did not survive reading them against the pattern. Treat a
`yes` as a claim to check, not a box already ticked.

`COVERAGE` is a token heuristic over each pattern's name and description, and it says
so in its own output. Measured against a 78-item summary inventory it returns 436 no,
36 partial and 8 yes, of which roughly half the yes verdicts are correct -- so **audit
them, do not act on them**. It cannot separate two techniques that share their defining
vocabulary -- a kernel module loaded to escape a container reads the same as one loaded
to hide a rootkit. **A verdict never removes a finding**, only demotes it, so a caller
who claims coverage they implement badly still sees the item. Audit by grepping
`COVERAGE: YES` and reading each `COVERAGE_BASIS`.

Do not hand-write the blocks. Run the script and build the reply around its output;
where a question needs reasoning the script cannot produce, add it around the blocks
rather than editing them. A format that varies per session is not a format.

Each finding carries the same blocks, in this order, and the key set does not vary
between findings even when a field is empty. `tests/test_locus_axis.py` asserts that,
which nothing did before 0.18.0:

| block | answers |
|---|---|
| `LOCUS` + `LOCUS_SPAN` + `LOCUS_BASIS` | **where the finding sits**, and on what signal |
| `COVERAGE` + `COVERAGE_BASIS` | whether the caller already implements it, and on what evidence |
| `ACTION` | **what to do** |
| `RATIONALE` | **why to do it** |
| `DETECTION_LOGIC` | the specifics, in full |
| `MARKERS` | typed, machine-readable specifics |
| `TELEMETRY_REQUIRED` | what it needs to fire |
| `DATA_GAP` + `RECOMMEND_ACQUIRE` | **feeds the caller has not got and should build** |
| `CAVEAT_VERBATIM` | the known false positive, word for word |
| `COUNTERMEASURES` | **what to do about it once found**, contain and eradicate first |
| `RESPONSE_DOCTRINE` | **in what order and how widely to act**, with the advisory cited |
| `REFERENCES` | **vendor, publisher and framework citations for code comments** |
| `METHODOLOGY` | how to proceed when the specifics are absent |

### Rules that are not negotiable

1. **Ordering is computed and stated.** Most critical and most recent first, by a
   scoring function whose inputs are printed as `PRIORITY_BASIS` on every finding.
   Never reorder by hand without saying so.
2. **`CAVEAT_VERBATIM` is reproduced exactly.** Never summarise it, never drop it. A
   detection handed over without its known false positive is worse than none.
3. **`STATUS: SEED` is unconfirmed** and must be presented that way. Seed means it
   was written from general knowledge and the source has not been re-read.
4. **Restricted sources are cited exactly as `where.title` states them.** No URL, no
   publisher, no filling the abstraction back in even when the report is
   recognisable. That is a licence condition, not a style choice.
5. **Recommend data acquisition.** If a detection needs telemetry the caller has not
   declared, that is a finding. Pass `--have` with whatever they told you they
   collect; anything missing becomes a `DATA_GAP` naming the connector to build.
   Saying nothing produces a rule that cannot fire. `--have` takes `evidence_type`
   values, a closed list in `corpus/schema/vocab.json`; a word that is not on it is
   accepted and then matches nothing, so translate what the caller said into that
   vocabulary rather than passing their words through.
6. **Say where an answer came from.** `DERIVATION` distinguishes a cited record from
   a library pattern matched on product class alone.
7. **An empty result is a finding about the corpus, not about the technology.** If
   the resolver returns nothing, say the term is missing from
   `corpus/schema/aliases.json` and offer to add it. Never let silence read as
   coverage.
8. **`LOCUS_ABSENT` is reported to the caller, never swallowed.** A locus with no
   match is a statement about this corpus and this question. It is not a statement
   that the locus is covered, and it is not a statement that it is safe.
9. **Answer across the MANAGEMENT, CONTROL and DATA planes, every time.** A
   technology has more than one relationship to an attack and the caller needs all
   three: the thing being attacked (CONTROL -- the appliance as a reachable service,
   and as the gate users authenticate through), the thing being administered
   (MANAGEMENT -- its console, its policy, its admin accounts), and the thing that
   SEES (DATA -- the traffic, URL, DNS, TLS and threat telemetry it produces).
   Name each plane as a heading and give several findings under each. Where a plane
   is genuinely thin, say so in that plane's own words rather than omitting it.

   **The ranked output is an input to the answer, not the answer.** Criticality
   ordering returns whatever the corpus is densest in, and density is not balance.
   Measured on "I have a Palo Alto firewall": 143 records touch the firewall, VPN
   gateway and proxy classes and **129 of them are `role: victim`**, so the top
   ranked findings were almost entirely the appliance-as-target -- while the **14
   non-victim records** (6 `control_bypassed`, 5 `inline_tool`, 2 `telemetry_source`,
   1 `lateral_path`), the patterns readable from that firewall's own telemetry and the
   remote-access authentication family sat below the cut and went unmentioned. The
   caller had to ask for the two planes the ranking had buried. (Counts are over the
   four `network.*` classes named above and move with the corpus; the ratio is the
   point, and it has been about nine in ten victim at every size the corpus has been.)

   So query the planes deliberately rather than taking the top of one ordering:
   filter records by `what.role` for the non-victim relationships, and filter
   patterns by `applies_to_classes` and by the `evidence_type` the technology
   actually emits.

10. **Carry the detail that makes a finding actionable.** A use-case answer names the
   pattern id, what it detects, the telemetry it needs, its ATT&CK ids, and the
   reference URLs -- source, ATT&CK, D3FEND countermeasure and response doctrine. A
   plane heading with no pattern ids under it is a topic list, not a consultation.
   Say plainly when patterns are generic (`vendor: any`) mechanism patterns the
   caller's logs can answer rather than incidents naming their product; the two carry
   different weight and the difference must not be blurred.

### Further reading, when you need it

- `references/locus-and-coverage.md` -- where a finding sits, why criticality ranking alone
  returns a lopsided answer, and what `LOCUS_ABSENT` does and does not claim. Read it when a
  spread looks wrong or before changing how the quota picks.
- `references/answering-another-session.md` -- the one-call contract for a rule-design consult
  from another session. Read it when the caller is a session rather than a person.
- `corpus/README.md` -- what a record guarantees. Read it before building on one.

### When the caller asks something the script cannot answer

Coverage diffs, scenario chains and "what are we missing" questions need reasoning
on top. Run `consult.py` for the per-finding blocks anyway and wrap the analysis
around them, so the machine-readable part stays intact and the prose is clearly
additional.

## Answering a question, fast

```sh
python3 scripts/query.py "I have a Cisco FW"
```

One line per match. A technology with real history returns thirty or more records,
so **start here and expand only what the question needs** -- the full form of the
same query costs about ten times as much to read.

**The listing is capped and says so.** For the query above the header reads `20 of 38
observation(s) and 10 of 88 exposure(s) shown, of 1151 records in corpus`, and an `OUTPUT CAPPED:` line names the flag to raise when the caps
bite: `--limit` for observations, `--exposure-limit` for exposures, `--pattern-limit` for
the library block, which shows six of the class's patterns by default. What a cap removes
is the tail of the ranking, never the corpus, so raise them when the question is "what is
there" rather than "what matters most". Under `--json` the same numbers ship in a `counts`
object, because a caller reading JSON has no other way to tell a capped array from a
complete one.

```sh
python3 scripts/query.py "I have a Cisco FW" --full     # detection logic and caveats
python3 scripts/emit_xql.py <record-id> --json          # the rule-authoring handoff
```

The resolver prints what it resolved to. If it resolves to nothing useful, the term
is missing from `corpus/schema/aliases.json` and belongs there.

### Reading the result

1. Lead with records where `what.role` is `victim`, then where the technology was
   the attacker's tool or the path through, then the rest.
2. Give `how.logic` in full and say what telemetry it needs.
3. **Always repeat `caveat`.** A detection handed over without its known false
   positive is worse than none.
4. **Never present a `status: seed` record as confirmed.** Seed means it was
   written from general knowledge and the source has not been re-read.
5. **Cite restricted sources exactly as `where.title` states them, no further.**
   Those come from licensed intelligence; the abstraction is deliberate and must
   not be filled back in, even when the underlying report is recognisable.

### Library patterns

A query also returns patterns that no record cites, matched on product class.
These are derived from technique space rather than from one incident, so they carry
no story -- but they are often the most reusable answer, and several are corroborated
by external detection rules. Say where they came from.

## What the corpus holds

1,151 records in `corpus/observations/observations.jsonl`, grouped by vendor, plus 475
patterns. Two record types:

- **`observation`** (`obs-`) -- hand-written, carries `how[]` detection logic.
- **`exposure`** (`exp-`) -- a vulnerability fact, no detection logic. Bulk-generated
  from the KEV catalogue so a product is findable by name. Do not add markers.

Detection logic is carried as typed `markers[]` against a closed vocabulary, plus a
`rule_shape` (`single_event`, `threshold`, `correlation`, `sequence`, `absence`,
`inventory`). Generic markers live on the **pattern**; source-specific literals live
on the **record**; the handoff supplies both unmerged.

`corpus/reference/d3fend-countermeasures.json` ships 272 D3FEND 1.5.0 countermeasures
keyed by the ATT&CK ids every finding already prints, which is what lets a consultation
answer what to do as well as what to look for. Lists are ordered contain, eradicate,
recover first, so a truncated answer loses the tail rather than the first step. D3FEND
covers 212 of the 410 technique ids this corpus cites: the other 48% report the gap
rather than an empty block, because silence must not read as coverage.

`corpus/reference/response-doctrine.json` holds 12 sequencing and scoping rules, matched
on a finding's product class and impact: collect before you mitigate, plan containment
assuming the adversary is watching, a factory reset is not eradication on a compromised
appliance. Each cites the advisory it came from. They are read in incident order rather
than lifecycle order, so preparation comes last, being the part nobody can action today.

`corpus/reference/attack-techniques.json` ships 1,166 ATT&CK v19.1 techniques with the
log sources each is visible in and the elements ATT&CK says to tune locally, so a
rule author needs no separate ATT&CK copy.

## Scope

In scope: what has happened to a vendor, product or product class; the detection
logic and telemetry for each; carrying a class-level lesson across vendors, so
somebody asking about their VPN concentrator gets more than their brand.

Out of scope: vulnerability management (CVEs are recorded where a source named
them; this is not a feed); attribution (actor names are repeated as sources gave
them, not adjudicated); Data Model Rule authoring (that is the
`cortex-platform-xdm-author` bundle).

## The corpus ships complete

The corpus arrives populated, validated and current. Nothing here needs syncing or
re-ingesting before it will answer a question, and a newer corpus arrives as a newer
version of the skill rather than as a fetch.

**One script reaches the network and it is worth knowing about.** `scripts/advise.py`
re-checks cited URLs that were last checked more than 14 days ago, by running `curl`,
and writes the result back to `corpus/reference/url-liveness.json`. That is on by
default. Pass `--no-verify` to answer purely from the shipped cache, which makes the
bundle entirely offline and leaves it unmodified. Everything else -- `consult.py`,
`query.py`, `emit_xql.py`, `validate.py` -- is offline and read-only already.

`corpus/README.md` is the contract behind the data -- record granularity, the six
keys, the vocabularies, the marker rules and the restricted-source rules. Read it to
know what a record guarantees before building on one.

To confirm the corpus survived transit:

```sh
python3 scripts/validate.py
```

One pass over schema, vocabulary, referential integrity, the marker contract and
disclosure hygiene. It exits non-zero if any of them fail.

## Scripts

- `scripts/query.py` -- lookup. Brief by default, `--full` for detail, `--json` for
  machine use, `--role` / `--sector` to filter.
- `scripts/validate.py` -- schema, vocabulary, referential integrity, marker
  contract, and disclosure hygiene. Fails if a restricted record carries a URL or a
  report identifier.
- `scripts/emit_xql.py` -- the handoff. Emits markers, ATT&CK context, D3FEND
  countermeasures and provenance. The XQL it prints is a skeleton for inspection,
  **not a finished rule**. `--shape` narrows to one `rule_shape`. The tally on stderr
  accounts for every candidate block as emitted, skipped for having no markers, or
  filtered by `--shape`, and when the filter takes everything it names the shapes that
  were actually present -- which is the answer whenever the shape name was a typo.
- `scripts/advise.py` -- **answers the pattern question**, "here are the shapes I am
  considering". Exact selection by pattern id or ATT&CK id, free text accepted but labelled
  a guess in `MATCH_BASIS`, corroboration and observation kept separate, caveats verbatim,
  D3FEND countermeasures per pattern, URL liveness cached. One call replaces the
  five-to-eight hand-written searches this previously took.
- `scripts/consult.py` -- **answers the technology question**, "I run this, what should I
  worry about". Resolves the term against the alias table and prints `RESOLVED_TO`. Fixed
  block text with stable keys, ranked by criticality and recency with the basis printed,
  telemetry gaps reported as acquisition recommendations, D3FEND countermeasures per
  finding. `--have` declares what the caller collects, `--covered` what they already
  implement, `--rank-by criticality|gap` chooses the question being answered, `--today`
  fixes the date for reproducible ranking. Exit 1 when nothing matched, exit 2 when
  `--rank-by gap` is asked for without `--covered`, so a caller can tell an empty answer
  from a failure.

Run every command from the bundle root -- the directory holding `SKILL.md` -- because
the paths above are relative to it and fail from anywhere else.

Python 3.9+, standard library only. The one external dependency is `curl`, used by
`scripts/advise.py` for URL re-checking and not needed under `--no-verify`.
