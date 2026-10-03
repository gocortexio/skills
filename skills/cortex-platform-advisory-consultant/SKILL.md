---
name: cortex-platform-advisory-consultant
description: Consult on what a vendor technology has historically been caught up in, what to detect as a result, and what to do about it once found. Answers three questions from a corpus of 1,142 threat advisory records joined to MITRE ATT&CK and D3FEND. One, scoping -- "I run this technology, what should I worry about" -- which works even when the corpus has never heard of the product. Two, rule design -- "here are the patterns or techniques I am considering, what does the corpus say". Three, coverage -- "what should I build that I have not got", ranked by gap against what the caller already implements. Answers cover the management, control and data planes, not only the plane the ranking favours. Use whenever someone names a firewall, VPN, EDR, cloud platform, OT device or any product they run and asks what to worry about, what to detect, what use cases to build, or where coverage is thin.
version: 0.44.0
license: AGPL-3.0-or-later
---

<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# cortex-platform-advisory-consultant

The current version is 0.44.0; the per-version change history lives in [CHANGELOG.md](CHANGELOG.md).


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
Handing the same words to `advise.py` returns up to three token-overlap guesses per phrase,
because `advise.py` selects and does not resolve.

**Pass `--have` with the telemetry you collect**, as `evidence_type` values from
`corpus/schema/vocab.json`, to either script. Without it every `DATA_GAP` comes back
`UNASSESSED`, which is not the same answer as "no gap"; any other value is refused and named
in `DECLARED_TELEMETRY_REJECTED`.

**Read the echo before you read a finding.** Both scripts state what they did with the
request, because a guess is returned in the same confident format as an exact match:

- `consult.py` prints `RESOLVED_TO:` in its header. It can resolve wider than you asked:
  "I have a Cisco firewall" resolves to `vendors=Cisco | classes=network.firewall`, and the
  class is what carries the lesson across vendors. A vendor or product you did not name is
  the first thing to check; `references/resolution.md` has the ones that once resolved
  falsely, and one this page documented as intended.
- `advise.py` prints a `### SHAPE:` banner per group and `MATCH_BASIS:` per pattern.
  `selected exactly by pattern id` and `selected exactly by ATT&CK id` mean you got what you
  named. `free-text overlap on <tokens> (score N) - VERIFY THIS IS THE RIGHT PATTERN BEFORE
  CITING IT` means the corpus ranked a guess for you. Nothing emits a line beginning
  `SELECTION:`; that text is the tail of the `### SHAPE:` banner. A parent `--attack` id also
  selects its sub-techniques and a revoked one is answered as MITRE's replacement would be,
  each with its own `MATCH_BASIS`; `ATTACK_REQUESTED` says what became of every id, and
  `SHAPE_RESULT` what each free-text shape added.
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
product name holds none. `consult.py` answers in labelled modes and prints which one it
used on a `RESOLUTION:` line:

| mode | when | what it means |
|---|---|---|
| `product` | an observation names the product, or the vendor when no product was named | the tight case |
| `VENDOR-LEVEL` | observations name the vendor, none the product | findings are the vendor's other lines or class analogues |
| `CLASS-LEVEL (inferred)` | only a class matched | answering on product class alone |
| `CLASS-LEVEL (declared via --as)` | you asserted the class | same, and you chose it |
| `NAME_WITHOUT_OBSERVATIONS` | a name resolved, no observation is about it | every finding came from tag or prose |
| `EXPOSURES_ONLY` | only exposure records name it | no findings; `EXPOSURE` blocks, exits 0; re-ask with `--as` |
| `mechanism` | nothing resolved, words matched | see the response contract |
| `UNRESOLVED` | nothing matched | exits 1, and prints how to re-ask |

`references/resolution.md` says how each mode is decided.

```bash
python3 scripts/consult.py "Portkey"                       # UNRESOLVED, tells you what to do
python3 scripts/consult.py "Portkey" --as app.ai_platform  # 32 findings
python3 scripts/consult.py "Portkey" \
  --as app.ai_platform,network.proxy,security.pam,cloud.saas   # 116, all six loci filled
```

**Name every class the technology behaves as.** The measurement above is the argument: one
class matched 32 findings and left ORGANISATION empty; naming what the thing also *is* -- a
proxy, a credential store, a SaaS app -- matched 116 and filled all six loci. A single class
is usually an under-description.

Every mode but `product` and `mechanism` prints a `CLASS_LEVEL_WARNING`, worded for the
mode, and it must survive into whatever you write. A class-level answer says what this
*kind* of technology has been caught up in, and passing it on as product intelligence is the
one failure here worse than an empty answer.

**When the corpus has nothing at all**, say so and report the term back here.
`consult.py` exits 1 when nothing matched, no finding, exposure or library pattern, and 2
when `--rank-by gap` was asked for without `--covered` or `--role` names an unknown role,
so an empty answer is distinguishable from a failure; `advise.py` exits 1 when nothing was
selected and says which path came back empty, since an id that does not exist is a
different problem from a guess that missed; `query.py` exits 0 either way. All three exit 2
when a count flag is below its floor (`--limit` and `--per-locus` 1, `--exposure-limit` and
`--pattern-limit` 0, `--per-shape` 1) rather than reading it as a slice from the end. An
empty consultation is far more often a term missing from `corpus/schema/aliases.json` than a
technology the corpus has never seen, so name the term you tried. That is a corpus gap and
it is fixable.

## The response contract

**You can ask by mechanism, not only by technology.** `consult.py "phishing"` reaches 78
findings and `"prompt injection"` 95; before 0.22.0 both returned nothing, because the
resolver only searched vendor and product names. A question that resolves to no vendor but
matches record wording is reported as `RESOLUTION: mechanism` rather than as unresolved.

**Every finding carries `MATCH_TIER:` and a `MATCH_BASIS:` sentence saying how it was
reached** -- `product` (names the product asked about), `vendor` (names the vendor, in a
class asked about), `class` (an analogue about another product), `vendor-other-class` (the
vendor's other product lines), `tag`, `name-fragment`, or `pattern` and `summary`, printed
`LOOSE`. `ORDERING` groups them before the score: product and vendor, then class and
vendor-other-class, then the rest, so a record naming your product is never outranked by a
fresher analogue. Loose matches may be about something else: 31 records once answered a
vendor query they are not about, all via prose. Treat a `LOOSE` finding as a lead.

**`name-fragment` means a word from the question sits inside a name nothing resolved.**
Read the `TECHNOLOGY:` line before treating such a finding as being about your technology;
roughly half of them are about something else. `UNMATCHED_TERMS:` lists the question's words
that reached no record, and a mechanism answer adds `MECHANISM_WARNING:` when one of them
looks like a name, with `CANDIDATE_CLASSES:` for an `--as` re-ask.

**The header says which words resolved and which were refused.** `RESOLVED_BY:` follows
`RESOLVED_TO:` and names the alias behind every vendor, product, class and sector. `GATED:`
appears when a word matched an alias and was refused because it is also an ordinary word:
`exchange` in "key exchange", `quantum` in "post-quantum", `IDs` in "event IDs", `ms` in
"500 ms". Such a product word resolves only within two words of a name for its vendor or of
an unambiguous product of that vendor, so `Cisco IOS` and `Cisco ASA and IOS` work and `iOS
apps` does not. A class acronym (IDS, IPS, RADIUS, AD, RAN, SIM, CI) resolves only where that
word is written in capitals, so **a consumer that lower-cases its questions loses those
routes**. `any` is never a vendor. Words a resolved alias consumed are not searched again as
free text, and a refused word reaches nothing it was refused as. **Read `RESOLVED_TO:` and
`RESOLVED_BY:` against the words you actually wrote.** If a class appears that you did not
mean, name your technology explicitly or pass `--as`, and treat everything under
`RESOLUTION: CLASS-LEVEL (inferred)` as the guess it is labelled as.
`references/resolution.md` has the rules, what each one fixed, and the two words (`relay`,
`switch`) still known to resolve falsely.

**The header's `MATCH_TIERS:` line is the check.** It counts the whole match set by tier
before `--limit` truncates, so `product=0, vendor=0, class=0` beside `RESOLVED_TO:
vendors=- | products=- | classes=-` is self-consistent and a consumer can gate on it without
parsing English. If those two ever disagree -- nothing resolved by name, yet findings
claiming a subject tier -- the answer is wrong and the tally is how you see it.

**Every finding carries a `SUPPORT:` line** saying when the source was last read and
whether it was verified -- the axis ranking and `CORROBORATION` do not cover. Bracketed
flags mark findings backed more weakly than the rest: `NO_READ_DATE`,
`VERIFICATION_UNSTATED`, `SOURCE_NOT_FULLY_RE-READ`, `SEED`, and
`NO_PUBLICATION_DATE:ranked-as-3650d`. Weigh a flagged finding accordingly rather than
discarding it; 89% of observations carry no flag at all, so a flag means something.
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
| `LOCUS` + `LOCUS_SPAN` + `LOCUS_BASIS` | **where the finding sits**, and on what signal; a class the question named only appends to the span |
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

After the findings, `EXPOSURE` blocks list the exposure records naming what was asked, with
handset records refused and counted, and `LIBRARY` blocks the patterns no record cites.
Every key is prefixed, and neither takes a slot or clears `LOCUS_ABSENT`;
`references/exposures.md` has the contract.

### Rules that are not negotiable

1. **Ordering is computed and stated.** Most critical and most recent first, by a
   scoring function whose inputs are printed as `PRIORITY_BASIS` on every finding.
   Never reorder by hand without saying so.
2. **`CAVEAT_VERBATIM` is reproduced exactly.** Never summarise it, never drop it. A
   detection handed over without its known false positive is worse than none.
3. **`STATUS: SEED` is unconfirmed** and must be presented that way. Seed means it
   was written from general knowledge and not fully re-read against its source, or the
   source was re-read and supports only part of it, which its `STATUS` line names.
4. **Restricted sources are cited exactly as `where.title` states them.** No URL, no
   publisher, no filling the abstraction back in even when the report is
   recognisable. That is a licence condition, not a style choice.
5. **Recommend data acquisition.** If a detection needs telemetry the caller has not
   declared, that is a finding. Pass `--have` with whatever they told you they
   collect; anything missing becomes a `DATA_GAP` naming the connector to build.
   Saying nothing produces a rule that cannot fire. `--have` takes `evidence_type`
   values, a closed list in `corpus/schema/vocab.json`; any other word is refused, so
   translate what the caller said into that vocabulary rather than passing their words
   through.
6. **Say where an answer came from.** `DERIVATION` on a finding is always a cited
   record. Patterns no record cites come in `LIBRARY` blocks, matched on class alone,
   and exposures in `EXPOSURE` blocks, as vulnerability facts with no detection logic.
   Neither is a finding: say which one you are passing on.
7. **An empty result is a finding about the corpus, not about the technology.** If
   the resolver returns nothing, offer to add the term to
   `corpus/schema/aliases.json`, never a handset. Never let silence read as
   coverage.
8. **`LOCUS_ABSENT` is reported to the caller, never swallowed.** A locus with no
   eligible match (`LOCUS_ELIGIBLE`; its bullet says what did reach it) is a statement
   about this corpus and this question. It is not a statement that the locus is covered,
   and it is not a statement that it is safe.
9. **Answer across the planes, every time, headed by the `LOCUS` the script printed.**
   The headings are the six `locus` values in `corpus/schema/vocab.json`, and each finding
   goes under the `LOCUS` it prints. Never re-judge a finding's plane: where you disagree
   with one, say so under its printed heading rather than moving it. Always head
   MANAGEMENT, CONTROL and DATA, and each of ENDPOINT, SUPPLY and ORGANISATION that
   `LOCUS_ELIGIBLE` populates. In the vocabulary's words, MANAGEMENT is "Administration of
   the subject", CONTROL is "The subject's own decisioning", in the network sense, so a
   cloud provider's control-plane API is MANAGEMENT, and DATA is "What traverses or is
   held". A locus in `LOCUS_ABSENT` keeps its heading and says what its bullet says reached
   it; one in `LOCUS_ANALOGUE_ONLY` says nothing there names what was asked and names each
   finding's own product from `TECHNOLOGY`. Give several findings under each:
   `--per-locus 3 --limit 18`.

   **The ranked output is an input to the answer, not the answer.** Criticality ordering
   returns whatever the corpus is densest in, and most records touching a network
   appliance's classes are `role: victim`, so the top of one ordering is mostly the
   appliance as target (`references/locus-and-coverage.md` has the measurement). A
   technology's other relationships to an attack -- the control the attacker bypassed, the
   tool it used, the telemetry that saw it, the path it crossed -- are a `what.role`, one
   per record, not a plane, and each such finding sits on whatever `LOCUS` it prints. Ask
   for them with `--role control_bypassed,inline_tool,telemetry_source,lateral_path`, and
   filter patterns by `applies_to_classes` (the `LIBRARY` blocks do) and by the
   `evidence_type` the technology actually emits.

10. **Carry the detail that makes a finding actionable.** A use-case answer names the
   pattern id, what it detects, the telemetry it needs, its ATT&CK ids, and the
   reference URLs -- source, ATT&CK, D3FEND countermeasure and response doctrine. A
   plane heading with no pattern ids under it is a topic list, not a consultation.
   Say plainly when patterns are generic (`vendor: any`) mechanism patterns the
   caller's logs can answer rather than incidents naming their product; the two carry
   different weight and the difference must not be blurred.

### Further reading, when you need it

- `references/locus-and-coverage.md` -- where a finding sits, why criticality ranking alone
  returns a lopsided answer, what `LOCUS_ABSENT` does and does not claim, and what
  `LOCUS_ELIGIBLE`, `RECORD_CAP`, `ROLE_FILTER` and each finding's `SLOT` say. Read it when a
  spread looks wrong or before changing how the quota picks.
- `references/answering-another-session.md` -- the one-call contract for a rule-design consult
  from another session, and the header and finding keys both scripts print. Read it when
  the caller is a session rather than a person.
- `references/exposures.md` -- what the `EXPOSURE` and `LIBRARY` blocks list, their order and
  header counts, and the handset refusal. Read it before relying on either block.
- `references/emit-xql.md` -- what the XQL skeleton promises, its statuses and comment kinds,
  and the `--json` handoff keys. Read it before passing a skeleton on.
- `references/resolution.md` -- how a question's words become vendors, products and classes,
  what `RESOLVED_BY:` and `GATED:` say, and which ordinary words are gated. Read it when
  `RESOLVED_TO:` names something you did not ask about.
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
observation(s) and 10 of 89 exposure(s) shown, of 1142 records in corpus`, and an `OUTPUT CAPPED:` line names the flag to raise when the caps
bite: `--limit` for observations, `--exposure-limit` for exposures, `--pattern-limit` for
the library block, which shows six of the class's patterns by default. What a cap removes
is the tail of the ranking, never the corpus, so raise them when the question is "what is
there" rather than "what matters most". Under `--json` the same numbers ship in a `counts`
object, because a caller reading JSON has no other way to tell a capped array from a
complete one.

```sh
python3 scripts/query.py "I have a Cisco FW" --full     # detection logic and caveats
python3 scripts/emit_xql.py <observation-id> --json     # the rule-authoring handoff
```

Each line ends `loci=` with the plane or planes the record sits in, and a `LOCUS over shown:`
header line counts them and names the absent ones.

The resolver prints what it resolved to. If it resolves to nothing useful, the term
belongs in `corpus/schema/aliases.json`, unless it names a handset.

### Reading the result

1. Lead with records where `what.role` is `victim`, then where the technology was
   the attacker's tool or the path through, then the rest.
2. Give `how.logic` in full and say what telemetry it needs.
3. **Always repeat `caveat`.** A detection handed over without its known false
   positive is worse than none.
4. **Never present a `status: seed` record as confirmed.** Seed means its source was
   not fully re-read, or supports only part of it, as `STATUS` says.
5. **Cite restricted sources exactly as `where.title` states them, no further.**
   Those come from licensed intelligence; the abstraction is deliberate and must
   not be filled back in, even when the underlying report is recognisable.

### Library patterns

A query, and a consultation's `LIBRARY` blocks, also return patterns that no record
cites, matched on product class.
No incident here is behind them, so they carry no story -- but they are often the most
reusable answer, and several are corroborated by external detection rules. Say where
they came from: `LIBRARY_MATCH` quotes each pattern's own `derived_from`.

## What the corpus holds

1,142 records in `corpus/observations/observations.jsonl`, grouped by vendor, plus 475
patterns. Two record types:

- **`observation`** (`obs-`) -- hand-written, carries `how[]` detection logic.
- **`exposure`** (`exp-`) -- a vulnerability fact, no detection logic, generated from
  the CISA KEV catalogue, ZDI, vendor PSIRT feeds and NVD, or written by hand from a joint
  government advisory. Do not add markers.

Detection logic is carried as typed `markers[]` against a closed vocabulary, plus a
`rule_shape` (`single_event`, `threshold`, `correlation`, `sequence`, `absence`,
`inventory`). Generic markers live on the **pattern**; source-specific literals live
on the **record**; the handoff supplies both unmerged.

`corpus/reference/d3fend-countermeasures.json` ships 272 D3FEND 1.6.0 countermeasures
keyed by the ATT&CK ids every finding already prints, which is what lets a consultation
answer what to do as well as what to look for. A block takes one control per tactic in
turn, contain, eradicate and recover first, a control D3FEND maps directly before one it
only infers, and names the rest in `NOT_SHOWN`. D3FEND covers 222 of the 407 technique
ids this corpus cites, 12 through a revoked predecessor: the other 45% report the gap
rather than an empty block, because silence must not read as coverage.

`corpus/reference/response-doctrine.json` holds 12 sequencing and scoping rules, matched
on a finding's product class and impact: collect before you mitigate, plan containment
assuming the adversary is watching, a factory reset is not eradication on a compromised
appliance. Each cites the advisories that say it, with their own words. They are read in
incident order rather than lifecycle order, so preparation comes last, being the part
nobody can action today.

`corpus/reference/attack-techniques.json` ships 1,166 ATT&CK v19.2 techniques with the
log sources each is visible in and the elements ATT&CK says to tune locally, so a
rule author needs no separate ATT&CK copy.

## Scope

In scope: what has happened to a vendor, product or product class; the detection
logic and telemetry for each; carrying a class-level lesson across vendors, so
somebody asking about their VPN concentrator gets more than their brand. A question naming
only a vendor is carried to the classes of that vendor's own records, printed as
`CLASSES_FROM_VENDOR:`.

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
  **not a finished rule**, but every line it prints as XQL is XQL: a computed or unbound
  condition is a comment saying why, and each header says `filter=complete|partial|none`.
  Given a consultation's `FINDING_KEY` (`<record-id>#how<n>`) it emits that one block.
  `references/emit-xql.md` has the skeleton, the statuses and the handoff keys.
- `scripts/advise.py` -- **answers the pattern question**, "here are the shapes I am
  considering". Exact selection by pattern id or ATT&CK id (a parent includes its
  sub-techniques unless `--attack-exact`), free text accepted but labelled a guess in
  `MATCH_BASIS`, corroboration and observation kept separate, `LOCUS_OBSERVED` beside
  `LOCUS`, caveats verbatim, D3FEND countermeasures per pattern, URL liveness cached. One
  call replaces the five-to-eight hand-written searches this previously took.
- `scripts/consult.py` -- **answers the technology question**, "I run this, what should I
  worry about". Resolves the term against the alias table and prints `RESOLVED_TO`. Fixed
  block text with stable keys, grouped by match tier and then ranked by criticality and
  recency with the basis printed, telemetry gaps reported as acquisition recommendations,
  D3FEND countermeasures per finding. `--have` declares what the caller collects,
  `--covered` what they already implement, `--rank-by criticality|gap` chooses the question
  being answered, `--per-locus` and `--role` set depth per plane and the relationship,
  `--today` fixes the date for reproducible ranking. `EXPOSURE` and `LIBRARY` blocks
  follow the findings, capped by `--exposure-limit` and `--pattern-limit`. Exit 1 when
  nothing matched, no finding, exposure or library pattern, exit 2 when `--rank-by gap` is
  asked for without `--covered` or on an unknown `--role`, so a caller can tell an empty
  answer from a failure.

Run every command from the bundle root -- the directory holding `SKILL.md` -- because
the paths above are relative to it and fail from anywhere else.

Python 3.9+, standard library only. The one external dependency is `curl`, used by
`scripts/advise.py` for URL re-checking and not needed under `--no-verify`.
