<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Answering another session's consult: one call, not six

Read this when another session asks this skill a rule-design question, rather than a person
asking about a technology they run.

A rule-design consult from another session -- "here are three shapes I am considering,
what does the corpus say" -- was costing **five to eight round trips**, each one a
hand-written search re-deriving the same three things. The corpus loads in 0.08s, so
none of that was compute; it was all latency. `scripts/advise.py` collapses it:

```sh
python3 scripts/advise.py --patterns pat-log-forwarding-gap,pat-log-restored-to-original-state --have syslog,auth_log
python3 scripts/advise.py --attack T1685.006
python3 scripts/advise.py "a device stops sending logs"   # best-effort, labelled as such
```

One invocation returns, per pattern, one key per line: `MATCH_BASIS`, `NAME`, `FIDELITY`,
`RULE_SHAPE`, `CLASSES`, `LOCUS`, `LOCUS_SPAN`, `LOCUS_BASIS`, `LOCUS_OBSERVED`,
**`CORROBORATED`** (public rule-library counts) and **`OBSERVED`** (citing records) as
separate claims, `ATTACK`, full `LOGIC`, `CAVEAT_VERBATIM`, `TELEMETRY_REQUIRED`,
`DATA_GAP`, `COUNTERMEASURES` and `RESPONSE_DOCTRINE`. The key set is the same on every
pattern, so a consumer can parse `^LOCUS: (.*)$` and get one of the six loci.

- `OBSERVED: yes, N record(s), M how-block(s)` counts distinct records, adds `; K of the records
  seed: U citing how-block(s) unconfirmed, S supported by a re-read source` where any is, then
  lists up to six,
  newest first, as `[STATUS] <record id> | <date or undated> | LOCUS <locus> | <title> |
  <url>`, and names the rest by id on a `... N more record(s) not shown:` line. A title is
  never cut: a restricted one is cited as given, whole.
- `LOCUS` is where the pattern applies: from its `applies_to_classes`, from its own markers,
  shape and evidence where a block's would decide (`input=pattern ...`: a pattern testing only
  a cloud administrative operation is `MANAGEMENT`, an inventory question reading only posture
  is `ORGANISATION`), or the locus a pattern declares with its reason (`tier=declared;
  input=locus declared on the pattern, ...`). `LOCUS_OBSERVED` is
  where its citing blocks sit, placed as `consult.py` places them, and when all of them agree
  on another locus that locus is the span, `span-source=observed span`. The two are separate
  claims, as corroboration and observation are.
- `COUNTERMEASURES` takes one D3FEND control per tactic in turn, ordered within a tactic by
  fit: a control D3FEND maps directly to a cited technique before one it only infers, then the
  one more of the cited techniques reach, then one acting on the artefact before one D3FEND
  defines as acting on the whole host (Host Reboot, Host Shutdown), and lists the rest on an
  indented `NOT_SHOWN:` line. Each shown control ends `| direct`, `| inferred-narrower` (it inherits
  a mapped class's relation) or `| inferred-broader` (a class containing a mapped control),
  and the header names every cited technique: those whose controls are shown, `also
  mapped`, `every control also reached above`, and `not mapped by D3FEND`. An unmapped parent
  whose sub-techniques D3FEND maps names them, and they are not joined: a sub-technique's
  controls are not its parent's.
  `RESPONSE_DOCTRINE` is matched on the pattern's classes and the impact of its citing
  records, and says so.

The header opens with `CORPUS`, `FINDINGS` and `SELECTED_BY`, and then says what became of
every id asked for, on stdout: `PATTERNS_REJECTED`, one `ATTACK_REQUESTED` line per
`--attack` id (live, a parent and its sub-techniques, `REVOKED` and followed to MITRE's
replacement and that replacement's sub-techniques, with a revoked parent's own revoked
sub-techniques followed to theirs, each route counted, `DEPRECATED`, or not in the shipped
reference), and `ATTACK_RECORD_ONLY` or
`ATTACK_PARENT_ONLY` where an id reaches patterns another way. `ATTACK_RECORD_ONLY` prints
whenever how-blocks cite the id under patterns it does not select, whether or not it selected
any, and names each record carrying them that cites no pattern returned, so appears nowhere
else in the answer. `SHAPES_EMPTY`,
`DECLARED_TELEMETRY` and `DECLARED_TELEMETRY_REJECTED` follow, then `LOCUS_RETURNED` and
`LOCUS_ABSENT` over the patterns returned, and it closes with `URL_LIVENESS` and `CONTRACT`.
When nothing was selected, a `NO_MATCH` line after the header says which path came back
empty, and the script exits 1. Every free-text shape gets a `### SHAPE:` banner with a
`SHAPE_RESULT` line, which counts the patterns that overlapped the shape and how many
`--per-shape` cut, and a `SUGGEST_ATTACK` line where the shape names an ATT&CK technique by
id or by name; a suggestion never selects anything. Free text is matched against a pattern's
name, description and id, then its logic and technique names, then, at half the weight of
the logic, its markers, caveat and the text of the records citing it, so a defender's word
such as "webshell", "vishing" or "mimikatz" reaches a pattern whose own prose never uses it.
The halves of a split word ("webshell" read as "web shell") are met only together. With
`--per-shape` 3 or more, when the shape names a behaviour in ATT&CK's words ("exploitation"
names Exploit Public-Facing Application) and no guess above the last cites it, the last guess
is kept for a detection of it, alert or hunt, that meets every other word of the shape in its
name, logic or classes; its `MATCH_BASIS` names the technique and the `--attack` that selects
every pattern citing it. A shape spelling a whole ATT&CK name ("pass the hash") names that
technique only. `ATTACK_RECORD_ONLY` names a pattern another selection already returned as
returned, not as one to select.

**Prefer `--patterns` and `--attack`.** Free-text search is kept but demoted to a
labelled guess, because it is not reliable here: this corpus names patterns evocatively
rather than descriptively, so a search for audit-trail destruction returned a
cloud-network-exposure pattern whose `logic` happens to contain "provider audit trail".
Finding the right pattern is the part to do by judgement; assembling and verifying it is
the part that was costing the time.

**The label is the only thing marking it as a guess.** A free-text guess comes back in the
same confident format as an exact match: same blocks, same corroboration counts, same
verbatim caveat, same citable references. So read `MATCH_BASIS:` on every pattern before
reading any finding. Preferring the exact flags is not a substitute, because it is on the
occasions somebody falls back to free text that the line matters.

**URL liveness is cached with a date** in `corpus/reference/url-liveness.json`, re-checked
after 14 days. It pays for itself twice: it removes the per-consult verification cost, and
a URL that was live and is now empty is a deprecated technique -- which is how the whole
T1562 family was caught.

## When the session asks the technology question

"I run this, what should I worry about" is `consult.py`'s question, and the same rule holds:
run it in the session that needs the answer and pass the output on whole, because it is keyed
so that nobody has to summarise it. `tests/test_reference_key_lists.py` holds both lists
below to what the script prints.

**Consultation header keys**, in this order; a key in brackets prints only when its condition
holds: `QUESTION`, `RESOLVED_TO`, `RESOLVED_BY`, [`GATED`, when a word matched an alias and was
refused], [`CLASSES_FROM_VENDOR`, when only a vendor resolved], `CORPUS`, [`ROLE_FILTER`, under
`--role`], `RESOLUTION`, [`CLASS_LEVEL_WARNING`, for every mode but `product` and
`mechanism`], `UNMATCHED_TERMS`, [`MECHANISM_WARNING` and `CANDIDATE_CLASSES`, when a mechanism
answer left a name unmatched], `FINDINGS`, `MATCH_TIERS`, `ORDERING`, `LOCUS_SPREAD`,
`LOCUS_MATCHED`, `LOCUS_ELIGIBLE`, `LOCUS_SUBJECT`, `LOCUS_SHOWN`, `LOCUS_ABSENT`,
`LOCUS_ANALOGUE_ONLY`, `LOCUS_DISPLACED`,
`LOCUS_RESERVED`, `RECORD_CAP`, [`LOCUS_UNDERSERVED`, when `--limit` is below the reserve],
`DECLARED_TELEMETRY`, `DECLARED_TELEMETRY_REJECTED`, `RANK_BY`, `DECLARED_COVERAGE`,
[`COVERAGE_TALLY` and `COVERAGE_IS_HEURISTIC`, under `--covered`], [`DEMOTION`, under
`--rank-by gap`], `EXPOSURES`, `EXPOSURE_KINDS`, `EXPOSURE_LOCUS`, `EXPOSURE_LOCUS_SPAN`,
`EXPOSURES_NOT_LISTED`,
`EXPOSURE_ORDERING`, `EXPOSURE_DATA_GAP`, `EXPOSURE_SCOPE`, `LIBRARY_PATTERNS`,
`LIBRARY_LOCUS`, `LIBRARY_ORDERING`, `CONTRACT`. An answer with nothing to list stops at
`FINDINGS`: under a `--role` that kept nothing it adds `NO_FINDINGS` and exits 1; otherwise
it prints `EXPOSURES_NOT_LISTED` before `FINDINGS` when the question reached an exposure,
and after it what to re-ask with, `CANDIDATE_CLASSES` among it, or, where a handset name stands
in a question that resolved no vendor, product or class, the handset refusal
(`references/exposures.md`). An answer with exposures and
no finding prints the whole header and adds `NO_FINDINGS` after it. `LOCUS_ABSENT`,
`LOCUS_ANALOGUE_ONLY`, `LOCUS_DISPLACED`, `LOCUS_RESERVED`, `RECORD_CAP` and
`EXPOSURE_DATA_GAP` carry indented
bullets, and `references/locus-and-coverage.md` and `references/exposures.md` say what each
line holds.

**Consultation finding keys**, in this order and the same on every finding: `RANK`, `SLOT`,
`PRIORITY`, `PRIORITY_BASIS`, `RECORD_ID`, `PATTERN_ID`, `FINDING_KEY`, `STATUS`,
`SOURCE_DISCLOSURE`, `CORROBORATION`, `SUPPORT`, `MATCH_TIER`, `MATCH_BASIS`, `TECHNOLOGY`,
`PRODUCT_CLASS`, `LOCUS`, `LOCUS_SPAN`, `LOCUS_BASIS`, `DERIVATION`, `ATTACK`, `RULE_SHAPE`,
`FIDELITY`, `IDENTIFIERS`, `COVERAGE`, `COVERAGE_BASIS`, `ACTION`, `RATIONALE`,
`DETECTION_LOGIC`, `MARKERS`, `TELEMETRY_REQUIRED`, `DATA_GAP`, `CAVEAT_VERBATIM`,
`COUNTERMEASURES`, `RESPONSE_DOCTRINE`, `REFERENCES`, `METHODOLOGY`. `FINDING_KEY`,
`<record-id>#how<n>`, is the one that is unique, and `emit_xql.py` takes it to hand off that
one block. The `EXPOSURE` and `LIBRARY` blocks that follow the findings prefix every key, so
none of these keys ever matches a line in them.
