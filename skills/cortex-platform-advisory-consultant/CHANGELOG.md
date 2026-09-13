<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Changelog

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
  a question resolves through; and **`route.py` has no delete**, so a merge orphans a
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

- **`route.py` was left behind by the 0.7.0 consolidation and is fixed.** It still
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
