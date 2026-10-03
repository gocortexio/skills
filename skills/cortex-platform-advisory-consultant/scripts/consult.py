#!/usr/bin/env python3
# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Emit a consultation in the fixed advisory format, for another session to build from.

The consumer of this output is a detection-engineering session that will write rules
in a language this skill does not know. That constrains the format in three ways, and
each is a decision rather than a preference.

**It is block text with stable keys, not prose.** A calling session has to find the
caveat and the telemetry list without parsing English. Every block is `KEY: value` or
`KEY:` followed by an indented body, and the key set does not vary between findings
even when a field is empty -- an absent key would have to be distinguished from an
empty one, and that is exactly the ambiguity that makes output unparseable.

**The order is computed, not chosen.** "Most critical and most recent" is a ranking
rule, so it is applied by a scoring function and the inputs are printed in
`PRIORITY_BASIS` on every finding. A reader who disagrees with the order can see what
produced it. An order asserted without its basis is not reviewable. Relevance comes
before the score and is a grouping rather than a multiplier: records naming the product
or vendor asked about, then class analogues and the vendor's other product lines, then
free-text leads, each finding printing its `MATCH_TIER` and its group. No multiplier
could promise that a record naming the product outranks a fresher analogue.

**Data the caller does not have is a finding, not a silence.** If a detection needs
`cloud_audit` and the caller has not declared it, saying nothing produces a rule that
cannot fire. `--have` declares what is collected; everything required and undeclared
becomes a `DATA_GAP` entry naming the connector to acquire. Recommending acquisition
is the consultant's job, so the absence of a feed is reported as work rather than
quietly designed around.

Three rules from the corpus contract survive into this format unchanged, because
breaking them makes the output actively harmful:

- `caveat` is reproduced verbatim and is never summarised. A detection handed over
  without its known false positive is worse than no detection.
- `status: seed` is printed in upper case with an explicit not-confirmed marker.
- Restricted sources are cited exactly as `where.title` states them, with the URL
  field forced to `RESTRICTED`, because the abstraction is a licence condition.

**Coverage matching is deliberately conservative, and its residual error is measured.**
Four defects were found and fixed after a caller reported a false positive: an overlap
that merely restated the caller's own label counted as a match; ordinary English words
leaked in once callers supplied prose instead of bare names, so richer input made
verdicts *worse*; marker literals such as `.credentials$` were tokenised into words that
prose could match; and a comma-and-newline split shredded multi-word entries into
fragments that still matched. Against a 78-item summary inventory the matcher now
returns 436 no, 36 partial and 8 yes, of which roughly half the yes verdicts are right.
That residual is inherent to matching category names rather than artefacts -- supplying
the richer "Name: what it produces" form is what improves it, and it now measurably
does, returning more decisive verdicts rather than noisier ones. Every yes prints its
basis so it can be audited in one grep, and coverage never removes a finding.

**Every finding says where it sits, and the answer says what it did not cover.** Ranking
by criticality alone returns whatever the corpus is densest in: the pure top twelve for
a Cisco firewall was eleven MANAGEMENT findings and one CONTROL, which reads as a
complete answer and is a monoculture. `LOCUS` places each finding on one of six values
-- CONTROL, MANAGEMENT and DATA where the subject decomposes into planes, and ENDPOINT,
SUPPLY and ORGANISATION where it does not, because roughly half the corpus is a host, a
dependency or a process rather than a device with three planes. The label is computed
from `attack_surface` and `product_class` by the ladder in `corpus/schema/locus-map.json`,
with the block's own evidence, techniques and cloud operations deciding whether the record's
surface reaches it and whether it tests a cloud administrative API, never guessed and never
moved by the question. `evidence_type` can add a second locus to `LOCUS_SPAN`, and the class
the question named can only append one after the record's own. `LOCUS_BASIS` prints every
signal, including the ones that lost. A block may declare `locus` to override the derivation,
and must then say why in the record's notes; a pattern may declare one with `locus_reason`.

Two consequences follow, and both are the point rather than side effects. The header
prints `LOCUS_ABSENT`, naming every locus holding no eligible finding -- a subject or tag
match at or above the MODERATE floor -- with a bullet saying what did reach it: a
statement about this corpus and this question, never a statement that the locus is safe.
And the shown set reserves `--per-locus` slots per eligible locus, so a thin locus is not
buried by a dense one -- from findings naming the product or vendor where the question named
one and a finding names it, with `LOCUS_ANALOGUE_ONLY` naming the loci only analogues hold --
and no record takes more than two slots while another record's finding
in its match group waits, so one incident's blocks do not fill the answer and the cap never
gives a record naming the product up for an analogue; every slot either costs is printed under
`LOCUS_DISPLACED` or `RECORD_CAP` with the finding it displaced, and every block prints its
`SLOT`, because a reordering that hides its own cost is not reviewable. `--no-locus-spread`
restores pure ORDERING order and still prints the distribution.

**Exposures and library patterns are answers too, and never findings.** 901 of the corpus's
records are exposures, vulnerability facts with no how-block, and 34 patterns are cited by no
record; until 0.43.0 this script printed neither, so "Check Point firewall" never showed the
catalogue's newest Check Point identifiers. They now follow the findings in `EXPOSURE` and
`LIBRARY` blocks, under header groups of their own, with every key prefixed. An exposure is
listed only where it names what was asked, by product or vendor, never another vendor's by
class alone, because a CVE carries no detection logic to transfer; the handset records
`corpus/schema/scope.json` names are refused and counted. Neither block takes a slot, counts
in a finding tally or clears `LOCUS_ABSENT`, whose bullets count them. `references/exposures.md`
is the contract.

Note that `control plane` means the network sense throughout: forwarding, routing,
signalling and session establishment. A cloud provider's control-plane API is
administration and lands in MANAGEMENT. The corpus previously used the phrase both ways.

Standard library only.
"""

import argparse
import collections
import datetime
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import query as Q  # noqa: E402  the resolver is shared deliberately, not reimplemented

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(os.path.dirname(HERE), "corpus")

# Evidence type mapped to the thing an operator would have to go and buy, switch on or
# build. Deliberately phrased as an acquisition action rather than a product name: the
# corpus should not be recommending vendors, and the calling session knows its own
# platform better than this does.
CONNECTOR = {
    "auth_log": "authentication logging from the application or appliance, forwarded centrally",
    "cloud_audit": "cloud provider audit trail (administrative API log) ingested per account and per region",
    "config_diff": "device or platform configuration under version control, or a change feed to diff against",
    "dns": "resolver query logging, or DNS collection at the network sensor",
    "edr_file": "endpoint agent file-event telemetry, with the relevant paths in scope",
    "edr_process": "endpoint agent process-execution telemetry including command line and parent",
    "email_gateway": "mail gateway message and verdict logging",
    "file_artefact": "file collection or retro-hunt capability over collected artefacts",
    "http_proxy": "forward or reverse proxy logging with URL path retained, not just domain",
    "ics_protocol": "industrial protocol capture at the IT/OT boundary",
    "integrity_check": "vendor integrity verification output, or a release-manifest comparison job",
    "memory": "memory acquisition capability on the affected host class",
    "netflow": "flow records or firewall session logging covering the relevant segment",
    "network_ids": "network intrusion detection sensor with signature and anomaly output",
    "process_telemetry": "host process telemetry (agent or auditd-class) on the affected host class",
    "registry": "endpoint agent registry telemetry",
    "syslog": "device syslog forwarded to a central collector",
    "tls_metadata": "TLS handshake metadata (JA3/JA4-class fingerprint, SNI, certificate subject)",
    "vuln_scan": "authenticated vulnerability scanning covering the asset class",
    "web_server": "web or application server access logging with full request path",
    "asset_inventory": "an asset inventory that can answer which hosts run this product and version",
}

# Framework references worth carrying into a code comment, keyed by identifier prefix.
# Order matters and is not alphabetical. The ICS pattern must be tested before the
# generic one, because T0883 satisfies both and would otherwise be labelled enterprise
# ATT&CK. `dotted` says whether the identifier keeps its dot in the URL: ATT&CK turns
# T1078.004 into a path segment, ATLAS does not and AML.T0051 stays whole.
FRAMEWORK = [
    (re.compile(r"^T0\d{3}$"), "MITRE ATT&CK for ICS", "https://attack.mitre.org/techniques/{}/", False),
    (re.compile(r"^T\d{4}(\.\d{3})?$"), "MITRE ATT&CK", "https://attack.mitre.org/techniques/{}/", False),
    (re.compile(r"^FGT"), "MITRE FiGHT (5G)", "https://fight.mitre.org/techniques/{}", True),
    (re.compile(r"^AML\."), "MITRE ATLAS (AI)", "https://atlas.mitre.org/techniques/{}", True),
]

# One scored finding. This was a bare tuple until the locus fields took it to twelve
# positions, at which point `f[6]` stopped being readable and started being a puzzle.
# Named fields only; no behaviour change.
# `refined` is the question's leftover words this record's tags or prose carry, after the
# technology resolved; it orders findings within a group and never changes the weight.
# `group` is the ORDERING group after any coverage demotion, `sector` the sector reason when
# the record was seen in a sector the question named, `crit` the weight before the gap
# multiplier, `reasons` what Q.score() matched it on, and `fit` whether the block's markers are
# written for the platform the question names (Q.platform_fit: +1, 0 or -1). `scope` is
# block_scope()'s verdict for a block of a campaign record the product reason reached, and
# None for every other block.
Finding = collections.namedtuple(
    "Finding",
    "weight record how pattern band basis verdict why locus span locus_basis how_index "
    "match_basis refined group sector crit reasons fit scope",
    defaults=((), 2, None, 0.0, (), 0, None))

# Words too common to distinguish one technique from another. A caller item has to
# overlap a pattern on at least two tokens outside this set before it counts as a
# name match, which is what stops "AccountManipulation" claiming every pattern that
# happens to mention an account.
STOPWORDS = {
    "abuse", "access", "account", "attack", "check", "code", "command", "common",
    "control", "data", "detection", "discovery", "escape", "execution", "file",
    "high", "host", "information", "local", "modify", "network", "process",
    "protocol", "remote", "scan", "server", "service", "simulation", "system",
    "test", "tool", "user", "value", "over", "from", "with", "into", "that", "this",
    # Three-letter function words slipped past the length floor and carried matches on
    # their own: "the" was appearing in MATCH_BASIS lines as if it were evidence.
    "the", "and", "for", "not", "any", "its", "was", "are", "has", "can", "who", "how",
    "where", "when", "what", "which", "than", "then", "them", "they", "each", "onto",
}

TECH_ID = re.compile(r"^(T\d{4}|T0\d{3}|FGT[\w.]+|AML\.[\w.]+)(\.\d{3})?$", re.I)
CAMEL = re.compile(r"[A-Z]+(?![a-z])|[A-Z][a-z]+|[a-z]+|\d+")

# How much a coverage verdict suppresses a finding when ranking by gap. Never zero:
# a caller who claims coverage they implement badly must still see the item, demoted,
# with the reason printed. Silencing on a self-declared claim is the failure shape
# this corpus has been caught by repeatedly.
# Demotion, not suppression, and deliberately gentler than it first was. The verdict is
# a token heuristic over prose: it cannot tell a kernel module loaded to escape a
# container from one loaded to hide a rootkit, because both are named the same things.
# At 0.2 a wrong `yes` buried a genuine gap seventy places down, which is suppression by
# another name. At 0.3 a covered item still leaves the top of the list and a wrong
# verdict stays close enough to be seen and overruled.
COVERAGE_WEIGHT = {"no": 1.0, "partial": 0.6, "yes": 0.3, "unassessed": 1.0}

FIDELITY_WEIGHT = {"alert": 3.0, "hunt": 2.0, "enrich": 1.0}
# Calibrated against the achievable range, not chosen by eye. The maximum score is
# fidelity 3.0 + prevalence 3.0 + identifiers 1.5 + victim 1.0 = 8.5 at full recency,
# so a CRITICAL floor above that would be a band nothing could ever reach -- which is
# how the first version of this shipped, silently capping every finding at MODERATE.
MAX_SCORE = 8.5
BANDS = [(7.0, "CRITICAL"), (5.0, "HIGH"), (3.0, "MODERATE"), (0.0, "CONTEXT")]


def attack_url(tid):
    for pattern, name, template, keep_dot in FRAMEWORK:
        if pattern.match(tid):
            return name, template.format(tid if keep_dot else tid.replace(".", "/"))
    return "MITRE ATT&CK", "https://attack.mitre.org/techniques/{}/".format(tid.replace(".", "/"))


# A date held to the year or the month: when.precision says which, and the record holds only
# that much. Only a full ISO date parsed, so the ten records dated this way printed "undated"
# and age_days() ranked them as 3,650 days old, while query.py's date_key read them.
PARTIAL_DATE = re.compile(r"^(\d{4})(?:-(\d{2}))?$")


def _held_date(record):
    """(the date, the string as the record holds it), the first of published, observed_end and
    observed_start that parses. A partial date is read as the first day of the period it
    names, so it is never ranked newer than it can be."""
    when = record.get("when") or {}
    for key in ("published", "observed_end", "observed_start"):
        value = when.get(key)
        if not value:
            continue
        try:
            return datetime.date.fromisoformat(value[:10]), value[:10]
        except ValueError:
            pass
        m = PARTIAL_DATE.match(str(value).strip())
        if m:
            try:
                return datetime.date(int(m.group(1)), int(m.group(2) or 1), 1), m.group(0)
            except ValueError:
                continue
    return None, None


def published(record):
    return _held_date(record)[0]


def published_text(record):
    """The record's date at the precision it holds it: 2022, 2026-08 or 2026-08-15."""
    return _held_date(record)[1]


def age_days(record, today):
    date = published(record)
    return (today - date).days if date else 3650


def _looks_like_a_path(value):
    """Is this argument meant to be a file rather than a literal list of covered items?

    Added after the pre-publication audit found that `--covered /tmp/typo.txt` exited 0 and
    reported the filename as one covered item, producing a confident coverage answer computed
    against nothing at all.
    """
    if "," in value or "\n" in value:
        return False
    return value.startswith(("/", "./", "../", "~")) or value.lower().endswith(
        (".txt", ".md", ".csv", ".json", ".jsonl", ".yaml", ".yml", ".tsv", ".list"))


def parse_covered(raw):
    """Split a caller's coverage list into technique identifiers and name token sets.

    Callers supply whatever they have: ATT&CK identifiers, their own class or struct
    names, or both. Identifiers are matched exactly; names are reduced to lower-case
    tokens with CamelCase split, so `CgroupReleaseAgentEscape` becomes the tokens that
    can be looked for in a pattern's own wording.
    """
    # Newline wins where the input has newlines. The rich form -- "Name: description of
    # the artefacts it produces" -- contains commas inside an entry, so splitting on both
    # separators shredded every entry into fragments. The fragments still matched things,
    # so the item count merely looked a little high rather than obviously wrong.
    text = raw or ""
    lines = [x for x in text.splitlines() if x.strip()]
    # More than one non-empty line means newline is the separator. Testing merely for the
    # presence of a newline was wrong the moment a comma-separated list arrived with a
    # trailing one: seventy-eight entries collapsed into a single item, and the run still
    # completed and still produced verdicts.
    parts = lines if len(lines) > 1 else text.split(",")
    ids, names = set(), []
    for item in parts:
        item = item.strip()
        if not item:
            continue
        if TECH_ID.match(item):
            ids.add(item.upper())
            continue
        # "Name: description of the artefacts it produces" is accepted as well as a bare
        # name. The label stays the name so the basis line reads sensibly, but the tokens
        # come from the whole entry. Matching a technique name against a pattern name is
        # comparing two labels and is why the verdicts were weak; matching the artefacts
        # each side actually names is a different and far better signal.
        label, _, detail = item.partition(":")
        label = label.strip() or item
        tokens = {w.lower() for w in CAMEL.findall(item if detail else label)}
        # Three characters, not four. Several of the most distinctive tokens a caller
        # can supply are short -- pam, ssh, dns, suid, cron -- and a four-character
        # floor silently reduced "PamBackdoor" to a single token, which can never
        # reach the two-token threshold and so could never match anything.
        distinctive = {w for w in tokens if len(w) >= 3 and w not in STOPWORDS}
        if distinctive:
            names.append((label, distinctive))
    return ids, names


# The DATA_GAP value when nothing can be assessed, and why. Two reasons, because a caller who
# declared nothing and a caller whose every declared value was refused are told different
# things to do next.
NO_INVENTORY = "UNASSESSED - caller declared no inventory"
REJECTED_INVENTORY = ("UNASSESSED - every --have value was rejected; "
                      "see DECLARED_TELEMETRY_REJECTED")


def parse_have(raw, vocab, technique_flag="--attack or --covered"):
    """(accepted evidence types or None, [(value, reason)]) for a `--have` value.

    Shared by consult.py and advise.py, so one input cannot mean two things. It accepted
    anything: `--have T1486` is an ATT&CK id, not an evidence type, and it silently turned
    every DATA_GAP from UNASSESSED into a confident MISSING/ACQUIRE list, as did a typo, a
    dataset name, `WEB_SERVER` in capitals and a lone comma. The two scripts also disagreed on
    `--have ''`: an empty set in one, which reported every requirement missing under a
    header saying nothing was declared, and None in the other.

    Case and separators are normalised (`WEB SERVER`, `web-server` -> `web_server`). A value
    that is not one of the evidence types in corpus/schema/vocab.json is refused with a
    reason, and when nothing is accepted the answer is None: UNASSESSED, never MISSING.
    Lenient rather than an exit 2, because callers really do pass dataset names and a
    refusal would cost them the rest of the answer; the header names every refused value.
    """
    if raw is None or not raw.strip():
        return None, []
    allowed = set((vocab or {}).get("evidence_type") or CONNECTOR)
    accepted, rejected = set(), []
    for item in raw.split(","):
        text = item.strip()
        if not text:
            continue
        value = re.sub(r"[\s-]+", "_", text.lower())
        if value in allowed:
            accepted.add(value)
        elif TECH_ID.match(text):
            rejected.append((text, "an ATT&CK id - use {}".format(technique_flag)))
        elif len(text.split()) > 1 and any(part in allowed for part in text.lower().split()):
            rejected.append((text, "not one evidence type; separate values with commas"))
        else:
            rejected.append((text, "not one of the {} evidence types in "
                                   "corpus/schema/vocab.json".format(len(allowed))))
    return (accepted or None), rejected


def have_header(have, rejected):
    """The DECLARED_TELEMETRY and DECLARED_TELEMETRY_REJECTED header lines, shared."""
    if have:
        declared = ", ".join(sorted(have))
    elif rejected:
        declared = "NONE DECLARED - every --have value was rejected; all DATA_GAP fields unassessed"
    else:
        declared = "NONE DECLARED - all DATA_GAP fields unassessed"
    return ["DECLARED_TELEMETRY: {}".format(declared),
            "DECLARED_TELEMETRY_REJECTED: {}".format(
                "; ".join("{} ({})".format(v, why) for v, why in rejected) or "none")]


def related(pattern_id, covered_id):
    """True only where the caller's identifier is a parent of the pattern's.

    Direction matters and the first version ignored it. A caller holding T1068.001,
    .002 and .003 -- three specific kernel exploits -- was treated as partially covering
    a pattern tagged plain T1068, which is the whole privilege-escalation class. Holding
    a child says nothing about the parent. Holding the parent may cover the child, so
    that direction is kept.
    """
    return (covered_id != pattern_id
            and "." not in covered_id
            and pattern_id.split(".")[0] == covered_id)


def build_rarity(patterns):
    """Token frequency and a postings index, so two different questions can be asked.

    A fixed stopword list cannot keep up: "path" and "run" are as uninformative as
    "system" here, and the next caller supplies vocabulary nobody anticipated. Corpus
    frequency answers that without maintenance -- a token appearing across a large share
    of patterns cannot distinguish one from another, whatever it means.

    But per-token rarity is not enough, and assuming it was produced two false positives
    in real use. "CredentialsInFiles" claimed a repository-scanning pattern on the tokens
    "credentials, files"; "KernelModuleEscape" claimed a rootkit-concealment pattern on
    "kernel, module". In both cases every token was individually uncommon and the pair
    was still uninformative, because the pair is simply the caller's own label restated
    and it fits dozens of patterns equally well.

    The postings index answers the question that actually matters: **how many patterns
    contain all of these tokens together.** A match that narrows the corpus to one or two
    patterns is evidence. A match that leaves forty candidates is a category name.
    """
    freq, postings = {}, {}
    for pid, pattern in patterns.items():
        blob = " ".join(str(x) for x in [
            pattern.get("name"), pattern.get("description"), pattern.get("logic")] if x).lower()
        for token in set(re.findall(r"[a-z0-9]+", blob)):
            freq[token] = freq.get(token, 0) + 1
            postings.setdefault(token, set()).add(pid)
    return freq, max(1, len(patterns)), postings


# How many patterns an overlapping token set may still fit before the match stops being
# evidence about any particular one. Two is deliberately tight: a real artefact match
# ("cgroup", "release_agent") lands on one pattern, while a restated category name
# ("credentials", "files") lands on many.
SELECTIVITY_LIMIT = 3


def coverage(record, how, pattern, covered, rarity=None):
    """Verdict on whether the caller already implements this, and why.

    Identifier-only agreement is deliberately reported as `partial`, never `yes`. An
    ATT&CK identifier is a coarser unit than a pattern: a caller holding any T1611
    technique would otherwise suppress every container-escape finding, including the
    specific routes they have not built. Only a match on the pattern's own wording is
    treated as real coverage.
    """
    if covered is None:
        return "unassessed", "caller declared no coverage inventory"
    ids, names = covered
    tech = {t.upper() for t in ((how or {}).get("technique") or [])}
    tech |= {t.upper() for t in ((pattern or {}).get("technique") or [])}

    # Two haystacks, not one, because they are not equally good evidence. The name and
    # description say what a pattern *is*; the logic and markers merely mention things.
    # "ModifyEnvironmentVariable" matched an authentication-interception pattern on
    # "environment, variable" appearing somewhere in its prose -- both rare tokens, and
    # the co-occurrence pure coincidence. A hit on the identity is treated as coverage;
    # a hit on the body is treated as a lead worth demoting for, and no more.
    def tokens_of(*parts):
        return set(re.findall(r"[a-z0-9]+",
                              " ".join(str(x) for x in parts if x).lower()))

    identity = tokens_of((pattern or {}).get("name"), (pattern or {}).get("description"))
    # Marker values are deliberately excluded. They are literals -- file paths, process
    # names, regexes -- and tokenising ".credentials$" or "config.sh" into words so that
    # a caller's prose can match them is the same tautology the selectivity test exists
    # to catch, arriving by a different route. Computed marker expressions are prose and
    # are kept; literal values are not.
    body = tokens_of((pattern or {}).get("logic"), (how or {}).get("logic"),
                     *[str(m.get("expr") or "")
                       for m in ((how or {}).get("markers") or (pattern or {}).get("markers") or [])])

    # Two overlapping tokens, at least one of which is rare enough across the corpus to
    # actually discriminate. Without the rarity test, "RunCMaskedPathEscape" claimed
    # every pattern containing "path" and "run".
    freq, total, postings = (rarity if rarity else ({}, 1, {}))

    def hit(tokens, hay):
        # Only corpus-rare tokens count toward the overlap at all. Requiring two tokens
        # of which merely one was rare let ordinary English carry the match: "the", "and"
        # and "for" are three characters, absent from any sensible stopword list, and
        # they multiplied as soon as callers supplied richer prose instead of bare names.
        # Supplying more detail made the verdicts worse, which is the opposite of what
        # richer input should do.
        overlap = {w for w in (tokens & hay) if freq.get(w, 0) <= 0.08 * total}
        if len(overlap) < 2:
            return None
        rare = sorted(overlap)
        # Selectivity: do these tokens together point at this pattern, or at a category?
        # Without this test an overlap that merely restates the caller's own label counts
        # as a match, which is how a container-escape technique came to claim a rootkit
        # pattern on the words "kernel" and "module".
        if postings:
            candidates = None
            for token in overlap:
                hits = postings.get(token, set())
                candidates = hits if candidates is None else (candidates & hits)
            if candidates is not None and len(candidates) > SELECTIVITY_LIMIT:
                return None
        return (overlap, rare)

    body_lead = None
    for label, tokens in names:
        found = hit(tokens, identity)
        if found:
            return "yes", ("caller item '{}' matches this pattern's name or description "
                           "on {} (discriminating: {}). HEURISTIC - audit before "
                           "acting on it.").format(
                label, ", ".join(sorted(found[0])[:4]), ", ".join(sorted(found[1])[:3]))
        if body_lead is None:
            found = hit(tokens, body)
            if found:
                body_lead = (label, found)
    if body_lead:
        label, (overlap, rare) = body_lead
        return "partial", ("caller item '{}' matches only this pattern's supporting prose "
                           "on {}, not its name or description, which is weak evidence "
                           "of coverage").format(label, ", ".join(sorted(overlap)[:4]))

    exact = sorted(tech & ids)
    if exact:
        return "partial", ("caller covers {} but identifier match alone does not "
                           "establish this specific route".format(", ".join(exact)))
    near = sorted({t for t in tech for c in ids if related(t, c)})
    if near:
        return "partial", ("caller covers a sibling of {} at different granularity"
                           .format(", ".join(near)))
    return "no", "no caller item matches this pattern's identifiers or wording"


# A seed record is unconfirmed for one of two reasons, as the schema's `status` and SKILL.md's
# rules define it: it was not fully re-read against its source, or it was and the source
# supports only part of the record. The banner once asserted the first alone, so the three
# records re-read on 2026-09-25 and held as seed printed "source not re-read" beside their own
# `verified=yes`; it then named both and sent the reader to notes nothing prints. A re-read
# seed record now says on every block whether its source supports it (how[].unconfirmed,
# required by validate.py), so the banner names the meaning that applies to the block it sits
# on. "Unread" says what where.verified false records, the whole record not re-read: ArcaneDoor's
# source was read on 2026-10-02 for one block, and "the source was not re-read" was then false.
SEED_TEXT = {
    "unread": "SEED - NOT CONFIRMED: written from general knowledge, and not fully re-read "
              "against its source",
    "unconfirmed": "SEED - NOT CONFIRMED: the source was re-read and does not support this block",
    "partial": "SEED - NOT CONFIRMED: the source was re-read and supports only part of the record",
    "supported": "SEED - the source was re-read and supports this block, not the whole record",
}


def seed_support(record, how_index=None):
    """Which seed meaning applies: None for a record that is not seed; for a block, unread,
    unconfirmed or supported; for the record as a whole, unread or partial.

    A block of a re-read seed is supported only where its `unconfirmed` is false: an unset flag
    fails closed. emit_xql.py, advise.py and validate.py decide it through this function, so
    the handoff, the citation counts and the refusal of `confidence: high` cannot disagree
    with the STATUS line.
    """
    if record.get("status") != "seed":
        return None
    if (record.get("where") or {}).get("verified") is not True:
        return "unread"
    blocks = record.get("how") or []
    if how_index is None or not 0 <= how_index < len(blocks):
        return "partial"
    return "supported" if blocks[how_index].get("unconfirmed") is False else "unconfirmed"


def status_line(record, how_index=None, key="STATUS"):
    """The STATUS line for a block (EXPOSURE_STATUS for a record), with the seed banner for the
    meaning that applies. emit_xql.py prints the same line in the skeleton for the same key.

    A supported block names the record's unconfirmed blocks, so its own support is never read
    as the record's.
    """
    status = (record.get("status") or "unknown").upper()
    part = seed_support(record, how_index)
    if part is None:
        return "{}: {}".format(key, status)
    text = SEED_TEXT[part]
    if part == "supported":
        rest = ["how[{}]".format(i) for i, how in enumerate(record.get("how") or [])
                if how.get("unconfirmed") is not False]
        text += "; unconfirmed: {}".format(", ".join(rest) if rest
                                           else "what it says outside its how-blocks")
    return "{}: {}  <<< {}".format(key, status, text)


def support(record, today):
    """How well-backed this finding is, on the axis nothing else in the block reports.

    Ranking already weighs recency and CORROBORATION already names independent accounts,
    but neither says when anybody last confirmed the source still says what the record
    claims. That matters more here than in most corpora: 30 observations carry no
    `retrieved` date at all, and a record whose source was read once and never revisited
    is a different kind of claim from one re-read last week. The flags are the point --
    a reader weighing twelve findings needs the weak ones to announce themselves rather
    than having to compute it.
    """
    where = record.get("where") or {}
    bits, flags = [], []

    # Age itself is deliberately NOT flagged here. PRIORITY_BASIS already prints
    # days_since_published and the ranking already decays recency, so a staleness flag
    # would restate both -- and it fired on 279 KEV exposures, which are old by
    # definition because the catalogue is a history. What is worth flagging is the
    # absence of a date, because age_days() silently treats an undated record as 3,650
    # days old and sinks it in the ranking with nothing saying so.
    pub = published(record)
    if pub:
        bits.append("published={} ({}d ago)".format(published_text(record), (today - pub).days))
    else:
        bits.append("published=unknown")
        flags.append("NO_PUBLICATION_DATE:ranked-as-3650d")

    read = (where.get("retrieved") or "").strip()
    if read:
        bits.append("source_last_read={}".format(read))
    else:
        bits.append("source_last_read=unrecorded")
        flags.append("NO_READ_DATE")

    # verified is False by schema definition when the record has not been fully re-read
    # against its source since it was written, so an absent key is not the same as a negative
    # one. The flag said SOURCE_NOT_RE-READ under a STATUS line saying "not fully re-read", and
    # ArcaneDoor's notes record a read of one block.
    if "verified" in where:
        bits.append("verified={}".format("yes" if where.get("verified") else "no"))
        if not where.get("verified"):
            flags.append("SOURCE_NOT_FULLY_RE-READ")
    else:
        bits.append("verified=unstated")
        flags.append("VERIFICATION_UNSTATED")

    if record.get("status") == "seed":
        flags.append("SEED")

    line = "SUPPORT: " + "; ".join(bits)
    if flags:
        line += "  [" + " ".join(flags) + "]"
    return line


# How much a match is trusted, by the tightest tier it came in on. A record naming the
# vendor answered the question; a record whose summary prose happens to contain the word
# may be about something else entirely. The 2026-08-19 measurement put numbers on that:
# widening the free-text haystack to prose reached 1,124 records over thirty mechanism
# terms against 33 before, and brought 31 records answering a vendor query they are not
# about -- every one of them via prose, none via a tag. The reach is wanted; the wrong
# answers outranking right ones is not, so prose matches are demoted rather than dropped.
# Every subject tier is trusted in full. What separates them is the group below, not the
# weight: a class analogue is a genuine finding about the class, and discounting it would
# only reorder it against free-text leads, which the group already does.
MATCH_WEIGHT = {"product": 1.0, "vendor": 1.0, "class": 1.0, "vendor-other-class": 1.0,
                "tag": 1.0, "name-fragment": 0.85, "pattern": 0.75, "summary": 0.6}

SUBJECT_TIERS = Q.SUBJECT_TIERS

# Relevance is a grouping, not a multiplier. Until 0.43.0 every structured match was one
# tier at weight 1.0 and the order was criticality times recency alone, so a fresh class
# analogue always beat an older record naming the product: "Fortinet FortiGate" put a Cisco
# FMC record at rank 1 and Fortinet at ranks 7 and 9, and "PAN-OS" led with the same Cisco
# record. No multiplier can promise that a record naming the product outranks a fresher
# analogue; a group can. Records naming the product or vendor asked about come first; then
# the class analogues and the vendor's other product lines, which share a group because
# putting the vendor's other lines below the class dropped the PAN-OS record to rank 70 for
# "Palo Alto Panorama"; then free-text leads. Product and vendor share the first group, so a
# product nothing names is still answered by its vendor's records ahead of every analogue. On
# a question naming a product, the vendor's other products follow the product inside it
# (follows_subject()): 0.43.0 left the two unordered, reading "ASA ahead of FMC for Cisco ASA"
# as a statement about the corpus's dates, and the 2026-10-01 fourth validation found the
# management centre leading the ASA's own answer four times over; of 95 such answers, 66 led
# with the vendor's other product.
MATCH_GROUP = {"product": 0, "vendor": 0, "class": 1, "vendor-other-class": 1,
               "tag": 2, "name-fragment": 2, "pattern": 2, "summary": 2}
LAST_GROUP = max(MATCH_GROUP.values())

# What may fill a reserved locus slot, and what makes a locus count as represented. Until
# 0.43.0 any match did: the quota took the first finding of every locus with a match at all,
# with no floor and no relevance test, so "Fortinet FortiGate" reserved ORGANISATION for a
# geolocation-limits record at score 1.50 (CONTEXT, 2,262 days old) and pushed out a record
# naming FortiGate, and "Check Point firewall" reserved ENDPOINT and ORGANISATION for records
# reached only by the word "point". Even after the tiers and the resolver of 0.43.0 had removed
# most of that filler at source, 143 of 1,900 reserved slots over 836 product questions sat
# below MODERATE and 55 came from free text.
#
# A tag match is eligible in every mode. Once the words a resolved name accounted for are no
# longer searched, a tag hit on a named question can only come from a word the caller wrote
# beyond the name, which is on topic; excluding it left "helpdesk social engineering" with
# four of six loci absent where it now has two. The name-fragment and prose tiers never are:
# about half of those findings are about something else. The floor is the MODERATE band's,
# read before the gap multiplier, so a locus the caller already covers is not reported
# absent in gap mode.
ELIGIBLE_TIERS = SUBJECT_TIERS + ("tag",)
RESERVE_FLOOR = next(floor for floor, name in BANDS if name == "MODERATE")

# The tiers that name what was asked, and so the only ones a reserved slot is filled from when
# the question named a product or vendor and a finding names it. Eligibility still decides
# LOCUS_ABSENT; this decides the reserve. Until the 2026-09-30 validation any eligible tier
# filled it, so "Fortinet FortiGate" reserved DATA and ENDPOINT for two other-product class
# analogues -- a known-vulnerability catalogue join and a Zeppelin share-enumeration block
# whose ENDPOINT came from its first-listed endpoint.os, at score 3.71 -- and pushed out two
# FortiGate findings, one of them at 3.92, while the header counted both planes as represented.
# "Cisco ASA" --per-locus 3 reserved the same two records, and so did the Palo Alto, Check
# Point, Juniper and Firepower questions. A locus whose eligible findings are all analogues is
# named in LOCUS_ANALOGUE_ONLY instead, and an analogue reaches it on rank alone. Where no
# finding names what was asked, the answer is analogues throughout, CLASS_LEVEL_WARNING says
# so, no finding naming it can be displaced, and the reserve spreads the analogues as before.
NAMING_TIERS = ("product", "vendor")

# The most slots one record takes while another record's finding in its own match group is
# still waiting. Findings are per how-block, and a record's blocks share recency, identifiers
# and role, so they score in a narrow band and sort together: "Atlassian Confluence" showed 6
# blocks of one PBX record in twelve, 8 in pure order, and 617 of 836 product questions gave
# one record 3 or more slots. Two is a choice, not a measurement: it keeps a record's
# detection and its follow-up together. The cap never crosses a group, because across groups
# it gave a record naming the product up for another vendor's analogue: 178 of 848 product
# questions lost 566 such findings. 266 of 836 questions still show a record 3 or more times,
# 175 of them a record naming the product, and each only where its match group, or a locus's
# reserve, held no other record's finding to take the slot.
RECORD_CAP = 2


# What the question asked about, as the quota and the locus lines count it. NAMING_TIERS is it
# wherever the question named no product of a vendor that a `vendor` finding names. Where it
# did, that finding names the vendor in a class asked about and another of its products, as its
# MATCH_BASIS says ("but not the product asked about"), and RESOLUTION and the exposure tiers
# already read it so. Until the 2026-10-01 fourth validation the quota did not: "Cisco ASA"
# counted three Secure Firewall Management Center blocks in LOCUS_SUBJECT, reserved MANAGEMENT
# for them and left it out of LOCUS_ANALOGUE_ONLY, though FMC administers Firepower Threat
# Defense and not ASA software. Decided per vendor: "Cisco ASA and Fortinet firewall" named
# Fortinet without a product, so Fortinet's vendor-tier findings stay what was asked, and a
# product whose name is its vendor's ("SimpleHelp", "Okta") names nothing narrower than the
# vendor. Where nothing names the product and a finding names its vendor in a class asked about,
# that is the tightest tier present and it keeps the reserve it had, named as the vendor's.
# `narrowed` says the subject is smaller than NAMING_TIERS; `tiers` is what LOCUS_SUBJECT
# prints and `names` what the locus lines name; `bare` the vendors whose vendor-tier findings
# count beside tier `product`; `makers` the vendors whose do not; `unnamed` the products nothing
# names when the subject fell back to the vendor. Unnarrowed, every count is the one
# NAMING_TIERS gives, and `names` is every product and vendor the question resolved.
Subject = collections.namedtuple("Subject", "narrowed tiers names bare makers unnamed")
WHOLE = Subject(False, NAMING_TIERS, frozenset(), frozenset(), frozenset(), frozenset())


def reason_vendor(reasons):
    """The resolved vendor a finding's `vendor ...` reason stands for (Q.vendor_reason()): the
    vendor itself, the one a record's own spelling was read as, the vendor named inside a
    generic record's entry, or the member a parent's record is filed for."""
    for reason in reasons or ():
        if reason.startswith("vendor "):
            named = reason[len("vendor "):]
            if " (as " in named:
                return named.split(" (as ", 1)[1].rstrip(")")
            for sep in (" (named in product ", " (filed under "):
                if sep in named:
                    return named.split(sep, 1)[0]
            return named
    return None


def question_subject(findings, resolved):
    """The question's Subject over its match set, decided once per answer.

    A maker is the vendor of a product the question named, with its kin ("VMware" for
    Broadcom), unless the product's name is the vendor's own or the vendor is a sentinel; a
    bare vendor is any other vendor it resolved. Only an eligible vendor-tier finding naming a
    maker narrows the subject: to tier `product` beside the bare vendors' vendor tier, or,
    where no finding names the product and no bare vendor holds one, to the makers' vendor
    tier, named as theirs. Anything else is WHOLE, and its answer is unchanged.
    """
    resolved = resolved or {}
    products = set(resolved.get("products") or ())
    vendors = set(resolved.get("vendors") or ())
    whole = WHOLE._replace(names=frozenset(products | vendors))
    if not products:
        return whole
    kin = resolved.get("vendor_kin") or {}
    makers = set()
    for vendor, product in resolved.get("product_pairs") or ():
        if vendor and vendor not in Q.SENTINEL_VENDORS \
                and Q.normalise(vendor) != Q.normalise(product):
            makers |= {vendor, kin.get(Q.normalise(vendor), vendor)}
    bare = vendors - makers
    # Over the eligible findings, which are all LOCUS_SUBJECT, the reserve and
    # LOCUS_ANALOGUE_ONLY count: a vendor-tier finding below the floor changes no count.
    named = [reason_vendor(f.reasons) for f in findings
             if f.match_basis == "vendor" and eligible(f)]
    other = {v for v in named if v not in bare}
    if not other:
        return whole
    kept = frozenset(v for v in named if v in bare)
    if kept or any(f.match_basis == "product" for f in findings):
        return Subject(True, ("product", "vendor") if kept else ("product",),
                       frozenset(products | kept), kept, frozenset(other), frozenset())
    return Subject(True, ("vendor",), frozenset(other), frozenset(), frozenset(other),
                   frozenset(products))


def follows_subject(finding, subject=None):
    """Does this finding sort after what was asked inside its group? A vendor-tier finding the
    subject leaves out, in the group naming what was asked. Until the 2026-10-01 fourth
    validation product and vendor shared group 0 with no order between them, so the management
    centre led "Cisco ASA" at ranks 1 and 2, FortiManager took ranks 2 and 3 of "Fortinet
    FortiGate", and Outlook ranks 1 and 2 of "Microsoft Exchange": of the 95 product questions
    whose subject leaves such a finding out, 66 led with another of the vendor's products."""
    return bool(subject is not None and subject.narrowed and "product" in subject.tiers
                and finding.match_basis == "vendor" and finding.group == MATCH_GROUP["vendor"]
                and not names_subject(finding, subject))


def names_subject(finding, subject=None):
    """Does this finding name what the question asked about (question_subject())?"""
    if subject is None or not subject.narrowed:
        return finding.match_basis in NAMING_TIERS
    if finding.match_basis == "vendor" and "product" in subject.tiers:
        return reason_vendor(finding.reasons) in subject.bare
    return finding.match_basis in subject.tiers


def match_basis(reasons, resolved=None):
    """Which tier this record matched on, tightest first, and what that is worth.

    A product reason puts the record in `product`. A vendor reason for a record filed under
    the vendor asked about puts it in `vendor` when the record also carries a class the
    question resolved, or the question resolved none, and in `vendor-other-class` when it
    carries none of them: that is the vendor's other product lines, which is its history and
    not this product's. A class reason alone is `class`, an analogue. Until 0.43.0 all of
    these were one tier, `identity`, labelled "named this technology", so a class analogue
    read as though it named the product.

    A vendor named inside a generic record's products is weaker than a record filed under the
    vendor. It is `vendor` only where it would name what was asked: no product was asked
    about, and the record carries an asked-for class or the question resolved none. "GitHub"
    is answered from eleven such records. Otherwise it is the record's class reason, or a
    name fragment: the Guardsquare question resolves the Android vendor and two
    build-pipeline classes, and a botnet record listing "Android TV boxes" reached its top 12
    at full weight labelled as naming the technology; five endpoint records listing "Linux
    servers" are not about "Linux kernel".

    Refine, sector and cross-sector reasons decide no tier. A refine reason is a leftover
    question word found in a record that already matched by name, and score() adds a sector
    reason only to a record that already matched on technology, so it says where the
    record's victims were and nothing about whether it names what was asked. Read as a
    subject match, a sector re-promoted a demoted record whenever the question named one.

    Anything else is a reason shape this function does not know, and it is given the
    weakest tier rather than the tightest. Until 2026-08-27 an unrecognised reason fell
    into an else branch and was labelled a subject match at full weight, which is failing
    open on the side that makes a coincidence read like an answer.
    """
    resolved = resolved or {}
    reasons = [r for r in reasons or ()
               if not r.startswith(("refine ", "sector ", "cross-sector"))]

    def tier(name):
        return name, MATCH_WEIGHT[name]

    if any(r.startswith("product ") for r in reasons):
        return tier("product")
    class_hit = any(r.startswith("class ") for r in reasons)
    in_class = class_hit or not resolved.get("classes")
    vendors = [r for r in reasons if r.startswith("vendor ")]
    if any(not Q.named_in_product(r) for r in vendors):
        return tier("vendor" if in_class else "vendor-other-class")
    listed = bool(vendors)
    if listed and in_class and not resolved.get("products"):
        return tier("vendor")
    if class_hit:
        return tier("class")
    if listed:
        return tier("name-fragment")
    tiers = set()
    for reason in reasons:
        if reason.startswith("term ") and reason.endswith(")"):
            found = reason.rsplit("(", 1)[1].rstrip(")")
            tiers.add(found if found in MATCH_WEIGHT and found not in SUBJECT_TIERS
                      else "summary")
        else:
            tiers.add("summary")
    for name in Q.TIER_ORDER:
        if name in tiers:
            return tier(name)
    return tier("summary")


def names_what_was_asked(reasons, resolved):
    """Does this record name the vendor or product the question named, in its asked-for class?

    That is the `product` and `vendor` tiers of match_basis(), and nothing else: a vendor's
    other product lines are its history, not this product's, and a vendor named inside a
    generic record's products names it only where no product was asked about and the record
    sits in an asked-for class, or none was asked about.
    """
    return match_basis(reasons, resolved)[0] in ("product", "vendor")


# --- which blocks of a campaign record concern what was asked ---------------------------------
#
# A record filed under a sentinel vendor ("any", "Multiple") lists what a campaign reached, and
# a product reason puts the whole record in the `product` tier, as a vendor named inside one of
# its entries puts it in `vendor`. Findings are per how-block, and until the 2026-09-30
# validation every block of such a record took that tier: "Microsoft Exchange" drew its whole
# product tier from one record listing Fortinet appliances, Exchange and VMware Horizon, and two
# of the four blocks it showed from it detect another product -- an outbound directory lookup
# for the logging-library flaw, and the FortiOS username-case second-factor bypass -- each
# printed as "names the product asked about", so a consumer gating on MATCH_TIER product passed
# on an appliance MFA bypass as Exchange's, and "Fortinet" printed the same Log4j block as
# naming Fortinet, through the record's entry "Fortinet appliances".
#
# The first reading of a block demoted it whenever the resolver found any other product in its
# text, and the 2026-10-01 review counted about a dozen blocks that were about what was asked
# demoted that way: the ESXi hypervisor-encryption block (/vmfs/volumes/, vmdk) for "Windows
# hosts" in a list of the three platforms one intrusion covered, the npm install-hook worm for a
# passing "self-hosted runner", the GitHub Actions runner block for the record's own co-listed
# entry "self-hosted runners", the IIS appcmd and inetsrv block for "BadIIS", an alias the table
# files under the Telerik entry, and Laravel's only block for a "/.git/" path fragment. So a
# block is now read for evidence that it concerns what was asked before anything it names is
# read against it, and a name takes a block away only where the block gives no reading of its
# own for the asked product and is not written for its kind (block_scope()).
#
# That reading kept every block with no reading either way, as "the campaign as it reached them
# all, yours among them", and the third review found the claim false where a block is another
# entry's: "Synacor Zimbra Collaboration Suite (ZCS)" drew its whole product tier from the
# web-server campaign, an antivirus exclusion for IIS's module directory (inetsrv) and an
# ASP.NET ViewState block first, and "VMware ESXi" shadow-copy deletion, Windows domain account
# creation and LDAP share enumeration. A block now keeps the tier only on a reading that it
# concerns what was asked, and one with none falls with the rest. The decision, first row that
# holds:
#
#   rule              reading                                                       tier
#   named             names the product, its family or the vendor, anywhere          keeps
#   identifier        carries an identifier held as the product's / the vendor's     keeps
#   other-identifier  carries only identifiers held under other products             falls
#   class             its own sentences read for an asked class no entry it names   keeps
#                     shares
#   shared-class      its own sentences read for an asked class an entry it names    keeps
#                     shares
#   only-block        the record's one block, citing a pattern written for an        keeps
#                     asked class
#   other-entry       names another entry the record lists, by its own words         falls
#   other-kind        names an unlisted product, citing a pattern written for none   falls
#                     of the asked classes
#   sole-product      nothing else the record lists reads as a product, vendor or    keeps
#                     class
#   kind              cites a pattern written for an asked class and for no kind     keeps
#                     another product the record lists holds
#   silent            none of these                                                  falls
#
# only-block, sole-product and kind never keep a block whose markers commit to another platform
# than the asked product's, and an entry on another platform is another kind unless the
# block's markers commit to the asked one: on "Linux", the hive record's shadow-copy block
# (vssadmin.exe) is the Windows endpoints entry's, both being endpoint.os.
#
# The Exchange question still takes the AA22-257A record's Log4j and FortiOS blocks
# (other-kind, other-identifier) and keeps its ProxyShell block (identifier); "Microsoft IIS"
# keeps the BadIIS block by kind, since no other product the record lists is a web server by its
# own words, and Zimbra, Nacos and ESXi take the blocks above as silent.

CVE_ID = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")

# `concerns` is whether the block keeps its record's tier, `text` the MATCH_BASIS clause saying
# why, `entries` how many product entries the record lists, `ids` the identifiers the block's
# own text carries, which the EXPOSURE cross-reference reads, `kind` whether the record was
# reached as the product or as the vendor asked about, and `rule` which of block_scope()'s
# readings decided it, one of BLOCK_RULES.
BlockScope = collections.namedtuple("BlockScope", "concerns text entries ids kind rule",
                                    defaults=(None,))

# block_scope()'s readings, in the order it applies them. `named`, `identifier`, `class` and
# `shared-class` keep the tier on what the block says; `only-block` and `kind` on the pattern it
# cites; `sole-product` where nothing else the record lists reads as a product; the `other-`
# three take it away on what it names, and `silent` because nothing in it says it concerns what
# was asked. No reading keeps a block by default.
BLOCK_RULES = ("named", "identifier", "other-identifier", "class", "shared-class",
               "only-block", "other-entry", "other-kind", "sole-product", "kind", "silent")
KEEPING_RULES = frozenset(("named", "identifier", "class", "shared-class", "only-block",
                           "sole-product", "kind"))


def block_evidence(how):
    """(text, identifiers) of one how-block on its own: its logic and caveat and every string a
    marker or field carries, and the CVE identifiers in them. The record's summary, notes and
    vulnerabilities belong to the whole record, so they say nothing about one block."""
    parts = [(how or {}).get("logic") or "", (how or {}).get("caveat") or ""]
    for item in list((how or {}).get("markers") or []) + list((how or {}).get("fields") or []):
        for key in ("value", "expr"):
            value = item.get(key) if isinstance(item, dict) else None
            for part in (value if isinstance(value, list) else [value]):
                if isinstance(part, str):
                    parts.append(part)
    text = " ".join(part for part in parts if part)
    return text, set(CVE_ID.findall(text))


def block_prose(how):
    """What one how-block says in its own sentences: its logic and caveat, without the strings
    its markers and fields match. A class reading is taken from this alone (block_scope()).

    A product's name in a matched string is evidence of whose files or processes the block
    looks for -- "/netscaler/" is NetScaler's directory -- but a class word inside one says only
    what the string looks like. The access-resale record's integrity block matches three
    NetScaler paths, one of them "/var/vpn/themes/imgs/", and read through the class alias
    "vpn" it was kept as Ivanti Connect Secure's own detection, at product tier, because a
    VPN gateway is Connect Secure's class; "ldap" in an outbound-lookup expression kept the
    Log4j block on Microsoft directory questions the same way."""
    return " ".join(part for part in ((how or {}).get("logic") or "",
                                      (how or {}).get("caveat") or "") if part)


# (product, vendor, holders): the identifiers exposure records hold as the asked product's own
# (Q.product_identifiers() over the `product` tier), those filed under a vendor asked about, and,
# for every identifier any exposure record carries, the vendor and product entries holding it.
Owners = collections.namedtuple("Owners", "product vendor holders")


def identifier_owners(records, resolved):
    """Owners for this question, read from the exposure records alone."""
    product, vendor, holders = set(), set(), collections.defaultdict(set)
    for record in records:
        if record.get("record_type") != "exposure":
            continue
        who = record.get("who") or {}
        label = "{} {}".format(who.get("vendor") or "-", "; ".join(who.get("products") or []))
        ids = (record.get("what") or {}).get("vulnerabilities") or []
        for identifier in ids:
            holders[identifier].add(label.strip())
        if resolved.get("vendors") and Q.vendor_reason(record, resolved):
            vendor |= set(ids)
        if resolved.get("products") and Q.exposure_tier(record, resolved) == "product":
            product |= set(Q.product_identifiers(resolved, record))
    return Owners(product, vendor, holders)


def _entries_naming(record, resolved, kind):
    """The record's product entries naming what was asked, as the record was reached: by a
    product (Q.product_hits()) or by a vendor named inside an entry."""
    entries = (record.get("who") or {}).get("products") or []
    if kind == "product":
        return set(Q.product_hits(resolved, record))
    names = resolved.get("vendor_names") or {}
    out = set()
    for vendor in resolved.get("vendors") or ():
        sequences = names.get(vendor) or {tuple(Q.normalise(vendor).split())}
        out |= {entry for entry in entries
                if any(seq and Q._contains(Q.normalise(entry).split(), tuple(seq))
                       for seq in sequences)}
    return out


# Per alias table, read once: what each product entry resolves to, the alias keys of each
# product pair, and the classes the table files each vendor's products under. Keyed by the
# table's identity and holding the table itself, so a table freed and another allocated at the
# same address is never answered from the first one's reading.
_TABLE_READINGS = {}


def _table_reading(aliases):
    held = _TABLE_READINGS.get(id(aliases))
    if held is not None and held[0] is aliases:
        return held[1]
    keys, vendor_classes = collections.defaultdict(list), collections.defaultdict(set)
    pair_classes = collections.defaultdict(set)
    for key, value in (aliases.get("product_aliases") or {}).items():
        keys[(value.get("vendor"), value.get("product"))].append(key)
        klass = value.get("product_class") or []
        klass = klass if isinstance(klass, list) else [klass]
        vendor_classes[value.get("vendor")].update(klass)
        pair_classes[(value.get("vendor"), value.get("product"))].update(klass)
    spelt = collections.defaultdict(set)
    for vendor, product in keys:
        spelt[Q.normalise(product or "")].add((vendor, product))
    reading = {"keys": keys, "vendor_classes": vendor_classes, "pair_classes": pair_classes,
               "entries": {}, "spelt": spelt, "single": Q.singular_only(aliases), "prose": {}}
    _TABLE_READINGS.clear()
    _TABLE_READINGS[id(aliases)] = (aliases, reading)
    return reading


def _entry_reading(entry, aliases):
    """(pairs, vendors, classes, own classes, platforms) the resolver reads one product entry as,
    the platforms from the curated `platform_of` table and the entry's own words ("Windows
    estates", "Unix and Linux hosts"), as query.py reads a question's and a record's. The pairs
    include any the alias table files under the entry's own spelling: "badiis" resolves to the
    Multiple pair "Progress Telerik UI for ASP.NET AJAX", which the entry of that name does not
    resolve to, because the vendor's own longer alias claims its words first, and a block
    reading as that pair was otherwise said to name a product "the record does not list".
    `classes` takes such a pair's classes too; `own classes` are those the entry's own words
    resolve, which is its kind: the Telerik entry is a library, and only the record-derived
    pair under its spelling files it as a web server."""
    table = _table_reading(aliases)
    cache = table["entries"]
    if entry not in cache:
        res = Q.resolve(entry, aliases)
        spelt = table["spelt"].get(Q.normalise(entry), set())
        cache[entry] = (frozenset(set(res.get("product_pairs") or ()) | spelt),
                        frozenset(res.get("vendors") or ()),
                        frozenset(set(res.get("classes") or ()).union(
                            *(table["pair_classes"].get(pair, ()) for pair in spelt))),
                        frozenset(res.get("classes") or ()),
                        frozenset(Q.question_platforms(res, aliases) | {
                            platform for platform, rx in Q.NAMED_PLATFORMS
                            if rx.search(Q.normalise(entry))}))
    return cache[entry]


def _stem(words):
    """Words with a plural "s" dropped, so "self hosted runner" sits inside "self-hosted
    runners" and a key is not refused a home for its number."""
    return tuple(w[:-1] if len(w) > 3 and w.endswith("s") else w for w in words)


def _alias_names(key, pair, homes):
    """Is alias `key`, matched in a block, a name of the product `pair` -- its words inside the
    product's own name or an entry the record lists it under -- rather than a word the table
    sends to it? "windows" names the entry "Windows estates" and "netscaler" the Citrix entry;
    "badiis" (a module the IIS block drops) is filed under the Telerik entry and names it no
    more than "domain controller" names Active Directory or "actions runner" the entry
    "self-hosted runners"."""
    seq = _stem(key.split())
    return any(Q._contains(_stem(Q.normalise(home or "").split()), seq)
               for home in (pair[1],) + tuple(homes))


def own_word_classes(admitted):
    """{class: words} the block's own words name through a class alias. Not the classes a
    product alias brings with it: a block naming NetScaler reads for NetScaler's class through
    NetScaler, which says nothing about whether it is about an F5 load balancer."""
    out = collections.defaultdict(set)
    for line in (admitted or {}).get("resolved_by") or ():
        head, sep, tail = line.partition(" -> class ")
        if sep:
            for klass in tail.split(", "):
                out[klass].add(head)
    return out


def _listed(items):
    return ", ".join(items[:-1]) + " and " + items[-1] if len(items) > 1 else "".join(items)


def block_scope(record, how, resolved, aliases, owners, kind="product", pattern=None):
    """For one block of a campaign record reached as the product (`kind` product) or as a vendor
    named inside its entries (`kind` vendor), whether it concerns what was asked and why, as a
    BlockScope; None for every other record.

    A campaign record is one filed under a sentinel vendor that lists, beside the entries naming
    what was asked, at least one entry that does not. The block is read on its own text and
    identifiers (block_evidence()) and the pattern it cites, and the first of these that holds
    decides it (`rule`, BLOCK_RULES). Names and identifiers are read in everything the block
    carries, its matched strings included; a class only in its own sentences (block_prose()):

    - `named`: it names what was asked -- a form product_forms() holds, a name of the vendor, or
      a product of the vendor the resolver admits there -- or `identifier`: it carries an
      identifier an exposure record holds as the product's own, or files under the vendor;
    - `other-identifier`: it carries identifiers exposure records hold, none of them the asked
      one's: the bypass block carries only one the corpus holds under FortiOS;
    - `class`: its own sentences name, through a class alias, a class of what was asked that no
      other entry it names by name shares: the ESXi block reads "hypervisor", "virtual
      machine" and "virtualisation" beside "Windows hosts". A class word inside a path or
      pattern it matches is not read: "/var/vpn/themes/imgs/" is a NetScaler directory, and
      says nothing about whether the block is a VPN gateway's other than NetScaler's;
    - `shared-class`: its own sentences read for a class of what was asked that another entry
      it names shares, so it is about the products of that class the campaign reached;
    - `only-block`: the record has no other block, so this one is its whole account of how the
      campaign reached every product it lists, and the pattern it cites is written for a class
      of what was asked: naming one of the others is not taking it away from the rest;
    - `other-entry`: it names, by that entry's own name, another product the record lists:
      the integrity block's paths are NetScaler's, and neither F5 nor Pulse Connect Secure is
      in them. An entry naming no product is named by its own words ("network backups"),
      unless every class it reads is one of what was asked ("CI/CD runners", beside GitHub
      Actions);
    - `other-kind`: it names a product the record does not list, or one it does by a word that
      is not that product's name, while the pattern it cites is written for none of the classes
      of what was asked: the Log4j lookup's pattern is a web and library one, and Exchange is
      a mail server;
    - `sole-product`: nothing else the record lists reads as a product, a vendor or a class
      ("personal access tokens" and "private source repositories", beside GitHub), so there is
      no other product the block could be about;
    - `kind`: the pattern it cites is written for a class of what was asked and for no class
      another product the record lists holds by its own words (other_kinds()), so within this
      record its detection is only for products of the asked kind: the build-log block on a
      GitHub Actions question, the tunnelling-client block on Cloudflare Tunnel. Not where its
      markers commit to another platform than the asked product's;
    - `silent`: none of these. Nothing in the block says it concerns what was asked, so it falls,
      saying what its pattern is written for and which of the record's other products hold
      that kind: the IIS module-directory exclusion on Zimbra, shadow-copy deletion on ESXi.
    """
    who = record.get("who") or {}
    if who.get("vendor") not in Q.SENTINEL_VENDORS:
        return None
    entries = who.get("products") or []
    naming = _entries_naming(record, resolved, kind)
    if not naming or all(entry in naming for entry in entries):
        return None
    reading = {entry: _entry_reading(entry, aliases) for entry in entries}
    table = _table_reading(aliases)
    text, ids = block_evidence(how)
    flat = Q.normalise(text)
    words = flat.split()
    admitted = Q.resolve(text, aliases) if text else {}
    got = set(admitted.get("product_pairs") or ())
    # The question's own classes and those of every entry naming what it asked. For a vendor
    # whose naming entries resolve no class ("Fortinet appliances"), the classes the alias table
    # files the vendor's products under.
    asked_classes = set(resolved.get("classes") or ())
    for entry in naming:
        asked_classes |= reading[entry][2]
    # The asked product's kind as this record lists it, for reading the pattern a block cites:
    # the classes the naming entries' own words resolve, never one the table reaches only
    # through a pair filed under an entry's spelling ("badiis" files Telerik as a web server),
    # and the question's own only where they resolve none. On "Microsoft IIS" the AA22-257A
    # record names Microsoft only in its Exchange entry, so a web-server pattern there is
    # written for no kind it lists the vendor as.
    asked_own = set().union(*(reading[entry][3] for entry in naming)) or \
        set(resolved.get("classes") or ())
    mine_pairs = {pair for entry in naming for pair in reading[entry][0]}
    from_table = False
    named = {}
    if kind == "product":
        # Every product the question resolved, not only the pair the record's entry named: an
        # entry "Laravel" reached as a vendorless product still speaks for "Laravel Framework".
        pairs = set(resolved.get("product_pairs") or ()) | {
            (vendor, product) for vendor, product, _, _ in Q.product_hits(resolved, record).values()}
        asked = ", ".join(sorted({product for _, product in pairs}))
        forms_of = resolved.get("product_forms") or {}
        for pair in pairs:
            for form in forms_of.get(pair) or {Q.canonical_product(pair[1]): "own"}:
                if form and Q._contains(words, tuple(form)):
                    named.setdefault(" ".join(form), " ".join(form))
        mine_pairs |= pairs
        mine = sorted(ids & owners.product)
        ours = (lambda pair: pair in mine_pairs)
    else:
        vendors = set(resolved.get("vendors") or ())
        asked = ", ".join(sorted(vendors))
        names = resolved.get("vendor_names") or {}
        for vendor in vendors:
            for seq in names.get(vendor) or {tuple(Q.normalise(vendor).split())}:
                if seq and Q._contains(words, tuple(seq)):
                    named.setdefault(" ".join(seq), " ".join(seq))
        for vendor in set(admitted.get("vendors") or ()) & vendors:
            # Said once, in the vendor's own spelling: "GitHub", not "GitHub, github".
            named[Q.normalise(vendor)] = vendor
        for vendor, product in got:
            if vendor in vendors:
                named.setdefault(Q.normalise("{} {}".format(vendor, product)),
                                 "{} {}".format(vendor, product))
        if not asked_classes:
            for vendor in vendors:
                asked_classes |= table["vendor_classes"].get(vendor, set())
            from_table = bool(asked_classes)
            asked_own = set(asked_classes)
        mine = sorted(ids & owners.vendor)
        ours = (lambda pair: pair in mine_pairs or pair[0] in vendors)
    # Each other product the block's words resolve to: the entry it is listed under, if any,
    # and whether a key the block matched is that product's name or only a word the table
    # sends to it.
    other_entries, loose = {}, []
    for pair in sorted(got, key=lambda p: (p[0] or "", p[1] or "")):
        if ours(pair):
            if kind == "product" and any(
                    _alias_names(key, pair, [e for e in naming if pair in reading[e][0]])
                    for key in table["keys"].get(pair, ())
                    if Q.alias_pattern(key, key not in table["single"]).search(flat)):
                named.setdefault(Q.normalise(pair[1]), pair[1])
            continue
        homes = [e for e in entries if e not in naming and pair in reading[e][0]]
        keys = [key for key in table["keys"].get(pair, ())
                if Q.alias_pattern(key, key not in table["single"]).search(flat)]
        own = [key for key in keys if _alias_names(key, pair, homes)]
        if homes and own:
            for entry in homes:
                other_entries.setdefault(entry, pair[1])
        elif homes:
            loose.append("{} (a word the alias table files under {}, which the record lists)"
                         .format(", ".join(sorted(keys)) or pair[1], pair[1]))
        else:
            loose.append("{} (which the record does not list)".format(pair[1]) if own or not keys
                         else "{} (read as {}, which the record does not list)".format(
                             ", ".join(sorted(keys)), pair[1]))
    # An entry the resolver reads no product in is named by its own words: "Linux servers", and
    # "cloud storage" and "network backups", which the enclave-mapping block names while it said
    # it named none of them. Not an entry whose every class is one of what was asked: "CI/CD
    # runners", beside GitHub Actions, is the kind asked about, not another product.
    for entry in entries:
        if entry in naming or entry in other_entries or reading[entry][0]:
            continue
        if not reading[entry][1] and reading[entry][2] and reading[entry][2] <= asked_classes:
            continue
        if Q._contains(words, tuple(Q.normalise(entry).split())):
            other_entries[entry] = entry
    other_classes = set().union(*(reading[e][2] for e in other_entries)) if other_entries \
        else set()
    # A class is read in the block's own sentences only (block_prose()): read in its matched
    # strings too, "vpn" in a NetScaler path kept the integrity block as Ivanti's.
    # It depends on the block alone, so it is read once per block for every question.
    prose = block_prose(how)
    if prose not in table["prose"]:
        table["prose"][prose] = own_word_classes(Q.resolve(prose, aliases) if prose else {})
    word_classes = table["prose"][prose]
    held_ids = sorted(i for i in ids if owners.holders.get(i))
    applies = set((pattern or {}).get("applies_to_classes") or ())
    for_asked = applies & asked_own
    pid = (pattern or {}).get("id") or (how or {}).get("pattern_id") or "-"
    also = ("; it also names {}".format(_listed(sorted(set(other_entries) | set(loose))))
            if other_entries or loose else "")
    # The platform the asked product runs on, where the platform table or its entries' own
    # words say ("Linux", "Windows endpoints"), and the platforms the block's markers commit
    # to, read by query.py's classifier as PRIORITY_BASIS reads them. A block written for
    # another platform is not the asked product's by kind: on "Linux", the hive record's
    # shadow-copy block (vssadmin.exe) is Windows endpoints', both being endpoint.os.
    asked_plats = Q.question_platforms(resolved, aliases) or set().union(
        *(reading[entry][4] for entry in naming))
    platforms = sorted(finding_platforms(how, pattern))
    fit = Q.platform_fit(platforms, asked_plats)
    kinds, kindless = other_kinds(entries, naming, reading, asked_own, table, asked_plats,
                                  fit > 0)
    # The record's other products of another kind the pattern is written for: {entry: classes}.
    shared = {entry: sorted(k & applies) for entry, k in kinds.items() if k & applies}

    def asked_kinds():
        listed = " or ".join(sorted(asked_classes))
        if from_table and len(asked_classes) > 3:
            return "any of the {} classes the alias table files {}'s products under".format(
                len(asked_classes), asked)
        if from_table:
            return "{}, which the alias table files {}'s products under".format(listed, asked)
        return listed

    def scope(concerns, text_, rule):
        return BlockScope(concerns, text_, len(entries), frozenset(ids), kind, rule)

    def carried(identifiers):
        return "; ".join("{} (held here under {})".format(i, ", ".join(sorted(owners.holders[i])))
                         if owners.holders.get(i)
                         else "{} (held by no exposure record here)".format(i)
                         for i in identifiers)

    def holders():
        """The kinds the pattern is written for that the record's other products hold, and
        which products hold them."""
        classes = sorted(set().union(*(set(c) for c in shared.values())))
        return "{}, held by {}, which the record also lists".format(
            _listed(classes), _listed(sorted(shared)))

    def unread():
        return ("; the resolver reads no kind in {}".format(_listed(sorted(kindless)))
                if kindless else "")

    if named or mine:
        bits = []
        if named:
            bits.append("names it ({})".format(", ".join(sorted(set(named.values()),
                                                                 key=str.lower))))
        if mine:
            bits.append("carries {}, which an exposure record here {} ({} of the {} "
                        "identifier(s) it carries)".format(
                            ", ".join(mine), "holds as {}'s own".format(asked)
                            if kind == "product" else "files under {}".format(asked),
                            len(mine), len(ids)))
        return scope(True, "this block concerns it: it " + " and ".join(bits),
                     "named" if named else "identifier")
    if held_ids:
        return scope(False, "this block concerns another: it carries {}, and neither names {} "
                            "nor carries an identifier an exposure record {}".format(
                                carried(sorted(ids)), asked,
                                "holds as its own" if kind == "product" else "files under it"),
                     "other-identifier")
    def read_for(classes):
        return "; ".join("{} ({})".format(k, ", ".join(sorted(word_classes[k])))
                         for k in sorted(classes))

    hit = {klass for klass in word_classes if klass in asked_classes}
    if hit - other_classes:
        return scope(True, "this block concerns it: its own words read for {}, a class of what "
                           "was asked ({}){}".format(read_for(hit - other_classes), asked, also),
                     "class")
    if hit:
        # The class it reads for is the asked product's and that of another entry it names by
        # name: "proc-macro1 was the first dependency arrayref had taken", read on an internment
        # question, is a crate block naming two crates the campaign reached and not the third.
        return scope(True, "this block names {}, which the record also lists, and its own words "
                           "read for {}, their class and a class of what was asked ({}): it "
                           "describes the campaign as it reached the products of that class, "
                           "yours among them".format(_listed(sorted(other_entries)), read_for(hit),
                                                     asked), "shared-class")
    if len((record.get("how") or [])) == 1 and for_asked and fit >= 0:
        return scope(True, "this is the record's only block, and the pattern it cites ({}) is "
                           "written for {}, a class of what was asked ({}): it is the record's "
                           "whole account of how the campaign reached every product it lists, "
                           "yours among them{}".format(pid, _listed(sorted(for_asked)), asked,
                                                       also), "only-block")
    if other_entries:
        return scope(False, "this block concerns another: it names {}, which the record also "
                            "lists, and names nothing of {}, carries no identifier of it, and "
                            "reads in its own sentences for none of its classes ({})".format(
                                _listed(sorted(other_entries)), asked, asked_kinds()),
                     "other-entry")
    if loose and asked_classes and applies and not applies & asked_classes:
        return scope(False, "this block concerns another: it names {}, and the pattern it cites "
                            "({}) is written for {}, not for {}".format(
                                _listed(sorted(loose)), pid, _listed(sorted(applies)),
                                asked_kinds()), "other-kind")
    readable = [entry for entry in entries if entry not in naming and any(reading[entry][:3])]
    if not readable and fit >= 0:
        return scope(True, "nothing else the record lists reads as a product, a vendor or a "
                           "class ({} name none), so this block describes the campaign as it "
                           "reached what was asked{}".format(
                               _listed(sorted(e for e in entries if e not in naming)), also),
                     "sole-product")
    if for_asked and not shared and fit >= 0:
        return scope(True, "this block concerns it by kind: it names {} and carries {}, but the "
                           "pattern it cites ({}) is written for {}, a class of what was asked "
                           "({}), and for no other kind the record's other entries hold{}: "
                           "within this record its detection is for products of that kind, "
                           "yours among them".format(
                               _listed(sorted(loose)) if loose else "none of the record's "
                               "products", "only " + carried(sorted(ids)) if ids else
                               "no identifier", pid, _listed(sorted(for_asked)), asked, unread()),
                     "kind")
    # Nothing in the block says it concerns what was asked. Say what it does name and carry,
    # what its pattern is written for, which other products the record lists hold that kind,
    # and the platform its markers commit to, so the reader can see whose block it is.
    says = ["it names {} and carries {}".format(
                _listed(sorted(loose)) if loose else "none of the record's products",
                "only " + carried(sorted(ids)) if ids else "no identifier"),
            "reads in its own sentences for none of its classes ({})".format(asked_kinds())
            if asked_classes else "has no class of {} to read it by".format(asked)]
    if not applies:
        says.append("cites no pattern to read its kind by")
    elif for_asked:
        says.append("cites a pattern ({}) written for {}, a class of what was asked, and as much "
                    "for {}".format(pid, _listed(sorted(for_asked)), holders()))
    else:
        says.append("cites a pattern ({}) written for {}, none of them a class of what was "
                    "asked{}".format(pid, _listed(sorted(applies)),
                                     ", and for {}".format(holders()) if shared else ""))
    lead = ("this block concerns the campaign and does not single it out from the other "
            "products the record lists" if for_asked and shared and fit >= 0 else
            "this block concerns the campaign, not it")
    where = ""
    if platforms:
        where = "; its markers are written for {}{}".format(_listed(platforms), (
            ", and {} runs on {}".format(asked, _listed(sorted(asked_plats))) if fit < 0 else ""))
    return scope(False, "{}: {}, and {}{}".format(lead, ", ".join(says[:-1]), says[-1], where),
                 "silent")


def other_kinds(entries, naming, reading, asked_classes, table, asked_plats=(), fits=False):
    """({entry: classes}, [entry]): the kinds other than what was asked that each other entry
    of the record holds, and the entries the resolver reads no kind in, for the `kind` reading
    of block_scope().

    An entry's kind is what its own words resolve; with no class of its own, an entry naming a
    vendor takes the classes the alias table files that vendor's products under ("Fortinet
    appliances"). A class the table reaches only through a pair filed under the entry's
    spelling is not its kind: "badiis" files the Telerik entry as a web server. A class of what
    was asked is left out, because a block written for that kind is about every product of it
    the campaign reached, yours among them: "CI/CD runners" beside GitHub Actions, or two other
    manufacturers' PLCs beside Siemens's, leave nothing. Not where the entry runs on another
    platform than the asked product (`asked_plats`) and the block's markers do not commit to the
    asked one (`fits`): "Windows endpoints" beside "Linux servers" is endpoint.os too, and a
    block with no platform of its own is either's. An entry the resolver reads nothing in
    ("LogMeIn", "security scanning actions") has no kind to read, and is named as such.
    """
    kinds, kindless = {}, []
    for entry in entries:
        if entry in naming:
            continue
        _, vendors, _, own, plats = reading[entry]
        found = set(own) or set().union(
            *(table["vendor_classes"].get(vendor, set()) for vendor in vendors))
        apart = bool(plats and asked_plats and not fits
                     and Q.platform_fit(plats, asked_plats) < 0)
        if not found:
            kindless.append(entry)
        elif apart or found - asked_classes:
            kinds[entry] = found if apart else found - asked_classes
    return kinds, kindless


def block_tier(tier, weight, why_matched, record, how, resolved, aliases, owners, pattern=None):
    """(tier, weight, scope) for one block: the record's tier, except that a block of a campaign
    record reached as the product, or as a vendor named inside its entries, that concerns
    another product takes the tier the record's other reasons give -- its class, as for a vendor
    named inside a generic record's products (match_basis()), or else a name fragment."""
    if tier == "product":
        kind, drop = "product", (lambda r: r.startswith("product "))
    elif tier == "vendor" and any(Q.named_in_product(r) for r in why_matched or ()):
        kind, drop = "vendor", Q.named_in_product
    else:
        return tier, weight, None
    scope = block_scope(record, how, resolved, aliases, owners, kind, pattern)
    if scope is None or scope.concerns:
        return tier, weight, scope
    fallen = match_basis([r for r in why_matched or () if not drop(r)], resolved)
    if fallen[0] not in SUBJECT_TIERS:
        # Reached by name, so never below a name fragment.
        fallen = ("name-fragment", MATCH_WEIGHT["name-fragment"])
    return fallen + (scope,)


def match_text(tier, reasons, resolved=None, derived=(), scope=None):
    """The MATCH_BASIS sentence for a tier, naming what matched from the record's reasons, and,
    for a block of a campaign record (block_scope()), whether this block concerns the product."""
    resolved = resolved or {}

    def named(prefix):
        return "; ".join(r[len(prefix):] for r in reasons or () if r.startswith(prefix)) or "-"

    if scope is not None and not scope.concerns:
        # Said whatever tier the block fell to: the other tiers' sentences describe how the
        # record was reached, and this one was reached as the product or the vendor.
        classes = named("class ")
        return ("{} - the record names the {} asked about ({}) among its {} product entries, "
                "but {}{}; analogy, not intelligence about yours".format(
                    "CLASS-LEVEL" if tier == "class" else "WEAK", scope.kind,
                    named(scope.kind + " "), scope.entries, scope.text,
                    "; it shares class {} with the question".format(classes)
                    if tier == "class" else ""))
    held = ("; the record lists {} product entries, and {}".format(scope.entries, scope.text)
            if scope is not None else "")
    # A record naming the vendor only inside an entry, with a product asked: its blocks that
    # concern no product asked about stay a class analogue or a name fragment, and say what the
    # record does name rather than that it is "about another product" or was "not reached as
    # the technology you named".
    inside = "; ".join(r[len("vendor "):] for r in reasons or () if Q.named_in_product(r))
    if tier == "class" and inside and resolved.get("products"):
        return ("CLASS-LEVEL - shares class {} with the question; the record names the vendor "
                "asked about ({}) among what it lists, but not the product asked about; "
                "analogy, not intelligence about yours".format(named("class "), inside))
    if tier == "name-fragment" and inside and resolved.get("products"):
        return ("WEAK - the record names the vendor asked about ({}) among what it lists, but "
                "neither the product nor a class asked about; read TECHNOLOGY below before "
                "treating this as being about your technology".format(inside))
    if tier == "product":
        return "PRODUCT - names the product asked about ({}){}".format(named("product "), held)
    if tier == "vendor":
        text = "VENDOR - names the vendor asked about ({})".format(named("vendor "))
        if any(r.startswith("class ") for r in reasons or ()):
            text += " in a class asked about ({})".format(named("class "))
        if resolved.get("products"):
            text += ", but not the product asked about ({})".format(
                ", ".join(sorted(resolved["products"])))
        return text + held
    if tier == "vendor-other-class":
        return ("VENDOR, OTHER PRODUCT LINE - names {} but none of the classes asked about; "
                "the vendor's history, not this product's".format(named("vendor ")))
    if tier == "class":
        hit = {c.strip() for r in reasons or () if r.startswith("class ")
               for c in r[len("class "):].split(",")}
        where = ("which the vendor's own records carry (CLASSES_FROM_VENDOR)"
                 if hit and hit <= set(derived) else "with the question")
        return ("CLASS-LEVEL - shares class {} {}, and is about another product than "
                "yours; analogy, not intelligence about yours".format(named("class "), where))
    tagged = sorted({r[len("term "):].rsplit(" (", 1)[0] for r in reasons or ()
                     if r.startswith("term ") and r.endswith(" (tag)")})
    return {
        "tag": "tagged with a term from the question ({})".format(", ".join(tagged) or "-"),
        "name-fragment": "WEAK - the question's words appear inside a vendor, product "
                         "or class name here, but the record was not reached as the "
                         "technology you named; read TECHNOLOGY below before treating "
                         "this as being about your technology",
        "pattern": "LOOSE - the cited pattern's wording matched; may be tangential",
    }.get(tier, "LOOSE - the record's prose matched; may be about something else")


def match_group(tier, verdict="unassessed", rank_by="criticality"):
    """The ORDERING group a finding sorts in: (group, how it was reached).

    Under `--rank-by gap` a finding `--covered` says is implemented drops one group. The group
    is a strict key ahead of the weight, and the gap multiplier lives inside the weight, so
    without this it could only reorder covered findings within their group: on a Fortinet
    coverage fixture, grouping put 12 covered Fortinet findings in the top 12 at weights of
    0.9 to 1.9, above uncovered class analogues at 3.6 to 6.1, and "what should I build
    that I have not got" returned what the caller had built. Dropped one group, a covered
    named finding competes on weight with the analogues, where the multiplier sinks it, and
    still outranks free-text leads. Demotion, never suppression.
    """
    group = MATCH_GROUP.get(tier, LAST_GROUP)
    if rank_by == "gap" and verdict == "yes" and group < LAST_GROUP:
        return group + 1, "group {} after coverage=yes".format(group + 1)
    return group, "group {}".format(group)


def refined_by(reasons):
    """The leftover question words a record matched on after it matched by name, sorted."""
    return tuple(sorted({r.split()[2] for r in reasons or ()
                         if r.startswith("refine term ") and len(r.split()) > 2}))


def sector_reason(reasons):
    """The `sector ...` reason, when the record was seen in a sector the question named."""
    return next((r for r in reasons or () if r.startswith("sector ")), None)


def finding_platforms(how, pattern):
    """The platforms a finding's markers are written for, read by query.py's classifier: the
    block's own markers, or its pattern's, the ones MARKERS prints and emit_xql.py renders.

    Per block and not per record, as query.py's listing is: a record's other blocks, or the
    names it carries, say nothing about the platform one block's detection is written for.
    Measured with the record's platforms as a fallback for a block committing to none, the
    fallback lifted every neutral block of a record holding one Unix path above the neutral
    blocks of records holding none, which is not evidence about the block at all.
    """
    return Q.marker_platforms(markers_of(how, pattern)[0])


def platform_text(fit, platforms, wanted):
    """The PRIORITY_BASIS value for a finding's platform fit, with what it was read from."""
    if not wanted:
        return "0 (the question names no platform)"
    if not platforms:
        return "0 (markers commit to no platform)"
    return "{} (markers written for {})".format("+1" if fit > 0 else fit,
                                                ",".join(sorted(platforms)))


def rank(record, how, citations, today, verdict="unassessed", rank_by="criticality",
         match_weight=1.0, match_tier="class", refined=(), group_label=None, sector=None,
         platform="0 (the question names no platform)"):
    """Criticality and recency, combined, with every input reported to the reader.

    Returns (score, band, basis, criticality), where criticality is the score before the
    gap multiplier, so a caller can ask how strong a finding is apart from what the caller
    already covers. `platform` is platform_text()'s account of the fit, which orders findings
    within a group and never changes the score.
    """
    days = age_days(record, today)
    fidelity = (how or {}).get("fidelity") or "enrich"
    weight = FIDELITY_WEIGHT.get(fidelity, 1.0)

    # Recency: full marks inside a year, decaying to nothing at five.
    recency = max(0.0, min(1.0, (1825 - days) / 1460.0))
    # Prevalence: how many records lean on the same pattern. Log-ish, capped, so one
    # very heavily cited pattern cannot bury everything else.
    prevalence = min(3.0, citations ** 0.5)
    exploited = 1.5 if (record.get("what", {}).get("vulnerabilities")) else 0.0
    victim = 1.0 if record.get("what", {}).get("role") == "victim" else 0.0
    seed_penalty = 0.5 if record.get("status") == "seed" else 1.0

    score = ((weight + prevalence + exploited + victim) * (0.55 + 0.45 * recency)) * seed_penalty
    criticality = score * match_weight
    novelty = COVERAGE_WEIGHT.get(verdict, 1.0) if rank_by == "gap" else 1.0
    score *= novelty
    score *= match_weight
    band = next(name for floor, name in BANDS if score >= floor)
    if group_label is None:
        group_label = match_group(match_tier, verdict, rank_by)[1]
    basis = ("score={:.1f}/8.5; rank_by={}; covered={}; novelty_multiplier={:.1f}; "
             "fidelity={}; records_citing_pattern={}; days_since_published={}; "
             "carries_identifiers={}; role={}; status={}; match={}x{:.2f} ({}); "
             "sector={}; platform_fit={}; refined_by={}").format(
        score, rank_by, verdict, novelty, fidelity, citations,
        days if days < 3650 else "unknown", "yes" if exploited else "no",
        record.get("what", {}).get("role") or "-", record.get("status") or "-",
        match_tier, match_weight, group_label, sector or "-", platform,
        ",".join(refined) or "-")
    return score, band, basis, criticality


def wrap(text, indent="  ", width=88):
    if not text:
        return indent + "(none stated)"
    out, line = [], indent
    for word in str(text).split():
        if len(line) + len(word) + 1 > width and line.strip():
            out.append(line.rstrip())
            line = indent + word + " "
        else:
            line += word + " "
    if line.strip():
        out.append(line.rstrip())
    return "\n".join(out)


def marker_line(marker, combine=None):
    """One marker as the corpus holds it, with how its list combines when the list says.

    Until 0.43.0 this printed type, match, value and expr, so a list whose markers are
    alternatives, or several events, read as one conjunction: pat-command-history-cleared's
    three labelled arms printed as five bare lines, and the ESX Admins group lost the target
    field it is bound to. emit_xql.py renders the combination; each line now carries what it
    needs to be read the same way: the field a marker names (`xdm=`), the event it is tested on
    (`event=`), and the list's key (`combine=`), which is printed on every line of a keyed list
    and on none of an unkeyed one. The expression stays last, because it holds spaces.
    """
    parts = ["type={}".format(marker.get("type")), "match={}".format(marker.get("match"))]
    if "value" in marker:
        parts.append("value={}".format(json.dumps(marker["value"])))
    if marker.get("xdm"):
        parts.append("xdm={}".format(marker["xdm"]))
    if marker.get("event"):
        parts.append("event={}".format(marker["event"]))
    if combine:
        parts.append("combine={}".format(combine))
    if marker.get("normalised"):
        # The corpus's own word, not a source literal: a rule author binds the source's value.
        parts.append("normalised=true")
    if marker.get("expr"):
        parts.append("expr={}".format(marker["expr"]))
    return "  - " + " ".join(parts)


def markers_of(how, pattern):
    """The markers a finding prints and the key they combine by, as emit_xql.py renders them:
    the block's own with its own key, else the pattern's with the pattern's."""
    if (how or {}).get("markers"):
        return how["markers"], how.get("combine")
    return (pattern or {}).get("markers") or [], (pattern or {}).get("combine")


def references(record, how, pattern):
    out, seen = [], set()
    where = record.get("where") or {}
    restricted = where.get("disclosure") != "public"
    title = where.get("title") or "(untitled)"
    url = "RESTRICTED" if restricted else (where.get("url") or "-")
    publisher = "RESTRICTED-SOURCE" if restricted else (where.get("publisher") or "-")
    out.append("  - {} | {} | {}".format(publisher, title, url))
    for tid in list((how or {}).get("technique") or []) + list((pattern or {}).get("technique") or []):
        if tid in seen:
            continue
        seen.add(tid)
        name, link = attack_url(tid)
        out.append("  - {} | {} | {}".format(name, tid, link))
    corroboration = (pattern or {}).get("external_corroboration") or {}
    for source in corroboration.get("sources") or []:
        out.append("  - CORROBORATION | {} | -".format(source))
    return out


def load_d3fend(corpus):
    """D3FEND countermeasures, so a finding can say what to do once it fires.

    Tolerates absence the same way the ATT&CK reference does: a missing file
    degrades the block to a stated gap rather than failing the consultation.
    """
    path = os.path.join(corpus, "reference", "d3fend-countermeasures.json")
    if os.path.exists(path):
        return json.load(open(path, encoding="utf-8"))
    return {}


def load_doctrine(corpus):
    """Response sequencing rules, distilled from the advisories the corpus already cites."""
    path = os.path.join(corpus, "reference", "response-doctrine.json")
    if os.path.exists(path):
        return json.load(open(path, encoding="utf-8"))
    return {}


def load_locus_map(corpus):
    """The derivation tables for LOCUS, kept in the corpus rather than in this file.

    They live beside the vocabulary they are keyed on because `validate.py --corpus DIR`
    has to check a corpus against its own tables. Constants here would mean a different
    corpus was checked against this bundle's mapping, which is the drift shape
    `check_vocab` already exists to catch.
    """
    path = os.path.join(corpus, "schema", "locus-map.json")
    if os.path.exists(path):
        return json.load(open(path, encoding="utf-8"))
    return {}


def load_vocab(corpus):
    """The controlled vocabularies, for validating and suggesting a declared class."""
    path = os.path.join(corpus, "schema", "vocab.json")
    if os.path.exists(path):
        return json.load(open(path, encoding="utf-8"))
    return {}


def load_attack(corpus):
    """The shipped ATT&CK reference's techniques, keyed by id, or {} when it is absent.

    Each entry carries `revoked` and `deprecated`, and a revoked one `replaced_by`: MITRE's
    revoked-by relation followed to the first live id, or null where the chain ends dead.
    advise.py reads them to tell "revoked, use T1685" from "no such id", and validate.py to
    tell a live citation from one ATT&CK has withdrawn.
    """
    path = os.path.join(corpus, "reference", "attack-techniques.json")
    if os.path.exists(path):
        return json.load(open(path, encoding="utf-8")).get("techniques") or {}
    return {}


def suggest_classes(question, vocab, aliases, limit=6):
    """Classes whose name or description shares a word with the question.

    Only ever used to make an UNRESOLVED answer actionable. It is a suggestion engine,
    not a resolver: a proper noun nobody has aliased -- which is what an unresolved
    question almost always is -- shares no words with anything and correctly yields
    nothing. The point is to tell the caller which vocabulary exists, not to guess.
    """
    terms = {w for w in Q.normalise(question).split() if w not in Q.NOISE and len(w) > 2}
    if not terms:
        return []
    scored = []
    for value, description in (vocab.get("product_class") or {}).items():
        haystack = Q.normalise("{} {}".format(value.replace(".", " "), description))
        words = set(haystack.split())
        overlap = len(terms & words)
        if overlap:
            scored.append((overlap, value))
    for alias, value in (aliases.get("class_aliases") or {}).items():
        if alias in terms:
            # A class alias may name several classes. Score each, or the suggestion
            # would offer the list object itself as though it were a class name.
            for one in (value if isinstance(value, list) else [value]):
                scored.append((2, one))
    ranked, seen = [], set()
    for _, value in sorted(scored, key=lambda t: (-t[0], t[1])):
        if value not in seen:
            seen.add(value)
            ranked.append(value)
    return ranked[:limit]


def mode_counts(findings, named_exposures=0):
    """The tallies resolution_mode() decides from, taken once over the whole match set.

    Counted per finding and by MATCH_TIER, so the mode and the MATCH_TIERS line cannot
    disagree. `named_exposures` is the number of exposure records naming what was asked
    (see exposures_naming()); the free-text tiers are `loose`.
    """
    counts = {"product": 0, "vendor": 0, "vendor_other_class": 0, "class": 0, "loose": 0,
              "named_exposures": named_exposures}
    taken = set()
    for finding in findings:
        tier = finding.match_basis
        if tier in SUBJECT_TIERS:
            counts[tier.replace("-", "_")] += 1
        else:
            counts["loose"] += 1
        if finding.scope is not None and not finding.scope.concerns:
            taken.add(finding.record.get("id"))
    # Campaign records naming what was asked whose blocks block_scope() took: an answer with
    # no finding naming it still has observations that list it, and must not say none does.
    counts["campaign_taken"] = len(taken)
    return counts


def resolution_mode(resolved, declared, counts=None):
    """What kind of answer this is, which the header has to state rather than imply.

    The corpus resolves 73 per cent of a real integration library to nothing, so
    "no vendor matched" is the normal case rather than the exceptional one. Returning
    an empty consultation for it -- which is what this did until 0.20.0 -- throws away
    an answer the corpus can give, because the class almost always holds findings even
    when the product name holds none. What it must never do is let a class-level answer
    read as product intelligence, so the mode is named on its own line.

    Decided from mode_counts(), in this order:
    1. A declared class is `class-level-declared`.
    2. A product resolved: `product` when a finding names it; otherwise `vendor-level` when a
       finding names its vendor, in an asked-for class or in another.
    3. Only vendors resolved: `product` when a finding names the vendor in an asked-for
       class, or the question asked for none; `vendor-level` when every finding naming the
       vendor is its other product lines. Never `product` on those alone: the Guardsquare
       question resolves the Android vendor and two build-pipeline classes, and one record
       of Android's other lines would make its class-level answer a product one.
    4. A class resolved: `class-level-inferred`.
    5. A name resolved and nothing above held: `name-without-observations` when free text
       reached findings; `exposures-only` when exposure records name it; else `unresolved`.
    6. Nothing resolved: `mechanism` when free text reached findings, else `unresolved`.

    Until 0.43.0 one tally, a finding naming the vendor or product, decided `product`, so a
    vendor's other lines in an asked-for class satisfied "the corpus holds records naming
    this technology": asked as questions, 196 of the 1,454 vendor and product alias keys
    said so with no finding naming the product, among them "FortiSandbox" and "IOS XR".
    129 more, "FortiMail" and "Panorama" among them, said "no vendor or product the corpus
    holds records for" over findings naming the vendor. And exposures counted for nothing,
    so "Linux kernel" was told the corpus holds no record naming it over exposure records
    that do, and 234 names held only as exposures exited 1 as UNRESOLVED.
    """
    counts = counts or {}
    if declared:
        return "class-level-declared"
    if resolved.get("products"):
        if counts.get("product"):
            return "product"
        if counts.get("vendor") or counts.get("vendor_other_class"):
            return "vendor-level"
    elif resolved.get("vendors"):
        if counts.get("vendor"):
            return "product"
        if counts.get("vendor_other_class"):
            return "vendor-level"
    if resolved.get("classes"):
        return "class-level-inferred"
    if resolved.get("vendors") or resolved.get("products"):
        # A name resolving is not the same event as the corpus holding records about it,
        # and until 0.29.0 this returned "product" for both.
        if counts.get("loose"):
            return "name-without-observations"
        if counts.get("named_exposures"):
            return "exposures-only"
        return "unresolved"
    # Nothing resolved by name, but the free-text tiers found records anyway -- which is
    # what a mechanism question looks like ("phishing", "ransomware"). Before 0.22.0 the
    # free-text haystack was vendor and product only, so this could not happen and
    # "nothing resolved" and "nothing found" were the same state. They are not any more,
    # and reporting a mechanism answer as UNRESOLVED would have hidden 33 findings for
    # "phishing" behind advice to go and name a product class.
    if counts.get("loose"):
        return "mechanism"
    return "unresolved"


# The exposure tiers that name what the question asked about. An exposure is a vulnerability
# fact with no detection logic, so unlike an observation it transfers nothing to another
# vendor's product, and a class match alone never names it. The vendor tier is the vendor's
# whole catalogue only when the question named nothing narrower; exposure_tier() calls it
# other-products-of-vendor otherwise.
NAMING_EXPOSURE_TIERS = ("product", "vendor-class", "vendor")

# The tiers EXPOSURES_NOT_LISTED counts, in the order it prints them. `handset` is not a tier
# of Q.exposure_tier(): it is an exposure in a naming tier that corpus/schema/scope.json keeps
# out of scope, or one a bare handset name names by product, counted here so the refusal is
# visible rather than silent.
UNLISTED_EXPOSURE_TIERS = ("other-products-of-vendor", "product-name-other-vendor",
                           "class-only", "prose-only", "handset")

EXPOSURE_KINDS = ("EXPLOITED", "ADVISORY", "DISCLOSED")

# The feed each generator tag stands for, for EXPOSURE_SCOPE. An exposure carrying none of
# these was written by hand, from a joint government advisory.
EXPOSURE_FEEDS = (("known-exploited-catalogue", "the CISA KEV catalogue"),
                  ("coordinated-disclosure", "ZDI published advisories"),
                  ("psirt", "vendor PSIRT advisories"),
                  ("vulnerability-database", "NVD"))

# What acting on an exposure needs: which hosts run the product, and at which version. The
# telemetry an exposure requires is the same whatever the CVE, so it is assessed once per
# answer, against --have, rather than per block.
EXPOSURE_TELEMETRY = ("asset_inventory", "vuln_scan")

_SCOPE_CACHE = {}


def load_scope(corpus):
    """What this corpus holds and declines to advise on (corpus/schema/scope.json), or {}."""
    path = os.path.join(corpus, "schema", "scope.json")
    if path not in _SCOPE_CACHE:
        _SCOPE_CACHE[path] = (json.load(open(path, encoding="utf-8"))
                              if os.path.exists(path) else {})
    return _SCOPE_CACHE[path]


# A product entry names one platform or several: "iOS, iPadOS, and watchOS", "iOS and macOS".
# The same split product_matches() reads, so the handset test and the tiers agree on parts.
_PRODUCT_PARTS = Q.PRODUCT_PARTS


def handset_record(record, scope):
    """Is this an exposure the handset decision keeps out of the consultation?

    Its vendor is in scope.json's `handset_exposures` and every platform its products name
    matches one of that vendor's terms, or the vendor's terms are `*`. A record naming a
    platform that is not a handset as well ("iOS and macOS") is that platform's exposure too,
    and stays listable.
    """
    table = (scope or {}).get("handset_exposures") or {}
    who = record.get("who") or {}
    terms = table.get(who.get("vendor") or "")
    if not terms or record.get("record_type") != "exposure":
        return False
    if "*" in terms:
        return True
    wanted = [tuple(Q.normalise(t).split()) for t in terms if Q.normalise(t)]
    parts = [Q.normalise(part).split() for product in who.get("products") or []
             for part in _PRODUCT_PARTS.split(product) if Q.normalise(part)]
    return bool(parts) and all(any(Q._contains(part, seq) for seq in wanted) for part in parts)


def named_by_terms(record, reasons, names):
    """Does one of `names` that reached this record as a free-text word stand whole in one of
    its products? Any word was measured and refused: "gpu", "audio" and "kernel" stand in a
    handset record's product name, and were refused as handsets."""
    words = {r.split()[1] for r in reasons or () if r.startswith("term ") and len(r.split()) > 1}
    words &= set(names)
    return any(Q._contains(Q.normalise(product).split(), (word,))
               for product in (record.get("who") or {}).get("products") or [] for word in words)


def handset_words(resolved, scope):
    """The handset names (scope.json `handset_names`) among a question's unresolved words,
    whatever else resolved: "Apple iOS" carries ios beside a resolved vendor."""
    return sorted(set(resolved.get("terms") or ()) & set((scope or {}).get("handset_names") or ()))


def handset_names(resolved, scope):
    """The handset names among a bare question's unresolved words.

    Empty whenever a vendor, product or class resolved: "Cisco ASA VPN users on iOS phones" and
    "iOS MDM" are answered for what resolved, and the mobile management plane is in scope.
    Beside a resolved sector, a name scope.json also lists as a place is not one: "banks in
    Mali" named a country, and was refused as Arm's GPU. Any sector once stopped the refusal,
    and "iOS in government" then counted Apple's handset records prose-only, handset=0.
    """
    if any(resolved.get(key) for key in ("vendors", "products", "classes")):
        return []
    words = handset_words(resolved, scope)
    if resolved.get("sectors"):
        places = set((scope or {}).get("handset_names_also_places") or ())
        return [word for word in words if word not in places]
    return words


def unknown_names(resolved, unmatched, scope, question):
    """The words of a question that reached no record, are written as a name, and are neither
    a handset name nor a word of an alias the resolver refused (GATED): what a name the corpus
    does not know looks like beside a handset name. "Kandji for iOS", "Mosyle iPad" and
    "MaaS360 iOS" name management products, the plane the scope keeps in, and were refused as
    handset questions and told no alias was missing. A name is a word holding a letter and
    written with a capital or a digit (proper_terms(), as MECHANISM_WARNING reads one): any word
    that reached nothing once counted, and "iOS spyware", "iPad jailbroken" and "stalkerware on
    iPhone" were told to add an alias. A refused alias's word is a name the table already
    holds: "arm" in "Arm Mali" is Arm's, and adding it would change nothing.
    """
    refused = {word for meaning in resolved.get("refused_meanings") or ()
               for word in meaning[1].split()}
    words = set(unmatched) - set((scope or {}).get("handset_names") or ()) - refused
    return sorted(word for word in proper_terms(question, words)
                  if any(ch.isalpha() for ch in word))


def handset_meanings(resolved, aliases, words):
    """What each handset word also names as a refused alias, as "<vendor> <product>": bare
    "IOS" is refused as Cisco's (GATED) and as a handset, and the answer said only the second."""
    table = (aliases or {}).get("product_aliases") or {}
    out = []
    for kind, alias, values in resolved.get("refused_meanings") or ():
        if alias in words and kind == "product" and alias in table:
            out.append((alias, "{} {}".format(table[alias].get("vendor"),
                                              table[alias].get("product"))))
        elif alias in words and kind == "vendor":
            out.append((alias, ", ".join(values)))
    return sorted(set(out))


def exposure_order(tier, record, kev_ids):
    """The fixed sort key: tier, then kind, then newest first with the undated last, then id."""
    return (NAMING_EXPOSURE_TIERS.index(tier) if tier in NAMING_EXPOSURE_TIERS
            else len(NAMING_EXPOSURE_TIERS),
            EXPOSURE_KINDS.index(Q.exposure_kind(record, kev_ids)),
            Q._descending(Q.date_key(record)), record.get("id") or "")


# What exposure_listing() decided. `listed` is (tier, record) in the fixed order, before
# --exposure-limit; `unlisted` counts the exposures the question reached and the listing does
# not show, by UNLISTED_EXPOSURE_TIERS; `handset` is the (tier, record) pairs refused as out of
# scope, which `unlisted["handset"]` counts; `scoped` says whether scope.json was read at all.
ExposureListing = collections.namedtuple("ExposureListing", "listed unlisted handset scoped")


def exposure_listing(records, resolved, scope=None, kev_ids=None, reasons=None, keep=None):
    """Every exposure the question reached, split into what the EXPOSURE blocks list and what
    EXPOSURES_NOT_LISTED counts.

    Every exposure is evaluated, not only those Q.score() reached, so that a vendor alias
    canonicalised through the family table reaches VMware records under a Broadcom question.
    The naming tiers are listed; a CVE in another vendor's product, or in the vendor's other
    lines when the question named a product or a class, carries no detection logic to transfer
    and is counted instead. `reasons` maps a record id to what Q.score() matched it on, which
    only the prose-only count reads. `keep` is the --role filter, applied before any tally.
    """
    scope = load_scope(CORPUS) if scope is None else scope
    kev_ids = Q.kev_identifiers(records) if kev_ids is None else kev_ids
    listed, handset = [], []
    unlisted = collections.OrderedDict((tier, 0) for tier in UNLISTED_EXPOSURE_TIERS)
    # A bare handset name (handset_names()) names an exposure only by the words of its product
    # name. "iOS" refused Cisco's alias and reached Apple's handset records by theirs, and
    # counted them prose-only, handset=0, beside advice to add the alias.
    named = handset_names(resolved, scope)
    for record in records:
        if record.get("record_type") != "exposure" or (keep and not keep(record)):
            continue
        why = (reasons or {}).get(record.get("id")) or ()
        tier = Q.exposure_tier(record, resolved, why)
        if tier is None:
            continue
        if tier == "prose-only" and named and named_by_terms(record, why, named) \
                and handset_record(record, scope):
            handset.append((tier, record))
            unlisted["handset"] += 1
            continue
        if tier in NAMING_EXPOSURE_TIERS:
            if handset_record(record, scope):
                handset.append((tier, record))
                unlisted["handset"] += 1
            else:
                listed.append((tier, record))
        elif tier in unlisted:
            unlisted[tier] += 1
    listed.sort(key=lambda pair: exposure_order(pair[0], pair[1], kev_ids))
    return ExposureListing(listed, unlisted, handset, "handset_exposures" in (scope or {}))


def exposures_naming(records, resolved, scope=None):
    """The exposure records that name what was asked, as (tier, record), in listing order.

    resolution_mode() counts these, and the EXPOSURE blocks list them: one function, so the
    mode and the listing cannot count different sets, and the handset refusal applies to
    both. Exposures never enter FINDINGS or MATCH_TIERS, and never clear LOCUS_ABSENT.
    """
    return exposure_listing(records, resolved, scope).listed


# One library pattern the LIBRARY blocks list: the classes it met the question on, how its
# markers fit the platform asked about (+1, 0 or -1), the Sigma and Splunk rules tagging a
# technique it cites, and the platforms its markers commit to.
LibraryEntry = collections.namedtuple("LibraryEntry", "pattern hit fit weight platforms")


def library_listing(records, patterns, classes, wanted=()):
    """Patterns no record cites, with markers, whose applies_to_classes meet `classes`.

    Until 0.43.0 consult.py built findings only from records' how-blocks, so these were
    unreachable from a consultation, and SKILL.md's rule 6 described a DERIVATION branch that
    no output ever printed: 19 of 24 probe questions had library patterns query.py showed and
    consult.py never did, among them three CONTROL patterns for SCADA and, for Kubernetes, a
    MANAGEMENT pattern while LOCUS_ABSENT named MANAGEMENT. Ordered as query.py orders its
    library block: a pattern written for another platform than the one asked about last,
    then corroboration descending, then id. A pattern has no date, no citation and no
    identifier, so it cannot be scored against a finding, and it never takes a finding's slot.
    """
    if not classes:
        return []
    cited = {how.get("pattern_id") for record in records for how in record.get("how") or []}
    out = []
    for pid, pattern in patterns.items():
        if pid in cited or not pattern.get("markers"):
            continue
        hit = tuple(c for c in pattern.get("applies_to_classes") or [] if c in classes)
        if not hit:
            continue
        corroboration = pattern.get("external_corroboration") or {}
        weight = (corroboration.get("sigma_rules") or 0) \
            + (corroboration.get("splunk_detections") or 0)
        platforms = Q.marker_platforms(pattern.get("markers"))
        out.append(LibraryEntry(pattern, hit, Q.platform_fit(platforms, wanted), weight,
                                tuple(sorted(platforms))))
    out.sort(key=lambda entry: (-entry.fit, -entry.weight, entry.pattern.get("id")))
    return out


def exposure_classes(named):
    """The product classes the naming exposures carry, most frequent first, as 'class (n)'."""
    counted = collections.Counter(c for _, record in named
                                  for c in (record.get("who") or {}).get("product_class") or [])
    return ["{} ({})".format(c, n) for c, n in sorted(counted.items(), key=lambda kv: (-kv[1], kv[0]))]


def classes_from_vendor(records, resolved, patterns, nonproduct=()):
    """The classes a vendor-only question is answered at, derived from the vendor's own records.

    "Cisco", "Fortinet", "Citrix" and "Siemens" resolve a vendor and no class, because a vendor
    alias carries none, so the class-level transfer the Scope section promises never happened
    for the commonest way people name what they run, and four or five loci came back absent
    for each. The classes are the first-listed product classes of the observations filed under
    the vendor: those first-listed by two or more of them, or, where none is, the three most
    frequent. The two-record floor is what bounds Microsoft, whose records carry many
    classes; the fallback is what reaches a vendor with one observation, such as Siemens.
    Non-product classes are skipped, because cross_sector would reach every record carrying
    it. A vendor named only inside a generic record's products derives nothing: those
    records' classes are the class they are about, not the vendor's.
    """
    counted = collections.Counter()
    for record in records:
        if not record.get("how"):
            continue
        hit, why = Q.score(record, resolved, patterns)
        if not hit or not any(r.startswith("vendor ") and not Q.named_in_product(r)
                              for r in why):
            continue
        first = [c for c in (record.get("who") or {}).get("product_class") or []
                 if c not in nonproduct]
        if first:
            counted[first[0]] += 1
    ranked = sorted(counted.items(), key=lambda kv: (-kv[1], kv[0]))
    return [c for c, n in ranked if n >= 2] or [c for c, _ in ranked[:3]]


def reached_terms(reasons):
    """The question words a record's reasons show it was reached or refined by.

    Both `term X (tier)` and `refine term X (tier)` count: a qualifying word that reordered a
    named answer ("boot image implant" after "Fortinet FortiGate") was found, and listing it
    as unmatched would say the opposite of what it did.
    """
    words = set()
    for reason in reasons or ():
        body = reason[len("refine "):] if reason.startswith("refine term ") else reason
        if body.startswith("term ") and " (" in body:
            words.add(body[len("term "):].rsplit(" (", 1)[0])
    return words


def proper_terms(question, terms):
    """The terms written with a capital or a digit in the question, which may be a name.

    An ordinary word that reached nothing is not a warning: "ransomware against hospitals"
    has nothing to report. "Zorblax" and "9000" are what a product name looks like.
    """
    out = set()
    for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9_.-]*", question or ""):
        word = Q.normalise(token)
        if word in terms and (any(ch.isupper() for ch in token)
                              or any(ch.isdigit() for ch in token)):
            out.add(word)
    return out


# What each mode's RESOLUTION line starts with; the declared label goes on to name the
# classes. SKILL.md's mode table carries the same labels, and a test holds the two together.
MODE_LABELS = {
    "product": "product",
    "vendor-level": "VENDOR-LEVEL",
    "class-level-inferred": "CLASS-LEVEL (inferred)",
    "class-level-declared": "CLASS-LEVEL (declared via --as",
    "name-without-observations": "NAME_WITHOUT_OBSERVATIONS",
    "exposures-only": "EXPOSURES_ONLY",
    "mechanism": "mechanism",
    "unresolved": "UNRESOLVED",
}

# The modes that print no CLASS_LEVEL_WARNING. Every other mode prints it, with its own text,
# because it is the one key a consumer gates on: a second warning key for vendor-level
# answers would be a key that consumers already reading this one never see.
UNWARNED_MODES = ("product", "mechanism")


def subject_of(resolved):
    """What the question named, as a reader would write it: "Linux Kernel", "Fortinet"."""
    pairs = sorted(resolved.get("product_pairs") or ())
    if pairs:
        return ", ".join(product if not vendor or vendor in Q.SENTINEL_VENDORS
                         else "{} {}".format(vendor, product) for vendor, product in pairs)
    return ", ".join(sorted(set(resolved.get("vendors") or ())
                            | set(resolved.get("products") or ())))


# Each corpus-wide "no observation" claim RESOLUTION and CLASS_LEVEL_WARNING can make, and its
# --role reading. Under --role both lines describe the kept records, and a filter that dropped
# records naming what was asked made "the corpus holds no observation naming it" false
# (planes-role, 2026-10-01). The UNRESOLVED texts are not here: a --role answer with no finding
# and no exposure is one the filter emptied, which says so instead. tests/test_locus_axis.py
# fails any mode that can carry `dropped` and still prints an unscoped claim.
ROLE_SCOPED = (("The corpus holds no observation naming", "No observation --role kept names"),
               ("The corpus holds no observation about", "No observation --role kept is about"),
               ("No observation names", "No observation --role kept names"),
               ("no observation in the corpus", "no observation --role kept"),
               ("no observation is about", "no observation --role kept is about"),
               ("no observation names", "no observation --role kept names"))


def handset_listed(handset, where="there"):
    """"ios is listed there as a handset name": the table's word, not a claim about the
    product. "Snapdragon" was said to name a handset, and its one record also lists laptop,
    vehicle and module parts, which the table files under the handset decision all the same."""
    return "{} {} listed {} as {}".format(
        ", ".join(handset), "is" if len(handset) == 1 else "are", where,
        "a handset name" if len(handset) == 1 else "handset names")


def handset_text(handset=(), refused=0, where="there"):
    """The handset names among a bare question's words (scope.json `handset_names`), and the
    handset records its words name. "" when it is neither."""
    parts = [handset_listed(handset, where)] if handset else []
    if refused:
        parts.append("the {} exposure record(s) its words name are handset records, held and "
                     "not listed".format(refused))
    elif handset:
        parts.append("no exposure record names {}".format("it" if len(handset) == 1 else "them"))
    return ", and ".join(parts)


def bare_unresolved(handset=(), refused=0, prose=0, unknown=()):
    """UNRESOLVED when nothing resolved. `handset` is the handset names among its words,
    `refused` the handset records they name, `prose` the other exposures they reached, and
    `unknown` its words that reached nothing and are written as a name (unknown_names()):
    beside one, the refusal says which word decides whether the question is a handset's."""
    line = "UNRESOLVED - nothing in this question matched a vendor, product or class"
    why = handset_text(handset, refused)
    if why:
        line += "; out of scope as a handset (corpus/schema/scope.json){}: {}".format(
            " unless {} names the product that manages these devices".format(
                " or ".join(unknown)) if unknown else "", why)
    if prose:
        # An exposure the words reached is not an observation, and "no record's prose" was
        # false under an EXPOSURES_NOT_LISTED line counting it.
        return line + ("{} no observation's tags or prose carried its words; {} {}exposure "
                       "record(s) did, counted in EXPOSURES_NOT_LISTED".format(
                           ";" if why else ", and", prose, "other " if why else ""))
    if why:
        return line + "; no observation's tags or prose carried its words"
    return line + ", and no record's tags or prose carried its words either"


def never_add_text(handset):
    """"Never add ios: it is listed in corpus/schema/scope.json as a handset name." """
    one = len(handset) == 1
    return "Never add {}: {} listed in corpus/schema/scope.json as {}.".format(
        ", ".join(handset), "it is" if one else "they are",
        "a handset name" if one else "handset names")


def never_add(handset, unknown=()):
    """What the add-an-alias paragraph says when a handset name stands among the words of a
    question it is not refused for, a place beside a sector ("banks in Mali"): never to add the
    handset name, and the management plane on the condition that the word names a handset. A
    name beside it that reached nothing (unknown_names()) is the one to add, and is offered as
    the product managing the devices on the same condition; "ministries" in "Mali government
    ministries" reached nothing too, and is written as no name. "" with no handset name."""
    if not handset:
        return ""
    text = " " + never_add_text(handset)
    if unknown:
        return " The {} that reached no record {} {}.{} If {} enrols and manages these " \
            "devices, its class is app.mdm, the mobile management plane, which is in " \
            "scope.".format("name" if len(unknown) == 1 else "names",
                            "is" if len(unknown) == 1 else "are", ", ".join(unknown), text,
                            " or ".join(unknown))
    return text + " If {} a handset, the mobile management plane is in scope: re-ask with " \
        "--as app.mdm.".format("it names" if len(handset) == 1 else "they name")


def handset_aside(beside):
    """What an EXPOSURES_ONLY answer says in place of its exposures' classes when a handset name
    stands beside the vendor that resolved: "Apple iOS" was sent to --as endpoint.os, the
    plane the handset decision keeps out, never to the management plane it keeps in."""
    return "{} {} a handset, which this corpus does not advise on".format(
        ", ".join(beside), "names" if len(beside) == 1 else "name")


def resolution_text(mode, resolved, declared=(), named_exposures=(), below="below", refused=0,
                    campaign=0, dropped=0, handset=(), prose=0, beside=(), unknown=()):
    """The RESOLUTION line for a mode, and its CLASS_LEVEL_WARNING or None.

    `below` says where the findings the lines describe are. When --role kept none of them,
    they describe the findings matched before the filter, and "the findings below" pointed
    at nothing.

    "Observation", never "record": 901 of the corpus's records are exposures, and "the
    corpus holds no record naming it" was false for "Linux kernel", which exposure records
    name. Exposures are vulnerability facts with no detection logic and never enter
    FINDINGS, so they are counted here, by tier, and listed in the EXPOSURE blocks. Only an
    exposure naming what was asked is said to name it: for a product question that is the
    product tier, and the vendor's exposures in an asked-for class are named as the vendor's.
    `refused` counts the exposures naming it that the handset decision keeps out, so an
    answer holding only those does not say that nothing names it. `campaign` counts the
    campaign records that list what was asked and whose every block block_scope() took, so
    an answer with no finding about it does not say that no observation names it: "Synacor
    Zimbra Collaboration Suite (ZCS)" is listed by the web-server campaign, none of whose
    blocks is Zimbra's. `handset` is the handset names of a question that resolved nothing
    (handset_names()), `prose` the other exposures its words reached, `unknown` its words
    that reached nothing and may be a name (unknown_names()), and `beside` the handset names
    standing beside what did resolve (handset_words()).
    """
    def show(key):
        return ", ".join(sorted(resolved.get(key) or ())) or "-"

    subject = subject_of(resolved)
    by_tier = collections.Counter(tier for tier, _ in named_exposures)
    parts = []
    if by_tier["product"]:
        parts.append("{} name {}".format(by_tier["product"], subject))
    if by_tier["vendor-class"]:
        parts.append("{} name {} in {}".format(by_tier["vendor-class"], show("vendors"),
                                               show("classes")))
    if by_tier["vendor"]:
        parts.append("{} name {}".format(by_tier["vendor"], show("vendors")))
    note = ("; exposure records: {} (vulnerability facts with no detection logic, listed in "
            "the EXPOSURE blocks)".format(", ".join(parts)) if parts else "")
    if refused:
        # A handset product asked about by name is answered at class level from desktop and
        # server records, and the line has to say that the records naming it were held back.
        note += ("; {} handset exposure record(s) naming it are held and not listed, because "
                 "handsets are out of scope".format(refused))
    # The exposures that name the subject itself: for a product question, the product tier.
    naming = by_tier["product"] if resolved.get("products") else len(named_exposures)
    # With such records, an observation does name it, so the lines say none is about it.
    beyond = (" ({} campaign record(s) list it among what a campaign reached, and every block "
              "of theirs concerns another product or the campaign, as MATCH_BASIS says)"
              .format(campaign) if campaign else "")
    names = "is about" if campaign else "names"
    if mode == "vendor-level" and resolved.get("products"):
        line = ("VENDOR-LEVEL - no observation {} {}{}; the findings below name {}'s other "
                "product lines or are class-level analogues{}. Every finding prints "
                "MATCH_TIER".format(names, subject, beyond, show("vendors"), note))
    elif mode == "vendor-level":
        line = ("VENDOR-LEVEL - no observation names {} in {}; the findings below are that "
                "vendor's other product lines or class-level analogues{}. Every finding "
                "prints MATCH_TIER".format(show("vendors"), show("classes"), note))
    else:
        line = {
            "product": "product - the corpus holds observations naming this technology",
            "class-level-inferred":
                "CLASS-LEVEL (inferred) - no observation is about {}{}; answering on product "
                "class alone{}".format(subject, beyond, note) if subject else
                "CLASS-LEVEL (inferred) - no vendor or product named; answering on product "
                "class alone",
            "class-level-declared": "CLASS-LEVEL (declared via --as: {}) - the caller asserted "
                                    "the class{}".format(", ".join(declared), note),
            "mechanism": "mechanism - nothing resolved by name, but the question's words match "
                         "record tags and prose; every finding prints its MATCH_BASIS",
            "name-without-observations":
                "NAME_WITHOUT_OBSERVATIONS - {} resolved against the alias table, but no "
                "observation in the corpus {} it{}{}. Every finding below was reached by tag "
                "or prose{}; read TECHNOLOGY on each one".format(
                    subject, names, beyond, note, " or is such a campaign's block" if campaign
                    else " and none by name"),
            "exposures-only":
                "EXPOSURES_ONLY - {} exposure record(s) name {}: vulnerability facts from KEV, "
                "ZDI, vendor PSIRT, NVD or a joint advisory, with no detection logic, listed "
                "in the EXPOSURE blocks. No observation names it and no class resolved, so "
                "there are no findings. {}{}".format(
                    len(named_exposures), subject,
                    "{} (corpus/schema/scope.json); the mobile management plane is in scope: "
                    "--as app.mdm".format(handset_aside(beside)) if beside else
                    "For class-level findings pass --as, e.g. the classes these exposures "
                    "carry: " + ", ".join(exposure_classes(named_exposures)),
                    # Every other mode carried the refusal in `note`, and this one, the mode
                    # "Apple iOS" answers in, counted it nowhere but EXPOSURES_NOT_LISTED.
                    "; {} handset exposure record(s) naming it are held and not listed, "
                    "because handsets are out of scope".format(refused) if refused else ""),
            "unresolved":
                "UNRESOLVED - {} resolved against the alias table, but no observation names "
                "it, no class resolved, and no record's tags or prose carried the question's "
                "other words; the {} exposure record(s) naming it are handset records, which "
                "this corpus holds and keeps out of scope (EXPOSURES_NOT_LISTED)".format(
                    subject, refused) if subject and refused else
                "UNRESOLVED - {} resolved against the alias table, but no observation or "
                "exposure in the corpus names it, no class resolved, and no record's tags or "
                "prose carried the question's other words".format(subject) if subject else
                bare_unresolved(handset, refused, prose, unknown),
        }[mode]
    if mode in UNWARNED_MODES:
        return line, None
    held = ("; {} exposure record(s) do, and they are the only material here about it"
            .format(naming) if naming else "")
    warning = {
        "vendor-level":
            "no finding below {} {}{}: each names {}'s other product lines or shares a "
            "class with the question{}. A vendor's other lines are its history, not this "
            "product's. Do not present any of it as intelligence about {}, and say so wherever "
            "it is passed on.".format(names, subject, beyond, show("vendors"),
                                "; {} exposure record(s) do".format(naming) if naming else "",
                                subject),
        "name-without-observations":
            "no finding below was reached by the name asked about, and each may be about "
            "something else. The corpus holds no observation {} {}{}{}. Do not present "
            "any of it as intelligence about it, and say so wherever it is passed on.".format(
                "about" if campaign else "naming", subject, beyond, held),
        "exposures-only":
            "there are no findings. The corpus holds no observation naming {}, only exposure "
            "records, which carry no detection logic. Do not present this as detection "
            "guidance, and do not report it as 'no known threats'.".format(subject),
        "unresolved":
            "nothing in this answer is about the technology asked about: the corpus holds no "
            "observation naming it. Do not report this as 'no known threats'.",
    }.get(mode,
          "every finding below describes what this CLASS of technology has been caught up "
          "in, not this product. The corpus holds no observation {} it{}{}. Do not "
          "present any of it as product-specific intelligence, and say so wherever it is "
          "passed on.".format("about" if campaign else "naming", beyond, held))
    if below != "below":
        line, warning = (re.sub(r"\b(findings?) below\b", r"\1 " + below, text)
                         if text else text for text in (line, warning))
    if dropped:
        # --role kept no observation naming what was asked and dropped `dropped` that do, so
        # each claim is scoped to the kept records and the dropped ones are counted.
        def kept(text):
            for old, new in ROLE_SCOPED:
                text = text.replace(old, new)
            return text
        line = kept(line) + "; {} observation record(s) naming it were dropped by --role".format(
            dropped)
        warning = warning and (kept(warning) + " {} observation record(s) naming it were "
                               "dropped by --role; drop --role to see them.".format(dropped))
    return line, warning


# The ladder's tiers, in the order locus_for() tries them, and the names LOCUS_BASIS prints.
# corpus/schema/locus-map.json carries the same list as `tier_order`, and until 0.43.0 that
# copy was documentation nothing read: reversing it in the file changed no output and failed
# no check. validate.py now refuses the corpus when the two disagree, so the file cannot
# describe a ladder the code does not run.
#
# There is no evidence tier. It sat between class_first and shape and could never fire,
# because every record carries a product_class and every class is mapped; since 0.43.0 the
# evidence signal is the last span source instead, because evidence is where a detection is
# read, not where the attack sits. Evidence decides in six narrow places only, each where a
# record-level input would otherwise outrank what the block itself says, and each only where
# the block reads nothing on the plane it displaces: whether a record's surface reaches a
# block (surface_reaches_block below), `host_evidence` (a block past its record's surface
# reading only host evidence, which is how the vocabulary defines ENDPOINT), `posture` (an
# inventory-shaped block reading only posture is an inventory question, which the vocabulary
# puts on ORGANISATION), `admin_api_unread` (a class the vocabulary defines as an
# administrative API does not place a block that reads none of it), `admin_api_listed` (a
# block reading the administrative API of a class its record lists after the first) and
# `host_listed` (a block reading only host evidence, on a record listing an operating system,
# browser or agent class after the first). All six read deciding_planes(), so no two of them
# can read one block differently. `operation` reads one typed marker, the cloud_operation,
# because it names the administrative act the vocabulary places.
#
# `shape` sat after class_first, with the same reachability as the evidence tier: never. It
# is gone, and `posture` above the surface is what it was meant to be. `default` is the floor
# for an input carrying no mapped class, which validate.py refuses in the corpus; it is kept
# so locus_for() answers for any input, and is the one tier the shipped corpus never reaches.
#
# `identifier` (0.44.0) places a generated exposure by what every one of its identifiers' own
# catalogue or advisory text names (what.identifier_signals), where all of them read one locus
# other than the first-listed class's: both BIG-IP Configuration Utility identifiers name the
# Configuration utility, and the class put them on CONTROL with the forwarding plane. It sits
# directly above class_first, the tier it outranks; for an exposure only class_nonproduct and
# class_first can otherwise fire, so its position among the per-block tiers changes nothing.
LOCUS_TIERS = ("declared", "surface_supply", "class_nonproduct", "posture", "surface",
               "host_evidence", "operation", "admin_api_unread", "admin_api_listed",
               "host_listed", "identifier", "class_first", "default")

# Where LOCUS_SPAN's second value may come from, in the order they are tried: the first
# source whose locus differs from the primary wins. The map carries the same list as
# `span_order`, checked by validate.py the way tier_order is. Every source is the record's
# and its block's, never the question's, so validate.py, emit_xql.py and advise.py print the
# span a consultation prints. The question's matched class is not a source here: until the
# 2026-09-30 validation it was the first, and on a firewall question it took the one slot
# from the record's own second locus, so a consultation and emit_xql.py disagreed about where
# the same block sits. It is appended after the record's span by question_locus(), and can
# only add a value.
#
# `identifier` (0.44.0) is a generated exposure's own identifiers: the class plane the
# identifier tier displaced, or, where some identifiers read another plane and not all, the
# plane most of them read. A generated exposure's surface is never read, so in practice it is
# the first source such a record has: FortiOS's two super-admin bypasses beside two SSL-VPN
# flaws keep CONTROL and carry MANAGEMENT here.
LOCUS_SPAN_SOURCES = ("surface_span_only", "surface", "identifier", "class", "nonproduct",
                      "evidence")


def finding_key(record, how_index):
    """`<record_id>#how<index>`, the one identity a finding has that is unique.

    A finding is one how-block, and (RECORD_ID, PATTERN_ID) is not unique: five records
    cite one pattern from two or more blocks, and ten blocks cite none and print
    `PATTERN_ID: -`. The pair was what a consumer, and this bundle's own displacement test,
    used to name a finding, so a displaced block could be counted as present because its
    record's other block citing the same pattern was still shown. emit_xql.py accepts the
    same key, so a finding can be asked for again by it.
    """
    return "{}#how{}".format((record or {}).get("id"), how_index)


def technique_parents(how):
    """The ATT&CK parent ids a block cites, so a sub-technique counts as its parent."""
    return {str(t).split(".")[0] for t in (how or {}).get("technique") or []}


def deciding_planes(how, locus_map):
    """The planes a block's evidence commits to wherever evidence decides anything.

    by_evidence of each evidence_type, with the deferred types (syslog) and the contested
    ones (process_telemetry) left out. Every evidence test reads this one set: the surface
    reach test and the host_evidence, posture, admin_api_unread, admin_api_listed and
    host_listed tiers, and the audit-trail case of `operation`. Until the fourth validation
    the reach test counted a contested type and the tiers did not, so process_telemetry could
    set a surface aside, or keep one, on a reading the locus map says never decides.
    """
    by_evidence = locus_map.get("by_evidence") or {}
    skip = set(locus_map.get("defer_evidence") or []) | set(
        locus_map.get("contested_evidence") or [])
    return {by_evidence[e] for e in (how or {}).get("evidence_type") or []
            if e in by_evidence and e not in skip}


def surface_reaches_block(surface, surface_locus, how, first_class_locus, locus_map):
    """(reaches, why, decides): whether a record's committing surface decides this block's locus.

    A surface is per record and a block is one detection, and for a whole record's blocks
    the surface said one thing: how the subject was reached. That placed a Siemens PLC's
    operator-display manipulation, read from industrial protocol and process telemetry, on
    MANAGEMENT with the record's internet-facing management interface, and a delivered
    miner's pool traffic on SUPPLY with the container images it came in. `why` is None when
    the surface reaches the block, and otherwise the words the basis prints.

    A supply surface reaches only a block that detects the supply path itself: one citing
    the technique its vector is filed under in `surface_vector_techniques`, or reading
    evidence on SUPPLY. Every other block of the record is what the delivered code or the
    trusted party did next.

    Any other surface reaches a block unless the block has gone past the way in: it cites
    no technique in `way_in_techniques`, reads no evidence on the surface's own plane, and
    its evidence reads the first-listed class's plane, reads only posture, or reads only host
    evidence. The burden is the other way round from supply, because on a device most of
    what follows a management login is still its administration: a configuration change, a
    firmware image, a log setting. A block with no evidence and no technique keeps the
    surface, as before.

    `decides` is None except in the host case, where neither the surface nor the class is
    read and the block's own evidence is the only input that says where it sits: ENDPOINT,
    which the vocabulary defines as process, file, registry and memory on a host. The Siemens
    S7 record's library-artefact block, read from EDR alone on a host that is not an
    engineering workstation, printed MANAGEMENT from the record's management interface, and
    both Siemens answers named ENDPOINT absent. Only host evidence decides here: the same test
    on any single third plane would put SNMP probes, which the vocabulary names as MANAGEMENT,
    on DATA because they were read from flow records, and a dropped database table read by
    an integrity check on SUPPLY. A contested type is left out of every test here, as it is
    in the tiers (deciding_planes), so it neither sets a surface aside nor keeps one.
    """
    read = deciding_planes(how, locus_map)
    cited = technique_parents(how)
    if surface in set(locus_map.get("surface_supply") or []):
        vector = set((locus_map.get("surface_vector_techniques") or {}).get(surface) or [])
        if cited & vector or surface_locus in read or first_class_locus == surface_locus:
            return True, None, None
        return False, ("set aside for this block, which cites none of {} and reads no "
                       "evidence on {}: it detects what followed the {}, not the {}".format(
                           ", ".join(sorted(vector)) or "-", surface_locus,
                           surface.replace("_", " "), surface.replace("_", " "))), None
    way_in = set(locus_map.get("way_in_techniques") or [])
    if (cited & way_in or surface_locus in read or not first_class_locus
            or first_class_locus == surface_locus):
        return True, None, None
    if first_class_locus in read:
        return False, ("set aside for this block, which reads {}, its first-listed class's "
                       "plane, cites no initial-access technique and reads nothing on "
                       "{}".format(first_class_locus, surface_locus)), None
    if read == {"ORGANISATION"}:
        return False, ("set aside for this block, whose evidence reads only posture, cites no "
                       "initial-access technique and reads nothing on {}".format(
                           surface_locus)), None
    if read == {"ENDPOINT"}:
        return False, ("set aside for this block, which reads only host evidence, cites no "
                       "initial-access technique and reads nothing on {} or on {}, its "
                       "first-listed class's plane".format(surface_locus, first_class_locus)), \
            "ENDPOINT"
    return True, None, None


def cloud_operations(how, locus_map):
    """(names, administrative) of the cloud_operation markers a block carries.

    `administrative` is True when at least one operation is not a use of the service listed
    in `non_administrative_operations`. A regex, substring, prefix or suffix names a family
    of operations and is never read as listed. The one place the listed-use test is written:
    the operation tier and admin_api_listed both read it.
    """
    listed = set(locus_map.get("non_administrative_operations") or [])
    names, administrative = [], False
    for marker in (how or {}).get("markers") or []:
        if marker.get("type") != "cloud_operation":
            continue
        value = marker.get("value")
        values = value if isinstance(value, list) else [value]
        names.extend(str(v) for v in values)
        if (marker.get("match") in ("regex", "contains", "prefix", "suffix")
                or any(v not in listed for v in values)):
            administrative = True
    return names, administrative


def operation_test(how, locus_map):
    """(names, beside): the operations when a block's live test is a cloud administrative API.

    Two shapes qualify, and `beside` says which, so the basis never claims the first for the
    second. Every typed marker is a cloud_operation (`beside` is []). Or the block's deciding
    evidence reads only MANAGEMENT, its MANAGEMENT evidence is the provider's audit trail
    (cloud_audit) alone, and it tests an operation there beside other typed markers, whose
    types `beside` lists: a block reading nothing but the audit trail filters on fields of
    that trail's event, so a user name or an agent beside the operation is still the API's
    live test. 0.43.0 required the first shape only and kept the Bedrock model-access block,
    its operations beside a user-name pattern and an HTTP client agent, on CONTROL; the fourth
    validation read both as fields of the same CloudTrail event. A process name beside host evidence is not such a
    field, and the block keeps its class. Either way not every operation may be a listed use.
    A computed marker is prose and tests nothing by itself, so it neither counts nor
    disqualifies. A record's block is read with its own markers, never its pattern's, so
    validate.py, which places a block without its pattern, agrees. A library pattern placed
    with no record is read with its own markers: it has no block, and locus_for() hands it in
    where the block would be.
    """
    typed = [m for m in (how or {}).get("markers") or []
             if m.get("type") and m.get("type") != "computed"]
    names, administrative = cloud_operations(how, locus_map)
    if not names or not administrative:
        return [], []
    beside = []
    for marker in typed:
        if marker.get("type") != "cloud_operation" and marker["type"] not in beside:
            beside.append(marker["type"])
    if beside:
        by_evidence = locus_map.get("by_evidence") or {}
        management = {e for e in (how or {}).get("evidence_type") or []
                      if by_evidence.get(e) == "MANAGEMENT"}
        if deciding_planes(how, locus_map) != {"MANAGEMENT"} or management != {"cloud_audit"}:
            return [], []
    return names, beside


def administrative_operation(how, locus_map):
    """The operations when a block's live test is a cloud administrative API, else [].

    operation_test() without saying which shape qualified.
    """
    return operation_test(how, locus_map)[0]


def service_use_only(how, locus_map):
    """True when a block carries cloud_operation markers and every one is a use of the service.

    A use is listed in `non_administrative_operations`: reading mail, invoking a model,
    reading a stored object. Such a block reads its provider's audit trail for the use, not
    for an administration, so admin_api_listed does not move it; that is how an Exchange
    Online block testing MailItemsAccessed stays on DATA whatever its record lists. False for
    a block with no cloud_operation marker.
    """
    names, administrative = cloud_operations(how, locus_map)
    return bool(names) and not administrative


def question_locus(record, pattern, primary, span, locus_map, matched_classes):
    """(locus, class) a class the question resolved adds to LOCUS_SPAN, or (None, None).

    The first productive class on the record, or on a pattern with no record, that the
    question resolved and whose locus is neither the primary nor the record's own span. It
    is appended, never substituted: the record's own second locus is what emit_xql.py and
    validate.py print, and a consultation prints the same value first.
    """
    if not matched_classes:
        return None, None
    by_class = locus_map.get("by_class") or {}
    nonproduct = set(locus_map.get("nonproduct_class") or [])
    classes = list(((record or {}).get("who") or {}).get("product_class")
                   or (pattern or {}).get("applies_to_classes") or [])
    for value in classes:
        if value in nonproduct or value not in by_class or value not in matched_classes:
            continue
        if by_class[value] not in (primary, span):
            return by_class[value], value
    return None, None


def identifier_loci(record, by_class):
    """({identifier: locus}, entries) a generated exposure's what.identifier_signals read.

    An identifier with a locus entry reads that locus; one with only a class entry reads the
    plane by_class gives the class. An identifier with no entry reads nothing of its own and
    sits where the record's class puts it. The caller asks only for a generated exposure:
    validate.py refuses the field on any other record."""
    entries = [e for e in ((record or {}).get("what") or {}).get("identifier_signals") or []
               if isinstance(e, dict) and e.get("id")]
    out = {}
    for entry in entries:
        if entry.get("locus"):
            out[entry["id"]] = entry["locus"]
    for entry in entries:
        if entry.get("class") and entry["id"] not in out and by_class.get(entry["class"]):
            out[entry["id"]] = by_class[entry["class"]]
    return out, entries


def identifier_note(entries, total, by_class):
    """The basis words for what.identifier_signals: how many identifiers read something, and
    each with what it read and the words it read it from. Never a ";", which splits the basis."""
    parts, order = collections.OrderedDict(), []
    for entry in entries:
        if entry["id"] not in parts:
            parts[entry["id"]] = []
            order.append(entry["id"])
        if entry.get("locus"):
            parts[entry["id"]].append('{} ("{}")'.format(entry["locus"], entry.get("phrase") or "-"))
        elif entry.get("class"):
            parts[entry["id"]].append('{} {} ("{}")'.format(
                entry["class"], by_class.get(entry["class"]) or "-", entry.get("phrase") or "-"))
    return "{} of {} identifier(s) read by their own text: {}".format(
        len(order), total, ", ".join("{} {}".format(i, " and ".join(parts[i])) for i in order))


def locus_for(record, how, pattern=None, locus_map=None, matched_classes=None):
    """Where this finding sits: (locus, span, basis).

    A ladder, first hit wins, no scoring. `attack_surface` outranks `product_class`
    where it commits to a locus and reaches the block, because it is single-valued and says
    something about this incident; the class list says what the product is and more than
    half of all observation records name products from more than one plane. First-listed
    class rather than a majority vote, because authors write the primary subject first and
    voting collapses ENDPOINT.

    Ten things the ladder deliberately does not do, each of which it once did:

    - A non-product class (cross_sector, process.service_desk) decides only when it is the
      first-listed class, or the only kind listed. It fired anywhere in the list, and
      authors use cross_sector as a sector tag, so EDR and auth-log device events printed
      "an inventory or advice question". Listed later, it is a span source.
    - A surface in `surface_span_only` never decides. email_flow and remote_access_service
      name the way in, not the plane the detection reads: a browser renderer breakout
      delivered by mail is an ENDPOINT finding, and the web form of the same vector,
      watering_hole, was already deferred for exactly that reason.
    - An exposure's surface is not read at all when the record carries a tag in
      `untrusted_surface_tags`. Those four generators write attack_surface from a class
      table, so the surface tier was re-encoding a class default through a table that
      disagrees with by_class, and a firewall CVE came out MANAGEMENT. What stands in for it
      is what each identifier's own text names (what.identifier_signals, written by the same
      generators from locus-map.json identifier_reading): a locus every identifier reads,
      other than the class's, decides (`identifier`), and otherwise the plane most of them
      read is the span, so a firewall's management-interface flaw is MANAGEMENT by its own
      words and never by a class table.
    - A committing surface does not decide a block that has gone past the way in
      (surface_reaches_block). It placed every block of a record, so a PLC's process
      manipulation sat on MANAGEMENT and a supply-chain record's IAM calls on SUPPLY. An
      exposure has no block, and its authored surface still decides for the record.
    - A committing surface does not decide a block past the way in that reads only host
      evidence and nothing on its first-listed class's plane (`host_evidence`): that is
      ENDPOINT by the vocabulary's own definition, and the S7 library-artefact block, read
      from EDR alone, printed the record's management interface.
    - The first-listed class does not decide a block whose live test is a cloud
      administrative API (operation_test): that is MANAGEMENT whatever the record lists
      first, and six such blocks sat on CONTROL or DATA. Since the fourth validation that
      includes a block reading only the provider's audit trail and testing an operation there
      beside other fields of the same event, which 0.43.0 left on its class.
    - The first-listed class does not decide an inventory-shaped block that reads only
      posture (`posture`): that is an inventory question, which the vocabulary places on
      ORGANISATION, and the shape tier that was meant to say so sat below class_first and
      never fired. A known-exploited catalogue join sat on five loci by its records' class
      order, and the one on a web-server-first record filled the DATA slot on firewall and
      VPN questions. It outranks a non-supply surface: a posture question about the way in
      is still a posture question, and the surface travels as its span.
    - A class the map lists in `administrative_api_classes` does not decide a block that
      never reads that API (`admin_api_unread`): no cloud_operation marker, nothing read on
      the class's plane or from inventory, and its deciding evidence on one other plane.
      cloud.iaas is the administrative API and console by definition, and it put a
      certificate-issuance alert read from DNS and TLS metadata on MANAGEMENT.
    - The first-listed class does not decide a record's block that reads nothing on its
      plane and reads the administrative API of a class in `administrative_api_classes`
      listed after it (`admin_api_listed`): a container's metadata credential request paired
      with the node role's first cloud API call printed CONTROL from cloud.container while
      reading only flow records and the provider's audit trail.
    - The first-listed class does not decide a record's block that reads only host evidence
      and nothing on its plane, where the record lists an operating system, browser or agent
      class after it (`host_listed`): an NTDS.dit copy staged in a temp path, read from EDR
      file events alone, printed CONTROL from identity.directory. Both *_listed tiers read a
      record's class list, which names the products the incident ran through; a pattern's
      applies_to_classes says only where it applies, so a pattern placed with no block is
      never read either way.

    Evidence types in `contested_evidence` take no part in any evidence test, the surface
    reach test included: their mapping is documented as contested, so they neither decide a
    primary nor stop one.

    The span is computed afterwards and is deliberately tier-independent: the first source
    in LOCUS_SPAN_SOURCES whose locus differs from the primary is a genuine second home,
    whichever tier decided the first. A class list split across loci is a bag, not a second
    opinion, and is never carried as a span -- that is over half of all observation records;
    the basis names the first-listed class and the other loci the list reaches instead.
    `matched_classes` is the classes the question resolved; it never moves the primary or
    the span returned here, so every caller without a question derives the same LOCUS and
    LOCUS_SPAN, and question_locus() gives the value it appends.

    A library pattern placed with no record has no block, so its own markers, rule_shape
    and evidence_type stand in for one, as its applies_to_classes stand in for a
    product_class. Until the 2026-10-01 third validation only its classes were read, and a
    pattern whose one live test is an Exchange role grant derived DATA from server.mail. It
    may also declare its own `locus` with a `locus_reason`, for the plane no class on its
    list can say: a network device's administration has no class of its own, so "SNMP from
    anything but the monitoring system" derived CONTROL from network.router. Neither ever
    reaches a record's block, which keeps the placement consult.py prints (pattern passed)
    and validate.py tallies (None) one.

    Missing tables fail loudly rather than degrading. A silent default on the one key
    that exists to be machine-parsed is worse than an honest refusal.
    """
    locus_map = locus_map or {}
    if not locus_map.get("by_class"):
        return ("UNDERIVABLE", None,
                "tier=none; corpus/schema/locus-map.json is absent or carries no tables")

    by_class = locus_map.get("by_class") or {}
    by_surface = locus_map.get("by_surface") or {}
    by_evidence = locus_map.get("by_evidence") or {}
    nonproduct = set(locus_map.get("nonproduct_class") or [])
    supply_surfaces = set(locus_map.get("surface_supply") or [])
    span_only_surfaces = set(locus_map.get("surface_span_only") or [])
    untrusted_tags = set(locus_map.get("untrusted_surface_tags") or {})
    deferred_evidence = set(locus_map.get("defer_evidence") or [])
    contested_evidence = set(locus_map.get("contested_evidence") or [])
    api_classes = set(locus_map.get("administrative_api_classes") or [])

    record = record or {}
    how = how or {}
    # What the block says. A library pattern placed with no record has no block, so its own
    # markers, rule_shape and evidence_type stand in, as its applies_to_classes stand in for
    # a product_class. A record's block never borrows its pattern's, which keeps the
    # placement consult.py prints (pattern passed) and validate.py tallies (None) one.
    block = how if record else (pattern or {})
    subject = "how[]." if record else "pattern "
    classes = list((record.get("who") or {}).get("product_class")
                   or (pattern or {}).get("applies_to_classes") or [])
    # Named in the basis, because a library pattern's classes are what it applies to, not
    # what a record's product is: the basis said "product_class" for both.
    class_source = ("product_class" if (record.get("who") or {}).get("product_class")
                    else "applies_to_classes")
    surface = (record.get("what") or {}).get("attack_surface")
    generated = (sorted(untrusted_tags & set(record.get("tags") or []))
                 if record.get("record_type") == "exposure" else [])
    read_surface = surface if surface and not generated else None
    # A generated exposure's identifiers, each read by its own text, stand in for the surface
    # the generator assigned and the ladder does not read.
    id_loci, id_entries = identifier_loci(record, by_class) if generated else ({}, [])
    id_total = len((record.get("what") or {}).get("vulnerabilities") or [])

    productive = [c for c in classes if c not in nonproduct and c in by_class]
    csig = [by_class[c] for c in productive]
    # Only a locus entry decides, and only when every identifier carries one and they agree on
    # a plane the class does not already give. A class read from an identifier's text says what
    # the product is, which the record's class already answers, so like a class the question
    # matched it only ever adds a span. A minority reading another plane is the span: FortiOS's
    # two super-admin bypasses beside two SSL-VPN flaws are not a management product.
    phrased = {e["id"]: e["locus"] for e in id_entries if e.get("locus")}
    read_loci = set(phrased.values())
    identifier_commits = None
    if id_total and len(phrased) == id_total and len(read_loci) == 1 \
            and read_loci != {csig[0] if csig else None}:
        identifier_commits = next(iter(read_loci))
    class_commits = csig[0] if csig and len(set(csig)) == 1 else None
    surface_commits = by_surface.get(read_surface) if read_surface else None
    span_only = read_surface in span_only_surfaces
    listed_nonproduct = [c for c in classes if c in nonproduct and c in by_class]
    declared = how.get("locus")
    pattern_declared = (pattern or {}).get("locus") if not record else None
    nonproduct_first = bool(listed_nonproduct and (classes[0] in nonproduct or not productive))

    # Evidence is read from the block, or from a library pattern's own list. `esig` is every
    # committing type and feeds the span; `deciding` leaves out the contested types as well,
    # and is all the evidence tests below read (deciding_planes, shared with the reach test).
    evidence_types = block.get("evidence_type") or []
    esig = [by_evidence[e] for e in evidence_types
            if e in by_evidence and e not in deferred_evidence]
    evidence_commits = esig[0] if esig and len(set(esig)) == 1 else None
    deciding = sorted(deciding_planes(block, locus_map))
    # Said in the basis wherever one of the evidence tests decides, so a contested type the
    # block does read is never silently missing from why it sits where it does.
    set_by = "".join(", {} contested and not read".format(e) for e in evidence_types
                     if e in contested_evidence)
    # An inventory question: answered against asset or configuration state, and reading
    # nothing but posture. The vocabulary's ORGANISATION is exactly that.
    posture = block.get("rule_shape") == "inventory" and deciding == ["ORGANISATION"]
    operations, beside = operation_test(block, locus_map)
    # A class defined as an administrative API places only a block that reads it. One that
    # carries no cloud_operation marker, reads nothing on the class's own plane or from the
    # provider's inventory, and whose deciding evidence sits on one other plane, is a workload
    # or a service reached through the provider, read where it runs.
    unread = None
    if productive and productive[0] in api_classes and len(deciding) == 1 \
            and deciding[0] not in (csig[0], "ORGANISATION") \
            and not any(m.get("type") == "cloud_operation" for m in block.get("markers") or []):
        unread = deciding[0]
    # The other way round: a record listing an administrative API class after its first names
    # the provider whose API that is. A block reading that API (cloud_audit or config_diff)
    # and nothing on the first-listed class's plane is administration of that provider, unless
    # every operation it tests is a use of a service. Read for a record's block only.
    listed = None
    if record and how and csig and csig[0] not in deciding \
            and not service_use_only(block, locus_map):
        listed = next((c for c in productive[1:]
                       if c in api_classes and by_class[c] in deciding), None)
    # The same for the host. A record listing an operating system, browser or agent class
    # after its first names the host the incident ran on, and a block reading only host
    # evidence, so nothing on the first-listed class's plane, is execution on that host.
    host_listed = None
    if record and how and csig and csig[0] != "ENDPOINT" and deciding == ["ENDPOINT"]:
        host_listed = next((c for c in productive[1:] if by_class[c] == "ENDPOINT"), None)

    # Per block, where there is one: an exposure is placed as a record, and its authored
    # surface decides for it as it always did. Asked only where the surface would otherwise
    # decide, so the basis never says a surface was set aside that a declaration, a
    # first-listed non-product class or a posture question outranked anyway. A supply
    # surface ranks above both and is always asked.
    set_aside, host = None, None
    if (how and surface_commits and not span_only and not declared
            and (read_surface in supply_surfaces or not (nonproduct_first or posture))):
        _, set_aside, host = surface_reaches_block(read_surface, surface_commits, how,
                                                   csig[0] if csig else None, locus_map)

    if declared:
        primary, tier, decided_by, why = declared, "declared", None, "how[].locus"
    elif pattern_declared:
        primary, tier, decided_by = pattern_declared, "declared", None
        why = "locus declared on the pattern, {}".format(
            (pattern or {}).get("locus_reason") or "no reason given")
    elif read_surface in supply_surfaces and not set_aside:
        primary, tier, decided_by = by_surface[read_surface], "surface_supply", "surface"
        why = "what.attack_surface={}".format(read_surface)
    elif nonproduct_first:
        # Read from the table rather than written as a literal, so the map is the one place
        # a non-product class is placed. validate.py refuses a nonproduct_class with no
        # by_class entry, which is what keeps this lookup from raising.
        first = classes[0] if classes[0] in nonproduct else listed_nonproduct[0]
        primary, tier, decided_by = by_class[first], "class_nonproduct", "nonproduct"
        why = ("{} first-listed={}".format(class_source, first) if productive
               else "{} carries only non-product classes: {}".format(
                   class_source, ", ".join(listed_nonproduct)))
    elif posture:
        primary, tier, decided_by = "ORGANISATION", "posture", None
        why = "{}rule_shape=inventory and its evidence_type reads only posture ({}){}".format(
            subject, ", ".join(e for e in evidence_types if by_evidence.get(e) == "ORGANISATION"),
            set_by)
    elif surface_commits and not span_only and not set_aside \
            and read_surface not in supply_surfaces:
        primary, tier, decided_by = surface_commits, "surface", "surface"
        why = "what.attack_surface={}".format(read_surface)
    elif host:
        primary, tier, decided_by = host, "host_evidence", None
        why = "{}evidence_type reads only host evidence ({}), past its record's surface{}".format(
            subject, ", ".join(e for e in evidence_types if by_evidence.get(e) == host), set_by)
    elif operations:
        primary, tier, decided_by = "MANAGEMENT", "operation", None
        shown = ", ".join(operations[:4]) + (" and {} more".format(len(operations) - 4)
                                             if len(operations) > 4 else "")
        if beside:
            why = ("{}evidence_type reads only the provider's audit trail (cloud_audit), and its "
                   "markers test cloud administrative operations there ({}) beside other fields "
                   "of the same event ({}){}".format(subject, shown, ", ".join(beside), set_by))
        else:
            why = "{}markers test only cloud administrative operations ({})".format(subject, shown)
    elif unread:
        primary, tier, decided_by = unread, "admin_api_unread", None
        why = ("{} first-listed={} is an administrative API the {} never reads: no "
               "cloud_operation marker, and its evidence_type reads {} only{}".format(
                   class_source, productive[0], "block" if record else "pattern", unread,
                   set_by))
    elif listed:
        primary, tier, decided_by = by_class[listed], "admin_api_listed", None
        why = ("{} lists {} after first-listed={}, and the block reads that administrative API "
               "and nothing on {}{}".format(class_source, listed, productive[0], csig[0], set_by))
    elif host_listed:
        primary, tier, decided_by = "ENDPOINT", "host_listed", None
        why = ("{} lists {} after first-listed={}, and the block reads only host evidence ({}) "
               "and nothing on {}{}".format(
                   class_source, host_listed, productive[0],
                   ", ".join(e for e in evidence_types if by_evidence.get(e) == "ENDPOINT"),
                   csig[0], set_by))
    elif identifier_commits:
        primary, tier, decided_by = identifier_commits, "identifier", "identifier"
        why = ("what.identifier_signals reads {} for every one of the {} identifier(s), by "
               "its own text, where {} first-listed={} reads {}".format(
                   identifier_commits, id_total, class_source,
                   productive[0] if productive else "-", csig[0] if csig else "-"))
    elif csig:
        primary, tier, decided_by = csig[0], "class_first", "class"
        why = "{} first-listed={}".format(class_source, productive[0])
    else:
        primary, tier, decided_by = locus_map.get("default") or "CONTROL", "default", None
        why = "no signal committed"

    # The identifiers' own span: the class plane the identifier tier displaced, or the plane
    # most of them read other than the primary, ties in locus_order. Never the question's.
    if decided_by == "identifier":
        identifier_span = csig[0] if csig else None
    else:
        order = list(locus_map.get("locus_order") or [])
        other = collections.Counter(v for v in id_loci.values() if v != primary)
        identifier_span = (sorted(other, key=lambda v: (-other[v], order.index(v) if v in order
                                                        else len(order)))[0] if other else None)
    sources = {
        "surface_span_only": surface_commits if span_only else None,
        "surface": surface_commits if not span_only and decided_by != "surface" else None,
        "identifier": identifier_span,
        "class": class_commits if decided_by != "class" else None,
        "nonproduct": (by_class[listed_nonproduct[0]]
                       if listed_nonproduct and decided_by != "nonproduct" else None),
        "evidence": evidence_commits,
    }
    span, span_source = None, None
    for source in LOCUS_SPAN_SOURCES:
        if sources[source] and sources[source] != primary:
            span, span_source = sources[source], source
            break
    asked, asked_class = question_locus(record, pattern, primary, span, locus_map,
                                        matched_classes)

    if generated and surface:
        surface_note = "{} (what.attack_surface={} is generator-assigned on an exposure " \
                       "tagged {}, not read)".format(by_surface.get(surface) or "-", surface,
                                                     ", ".join(generated))
    elif span_only and surface_commits:
        surface_note = "{} ({} is the way in, not the plane: span only)".format(
            surface_commits, read_surface)
    elif set_aside:
        surface_note = "{} (what.attack_surface={} {}{})".format(
            surface_commits, read_surface, set_aside,
            ": span only" if span_source == "surface" else "")
    else:
        surface_note = surface_commits or "-"
    if class_commits:
        class_note = "{} (unanimous)".format(class_commits)
    elif csig:
        # "split" alone hid which class decided and what else was listed: a firewall
        # question's KEV-harvest finding printed DATA with no word that network.firewall,
        # CONTROL, was on the same record.
        others = []
        for value in csig:
            if value != csig[0] and value not in others:
                others.append(value)
        class_note = "split(first={}:{}; also {})".format(productive[0], csig[0], ", ".join(others))
    else:
        class_note = "-"
    if not listed_nonproduct:
        nonproduct_note = "-"
    elif decided_by == "nonproduct":
        nonproduct_note = "{} ({})".format(
            primary, "{} first-listed".format(classes[0]) if productive
            else "only non-product classes listed")
    else:
        nonproduct_note = "{} ({} listed, not primary)".format(
            by_class[listed_nonproduct[0]], ", ".join(listed_nonproduct))
    if evidence_commits:
        evidence_note = "{} (unanimous)".format(evidence_commits)
    else:
        evidence_note = "split" if esig else "-"
    span_notes = [span_source] if span_source else []
    if asked:
        span_notes.append("class_matched span: {}".format(asked_class))
    span_note = ", then ".join(span_notes) or "-"

    basis = ("tier={}; input={}; surface-signal={}; class-signal={}; nonproduct-signal={}; "
             "evidence-signal={}; span-source={}; declared={}").format(
                 tier, why, surface_note, class_note, nonproduct_note, evidence_note,
                 span_note, "yes" if (declared or pattern_declared) else "no")
    # Only on a record carrying the field, so every other basis is byte-identical to 0.43.0's.
    if id_entries:
        basis += "; identifier-signal={}".format(identifier_note(id_entries, id_total, by_class))
    return primary, span, basis


def placed(record, how, pattern, locus_map, matched_classes=None):
    """(locus, span values, basis) as a consultation prints them.

    The span values are the record's own second locus, which every caller without a
    question prints as well, then the locus a class the question resolved adds, if any. A
    consumer splitting LOCUS_SPAN on ", " gets the primary and up to two more, and the
    values after the primary that emit_xql.py prints are always the first of these.
    """
    locus, span, basis = locus_for(record, how, pattern, locus_map, matched_classes)
    asked = question_locus(record, pattern, locus, span, locus_map, matched_classes)[0]
    return locus, tuple(value for value in (span, asked) if value), basis


def span_text(locus, spans):
    """LOCUS_SPAN's value: the primary, then every span value, never "-"."""
    return ", ".join([locus] + list(spans or ()))


def eligible(finding):
    """Does this finding keep its locus out of LOCUS_ABSENT, and may it fill a reserved slot?

    A subject or tag match (ELIGIBLE_TIERS) whose criticality before any coverage demotion
    reaches RESERVE_FLOOR. Where the question named a product or vendor and a finding names
    it, a reserved slot is further filled only from a finding naming what was asked
    (question_subject(), naming_eligible()).
    Eligibility never removes a finding: it decides only what the quota may reserve and what
    LOCUS_ELIGIBLE, LOCUS_SUBJECT, LOCUS_ABSENT and LOCUS_ANALOGUE_ONLY count.
    """
    return finding.match_basis in ELIGIBLE_TIERS and finding.crit >= RESERVE_FLOOR


def naming_eligible(finding, subject=None):
    """Eligible, and naming the product or vendor asked about (question_subject())."""
    return eligible(finding) and names_subject(finding, subject)


# One locus's tallies over the whole match set. `loose` is matched in a tier that can never
# be eligible and `below_floor` in one that can at a criticality under RESERVE_FLOOR, so for an
# absent locus the two sum to `matched`. `span_only` counts the findings placed elsewhere that
# carry this locus anywhere after the primary in LOCUS_SPAN: the record's own second locus, or
# the locus the question's matched class appends.
# `best` is the (rank, finding) of the locus's first ineligible finding in ORDERING order.
# `naming` counts the eligible findings naming what was asked (question_subject()), `by_tier`
# every eligible finding by tier, and `first` is the (rank, finding) of the locus's first
# eligible finding.
LocusTally = collections.namedtuple(
    "LocusTally", "matched eligible loose below_floor span_only best naming by_tier first")

# What apply_locus_quota() decided. `shown` is (rank, finding, slot) in ORDERING order, where
# rank is the finding's 1-based position in the whole ORDERING order and slot is `natural`,
# `natural-reserve`, `replacement`, `reserved` or `backfill`. `reserved`, `passed` and
# `backfilled` are (rank, finding) lists; `displaced` is (rank, finding, chosen by the cap).
# `capped` counts the natural top-N findings the cap passed over and never showed,
# `capped_records` their records, and `want` is each reserved locus's reserve. `past_cap` maps
# the rank of each finding a record holds beyond RECORD_CAP, counted in RANK order, to why the
# record holds that many, and `holds` counts the shown slots by record id. `naming` says whether
# the reserve was filled only from findings naming what was asked, `analogue_only` lists the
# loci holding eligible findings none of which names it, which the reserve then passes over,
# and `subject` is what was asked (question_subject()), WHOLE where nothing narrowed it.
Quota = collections.namedtuple(
    "Quota", "shown reserved displaced passed backfilled tallies shown_counts absent "
             "underserved asked per_locus cap spread capped capped_records want past_cap "
             "holds naming analogue_only subject")


def locus_tallies(findings, order, subject=None):
    """Per-locus counts over the whole match set, before --limit, as an ordered dict."""
    def blank():
        return dict(matched=0, eligible=0, loose=0, below_floor=0, span_only=0, best=None,
                    naming=0, by_tier=collections.Counter(), first=None)
    rows = collections.OrderedDict((locus, blank()) for locus in order)
    for i, finding in enumerate(findings):
        row = rows.setdefault(finding.locus, blank())
        row["matched"] += 1
        if eligible(finding):
            row["eligible"] += 1
            row["by_tier"][finding.match_basis] += 1
            if naming_eligible(finding, subject):
                row["naming"] += 1
            if row["first"] is None:
                row["first"] = (i + 1, finding)
        else:
            row["loose" if finding.match_basis not in ELIGIBLE_TIERS else "below_floor"] += 1
            if row["best"] is None:
                row["best"] = (i + 1, finding)
        for value in finding.span or ():
            rows.setdefault(value, blank())["span_only"] += 1
    return collections.OrderedDict((locus, LocusTally(**row)) for locus, row in rows.items())


def reserve_from_naming(findings, resolved, subject=None):
    """Is the reserve filled only from findings naming what was asked (question_subject())?
    Where the question named a product or vendor and any finding in the match set names it,
    below the floor included, yes; where it named neither, or no finding names what it named,
    the answer is about the class or the mechanism throughout and every eligible tier may fill
    it."""
    named = bool((resolved or {}).get("products") or (resolved or {}).get("vendors"))
    return named and any(names_subject(f, subject) for f in findings)


def apply_locus_quota(findings, limit, order, spread=True, per_locus=1, cap=RECORD_CAP,
                      naming=False, subject=None):
    """Reserve up to `per_locus` slots per locus holding a finding that may fill one, then fill
    in ORDERING order with no record taking more than `cap` slots while another record's
    finding in its own match group waits.

    A finding may fill a reserve when it is eligible, and, under `naming`
    (reserve_from_naming()), when it also names what was asked (`subject`,
    question_subject()): the reserve never takes an analogue's slot at the cost of a finding
    naming what was asked, and a locus holding only analogues is listed in `analogue_only`
    rather than reserved for.

    `findings` arrives in ORDERING order, grouped by match tier before the score, and the
    shown set is returned in that same order, so RANK, the finding's position in the whole
    ORDERING order, stays strictly increasing and agrees with every rank the header cites.

    Three steps, each of which the header accounts for against pure ORDERING order, which is
    what --no-locus-spread shows:

    1. Reserve. In round k, each eligible locus whose reserve is not yet met takes its next
       eligible finding; where that finding's record already holds `cap` slots, it takes the
       next one of the same match group whose record does not, if there is one. The round's
       picks go in ORDERING order, so a --limit below the reserve keeps the strongest loci.
       A reserve inside the natural top N costs nothing and is not reported.
    2. Fill the remaining slots group by group in ORDERING order, passing over a finding whose
       record already holds `cap` slots while its group holds another record's finding.
    3. At the end of each group, before the next is reached, backfill any slot still open
       with the findings step 2 passed over in that group, in ORDERING order.

    The cap never crosses a group. Applied across groups it passed over a record naming the
    product for another vendor's class analogue: "Check Point firewall" lost its rank-3 Check
    Point block to a Cisco VPN record at rank 10, and 178 of 848 product questions lost 566
    findings naming what was asked in that way. Within a group it still stops one analogue
    filling the answer, which is what it is for.

    The natural top N loses exactly as many findings as the shown set gains from below it.
    The reserves account for as many as they took from below the cut, the lowest ranked of
    what was lost, listed under LOCUS_DISPLACED, so LOCUS_DISPLACED and LOCUS_RESERVED stay the
    same length. The rest were passed over by the cap and are listed under RECORD_CAP, each
    balanced by one finding of its own group the fill reached below the cut. Where the reserves
    had already cost the slot, the cap only chose which finding left, and its LOCUS_DISPLACED
    bullet says so; RECORD_CAP's line counts both kinds. --no-locus-spread turns off the
    reserve and the cap together, so pure order stays pure.
    """
    tallies = locus_tallies(findings, order, subject)
    fills = (lambda f: naming_eligible(f, subject)) if naming else eligible
    populated = [locus for locus, row in tallies.items()
                 if (row.naming if naming else row.eligible)]
    absent = [locus for locus, row in tallies.items() if not row.eligible]
    # Stated whether or not the quota is on: it is a statement about the planes, not about
    # which findings were shown.
    analogue_only = [locus for locus, row in tallies.items()
                     if row.eligible and locus not in populated]
    shown_counts = collections.OrderedDict((locus, 0) for locus in order)
    cut = min(limit, len(findings))
    natural = set(range(cut))

    if not spread:
        shown = [(i + 1, findings[i], "natural") for i in range(cut)]
        for _, finding, _ in shown:
            shown_counts[finding.locus] = shown_counts.get(finding.locus, 0) + 1
        return Quota(shown, [], [], [], [], tallies, shown_counts, absent, [], 0, per_locus,
                     cap, False, 0, 0, {}, {}, collections.Counter(), naming, analogue_only,
                     subject or WHOLE)

    def owner(i):
        return findings[i].record.get("id")

    def group(i):
        return findings[i].group

    held = collections.Counter()
    chosen = set()
    pool = {locus: [i for i, f in enumerate(findings) if f.locus == locus and fills(f)]
            for locus in populated}
    want = collections.OrderedDict((locus, min(per_locus, len(pool[locus])))
                                   for locus in populated)
    got = collections.Counter()
    reserve = []
    # The loci whose reserve took a finding from a record already at the cap, by record.
    beyond_cap = collections.defaultdict(list)

    def candidate(locus):
        left = [i for i in pool[locus] if i not in chosen]
        first = left[0]
        if held[owner(first)] < cap:
            return first
        # Only within the first finding's own group: a reserve never gives a record naming the
        # product up for a looser group's analogue.
        return next((i for i in left if group(i) == group(first) and held[owner(i)] < cap),
                    first)

    for round_no in range(per_locus):
        waiting = [locus for locus in populated if want[locus] > round_no]
        while waiting and len(reserve) < limit:
            i, locus = min((candidate(l), l) for l in waiting)
            waiting.remove(locus)
            if held[owner(i)] >= cap:
                beyond_cap[owner(i)].append(locus)
            reserve.append(i)
            chosen.add(i)
            held[owner(i)] += 1
            got[locus] += 1
    underserved = [locus for locus in populated if got[locus] < want[locus]]

    passed_over, backfill, pending, filled = set(), [], [], []

    def backfill_group():
        for i in pending:
            if len(chosen) >= limit:
                break
            chosen.add(i)
            backfill.append(i)
        del pending[:]

    for i in range(len(findings)):
        if pending and group(i) != group(pending[0]):
            backfill_group()
        if len(chosen) >= limit:
            break
        if i in chosen:
            continue
        if held[owner(i)] >= cap:
            pending.append(i)
            passed_over.add(i)
            continue
        chosen.add(i)
        filled.append(i)
        held[owner(i)] += 1
    backfill_group()

    # The cap cost a finding only where the fill then took a lower-ranked one in its place. A
    # capped finding at the tail of a group that ran out of room would have left with the cap
    # off as well, because the reserves had already spent that slot.
    last_filled = max(filled, default=-1)
    capped = [i for i in sorted(natural)
              if i not in chosen and i in passed_over and i < last_filled]
    reserved = [i for i in sorted(reserve) if i not in natural]
    lost = [i for i in sorted(natural) if i not in chosen]
    split = len(lost) - len(reserved)
    displaced = [(i + 1, findings[i], i in capped) for i in lost[split:]]
    passed = [(i + 1, findings[i]) for i in lost[:split]]

    def slot(i):
        if i in backfill:
            return "backfill"
        if i in natural:
            # A reserve inside the natural top N costs nothing, but where a reserve's cost fell
            # on a higher-ranked finding, being a reserve is why this one stayed, even from a
            # looser group.
            return "natural-reserve" if i in reserve and lost[split:] and lost[split] < i \
                else "natural"
        return "reserved" if i in reserve else "replacement"

    # A record past the cap is described on the blocks it holds beyond the cap in RANK order,
    # the order a reader counts them in. The reserve rounds and the backfill do not pick in
    # that order, so the block that tipped a record over is not always the one read third.
    by_record = collections.defaultdict(list)
    for i in sorted(chosen):
        by_record[owner(i)].append(i)
    past_cap = {}
    for record_id, held_here in by_record.items():
        if len(held_here) <= cap:
            continue
        why = []
        if beyond_cap[record_id]:
            why.append("the reserve for LOCUS {} held no other record's eligible finding in "
                       "its match group".format(" and ".join(sorted(set(beyond_cap[record_id])))))
        backfilled = sum(1 for i in held_here if i in backfill)
        if backfilled:
            why.append("{} of them are backfill, taken when no finding of the same match group "
                       "from a record under the cap remained".format(backfilled))
        for i in held_here[cap:]:
            past_cap[i + 1] = "; and ".join(why)

    shown = [(i + 1, findings[i], slot(i)) for i in sorted(chosen)]
    for _, finding, _ in shown:
        shown_counts[finding.locus] = shown_counts.get(finding.locus, 0) + 1
    return Quota(shown, [(i + 1, findings[i]) for i in reserved], displaced, passed,
                 [(i + 1, findings[i]) for i in backfill], tallies, shown_counts, absent,
                 underserved, sum(want.values()), per_locus, cap, True, len(capped),
                 len({owner(i) for i in capped}), want, past_cap,
                 collections.Counter({r: len(v) for r, v in by_record.items()}), naming,
                 analogue_only, subject or WHOLE)


def slot_text(slot, rank, finding, quota, limit):
    """The SLOT value a finding block prints: why it is in the shown set at all.

    The first word is the kind of slot, one of natural, replacement, reserved and backfill,
    so a consumer can count by it; everything after the dash is for the reader.
    """
    holds = quota.holds.get(finding.record.get("id"), 0)
    beyond = ""
    if rank in quota.past_cap and slot != "backfill":
        beyond = ("; its record holds {} slots in this answer, past RECORD_CAP ({}), "
                  "because {}".format(holds, quota.cap, quota.past_cap[rank]))
    want = quota.want.get(finding.locus, quota.per_locus)
    reserve = "LOCUS {}'s reserve of {} ({})".format(
        finding.locus, want, "--per-locus {}".format(quota.per_locus) if want == quota.per_locus
        else "--per-locus {}, but the locus holds {} eligible finding(s){}".format(
            quota.per_locus, want, " naming what was asked" if quota.naming else ""))
    if slot == "reserved":
        return ("reserved - taken from rank {} below the natural top {} to fill {}; it costs "
                "one slot, listed under LOCUS_DISPLACED{}".format(rank, limit, reserve, beyond))
    if slot == "natural-reserve":
        return ("natural - rank {} is within the natural top {} and fills {}, so it stays while "
                "a higher-ranked finding is listed under LOCUS_DISPLACED{}".format(
                    rank, limit, reserve, beyond))
    if slot == "replacement":
        return ("replacement - rank {} is below the natural top {}; it takes the slot of a "
                "finding of its own match group listed under RECORD_CAP, whose record had "
                "reached the cap of {}{}".format(rank, limit, quota.cap, beyond))
    if slot == "backfill":
        return ("backfill - passed over under RECORD_CAP ({} per record within a match group), "
                "then shown because no finding of match group {} from a record under the cap "
                "was left to take the slot; its record holds {} slots in this answer".format(
                    quota.cap, finding.group, holds))
    if beyond:
        return "natural - rank {} is within the natural top {}{}".format(rank, limit, beyond)
    return "natural"


def _bullet(rank, finding, locus_first=False):
    """One finding named in a header bullet, by FINDING_KEY, with the tier it matched on."""
    key = "{} / {}".format(finding_key(finding.record, finding.how_index),
                           (finding.how or {}).get("pattern_id") or "-")
    score = "score {:.2f}".format(finding.weight)
    if abs(finding.crit - finding.weight) > 0.005:
        score += " (criticality {:.2f} before coverage)".format(finding.crit)
    if locus_first:
        return "  - {}, rank {}, {}, tier {}, {}".format(
            finding.locus, rank, score, finding.match_basis, key)
    return "  - rank {}, {}, {}, tier {}, {}".format(
        rank, score, finding.locus, finding.match_basis, key)


def locus_header(quota, limit, total, exposure_loci=None, library_loci=None, asked=()):
    """The spread lines. Printed whether or not the quota is on.

    Reporting the distribution under --no-locus-spread is the part that matters most:
    it makes a concentrated answer visible without asking the reader to run it twice.

    `exposure_loci` and `library_loci` count the EXPOSURE and LIBRARY blocks by locus, over
    everything each block matched before its own limit. They reach an absent locus's bullet
    and nothing else: neither block takes a slot, and neither makes a locus represented,
    because an exposure carries no detection logic and a library pattern no incident.
    `asked` is what the question asked about (question_subject()'s `names`): the products and
    vendors it resolved, or narrower, empty when it named neither; LOCUS_SUBJECT and
    LOCUS_ANALOGUE_ONLY are stated against them.
    """
    exposure_loci = exposure_loci or {}
    library_loci = library_loci or {}
    def dist(counts):
        return ", ".join("{}={}".format(k, v) for k, v in counts.items()) or "none"

    tallies = quota.tallies
    reserved_loci = sum(1 for row in tallies.values()
                        if (row.naming if quota.naming else row.eligible))
    names = ", ".join(sorted(asked))
    out = []
    if quota.spread:
        out.append("LOCUS_SPREAD: quota - {} slot(s) reserved per locus holding a finding that "
                   "may fill one ({}), filled by that locus's first such findings in ORDERING "
                   "order; remaining slots in ORDERING order, no record taking more than "
                   "RECORD_CAP while another record's finding in its match group waits. Pass "
                   "--no-locus-spread for pure ORDERING order.".format(
                       quota.per_locus,
                       "see LOCUS_SUBJECT: the question named {} and a finding names it, so "
                       "only a finding naming it may".format(names) if quota.naming
                       else "see LOCUS_ELIGIBLE"))
    else:
        out.append("LOCUS_SPREAD: off - pure ORDERING order (--no-locus-spread), with no "
                   "reserve and no record cap. LOCUS_MATCHED and LOCUS_SHOWN below are "
                   "reported anyway, so a concentrated answer is visible without re-running.")
    out.append("LOCUS_MATCHED: {}  (over all {} matched findings, before --limit)".format(
        dist(collections.OrderedDict((k, v.matched) for k, v in tallies.items())), total))
    out.append("LOCUS_ELIGIBLE: {}  (matched findings in tier {} whose criticality before "
               "coverage is {:.1f} or more: what keeps a locus out of LOCUS_ABSENT, and what "
               "a reserved slot may be filled from unless LOCUS_SUBJECT narrows it)".format(
                   dist(collections.OrderedDict((k, v.eligible) for k, v in tallies.items())),
                   ", ".join(ELIGIBLE_TIERS), RESERVE_FLOOR))
    # A fixed line in every answer. Counting class analogues as what made a plane represented
    # told "Fortinet FortiGate" that DATA and ENDPOINT were covered by two other products' blocks.
    if asked:
        # Said on the line wherever the subject narrowed (question_subject()), because the count
        # is then smaller than the two naming tiers would give.
        subject = quota.subject
        why = ""
        if subject.narrowed and "product" in subject.tiers:
            why = (", and not tier vendor{}, which names the vendor in a class asked about and "
                   "another of its products".format(
                       " for " + ", ".join(sorted(subject.makers)) if subject.bare else ""))
        elif subject.narrowed:
            why = ", because no finding names {}".format(", ".join(sorted(subject.unnamed)))
        out.append("LOCUS_SUBJECT: {}  (the eligible findings in tier {}, naming {}{}: {})".format(
            dist(collections.OrderedDict((k, v.naming) for k, v in tallies.items())),
            " or ".join(subject.tiers), names, why,
            "what a reserved slot is filled from" if quota.naming and quota.spread else
            # Under --no-locus-spread nothing is reserved, and the line said a slot was filled.
            "what a reserved slot would be filled from; LOCUS_SPREAD is off, so no slot is "
            "reserved" if quota.naming else
            # "Apple iOS" answers from exposures alone and said a slot was filled from
            # LOCUS_ELIGIBLE with no finding to fill it.
            "no finding matched, so there is nothing to reserve" if not total else
            "none names it, so the answer is analogues throughout and a reserved slot is "
            "filled from LOCUS_ELIGIBLE" if quota.spread else
            "none names it, so the answer is analogues throughout; LOCUS_SPREAD is off, so "
            "no slot is reserved"))
    else:
        out.append("LOCUS_SUBJECT: not applicable - the question named no product or vendor, "
                   "so no finding names one; {}".format(
                       "a reserved slot is filled from LOCUS_ELIGIBLE" if quota.spread else
                       "LOCUS_SPREAD is off, so no slot is reserved"))
    out.append("LOCUS_SHOWN: {}  (over the {} shown)".format(
        dist(quota.shown_counts), sum(quota.shown_counts.values())))
    if quota.absent:
        out.append("LOCUS_ABSENT: {} - no eligible finding in this match set sits there; each "
                   "is itemised below. That is a statement about this corpus and this "
                   "question, not a statement that the locus is safe.".format(
                       ", ".join(quota.absent)))
        # One bullet per absent locus, saying what did reach it. A bare "absent" read the same
        # whether nothing matched there or thirty prose hits did, and a locus carried only as
        # another finding's second home was reported as holding nothing.
        for locus in quota.absent:
            row = tallies[locus]
            text = "  - {}: matched {}".format(locus, row.matched)
            if row.matched:
                text += " (loose {}, below floor {})".format(row.loose, row.below_floor)
            text += "; span-only {}; exposures {}; library {}".format(
                row.span_only, exposure_loci.get(locus, 0), library_loci.get(locus, 0))
            if row.best:
                rank, finding = row.best
                text += "; best ineligible rank {}, score {:.2f}, tier {}, {} / {}".format(
                    rank, finding.weight, finding.match_basis,
                    finding_key(finding.record, finding.how_index),
                    (finding.how or {}).get("pattern_id") or "-")
            # LOCUS_SHOWN counts every shown finding, eligible or not, and a locus counted there
            # and named here read as a contradiction (planes-role, 2026-10-01).
            if quota.shown_counts.get(locus):
                text += "; shown {}, none eligible".format(quota.shown_counts[locus])
            out.append(text)
    else:
        out.append("LOCUS_ABSENT: none - every locus holds an eligible finding")
    out.extend(analogue_only_lines(quota, asked))
    out.append("LOCUS_DISPLACED: {}{}".format(
        len(quota.displaced),
        " finding(s) pushed out of the top {} to make room for a reserved slot".format(limit)
        if quota.displaced else ""))
    # Every bullet list leads with FINDING_KEY, the identity each finding block also prints.
    # The record id alone cannot say which of a record's blocks moved, and the record and
    # pattern together could not either, because one record can cite one pattern twice.
    for rank, finding, by_cap in quota.displaced:
        out.append(_bullet(rank, finding) + (
            "; RECORD_CAP chose it, its record having reached the cap of {}".format(quota.cap)
            if by_cap else ""))
    out.append("LOCUS_RESERVED: {}{}".format(
        len(quota.reserved),
        " slot(s) filled from below the natural cut" if quota.reserved else ""))
    for rank, finding in quota.reserved:
        out.append(_bullet(rank, finding, locus_first=True))
    if quota.spread:
        # Counts every natural top-N finding the cap passed over and never showed, wherever it
        # is listed. Counting its own bullets alone, the line told "Check Point firewall" that
        # nothing was passed over while LOCUS_DISPLACED named a rank-3 block the cap had chosen.
        by_cap = sum(1 for _, _, chosen_by_cap in quota.displaced if chosen_by_cap)
        if quota.capped:
            text = ("RECORD_CAP: {} per record within a match group; {} finding(s) from {} "
                    "record(s) passed over in the top {}: {} listed below{}, and {} listed under "
                    "LOCUS_DISPLACED{}".format(
                        quota.cap, quota.capped, quota.capped_records, limit, len(quota.passed),
                        ", each replaced by a finding of its own match group from below the cut"
                        if quota.passed else "", by_cap,
                        ", where a reserved slot had already cost the place" if by_cap else ""))
        else:
            text = ("RECORD_CAP: {} per record within a match group; 0 finding(s) passed over "
                    "in the top {}".format(quota.cap, limit))
        if quota.backfilled:
            text += ("; {} shown past the cap as backfill, because no finding of their match "
                     "group from a record under the cap remained".format(len(quota.backfilled)))
        out.append(text)
        for rank, finding in quota.passed:
            out.append(_bullet(rank, finding))
    else:
        out.append("RECORD_CAP: off - pure ORDERING order (--no-locus-spread)")
    kind = "loci holding a finding naming what was asked" if quota.naming else "eligible loci"
    if quota.underserved and quota.per_locus == 1:
        out.append("LOCUS_UNDERSERVED: --limit {} is below the {} {}, so {} got no "
                   "slot. Raise --limit to {} or more to see one of each.".format(
                       limit, reserved_loci, kind, ", ".join(quota.underserved), quota.asked))
    elif quota.underserved:
        out.append("LOCUS_UNDERSERVED: --limit {} is below the {} slot(s) --per-locus {} "
                   "reserves over the {} {}, so {} got fewer than their reserve. "
                   "Raise --limit to {} or more to see every reserve.".format(
                       limit, quota.asked, quota.per_locus, reserved_loci, kind,
                       ", ".join(quota.underserved), quota.asked))
    return out


def analogue_only_lines(quota, asked=()):
    """LOCUS_ANALOGUE_ONLY and its bullets: the loci holding eligible findings of which none
    names the product or vendor asked about.

    A fixed line, printed in every answer, because the difference between "the corpus holds
    FortiGate evidence on DATA" and "it holds another product's" is the one a plane heading
    hides. Each bullet counts the locus's eligible findings by tier and names its first, the
    one a reserve would have taken, so the reader can find it without re-running.
    """
    if not asked:
        return ["LOCUS_ANALOGUE_ONLY: not applicable - the question named no product or vendor, "
                "so every finding is about the class or the mechanism asked about"]
    names = ", ".join(sorted(asked))
    loci = quota.analogue_only if quota.naming else [
        locus for locus, row in quota.tallies.items() if row.eligible]
    if not loci:
        return ["LOCUS_ANALOGUE_ONLY: none - {}".format(
            "every locus holding an eligible finding holds one naming {}".format(names)
            if quota.naming else "no locus holds an eligible finding")]
    if quota.naming:
        # Narrowed to the vendor (question_subject()), the line names the vendor, whose other
        # product lines name it too, in another class.
        subject = quota.subject
        head = ("LOCUS_ANALOGUE_ONLY: {} - eligible findings sit there and none names {}{}: each "
                "is a class analogue, another product line of the vendor{} or a tag match, about "
                "another product than yours. Do not report these loci as covered for what was "
                "asked. No slot is reserved for them, so a finding there is shown on rank alone; "
                "each is itemised below.".format(
                    ", ".join(loci), names,
                    " in a class asked about" if subject.narrowed and subject.tiers == ("vendor",)
                    else "",
                    ", another of its products in a class asked about (tier vendor)"
                    if subject.narrowed and "product" in subject.tiers else ""))
    else:
        head = ("LOCUS_ANALOGUE_ONLY: {} - no finding in this match set names {}, so every "
                "locus holding an eligible finding holds analogues only, and {} (see "
                "RESOLUTION); each is itemised below.".format(
                    ", ".join(loci), names, "the reserve spreads them" if quota.spread else
                    "with LOCUS_SPREAD off no slot is reserved for them"))
    out = [head]
    for locus in loci:
        row = quota.tallies[locus]
        text = "  - {}: eligible {} ({})".format(locus, row.eligible, ", ".join(
            "{} {}".format(tier, row.by_tier[tier]) for tier in ELIGIBLE_TIERS
            if row.by_tier.get(tier)))
        if row.first:
            rank, finding = row.first
            text += "; first rank {}, score {:.2f}, tier {}, {} / {}; shown {}".format(
                rank, finding.weight, finding.match_basis,
                finding_key(finding.record, finding.how_index),
                (finding.how or {}).get("pattern_id") or "-", quota.shown_counts.get(locus, 0))
        out.append(text)
    return out


# Always-on doctrine rules whose stage is one of these are never cut. Truncation selected by
# specificity first, so once six or more class- or impact-keyed rules matched, the limit was
# spent before any always-on rule: 7 patterns lost "collect before you mitigate" and 57 lost
# "containment assumes the adversary is watching" as soon as advise.py read their classes and
# their citing records' impact, and 62 of the 770 consultation how-blocks had already lost the
# second -- the two steps whose ORDER decides whether a response works.
DOCTRINE_RESERVED_STAGES = ("collect", "contain")


def doctrine_for(classes, impacts, doctrine, limit=6, indent="  ", basis=None):
    """In what order and how widely to act, as distinct from which control to apply.

    D3FEND answers the control question per technique. This answers the questions
    that decide whether a response works at all: collect before you mitigate,
    assume the adversary is watching, scope remediation to everything exposed
    rather than to what you saw. Matched on the finding's own product class and
    impact, so a network appliance is told that a factory reset is not eradication
    and an OT record is told its emergency plan needs named degraded states.

    `basis` replaces only the header's "this finding's class or impact", for a caller
    whose classes and impact come from somewhere a reader would not assume: advise.py
    reads a pattern's applies_to_classes and its citing records' impact, and says so.
    """
    table = (doctrine or {}).get("doctrine") or {}
    if not table:
        return []
    classes = set(classes or [])
    prefixes = {c.split(".")[0] for c in classes}
    impacts = set(impacts or [])

    picked, by_class = [], set()
    for did, entry in sorted(table.items()):
        applies = entry.get("applies_to") or {}
        class_hit = bool(classes & set(applies.get("product_class") or [])
                         or prefixes & set(applies.get("class_prefix") or []))
        specific = class_hit or bool(impacts & set(applies.get("impact") or []))
        if specific or applies.get("always"):
            picked.append((did, entry, specific))
            if class_hit:
                by_class.add(did)
    if not picked:
        return []

    order = {name: i for i, name in enumerate((doctrine or {}).get("stage_order") or [])}
    # Select by relevance, display by sequence. A rule that matched because of THIS
    # finding's class or impact is why the reader is on this finding, so it must never
    # be the one truncation drops: an OT record kept losing "your emergency plan needs
    # named degraded states" behind four rules that apply to everything. But the shown
    # set is then re-sorted into incident order, because "collect before you mitigate"
    # is worthless if it prints after the eradication step it is meant to precede. The
    # always-on collect and contain rules are reserved first, for the same reason. Among the
    # specific rules, a class match outranks an impact match: the class is what the subject
    # IS, and for a pattern the impact is borrowed from the incidents citing it, so an OT
    # pattern keeps its degraded-states rule ahead of a second communications-plan rule.
    reserved = [kv for kv in picked if not kv[2]
                and ((kv[1].get("applies_to") or {}).get("always"))
                and kv[1].get("stage") in DOCTRINE_RESERVED_STAGES][:limit]
    rest = sorted((kv for kv in picked if kv not in reserved),
                  key=lambda kv: (not kv[2], kv[0] not in by_class,
                                  order.get(kv[1].get("stage"), 99), kv[0]))
    shown = reserved + rest[:max(0, limit - len(reserved))]
    shown.sort(key=lambda kv: (order.get(kv[1].get("stage"), 99), kv[0]))
    cut = [did for did, _, _ in picked if did not in {d for d, _, _ in shown}]

    body = indent + "    "
    out = ["RESPONSE_DOCTRINE: {} shown of {}, {} matched on {}, ordered {}".format(
               len(shown), len(picked), sum(1 for _, _, s in picked if s),
               basis or "this finding's class or impact",
               "-".join((doctrine.get("stage_order") or [])).lower())]
    for did, entry, _ in shown:
        out.append("{}- {} | {} | {}".format(
            indent, did, (entry.get("stage") or "-").upper(), entry.get("rule")))
        for source in entry.get("sources") or []:
            out.append("{}{} | {}".format(body, source.get("publisher"), source.get("url")))
    if cut:
        # Ids only, so the count in the header is accounted for and nothing is cut silently.
        out.append("{}NOT_SHOWN: {}".format(indent, ", ".join(cut)))
    return out


# The countermeasure selection, shared by every script that hands one on: consult.py's
# findings and library entries, advise.py's patterns and emit_xql.py's JSON handoff. Two
# selections of the same controls would disagree about what to do first, which is what
# emit_xql.py's handoff did until 0.43.0 by concatenating each technique's list and cutting
# at twelve. `techniques` is every ATT&CK id joined on, in citation order; `picked` every
# control reached, deduplicated; `grade` each one's best D3FEND grade over the techniques
# reaching it (see D3FEND_GRADES), with `owner` the first technique giving it that grade;
# `chosen` the shown controls in tactic order; `not_shown` the rest; `available` the count
# per tactic.
CountermeasureSelection = collections.namedtuple(
    "CountermeasureSelection", "techniques picked owner chosen not_shown available tactics grade")

# How D3FEND reaches a control from a technique, best first: it states the control's own
# relation to an artefact the technique touches, the control only inherits that relation from
# a class above it, or it only reaches it through a class below it. The harvest writes every
# link that is not direct into `by_attack_inferred`.
D3FEND_GRADES = ("direct", "narrower", "broader")


def d3fend_grade(d3fend, tid, cid):
    return (((d3fend or {}).get("by_attack_inferred") or {}).get(tid) or {}).get(cid, "direct")


def select_countermeasures(how, pattern, d3fend, limit=6):
    """The controls a block's techniques reach, chosen round-robin by tactic; None if none.

    Returns None when D3FEND is absent, and a selection with an empty `picked` when the block
    cites no technique or D3FEND maps none of them; the callers word those cases themselves.

    Within a tactic the order is the control's fit to the finding: a control D3FEND maps
    directly to a cited technique before one it only infers; then the one more of the
    finding's techniques reach; then one acting on the artefact before one D3FEND defines as
    acting on the whole host (the file's `host_wide`); and only then citation order, which is
    each list's name order. The lists hold both grades, and were taken in name order, so
    superclasses filled the visible slots: Access Mediation, whose definition is about
    buildings and border crossings, headed 21 of the 28 answers for T1685. Name order then
    made Host Reboot and Host Shutdown the eviction advice on 17 and 8 of 29 findings, and
    Process Termination and Process Suspension, which D3FEND maps to the same techniques
    through the same relation, on none: the LSASS answer was to reboot or shut the host down,
    which loses the memory a responder collects first.
    """
    table = (d3fend or {}).get("countermeasures") or {}
    index = (d3fend or {}).get("by_attack") or {}
    if not table:
        return None

    techniques, seen = [], set()
    for tid in list((how or {}).get("technique") or []) + list((pattern or {}).get("technique") or []):
        upper = tid.upper()
        if upper not in seen:
            seen.add(upper)
            techniques.append(upper)

    picked, owner, grade = [], {}, {}
    reach = collections.Counter()
    for tid in techniques:
        for cid in index.get(tid) or []:
            this = d3fend_grade(d3fend, tid, cid)
            reach[cid] += 1
            if cid not in owner:
                picked.append(cid)
            if cid not in owner or D3FEND_GRADES.index(this) < D3FEND_GRADES.index(grade[cid]):
                owner[cid], grade[cid] = tid, this
    host_wide = set((d3fend or {}).get("host_wide") or ())

    tactics = list((d3fend or {}).get("tactic_order") or [])
    rank = {name: i for i, name in enumerate(tactics)}

    def tactic(cid):
        return (table.get(cid) or {}).get("tactic") or "-"

    position = {cid: i for i, cid in enumerate(picked)}

    def order(cid):
        return (rank.get(tactic(cid), len(tactics)), D3FEND_GRADES.index(grade[cid]),
                -reach[cid], cid in host_wide, position[cid])

    queues = collections.OrderedDict()
    for cid in sorted(picked, key=order):
        queues.setdefault(tactic(cid), []).append(cid)
    available = collections.OrderedDict((name, len(ids)) for name, ids in queues.items())
    chosen = []
    while len(chosen) < limit and any(queues.values()):
        for name in list(queues):
            if queues[name] and len(chosen) < limit:
                chosen.append(queues[name].pop(0))
    chosen.sort(key=order)
    not_shown = [cid for ids in queues.values() for cid in ids]
    return CountermeasureSelection(techniques, picked, owner, chosen, not_shown, available,
                                   tactics, grade)


def countermeasures(how, pattern, d3fend, limit=6, indent="  "):
    """What to do about this finding, joined on the ATT&CK ids it already prints.

    D3FEND covers 222 of the 407 technique ids this corpus cites, 12 of them only
    through a predecessor ATT&CK has revoked, so a little under half of all
    findings have nothing to join to. That is reported as a gap in D3FEND rather
    than passed off as nothing to do, on the same rule as an empty resolve:
    silence must never read as coverage.

    Selected round-robin across D3FEND's tactics, in the file's tactic_order. Each
    technique's list is ordered contain-eradicate-recover first, but the lists were
    concatenated in citation order and the head taken, so the answer was the first
    technique's first six entries: six Isolate controls for LSASS dumping, with its five
    Evict and four Detect controls cut, and a header naming techniques none of whose
    controls was shown. Across the 475 patterns, 191 dropped every Evict entry and 205
    every Detect. One per tactic per pass keeps every stage that has a control, the
    header counts each tactic, names only the techniques that own a shown control, and
    NOT_SHOWN lists the rest by id.

    A technique D3FEND keys only under a revoked predecessor is joined through it and
    labelled: D3FEND 1.6.0 maps the revoked id and not its replacement, and the harvest
    re-keys its table through MITRE's revoked-by relation (`by_attack_via`). The label said
    D3FEND "predates ATT&CK 19.2", which revoked nothing: 19.1 already carried T1685.

    Each shown control says whether D3FEND maps it directly or only infers it, and the header
    names every cited technique: one whose controls were all reached through an earlier one,
    and one D3FEND does not map, vanished from the line, so six host controls for T1685 read
    as covering a router firmware implant whose T1601 has no mapping at all.
    """
    table = (d3fend or {}).get("countermeasures") or {}
    via = (d3fend or {}).get("by_attack_via") or {}
    selection = select_countermeasures(how, pattern, d3fend, limit)
    if selection is None:
        return ["COUNTERMEASURES: UNASSESSED - corpus/reference/d3fend-countermeasures.json "
                "is absent; run the D3FEND harvest to enable this block"]
    techniques, picked, owner = selection.techniques, selection.picked, selection.owner
    chosen, not_shown, tactics = selection.chosen, selection.not_shown, selection.tactics
    if not techniques:
        return ["COUNTERMEASURES: none - this finding cites no ATT&CK technique to join on"]
    index = (d3fend or {}).get("by_attack") or {}

    def mapped_below(tid):
        """The sub-techniques of an unmapped parent that D3FEND does map. A gap at the parent
        was reported as a gap in D3FEND, while T1542.004 (ROMMONkit) and T1542.005 (TFTP Boot)
        are mapped: the network-device boot persistence a T1542 finding is about. They are
        named and not joined, because a sub-technique's controls are not its parent's."""
        if "." in tid:
            return []
        return sorted(t for t in index if t.startswith(tid + ".") and index.get(t))

    below = {t: mapped_below(t) for t in techniques if not index.get(t)}
    below = {t: subs for t, subs in below.items() if subs}

    def below_text():
        return " and ".join("of {} ({})".format(t, ", ".join(subs)) for t, subs in below.items())
    if not picked:
        return ["COUNTERMEASURES: none - D3FEND {} maps no countermeasure to {}, even through "
                "a revoked predecessor. That is a gap in D3FEND coverage at the ids cited, not "
                "an absence of anything to do.{}".format(
                    (d3fend or {}).get("version") or "?", ", ".join(techniques),
                    " D3FEND does map sub-techniques {}, which this finding does not cite; "
                    "they are not joined, because a sub-technique's controls are not its "
                    "parent's.".format(below_text()) if below else "")]

    shown_by = collections.Counter((table.get(c) or {}).get("tactic") or "-" for c in chosen)
    contributors = [t for t in techniques if any(owner[c] == t for c in chosen)]
    also = [t for t in techniques if t not in contributors and any(owner[c] == t for c in picked)]
    shared = [t for t in techniques if t not in contributors and t not in also and index.get(t)]
    unmapped = [t for t in techniques if not index.get(t)]
    grade = selection.grade

    def label(tid):
        if tid in via:
            return "{} (via revoked {}: D3FEND {} maps the revoked id, not its " \
                "replacement)".format(tid, ", ".join(via[tid]), (d3fend or {}).get("version") or "?")
        return tid

    out = ["COUNTERMEASURES: {} shown of {} ({}), ordered {} and by fit in each: D3FEND's "
           "direct mappings first, then the control more cited techniques reach, then one acting "
           "on the artefact before one acting on the whole host ({} of the {} shown are direct, "
           "as are {} of the {} reached), from {}{}{}{}".format(
               len(chosen), len(picked),
               ", ".join("{} {}/{}".format(name, shown_by.get(name, 0), count)
                         for name, count in selection.available.items()),
               "-".join(tactics).lower(),
               sum(1 for c in chosen if grade[c] == "direct"), len(chosen),
               sum(1 for c in picked if grade[c] == "direct"), len(picked),
               ", ".join(label(t) for t in contributors),
               "; also mapped: {}".format(", ".join(label(t) for t in also)) if also else "",
               "; every control also reached above: {}".format(", ".join(label(t) for t in shared))
               if shared else "",
               "; not mapped by D3FEND {}: {}".format((d3fend or {}).get("version") or "?",
                                                      ", ".join(
                   "{} (its sub-techniques {} are mapped, and not joined)".format(
                       t, ", ".join(below[t])) if t in below else t for t in unmapped))
               if unmapped else "")]
    body = indent + "    "
    for cid in chosen:
        entry = table.get(cid) or {}
        out.append("{}- {} | {} | {} | {}".format(
            indent, cid, entry.get("tactic") or "-", entry.get("name"),
            "direct" if grade[cid] == "direct" else "inferred-" + grade[cid]))
        if entry.get("definition"):
            out.append(wrap(entry["definition"], indent=body))
        if entry.get("url"):
            out.append("{}{}".format(body, entry["url"]))
    if not_shown:
        out.append("{}NOT_SHOWN: {}".format(indent, ", ".join(not_shown)))
    return out


def emit(record, how, pattern, index, total, band, basis, have,
         verdict="unassessed", why="caller declared no coverage inventory", d3fend=None,
         doctrine=None, locus="UNDERIVABLE", span=(), locus_basis="tier=none",
         today=None, match_tier="summary", how_index=None, match_sentence=None,
         rank_no=None, slot="natural", unassessed=NO_INVENTORY):
    lines = []
    A = lines.append
    where = record.get("where") or {}
    who = record.get("who") or {}
    what = record.get("what") or {}
    restricted = where.get("disclosure") != "public"

    # The delimiter counts positions in the shown set; RANK is the finding's place in the whole
    # ORDERING order, which is the number every header bullet cites. They were the same number
    # until a reserved slot printed "RANK: 12" under a header that called it rank 78, and
    # nothing in the block said it had been reserved. RANK now gaps where the quota skipped,
    # and SLOT says why the finding is in the shown set.
    A("=== FINDING {} OF {} ===".format(index, total))
    A("RANK: {}".format(rank_no if rank_no is not None else index))
    A("SLOT: {}".format(slot))
    A("PRIORITY: {}".format(band))
    A("PRIORITY_BASIS: {}".format(basis))
    A("RECORD_ID: {}".format(record.get("id")))
    # The pattern id is the corpus's stable handle for a detection, and it was missing:
    # a consumer could read the logic but had no identifier to cite back or to ask for
    # again by name. The record id alone is not enough, because one record cites several.
    A("PATTERN_ID: {}".format((how or {}).get("pattern_id") or (pattern or {}).get("id") or "-"))
    # PATTERN_ID is a handle for the detection, not for the finding: one record can cite
    # one pattern from two blocks. This is the key that is unique, and the one the header's
    # LOCUS_DISPLACED and LOCUS_RESERVED bullets name.
    A("FINDING_KEY: {}".format(finding_key(record, how_index) if how_index is not None
                               else "-"))
    A(status_line(record, how_index))
    A("SOURCE_DISCLOSURE: {}".format("RESTRICTED - cite title only, no URL, no further detail"
                                     if restricted else "public"))
    # Corroboration was in the schema from early on and read by nothing, so a second or
    # third independent account of the same mechanism changed no output anywhere. It is
    # printed here rather than only stored because it answers the question a consumer
    # actually has about a single-source finding, and because on a RESTRICTED record it is
    # the only citable route to the material -- these URLs are public by definition, which
    # is why the restriction above does not suppress them.
    corroborations = (record.get("where") or {}).get("corroborations") or []
    if corroborations:
        A("CORROBORATION: {} independent account(s): {}".format(
            len(corroborations),
            "; ".join("{} ({})".format(c.get("publisher") or "-", c.get("url") or "-")
                      for c in corroborations)))
    else:
        A("CORROBORATION: none - single source, weigh it accordingly")
    A(support(record, today or datetime.date.today()))
    # Say how this record reached the answer. A finding that arrived because a word
    # appears in its prose may be about something else entirely, and until 0.22.0 it
    # was indistinguishable in the output from one that named the technology. MATCH_TIER is
    # the machine-readable half, one of Q.TIER_ORDER; until 0.43.0 a class analogue and a
    # record naming the product shared one tier and one sentence, "named this technology".
    A("MATCH_TIER: {}".format(match_tier))
    A("MATCH_BASIS: {}".format(match_sentence or match_text(match_tier, ())))
    A("TECHNOLOGY: {} / {}".format(who.get("vendor") or "-", "; ".join(who.get("products") or []) or "-"))
    A("PRODUCT_CLASS: {}".format(", ".join(who.get("product_class") or []) or "-"))
    # LOCUS_SPAN always carries the primary, so a consumer splitting on ", " gets a list
    # of one to three in every case rather than shapes to handle. It is never "-". The second
    # value is the record's own, and the one emit_xql.py prints; a class the question
    # resolved can only add a value after it (placed()).
    A("LOCUS: {}".format(locus))
    A("LOCUS_SPAN: {}".format(span_text(locus, span)))
    A("LOCUS_BASIS: {}".format(locus_basis))
    # Always a cited record: a finding is one how-block. The library-pattern branch this line
    # had could never fire, because findings were only ever built from how-blocks, and rule 6
    # described it until 0.43.0; library patterns are the LIBRARY blocks now. The key stays,
    # with its one value, so the finding key set does not move.
    A("DERIVATION: cited record")
    A("ATTACK: {}".format(", ".join((how or {}).get("technique") or (pattern or {}).get("technique") or []) or "-"))
    A("RULE_SHAPE: {}".format((how or {}).get("rule_shape") or (pattern or {}).get("rule_shape") or "-"))
    A("FIDELITY: {}".format((how or {}).get("fidelity") or (pattern or {}).get("fidelity") or "-"))
    A("IDENTIFIERS: {}".format(", ".join(what.get("vulnerabilities") or []) or "none"))
    A("COVERAGE: {}".format(verdict.upper()))
    A("COVERAGE_BASIS: {}".format(why))
    A("")

    A("ACTION:")
    shape = (how or {}).get("rule_shape") or (pattern or {}).get("rule_shape") or "single_event"
    verb = {"inventory": "Build a reconciliation, not an alert:",
            "absence": "Detect on what is missing, not on what appears:",
            "threshold": "Build a threshold rule:",
            "sequence": "Build an ordered-sequence rule:",
            "correlation": "Build a correlation rule:",
            "single_event": "Build a single-event rule:"}.get(shape, "Build a rule:")
    A(wrap("{} {}".format(verb, (pattern or {}).get("name") or record.get("id"))))
    A("")

    A("RATIONALE:")
    A(wrap(what.get("summary") or (pattern or {}).get("description")))
    A("")

    A("DETECTION_LOGIC:")
    A(wrap((how or {}).get("logic") or (pattern or {}).get("logic")))
    A("")

    markers, combine = markers_of(how, pattern)
    A("MARKERS: {}".format(len(markers)))
    for marker in markers:
        A(marker_line(marker, combine))
    if not markers:
        A("  (none - see METHODOLOGY)")
    A("")

    needed = sorted(set((how or {}).get("evidence_type") or (pattern or {}).get("evidence_type") or []))
    A("TELEMETRY_REQUIRED:")
    for item in needed:
        A("  - {}".format(item))
    if not needed:
        A("  - (not stated)")
    A("")

    gaps = [item for item in needed if have is not None and item not in have]
    A("DATA_GAP: {}".format(len(gaps) if have is not None else unassessed))
    for item in gaps:
        A("  - MISSING: {}".format(item))
        A("    RECOMMEND_ACQUIRE: {}".format(CONNECTOR.get(item, "a feed supplying " + item)))
    if have is not None and not gaps:
        A("  (none - every required telemetry type is declared as collected)")
    A("")

    A("CAVEAT_VERBATIM:")
    caveat = (how or {}).get("caveat") or (pattern or {}).get("caveat")
    A(wrap(caveat) if caveat else "  (none recorded on this item)")
    A("")

    for line in countermeasures(how, pattern, d3fend):
        A(line)
    A("")

    # Unconditional, on the same rule as COUNTERMEASURES: the key set must not vary
    # between findings. Six of the twelve doctrine rules are always-on, so this block
    # is non-empty for every record in the shipped corpus and the gap line fires only
    # if the reference file goes missing -- which is exactly when a silently absent
    # key would be hardest to notice.
    lines_doctrine = doctrine_for((record.get("who") or {}).get("product_class"),
                                  (record.get("what") or {}).get("impact"), doctrine)
    for line in (lines_doctrine or
                 ["RESPONSE_DOCTRINE: UNASSESSED - corpus/reference/response-doctrine.json "
                  "is absent or empty; no sequencing rule could be matched"]):
        A(line)
    A("")

    A("REFERENCES:")
    for line in references(record, how, pattern):
        A(line)
    A("")

    A("METHODOLOGY:")
    if markers:
        A(wrap("Markers above are the specifics. Generic markers come from the pattern and "
               "source-specific literals from the record; they are supplied unmerged so the "
               "rule author decides which to bind. Run scripts/emit_xql.py {} for the full "
               "typed handoff including ATT&CK log-source context.".format(record.get("id"))))
    else:
        A(wrap("No markers are recorded, so treat this as a scoping question rather than a "
               "rule. Establish the population first (which assets run this, which are "
               "reachable, which are current), then measure the normal rate of the behaviour "
               "described in DETECTION_LOGIC before setting any threshold. Where the logic "
               "names a comparison, the comparison is the deliverable, not an alert."))
    A("=== END FINDING {} ===".format(index))
    return "\n".join(lines)


# --- the separate blocks ------------------------------------------------------------------
#
# Exposures and library patterns follow the findings in blocks of their own, with a header
# group each, and are never merged into FINDINGS. Neither can be scored against a finding: an
# exposure carries no detection logic, and a library pattern no date, no citation and no
# identifier. Every key in either block is prefixed, EXPOSURE_ or LIBRARY_, so no key collides
# with a finding's (LOCUS, RECORD_ID, PATTERN_ID, PRIORITY_BASIS) for a consumer scanning the
# whole output, and each block's key set is fixed whether or not a field is empty.

def kev_snapshot(records):
    """The newest CISA KEV delta the corpus's catalogue records were generated from, or None."""
    found = [(record.get("where") or {}).get("source_id") or "" for record in records
             if Q.KEV_TAG in (record.get("tags") or [])]
    found = [source for source in found if source.startswith("src-cisa-kev-")]
    return max(found) if found else None


def data_gap_lines(needed, have, key, unassessed=NO_INVENTORY):
    """A DATA_GAP line and its MISSING / RECOMMEND_ACQUIRE bullets, under `key`."""
    gaps = [item for item in needed if have is not None and item not in have]
    out = ["{}: {}".format(key, len(gaps) if have is not None else unassessed)]
    for item in gaps:
        out.append("  - MISSING: {}".format(item))
        out.append("    RECOMMEND_ACQUIRE: {}".format(CONNECTOR.get(item, "a feed supplying " + item)))
    if have is not None and not gaps:
        out.append("  (none - every required telemetry type is declared as collected)")
    return out


def exposure_header(listing, shown, locus_of, locus_order, records, kev_ids, have,
                    unassessed=NO_INVENTORY, span_of=None):
    """The EXPOSURE header group. Every count but `shown` is over everything listed or
    reached, before --exposure-limit, so a cap never reads as a thinner corpus.

    EXPOSURE_LOCUS_SPAN counts what the blocks print after their primary, one per exposure per
    locus (0.44.0). EXPOSURE_LOCUS alone read as though FortiGate had no management-plane
    exposure, when two of its records' identifiers name the super-admin account and the
    administrative interface and their blocks carry MANAGEMENT as the span."""
    listed = listing.listed
    total = len(listed)
    by_tier = collections.Counter(tier for tier, _ in listed)
    kinds = collections.Counter(Q.exposure_kind(record, kev_ids) for _, record in listed)
    loci = collections.Counter(locus_of[record.get("id")] for _, record in listed)
    out = ["EXPOSURES: {} shown of {} naming what was asked ({}){}".format(
        shown, total, ", ".join("{}={}".format(t, by_tier.get(t, 0)) for t in NAMING_EXPOSURE_TIERS),
        "; raise --exposure-limit for the rest" if total > shown else "")]
    out.append("EXPOSURE_KINDS: {}  (over all {}, before --exposure-limit)".format(
        ", ".join("{}={}".format(k.lower(), kinds.get(k, 0)) for k in EXPOSURE_KINDS), total))
    out.append("EXPOSURE_LOCUS: {}  (over all {}, before --exposure-limit)".format(
        ", ".join("{}={}".format(l, loci.get(l, 0)) for l in locus_order), total))
    spans = collections.Counter(value for _, record in listed
                                for value in set((span_of or {}).get(record.get("id")) or ()))
    out.append("EXPOSURE_LOCUS_SPAN: {}  (exposures carrying the locus in EXPOSURE_LOCUS_SPAN "
               "after their primary, over all {})".format(
                   ", ".join("{}={}".format(l, spans.get(l, 0)) for l in locus_order), total))
    unlisted = sum(listing.unlisted.values())
    counts = ", ".join("{}={}".format(t, n if (t != "handset" or listing.scoped) else "unassessed")
                       for t, n in listing.unlisted.items())
    out.append("EXPOSURES_NOT_LISTED: {} - {}. Reached by the question and not listed: a CVE in "
               "another vendor's product, or in the vendor's other lines when the question named "
               "a product or a class, carries no detection logic to transfer; handset counts "
               "exposures naming what was asked that are handset records, which "
               "corpus/schema/scope.json keeps out of scope{}. python3 scripts/query.py lists "
               "them all.".format(
                   unlisted, counts, "" if listing.scoped else
                   " (the file is absent, so no handset record was refused)"))
    snapshot = kev_snapshot(records)
    out.append("EXPOSURE_ORDERING: fixed, not scored. By tier (product, then vendor-class, then "
               "vendor), then kind (EXPLOITED, ADVISORY, DISCLOSED), then newest published "
               "first with the undated last, then id. EXPOSURE_KIND is computed from the "
               "identifiers against the {} the corpus's catalogue records carry (KEV snapshot "
               "{}), never from a tag, and an EXPOSURE_SUMMARY was written when the record was "
               "generated, so it can predate a later catalogue addition. --covered and "
               "--rank-by do not apply: an exposure carries no detection to cover. Exposures "
               "never take a slot in FINDINGS, never count in MATCH_TIERS, LOCUS_MATCHED, "
               "LOCUS_ELIGIBLE or LOCUS_SHOWN, and never clear LOCUS_ABSENT, whose bullets "
               "count them.".format(len(kev_ids), snapshot or "none held"))
    out.extend(data_gap_lines(EXPOSURE_TELEMETRY, have, "EXPOSURE_DATA_GAP", unassessed))
    exposures = [record for record in records if record.get("record_type") == "exposure"]
    feeds = collections.Counter()
    for record in exposures:
        tags = set(record.get("tags") or [])
        feeds[next((name for tag, name in EXPOSURE_FEEDS if tag in tags), None)] += 1
    out.append("EXPOSURE_SCOPE: the {} exposure records this corpus holds: {}{}. It is not a "
               "vulnerability feed: an identifier absent here is not an absent vulnerability, "
               "and the handset records it holds are never listed.".format(
                   len(exposures),
                   ", ".join("{} from {}".format(feeds[name], name)
                             for _, name in EXPOSURE_FEEDS if feeds[name]),
                   ", {} written by hand from joint government advisories".format(feeds[None])
                   if feeds[None] else ""))
    return out


NO_DERIVED_FROM = "no derived_from recorded"


def library_origins(pattern):
    """A pattern's derived_from entries as written, or NO_DERIVED_FROM when it has none."""
    return [str(x) for x in pattern.get("derived_from") or [] if x] or [NO_DERIVED_FROM]


def library_header(entries, shown, classes, derived, locus_of, locus_order):
    """The LIBRARY header group, counted over every pattern matched before --pattern-limit."""
    total = len(entries)
    loci = collections.Counter(locus_of[entry.pattern.get("id")] for entry in entries)
    if classes:
        matched = "matched on class {}{}".format(
            ", ".join(sorted(classes)),
            " (with the classes derived from the vendor's own records, CLASSES_FROM_VENDOR)"
            if derived else "")
    else:
        matched = "matched on class - the question resolved no class, and a library pattern " \
                  "is matched on class alone"
    # Where they came from is each pattern's own derived_from, counted here and quoted on its
    # block. This said all of them were "derived from technique space rather than from an
    # incident", and three are drawn from CISA malware analysis reports, one of them naming a
    # single vendor's appliance paths.
    origins = collections.Counter(
        source for entry in entries for source in library_origins(entry.pattern))
    out = ["LIBRARY_PATTERNS: {} shown of {} {}: patterns no record cites, with markers; each "
           "block's LIBRARY_MATCH quotes the pattern's own derived_from, over all {}: {}{}".format(
               shown, total, matched, total,
               "; ".join("{} x {}".format(n, source) for source, n in sorted(
                   origins.items(), key=lambda kv: (-kv[1], kv[0]))) or "none",
               "; raise --pattern-limit for the rest" if total > shown else "")]
    out.append("LIBRARY_LOCUS: {}  (over all {}, before --pattern-limit)".format(
        ", ".join("{}={}".format(l, loci.get(l, 0)) for l in locus_order), total))
    out.append("LIBRARY_ORDERING: fixed, not scored. A pattern whose markers are written for "
               "another platform than the one the question names comes last, then Sigma plus "
               "Splunk rules tagging a technique it cites, descending, then id. --covered, "
               "--rank-by and --role do not apply: a library pattern has no incident behind "
               "it, no date and no role. Library patterns never take a slot in FINDINGS, never "
               "count in MATCH_TIERS, LOCUS_MATCHED, LOCUS_ELIGIBLE or LOCUS_SHOWN, and never "
               "clear LOCUS_ABSENT, whose bullets count them.")
    return out


def catalogue_match_text(record, named):
    """EXPOSURE_MATCH for a catch-all catalogue entry the catalogue's descriptions place in the
    product tier: which identifiers name the product, which do not, and which this record
    does not describe. Until 0.43.0 such a record was "not the product asked about", and
    "Fortinet Multiple Products", naming FortiOS for five of its six exploited identifiers,
    sat seventh in a FortiGate answer, below a PSIRT record none of whose identifiers was
    exploited."""
    ids = list((record.get("what") or {}).get("vulnerabilities") or [])
    described = list(Q.catalogue_descriptions(record))
    hit = [identifier for _, group in named for identifier in group]
    text = ("PRODUCT - filed under {}, which names no product; the catalogue's own description "
            "names the product asked about for {} of its {} identifier(s): {}".format(
                "; ".join((record.get("who") or {}).get("products") or []) or "-",
                len(hit), len(ids), "; ".join("{} in {}".format(label, ", ".join(group))
                                              for label, group in named)))
    other = [identifier for identifier in described if identifier not in hit]
    if other:
        text += "; its description of {} does not name it".format(", ".join(other))
    unread = len(ids) - len(described)
    if unread:
        text += ("; {} {} not described in this record, so whether the catalogue names the "
                 "product for {} is not read here".format(
                     unread, "is" if unread == 1 else "are", "it" if unread == 1 else "them"))
    return text


def exposure_match_text(tier, record, resolved, refused=0):
    """The sentence after the tier on EXPOSURE_MATCH. Never "named this technology". `refused`
    counts the handset records the listing kept out, which "every exposure filed under the
    vendor is listed" would otherwise deny."""
    vendor = (Q.vendor_reason(record, resolved) or "vendor -")[len("vendor "):]
    if tier == "product":
        labels = Q.product_labels(resolved, record)
        named = [] if labels else Q.catalogue_labels(resolved, record)
        if named:
            return catalogue_match_text(record, named)
        return "PRODUCT - names the product asked about ({})".format("; ".join(labels) or "-")
    if tier == "vendor-class":
        hit = [c for c in (record.get("who") or {}).get("product_class") or []
               if c in (resolved.get("classes") or ())]
        # A class only an identifier's own text reads is named with the identifiers, because
        # the EXPOSURE_PRODUCT_CLASS line beside it does not hold it (0.44.0).
        read = {c: ids for c, ids in Q.identifier_classes(record).items()
                if c in (resolved.get("classes") or ()) and c not in hit}
        text = "VENDOR IN A CLASS ASKED ABOUT - names the vendor asked about ({}) in {}".format(
            vendor, ", ".join(hit + ["{} (by the source's own text of {}, not its product "
                                     "class)".format(c, ", ".join(ids))
                                     for c, ids in sorted(read.items())]))
        if resolved.get("products"):
            text += ", but not the product asked about ({})".format(
                ", ".join(sorted(resolved["products"])))
        return text
    # "resolved", not "named": "Apple iOS" named iOS, and the word was refused (GATED), not
    # absent.
    return ("VENDOR - names the vendor asked about ({}); the question resolved no product or "
            "class, so every exposure filed under the vendor is listed{}".format(
                vendor, " except {} handset record(s), which are refused "
                "(EXPOSURES_NOT_LISTED)".format(refused) if refused else ""))


def shown_text(rid, identifiers, shown_at, blocks_shown=None):
    """Where above a carrier of these identifiers is shown, or "" where it is not.

    A record shown whole points at its first shown finding. A campaign record's blocks each
    concern their own product (block_scope()), so it points at the first shown block whose
    own text carries one of these identifiers, and says so where none of its shown blocks
    does, rather than sending the reader to a block about another product.
    """
    if rid not in shown_at:
        return ""
    blocks = (blocks_shown or {}).get(rid)
    if not blocks:
        return " - FINDING {} above".format(shown_at[rid])
    wanted = set(identifiers)
    hit = next((index for index, ids in blocks if ids & wanted), None)
    if hit is not None:
        return " - FINDING {} above".format(hit)
    return " - its record is shown above ({}), in {} carrying none of {}".format(
        ", ".join("FINDING {}".format(index) for index, _ in blocks),
        "a block" if len(blocks) == 1 else "blocks", "them" if len(wanted) > 1 else "it")


def detection_held_text(ids, held, shown_at, blocks_shown=None):
    """EXPOSURE_DETECTION_HELD: how many of the identifiers an observation carries, each
    carrier with the identifiers it carries, and the identifiers none carries.

    A campaign record can cite a CVE as one link in a chain against another product, so the
    observation's vendor is printed beside it rather than implied. Each carrier says which
    identifiers it holds because a union overstated the one field telling a caller whether
    detection logic exists: the EPMM catalogue record named the 2023 chain's observation as
    holding its detection, and that observation carries two of the seven exploited
    identifiers; the 2025 and 2026 five are carried by nothing, which only a sentence in the
    prose summary said.
    """
    carrying = collections.OrderedDict()
    for identifier in ids:
        for pair in sorted(held.get(identifier, ())):
            carrying.setdefault(pair, []).append(identifier)
    carried = [identifier for identifier in ids if held.get(identifier)]
    if not carried:
        return ("none - no observation in this corpus carries any of these identifiers, so "
                "there is no detection logic to build from here")
    parts = ["{} of {} identifier(s) carried".format(len(carried), len(ids))]
    for (rid, vendor), identifiers in sorted(carrying.items()):
        parts.append("{} ({}) carries {}{}".format(
            rid, vendor, ", ".join(identifiers),
            shown_text(rid, identifiers, shown_at, blocks_shown)))
    uncarried = [identifier for identifier in ids if not held.get(identifier)]
    parts.append("no observation carries {}".format(", ".join(uncarried)) if uncarried
                 else "every identifier is carried")
    return "; ".join(parts)


def emit_exposure(index, total, tier, record, resolved, kev_ids, held, shown_at, locus, span,
                  locus_basis, today, blocks_shown=None, refused=0):
    """One EXPOSURE block. The key set is fixed; every key is EXPOSURE_-prefixed."""
    lines = []
    A = lines.append
    who = record.get("who") or {}
    what = record.get("what") or {}
    where = record.get("where") or {}
    tags = set(record.get("tags") or [])
    ids = list(what.get("vulnerabilities") or [])
    in_kev = [v for v in ids if v in kev_ids]
    kind = Q.exposure_kind(record, kev_ids)
    A("=== EXPOSURE {} OF {} ===".format(index, total))
    A("EXPOSURE_RANK: {}".format(index))
    A("EXPOSURE_ID: {}".format(record.get("id")))
    A("EXPOSURE_MATCH: {} - {}".format(tier, exposure_match_text(tier, record, resolved,
                                                                  refused)))
    A("EXPOSURE_KIND: {} - {} of {} identifier(s) in the CISA KEV catalogue as this corpus "
      "holds it{}".format(kind, len(in_kev), len(ids), {
          "ADVISORY": "; from a government advisory",
          "DISCLOSED": "; disclosed, with no catalogue entry here"}.get(kind, "")))
    A("EXPOSURE_ORDER_BASIS: tier={}; kind={}; published={}; then id".format(
        tier, kind, Q.held_date(record) or "undated"))
    A("EXPOSURE_LOCUS: {}".format(locus))
    A("EXPOSURE_LOCUS_SPAN: {}".format(span_text(locus, span)))
    A("EXPOSURE_LOCUS_BASIS: {}".format(locus_basis))
    A("EXPOSURE_TECHNOLOGY: {} / {}".format(who.get("vendor") or "-",
                                            "; ".join(who.get("products") or []) or "-"))
    A("EXPOSURE_PRODUCT_CLASS: {}".format(", ".join(who.get("product_class") or []) or "-"))
    # Every identifier, never truncated: a consumer checking its own estate against this list
    # needs the whole of it, and a cut list reads as a complete one.
    A("EXPOSURE_IDENTIFIERS: {}".format(", ".join(ids) or "none - the record carries affected "
                                                          "versions instead"))
    if Q.KEV_TAG in tags:
        # The catalogue's two values are Known and Unknown. A bare "no" read as a negative
        # finding for a flag the catalogue leaves open (0.43.0).
        ransomware = ("yes - the catalogue flags known ransomware use"
                      if "ransomware-linked" in tags
                      else "unknown - the catalogue does not flag known ransomware use")
    elif "ransomware-entry" in tags:
        ransomware = "yes - its source ties it to ransomware entry; not a catalogue flag"
    else:
        ransomware = "not stated - not a catalogue record"
    A("EXPOSURE_RANSOMWARE: {}".format(ransomware))
    A(status_line(record, None, "EXPOSURE_STATUS"))
    A("EXPOSURE_SOURCE_DISCLOSURE: {}".format(
        "RESTRICTED - cite title only, no URL, no further detail"
        if where.get("disclosure") != "public" else "public"))
    A("EXPOSURE_" + support(record, today or datetime.date.today()))
    A("EXPOSURE_DETECTION_HELD: {}".format(detection_held_text(ids, held, shown_at,
                                                                blocks_shown)))
    A("EXPOSURE_SUMMARY:")
    A(wrap(what.get("summary")))
    A("EXPOSURE_REFERENCES:")
    for line in references(record, None, None):
        A(line)
    A("=== END EXPOSURE {} ===".format(index))
    return "\n".join(lines)


def emit_library(index, total, entry, question_classes, derived, locus, span, locus_basis,
                 have, d3fend, doctrine, unassessed=NO_INVENTORY):
    """One LIBRARY block. The key set is fixed; every key is LIBRARY_-prefixed."""
    lines = []
    A = lines.append
    pattern = entry.pattern
    corroboration = pattern.get("external_corroboration") or {}
    sigma, splunk = corroboration.get("sigma_rules") or 0, corroboration.get("splunk_detections") or 0
    from_vendor = set(entry.hit) <= set(derived) and not set(entry.hit) & set(question_classes)
    A("=== LIBRARY {} OF {} ===".format(index, total))
    A("LIBRARY_RANK: {}".format(index))
    A("LIBRARY_PATTERN_ID: {}".format(pattern.get("id")))
    A("LIBRARY_NAME: {}".format(pattern.get("name") or "-"))
    # The origin is the pattern's own derived_from, never a template. A fixed "derived from
    # technique space rather than from an incident and is about no one product" was false for
    # pat-appliance-internal-handler-requested-directly, derived from CISA malware analysis
    # reports, whose markers are one product line's paths and whose caveat says eighteen of
    # the reports concern it, so SKILL.md's "say where they came from" was answered wrongly.
    origins = library_origins(pattern)
    A("LIBRARY_MATCH: class - applies to {} {}; no record in the corpus cites it; derived "
      "from {}".format(", ".join(entry.hit),
                       "which the vendor's own records carry (CLASSES_FROM_VENDOR)"
                       if from_vendor else "with the question",
                       "; ".join(origins) if origins != [NO_DERIVED_FROM] else
                       "nothing stated - the pattern records no derived_from, so where it came "
                       "from is not known here"))
    A("LIBRARY_ORDER_BASIS: platform_fit={} (markers written for {}); corroboration={} "
      "(Sigma {}, Splunk {}); then id".format("+1" if entry.fit > 0 else entry.fit,
                                              ", ".join(entry.platforms) or
                                              "no committed platform", entry.weight, sigma, splunk))
    A("LIBRARY_CLASSES: {}".format(", ".join(pattern.get("applies_to_classes") or []) or "-"))
    A("LIBRARY_LOCUS: {}".format(locus))
    A("LIBRARY_LOCUS_SPAN: {}".format(span_text(locus, span)))
    A("LIBRARY_LOCUS_BASIS: {}".format(locus_basis))
    A("LIBRARY_FIDELITY: {}".format(pattern.get("fidelity") or "-"))
    A("LIBRARY_RULE_SHAPE: {}".format(pattern.get("rule_shape") or "-"))
    A("LIBRARY_ATTACK: {}".format(", ".join(pattern.get("technique") or []) or "-"))
    # Two claims, kept apart as advise.py keeps them: public rules tagging a technique the
    # pattern cites, and records in this corpus that cite the pattern, of which a library
    # pattern has none by definition.
    A("LIBRARY_CORROBORATED: {}".format(
        "yes - {} Sigma, {} Splunk rule(s) tag a technique this pattern cites (matched on "
        "technique, not on detection shape)".format(sigma, splunk) if sigma or splunk
        else "no - no Sigma or Splunk rule tags a technique this pattern cites"))
    A("LIBRARY_OBSERVED: no - no record in the corpus cites this pattern")
    A("")
    A("LIBRARY_DETECTION_LOGIC:")
    A(wrap(pattern.get("logic") or pattern.get("description")))
    A("")
    markers = pattern.get("markers") or []
    A("LIBRARY_MARKERS: {}".format(len(markers)))
    for marker in markers:
        A(marker_line(marker, pattern.get("combine")))
    A("")
    needed = sorted(set(pattern.get("evidence_type") or []))
    A("LIBRARY_TELEMETRY_REQUIRED:")
    for item in needed or ["(not stated)"]:
        A("  - {}".format(item))
    A("")
    for line in data_gap_lines(needed, have, "LIBRARY_DATA_GAP", unassessed):
        A(line)
    A("")
    A("LIBRARY_CAVEAT_VERBATIM:")
    A(wrap(pattern.get("caveat")) if pattern.get("caveat") else "  (none recorded on this item)")
    A("")
    for line in countermeasures(None, pattern, d3fend):
        A(("LIBRARY_" + line) if not line.startswith(" ") else line)
    A("")
    for line in (doctrine_for(pattern.get("applies_to_classes"), None, doctrine) or
                 ["RESPONSE_DOCTRINE: UNASSESSED - corpus/reference/response-doctrine.json "
                  "is absent or empty; no sequencing rule could be matched"]):
        A(("LIBRARY_" + line) if not line.startswith(" ") else line)
    A("")
    A("LIBRARY_REFERENCES:")
    refs = []
    for tid in pattern.get("technique") or []:
        name, link = attack_url(tid)
        refs.append("  - {} | {} | {}".format(name, tid, link))
    for source in corroboration.get("sources") or []:
        refs.append("  - CORROBORATION | {} | -".format(source))
    for source in pattern.get("derived_from") or []:
        if source and source not in (corroboration.get("sources") or []):
            refs.append("  - DERIVED_FROM | {} | -".format(source))
    for line in refs or ["  (none - this pattern cites no technique and no corroboration)"]:
        A(line)
    A("=== END LIBRARY {} ===".format(index))
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Emit a consultation in the fixed advisory format.")
    ap.add_argument("question", help="technology, vendor, product class or scenario")
    ap.add_argument("--corpus", default=CORPUS)
    ap.add_argument("--have", default=None,
                    help="comma-separated evidence types the caller already collects, from "
                         "the 21 in corpus/schema/vocab.json (e.g. edr_process,auth_log); "
                         "any other value is refused and named. Omit to have every "
                         "requirement reported as unassessed")
    ap.add_argument("--covered", default=None,
                    help="what the caller already implements: ATT&CK identifiers, their own "
                         "technique names, or both, comma or newline separated. May also be "
                         "a path to a file, one entry per line, where an entry may be "
                         "'Name: description of the artefacts it produces' -- the richer "
                         "form matches far better, because comparing two labels is what "
                         "made the early verdicts weak. Enables COVERAGE on every finding.")
    ap.add_argument("--rank-by", choices=("criticality", "gap"), default="criticality",
                    help="criticality (default) answers 'what matters most about this "
                         "technology'. gap answers 'what should I build that I have not "
                         "got', by demoting what --covered says is already implemented. "
                         "Coverage never removes a finding, only demotes it.")
    ap.add_argument("--as", dest="as_class", default=None, metavar="CLASS[,CLASS...]",
                    help="Answer at class level for a product this corpus does not know by "
                         "name. 73%% of a real integration library resolves to zero records "
                         "here, and for those the class still holds findings -- this is how "
                         "you reach them. The answer is labelled as class-level throughout "
                         "and must not be passed on as product intelligence.")
    ap.add_argument("--limit", type=int, default=12,
                    help="findings to show, 1 or more (default 12)")
    ap.add_argument("--no-locus-spread", action="store_true",
                    help="disable the per-locus quota and the record cap and return pure "
                         "ORDERING order. The quota reserves slots per locus holding an "
                         "eligible finding, which displaces higher-ranked findings; every "
                         "displacement is printed either way, as is the distribution.")
    ap.add_argument("--per-locus", type=int, default=1, metavar="N",
                    help="slots reserved per locus holding an eligible finding, 1 or more "
                         "(default 1). For several findings under each plane, pass e.g. "
                         "--per-locus 3 --limit 18.")
    ap.add_argument("--role", default=None, metavar="ROLE[,ROLE...]",
                    help="keep only records whose what.role is one of these (the values in "
                         "corpus/schema/vocab.json), e.g. control_bypassed,inline_tool,"
                         "telemetry_source,lateral_path for the relationships other than "
                         "victim. what.role is one value per record, not per product or class "
                         "it names, so on a record naming several the role may be another "
                         "technology's than the one asked about. Every tally is then over the "
                         "kept records.")
    ap.add_argument("--exposure-limit", type=int, default=10, metavar="N",
                    help="EXPOSURE blocks to show, 0 or more (default 10), after the findings. "
                         "0 lists none; the header still counts every exposure naming what "
                         "was asked.")
    ap.add_argument("--pattern-limit", type=int, default=6, metavar="N",
                    help="LIBRARY blocks to show, 0 or more (default 6): patterns no record "
                         "cites, matched on class. 0 lists none; the header still counts them.")
    ap.add_argument("--today", default=None, help="ISO date, for reproducible ranking")
    args = ap.parse_args()
    refused = Q.below_floor(args, (("--limit", 1), ("--per-locus", 1), ("--exposure-limit", 0),
                                   ("--pattern-limit", 0)))
    if refused:
        print(refused, file=sys.stderr)
        return 2

    today = datetime.date.fromisoformat(args.today) if args.today else datetime.date.today()
    # Checked against vocab.json's evidence types, so an ATT&CK id or a typo is refused by
    # name rather than turning every DATA_GAP into MISSING; see parse_have.
    have, have_rejected = parse_have(args.have, load_vocab(args.corpus), "--covered")
    for value, why in have_rejected:
        print("WARNING: --have value refused: {} ({})".format(value, why), file=sys.stderr)
    unassessed = REJECTED_INVENTORY if have_rejected and have is None else NO_INVENTORY
    covered_raw = args.covered
    if covered_raw is not None and os.path.isfile(covered_raw):
        with open(covered_raw, "r", encoding="utf-8") as handle:
            covered_raw = handle.read()
    elif covered_raw is not None and _looks_like_a_path(covered_raw):
        # A mistyped path used to be accepted as literal coverage TEXT: the run exited 0 and
        # reported one named item, which is the filename, and a coverage tally computed against
        # nothing. A wrong answer that looks like a right one is worse than an error, so a
        # value shaped like a path has to be a path.
        print("ERROR: --covered looks like a file path and no such file exists: {}\n"
              "       Pass an existing file, or a comma-separated list with no path separators."
              .format(covered_raw), file=sys.stderr)
        return 2
    covered = parse_covered(covered_raw) if covered_raw is not None else None
    if args.rank_by == "gap" and covered is None:
        print("ERROR: --rank-by gap requires --covered, otherwise nothing is known to "
              "be covered and the ordering is identical to criticality.", file=sys.stderr)
        return 2

    with open(os.path.join(args.corpus, "schema", "aliases.json"), "r", encoding="utf-8") as handle:
        aliases = Q.normalise_alias_keys(json.load(handle))
    records, patterns = Q.load_corpus(args.corpus)
    d3fend = load_d3fend(args.corpus)
    doctrine = load_doctrine(args.corpus)
    locus_map = load_locus_map(args.corpus)
    vocab = load_vocab(args.corpus)
    resolved = Q.resolve(args.question, aliases)

    # A declared class is added to whatever resolved naturally rather than replacing it,
    # so "--as app.ai_platform" on a question that also names a vendor narrows instead of
    # discarding. Validated against the vocabulary because a silently-ignored typo would
    # produce an empty answer indistinguishable from a genuine one.
    declared_classes = []
    if args.as_class:
        known = set((vocab.get("product_class") or {}))
        for value in [c.strip() for c in args.as_class.split(",") if c.strip()]:
            if value not in known:
                print("ERROR: --as {!r} is not a product_class in this corpus's "
                      "vocabulary.".format(value), file=sys.stderr)
                near = [k for k in sorted(known) if value.split(".")[0] in k]
                if near:
                    print("       closest by prefix: {}".format(", ".join(near[:8])),
                          file=sys.stderr)
                return 2
            declared_classes.append(value)
        resolved["classes"] = set(resolved.get("classes") or set()) | set(declared_classes)

    # Rule 9 asks for the relationships other than victim, and until 0.43.0 no flag here
    # reached them: the only route was --limit 500 and filtering by hand, which the block
    # contract forbids. Checked against the vocabulary, because a typo would filter to nothing
    # and read as a corpus with nothing to say.
    roles = []
    if args.role is not None:
        known = set(vocab.get("role") or {})
        roles = [r.strip() for r in args.role.split(",") if r.strip()]
        unknown = [r for r in roles if r not in known]
        if unknown or not roles:
            # The values that failed, not the whole argument: "--role 'victim,nonsense' is not
            # a what.role" named a valid role among the refused.
            bad = ",".join(unknown) if unknown else args.role
            print("ERROR: --role {!r} is not a what.role in this corpus's vocabulary{}. Known "
                  "values: {}".format(bad, " (in {!r})".format(args.role) if bad != args.role
                                      else "", ", ".join(sorted(known))), file=sys.stderr)
            return 2


    rarity = build_rarity(patterns)
    citations = {}
    for record in records:
        for how in record.get("how") or []:
            if how.get("pattern_id"):
                citations[how["pattern_id"]] = citations.get(how["pattern_id"], 0) + 1

    # A vendor alias carries no class, so "Fortinet" resolved a vendor and nothing else, and
    # the class analogues the Scope section promises never reached a vendor-only question:
    # four or five loci came back absent for Cisco, Fortinet, Citrix and Siemens. The classes
    # are derived from the vendor's own records and used for scoring only. RESOLVED_TO, the
    # match tiers, the exposure tiers and the span still read what the question named, so the
    # vendor's own findings stay `vendor` and lead, and the analogues arrive as `class`.
    derived_classes = []
    if resolved.get("vendors") and not resolved.get("products") \
            and not resolved.get("classes"):
        derived_classes = classes_from_vendor(records, resolved, patterns,
                                              locus_map.get("nonproduct_class") or ())
    scoring = resolved
    if derived_classes:
        scoring = dict(resolved, classes=set(derived_classes))

    findings = []
    # The platform the question names, from the curated platform_of table, which orders the
    # findings, the library and query.py's listing alike.
    wanted_platforms = Q.question_platforms(resolved, aliases)
    # Every word of the question a record's reasons show it reached or refined. What is left
    # reached no record at all, which is what an unknown product name padded with ordinary
    # words looks like: "Zorblax Edge Gateway 9000" was answered as a confident mechanism
    # answer about other vendors' edge devices, reached by "edge" and "gateway" alone.
    reached = set()
    # The records a finding would come from, before and after --role: the ROLE_FILTER line
    # states both, so a filtered answer never reads as the whole one.
    role_matched, role_kept = collections.Counter(), 0
    dropped = []
    # What each exposure was reached on, for EXPOSURES_NOT_LISTED's prose-only count. The
    # tier itself reads what the question named, never the derived classes.
    exposure_reasons = {}
    # Which identifiers the exposure records hold as the asked product's own, and who holds
    # every other, for block_scope(): a campaign record's block concerns the product it
    # names only where the block itself says so.
    owners = identifier_owners(records, resolved)
    for record in records:
        hit, why_matched = Q.score(record, scoring, patterns)
        if not hit:
            continue
        if record.get("record_type") == "exposure":
            exposure_reasons[record.get("id")] = why_matched
        # Every word a record reached counts, whatever its role: UNMATCHED_TERMS says a word
        # reached nothing in the corpus, and a filter does not make that true.
        reached |= reached_terms(why_matched)
        if roles and record.get("how"):
            role_matched[(record.get("what") or {}).get("role") or "-"] += 1
            if (record.get("what") or {}).get("role") not in roles:
                dropped.append((record, why_matched))
                continue
            role_kept += 1
        # The tier reads what the question named, never the derived classes. It is the
        # record's, except for a campaign record's block concerning another product.
        record_tier, record_weight = match_basis(why_matched, resolved)
        refined = refined_by(why_matched)
        sector = sector_reason(why_matched)
        for how_index, how in enumerate(record.get("how") or []):
            pattern = patterns.get(how.get("pattern_id"))
            tier, tier_weight, scope = block_tier(record_tier, record_weight, why_matched,
                                                  record, how, resolved, aliases, owners,
                                                  pattern)
            verdict, why = coverage(record, how, pattern, covered, rarity)
            group, group_label = match_group(tier, verdict, args.rank_by)
            # The platform the block's markers are written for, from the markers it renders,
            # against the platform the question names. query.py and the LIBRARY block already
            # order by it; the findings did not, so "Linux kernel" led with a Chrome record's
            # Windows extension-persistence and DLL search-order blocks.
            platforms = finding_platforms(how, pattern)
            fit = Q.platform_fit(platforms, wanted_platforms)
            weight, band, basis, crit = rank(
                record, how, citations.get(how.get("pattern_id"), 1), today, verdict,
                args.rank_by, tier_weight, tier, refined, group_label, sector,
                platform_text(fit, platforms, wanted_platforms))
            # The question's classes reach the span only, and only after the record's own.
            # A firewall question still sees the KEV-harvest record's LOCUS as DATA, the plane
            # its first-listed web server puts it on, keeps the ORGANISATION its evidence adds,
            # and learns from LOCUS_SPAN's last value that the record also sits on CONTROL.
            locus, span, locus_basis = placed(record, how, pattern, locus_map,
                                              resolved.get("classes"))
            findings.append(Finding(weight, record, how, pattern, band, basis, verdict, why,
                                    locus, span, locus_basis, how_index, tier, refined,
                                    group, sector, crit, tuple(why_matched), fit, scope))

    # Grouped by MATCH_TIER first, then within a group by the sector the question named, the
    # question's leftover words the record carries, the platform fit, and the weight. The sort
    # key runs all the way to the how-index: score and record id alone collide eleven times in
    # a single Cisco query, and the quota below picks "the first finding of each locus" off
    # this order, so it has to be stated rather than inherited. The fit is a key and not a
    # weight, as in query.py: a block written for another platform sinks below every neutral
    # or fitting one in its group, and never below a weaker group.
    subject = question_subject(findings, resolved)
    # Inside group 0, a vendor-tier finding the subject leaves out follows the findings naming
    # what was asked (follows_subject()), and PRIORITY_BASIS says so, so the order can be read
    # back from every block.
    def after_subject(finding):
        label = "({})".format(match_group(finding.match_basis, finding.verdict,
                                          args.rank_by)[1])
        return finding._replace(basis=finding.basis.replace(
            label, label[:-1] + ", after what was asked)", 1))
    findings = [after_subject(f) if follows_subject(f, subject) else f for f in findings]
    findings.sort(key=lambda f: (f.group, follows_subject(f, subject), f.sector is None,
                                 -len(f.refined), -f.fit, -f.weight, f.record.get("id"),
                                 (f.how or {}).get("pattern_id") or "", f.how_index))
    # Tallied before truncation. Counting only the findings that survived --limit would
    # report the coverage of the output rather than of the match set, which is the
    # opposite of what a reader checking for over-suppression needs to see.
    tally, matched = {}, len(findings)
    tier_tally = {}
    for f in findings:
        tally[f.verdict] = tally.get(f.verdict, 0) + 1
        tier_tally[f.match_basis] = tier_tally.get(f.match_basis, 0) + 1
    # After the tally, not before it: the mode depends on how the findings were reached, and
    # on whether any exposure record names the technology, so it cannot be decided from the
    # resolved names alone.
    # The listing and the mode read one set, so the handset refusal applies to both.
    scope = load_scope(args.corpus)
    kev_ids = Q.kev_identifiers(records)
    listing = exposure_listing(records, resolved, scope, kev_ids, exposure_reasons)
    named_exposures = listing.listed
    # A handset name no alias accounts for: "iPhone" reaches no record, and was told to add one.
    # beside_handset is that name wherever it stands, which "Apple iOS" reads to point at the
    # management plane; handset_terms is it in a question nothing else resolved, the question
    # the refusal is for. A name beside it that reached nothing ("Kandji for iOS") may be the
    # product managing the devices, which is in scope, or something on the handset ("Pegasus",
    # "iMessage"), which is not; the word cannot say which, so the refusal still stands and
    # names it as the one word that would move the question. Once it stopped the refusal, and
    # any word that reached nothing did: "iOS spyware" was told to add spyware as an alias.
    beside_handset = handset_words(resolved, scope)
    handset_terms = handset_names(resolved, scope)
    unknown = unknown_names(resolved, set(resolved.get("terms") or ()) - reached, scope,
                            args.question) if beside_handset else []
    # --role filters exposure records too. Each carries a what.role, and a RESOLUTION marked as
    # over the kept records only counted "4 exposure records" for "Palo Alto firewall" --role
    # telemetry_source that the filter had never looked at. Every exposure tally is then over
    # the kept records, as every finding tally is.
    all_exposures = named_exposures
    if roles:
        listing = exposure_listing(records, resolved, scope, kev_ids, exposure_reasons,
                                   keep=lambda r: (r.get("what") or {}).get("role") in roles)
        named_exposures = listing.listed
    # Decided on the scoring view, whose classes include any derived from the vendor's own
    # records. Unfiltered that changes nothing, because the records the classes came from name
    # the vendor and make the answer `product` first; but once --role keeps only the class
    # analogues of "Fortinet", the answer is class-level, and read against the question's own
    # empty class list it fell through to UNRESOLVED over the findings it had.
    counts = mode_counts(findings, len(named_exposures))
    # Emptied only when the filter kept no finding and no exposure: exposures it kept are an
    # answer, listed in their own blocks.
    role_emptied = bool(roles and not findings and not named_exposures
                        and (dropped or all_exposures))
    if role_emptied:
        # Nothing survived the filter, so there is no answer to describe; the mode says what the
        # corpus holds before it, and the NO_FINDINGS line below says the filter is why none is
        # shown.
        named_exposures = all_exposures
        counts = collections.Counter(named_exposures=len(named_exposures))
        taken = set()
        for record, why_matched in dropped:
            record_tier, record_weight = match_basis(why_matched, resolved)
            for how in record.get("how") or []:
                tier, _, block = block_tier(record_tier, record_weight, why_matched, record,
                                            how, resolved, aliases, owners,
                                            patterns.get(how.get("pattern_id")))
                counts[tier.replace("-", "_") if tier in SUBJECT_TIERS else "loose"] += 1
                if block is not None and not block.concerns:
                    taken.add(record.get("id"))
        counts["campaign_taken"] = len(taken)
    mode = resolution_mode(scoring, declared_classes, counts)
    locus_order = (locus_map.get("locus_order")
                   or sorted({f.locus for f in findings}))
    quota = apply_locus_quota(findings, args.limit, locus_order,
                              spread=not args.no_locus_spread, per_locus=args.per_locus,
                              naming=reserve_from_naming(findings, resolved, subject),
                              subject=subject)

    # The separate blocks, placed before the header is printed so that an absent locus's
    # bullet can count them. Each is placed with the question's classes as a span source
    # only, as a finding is. The library is matched on the scoring view's classes: a
    # vendor-only question reaches the class analogues through the classes derived from the
    # vendor's own records, and the library patterns of those classes are analogues as well.
    question_classes = resolved.get("classes") or set()
    exposure_placed = {record.get("id"): placed(record, None, None, locus_map,
                                                question_classes)
                       for _, record in named_exposures}
    library = library_listing(records, patterns, set(scoring.get("classes") or ()),
                              wanted_platforms)
    library_placed = {entry.pattern.get("id"): placed(None, None, entry.pattern, locus_map,
                                                      question_classes)
                      for entry in library}
    exposure_loci = collections.Counter(p[0] for p in exposure_placed.values())
    library_loci = collections.Counter(p[0] for p in library_placed.values())
    shown_exposures = named_exposures[:args.exposure_limit]
    shown_library = library[:args.pattern_limit]

    print("=== CONSULTATION ===")
    print("QUESTION: {}".format(args.question))
    def show(key):
        return ", ".join(sorted(resolved.get(key) or [])) or "-"
    # The sectors are printed because they order findings within a group: a named sector puts
    # the records seen in it first. They were resolved and applied before 0.43.0 and never
    # shown, and applied to nothing but query.py's scores.
    print("RESOLVED_TO: vendors={} | products={} | classes={} | sectors={}".format(
        show("vendors"), show("products"), show("classes"), show("sectors")))
    # Which words produced that line, so it can be read against the question: "check the
    # RESOLVED_TO against your own words" cannot be carried out when nothing ties Check Point
    # to the word "quantum" that produced it. Its own line, so RESOLVED_TO keeps its shape.
    print("RESOLVED_BY: {}".format("; ".join(sorted(resolved.get("resolved_by") or []))
                                   or "nothing - no alias matched"))
    if resolved.get("gated"):
        # Every alias that matched the words and was refused. A refusal that prints nothing
        # reads as though the word was never seen, and "Ivanti EPMM and Sentry" lost Sentry
        # silently. Printed only when there is one, and only for words nothing else claimed.
        print("GATED: {} - matched an alias but not admitted, because the word is ordinary as "
              "well as a name. Name the technology if one of these is what you meant.".format(
                  "; ".join(sorted(resolved["gated"]))))
    if resolved.get("vendors") and not resolved.get("products") \
            and not resolved.get("classes"):
        # Printed for every vendor-only question, so a consumer can see the fallback was tried
        # when it derived nothing.
        print("CLASSES_FROM_VENDOR: {}".format(
            "{} - derived from the vendor's own records; class matches below are analogues"
            .format(", ".join(derived_classes)) if derived_classes else
            "none - no observation filed under the vendor carries a product class to answer "
            "at"))
    print("CORPUS: {} records, {} patterns".format(len(records), len(patterns)))
    scope = ""
    if roles:
        # Before RESOLUTION, because RESOLUTION and every tally after it are then about the kept
        # records: a filtered answer that did not say so would read as the corpus's whole one.
        matched_records = sum(role_matched.values())
        kept_exposures = sum(1 for _, record in all_exposures
                             if (record.get("what") or {}).get("role") in roles)
        # What is filtered is the record's one what.role. Said here because the help, the
        # reference and the CHANGELOG said "records where the technology played the roles
        # named", and two of the seven records "Palo Alto firewall" kept as control_bypassed
        # say in their own summaries that no actor was found and that the perimeter held.
        # Each role asked for is counted, 0 included: a role that matched nothing showed only
        # by its absence from the matched records' tally.
        print("ROLE_FILTER: {} - {} of {} matched observation records kept (their roles: {}; "
              "asked for: {}); "
              "{} of {} exposure records naming it kept; each record carries one what.role, "
              "not one per product or class it names, so on a record naming several the role "
              "kept may be another technology's; {}".format(
                  ", ".join(roles), role_kept, matched_records,
                  ", ".join("{} {}".format(r, n) for r, n in sorted(
                      role_matched.items(), key=lambda kv: (-kv[1], kv[0]))) or "none",
                  ", ".join("{} {}".format(r, role_matched.get(r, 0)) for r in roles),
                  kept_exposures, len(all_exposures),
                  "RESOLUTION below describes the records matched before the filter, and no "
                  "finding is shown" if role_emptied else
                  "RESOLUTION, FINDINGS and every tally below describe the kept records only"))
        scope = (" [before --role {}, which kept no finding]" if role_emptied else
                 " [--role {}: over the kept records only]").format(",".join(roles))
    # The mode is stated on its own line and never left to be inferred from RESOLVED_TO,
    # because the difference between "this product was attacked" and "products of this
    # kind are attacked" is the difference between intelligence and analogy, and a
    # consumer building detection content from this block has to know which it holds.
    # A name can resolve and still reach nothing: the alias exists and no observation is filed
    # under it. "nothing in this question matched a vendor" printed under a RESOLVED_TO naming
    # one for 230 of 1,396 vendor and product questions measured, 31 of them new once 0.43.0
    # stopped searching the words a name had resolved.
    named_only = ", ".join(sorted((resolved.get("vendors") or set())
                                  | (resolved.get("products") or set())))
    # The observation records --role dropped that name what was asked, in the tier the mode
    # reads as naming it (the product's, where a product was named). Counted only where the
    # filter kept something and the mode says nothing names it.
    naming_tiers = ("product",) if resolved.get("products") else NAMING_TIERS
    role_dropped = 0 if role_emptied or mode == "product" else sum(
        1 for _, why_matched in dropped if match_basis(why_matched, resolved)[0] in naming_tiers)
    line, warning = resolution_text(mode, resolved, declared_classes, named_exposures,
                                    below="matched before --role" if role_emptied else "below",
                                    refused=len(listing.handset),
                                    campaign=counts.get("campaign_taken", 0),
                                    dropped=role_dropped, handset=handset_terms,
                                    prose=listing.unlisted["prose-only"],
                                    beside=beside_handset, unknown=unknown)
    exposure_lines = exposure_header(listing, len(shown_exposures),
                                     {rid: placed[0] for rid, placed in exposure_placed.items()},
                                     locus_order, records, kev_ids, have, unassessed,
                                     {rid: placed[1] for rid, placed in exposure_placed.items()})
    print("RESOLUTION: {}{}".format(line, scope))
    if warning:
        print("CLASS_LEVEL_WARNING: {}{}".format(warning, scope))
    unmatched = sorted(set(resolved.get("terms") or ()) - reached)
    print("UNMATCHED_TERMS: {}".format(", ".join(unmatched) or "none"))
    proper = sorted(proper_terms(args.question, set(unmatched)))
    if mode == "mechanism" and proper:
        # A mechanism answer is the right answer to "phishing". It is the wrong one to a product
        # name the corpus does not know, and the only difference on screen is that the name's
        # own words reached nothing. Only words written with a capital or a digit are named,
        # because an ordinary word that reached nothing says nothing about the question.
        print("MECHANISM_WARNING: {} reached no record at all. If {} the name of what you run, "
              "the corpus does not know it and no finding below is about it: each was reached "
              "by the other words only. Re-ask with --as, naming every class it behaves as."
              .format(", ".join(proper), "that is" if len(proper) == 1 else "those are"))
        print("CANDIDATE_CLASSES: {}".format(
            ", ".join(suggest_classes(args.question, vocab, aliases))
            or "none - the question shares no wording with any class description"))
    if role_emptied:
        # The filter is why nothing is shown, and the re-ask advice below would send the caller
        # to name a class for a technology the corpus does hold observations about.
        before = sum(len(r.get("how") or []) for r, _ in dropped)
        print("FINDINGS: 0 shown of 0 matched [--role {}: over the kept records only; {} "
              "matched before it]".format(",".join(roles), before))
        print("NO_FINDINGS: {} finding(s) matched before --role, none from a record whose "
              "what.role is {}{}. Drop --role, or pass one of the roles ROLE_FILTER lists."
              .format(before, " or ".join(roles),
                      ", and it kept {} of the {} exposure record(s) naming it".format(
                          kept_exposures, len(all_exposures))
                      if all_exposures and not before else ""))
        return 1
    if mode == "unresolved":
        if sum(listing.unlisted.values()):
            # The exposures the question reached are still counted, so "no exposure names it"
            # is read beside what did reach it and why it is not listed.
            for text in exposure_lines:
                if text.startswith("EXPOSURES_NOT_LISTED:"):
                    print(text)
        print("FINDINGS: 0 shown of 0 matched")
        print("")
        if handset_terms:
            # A handset name in a question nothing else resolved. The re-ask block below offers
            # every class, endpoint.os among them, and asks for every class the technology
            # behaves as: the handset plane the scope decision keeps out.
            found = handset_text(handset_terms, len(listing.handset),
                                 "in corpus/schema/scope.json")
            # Bare "IOS" is Cisco's spelling too, and GATED offered Cisco IOS above a refusal
            # that named only the handset.
            also = "".join(" {} is also the alias of {}, refused as GATED says: if that is what "
                           "you meant, ask \"{}\".".format(word, meaning, meaning)
                           for word, meaning in handset_meanings(resolved, aliases,
                                                                 handset_terms))
            if unknown:
                one = len(unknown) == 1
                print("=== THE QUESTION NAMES A HANDSET, BESIDE A NAME THIS CORPUS DOES NOT "
                      "KNOW ===")
                print("{}; {} reached no record. This corpus holds handset records and does not "
                      "advise on handsets; python3 scripts/query.py lists them. A handset name "
                      "is never an alias to add. Which plane the question is on turns on {}, "
                      "and the {} cannot say: if {} the product that enrols and manages these "
                      "devices, the question is on the mobile management plane, which is in "
                      "scope, and the name is a gap in corpus/schema/aliases.json: add its "
                      "vendor and product with class app.mdm and re-run, or re-ask with --as "
                      "app.mdm. If {} something on the handset, an app, a feature or spyware, "
                      "the question is a handset question, and nothing is to be added.{}"
                      .format(found, ", ".join(unknown), ", ".join(unknown),
                              "word" if one else "words", "it names" if one else "they name",
                              "it names" if one else "they name", also))
            else:
                print("=== THE ONLY NAME IN THE QUESTION IS ON THE HANDSET LIST, AND HANDSETS "
                      "ARE OUT OF SCOPE ===")
                print("{}. This corpus holds handset records and does not advise on handsets; "
                      "python3 scripts/query.py lists them. A handset name is never an alias "
                      "to add. The mobile management plane is in scope: name the product that "
                      "enrols and manages these devices, or re-ask with --as app.mdm.{}".format(
                          found, also))
        else:
            print("=== NOTHING MATCHED, AND THAT IS USUALLY NOT AN ANSWER ===")
            print("A name this corpus does not carry resolves to nothing, and 73% of a real "
                  "integration library does exactly that. It rarely means there is nothing to "
                  "say: the product class almost always holds findings when the product name "
                  "holds none. Re-ask in one of these ways.")
            print("")
            suggestions = suggest_classes(args.question, vocab, aliases)
            if suggestions:
                print("CANDIDATE_CLASSES (share wording with the question):")
                for value in suggestions:
                    print("  --as {:<28} {}".format(
                        value, (vocab.get("product_class") or {}).get(value, "")))
            else:
                print("CANDIDATE_CLASSES: none - the question shares no wording with any class "
                      "description, which is what a bare product name does. Name the class "
                      "yourself:")
                # Printed, not pointed at. This fires at the moment the caller is most stuck,
                # and the route offered here until 0.33.0 was `query.py --help`, whose output
                # contains no class name at all -- so the one instruction given to somebody who
                # has just been told the corpus does not know their product cost them a second
                # failed lookup before they got anywhere.
                classes = sorted((vocab.get("product_class") or {}))
                print("  the {} classes this corpus knows, from corpus/schema/vocab.json:".format(
                    len(classes)))
                for row in range(0, len(classes), 3):
                    print("    " + "".join("{:<28}".format(c)
                                           for c in classes[row:row + 3]).rstrip())
            print("")
            print("NAME EVERY CLASS IT BEHAVES AS, not just the obvious one. Measured on an "
                  "AI gateway: --as app.ai_platform alone matched 29 findings and left "
                  "MANAGEMENT, DATA and ORGANISATION empty; adding network.proxy, security.pam "
                  "and cloud.saas -- what it also is, a proxy holding credentials for everyone "
                  "-- matched 129 and filled all six loci. A single class is usually an "
                  "under-description.")
            print("")
            print("OR: describe the technology rather than naming it, e.g. "
                  "\"gateway holding provider credentials for every model call\" instead of "
                  "the product name.")
            print("")
            if named_only and listing.handset:
                # Not a gap to report: the records exist and the scope decision keeps them out.
                print("THE ALIAS EXISTS AND WHAT CARRIES IT IS OUT OF SCOPE: {} resolved, and the "
                      "{} exposure record(s) naming it are handset records. This corpus holds "
                      "them and does not advise on handsets (corpus/schema/scope.json); python3 "
                      "scripts/query.py lists them. That is a standing scope decision, not a gap "
                      "in the records.".format(named_only, len(listing.handset)))
            elif named_only:
                # The alias already exists, so advice to add it sends the caller to a fix that
                # is in place. The gap is in the records.
                print("THE ALIAS EXISTS AND NO OBSERVATION CARRIES IT: {} resolved, so this is a "
                      "gap in the records, not in corpus/schema/aliases.json. No exposure record "
                      "names it either. Report the name so a source can be found.".format(
                          named_only))
            else:
                print("IF THIS IS A TECHNOLOGY THE CORPUS SHOULD KNOW BY NAME, that is a corpus "
                      "gap and it is fixable: add the vendor, product and product class to "
                      "corpus/schema/aliases.json and re-run. An unresolved name is far more "
                      "often a missing alias than a technology nobody has written about.{}"
                      .format(never_add(beside_handset, unknown)))
        print("")
        print("DO NOT report this as 'no known threats'. It is a statement about what this "
              "corpus has been fed, not about the safety of the technology.")
        # Exit 1, the same as the NO_FINDINGS path below: SKILL.md contracts that nothing
        # matched is distinguishable from a failure by exit code, and an unresolved
        # question is a case of nothing matching. Returning 0 here because the block is
        # now useful would make a caller's `if consult; then` treat it as an answer.
        return 1
    print("FINDINGS: {} shown of {} matched".format(len(quota.shown), matched))
    # How the match set was reached, tier by tier, counted before --limit truncates it --
    # the same discipline as LOCUS_MATCHED and for the same reason. This exists because
    # RESOLVED_TO could read "vendors=- products=- classes=-" while sixteen findings each
    # claimed to have named the technology, and nothing on screen reconciled the two. A
    # tally rather than another sentence: a consumer can gate on product=0, vendor=0,
    # class=0 without parsing English. Until 0.43.0 the first three were one count,
    # `identity`, which counted a class analogue as naming the product.
    print("MATCH_TIERS: {}  (over all {} matched findings, before --limit)".format(
        ", ".join("{}={}".format(t, tier_tally.get(t, 0)) for t in Q.TIER_ORDER), matched))
    print("ORDERING: computed. Grouped first by MATCH_TIER{}: records naming the product or "
          "vendor asked about (group 0), then class analogues and the vendor's other product "
          "lines (group 1), then free-text matches (group 2).{} Within a group, records seen in "
          "a sector the question named come first, then records carrying more of the "
          "question's leftover words, then blocks whose markers are written for the platform "
          "the question names (platform_fit +1, then 0 where either side names none, then -1 "
          "for another platform), then descending criticality (fidelity, records citing "
          "the pattern, whether identifiers are carried, victim role) combined with recency "
          "(days since publication, decaying to zero at five years). Seed-status records are "
          "halved.{} Every finding prints its PRIORITY_BASIS inputs, its group "
          "included.".format(
              " after coverage: a finding your --covered says is implemented drops one group"
              if args.rank_by == "gap" else "",
              " In group 0 a record naming only another of that vendor's products follows the "
              "records naming what was asked (PRIORITY_BASIS: after what was asked), because "
              "the question named a product."
              if subject.narrowed and "product" in subject.tiers else "",
              " Then weighted by novelty, so what --covered says is already implemented "
              "sinks within its group." if args.rank_by == "gap" else ""))
    for line in locus_header(quota, args.limit, matched, exposure_loci, library_loci,
                             subject.names):
        print(line)
    for line in have_header(have, have_rejected):
        print(line)
    print("RANK_BY: {}".format(args.rank_by))
    if covered is None:
        print("DECLARED_COVERAGE: NONE DECLARED - COVERAGE is UNASSESSED on every finding")
    else:
        rich = sum(1 for _, tk in covered[1] if len(tk) > 4)
        print("DECLARED_COVERAGE: {} identifier(s), {} named item(s), {} of them carrying "
              "artefact detail beyond the name".format(len(covered[0]), len(covered[1]), rich))
        print("COVERAGE_TALLY: {}  (over all {} matched findings, before --limit)".format(
            ", ".join("{}={}".format(k, v) for k, v in sorted(tally.items())) or "none",
            matched))
        print("COVERAGE_IS_HEURISTIC: verdicts come from token overlap against a pattern's "
              "name and description. It cannot separate two techniques that share their "
              "defining vocabulary -- a kernel module loaded to escape a container reads "
              "the same as one loaded to hide a rootkit. Audit by grepping COVERAGE: YES "
              "and reading each COVERAGE_BASIS.")
        if args.rank_by == "gap":
            print("DEMOTION: covered findings are multiplied by {} (yes) and {} (partial) "
                  "and remain in the output, ranked lower. Coverage never removes a "
                  "finding. A claim you implement badly must still be visible."
                  .format(COVERAGE_WEIGHT["yes"], COVERAGE_WEIGHT["partial"]))
    # After the finding lines, because they describe blocks printed after the findings.
    for line in exposure_lines:
        print(line)
    for line in library_header(library, len(shown_library), set(scoring.get("classes") or ()),
                               derived_classes,
                               {pid: placed[0] for pid, placed in library_placed.items()},
                               locus_order):
        print(line)
    print("CONTRACT: CAVEAT_VERBATIM is reproduced exactly and must not be summarised or "
          "dropped. SUPPORT reports when the source was last read and whether it was "
          "verified, and its bracketed flags mark findings backed more weakly than the "
          "rest -- weigh a flagged finding accordingly rather than discarding it. "
          "CORROBORATION names independent accounts of the same mechanism and "
          "'none' means single-source, which is a weight rather than a defect. "
          "STATUS: SEED means unconfirmed. SOURCE_DISCLOSURE: RESTRICTED means "
          "cite the title as given and nothing further. COUNTERMEASURES are candidate "
          "controls D3FEND maps to the cited techniques, not controls verified as present "
          "here, and an empty set is a gap in D3FEND rather than nothing to do. EXPOSURE "
          "blocks are vulnerability facts with no detection logic, and LIBRARY blocks are "
          "patterns no record cites, matched on class alone: neither is a finding, and "
          "neither may be presented as one.")
    print("=== END HEADER ===")
    print()

    # The match set, not the shown set. These are the same thing only while --limit is at
    # least 1, and --limit 0 once printed "the resolver matched nothing" over 97 matches.
    if not matched:
        # "ServiceNow" resolves a vendor and app.itsm and reaches no observation, and this
        # said the resolver matched nothing under a RESOLVED_TO showing both.
        what = ", ".join(sorted(set(declared_classes) | set(resolved.get("vendors") or ())
                                | set(resolved.get("products") or ())
                                | set(resolved.get("classes") or ())))
        unlisted = sum(listing.unlisted.values())
        if what:
            before = sum(len(r.get("how") or []) for r, _ in dropped)
            print("{}{}".format(
                "NO_FINDINGS: {} resolved; {} finding(s) matched before --role, none from a "
                "record whose what.role is {}.".format(what, before, " or ".join(roles))
                if roles and before else
                "NO_FINDINGS: {} resolved, but no observation sits under it.".format(what),
                " {} exposure record(s) reached it and are not listed; EXPOSURES_NOT_LISTED "
                "says why.".format(unlisted) if unlisted else ""))
            if named_exposures:
                # Something in the corpus does name it, so this is an answer and exits 0.
                print("METHODOLOGY: {} exposure record(s) name it: vulnerability facts with no "
                      "detection logic, listed in the EXPOSURE blocks below. There is no "
                      "observation to build a detection from{}".format(
                          len(named_exposures),
                          # "and", not "so": that there is no observation is not why iOS is a
                          # handset, and the "so" made it read as the reason.
                          ", and {}: answer the mobile management plane, which is in scope, "
                          "with --as app.mdm.".format(handset_aside(beside_handset))
                          if beside_handset else
                          ", so a detection means answering at class level with --as, naming "
                          "every class it behaves as; the classes these exposures carry are {}."
                          .format(", ".join(exposure_classes(named_exposures)))))
            elif library:
                print("METHODOLOGY: no observation sits under what resolved, and the LIBRARY "
                      "blocks below are patterns no record cites, matched on class alone: "
                      "detection logic for the class, with no incident behind it. Do not infer "
                      "coverage from an empty result.")
            else:
                print("METHODOLOGY: what the question named resolved, so this is a gap in the "
                      "records, not in corpus/schema/aliases.json. Report it so a source can be "
                      "found. Do not infer coverage from an empty result.")
        else:
            print("NO_FINDINGS: the resolver matched nothing.")
            print("METHODOLOGY: the term is probably absent from corpus/schema/aliases.json. "
                  "Add the vendor, product and product class there, then re-run. Do not "
                  "infer coverage from an empty result.")
        if not named_exposures and not library:
            return 1
        print()

    first_shown = {}
    # A campaign record's shown blocks with the identifiers each carries, so an exposure points
    # at the block holding its identifier: the ProxyShell exposure pointed at "FINDING 3 above",
    # the first block shown from the campaign record carrying it, and that was the Log4j block.
    blocks_shown = collections.defaultdict(list)
    for index, (rank_no, f, slot) in enumerate(quota.shown, 1):
        first_shown.setdefault(f.record.get("id"), index)
        if f.scope is not None:
            blocks_shown[f.record.get("id")].append((index, f.scope.ids))
        print(emit(f.record, f.how, f.pattern, index, len(quota.shown), f.band, f.basis, have,
                   f.verdict, f.why, d3fend, doctrine, f.locus, f.span, f.locus_basis,
                   today, f.match_basis, f.how_index,
                   match_text(f.match_basis, f.reasons, resolved, derived_classes, f.scope),
                   rank_no, slot_text(slot, rank_no, f, quota, args.limit),
                   unassessed))
        print()

    # The observations carrying each identifier, so an exposure can point at the detection the
    # corpus does hold for it, and at the finding above where that is shown.
    # The map is query.py's, which lists the same carriers under each exposure.
    vendor_of = {r.get("id"): (r.get("who") or {}).get("vendor") or "-" for r in records}
    held = {identifier: {(rid, vendor_of[rid]) for rid in rids}
            for identifier, rids in Q.identifier_carriers(records).items()}
    for index, (tier, record) in enumerate(shown_exposures, 1):
        locus, span, basis = exposure_placed[record.get("id")]
        print(emit_exposure(index, len(shown_exposures), tier, record, resolved, kev_ids, held,
                            first_shown, locus, span, basis, today, blocks_shown,
                            len(listing.handset)))
        print()
    for index, entry in enumerate(shown_library, 1):
        locus, span, basis = library_placed[entry.pattern.get("id")]
        print(emit_library(index, len(shown_library), entry, question_classes, derived_classes,
                           locus, span, basis, have, d3fend, doctrine, unassessed))
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
