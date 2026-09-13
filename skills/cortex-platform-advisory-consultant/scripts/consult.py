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
produced it. An order asserted without its basis is not reviewable.

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
from `attack_surface`, `product_class` and `evidence_type` by the ladder in
`corpus/schema/locus-map.json`, never guessed, and `LOCUS_BASIS` prints every signal
including the ones that lost. A block may declare `locus` to override the derivation.

Two consequences follow, and both are the point rather than side effects. The header
prints `LOCUS_ABSENT`, naming every locus the match set could not fill -- a statement
about this corpus and this question, never a statement that the locus is safe. And the
shown set reserves one slot per populated locus, so a thin locus is not buried by a
dense one; every displacement that costs is printed under `LOCUS_DISPLACED` with the
finding it displaced, because a reordering that hides its own cost is not reviewable.
`--no-locus-spread` restores pure criticality order and still prints the distribution.

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
Finding = collections.namedtuple(
    "Finding",
    "weight record how pattern band basis verdict why locus span locus_basis how_index "
    "match_basis")

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


def published(record):
    when = record.get("when") or {}
    for key in ("published", "observed_end", "observed_start"):
        value = when.get(key)
        if value:
            try:
                return datetime.date.fromisoformat(value[:10])
            except ValueError:
                continue
    return None


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
        bits.append("published={} ({}d ago)".format(pub.isoformat(), (today - pub).days))
    else:
        bits.append("published=unknown")
        flags.append("NO_PUBLICATION_DATE:ranked-as-3650d")

    read = (where.get("retrieved") or "").strip()
    if read:
        bits.append("source_last_read={}".format(read))
    else:
        bits.append("source_last_read=unrecorded")
        flags.append("NO_READ_DATE")

    # verified is False by schema definition when the source has not been re-read since
    # the record was written, so an absent key is not the same as a negative one.
    if "verified" in where:
        bits.append("verified={}".format("yes" if where.get("verified") else "no"))
        if not where.get("verified"):
            flags.append("SOURCE_NOT_RE-READ")
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
MATCH_WEIGHT = {"identity": 1.0, "tag": 1.0, "name-fragment": 0.85,
                "pattern": 0.75, "summary": 0.6}


def match_basis(reasons):
    """Which tier this record matched on, tightest first, and what that is worth.

    A reason naming a vendor, product, class or sector means the resolver identified the
    technology, which is the tight case and the one this corpus was built around. A
    free-text reason names its own tier and is trusted to.

    Anything else is a reason shape this function does not know, and it is given the
    weakest tier rather than the tightest. Until 2026-08-27 an unrecognised reason fell
    into an else branch and was labelled `identity` at full weight, which is failing open
    on the side that makes a coincidence read like an answer.
    """
    tiers = set()
    for reason in reasons or ():
        if reason.startswith("term ") and reason.endswith(")"):
            tier = reason.rsplit("(", 1)[1].rstrip(")")
            tiers.add(tier if tier in MATCH_WEIGHT else "summary")
        elif reason.startswith(Q.STRUCTURED_REASONS):
            tiers.add("identity")
        else:
            tiers.add("summary")
    for tier in Q.TIER_ORDER:
        if tier in tiers:
            return tier, MATCH_WEIGHT[tier]
    return "summary", MATCH_WEIGHT["summary"]


def rank(record, how, citations, today, verdict="unassessed", rank_by="criticality",
         match_weight=1.0, match_tier="identity"):
    """Criticality and recency, combined, with every input reported to the reader."""
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
    novelty = COVERAGE_WEIGHT.get(verdict, 1.0) if rank_by == "gap" else 1.0
    score *= novelty
    score *= match_weight
    band = next(name for floor, name in BANDS if score >= floor)
    basis = ("score={:.1f}/8.5; rank_by={}; covered={}; novelty_multiplier={:.1f}; "
             "fidelity={}; records_citing_pattern={}; days_since_published={}; "
             "carries_identifiers={}; role={}; status={}; match={}x{:.2f}").format(
        score, rank_by, verdict, novelty, fidelity, citations,
        days if days < 3650 else "unknown", "yes" if exploited else "no",
        record.get("what", {}).get("role") or "-", record.get("status") or "-",
        match_tier, match_weight)
    return score, band, basis


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


def marker_line(marker):
    parts = ["type={}".format(marker.get("type")), "match={}".format(marker.get("match"))]
    if "value" in marker:
        parts.append("value={}".format(json.dumps(marker["value"])))
    if marker.get("expr"):
        parts.append("expr={}".format(marker["expr"]))
    return "  - " + " ".join(parts)


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


def resolution_mode(resolved, declared, matched=0, identity=0):
    """What kind of answer this is, which the header has to state rather than imply.

    The corpus resolves 73 per cent of a real integration library to nothing, so
    "no vendor matched" is the normal case rather than the exceptional one. Returning
    an empty consultation for it -- which is what this did until 0.20.0 -- throws away
    an answer the corpus can give, because the class almost always holds findings even
    when the product name holds none. What it must never do is let a class-level answer
    read as product intelligence, so the mode is named on its own line.
    """
    if declared:
        return "class-level-declared"
    if resolved.get("vendors") or resolved.get("products"):
        # A name resolving is not the same event as the corpus holding records about it,
        # and until 0.29.0 this returned "product" for both. "Guardsquare mobile application
        # runtime protection ... Android and iOS apps" resolved the word "Android" off the
        # vendor table and was told "the corpus holds records naming this technology" with
        # identity=0 underneath it -- the self-inconsistency SKILL.md says a consumer can
        # gate on, printed as though it were the tight case. The identity tally is the
        # arbiter because it counts what the findings were actually reached by, and it
        # counts only the ones reached by the vendor or product the caller named.
        if identity:
            return "product"
        if resolved.get("classes"):
            return "class-level-inferred"
        return "name-without-records" if matched else "unresolved"
    if resolved.get("classes"):
        return "class-level-inferred"
    # Nothing resolved by name, but the free-text tiers found records anyway -- which is
    # what a mechanism question looks like ("phishing", "ransomware"). Before 0.22.0 the
    # free-text haystack was vendor and product only, so this could not happen and
    # "nothing resolved" and "nothing found" were the same state. They are not any more,
    # and reporting a mechanism answer as UNRESOLVED would have hidden 33 findings for
    # "phishing" behind advice to go and name a product class.
    if matched:
        return "mechanism"
    return "unresolved"


def locus_for(record, how, pattern=None, locus_map=None):
    """Where this finding sits: (locus, span, basis).

    A ladder, first hit wins, no scoring. `attack_surface` outranks `product_class`
    where it commits to a locus, because it is single-valued and says something about
    this incident; the class list says what the product is and half of all records name
    products from more than one plane. First-listed class rather than a majority vote,
    because authors write the primary subject first and voting collapses ENDPOINT.

    The span is computed afterwards and is deliberately tier-independent: any other
    signal that unanimously commits to a different locus is a genuine second home,
    whichever tier decided the first. A class list split across loci is a bag, not a
    second opinion, and is never reported -- that is 51 per cent of records, and
    surfacing it would make the key meaningless.

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
    order = locus_map.get("locus_order") or []

    record = record or {}
    how = how or {}
    classes = list((record.get("who") or {}).get("product_class")
                   or (pattern or {}).get("applies_to_classes") or [])
    surface = (record.get("what") or {}).get("attack_surface")

    productive = [c for c in classes if c not in nonproduct]
    csig = [by_class[c] for c in productive if c in by_class]
    class_commits = csig[0] if csig and len(set(csig)) == 1 else None
    surface_commits = by_surface.get(surface) if surface else None

    declared = how.get("locus")
    if declared:
        primary, tier, decided_by, why = declared, "declared", None, "how[].locus"
    elif surface in supply_surfaces:
        primary, tier, decided_by = by_surface[surface], "surface_supply", "surface"
        why = "what.attack_surface={}".format(surface)
    elif any(c in nonproduct for c in classes):
        primary, tier, decided_by = "ORGANISATION", "class_nonproduct", None
        why = "product_class carries {}".format(
            ", ".join(sorted(c for c in classes if c in nonproduct)))
    elif surface_commits:
        primary, tier, decided_by = surface_commits, "surface", "surface"
        why = "what.attack_surface={}".format(surface)
    elif csig:
        primary, tier, decided_by = csig[0], "class_first", "class"
        why = "product_class first-listed={}".format(productive[0])
    else:
        evidence = [by_evidence[e] for e in (how.get("evidence_type")
                                             or (pattern or {}).get("evidence_type") or [])
                    if e in by_evidence]
        if evidence:
            counts = {}
            for value in evidence:
                counts[value] = counts.get(value, 0) + 1
            top = max(counts.values())
            tied = sorted((v for v, n in counts.items() if n == top),
                          key=lambda v: order.index(v) if v in order else 99)
            primary, tier, decided_by = tied[0], "evidence", None
            why = "evidence_type plurality"
        elif how.get("rule_shape") == "inventory":
            primary, tier, decided_by, why = "ORGANISATION", "shape", None, "rule_shape=inventory"
        else:
            primary, tier, decided_by = locus_map.get("default") or "CONTROL", "default", None
            why = "no signal committed"

    span = None
    for source, locus in (("surface", surface_commits), ("class", class_commits)):
        if source == decided_by or not locus or locus == primary:
            continue
        span = locus
        break

    basis = "tier={}; input={}; surface-signal={}; class-signal={}; declared={}".format(
        tier, why, surface_commits or "-",
        "{} ({})".format(class_commits, "unanimous") if class_commits
        else ("split" if len(set(csig)) > 1 else "-"),
        "yes" if declared else "no")
    return primary, span, basis


def apply_locus_quota(findings, limit, order, spread=True):
    """Reserve one slot per populated locus, then fill by descending score.

    `findings` arrives sorted descending and is returned in that same order, so RANK
    stays monotonic and a reader is never asked to believe rank 3 outscores rank 2.
    Reserves that fall inside the natural top-N cost nothing and are not reported.

    Returns (shown, reserved, displaced, matched, shown_counts, absent, underserved),
    where `reserved` and `displaced` are lists of (rank, finding) and are always the
    same length -- every slot taken from below the cut costs exactly one above it.
    """
    matched = collections.OrderedDict((locus, 0) for locus in order)
    for finding in findings:
        matched[finding.locus] = matched.get(finding.locus, 0) + 1
    populated = [locus for locus, n in matched.items() if n]
    absent = [locus for locus, n in matched.items() if not n]

    cut = min(limit, len(findings))
    natural = set(range(cut))

    if not spread or limit >= len(findings):
        chosen = sorted(natural)
        reserved, displaced, underserved = [], [], []
    else:
        first = {}
        for i, finding in enumerate(findings):
            first.setdefault(finding.locus, i)
        # Representatives in score order, so a --limit below the populated count keeps
        # the strongest loci rather than whichever happens to sort first.
        picked = set(sorted(first[locus] for locus in populated)[:limit])
        for i in range(len(findings)):
            if len(picked) >= limit:
                break
            picked.add(i)
        chosen = sorted(picked)
        underserved = [locus for locus in populated if first[locus] not in picked]
        reserved = [(i + 1, findings[i]) for i in chosen if i not in natural]
        displaced = [(i + 1, findings[i]) for i in sorted(natural) if i not in picked]

    shown = [findings[i] for i in chosen]
    shown_counts = collections.OrderedDict((locus, 0) for locus in order)
    for finding in shown:
        shown_counts[finding.locus] = shown_counts.get(finding.locus, 0) + 1
    return shown, reserved, displaced, matched, shown_counts, absent, underserved


def locus_header(matched, shown_counts, absent, reserved, displaced, underserved,
                 spread, limit, total):
    """The six spread lines. Printed whether or not the quota is on.

    Reporting the distribution under --no-locus-spread is the part that matters most:
    it makes a concentrated answer visible without asking the reader to run it twice.
    """
    def dist(counts):
        return ", ".join("{}={}".format(k, v) for k, v in counts.items()) or "none"

    out = []
    if spread:
        out.append("LOCUS_SPREAD: quota - one slot reserved per locus with any match, "
                   "filled by that locus's highest scorer; remaining slots by descending "
                   "score. Pass --no-locus-spread for pure criticality order.")
    else:
        out.append("LOCUS_SPREAD: off - pure criticality order (--no-locus-spread). "
                   "LOCUS_MATCHED and LOCUS_SHOWN below are reported anyway, so a "
                   "concentrated answer is visible without re-running.")
    out.append("LOCUS_MATCHED: {}  (over all {} matched findings, before --limit)".format(
        dist(matched), total))
    out.append("LOCUS_SHOWN: {}  (over the {} shown)".format(
        dist(shown_counts), sum(shown_counts.values())))
    if absent:
        out.append("LOCUS_ABSENT: {} - no finding in this match set sits there. That is a "
                   "statement about this corpus and this question, not a statement that "
                   "the locus is safe.".format(", ".join(absent)))
    else:
        out.append("LOCUS_ABSENT: none - every locus is represented in the match set")
    out.append("LOCUS_DISPLACED: {}{}".format(
        len(displaced),
        " finding(s) pushed out of the top {} to make room for a reserved slot".format(limit)
        if displaced else ""))
    for rank, finding in displaced:
        out.append("  - rank {}, score {:.2f}, {}, {} / {}".format(
            rank, finding.weight, finding.locus, finding.record.get("id"),
            (finding.how or {}).get("pattern_id") or "-"))
    out.append("LOCUS_RESERVED: {}{}".format(
        len(reserved), " slot(s) filled from below the natural cut" if reserved else ""))
    for rank, finding in reserved:
        out.append("  - {}, rank {}, score {:.2f}, {}".format(
            finding.locus, rank, finding.weight, finding.record.get("id")))
    if underserved:
        out.append("LOCUS_UNDERSERVED: --limit {} is below the {} populated loci, so {} got "
                   "no slot. Raise --limit to {} or more to see one of each.".format(
                       limit, sum(1 for v in matched.values() if v),
                       ", ".join(underserved), sum(1 for v in matched.values() if v)))
    return out


def doctrine_for(classes, impacts, doctrine, limit=6, indent="  "):
    """In what order and how widely to act, as distinct from which control to apply.

    D3FEND answers the control question per technique. This answers the questions
    that decide whether a response works at all: collect before you mitigate,
    assume the adversary is watching, scope remediation to everything exposed
    rather than to what you saw. Matched on the finding's own product class and
    impact, so a network appliance is told that a factory reset is not eradication
    and an OT record is told its emergency plan needs named degraded states.
    """
    table = (doctrine or {}).get("doctrine") or {}
    if not table:
        return []
    classes = set(classes or [])
    prefixes = {c.split(".")[0] for c in classes}
    impacts = set(impacts or [])

    picked = []
    for did, entry in sorted(table.items()):
        applies = entry.get("applies_to") or {}
        specific = bool(classes & set(applies.get("product_class") or [])
                        or prefixes & set(applies.get("class_prefix") or [])
                        or impacts & set(applies.get("impact") or []))
        if specific or applies.get("always"):
            picked.append((did, entry, specific))
    if not picked:
        return []

    order = {name: i for i, name in enumerate((doctrine or {}).get("stage_order") or [])}
    # Select by relevance, display by sequence. A rule that matched because of THIS
    # finding's class or impact is why the reader is on this finding, so it must never
    # be the one truncation drops: an OT record kept losing "your emergency plan needs
    # named degraded states" behind four rules that apply to everything. But the shown
    # set is then re-sorted into incident order, because "collect before you mitigate"
    # is worthless if it prints after the eradication step it is meant to precede.
    shown = sorted(picked, key=lambda kv: (not kv[2], order.get(kv[1].get("stage"), 99), kv[0]))[:limit]
    shown.sort(key=lambda kv: (order.get(kv[1].get("stage"), 99), kv[0]))

    body = indent + "    "
    out = ["RESPONSE_DOCTRINE: {} shown of {}, {} matched on this finding's class or "
           "impact, ordered {}".format(
               len(shown), len(picked), sum(1 for _, _, s in picked if s),
               "-".join((doctrine.get("stage_order") or [])).lower())]
    for did, entry, _ in shown:
        out.append("{}- {} | {} | {}".format(
            indent, did, (entry.get("stage") or "-").upper(), entry.get("rule")))
        for source in entry.get("sources") or []:
            out.append("{}{} | {}".format(body, source.get("publisher"), source.get("url")))
    return out


def countermeasures(how, pattern, d3fend, limit=6, indent="  "):
    """What to do about this finding, joined on the ATT&CK ids it already prints.

    D3FEND covers 214 of the 396 technique ids this corpus cites, so a little
    under half of all findings have nothing to join to. That is reported as a
    gap in D3FEND rather than passed off as nothing to do, on the same rule as
    an empty resolve: silence must never read as coverage.
    """
    table = (d3fend or {}).get("countermeasures") or {}
    index = (d3fend or {}).get("by_attack") or {}
    if not table:
        return ["COUNTERMEASURES: UNASSESSED - corpus/reference/d3fend-countermeasures.json "
                "is absent; run the D3FEND harvest to enable this block"]

    techniques, seen = [], set()
    for tid in list((how or {}).get("technique") or []) + list((pattern or {}).get("technique") or []):
        upper = tid.upper()
        if upper not in seen:
            seen.add(upper)
            techniques.append(upper)
    if not techniques:
        return ["COUNTERMEASURES: none - this finding cites no ATT&CK technique to join on"]

    picked, source = [], set()
    for tid in techniques:
        for cid in index.get(tid) or []:
            if cid not in picked:
                picked.append(cid)
                source.add(tid)
    if not picked:
        return ["COUNTERMEASURES: none - D3FEND {} maps no countermeasure to {}. That is a gap "
                "in D3FEND coverage, not an absence of anything to do.".format(
                    (d3fend or {}).get("version") or "?", ", ".join(techniques))]

    # Already ordered contain-eradicate-recover first by the harvest, so a cut
    # here loses the tail rather than the step somebody needs first.
    out = ["COUNTERMEASURES: {} shown of {}, ordered {}, from {}".format(
        min(limit, len(picked)), len(picked),
        "-".join((d3fend.get("tactic_order") or [])[:3]).lower(),
        ", ".join(sorted(source)))]
    body = indent + "    "
    for cid in picked[:limit]:
        entry = table.get(cid) or {}
        out.append("{}- {} | {} | {}".format(
            indent, cid, entry.get("tactic") or "-", entry.get("name")))
        if entry.get("definition"):
            out.append(wrap(entry["definition"], indent=body))
        if entry.get("url"):
            out.append("{}{}".format(body, entry["url"]))
    return out


def emit(record, how, pattern, index, total, band, basis, have,
         verdict="unassessed", why="caller declared no coverage inventory", d3fend=None,
         doctrine=None, locus="UNDERIVABLE", span=None, locus_basis="tier=none",
         today=None, match_tier="identity"):
    lines = []
    A = lines.append
    where = record.get("where") or {}
    who = record.get("who") or {}
    what = record.get("what") or {}
    restricted = where.get("disclosure") != "public"

    A("=== FINDING {} OF {} ===".format(index, total))
    A("RANK: {}".format(index))
    A("PRIORITY: {}".format(band))
    A("PRIORITY_BASIS: {}".format(basis))
    A("RECORD_ID: {}".format(record.get("id")))
    # The pattern id is the corpus's stable handle for a detection, and it was missing:
    # a consumer could read the logic but had no identifier to cite back or to ask for
    # again by name. The record id alone is not enough, because one record cites several.
    A("PATTERN_ID: {}".format((how or {}).get("pattern_id") or (pattern or {}).get("id") or "-"))
    status = (record.get("status") or "unknown").upper()
    A("STATUS: {}{}".format(status, "  <<< SEED - NOT CONFIRMED, source not re-read"
                            if record.get("status") == "seed" else ""))
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
    # was indistinguishable in the output from one that named the technology.
    A("MATCH_BASIS: {}".format({
        "identity": "named this technology (vendor, product or class)",
        "tag": "tagged with a term from the question",
        "name-fragment": "WEAK - the question's words appear inside a vendor, product "
                         "or class name here, but nothing resolved by name; read "
                         "TECHNOLOGY below before treating this as being about "
                         "your technology",
        "pattern": "LOOSE - the cited pattern's wording matched; may be tangential",
        "summary": "LOOSE - the record's prose matched; may be about something else",
    }[match_tier]))
    A("TECHNOLOGY: {} / {}".format(who.get("vendor") or "-", "; ".join(who.get("products") or []) or "-"))
    A("PRODUCT_CLASS: {}".format(", ".join(who.get("product_class") or []) or "-"))
    # LOCUS_SPAN always carries the primary, so a consumer splitting on ", " gets a list
    # of one or two in every case rather than three shapes to handle. It is never "-".
    A("LOCUS: {}".format(locus))
    A("LOCUS_SPAN: {}".format(", ".join([locus] + ([span] if span else []))))
    A("LOCUS_BASIS: {}".format(locus_basis))
    A("DERIVATION: {}".format("library pattern (product-class derived, no incident record)"
                              if pattern and not how else "cited record"))
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

    markers = (how or {}).get("markers") or (pattern or {}).get("markers") or []
    A("MARKERS: {}".format(len(markers)))
    for marker in markers:
        A(marker_line(marker))
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
    A("DATA_GAP: {}".format(len(gaps) if have is not None else "UNASSESSED - caller declared no inventory"))
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


def main():
    ap = argparse.ArgumentParser(description="Emit a consultation in the fixed advisory format.")
    ap.add_argument("question", help="technology, vendor, product class or scenario")
    ap.add_argument("--corpus", default=CORPUS)
    ap.add_argument("--have", default=None,
                    help="comma-separated evidence types the caller already collects; "
                         "omit to have every requirement reported as unassessed")
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
    ap.add_argument("--limit", type=int, default=12)
    ap.add_argument("--no-locus-spread", action="store_true",
                    help="disable the per-locus quota and return pure criticality order. "
                         "The quota reserves one slot per locus that has any match, which "
                         "displaces higher-scoring findings; every displacement is printed "
                         "either way, as is the distribution.")
    ap.add_argument("--today", default=None, help="ISO date, for reproducible ranking")
    args = ap.parse_args()

    today = datetime.date.fromisoformat(args.today) if args.today else datetime.date.today()
    have = None
    if args.have is not None:
        have = {x.strip() for x in args.have.split(",") if x.strip()}
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


    rarity = build_rarity(patterns)
    citations = {}
    for record in records:
        for how in record.get("how") or []:
            if how.get("pattern_id"):
                citations[how["pattern_id"]] = citations.get(how["pattern_id"], 0) + 1

    findings = []
    # Identity findings reached because the caller named a VENDOR or a PRODUCT, as opposed
    # to a class. The two are one tier but they are not one claim: "Guardsquare ... Android
    # and iOS apps" resolves the word "Android" off the vendor table while the subject of
    # the question resolves only to a class, and reporting that as "the corpus holds records
    # naming this technology" is the over-confidence this release is about. Q.score() labels
    # its reasons by kind, so the distinction is already there to be read.
    named_identity = 0
    for record in records:
        hit, why_matched = Q.score(record, resolved, patterns)
        if not hit:
            continue
        if any(r.startswith(("vendor ", "product ")) for r in why_matched or ()):
            named_identity += len(record.get("how") or [])
        for how_index, how in enumerate(record.get("how") or []):
            pattern = patterns.get(how.get("pattern_id"))
            verdict, why = coverage(record, how, pattern, covered, rarity)
            tier, tier_weight = match_basis(why_matched)
            weight, band, basis = rank(record, how, citations.get(how.get("pattern_id"), 1),
                                       today, verdict, args.rank_by, tier_weight, tier)
            locus, span, locus_basis = locus_for(record, how, pattern, locus_map)
            findings.append(Finding(weight, record, how, pattern, band, basis, verdict, why,
                                    locus, span, locus_basis, how_index, tier))

    # The sort key runs all the way to the how-index. Score and record id alone collide
    # eleven times in a single Cisco query, and order between colliding findings used to
    # fall out of insertion order. That was deterministic but incidental, and the quota
    # below now picks "the first finding of each locus" off this order, so it has to be
    # stated rather than inherited.
    findings.sort(key=lambda f: (-f.weight, f.record.get("id"),
                                 (f.how or {}).get("pattern_id") or "", f.how_index))
    # Tallied before truncation. Counting only the findings that survived --limit would
    # report the coverage of the output rather than of the match set, which is the
    # opposite of what a reader checking for over-suppression needs to see.
    tally, matched = {}, len(findings)
    tier_tally = {}
    for f in findings:
        tally[f.verdict] = tally.get(f.verdict, 0) + 1
        tier_tally[f.match_basis] = tier_tally.get(f.match_basis, 0) + 1
    # After the tally, not before it: the mode depends on how many findings were reached by
    # identity, so it cannot be decided from the resolved names alone.
    mode = resolution_mode(resolved, declared_classes, matched, named_identity)
    locus_order = (locus_map.get("locus_order")
                   or sorted({f.locus for f in findings}))
    (findings, reserved, displaced, locus_matched, locus_shown,
     locus_absent, locus_underserved) = apply_locus_quota(
         findings, args.limit, locus_order, spread=not args.no_locus_spread)

    print("=== CONSULTATION ===")
    print("QUESTION: {}".format(args.question))
    def show(key):
        return ", ".join(sorted(resolved.get(key) or [])) or "-"
    print("RESOLVED_TO: vendors={} | products={} | classes={}".format(
        show("vendors"), show("products"), show("classes")))
    print("CORPUS: {} records, {} patterns".format(len(records), len(patterns)))
    # The mode is stated on its own line and never left to be inferred from RESOLVED_TO,
    # because the difference between "this product was attacked" and "products of this
    # kind are attacked" is the difference between intelligence and analogy, and a
    # consumer building detection content from this block has to know which it holds.
    print("RESOLUTION: {}".format({
        "product": "product - the corpus holds records naming this technology",
        "class-level-inferred": "CLASS-LEVEL (inferred) - no vendor or product the corpus "
                                "holds records for; answering on product class alone",
        "class-level-declared": "CLASS-LEVEL (declared via --as: {}) - the caller asserted "
                                "the class".format(", ".join(declared_classes)),
        "mechanism": "mechanism - nothing resolved by name, but the question's words match "
                     "record tags and prose; every finding prints its MATCH_BASIS",
        "name-without-records": "NAME_WITHOUT_RECORDS - a name in this question resolved "
                                "against the alias table, but no record in the corpus is "
                                "about it. Every finding below was reached by tag or prose "
                                "and none by identity; read TECHNOLOGY on each one",
        "unresolved": "UNRESOLVED - nothing in this question matched a vendor, product or "
                      "class, and no record's tags or prose carried its words either",
    }[mode]))
    if mode in ("class-level-inferred", "class-level-declared"):
        print("CLASS_LEVEL_WARNING: every finding below describes what this CLASS of "
              "technology has been caught up in, not this product. The corpus holds no "
              "record naming it. Do not present any of it as product-specific "
              "intelligence, and say so wherever it is passed on.")
    if mode == "unresolved":
        print("FINDINGS: 0 shown of 0 matched")
        print("")
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
                print("    " + "".join("{:<28}".format(c) for c in classes[row:row + 3]).rstrip())
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
        print("IF THIS IS A TECHNOLOGY THE CORPUS SHOULD KNOW BY NAME, that is a corpus gap "
              "and it is fixable: add the vendor, product and product class to "
              "corpus/schema/aliases.json and re-run. An unresolved name is far more often "
              "a missing alias than a technology nobody has written about.")
        print("")
        print("DO NOT report this as 'no known threats'. It is a statement about what this "
              "corpus has been fed, not about the safety of the technology.")
        # Exit 1, the same as the NO_FINDINGS path below: SKILL.md contracts that nothing
        # matched is distinguishable from a failure by exit code, and an unresolved
        # question is a case of nothing matching. Returning 0 here because the block is
        # now useful would make a caller's `if consult; then` treat it as an answer.
        return 1
    print("FINDINGS: {} shown of {} matched".format(len(findings), matched))
    # How the match set was reached, tier by tier, counted before --limit truncates it --
    # the same discipline as LOCUS_MATCHED and for the same reason. This exists because
    # RESOLVED_TO could read "vendors=- products=- classes=-" while sixteen findings each
    # claimed to have named the technology, and nothing on screen reconciled the two. A
    # tally rather than another sentence: a consumer can gate on identity=0 without
    # parsing English.
    print("MATCH_TIERS: {}  (over all {} matched findings, before --limit)".format(
        ", ".join("{}={}".format(t, tier_tally.get(t, 0)) for t in Q.TIER_ORDER), matched))
    print("ORDERING: computed, descending. Criticality (fidelity, records citing the "
          "pattern, whether identifiers are carried, victim role) combined with recency "
          "(days since publication, decaying to zero at five years). Seed-status records "
          "are halved.{} Every finding prints its PRIORITY_BASIS inputs.".format(
              " Then weighted by novelty, so what --covered says is already implemented "
              "sinks." if args.rank_by == "gap" else ""))
    for line in locus_header(locus_matched, locus_shown, locus_absent, reserved, displaced,
                             locus_underserved, not args.no_locus_spread, args.limit, matched):
        print(line)
    print("DECLARED_TELEMETRY: {}".format(
        ", ".join(sorted(have)) if have else "NONE DECLARED - all DATA_GAP fields unassessed"))
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
    print("CONTRACT: CAVEAT_VERBATIM is reproduced exactly and must not be summarised or "
          "dropped. SUPPORT reports when the source was last read and whether it was "
          "verified, and its bracketed flags mark findings backed more weakly than the "
          "rest -- weigh a flagged finding accordingly rather than discarding it. "
          "CORROBORATION names independent accounts of the same mechanism and "
          "'none' means single-source, which is a weight rather than a defect. "
          "STATUS: SEED means unconfirmed. SOURCE_DISCLOSURE: RESTRICTED means "
          "cite the title as given and nothing further. COUNTERMEASURES are candidate "
          "controls D3FEND maps to the cited techniques, not controls verified as present "
          "here, and an empty set is a gap in D3FEND rather than nothing to do.")
    print("=== END HEADER ===")
    print()

    if not findings:
        print("NO_FINDINGS: the resolver matched nothing.")
        print("METHODOLOGY: the term is probably absent from corpus/schema/aliases.json. "
              "Add the vendor, product and product class there, then re-run. Do not infer "
              "coverage from an empty result.")
        return 1

    for index, f in enumerate(findings, 1):
        print(emit(f.record, f.how, f.pattern, index, len(findings), f.band, f.basis, have,
                   f.verdict, f.why, d3fend, doctrine, f.locus, f.span, f.locus_basis,
                   today, f.match_basis))
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
