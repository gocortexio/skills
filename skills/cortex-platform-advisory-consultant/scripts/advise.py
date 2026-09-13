#!/usr/bin/env python3
# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Answer a rule-design consultation about behaviours, in one invocation.

`consult.py` resolves a *technology* -- "I have a Cisco firewall" -- and that is the
common case. A different question kept arriving and had no tool: somebody is designing
detections and describes the *behaviour* they are thinking of building, in their own
words, and wants to know what the corpus says about that shape before they write it.

Answering those was costing five to eight round trips, every one of them re-deriving
the same three things with a slightly different hand-written search: which patterns
match the shape, whether anyone else ships that shape, and whether it has actually been
observed. None of that is slow to compute -- the whole corpus loads in under a tenth of
a second -- so the cost was entirely in the round trips. This collapses them to one.

**Corroboration and observation are separated and never merged.** They answer different
questions and conflating them is how "other people write rules for this" gets presented
as "this has been seen happening". `external_corroboration` counts public rule libraries;
citing records are incidents somebody wrote up. A shape can have either, both or neither,
and the honest answer is often "no corroboration, observed three times", which is the
most interesting result this tool produces and the easiest one to miss by hand.

**Selection is exact where it can be and best-effort where it cannot, and the output says
which.** Free-text behaviour search was tried first and is not good enough to rely on:
this corpus names its patterns evocatively rather than descriptively -- "The repository
told the internet where its credentials were" -- so token overlap against a name carries
little signal, and a search for audit-trail destruction returned a cloud-network-exposure
pattern whose logic happens to contain the phrase "provider audit trail". Free text is
therefore kept as a ranked suggestion, labelled SELECTION: free-text-guess, and
`--patterns` and `--attack` select exactly. Use the exact forms when the pattern is
already known, which for a consultation it usually is.

**URL liveness is cached with a date.** Verifying the same ATT&CK and advisory URLs on
every consult is minutes of wall clock for information that changes a few times a year.
The cache also earns its keep as a side effect: a URL that was live and is now empty is
a deprecated technique, which is exactly how the T1562 family was found.

Standard library only.
"""

import argparse
import collections
import datetime
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import consult as C  # noqa: E402  rarity, stopwords and the block format are shared
import query as Q  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(os.path.dirname(HERE), "corpus")
CACHE = os.path.join(CORPUS, "reference", "url-liveness.json")
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
# Re-check a URL if the cached verdict is older than this. Deprecations are rare and
# announced with a release, so a fortnight is far more often than they happen.
STALE_DAYS = 14

# How a pattern came to be in the answer, carried on every finding and printed as
# MATCH_BASIS. A caller is told to read that line to tell an exact selection from a
# ranking guess, so the two must never be confusable. These are strings and a free-text
# selection carries a list of overlapping tokens, so no corpus token can impersonate one.
# The previous sentinel was the list ["exact"], and "exact" is itself a legal token: a
# free-text search for it matched a pattern on the word and then reported the guess as
# "selected exactly", suppressing the verify-this warning in the one case it exists for.
BY_PATTERN_ID = "pattern-id"
BY_ATTACK_ID = "attack-id"


def load(corpus):
    with open(os.path.join(corpus, "schema", "aliases.json"), encoding="utf-8") as h:
        aliases = Q.normalise_alias_keys(json.load(h))
    records, patterns = Q.load_corpus(corpus)
    citing = collections.defaultdict(list)
    for record in records:
        for how in record.get("how") or []:
            if how.get("pattern_id"):
                citing[how["pattern_id"]].append((record, how))
    return records, patterns, aliases, citing


def match(shape, patterns, rarity, limit):
    """Rank patterns by behavioural overlap with a free-text shape."""
    freq, total, _ = rarity
    tokens = {w.lower() for w in re.findall(r"[A-Za-z0-9]+", shape)}
    tokens = {w for w in tokens if len(w) >= 3 and w not in C.STOPWORDS}
    scored = []
    for pid, pattern in patterns.items():
        # Identity and body are scored separately and weighted differently. A pattern's
        # name and description say what it *is*; its logic is long prose that mentions
        # many things in passing. Pooling them let a cloud-network-exposure pattern win a
        # search for audit-trail destruction, because its logic happens to contain the
        # phrase "provider audit trail". Identity counts for three times body.
        ident = set(re.findall(r"[a-z0-9]+", " ".join(
            str(x) for x in [pattern.get("name"), pattern.get("description")] if x).lower()))
        body = set(re.findall(r"[a-z0-9]+", str(pattern.get("logic") or "").lower()))
        hit_i, hit_b = tokens & ident, (tokens & body) - ident
        if not (hit_i or hit_b):
            continue
        # Rare tokens carry the score; common ones contribute almost nothing.
        def weight(ws):
            return sum(1.0 / (1 + freq.get(w, 0)) for w in ws)
        raw = 3.0 * weight(hit_i) + weight(hit_b)
        # Normalised by pattern length, so a verbose pattern cannot win on volume alone.
        score = raw * 100 / (1 + len(ident | body) ** 0.5)
        if hit_i or len(hit_b) >= 2:
            scored.append((score, pid, sorted(hit_i | hit_b)))
    scored.sort(reverse=True)
    return scored[:limit]


def liveness(urls, verify, corpus=None):
    """Check URLs against a dated cache, re-fetching only what is missing or stale.

    Takes the corpus rather than reading the module-level CACHE, because --corpus threaded
    through every other loader and stopped here: a run against another corpus read and WROTE
    this bundle's own cache, while the header printed a relative path that rendered the same
    either way, so the output looked as though the flag had been honoured.

    A transport failure never overwrites a verdict. Losing curl or the network used to write
    `unreachable` over whatever the entry held and stamp it fresh for the full staleness
    window, so one offline run turned 208 known-live URLs into 208 apparently dead sources
    for a fortnight -- and every REFERENCES line then carried '<<< unreachable', which reads
    as a claim about the source rather than about the caller's network.

    The title pattern accepts attributes on the open tag. Requiring a bare `<title>` filed
    pages answering 200 with 160 KB or more as DEPRECATED-OR-EMPTY, because their title was
    served as `<title data-react-helmet="true">`: present in the markup, and invisible to a
    pattern that allowed nothing between the name and the bracket. It still requires
    whitespace before any attribute, so `<titlebar>` is not a title.
    """
    cache_path = (os.path.join(corpus, "reference", "url-liveness.json")
                  if corpus else CACHE)
    try:
        with open(cache_path, encoding="utf-8") as h:
            cache = json.load(h)
    except (OSError, ValueError):
        cache = {}
    today = datetime.date.today()
    todo = []
    for url in urls:
        entry = cache.get(url)
        if not entry:
            todo.append(url)
            continue
        try:
            age = (today - datetime.date.fromisoformat(entry.get("checked", "1970-01-01"))).days
        except ValueError:
            age = 9999
        if age > STALE_DAYS:
            todo.append(url)
    unreachable = 0
    if todo and verify:
        for url in todo:
            try:
                done = subprocess.run(["curl", "-sSL", "--max-time", "20", "-A", UA, url],
                                      capture_output=True, timeout=40)
                body = done.stdout.decode("utf-8", "replace")
                m = re.search(r"<title(?:\s[^>]*)?>(.*?)</title>", body, re.S)
                title = re.sub(r"\s+", " ", m.group(1)).strip() if m else ""
            except (subprocess.TimeoutExpired, OSError):
                # Transport failure. Say nothing rather than something false: leave any prior
                # verdict exactly as it was, and do not re-stamp `checked`, so the next run
                # with a network re-checks instead of trusting a fortnight-old shrug.
                unreachable += 1
                continue
            cache[url] = {"checked": today.isoformat(),
                          "title": title,
                          "state": ("DEPRECATED-OR-EMPTY" if not title else "live")}
        try:
            with open(cache_path, "w", encoding="utf-8") as h:
                json.dump(cache, h, indent=1, sort_keys=True)
        except OSError:
            pass
    return cache, todo, unreachable


def attack_urls(pattern, how):
    out = []
    for tid in list((how or {}).get("technique") or []) + list((pattern or {}).get("technique") or []):
        if tid not in [t for t, _ in out]:
            out.append((tid, C.attack_url(tid)[1]))
    return out


def main():
    ap = argparse.ArgumentParser(
        description="Answer a behaviour-shaped consultation in one invocation.")
    ap.add_argument("shapes", nargs="*", default=[],
                    help="free-text behaviours, one per argument. Best-effort ranking only; "
                         "prefer --patterns or --attack when the pattern is known.")
    ap.add_argument("--patterns", default=None,
                    help="comma-separated pattern ids, selected exactly")
    ap.add_argument("--attack", default=None,
                    help="comma-separated ATT&CK ids; every pattern citing one is selected")
    ap.add_argument("--corpus", default=CORPUS)
    ap.add_argument("--per-shape", type=int, default=3, help="patterns to report per shape")
    ap.add_argument("--have", default=None, help="evidence types the caller collects")
    ap.add_argument("--no-verify", action="store_true",
                    help="use the URL cache only; do not fetch anything")
    args = ap.parse_args()

    have = {x.strip() for x in args.have.split(",")} if args.have else None
    records, patterns, aliases, citing = load(args.corpus)
    d3fend = C.load_d3fend(args.corpus)
    doctrine = C.load_doctrine(args.corpus)
    locus_map = C.load_locus_map(args.corpus)
    rarity = C.build_rarity(patterns)

    findings, seen = [], set()
    if args.patterns:
        for pid in [x.strip() for x in args.patterns.split(",") if x.strip()]:
            if pid in patterns and pid not in seen:
                seen.add(pid)
                findings.append(("SELECTION: exact pattern id", 0.0, pid, BY_PATTERN_ID))
            elif pid not in patterns:
                print("WARNING: no such pattern id: {}".format(pid), file=sys.stderr)
    if args.attack:
        want = {x.strip().upper() for x in args.attack.split(",") if x.strip()}
        # Label each pattern with the ids it actually cites, not with everything that was
        # asked for. Announcing the whole --attack set over a pattern citing one of them is
        # how a caller ends up citing a technique the corpus never connected to it. Grouped
        # by that label so the banner still changes once per set rather than per pattern.
        picked = []
        for pid, pattern in sorted(patterns.items()):
            cites = want & {t.upper() for t in (pattern.get("technique") or [])}
            if cites and pid not in seen:
                seen.add(pid)
                picked.append((", ".join(sorted(cites)), pid))
        for label, pid in sorted(picked):
            findings.append(("SELECTION: cites {}".format(label), 0.0, pid, BY_ATTACK_ID))
    for shape in args.shapes:
        for score, pid, overlap in match(shape, patterns, rarity, args.per_shape):
            if pid not in seen:
                seen.add(pid)
                findings.append(("SELECTION: free-text-guess -- {}".format(shape),
                                 score, pid, overlap))

    urls = set()
    for _, _, pid, _ in findings:
        pattern = patterns[pid]
        for record, how in citing[pid]:
            if record["where"].get("disclosure") == "public" and record["where"].get("url"):
                urls.add(record["where"]["url"])
        for _, u in attack_urls(pattern, None):
            urls.add(u)
    cache, fetched, unreachable = liveness(sorted(urls), not args.no_verify, args.corpus)

    # The headline count is what came back, not what was asked for. This printed
    # len(args.shapes) until 0.11.1, so every exact selection announced "SHAPES: 0" over
    # the findings it went on to print -- `--attack T1190` returned 48 patterns under a
    # header saying nothing matched. A caller is told to read the header before the
    # findings, so the one line it reads first denied the answer underneath it.
    by_pattern = sum(1 for _, _, _, basis in findings if basis == BY_PATTERN_ID)
    by_attack = sum(1 for _, _, _, basis in findings if basis == BY_ATTACK_ID)
    by_text = len(findings) - by_pattern - by_attack
    print("=== CONSULTATION (behaviour shapes) ===")
    print("CORPUS: {} records, {} patterns".format(len(records), len(patterns)))
    print("FINDINGS: {} pattern(s) returned".format(len(findings)))
    print("SELECTED_BY: exact pattern id {}, exact ATT&CK id {}, free-text guess {} "
          "across {} shape(s) asked".format(by_pattern, by_attack, by_text, len(args.shapes)))
    # The resolved path, not a relpath of the module global: the global rendered identically
    # whether or not --corpus was honoured, which is how the redirect defect stayed invisible.
    # The unreachable count is here so a caller can tell a dead source from a dead network.
    cache_path = os.path.join(args.corpus, "reference", "url-liveness.json")
    print("URL_LIVENESS: {} distinct URLs, {} re-checked this run, {} unreachable this run "
          "(network, not a verdict), cache at {}".format(
              len(urls), len(fetched) if not args.no_verify else 0, unreachable, cache_path))
    print("CONTRACT: CORROBORATED and OBSERVED are separate claims and must stay separate. "
          "CAVEAT_VERBATIM is reproduced exactly. STATUS: SEED means unconfirmed. "
          "SOURCE_DISCLOSURE: RESTRICTED means cite the title as given and nothing further. "
          "COUNTERMEASURES are candidate controls D3FEND maps to the cited techniques, not "
          "controls verified as present here.")
    print("=== END HEADER ===")
    print()

    current = None
    for shape, score, pid, overlap in findings:
        if shape != current:
            current = shape
            print("############################################################")
            print("### SHAPE: {}".format(shape))
            print("############################################################")
            print()
        pattern = patterns[pid]
        cited = citing[pid]
        ec = pattern.get("external_corroboration") or {}
        A = print
        A("--- PATTERN_ID: {}".format(pid))
        A("MATCH_BASIS: {}".format(
            "selected exactly by pattern id" if overlap == BY_PATTERN_ID
            else "selected exactly by ATT&CK id" if overlap == BY_ATTACK_ID
            else "free-text overlap on {} (score {:.1f}) - VERIFY THIS IS THE RIGHT "
                 "PATTERN BEFORE CITING IT".format(", ".join(overlap[:6]), score)))
        A("NAME: {}".format(pattern.get("name")))
        A("FIDELITY: {}   RULE_SHAPE: {}".format(
            pattern.get("fidelity") or "unstated", pattern.get("rule_shape") or "unstated"))
        A("CLASSES: {}".format(", ".join(pattern.get("applies_to_classes") or []) or "-"))
        # Class-only, and coarser than the consultation's. A pattern has no incident
        # behind it, so there is no attack_surface to outrank the class list and no
        # second signal to disagree with -- hence no LOCUS_SPAN here. There is no quota
        # either: advise.py returns what the caller selected by id, and reordering that
        # to balance an axis would answer a question nobody asked.
        p_locus, _, p_basis = C.locus_for(None, None, pattern, locus_map)
        A("LOCUS: {}   LOCUS_BASIS: {}".format(p_locus, p_basis))
        sigma, splunk = ec.get("sigma_rules"), ec.get("splunk_detections")
        if sigma or splunk:
            A("CORROBORATED: yes - {} Sigma, {} Splunk rule(s) ship this shape".format(
                sigma or 0, splunk or 0))
        else:
            A("CORROBORATED: no - no public rule library ships this shape")
        A("OBSERVED: {}".format(
            "yes, {} record(s)".format(len(cited)) if cited else "no citing record in the corpus"))
        for record, how in cited[:4]:
            where = record["where"]
            restricted = where.get("disclosure") != "public"
            url = "RESTRICTED - cite the title as given, nothing further" if restricted \
                else where.get("url") or "-"
            state = cache.get(url, {}).get("state", "unchecked")
            A("   [{}] {} | {}{}".format(
                (record.get("status") or "?").upper(), where.get("title", "")[:74], url,
                "" if restricted or state in ("live", "unchecked") else "  <<< {}".format(state)))
        A("ATTACK:")
        for tid, url in attack_urls(pattern, None):
            state = cache.get(url, {}).get("state", "unchecked")
            A("   {:12} {}{}".format(tid, url,
                                     "  <<< {}".format(state) if state not in ("live", "unchecked") else ""))
        A("LOGIC: {}".format(C.wrap(pattern.get("logic"), indent="   ")).lstrip())
        A("CAVEAT_VERBATIM:")
        A(C.wrap(pattern.get("caveat"), indent="   "))
        need = sorted(set(pattern.get("evidence_type") or []))
        A("TELEMETRY_REQUIRED: {}".format(", ".join(need) or "-"))
        if have is not None:
            gaps = [x for x in need if x not in have]
            A("DATA_GAP: {}".format(len(gaps)))
            for g in gaps:
                A("   MISSING {} -> ACQUIRE {}".format(g, C.CONNECTOR.get(g, g)))
        else:
            A("DATA_GAP: UNASSESSED - caller declared no inventory")
        for line in C.countermeasures(None, pattern, d3fend, indent="   "):
            A(line)
        # A pattern carries classes but no impact, so doctrine keyed on impact
        # alone cannot match here. The always-on and class-keyed rules still do,
        # which is the sequencing a rule designer needs at design time.
        for line in C.doctrine_for(pattern.get("product_class"), None, doctrine, indent="   "):
            A(line)
        A("")
    if not findings:
        if args.patterns or args.attack:
            # An exact selection returning nothing is a different failure from a guess
            # returning nothing, and the caller cannot act on it without knowing which.
            print("NO_MATCH: nothing was selected by exact id. A pattern id must exist in "
                  "the corpus, and an ATT&CK id selects on the pattern's own technique "
                  "list -- a technique cited only by records selects no pattern here. Any "
                  "unknown pattern id was named on stderr above.")
        else:
            print("NO_MATCH: no pattern overlapped any shape. Rephrase using the "
                  "behaviour's own vocabulary, or the shape may genuinely be absent from "
                  "the corpus - which is itself a reportable finding.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
