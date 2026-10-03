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
import consult as C  # noqa: E402  stopwords, the locus ladder and the block format are shared
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
# A requested parent reaches the patterns citing its sub-techniques, as ATT&CK itself reads
# a parent. `--attack T1003` selected 2 patterns while 7 cite the family, and T1684, where
# ATT&CK 19.2 moved Impersonation, selected none of the 6 citing its sub-techniques.
BY_ATTACK_SUB = "attack-subtechnique"
# A revoked id is followed to MITRE's own replacement, never to a guess: --attack T1562.001
# answered "nothing was selected" over the 20 patterns citing T1685, which revoked it. A
# revoked parent's revoked sub-techniques are followed to theirs too: its family, read in the
# taxonomy the id came from.
BY_ATTACK_REPLACEMENT = "attack-replacement"
# A followed replacement is answered as `--attack <replacement>` would be, so a live parent
# reaches its sub-techniques. Following T1562 to T1685 and stopping there returned 20 of the 31
# patterns in its family and said nothing of the other 11, among them the event-log clearing,
# host firewall and cloud audit coverage patterns.
BY_ATTACK_REPLACEMENT_SUB = "attack-replacement-subtechnique"
BY_FREE_TEXT = "free-text"
ATTACK_BASES = (BY_ATTACK_ID, BY_ATTACK_SUB, BY_ATTACK_REPLACEMENT, BY_ATTACK_REPLACEMENT_SUB)

# One selected pattern. `detail` is what the basis needs to explain itself: the overlapping
# tokens for a guess, (cited, requested) for a sub-technique, (replacement, revoked) for a
# followed id. The basis is dispatched on explicitly, never inferred from detail's type: a
# string basis once formatted through the token-list branch printed as "a, t, t, a, c, k".
Finding = collections.namedtuple("Finding", "banner score pid basis detail")

# Record lines printed under OBSERVED before the rest are listed by id only.
OBSERVED_LINES = 6

# A candidate whose only overlap is one token carried by more than this share of patterns
# is dropped: "credential" alone returned three patterns at score 0.8.
COMMON_TOKEN_SHARE = 0.10

# What a word found only in a pattern's markers, caveat or citing records is worth, against
# 1.0 for its logic and 3.0 for its name, description and id.
CONTEXT_WEIGHT = 0.5

# A single word outside a pattern's identity admits it only when no more than this share of
# patterns carry the word anywhere: "mimikatz" and "vishing" are a handful's, "shell" many.
RARE_TOKEN_SHARE = 0.02


def _coverage(met):
    """What the share of a shape's words a candidate met does to its score: half of it is
    always kept, so a pattern strongly about one word of two is not ranked out by one that
    mentions both in passing."""
    return 0.5 + 0.5 * met


# At this --per-shape or more, the last guess is kept for the behaviour the shape names in
# ATT&CK's words when no guess above it cites that behaviour; see Matcher.behaviour_slot.
BEHAVIOUR_SLOT_FROM = 3

# The fidelities that detect, as against enrich, which adds context to something else. Only
# these fill the behaviour slot: a caller naming a behaviour is designing a rule for it.
DETECTION_GRADE = ("alert", "hunt")


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


def _inflect(word):
    """The inflectional half of the stemmer: plurals, -ing, -ed and a trailing "e".

    Without it appliance/appliances, spawn/spawns/spawning and clear/cleared were unrelated,
    so "edge appliance" and "edge appliances" returned different patterns. A word ending in
    "ss" is left alone, so lsass, access and process survive whole. A trailing "e" goes too,
    so that "abuse" and "abused" meet at "abus", and a doubled final consonant left by -ing
    or -ed is undoubled, so "logging" meets "logs" at "log".
    """
    if word.endswith("ss"):
        return word
    if word.endswith("ies") and len(word) > 4:
        return word[:-3] + "y"
    for suffix, floor in (("ing", 4), ("ed", 4), ("es", 4), ("s", 3)):
        if word.endswith(suffix) and len(word) - len(suffix) >= floor:
            stem = word[:-len(suffix)]
            if suffix in ("ing", "ed") and len(stem) >= 4 and stem[-1] == stem[-2] \
                    and stem[-1] not in "aeiouls":
                stem = stem[:-1]
            word = stem
            break
    if word.endswith("e") and len(word) > 4:
        word = word[:-1]
    return word


# Derivational endings, tried in order after _inflect, each with the length the stem must
# keep. Inflection alone left "exploitation" whole, so it never met "exploit": 69 patterns
# carried the one and 30 the other. "impersonation" never met "impersonate", nor
# "escalation" "escalated".
# A verb's "-ate" is already "-at" once _inflect has taken the "e", so "-at" meets "-ation".
# "-tion"/"-sion" lose only "-ion", so "injection" meets "inject" and "execution" "execute".
DERIVATIONAL = (("ation", 4), ("ator", 4), ("ment", 4), ("at", 5))


def _stem(word):
    """A light suffix stemmer applied to both sides of a free-text match; see _inflect and
    DERIVATIONAL. Five characters of stem are kept before "-at", so "threat" and "format"
    stay whole."""
    word = _inflect(word)
    if word.endswith("ss"):
        return word
    for suffix, floor in DERIVATIONAL:
        if word.endswith(suffix) and len(word) - len(suffix) >= floor:
            word = word[:-len(suffix)]
            break
    else:
        if word[-4:] in ("tion", "sion") and len(word) - 3 >= 4:
            word = word[:-3]
    if word.endswith("e") and len(word) > 4:
        word = word[:-1]
    return word


def _terms(text):
    """The match terms of a piece of text, stemmed, stop words removed."""
    return set(_term_forms(text))


def _term_forms(text):
    """{stem: the word it came from} for a piece of text; see _terms.

    A hyphenated compound is kept joined ("pre-auth" -> "preauth") and its parts are kept
    only at four characters or more, so "pre" is dropped and "auth" kept. Splitting on the
    hyphen alone made "pre" a token, and it matched every pre-X compound in the corpus:
    "pre-auth RCE on VPN appliances" ranked a safe-mode-boot pattern third because its text
    says "pre-encryption".

    A stop word is refused as written, after inflection and after derivation, so that
    "executions", once it no longer stops at "execution", is not let in as "execut".
    """
    out = {}
    for compound in re.findall(r"[a-z0-9]+(?:-[a-z0-9]+)*", (text or "").lower()):
        parts = compound.split("-")
        words = ["".join(parts)] + [p for p in parts if len(p) >= 4] if len(parts) > 1 \
            else ([compound] if len(compound) >= 3 else [])
        for word in words:
            if word in C.STOPWORDS or _inflect(word) in C.STOPWORDS:
                continue
            stem = _stem(word)
            if stem not in C.STOPWORDS:
                out.setdefault(stem, word)
    return out


def _marker_text(markers):
    """The literal words of a marker list: each value, or each item of a list value, and
    any note. A regex keeps its alternatives as words, so (w3wp|httpd) yields both."""
    out = []
    for marker in markers or []:
        value = marker.get("value")
        out.extend(str(v) for v in (value if isinstance(value, list) else [value]) if v)
        if marker.get("note"):
            out.append(str(marker["note"]))
    return " ".join(out)


def whole(present, parts):
    """`present` less the halves of a split word met without the other half; see
    Matcher.shape_forms. A half the caller also wrote as a word of its own is kept."""
    for group, derived in parts:
        if not group <= present:
            present = present - derived
    return present


class Matcher:
    """Free-text ranking over the patterns, built once per run.

    The identity haystack is name, description and the pattern id's own words. The id is
    the most descriptive field this corpus has -- names are evocative by design -- and 150
    tokens appear only there: a search for lsass, dcsync, kerberoasting, impacket or
    helpdesk impersonation returned nothing although a pattern exists for each. The body is
    the logic plus the ATT&CK names of the pattern's own techniques, so "OS Credential
    Dumping" reaches the patterns citing T1003. Rarity is computed over exactly these
    haystacks rather than borrowed from consult.py, whose table drives COVERAGE verdicts
    and must not move with this.

    The context haystack is the pattern's markers and caveat, and the text of the records
    citing it: title, summary, and the citing block's logic, caveat and markers. It counts
    for CONTEXT_WEIGHT of body, with its own rarity over all three haystacks. Without it the
    matcher read only what the pattern says about itself, and the words a defender uses were
    somewhere else: "webshell", "vishing" and "mimikatz" each returned NO_MATCH and called
    itself a reportable finding, while seven patterns cite Web Shell, a Teams vishing record
    cites the helpdesk pattern and a marker names mimikatz; "w3wp" sat only in a marker.
    """

    def __init__(self, patterns, attack, citing=None, classes=None):
        self.ident, self.body, self.context = {}, {}, {}
        self.freq, self.freq_all = collections.Counter(), collections.Counter()
        self.observed, self.cites, self.fidelity, self.applies = {}, {}, {}, {}
        for pid, pattern in patterns.items():
            words = pid[4:].replace("-", " ") if pid.startswith("pat-") else pid
            self.ident[pid] = _terms(" ".join(
                str(x) for x in [pattern.get("name"), pattern.get("description"), words] if x))
            names = [(attack.get(t) or {}).get("name") or "" for t in pattern.get("technique") or []]
            self.body[pid] = _terms(" ".join([str(pattern.get("logic") or "")] + names))
            text = [str(pattern.get("caveat") or ""), _marker_text(pattern.get("markers"))]
            cited = (citing or {}).get(pid) or []
            for record, how in cited:
                text += [str((record.get("where") or {}).get("title") or ""),
                         str((record.get("what") or {}).get("summary") or ""),
                         str(how.get("logic") or ""), str(how.get("caveat") or ""),
                         _marker_text(how.get("markers"))]
            self.context[pid] = _terms(" ".join(text)) - self.ident[pid] - self.body[pid]
            self.observed[pid] = len({record["id"] for record, _ in cited})
            self.freq.update(self.ident[pid] | self.body[pid])
            self.freq_all.update(self.ident[pid] | self.body[pid] | self.context[pid])
            self.cites[pid] = {t.upper() for t in pattern.get("technique") or []}
            self.fidelity[pid] = pattern.get("fidelity")
            # What the pattern applies to, in the corpus's own class vocabulary: the class id's
            # words and its description in vocab.json. Read only by the behaviour slot, to ask
            # whether a pattern is about the thing a shape names: network.router is described
            # as an "edge routing platform" and network.firewall as a "firewall appliance".
            self.applies[pid] = _terms(" ".join(
                "{} {}".format(k.split(".", 1)[-1].replace("_", " "), (classes or {}).get(k) or "")
                for k in pattern.get("applies_to_classes") or []))
        self.total = max(1, len(patterns))
        # The words of every live ATT&CK name a pattern cites, directly or through a
        # sub-technique of it, so that a shape can be read for the behaviour it names in
        # ATT&CK's own words.
        cited = set().union(*self.cites.values()) if self.cites else set()
        parents = {t.split(".")[0] for t in cited}
        self.attack = attack
        self.named_by = collections.defaultdict(set)
        for tid, entry in attack.items():
            if entry.get("revoked") or entry.get("deprecated"):
                continue
            if tid in cited or tid in parents:
                for stem in _terms(entry.get("name") or ""):
                    self.named_by[stem].add(tid)

    def weight(self, token):
        return 1.0 / (1 + self.freq.get(token, 0))

    def weight_context(self, token):
        return CONTEXT_WEIGHT / (1 + self.freq_all.get(token, 0))

    def known(self, stem):
        return stem in self.freq_all

    def shape_forms(self, shape):
        """({stem: the caller's word}, {stem: the positions of the caller's words it came
        from}, [(a split word's two halves, the halves only the split put there)]) for a
        shape, with its compounds resolved both ways.

        Two adjacent words whose join is a word the corpus holds are also read joined, so
        "DC sync" meets dcsync where it met only "sync" and ranked three unrelated sync
        patterns above the DCSync one. A word the corpus holds on at most RARE_TOKEN_SHARE of
        its patterns, or not at all, is also split where both halves are words it holds, so
        "webshell" meets "web shell". Both are resolved against the haystacks, never against
        a list of synonyms, so nothing here is fitted to a phrase. A split word's halves are
        met only together (whole()), including a word the corpus already holds whole, such as
        "helpdesk", which is also written "help desk".
        """
        forms, origin, parts = {}, {}, []
        units = re.findall(r"[a-z0-9]+(?:-[a-z0-9]+)*", (shape or "").lower())
        for i, unit in enumerate(units):
            for stem, word in _term_forms(unit).items():
                forms.setdefault(stem, word)
                origin.setdefault(stem, set()).add(i)
        for i, (first, second) in enumerate(zip(units, units[1:])):
            joined = first + second
            if "-" in joined or len(joined) < 5 or joined in C.STOPWORDS:
                continue
            stem = _stem(joined)
            if self.known(stem):
                forms.setdefault(stem, "{} {}".format(first, second))
                origin.setdefault(stem, set()).update((i, i + 1))
        for i, word in enumerate(units):
            if "-" in word or len(word) < 6 or word in C.STOPWORDS \
                    or self.freq_all.get(_stem(word), 0) > RARE_TOKEN_SHARE * self.total:
                continue
            for cut in range(3, len(word) - 2):
                head, tail = word[:cut], word[cut:]
                if head in C.STOPWORDS or tail in C.STOPWORDS:
                    continue
                if all(self.known(_stem(p)) for p in (head, tail)):
                    derived = set()
                    for part in (head, tail):
                        if _stem(part) not in forms:
                            forms[_stem(part)] = "{} (in {})".format(part, word)
                            derived.add(_stem(part))
                        origin.setdefault(_stem(part), set()).add(i)
                    # Both halves, and the ones that are in the shape only because of the split.
                    parts.append((frozenset(_stem(p) for p in (head, tail)), frozenset(derived)))
                    break
        return forms, origin, parts

    def match(self, shape, limit, spelled=()):
        """(up to `limit` (score, pid, overlap-by-weight, slot) for one shape best first, the
        number of patterns that overlapped it before the cut).

        The overlap is reported in the caller's own words, not as stems, rarest first, so
        the token that decided the match cannot be the one a six-token cut drops. The count
        before the cut is returned so SHAPE_RESULT can say what --per-shape left out: the
        edge-appliance exploitation patterns sat just below a cut of three with nothing
        saying they existed. `slot` is None, or what behaviour_slot() kept the guess for;
        `spelled` is the ATT&CK ids the shape spells by id or whole name (AttackIndex.spotted).
        """
        forms, origin, parts = self.shape_forms(shape)
        tokens = set(forms)
        asked = set().union(*origin.values()) if origin else set()
        scored = []
        for pid in self.ident:
            ident, body, context = self.ident[pid], self.body[pid], self.context[pid]
            present = tokens & (ident | body | context)
            # The halves of a split word are met only together. "helpdesk impersonation" filled
            # its second and third slots with patterns meeting "help (in helpdesk)" and "desk
            # (in helpdesk)" alone, because the halves counted one at a time.
            present = whole(present, parts)
            hit_i = present & ident
            hit_b = (present & body) - ident
            hit_c = (present & context) - ident - body
            loose = hit_b | hit_c
            rare = [w for w in loose if self.freq_all.get(w, 0) <= RARE_TOKEN_SHARE * self.total]
            if not (hit_i or len(loose) >= 2 or rare):
                continue
            overlap = hit_i | loose
            if len(overlap) == 1:
                only = next(iter(overlap))
                if (self.freq if only in ident | body else self.freq_all).get(only, 0) \
                        > COMMON_TOKEN_SHARE * self.total:
                    continue
            # Identity counts for three times body, and context for CONTEXT_WEIGHT of it: a
            # pattern's name and id say what it is, its logic mentions many things in
            # passing, and its records mention more. Normalised by the pattern's own length,
            # not its records', so neither a verbose pattern nor a much-cited one wins on
            # volume alone.
            raw = 3.0 * sum(self.weight(w) for w in hit_i) + sum(self.weight(w) for w in hit_b) \
                + sum(self.weight_context(w) for w in hit_c)
            # Scaled by the share of the caller's words it met, a word met only in context
            # counting CONTEXT_WEIGHT: "IIS spawning cmd.exe" ranked a logging-module pattern
            # first on "iis" alone, over the one pattern meeting all four words.
            strong = set().union(*(origin[w] for w in hit_i | hit_b)) if hit_i | hit_b else set()
            weak = set().union(*(origin[w] for w in hit_c)) - strong if hit_c else set()
            met = (len(strong) + CONTEXT_WEIGHT * len(weak)) / len(asked) if asked else 1.0
            score = raw * 100 / (1 + len(ident | body) ** 0.5) * _coverage(met)
            scored.append((score, len(overlap), pid, [forms[w] for w in sorted(
                overlap, key=lambda w: (-self.weight(w) if w in ident | body
                                        else -self.weight_context(w), w))]))
        # A tie goes to the pattern matching more of the shape's words, then to the one more
        # records cite, and only then to the id: "IIS spawning cmd.exe" ranked
        # pat-print-spooler-abuse first on the alphabet, tied with pat-webserver-spawns-shell.
        scored.sort(key=lambda item: (-round(item[0], 6), -item[1], -self.observed[item[2]],
                                      item[2]))
        top = [(score, pid, overlap, None) for score, _, pid, overlap in scored[:limit]]
        if limit >= BEHAVIOUR_SLOT_FROM and len(scored) >= limit:
            kept = self.behaviour_slot(forms, origin, parts, scored, limit, spelled)
            if kept:
                top[-1] = kept
        return top, len(scored)

    def named(self, forms, spelled=()):
        """{technique id: the caller's words naming it} for the behaviour a shape names.

        A shape that spells an id or a whole ATT&CK name (`spelled`) names that technique and
        no other: "pass the hash" is T1550.002, which no pattern cites, and not Pass the Ticket
        by its first word. Otherwise each word names the live techniques whose ATT&CK name
        carries it and some pattern cites, directly or through a sub-technique.
        """
        out = collections.defaultdict(set)
        live = [t for t in spelled
                if (self.attack.get(t) or {}) and not self.attack[t].get("revoked")
                and not self.attack[t].get("deprecated")]
        if live:
            for tid in live:
                terms = _terms(self.attack[tid].get("name") or "")
                if any(c == tid or c.startswith(tid + ".") for cites in self.cites.values()
                       for c in cites):
                    typed = {tid.lower()} | set(tid.lower().split("."))
                    out[tid] = {forms[w] for w in terms | typed if w in forms} or {tid}
            return out
        for stem, word in forms.items():
            for tid in self.named_by.get(stem, ()):
                out[tid].add(word)
        return out

    def _cites_named(self, pid, named):
        return sorted(t for t in named
                      if any(c == t or c.startswith(t + ".") for c in self.cites[pid]))

    def behaviour_slot(self, forms, origin, parts, scored, limit, spelled=()):
        """The guess kept in the last slot for the behaviour the shape names, or None.

        Rarity rightly lets a rare word decide a ranking, and it let the thing a shape is about
        outrank what is done to it: "exploitation of edge network appliances" returned three
        patterns named for edge appliances, integrity, reboots and a trusted proxy, none of
        them an exploitation, and the patterns detecting exploitation of an appliance ranked
        eighth to fourteenth, cut. Rarity cannot separate the two readings, because "edge" is
        on 8 patterns and "exploit" on 85: this corpus is about exploited edge devices.
        ATT&CK can, because the behaviour is what it names: "exploitation" names Exploit
        Public-Facing Application and the other Exploitation techniques, and "edge" and
        "appliances" name none.

        So when no guess above the last slot cites a technique the shape names (named()), and
        the last guess is not itself such a detection, the last slot goes to the highest
        ranked candidate that is: detection-grade (DETECTION_GRADE), citing a technique the
        shape names, and meeting every other word of the shape in its name, description, id,
        logic or classes, so that it is about the whole shape and not only its behaviour.
        Its MATCH_BASIS says why it is there. An earlier slot kept the last guess for any word
        of the shape the guesses above did not meet in their names; it fired on "pass", "made"
        and "implant" in shapes that were not about them, displaced a relevant third guess
        twice, and filled the edge-appliance slot with an inventory pattern. Asking for one
        other word rather than every one fired on the object words ATT&CK names also carry,
        "device", "deploy" and "copy", and displaced a network-device configuration pattern
        for "configuration change on a network device".
        """
        named = self.named(forms, spelled)
        if not named or any(self._cites_named(pid, named) for _, _, pid, _ in scored[:limit - 1]):
            return None
        tokens = set(forms)
        asked = set().union(*origin.values()) if origin else set()

        def fit(pid):
            """(the named techniques it cites, the stems meeting the shape's other words), or
            None. Read by the caller's word, not the stem, so a split or joined word is met by
            either of its forms."""
            cited = self._cites_named(pid, named)
            if self.fidelity.get(pid) not in DETECTION_GRADE or not cited:
                return None
            words = set().union(*(named[t] for t in cited))
            naming = {w for w in tokens if forms[w] in words}
            other = asked - set().union(set(), *(origin[w] for w in naming))
            present = whole(tokens & (self.ident[pid] | self.body[pid] | self.applies[pid]),
                            parts) - naming
            met = set().union(set(), *(origin[w] for w in present))
            if not other or not other <= met:
                return None
            return cited, {w for w in present if origin[w] & other}

        if fit(scored[limit - 1][2]):
            return None
        best = None
        for rank, (score, _, pid, overlap) in enumerate(scored[limit:], limit):
            found = fit(pid)
            if found:
                best = (score, pid, overlap, rank, found)
                break
        if best is None:
            return None
        score, pid, overlap, rank, (cited, objects) = best
        return (score, pid, overlap, {
            "techniques": cited,
            "naming": sorted(set().union(*(named[t] for t in cited))),
            "objects": sorted(forms[w] for w in objects),
            "fidelity": self.fidelity[pid],
            "rank": rank + 1,
            "of": len(scored),
            "labels": ["{} ({})".format(t, (self.attack.get(t) or {}).get("name") or "?")
                       for t in cited]})


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


class AttackIndex:
    """What each requested ATT&CK id selects, and what the reference says about the id.

    Built once, so the header line for an id, the selection it makes and a SUGGEST_ATTACK
    pointer at it can never disagree about how many patterns it reaches.
    """

    def __init__(self, patterns, records, attack, reference_version, expand=True):
        self.attack, self.version, self.expand = attack, reference_version or "?", expand
        self.cites = {pid: {t.upper() for t in (p.get("technique") or [])}
                      for pid, p in patterns.items()}
        self.how_cites = collections.defaultdict(list)
        for record in records:
            for how in record.get("how") or []:
                for tid in how.get("technique") or []:
                    self.how_cites[tid.upper()].append((record, how))
        # Every name of a live id, for spotting one typed as free text. A name can belong to
        # more than one id (117 do), which is why a name only ever suggests, never selects.
        self.names = collections.defaultdict(list)
        for tid, entry in attack.items():
            name = (entry.get("name") or "").strip()
            if name and self.live(tid) and (len(name) >= 8 or len(name.split()) >= 2):
                self.names[name.lower()].append(tid)

    def live(self, tid):
        entry = self.attack.get(tid)
        return bool(entry) and not entry.get("revoked") and not entry.get("deprecated")

    def name(self, tid):
        return (self.attack.get(tid) or {}).get("name")

    def direct(self, tid):
        return sorted(pid for pid, cites in self.cites.items() if tid in cites)

    def subs(self, tid):
        """Patterns citing a sub-technique of live parent `tid` and not `tid` itself."""
        if "." in tid or not self.expand or not self.live(tid):
            return []
        prefix = tid + "."
        return sorted(pid for pid, cites in self.cites.items()
                      if tid not in cites and any(c.startswith(prefix) for c in cites))

    def replacement(self, tid):
        """MITRE's live replacement for a revoked id, or None."""
        entry = self.attack.get(tid) or {}
        new = entry.get("replaced_by") if entry.get("revoked") else None
        return new if new and self.live(new) else None

    def followed(self, tid):
        """[(replacement, revoked id)]: what a request for `tid` follows, one per replacement.

        MITRE's replacement for `tid` itself first; then, for a revoked parent being expanded,
        each of its revoked sub-techniques' replacements. A revoked id is read in the taxonomy
        it came from, where a parent held its sub-techniques: T1562's ten went to T1685,
        T1685.001-.004, T1686 and its two, T1688, T1689 and T1690. A live parent is read in the
        current one, and is not followed into sub-techniques ATT&CK has since moved out of it.
        """
        out, seen = [], set()
        new = self.replacement(tid)
        if new:
            out.append((new, tid))
            seen.add(new)
        entry = self.attack.get(tid) or {}
        if "." not in tid and self.expand and entry.get("revoked"):
            for sub in sorted(t for t in self.attack if t.startswith(tid + ".")):
                moved = self.replacement(sub)
                if moved and moved not in seen:
                    out.append((moved, sub))
                    seen.add(moved)
        return out

    def parts(self, tid):
        """(cite it, cite a sub-technique of it, cite a replacement it follows, cite a
        sub-technique of such a replacement): what `--attack tid` selects, by how, each list
        disjoint from those before it, so the four sum to selects()."""
        direct = set(self.direct(tid))
        subs = set(self.subs(tid)) - direct
        follows = [new for new, _ in self.followed(tid)]
        repl = set(pid for new in follows for pid in self.direct(new)) - direct - subs
        under = set(pid for new in follows for pid in self.subs(new)) - direct - subs - repl
        return sorted(direct), sorted(subs), sorted(repl), sorted(under)

    def describe(self, tid):
        """(selected pattern count, the text after '<id> -> ') for one requested id."""
        entry = self.attack.get(tid)
        direct = self.direct(tid)
        if entry is None:
            text = "not an id in the shipped ATT&CK {} reference (enterprise, ics, mobile)".format(
                self.version)
            return len(direct), text + (", but {} pattern(s) cite it".format(len(direct))
                                        if direct else "")
        if entry.get("revoked"):
            new = self.replacement(tid)
            follows = self.followed(tid)
            if follows:
                own, subs, repl, under = self.parts(tid)
                reached = len(own) + len(subs) + len(repl) + len(under)
                text = ("REVOKED in ATT&CK {}, replaced by {} ({}): followed, {} pattern(s)".format(
                    self.version, new, self.name(new), reached) if new else
                    "REVOKED in ATT&CK {}, no replacement recorded for it; its revoked "
                    "sub-techniques followed, {} pattern(s)".format(self.version, reached))
                cites_new = set(self.direct(new)) if new else set()
                family = sorted(moved for moved, old in follows if old != tid)
                parts = []
                if new:
                    parts.append("{} cite {}".format(len(cites_new | set(own)), new))
                if family:
                    parts.append("{} cite the replacement of one of its own revoked "
                                 "sub-techniques ({})".format(
                                     len([pid for pid in repl if pid not in cites_new]),
                                     ", ".join(family)))
                parents = [moved for moved, _ in follows if "." not in moved]
                if self.expand and parents:
                    parts.append("{} cite {} sub-technique of {}".format(
                        len(under), "a" if parents == [new] else "only a",
                        "it" if parents == [new] else "one of them"))
                text += ": " + ", ".join(parts) if parts else ""
                if not self.expand and new and "." not in new:
                    text += "; sub-techniques of {}{} not followed (--attack-exact)".format(
                        new, ", and {}'s own revoked sub-techniques,".format(tid)
                        if "." not in tid else "")
                return reached, text
            dead = entry.get("successor_deprecated")
            return len(direct), "REVOKED in ATT&CK {}, {}; nothing followed{}".format(
                self.version,
                "its successor {} is deprecated".format(dead) if dead
                else "no replacement recorded",
                ", {} pattern(s) cite it".format(len(direct)) if direct else "")
        if entry.get("deprecated"):
            return len(direct), "DEPRECATED in ATT&CK {}, no replacement{}".format(
                self.version, ", {} pattern(s) cite it".format(len(direct)) if direct else "")
        subs = self.subs(tid)
        text = "{} pattern(s): {} cite it".format(len(direct) + len(subs), len(direct))
        if "." not in tid:
            text += (", {} cite a sub-technique of it".format(len(subs)) if self.expand
                     else "; sub-techniques not expanded (--attack-exact)")
        return len(direct) + len(subs), text

    def label(self, tid):
        name = self.name(tid)
        return "{} ({})".format(tid, name) if name else tid

    def selects(self, tid):
        """Every pattern `--attack tid` selects: its own citers, its sub-techniques' where it
        is a live parent being expanded, the citers of every replacement it follows, and of
        their sub-techniques where one is a live parent being expanded."""
        return set(pid for part in self.parts(tid) for pid in part)

    def record_only(self, tid):
        """How-blocks citing `tid` (or what it stands for) whose pattern `tid` does not select.

        Filtered on the selection, not only reported when it is empty. The line printed only
        when an id selected nothing, so `--attack T1190` returned 50 patterns and said nothing
        of the 21 T1190 how-blocks under 12 patterns that do not list it, seven of whose records
        -- four of them exploitation of a management interface -- appeared nowhere in the answer.
        """
        targets = {tid}
        for new, _ in self.followed(tid):
            targets.add(new)
            if "." not in new and self.expand:
                targets |= {t for t in self.how_cites if t.startswith(new + ".")}
        if "." not in tid and self.expand and self.live(tid):
            targets |= {t for t in self.how_cites if t.startswith(tid + ".")}
        selected, blocks, counted = self.selects(tid), [], set()
        for t in sorted(targets):
            for r, h in self.how_cites.get(t, []):
                # A block citing two sub-techniques of one parent is one block.
                if id(h) not in counted and h.get("pattern_id") not in selected:
                    counted.add(id(h))
                    blocks.append((r, h))
        pids = sorted({h.get("pattern_id") for _, h in blocks if h.get("pattern_id")})
        loose = sum(1 for _, h in blocks if not h.get("pattern_id"))
        return blocks, pids, loose

    def record_only_ids(self, tid, blocks):
        """{id the blocks cite: how many cite it}, over the ids `tid` reaches. A parent's line
        said "cite it" of blocks citing only a sub-technique, and a revoked id's of blocks
        citing only its replacement."""
        targets = {tid} | {new for new, _ in self.followed(tid)}
        reach = [t for t in targets if "." not in t and self.expand
                 and (self.live(t) or t != tid)]
        counted = collections.Counter()
        for _, h in blocks:
            for t in sorted({c.upper() for c in h.get("technique") or []}):
                if t in targets or any(t.startswith(p + ".") for p in reach):
                    counted[t] += 1
        return counted

    def spotted(self, shape):
        """ATT&CK ids in a free-text shape: typed as ids, or named by a live name."""
        found = []
        for token in re.findall(r"[A-Za-z0-9.]+", shape):
            token = token.strip(".").upper()
            if C.TECH_ID.match(token) and token not in found:
                found.append(token)
        text, spans = shape.lower(), []
        for name, tids in self.names.items():
            for m in re.finditer(r"(?<![a-z0-9]){}(?![a-z0-9])".format(re.escape(name)), text):
                spans.append((m.start(), m.end(), tids))
        # A name inside a longer matched name is the longer name's word, not a second hit.
        for start, end, tids in sorted(spans, key=lambda s: (s[0], -(s[1] - s[0]))):
            if any(a <= start and end <= b and (a, b) != (start, end) for a, b, _ in spans):
                continue
            for tid in sorted(tids):
                if tid not in found:
                    found.append(tid)
        return found


def select_attack(requested, index, seen):
    """Findings for --attack, direct citations first, then sub-techniques, then replacements.

    Each pattern is labelled with the ids it actually cites, not with everything that was
    asked for. Announcing the whole --attack set over a pattern citing one of them is how a
    caller ends up citing a technique the corpus never connected to it. Grouped by that
    label so the banner still changes once per set rather than per pattern.
    """
    want = set(requested)
    # Only a live parent expands: a revoked one is followed to its replacement instead, and
    # an id the reference does not carry is selected on exact citation alone.
    parents = {t for t in requested if "." not in t and index.live(t)} if index.expand else set()
    followed = collections.defaultdict(list)
    for tid in requested:
        for new, old in index.followed(tid):
            # A revoked sub-technique followed for its parent says so: it was not asked for.
            followed[new].append(old if old == tid else
                                 "{}, a sub-technique of requested {}".format(old, tid))
    # A followed replacement is answered as --attack <replacement> would be.
    expanding = {new for new in followed if "." not in new} if index.expand else set()
    picked = []
    for pid, cites in sorted(index.cites.items()):
        if pid in seen:
            continue
        hit = sorted(want & cites)
        sub = sorted(c for c in cites if "." in c and c.split(".")[0] in parents)
        repl = sorted(c for c in cites if c in followed)
        under = sorted(c for c in cites if "." in c and c.split(".")[0] in expanding
                       and c not in followed)
        if hit:
            picked.append((0, "SELECTION: cites {}".format(", ".join(hit)), pid,
                           BY_ATTACK_ID, tuple(hit)))
        elif sub:
            picked.append((1, "SELECTION: cites {} ({} of requested {})".format(
                ", ".join(sub), "sub-techniques" if len(sub) > 1 else "sub-technique",
                ", ".join(sorted({c.split(".")[0] for c in sub}))), pid,
                BY_ATTACK_SUB, (tuple(sub), tuple(sorted({c.split(".")[0] for c in sub})))))
        elif repl:
            olds = tuple(old for c in repl for old in followed[c])
            pairs = tuple((c, tuple(followed[c])) for c in repl)
            picked.append((2, "SELECTION: cites {} (MITRE's replacement for revoked {})".format(
                ", ".join(repl), ", ".join(olds)) if len(repl) == 1 else
                "SELECTION: cites {}".format(replacement_pairs(pairs)), pid,
                BY_ATTACK_REPLACEMENT, (tuple(repl), olds, pairs)))
        elif under:
            news = tuple(sorted({c.split(".")[0] for c in under}))
            olds = tuple(old for new in news for old in followed[new])
            picked.append((3, "SELECTION: cites {} ({} of {}, MITRE's replacement for revoked "
                           "{})".format(", ".join(under), "sub-techniques" if len(under) > 1
                                        else "sub-technique", ", ".join(news), ", ".join(olds)),
                           pid, BY_ATTACK_REPLACEMENT_SUB, (tuple(under), news, olds)))
        else:
            continue
        seen.add(pid)
    return [Finding(banner, 0.0, pid, basis, detail)
            for _, banner, pid, basis, detail in sorted(picked)]


def replacement_pairs(pairs):
    """'T1685 (MITRE's replacement for revoked T1562) and T1685.001 (... for revoked ...)':
    a pattern citing two replacements says which revoked id each one stands for."""
    return " and ".join("{} (MITRE's replacement for revoked {})".format(new, "; ".join(olds))
                        for new, olds in pairs)


def match_basis(finding):
    """The MATCH_BASIS text, dispatched on the basis rather than on the detail's type."""
    if finding.basis == BY_PATTERN_ID:
        return "selected exactly by pattern id"
    if finding.basis == BY_ATTACK_ID:
        return "selected exactly by ATT&CK id"
    if finding.basis == BY_ATTACK_SUB:
        cited, parents = finding.detail
        return ("selected by {}, {} of requested {} - the pattern does not cite the parent "
                "itself".format(", ".join(cited), "sub-techniques" if len(cited) > 1
                                else "a sub-technique", ", ".join(parents)))
    if finding.basis == BY_ATTACK_REPLACEMENT:
        new, old, pairs = finding.detail
        if len(new) > 1:
            return "selected via {}".format(replacement_pairs(pairs))
        return "selected via {}, MITRE's replacement for revoked {}".format(
            ", ".join(new), ", ".join(old))
    if finding.basis == BY_ATTACK_REPLACEMENT_SUB:
        cited, news, old = finding.detail
        return ("selected by {}, {} of {}, MITRE's replacement for revoked {} - the pattern "
                "cites neither the replacement nor the revoked id".format(
                    ", ".join(cited), "sub-techniques" if len(cited) > 1 else "a sub-technique",
                    ", ".join(news), ", ".join(old)))
    overlap, slot = finding.detail
    return ("free-text overlap on {}{} (score {:.1f}){} - VERIFY THIS IS THE RIGHT PATTERN "
            "BEFORE CITING IT".format(
                ", ".join(overlap[:6]),
                " (+{} more)".format(len(overlap) - 6) if len(overlap) > 6 else "",
                finding.score, behaviour_basis(slot) if slot else ""))


def behaviour_basis(slot):
    """The MATCH_BASIS clause for a guess Matcher.behaviour_slot kept."""
    return ("; kept for the behaviour the shape names: it cites {}, which {} names and no guess "
            "above it cites, it detects ({}), and its name, logic or classes meet {}; {} of {} "
            "on overlap alone - --attack {} selects every pattern citing {}".format(
                ", ".join(slot["labels"]), ", ".join(slot["naming"]), slot["fidelity"],
                ", ".join(slot["objects"]), slot["rank"], slot["of"],
                ",".join(slot["techniques"]), "it" if len(slot["techniques"]) == 1 else "them"))


def observed_locus(cited, pattern, locus_map, order):
    """(Counter of how-block loci, the unanimous locus or None, per-record loci) for a
    pattern's citing blocks, each placed exactly as consult.py places that finding."""
    per_block, per_record = collections.Counter(), collections.defaultdict(list)
    for record, how in cited:
        locus = C.locus_for(record, how, pattern, locus_map)[0]
        per_block[locus] += 1
        if locus not in per_record[record["id"]]:
            per_record[record["id"]].append(locus)
    unanimous = next(iter(per_block)) if len(per_block) == 1 else None
    for rid in per_record:
        per_record[rid].sort(key=lambda value: order.index(value) if value in order else 99)
    return per_block, unanimous, per_record


def pattern_locus(pattern, cited, locus_map, order):
    """(LOCUS, LOCUS_SPAN, LOCUS_BASIS, LOCUS_OBSERVED) for one pattern.

    LOCUS stays the class derivation: it is where the pattern applies, and it is the same
    whatever was asked. But a pattern with citing records is not without an incident behind
    it, which is what this once assumed: pat-audit-policy-tampering printed ENDPOINT, from
    endpoint.os listed first, while its only citing record is a CloudTrail incident placed on
    MANAGEMENT, and nothing on its block said so. For 147 of the 441 cited patterns no citing
    block sits on the printed locus at all, and MANAGEMENT is the plane most often hidden: 92
    patterns have a citing block there that their LOCUS does not show.

    LOCUS_OBSERVED now counts where the citing blocks sit, placed as consult.py places them,
    and when every one of them agrees on a locus other than the primary, that locus is the
    span, as `observed span`, ahead of the class list's own span source. A split is never a
    span, on the rule consult.py holds for a class list. There is still no quota: advise.py
    returns what the caller selected, and reordering it to balance an axis would answer a
    question nobody asked.
    """
    primary, span, basis = C.locus_for(None, None, pattern, locus_map)
    per_block, unanimous, _ = observed_locus(cited, pattern, locus_map, order)
    records = len({record["id"] for record, _ in cited})
    if not cited:
        observed = "none - no citing record"
        signal = "-"
    else:
        observed = "{} (over {} citing how-block(s) in {} record(s), placed as consult.py " \
                   "places them)".format(
                       ", ".join("{}={}".format(k, per_block[k]) for k in order if per_block.get(k)),
                       sum(per_block.values()), records)
        signal = ("{} (unanimous over {} citing how-block(s))".format(unanimous, sum(per_block.values()))
                  if unanimous else "split")
    if unanimous and unanimous != primary:
        span = unanimous
        # locus_for never puts ';' inside a field, so the span-source field is replaced whole.
        basis = re.sub(r"span-source=[^;]*", "span-source=observed span: {} citing "
                       "how-block(s)".format(sum(per_block.values())), basis)
    basis += "; observed-signal={}".format(signal)
    return primary, ", ".join([primary] + ([span] if span else [])), basis, observed


def citing_impacts(cited):
    """The impact of the distinct non-seed records citing a pattern, and how many there are."""
    impacts, counted, seed = set(), set(), set()
    for record, _ in cited:
        if (record.get("status") or "").lower() == "seed":
            seed.add(record["id"])
            continue
        counted.add(record["id"])
        impacts.update((record.get("what") or {}).get("impact") or [])
    return sorted(impacts), len(counted), len(seed)


def doctrine_basis(counted, seed):
    if counted:
        # The seed records are excluded from the impact match, and said to be: OBSERVED
        # counted 7 records where this counted 6 with no word of the seventh.
        return ("this pattern's applies_to_classes or the impact of its {} citing "
                "record(s){}".format(counted, " (and not of its {} seed record(s))".format(seed)
                                     if seed else ""))
    if seed:
        return ("this pattern's applies_to_classes (its {} citing record(s) are seed, so "
                "impact is not assessed)".format(seed))
    return "this pattern's applies_to_classes (no citing record, so impact is not assessed)"


def main():
    ap = argparse.ArgumentParser(
        description="Answer a behaviour-shaped consultation in one invocation.")
    ap.add_argument("shapes", nargs="*", default=[],
                    help="free-text behaviours, one per argument. Best-effort ranking only; "
                         "prefer --patterns or --attack when the pattern is known.")
    ap.add_argument("--patterns", default=None,
                    help="comma-separated pattern ids, selected exactly")
    ap.add_argument("--attack", default=None,
                    help="comma-separated ATT&CK ids; every pattern citing one is selected, a "
                         "parent also selects the patterns citing its sub-techniques, and a "
                         "revoked id is followed to MITRE's replacement")
    ap.add_argument("--attack-exact", action="store_true",
                    help="do not expand a parent --attack id to its sub-techniques")
    ap.add_argument("--corpus", default=CORPUS)
    ap.add_argument("--per-shape", type=int, default=3,
                    help="patterns to report per shape, 1 or more; from 3, the last is kept "
                         "for a detection of the behaviour the shape names in ATT&CK's words "
                         "when no guess above it cites that behaviour")
    ap.add_argument("--have", default=None,
                    help="evidence types the caller collects, from the 21 in "
                         "corpus/schema/vocab.json; any other value is refused and named")
    ap.add_argument("--no-verify", action="store_true",
                    help="use the URL cache only; do not fetch anything")
    args = ap.parse_args()
    # A negative value was a slice from the end, so --per-shape -1 returned every match but
    # one, and 0 printed "no pattern overlapped any shape" over shapes that matched.
    refused = Q.below_floor(args, (("--per-shape", 1),))
    if refused:
        print(refused, file=sys.stderr)
        return 2

    vocab = C.load_vocab(args.corpus)
    # advise.py takes no coverage, so the refusal names both routes: --attack selects by the
    # id, which is the opposite of declaring it covered, and consult.py --covered declares it.
    have, have_rejected = C.parse_have(args.have, vocab,
                                       "--attack to select by it, or consult.py --covered to "
                                       "declare it covered")
    for value, why in have_rejected:
        print("WARNING: --have value refused: {} ({})".format(value, why), file=sys.stderr)
    unassessed = C.REJECTED_INVENTORY if have_rejected and have is None else C.NO_INVENTORY
    records, patterns, aliases, citing = load(args.corpus)
    d3fend = C.load_d3fend(args.corpus)
    doctrine = C.load_doctrine(args.corpus)
    locus_map = C.load_locus_map(args.corpus)
    order = list(locus_map.get("locus_order") or [])
    attack = C.load_attack(args.corpus)
    reference_version = None
    ref_path = os.path.join(args.corpus, "reference", "attack-techniques.json")
    if os.path.exists(ref_path):
        with open(ref_path, encoding="utf-8") as h:
            reference_version = json.load(h).get("version")
    index = AttackIndex(patterns, records, attack, reference_version, not args.attack_exact)

    findings, seen, rejected = [], set(), []
    if args.patterns:
        for pid in [x.strip() for x in args.patterns.split(",") if x.strip()]:
            if pid in patterns and pid not in seen:
                seen.add(pid)
                findings.append(Finding("SELECTION: exact pattern id", 0.0, pid, BY_PATTERN_ID, None))
            elif pid not in patterns:
                why = ("an ATT&CK id - use --attack" if C.TECH_ID.match(pid)
                       else "no such pattern id")
                rejected.append("{} ({})".format(pid, why))
                print("WARNING: {}: {}".format(why, pid), file=sys.stderr)
    requested = []
    if args.attack:
        for tid in [x.strip().upper() for x in args.attack.split(",") if x.strip()]:
            if tid not in requested:
                requested.append(tid)
        findings.extend(select_attack(requested, index, seen))

    # Every shape gets a banner, matched or not. A shape that matched nothing used to add
    # nothing, so it vanished from the answer without a trace, and a match already shown
    # under an earlier selection was dropped with no word to the shape that found it.
    matcher = Matcher(patterns, attack, citing, vocab.get("product_class")) if args.shapes \
        else None
    shape_notes = []
    for shape in args.shapes:
        fresh, repeated = [], []
        top, overlapped = matcher.match(shape, args.per_shape, index.spotted(shape))
        for score, pid, overlap, slot in top:
            if pid in seen:
                repeated.append(pid)
                continue
            seen.add(pid)
            fresh.append(Finding("SELECTION: free-text-guess -- {}".format(shape),
                                 score, pid, BY_FREE_TEXT, (overlap, slot)))
        findings.extend(fresh)
        notes = []
        if not fresh and not repeated:
            notes.append("SHAPE_RESULT: no pattern overlapped this shape")
        else:
            # The cut is counted: "3 new" over twenty overlapping candidates hid the
            # exploitation patterns ranked just below it.
            notes.append("SHAPE_RESULT: {} new, {} already shown above{}; {} pattern(s) "
                         "overlapped this shape, {}".format(
                             len(fresh), len(repeated),
                             " ({})".format(", ".join(repeated)) if repeated else "",
                             overlapped,
                             "{} cut by --per-shape {}".format(overlapped - len(top), args.per_shape)
                             if overlapped > len(top) else "none cut"))
        # An ATT&CK id typed as text, or a technique named by its ATT&CK name, is pointed at
        # the exact path. Never selected from: a name can belong to more than one id.
        for tid in index.spotted(shape):
            _, text = index.describe(tid)
            notes.append("SUGGEST_ATTACK: {} - --attack {} -> {}".format(index.label(tid), tid, text))
        shape_notes.append(("SELECTION: free-text-guess -- {}".format(shape), fresh, notes))

    # Each pattern's distinct citing records, newest first and then by id; undated last.
    newest = {f.pid: sorted({r["id"]: r for r, _ in citing[f.pid]}.values(),
                            key=lambda r: (-(C.published(r) or datetime.date.min).toordinal(),
                                           r["id"]))
              for f in findings}
    shown = {pid: ordered[:OBSERVED_LINES] for pid, ordered in newest.items()}

    urls = set()
    for f in findings:
        for record in shown[f.pid]:
            if record["where"].get("disclosure") == "public" and record["where"].get("url"):
                urls.add(record["where"]["url"])
        for _, u in attack_urls(patterns[f.pid], None):
            urls.add(u)
    cache, fetched, unreachable = liveness(sorted(urls), not args.no_verify, args.corpus)

    # The headline count is what came back, not what was asked for. This printed
    # len(args.shapes) until 0.11.1, so every exact selection announced "SHAPES: 0" over
    # the findings it went on to print -- `--attack T1190` returned 48 patterns under a
    # header saying nothing matched. A caller is told to read the header before the
    # findings, so the one line it reads first denied the answer underneath it. Every basis
    # is counted explicitly: the free-text column was once the remainder, so any new basis
    # would have been tallied as a guess.
    tally = collections.Counter(f.basis for f in findings)
    print("=== CONSULTATION (behaviour shapes) ===")
    print("CORPUS: {} records, {} patterns".format(len(records), len(patterns)))
    print("FINDINGS: {} pattern(s) returned".format(len(findings)))
    print("SELECTED_BY: exact pattern id {}, exact ATT&CK id {}, free-text guess {} "
          "across {} shape(s) asked; of the ATT&CK selections, {} cite a requested id, {} "
          "cite a sub-technique of a requested parent, {} cite MITRE's replacement for a "
          "revoked id, {} cite a sub-technique of such a replacement".format(
              tally[BY_PATTERN_ID], sum(tally[b] for b in ATTACK_BASES), tally[BY_FREE_TEXT],
              len(args.shapes), tally[BY_ATTACK_ID], tally[BY_ATTACK_SUB],
              tally[BY_ATTACK_REPLACEMENT], tally[BY_ATTACK_REPLACEMENT_SUB]))
    # What happened to each id the caller typed, on stdout. Rejections went to stderr only,
    # so a mixed list printed a clean FINDINGS over the ids it had silently dropped.
    print("PATTERNS_REJECTED: {}".format("; ".join(rejected) or "none"))
    if not requested:
        print("ATTACK_REQUESTED: none")
    returned = {f.pid for f in findings}
    for tid in requested:
        count, text = index.describe(tid)
        # Whenever such blocks exist, not only when the id selected nothing: silence here read
        # as "every record citing this id is under a pattern above", which it was not.
        blocks, pids, loose = index.record_only(tid)
        named = index.record_only_ids(tid, blocks)
        # The ids the blocks actually cite, where any is not the one asked for.
        as_cited = "" if set(named) <= {tid} else ", as {},".format(" and ".join(
            "{} ({})".format(t, n) for t, n in sorted(named.items())))
        if blocks:
            text += ("; cited only by records, see ATTACK_RECORD_ONLY" if count == 0 else
                     "; {} further how-block(s) cite {} under patterns that do not list it, "
                     "see ATTACK_RECORD_ONLY".format(
                         len(blocks), "it" if not as_cited else "it or what it reaches"))
        print("ATTACK_REQUESTED: {} -> {}".format(index.label(tid), text))
        if blocks:
            # A record is named in the answer when it cites a returned pattern, under OBSERVED
            # or on its remainder line; one citing none of them appears nowhere unless it is
            # named here.
            unseen = sorted({r["id"] for r, _ in blocks} - {
                r["id"] for r, _ in blocks
                for h in r.get("how") or [] if h.get("pattern_id") in returned})
            # A pattern another selection already returned is named as returned, not as one to
            # select: `--attack T1190,T1078` told the caller to select, for T1190, a pattern
            # T1078 had returned, and for T1078 two that T1190 had.
            fresh = [pid for pid in pids if pid not in returned]
            back = [pid for pid in pids if pid in returned]
            print("ATTACK_RECORD_ONLY: {} is cited by {} how-block(s){} whose pattern does not "
                  "list it{}{}{}; {}".format(
                      tid, len(blocks), as_cited,
                      ": {} - select them with --patterns".format(", ".join(fresh)) if fresh else "",
                      "; {} of their pattern(s) returned here by another selection: {}".format(
                          len(back), ", ".join(back)) if back else "",
                      "; {} of them cite no pattern".format(loose) if loose else "",
                      "{} of their {} record(s) cite no pattern returned here and appear "
                      "nowhere else in this answer: {}".format(
                          len(unseen), len({r["id"] for r, _ in blocks}), ", ".join(unseen))
                      if unseen else "every record carrying them cites a pattern returned here"))
        if "." in tid and index.live(tid):
            parent = tid.split(".")[0]
            only = [pid for pid in index.direct(parent) if tid not in index.cites[pid]]
            if only and parent not in requested:
                print("ATTACK_PARENT_ONLY: {} pattern(s) cite the parent {} but not {}; "
                      "--attack {} includes them".format(len(only), parent, tid, parent))
    print("SHAPES_EMPTY: {} of {}".format(
        sum(1 for _, _, notes in shape_notes if notes[0].endswith("overlapped this shape")),
        len(args.shapes)))
    for line in C.have_header(have, have_rejected):
        print(line)
    placed = {f.pid: pattern_locus(patterns[f.pid], citing[f.pid], locus_map, order)
              for f in findings}
    returned = collections.Counter(placed[f.pid][0] for f in findings)
    print("LOCUS_RETURNED: {}  (the pattern-level LOCUS over the {} finding(s))".format(
        ", ".join("{}={}".format(k, returned.get(k, 0)) for k in order), len(findings)))
    absent = [k for k in order if not returned.get(k)]
    print("LOCUS_ABSENT: {}".format(
        "{} - no returned pattern's LOCUS sits there; a span or an observed locus does not "
        "count. That is a statement about this selection, not a statement that the locus is "
        "safe.".format(", ".join(absent)) if absent
        else "none - every locus holds a returned pattern"))
    # The resolved path, not a relpath of the module global: the global rendered identically
    # whether or not --corpus was honoured, which is how the redirect defect stayed invisible.
    # The unreachable count is here so a caller can tell a dead source from a dead network.
    cache_path = os.path.join(args.corpus, "reference", "url-liveness.json")
    # Under --no-verify the URLs the cache holds no fresh verdict for are counted: they print
    # with no marker, as a live one does, and "0 re-checked" said nothing of them.
    print("URL_LIVENESS: {} distinct URLs, {} re-checked this run, {} unreachable this run "
          "(network, not a verdict), {} with no fresh verdict in the cache{}, cache at {}".format(
              len(urls), len(fetched) if not args.no_verify else 0, unreachable,
              len(fetched), " and printed unchecked, with no marker" if args.no_verify else
              " before this run", cache_path))
    print("CONTRACT: CORROBORATED and OBSERVED are separate claims and must stay separate. "
          "LOCUS is where the pattern applies, from its classes or its own markers, shape and "
          "evidence; LOCUS_OBSERVED is where its "
          "citing how-blocks sit, each placed as consult.py places it, and is a separate "
          "claim. "
          "CAVEAT_VERBATIM is reproduced exactly. [SEED] marks a record that is unconfirmed: "
          "it was not fully re-read against its source, or its source supports only part of "
          "it, and OBSERVED says which of the citing how-blocks a re-read source supports. "
          "A source printed RESTRICTED in place of its URL means cite the title as given and "
          "nothing further. "
          "COUNTERMEASURES are candidate controls D3FEND maps to the cited techniques, not "
          "controls verified as present here.")
    print("=== END HEADER ===")
    print()

    # Exact selections grouped by banner, then one section per shape asked, in order, so a
    # shape typed twice gets two banners rather than one with both results under it.
    groups = collections.OrderedDict()
    for f in findings:
        if f.basis != BY_FREE_TEXT:
            groups.setdefault(f.banner, []).append(f)
    sections = [(banner, members, []) for banner, members in groups.items()] + shape_notes

    A = print
    for banner, members, notes in sections:
        A("############################################################")
        A("### SHAPE: {}".format(banner))
        for note in notes:
            A("   {}".format(note))
        A("############################################################")
        A()
        for f in members:
            pid = f.pid
            pattern = patterns[pid]
            cited = citing[pid]
            ec = pattern.get("external_corroboration") or {}
            A("--- PATTERN_ID: {}".format(pid))
            A("MATCH_BASIS: {}".format(match_basis(f)))
            A("NAME: {}".format(pattern.get("name")))
            # One key per line, as consult.py prints them: LOCUS and FIDELITY each carried a
            # second key on the same line, so r'^LOCUS: (.*)$' read "ENDPOINT   LOCUS_BASIS:
            # tier=..." and the machine-parsed plane key was unparseable in this script only.
            A("FIDELITY: {}".format(pattern.get("fidelity") or "unstated"))
            # A pattern stating no shape still says what its citing blocks state, after the
            # word a parser reads: "unstated" lost a shape every citing block agreed on.
            shapes = collections.Counter(h.get("rule_shape") for _, h in cited
                                         if h.get("rule_shape"))
            A("RULE_SHAPE: {}".format(pattern.get("rule_shape") or "unstated{}".format(
                " (its citing how-blocks state {} of {})".format(", ".join(
                    "{} {}".format(s, n) for s, n in shapes.most_common()), len(cited))
                if shapes else "")))
            A("CLASSES: {}".format(", ".join(pattern.get("applies_to_classes") or []) or "-"))
            p_locus, p_span, p_basis, p_observed = placed[pid]
            A("LOCUS: {}".format(p_locus))
            A("LOCUS_SPAN: {}".format(p_span))
            A("LOCUS_BASIS: {}".format(p_basis))
            A("LOCUS_OBSERVED: {}".format(p_observed))
            sigma, splunk = ec.get("sigma_rules"), ec.get("splunk_detections")
            # Worded as what the count measures. It is distinct rules tagging a technique the
            # pattern cites, matched on technique and not on detection shape: "ship this shape"
            # claimed more than a technique join can know.
            if sigma or splunk:
                A("CORROBORATED: yes - {} Sigma, {} Splunk rule(s) tag a technique this pattern "
                  "cites (matched on technique, not on detection shape)".format(sigma or 0, splunk or 0))
            else:
                A("CORROBORATED: no - no Sigma or Splunk rule tags a technique this pattern cites")
            # Records, not how-blocks: one record citing a pattern from three blocks printed
            # "3 record(s)" over the same line three times. Newest first, each with its id,
            # and the ones past the cap named, so the count is what the lines account for.
            # The title is never cut: a restricted source is cited as given, whole.
            distinct = {record["id"] for record, _ in cited}
            # A seed record is counted, and said to be one: "yes, 1 record(s)" over a single
            # seed read as observed while RESPONSE_DOCTRINE in the same block called the same
            # record unassessable.
            seeds = len({record["id"] for record, _ in cited
                         if (record.get("status") or "").lower() == "seed"})
            # And which of the citing blocks a re-read source supports, decided per block as
            # consult.py's STATUS line decides it: "unconfirmed" over a record whose source
            # was re-read and supports the very block citing this pattern was not true of it.
            parts = collections.Counter(
                C.seed_support(record, next(i for i, block in enumerate(record.get("how") or [])
                                            if block is how))
                for record, how in cited if (record.get("status") or "").lower() == "seed")
            A("OBSERVED: {}".format(
                "yes, {} record(s), {} how-block(s){}".format(
                    len(distinct), len(cited),
                    "; {} of the records seed: {} citing how-block(s) unconfirmed, {} supported "
                    "by a re-read source".format(seeds, parts["unread"] + parts["unconfirmed"],
                                                 parts["supported"]) if seeds else "")
                # An uncited pattern says where it came from, as consult.py's LIBRARY_MATCH
                # does: its caveat can point at reports the answer otherwise never names.
                if cited else "no citing record in the corpus; derived from {}".format(
                    "; ".join(C.library_origins(pattern)))))
            _, _, record_loci = observed_locus(cited, pattern, locus_map, order)
            for record in shown[pid]:
                where = record["where"]
                restricted = where.get("disclosure") != "public"
                url = "RESTRICTED - cite the title as given, nothing further" if restricted \
                    else where.get("url") or "-"
                state = cache.get(url, {}).get("state", "unchecked")
                date = C.published_text(record)
                A("   [{}] {} | {} | LOCUS {} | {} | {}{}".format(
                    (record.get("status") or "?").upper(), record["id"],
                    date or "undated",
                    "/".join(record_loci.get(record["id"]) or ["-"]),
                    where.get("title", ""), url,
                    "" if restricted or state in ("live", "unchecked") else "  <<< {}".format(state)))
            rest = [r["id"] for r in newest[pid][OBSERVED_LINES:]]
            if rest:
                A("   ... {} more record(s) not shown: {}".format(len(rest), ", ".join(rest)))
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
                A("DATA_GAP: {}".format(unassessed))
            for line in C.countermeasures(None, pattern, d3fend, indent="   "):
                A(line)
            # Classes from applies_to_classes, which every pattern carries; this read
            # product_class, which none does, so every block printed "0 matched" and the
            # class-keyed rules never fired. Impact from the citing records, the only place a
            # pattern has one, and the header says so: ransomware doctrine on a pattern is a
            # property of the incidents behind it, not of the detection.
            impacts, counted, seed = citing_impacts(cited)
            for line in (C.doctrine_for(pattern.get("applies_to_classes") or [], impacts, doctrine,
                                        indent="   ", basis=doctrine_basis(counted, seed)) or
                         ["RESPONSE_DOCTRINE: UNASSESSED - corpus/reference/response-doctrine.json "
                          "is absent or empty; no sequencing rule could be matched"]):
                A(line)
            A("")
    if not findings:
        if args.patterns or args.attack:
            # An exact selection returning nothing is a different failure from a guess
            # returning nothing, and the caller cannot act on it without knowing which.
            print("NO_MATCH: nothing was selected by exact id. A pattern id must exist in "
                  "the corpus, and an ATT&CK id selects on the pattern's own technique "
                  "list, its sub-techniques and MITRE's replacement for a revoked id -- a "
                  "technique cited only by records selects no pattern here. "
                  "PATTERNS_REJECTED and ATTACK_REQUESTED above say what became of each id.")
        else:
            suggested = list(dict.fromkeys(
                tid for shape in args.shapes for tid in index.spotted(shape)))
            reaching = [tid for tid in suggested if index.describe(tid)[0]]
            if reaching:
                # "may genuinely be absent ... a reportable finding" printed two lines under a
                # SUGGEST_ATTACK saying a pattern cites the id the shape typed.
                print("NO_MATCH: no pattern overlapped any shape as free text, but a shape "
                      "names an ATT&CK technique that {} pattern(s) cite: run --attack {}. "
                      "That is not an absence from the corpus.".format(
                          sum(index.describe(tid)[0] for tid in reaching), ",".join(reaching)))
            else:
                print("NO_MATCH: no pattern overlapped any shape. Rephrase using the "
                      "behaviour's own vocabulary, or the shape may genuinely be absent from "
                      "the corpus - which is itself a reportable finding.{}".format(
                          " A shape names an ATT&CK technique: try --attack {}.".format(
                              ",".join(suggested)) if suggested else ""))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
