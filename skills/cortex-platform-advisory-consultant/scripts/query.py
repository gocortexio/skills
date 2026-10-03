#!/usr/bin/env python3
# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Look up corpus observations for a technology described in ordinary words.

    python3 scripts/query.py "I have a Cisco FW"
    python3 scripts/query.py "fortigate" --json
    python3 scripts/query.py "email gateway" --role victim

Resolution order: product aliases, longest first, then vendor aliases, then class
and sector aliases, each gated where the word is also an ordinary one (see
references/resolution.md). Words no alias accounted for are then searched as free
text, and an admitted vendor or product name is searched whole, in names only.
Anything the query resolves to is reported with the alias behind it, and every
alias that matched and was refused is reported too, so a caller can see why a
record came back and why another did not.

Ties in the observation listing fall to the question's leftover words, then to a
record naming what resolved, then to the platform the question names, then to
recency, and only then to the id. Exposures are listed by how they relate to the
question (EXPOSURE_TIERS), then exploited before advised before disclosed, each
naming the observations that carry its identifiers; an observation carrying an
identifier of an exposure that names the product is reached too, and says so.

Python 3.9+, standard library only.
"""

import argparse
import collections
import json
import os
import re
import sys

BUNDLE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

NOISE = {
    "i", "have", "a", "an", "the", "we", "our", "my", "got", "run", "running",
    "use", "using", "some", "few", "lot", "of", "is", "are", "what", "should",
    "worried", "about", "worry", "concerned", "with", "and", "or", "on", "in",
    "for", "to", "at", "estate", "environment", "network", "box", "boxes",
    "device", "devices", "appliance", "appliances", "kit",
}


def normalise(text):
    # Runs of whitespace collapse to one space. Punctuation became a space and a space next to
    # it stayed, so "Backup & Replication" normalised to "backup   replication" -- and 110
    # alias keys were stored with such runs, each matching only text punctuated exactly as the
    # key was. "Veeam Backup&Replication" resolved no product, and "Check  Point firewall",
    # with two spaces, no vendor.
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]+", " ", text.lower())).strip()


def load_corpus(corpus_dir):
    records = []
    obs_dir = os.path.join(corpus_dir, "observations")
    if os.path.isdir(obs_dir):
        for filename in sorted(os.listdir(obs_dir)):
            if not filename.endswith(".jsonl"):
                continue
            with open(os.path.join(obs_dir, filename), "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if line and not line.startswith("//"):
                        records.append(json.loads(line))
    patterns = {}
    patterns_path = os.path.join(corpus_dir, "patterns", "patterns.jsonl")
    if os.path.exists(patterns_path):
        with open(patterns_path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line and not line.startswith("//"):
                    pattern = json.loads(line)
                    patterns[pattern["id"]] = pattern
    return records, patterns


# Tables keyed by a vendor's display name rather than by words a question may contain. Their
# keys are compared with who.vendor and resolved vendor names, never with question text, so
# normalising them would make every lookup miss.
NAME_KEYED_TABLES = frozenset({"vendor_families"})


def normalise_alias_keys(aliases):
    """Rewrite alias keys through normalise() so they can actually match.

    Aliases are matched against normalised query text, but the keys themselves were
    stored raw. Any key holding a hyphen, bracket, ampersand or accent therefore
    could never match: "7-zip", "d-link", "serv-u", "big-ip" and 203 others were
    unreachable. The failure was invisible because a few of them happened to have a
    separately written normalised twin ("pan os" alongside "pan-os"), so the table
    looked like it worked.

    Normalising here rather than editing the data keeps the file readable as product
    names people recognise, and means a future entry written with a hyphen resolves
    without anyone having to remember this.
    """
    out = {}
    for table, entries in aliases.items():
        if not isinstance(entries, dict) or table in NAME_KEYED_TABLES:
            out[table] = entries
            continue
        rewritten, source = {}, {}
        for key, value in entries.items():
            norm = normalise(key)
            if not norm:
                continue
            # Two raw keys can normalise to one ("pan-os" and "pan os"). Keep the
            # longer original, which is the more specific way it was written.
            if norm in rewritten and len(source[norm]) >= len(key):
                continue
            rewritten[norm] = value
            source[norm] = key
        out[table] = rewritten
    return out


# How close an ambiguous alias has to sit to its vendor's name before it counts as naming
# the product. Two tokens, measured against the reported defect: "Guardsquare mobile
# application runtime protection ... Android and iOS apps" puts "runtime" four tokens from
# "android", so a window of three still resolved it to Android Runtime and left the bug
# open. Two closes it and still admits every natural way of writing the product -- "Cisco
# IOS", "Cisco IOS XE", "Cisco's IOS software", "Microsoft Exchange Server". A query that
# names the vendor further off than this still resolves the vendor on its own alias, so the
# answer degrades to a vendor-level one rather than to nothing.
AMBIGUITY_WINDOW = 2

# Values of who.vendor that name no vendor. corpus/README.md defines `any` as a record about a
# class of product rather than somebody's, and `Multiple` as a catalogue entry spanning
# several vendors. Until 0.43.0 the resolver added them to the resolved vendors like any other
# name, so every one of the 131 `any` records scored +4 and a vendor reason whenever an
# alias pointing at a class-of-product record resolved -- git, npm, yarn, pypi, suricata,
# github actions -- and consult.py printed RESOLUTION: product over hundreds of findings that
# name nothing the caller said. A sentinel is never a resolved vendor, never corroborates and
# never matches a record's vendor.
SENTINEL_VENDORS = frozenset({"any", "Multiple"})

# A composite alias names several products at once ("apex one and officescan"), so a shorter
# alias inside it is one of those products rather than a fragment of a longer name.
CONJUNCTIONS = frozenset({"and", "or"})

_PATTERNS = {}


def alias_pattern(alias, plural=True):
    """The compiled pattern for an alias: whole words, trailing "s" optional unless singular.

    Compiled once per alias and kept. The re module caches 512 patterns and the table holds
    nearly two thousand aliases, so every resolve() recompiled most of them, about 45 ms a
    call -- which is what made a test asking the whole table about itself too slow to keep.
    """
    key = (alias, plural)
    compiled = _PATTERNS.get(key)
    if compiled is None:
        compiled = _PATTERNS[key] = re.compile(
            r"\b{}{}\b".format(re.escape(alias), "s?" if plural else ""))
    return compiled


def singular_only(aliases):
    """Aliases whose plural is a different word: "ci" is not "cis", "ad" is not "ads"."""
    return {normalise(a) for a in (aliases.get("singular_only") or []) if normalise(a)}


def alias_spans(tokens, alias, plural=True):
    """Token spans where the alias sits, trailing "s" optional on the last token only."""
    parts = alias.split()
    width = len(parts)
    if not width:
        return []
    last = (parts[-1], parts[-1] + "s") if plural else (parts[-1],)
    return [(i, i + width) for i in range(len(tokens) - width + 1)
            if tokens[i:i + width - 1] == parts[:-1] and tokens[i + width - 1] in last]


def near(tokens, span, sequences, window=AMBIGUITY_WINDOW):
    """The first of `sequences` placed within `window` tokens of the span, or None.

    A placement counts when its nearest token is within the window, whatever its length, and
    never when it is the span itself.
    """
    s, e = span
    for seq in sorted(sequences, key=lambda q: (-len(q), q)):
        n = len(seq)
        for a in range(max(0, s - window - n + 1), min(len(tokens) - n, e + window - 1) + 1):
            if (a, a + n) != (s, e) and tuple(tokens[a:a + n]) == seq:
                return seq
    return None


def corroborator(text, alias, vendor, names=(), plural=True):
    """The name for its vendor that an ambiguous alias sits beside, or None.

    A name is the vendor's whole normalised name, or any vendor alias pointing at it, matched
    as a complete token sequence. Until 0.43.0 any single token of the vendor's name counted,
    so "an AV viewer" resolved Justice AV Solutions' Viewer on "av", and "wan link routers"
    resolved D-Link's on "link"; and a vendor alias never counted, so "MS Word" lost Word
    although "ms" is a registered Microsoft alias.

    Fails closed when the alias cannot be located, for the reason the first version taught:
    it indexed by single-token equality, found nothing for "device management", and returned
    True -- a gate that reads as though it protects a two-word alias while being a no-op on
    it. A sentinel vendor fails closed too: a class of product has no name to sit beside, and
    admitting it on nothing is how "any package manager" would have named the npm registry.
    """
    if not vendor or vendor in SENTINEL_VENDORS:
        return None
    tokens = text.split()
    sequences = {tuple(normalise(vendor).split())} | {tuple(normalise(n).split()) for n in names}
    sequences.discard(())
    for span in alias_spans(tokens, alias, plural):
        seq = near(tokens, span, sequences)
        if seq:
            return seq
    return None


def corroborated(text, alias, vendor, names=(), plural=True):
    """Does an ambiguous alias sit near a name for its vendor, or is it just the words?

    See "ambiguous_aliases" in corpus/schema/aliases.json for why the list is curated rather
    than derived, and corroborator() for what counts as a name.
    """
    return corroborator(text, alias, vendor, names, plural) is not None


def raw_token_spans(raw):
    """Where each token of normalise(raw) sits in raw, as (start, end) character offsets.

    normalise() keeps runs of [a-z0-9] after lower-casing and nothing else, so the same runs
    are found here with each lower-cased character mapped back to the character it came from.
    A caller compares the length with the token list and falls back when they differ.
    """
    spans, start, end = [], None, None
    for index, char in enumerate(raw or ""):
        for low in char.lower():
            if "a" <= low <= "z" or "0" <= low <= "9":
                if start is None:
                    start = index
                end = index + 1
            elif start is not None:
                spans.append((start, end))
                start = None
    if start is not None:
        spans.append((start, end))
    return spans


def class_gate(raw, tokens, span, alias, rule, plural=True, raw_spans=None):
    """None when an ambiguous class alias may resolve at this span, else why it may not.

    Three modes, each recorded per alias in `ambiguous_class_aliases`:
    - `upper`: an acronym that is also a word ("IDs", "ran", "blast radius") resolves only
      where the question writes it in capitals, read at this span: looked for anywhere in
      the question, one capitalised acronym admitted a lower-case occurrence of the same word
      elsewhere, and consumed it.
      An alias whose rule sets `acronym_plural` also takes a lower-case "s" after the
      capitals, the acronym's plural ("ADs", "SIMs"), even where `singular_only` refuses
      "ads". It depends on the caller's casing, so a consumer that lower-cases its questions
      loses these routes, and SKILL.md says so.
    - `refuse_near`: the word resolves unless one of its listed context words sits within
      the ambiguity window -- "actuator" is a field device except beside "spring boot".
    - `require_near`: the word resolves only beside one of its listed context words --
      "controller" is a PLC beside "plc" or "s7", and a domain, ingress or baseboard
      management controller everywhere else.
    """
    mode = (rule or {}).get("mode")
    context = {tuple(normalise(w).split()) for w in (rule or {}).get("near") or []}
    context.discard(())
    if mode == "upper":
        suffix = "S?" if plural else ""
        if (rule or {}).get("acronym_plural"):
            suffix = "[Ss]?" if plural else "s?"
        pattern = r"(?<![A-Za-z0-9]){}{}(?![A-Za-z0-9])".format(re.escape(alias.upper()), suffix)
        where = raw
        if raw_spans and len(raw_spans) == len(tokens):
            where = raw[raw_spans[span[0]][0]:raw_spans[span[1] - 1][1]]
        return None if re.search(pattern, where) else "an acronym only when written in capitals"
    if mode == "refuse_near":
        hit = near(tokens, span, context)
        return "beside '{}', where it means something else".format(" ".join(hit)) if hit else None
    if mode == "require_near":
        return None if near(tokens, span, context) else \
            "none of the words that make it this class sits within two words of it"
    return "gate mode {!r} is not one resolve() knows, so it is refused".format(mode)


def reads_as_class(words, class_table, single=()):
    """Does a class alias stand as whole words inside `words`, ungated? The conservative
    reading: a gate that would refuse the class alias in a question is not applied here."""
    return any(alias_pattern(alias, alias not in single).search(words) for alias in class_table)


def resolve(query, aliases):
    """Turn a free-text query into vendor, product and class constraints, and say how.

    Besides the sets that resolved, the result carries the account of how:
    - `resolved_by` names the alias behind every admitted vendor, product, class and sector,
      and what corroborated an ambiguous one;
    - `gated` names every alias that matched the words and was refused, with the reason,
      because a refusal that prints nothing reads as though the word was never seen;
    - `terms` holds only the words no admitted alias accounted for, and `name_phrases` the
      admitted vendor and product aliases, which score() searches as whole phrases in names
      only. Until 0.43.0 every word of the question was a free-text term, so "Check Point
      firewall" searched "check" and "point" through every record's prose and matched 188
      findings on "entry point" and "integrity check";
    - `product_pairs`, `vendorless_products`, `product_names`, `vendor_kin`, `vendor_names`
      and `filed_under` are what score(), product_matches() and exposure_tier() need to match
      a record's own spelling.
    """
    raw = query or ""
    text = normalise(raw)
    tokens = text.split()
    start_of, end_of, offset = {}, {}, 0
    for index, token in enumerate(tokens):
        start_of[offset] = index
        end_of[offset + len(token)] = index + 1
        offset += len(token) + 1

    def token_span(span):
        return start_of[span[0]], end_of[span[1]]

    resolved = {"vendors": set(), "products": set(), "classes": set(), "sectors": set(),
                "terms": set(), "gated": set(), "resolved_by": set(), "name_phrases": set(),
                "product_pairs": set(), "vendorless_products": set(), "product_names": {},
                "vendor_kin": {}, "vendor_names": {}, "filed_under": {}, "product_forms": {},
                "refused_meanings": []}
    product_table = aliases.get("product_aliases") or {}
    vendor_table = aliases.get("vendor_aliases") or {}
    ambiguous = aliases.get("ambiguous_aliases") or {}
    ambiguous_vendors = aliases.get("ambiguous_vendor_aliases") or {}
    ambiguous_classes = aliases.get("ambiguous_class_aliases") or {}
    single = singular_only(aliases)
    names = {}
    for key, vendor in vendor_table.items():
        names.setdefault(vendor, set()).add(key)
    consumed = set()
    # Refusals are kept with their spans, and reported only where no admitted alias accounted
    # for the words: "firewall" is refused as Sophos's product and resolved as a class, and
    # printing the refusal on every firewall question would bury the ones that matter.
    refused = []

    def consume(spans):
        for span in spans:
            consumed.update(range(*token_span(span)))

    def refuse(text_, spans, meaning=None):
        refused.append((text_, [i for span in spans for i in range(*token_span(span))],
                        meaning))

    def spans_of(alias, haystack):
        return [m.span() for m in alias_pattern(alias, alias not in single).finditer(haystack)]

    # --- products. Longest alias first, so "next gen firewall" wins over "firewall".
    found = {alias: spans for alias, spans in
             ((alias, spans_of(alias, text)) for alias in product_table) if spans}
    # An UNAMBIGUOUS product alias of the same vendor anchors an ordinary word within the same
    # two-word window a vendor name gets: "Ivanti EPMM and Sentry" names Ivanti's Sentry,
    # although three words separate it from the vendor, and "Cisco ASA and IOS" names IOS.
    # Anchoring from anywhere in the question was measured and refused, because it brought the
    # 0.29.0 defect back by another route: "Cisco ASA VPN users on iOS and Android phones"
    # resolved Cisco IOS, and "edge devices ... domain controllers" Microsoft Edge, since
    # Microsoft has over a hundred unambiguous aliases to anchor its eight gated ones. Vendor
    # aliases deliberately do not anchor -- "Guardsquare ... runtime protection ... Android
    # and iOS apps" names the Android vendor and still does not mean Android Runtime.
    anchors = {}
    for alias in sorted(found, key=lambda a: (-len(a), a)):
        vendor = product_table[alias]["vendor"]
        if alias not in ambiguous and vendor not in SENTINEL_VENDORS:
            anchors.setdefault(vendor, []).extend(
                (alias, token_span(span)) for span in found[alias])

    def anchor_for(vendor, spans):
        """The unambiguous alias of `vendor` within the window of one of `spans`, or None."""
        for span in spans:
            s, e = token_span(span)
            for alias, (a, b) in anchors.get(vendor, ()):
                if 1 <= max(a - (e - 1), s - (b - 1)) <= AMBIGUITY_WINDOW:
                    return alias
        return None
    # (start, end, vendor, product, composite) of every admitted product alias, and later of
    # every admitted vendor alias, whose product is None.
    claimed = []
    for alias in sorted(found, key=len, reverse=True):
        value = product_table[alias]
        vendor, product, spans = value["vendor"], value["product"], found[alias]

        # Longest wins, as it already did for classes and sectors: a shorter alias lying wholly
        # inside an admitted longer one does not also resolve when it names another vendor --
        # "prisma sd wan" is not Cisco's SD-WAN, and "barracuda email security gateway" not
        # Check Point's gateway. Inside a longer name of the SAME vendor it is a separate
        # product only where the words say so: the longer name is a composite ("apex one and
        # officescan"), or the shorter one's product is ("netscaler" is Citrix's "Application
        # Delivery Controller and NetScaler Gateway"), or the two are one product spelt two ways
        # ("junos os" inside "juniper junos os", "fta" inside "accellion fta"). Otherwise the
        # longer name is a different product line and the shorter one does not come with it:
        # "ivanti endpoint manager mobile" is EPMM and not EPM as well, and "azure active
        # directory" is Entra ID and not on-premises Active Directory, which sits on another
        # plane. An ordinary word inside a longer name is always part of that name. A sentinel
        # product names no vendor and claims nobody's words.
        strip = {tuple(k.split()) for k in names.get(vendor, ())} \
            | {tuple(normalise(vendor).split())}
        mine = canonical_product(product, strip)

        def claimed_by_another(span):
            s, e = span
            for cs, ce, cv, cp, composite in claimed:
                if not (cs <= s and e <= ce) or cv in SENTINEL_VENDORS:
                    continue
                if cv != vendor:
                    return True
                if cp == product:
                    continue
                theirs = canonical_product(cp, strip)
                one_product = _same_product(mine, theirs) or (
                    len(mine) == 1 and len(theirs) > 1 and mine[0] == "".join(w[0] for w in theirs))
                if alias in ambiguous and not one_product:
                    return True
                if not (composite or one_product or CONJUNCTIONS & set(normalise(product).split())):
                    return True
            return False
        if all(claimed_by_another(span) for span in spans):
            continue
        if all(any(cs <= s and e <= ce and cp == product for cs, ce, _, cp, _ in claimed)
               for s, e in spans):
            # "github action" inside "github actions": the same product, already resolved.
            continue

        plural = alias not in single
        how = ""
        if alias in ambiguous:
            # An ambiguous word resolves only beside a name for its vendor, or beside an
            # unambiguous product of that vendor, both within two words.
            seq = corroborator(text, alias, vendor, names.get(vendor, ()), plural)
            anchor = None if seq else anchor_for(vendor, spans)
            if seq:
                how = " (beside {})".format(" ".join(seq))
            elif anchor:
                how = " (anchored by {})".format(anchor)
            else:
                refuse("{} (product {} / {}: an ordinary word, with no name or unambiguous "
                       "product of its vendor within two words of it)".format(
                           alias, vendor, product), spans, ("product", alias, (vendor,)))
                continue
        claimed.extend((s, e, vendor, product, bool(CONJUNCTIONS & set(alias.split())))
                       for s, e in spans)
        consume(spans)
        resolved["products"].add(product)
        resolved["product_pairs"].add((vendor, product))
        resolved["name_phrases"].add(alias)
        if vendor in SENTINEL_VENDORS:
            # "npm registry", "git" and "github actions" name a product and no vendor. The
            # product still resolves, and matches that product under any vendor.
            resolved["vendorless_products"].add(product)
        else:
            resolved["vendors"].add(vendor)
        klass = value.get("product_class") or []
        # A product may belong to more than one class, and saying so is the difference between
        # an answer and a thinner answer that reads as a safer one. Moving EPMM from app.rmm to
        # app.mdm alone took the question from 74 findings to 17: the MDM records arrived, and
        # the fleet-management context that had been carrying it left.
        resolved["classes"].update(klass if isinstance(klass, list) else [klass])
        resolved["resolved_by"].add("{} -> product {}{}".format(
            alias, "{} (names no vendor)".format(product) if vendor in SENTINEL_VENDORS
            else "{} / {}".format(vendor, product), how))

    # The names each resolved product answers to without its vendor beside it, which
    # product_matches() reads. A record about a class of product lists the makers and products
    # it covers in who.products, under no vendor of its own, and what competes with a product
    # name there is a class of product, not an ordinary word: an entry is written "Cursor" or
    # "firewalls", never "the text cursor". So an unambiguous alias is a name, and so is a
    # gated one unless its words read as a class -- "cursor" names Anysphere's editor in a
    # list of coding agents, and "firewall", "routers" and "network attached storage" are
    # every vendor's, which is why they are Sophos's, D-Link's and QNAP's only beside them.
    class_words = aliases.get("class_aliases") or {}
    for alias, value in product_table.items():
        pair = (value["vendor"], value["product"])
        if pair not in resolved["product_pairs"] or pair[0] in SENTINEL_VENDORS:
            continue
        if alias in ambiguous and reads_as_class(alias, class_words, single):
            continue
        resolved["product_names"].setdefault(pair, set()).add(tuple(alias.split()))

    # --- vendors. Ordinary-word vendor aliases are held back until every other vendor alias has
    # been read, so length ordering cannot decide whether their vendor is already named.
    held = []
    for alias in sorted(vendor_table, key=len, reverse=True):
        spans = spans_of(alias, text)
        vendor = vendor_table[alias]
        if not spans or vendor in SENTINEL_VENDORS:
            # A vendor alias naming a sentinel names nobody and consumes nothing.
            continue
        if all(any(cs <= s and e <= ce and cv != vendor and cv not in SENTINEL_VENDORS
                   for cs, ce, cv, _, _ in claimed) for s, e in spans):
            continue
        if alias in ambiguous_vendors:
            held.append((alias, spans, vendor))
            continue
        claimed.extend((s, e, vendor, None, False) for s, e in spans)
        consume(spans)
        resolved["vendors"].add(vendor)
        resolved["name_phrases"].add(alias)
        resolved["resolved_by"].add("{} -> vendor {}".format(alias, vendor))
    for alias, spans, vendor in held:
        if vendor in resolved["vendors"]:
            # "PAN Panorama", "Progress MOVEit": the word names a vendor something else named.
            consume(spans)
            resolved["name_phrases"].add(alias)
            resolved["resolved_by"].add("{} -> vendor {} (named elsewhere too)".format(
                alias, vendor))
        else:
            refuse("{} (vendor {}: an ordinary word, and nothing else in the question names "
                   "this vendor)".format(alias, vendor), spans, ("vendor", alias, (vendor,)))

    # --- classes, then sectors. Each admitted span is blanked so a shorter overlapping alias
    # cannot also match: "water utility" must resolve to water alone, not to water and
    # electric because "utility" is also a term.
    remaining = text
    raw_spans = raw_token_spans(raw)
    for table, key in ((aliases.get("class_aliases") or {}, "classes"),
                       (aliases.get("sector_aliases") or {}, "sectors")):
        if key == "sectors":
            # The words of an admitted product name are the product's, and name no sector:
            # "Cisco Firepower Threat Defense" was a question about the defence sector, "Ruby on
            # Rails" one about transportation, and "Kerberos Key Distribution Center" one about
            # electricity. A class word inside a product name still reads as a class.
            for s, e, _, product, _ in claimed:
                if product is not None:
                    remaining = remaining[:s] + " " * (e - s) + remaining[e:]
        for alias in sorted(table, key=len, reverse=True):
            plural = alias not in single
            rule = ambiguous_classes.get(alias) if key == "classes" else None
            admitted, refusals = [], []
            # An acronym's own plural ("ADs") is looked for even where the plain plural is
            # another word, and class_gate() decides from its capitals.
            search = plural or bool((rule or {}).get("acronym_plural"))
            for span in alias_pattern(alias, search).finditer(remaining):
                span = span.span()
                why = class_gate(raw, tokens, token_span(span), alias, rule, plural,
                                 raw_spans) if rule else None
                if why and not plural and span[1] - span[0] > len(alias):
                    # "ads" is the other word singular_only names, not a refused acronym.
                    continue
                if why:
                    refusals.append((span, why))
                else:
                    admitted.append(span)
            value = table[alias]
            if not admitted:
                if refusals:
                    refuse("{} (class {}: {})".format(
                        alias, ", ".join(value) if isinstance(value, list) else value,
                        refusals[0][1]), [span for span, _ in refusals],
                        ("class", alias, tuple(value) if isinstance(value, list) else (value,)))
                continue
            # A class alias may name more than one class, because one word often does. "mdm"
            # is a fleet-management console AND remote management tooling, and answering it
            # from app.mdm alone dropped the question from 63 findings to 4.
            resolved[key].update(value if isinstance(value, list) else [value])
            consume(admitted)
            for s, e in admitted:
                remaining = remaining[:s] + " " * (e - s) + remaining[e:]
            resolved["resolved_by"].add("{} -> {} {}".format(
                alias, {"classes": "class", "sectors": "sector"}[key],
                ", ".join(value) if isinstance(value, list) else value))

    resolved["terms"] = {t for i, t in enumerate(tokens)
                         if i not in consumed and t not in NOISE and len(t) > 2}
    resolved["gated"] = {text_ for text_, where, _ in refused
                         if any(i not in consumed for i in where)}
    # What each reported refusal would have meant, which score() reads so that the refused
    # word cannot come back as a free-text term and reach, by name, the very thing it was
    # refused as. It did: "quantum" was refused as Check Point's gateway and then matched the
    # gateway's product name, ranking the Check Point record first of 70 for a product nobody
    # had heard of, and "Apple iOS" refused Cisco IOS and answered with twelve Cisco router
    # findings reached through the same word.
    resolved["refused_meanings"] = sorted({meaning for text_, where, meaning in refused
                                           if meaning and any(i not in consumed for i in where)})

    # How a record's own vendor string is matched to what resolved. A vendor is itself under
    # every name the corpus spells it by (`vendor_spellings`, both ways) and every alias key of
    # those names ("VMware" is Broadcom's). A family is directional: the lines a parent
    # acquired are the parent's, so "Broadcom" reaches VMware, VMware Tanzu and Symantec, and
    # a member is only itself. Read as a flat set, `vendor_families` took "Symantec" from no
    # answer to 41 VMware ESXi findings under RESOLUTION: product. A record filed under the
    # parent is a member's where its products name the member, and `filed_under` says which
    # members to look for.
    spellings, members, parent = vendor_relations(aliases)

    def spelt(name):
        return spellings.get(name) or {name}

    for vendor in sorted(resolved["vendors"]):
        kin = set(spelt(vendor))
        for name in list(kin):
            for member in members.get(name, ()):
                kin |= spelt(member)
        for name in sorted(kin):
            resolved["vendor_kin"].setdefault(normalise(name), vendor)
            for key in names.get(name, ()):
                resolved["vendor_kin"].setdefault(key, vendor)
        for name in spelt(vendor):
            if name in parent:
                for head in spelt(parent[name]):
                    resolved["filed_under"].setdefault(normalise(head), set()).add(vendor)
    for key, vendor in resolved["vendor_kin"].items():
        resolved["vendor_names"].setdefault(vendor, set()).add(tuple(key.split()))
    # The names of each vendor a refused alias belonged to, which refused_terms() reads.
    resolved["refused_names"] = {}
    for kind, _, targets in resolved["refused_meanings"]:
        if kind == "class":
            continue
        for vendor in targets:
            seqs = {tuple(normalise(name).split()) for name in spelt(vendor)}
            seqs |= {tuple(key.split()) for name in spelt(vendor) for key in names.get(name, ())}
            seqs.discard(())
            resolved["refused_names"][vendor] = seqs
    # Every spelling a record may name a resolved product by, which product_matches() reads.
    for vendor, product in resolved["product_pairs"]:
        if vendor in SENTINEL_VENDORS:
            continue
        strip = resolved["vendor_names"].get(vendor) or {tuple(normalise(vendor).split())}
        resolved["product_forms"][(vendor, product)] = product_forms(
            aliases, vendor, product, strip, resolved["product_names"].get((vendor, product), ()))
    return resolved


def vendor_relations(aliases):
    """The two vendor tables, read: (spellings, members, parent).

    `spellings` maps each name in a `vendor_spellings` group to the whole group, which is one
    company filed under several names (QNAP and QNAP Systems). `members` maps a
    `vendor_families` parent to the lines it acquired, and `parent` maps each line back.
    """
    spellings = {}
    for group in aliases.get("vendor_spellings") or []:
        if isinstance(group, list):
            for name in group:
                spellings.setdefault(name, set()).update(group)
    members, parent = {}, {}
    families = aliases.get("vendor_families") or {}
    for head, lines in (families.items() if isinstance(families, dict) else ()):
        for line in lines or []:
            members.setdefault(head, set()).add(line)
            parent[line] = head
    return spellings, members, parent


# What the free-text fallback searches, in descending order of how much a hit there is
# worth. Measured 2026-08-19 over thirty mechanism terms: vendor/product/class alone
# reached 33 records and left 22 of the 30 terms matching nothing at all, because a word
# that is not a technology appears nowhere in that haystack. Adding these three tiers
# reaches 1,124. They are tiered rather than merged because the reach is not free -- the
# same measurement found 31 records answering a vendor query they are not about, every
# one of them via summary or pattern prose, and none via a tag. So a tag hit is worth
# what a product hit is worth and a prose hit is worth half, which lets the wide net
# catch what it should while the loose matches rank below the tight ones.
# The first tier was called "identity" until 2026-08-27, which collided with the name
# consult.py then gave a *resolved* vendor, product or class, and the two printed as one
# label. They are not the same event. If the alias table had resolved the word, score()
# would have returned before it ever reached this fallback -- so a hit here is a word
# sitting inside a name that the resolver did not recognise. "mobile app hardening"
# resolved to nothing and still returned an Ivanti VPN gateway at rank 1, reported as
# though the caller had named it, because "Mobile" is inside "Endpoint Manager Mobile".
# The haystack is unchanged; only the honest name for what a hit in it is has changed.
#
# tag now sorts above name-fragment. The loop below already claims the first tier wins
# "at the tighter of the two", and a curated tag is tighter than an unresolved fragment
# of a name. Both are worth 2, so the reorder is points-neutral: measured over eight
# queries the corpus-wide score sum is identical either way, and exactly one reason
# moves tier.
FREE_TEXT_TIERS = (
    ("tag", 2),            # curated per record; measured to add reach at zero precision cost
    ("name-fragment", 2),  # a query word sits inside a vendor, product or class name
    ("pattern", 1),        # the cited pattern's name and description
    ("summary", 1),        # what.summary, the widest and loosest source
)

# The reason prefixes score() emits when the resolver identified the technology by name.
# consult.py classifies against this rather than treating "anything that is not a term"
# as a subject match, which fails open: an unrecognised reason shape would silently be
# given the tightest tier and full weight.
STRUCTURED_REASONS = ("vendor ", "product ", "class ", "sector ", "cross-sector")

# The tiers a structured reason can put a record in. Until 0.43.0 they were one tier,
# `identity`, and MATCH_TIERS counted a class analogue as though it named the product: "PAN-OS"
# printed identity=74 over 3 findings naming PAN-OS and 71 other vendors' firewalls.
# `product` names the product asked about; `vendor` names the vendor asked about in a class
# asked about, or with no class asked about; `class` shares a class and names another
# vendor's product; `vendor-other-class` names the vendor asked about in none of the classes
# asked about, which is the vendor's other product lines.
SUBJECT_TIERS = ("product", "vendor", "class", "vendor-other-class")

# Tightest first. consult.py derives its own ordering from this so that a tier added
# here cannot be silently dropped there.
TIER_ORDER = SUBJECT_TIERS + tuple(name for name, _ in FREE_TEXT_TIERS)


def free_text_haystacks(record, patterns=None):
    """The tiers of text a free-text term may match, keyed by tier name.

    The key names where the text was found, never that the technology was identified.
    A hit in the name-fragment haystack means a query word appears inside this record's
    vendor, product or class names -- not that the resolver recognised any of them.
    """
    who = record.get("who", {})
    name_fragment = [who.get("vendor", "")] + (who.get("products") or []) \
        + [c.split(".", 1)[-1] for c in (who.get("product_class") or [])]
    tags = [t.replace("-", " ") for t in (record.get("tags") or [])]
    pattern_text = []
    for how in record.get("how") or []:
        pattern = (patterns or {}).get(how.get("pattern_id")) or {}
        pattern_text += [pattern.get("name", ""), pattern.get("description", "")]
    return {
        "name-fragment": normalise(" ".join(name_fragment)),
        "tag": normalise(" ".join(tags)),
        "pattern": normalise(" ".join(pattern_text)),
        "summary": normalise((record.get("what") or {}).get("summary", "")),
    }


def vendor_match(vendor, resolved):
    """The `vendor ...` reason when a record's own vendor string is a vendor that resolved.

    Matched exactly, or through the resolved vendor's alias keys, its other spellings and the
    lines it acquired: 18 exposures are filed under "VMware" while the alias table resolves
    "VMware" to Broadcom, so a Broadcom or VMware question reached them only on free text.
    Never the other way: a member's question does not reach its parent or a sibling. A
    sentinel vendor never matches.
    """
    if not vendor or vendor in SENTINEL_VENDORS:
        return None
    if vendor in resolved.get("vendors", ()):
        return "vendor {}".format(vendor)
    kin = (resolved.get("vendor_kin") or {}).get(normalise(vendor))
    if kin:
        return "vendor {} (as {})".format(vendor, kin)
    return None


def _contains(tokens, seq):
    n = len(seq)
    return any(tuple(tokens[i:i + n]) == seq for i in range(len(tokens) - n + 1))


def named_in_product(reason):
    """Is this the reason for a vendor named inside a generic record's product entry?

    Such a record is about a class of product and lists its makers, so the vendor matching it
    says less than a record filed under that vendor. consult.py weighs it by whether the
    record also carries a class the question asked about.
    """
    return reason.startswith("vendor ") and "(named in product " in reason


def vendor_named_in_products(record, resolved):
    """For a record whose vendor is a sentinel, the resolved vendor its products name, if any.

    Where a record covers a class, the makers move into who.products: eleven observations list
    GitHub there under vendor `any`, and "GitHub" was told no record is about it, reached
    only by tag and name fragment. A resolved vendor's name, or any alias key of it, standing
    as whole words inside a product entry is that vendor named.
    """
    for vendor in sorted(resolved.get("vendors") or ()):
        product = _product_naming(record, resolved, vendor)
        if product:
            return "vendor {} (named in product {})".format(vendor, product)
    return None


def _product_naming(record, resolved, vendor):
    """The first of the record's product entries naming `vendor` as whole words, or None."""
    sequences = (resolved.get("vendor_names") or {}).get(vendor) \
        or {tuple(normalise(vendor).split())}
    for product in (record.get("who") or {}).get("products") or []:
        words = normalise(product).split()
        if any(seq and _contains(words, seq) for seq in sequences):
            return product
    return None


def filed_under_parent(record, resolved):
    """For a record filed under a family parent, the `vendor ...` reason for the resolved
    member its products name, or None.

    The corpus files lines of VMware and Symantec under Broadcom, and of Telerik under
    Progress. Such a record is the member's history where a product entry names the member
    ("Symantec Messaging Gateway" under Broadcom, for a Symantec question), and otherwise the
    parent's other lines, which a question naming only the member did not ask about.
    """
    vendor = (record.get("who") or {}).get("vendor") or ""
    for member in sorted((resolved.get("filed_under") or {}).get(normalise(vendor), ())):
        if _product_naming(record, resolved, member):
            return "vendor {} (filed under {})".format(member, vendor)
    return None


def vendor_reason(record, resolved):
    """The `vendor ...` reason this record earns, or None: the one vendor test score() and
    exposure_tier() share, so the observation and exposure listings cannot disagree."""
    vendor = (record.get("who") or {}).get("vendor") or ""
    named = vendor_match(vendor, resolved)
    if not named and vendor in SENTINEL_VENDORS:
        named = vendor_named_in_products(record, resolved)
    return named or filed_under_parent(record, resolved)


def canonical_product(name, strip=()):
    """A product string reduced to what names the product itself.

    Parenthesised segments go ("Endpoint Manager Mobile (EPMM)"), then any vendor name
    sequence in `strip` ("VMware ESXi" under Broadcom is "esxi"). Exact string equality missed
    twelve products that have observations -- the alias table spells them as the catalogue
    does, and the records as the vendor does -- and token containment, measured as the
    alternative, matched Endpoint Manager (EPM) to Endpoint Manager Mobile and ADFS to Active
    Directory.
    """
    words = normalise(re.sub(r"\([^)]*\)", " ", name or "")).split()
    for seq in sorted({tuple(s) for s in strip if s}, key=lambda q: (-len(q), q)):
        n, out, i = len(seq), [], 0
        while i < len(words):
            if tuple(words[i:i + n]) == seq:
                i += n
            else:
                out.append(words[i])
                i += 1
        words = out
    return tuple(words)


def _same_product(a, b):
    """Canonical equality, with a trailing "s" optional on the last word ("Gateway(s)")."""
    if not a or not b:
        return False
    if a == b:
        return True
    return a[:-1] == b[:-1] and (a[-1] + "s" == b[-1] or b[-1] + "s" == a[-1])


# A product entry names one product or several: the catalogue writes "Adaptive Security
# Appliance (ASA) and Firepower Threat Defense (FTD)" and "iOS, iPadOS, and watchOS" as one
# string. Bracketed segments go first, so a comma inside one cannot split it.
PRODUCT_PARTS = re.compile(r"\s*,\s*(?:and\s+)?|\s+and\s+")


def product_parts(name):
    """The products one entry names: the entry itself, then each part where it names several.

    Until 0.43.0 an entry was compared whole, so a Cisco ASA question called three catalogue
    records "not the product asked about" while their own technology line named ASA, and
    left the ArcaneDoor record behind three management-centre records. A part only adds a
    match, since the whole entry is always tried too.
    """
    parts = [re.sub(r"\s+", " ", p).strip()
             for p in PRODUCT_PARTS.split(re.sub(r"\([^)]*\)", " ", name or "")) if normalise(p)]
    return [name] + parts if len(parts) > 1 else [name]


def product_families(aliases):
    """`product_families` read: {vendor: [(names, components), ...]}, as given."""
    out = {}
    for entry in aliases.get("product_families") or []:
        if isinstance(entry, dict) and entry.get("vendor"):
            out.setdefault(entry["vendor"], []).append(
                (tuple(entry.get("names") or ()), tuple(entry.get("components") or ())))
    return out


# How a spelling names a product, closest first: its own name, an alias the table resolves
# to it, another name of its product family, or a component of it.
FORM_RELATIONS = ("own", "alias", "name", "component")


def product_forms(aliases, vendor, product, strip, alias_forms=()):
    """Every canonical form a record may spell `product` by, the vendor's names removed, as
    {form: relation}, relation one of FORM_RELATIONS.

    The product's own canonical form; each alias the table resolves to it ("Exchange" for
    Exchange Server, which the resolver held and product_matches() never consulted for a
    record filed under Microsoft); and, where `product_families` places the product in a
    family, every name of the family and every component. A component asked about brings
    only itself.
    """
    own = canonical_product(product, strip)
    forms = {}

    def add(form, relation):
        if form and (form not in forms or FORM_RELATIONS.index(relation)
                     < FORM_RELATIONS.index(forms[form])):
            forms[form] = relation
    add(own, "own")
    for form in alias_forms:
        add(canonical_product(" ".join(form), strip), "alias")
    spellings, _, _ = vendor_relations(aliases)
    vendors = spellings.get(vendor) or {vendor}
    for family_vendor, families in product_families(aliases).items():
        if family_vendor not in vendors:
            continue
        for names, components in families:
            canon = [canonical_product(n, strip) for n in names]
            if any(_same_product(own, c) for c in canon):
                for c in canon:
                    add(c, "name")
                for c in components:
                    add(canonical_product(c, strip), "component")
    return forms


def product_matches(resolved, record, any_vendor=False):
    """The record's own product spellings that name a resolved product.

    One matcher for observations and exposures, so query.py and consult.py cannot disagree
    about whether a record names what was asked. A product names this record only under the
    alias's own vendor: "Kernel" is Linux's and Android's, "Core" WordPress's and Drupal's,
    "Multiple Products" eighteen vendors', and matching the string alone gave an Android
    handset record product weight on a Linux question. The alias's own vendor includes its
    spellings, the lines it acquired, and a parent the record is filed under. A product whose
    alias names no vendor (npm registry, git) matches under any vendor.

    A record whose own vendor is a sentinel is about a class of product, and its entries name
    the makers it covers. Such an entry names a resolved product only where it names the
    product's vendor ("VMware ESXi", "Google Chrome"), or is one of `product_names` on its own:
    an unambiguous alias ("Zimbra Collaboration Suite", "Active Directory"), or a gated one
    whose words read as no class ("Cursor", in a list of coding agents). Until then any entry
    matched under the question's vendor, so "Sophos Firewall" was answered RESOLUTION: product
    from two records listing "firewalls", and "D-Link routers", "QNAP network attached storage"
    and "SonicWall firewall appliances" lost CLASS_LEVEL_WARNING the same way: a word the
    resolver admits only beside its vendor was admitted in a record that names no vendor.
    `any_vendor` drops the vendor test, to count what it refused.

    An entry naming several products ("Adaptive Security Appliance (ASA) and Firepower Threat
    Defense (FTD)") names each of them, and a product is spelt by any of its `product_forms()`:
    the aliases that resolve to it and the other names of its `product_families` entry.
    """
    return set(product_hits(resolved, record, any_vendor))


def product_hits(resolved, record, any_vendor=False):
    """product_matches() as {record spelling: (vendor, product, part, relation)}: the pair it
    names (the first in sorted order where it names more than one), the part of the spelling
    that names it, and how, one of FORM_RELATIONS."""
    who = record.get("who") or {}
    record_vendor = who.get("vendor") or ""
    pairs = resolved.get("product_pairs")
    if pairs is None:
        # A resolved dict built by hand, before product_pairs existed: exact strings only.
        pairs = {(None, p) for p in resolved.get("products") or ()}
    names = resolved.get("vendor_names") or {}
    kin = resolved.get("vendor_kin") or {}
    alone = resolved.get("product_names")
    forms_of = resolved.get("product_forms") or {}
    parents = (resolved.get("filed_under") or {}).get(normalise(record_vendor)) or ()
    generic_record = record_vendor in SENTINEL_VENDORS
    hits = {}
    for spelling in who.get("products") or []:
        # A record about a class of product describes what it covers ("Windows and Linux
        # estates") rather than listing catalogue names, so its entries are read whole.
        parts = [spelling] if generic_record else product_parts(spelling)
        for vendor, product in sorted(pairs, key=lambda pair: (pair[0] or "", pair[1])):
            vendorless = vendor is None or vendor in SENTINEL_VENDORS
            generic = generic_record and not (any_vendor or vendorless)
            filed = (vendorless or generic
                     or record_vendor == vendor or kin.get(normalise(record_vendor)) == vendor
                     or vendor in parents)
            if not (filed or any_vendor):
                continue
            strip = names.get(vendor) or {tuple(normalise(vendor or "").split())}
            if generic and not _contains_any(normalise(spelling).split(), strip):
                # No name for the vendor in the entry: it has to be a name of the product that
                # stands without one. A hand-built resolved dict has no product_names, and
                # falls back to the product's own spelling.
                alone_forms = {canonical_product(product)} if alone is None \
                    else alone.get((vendor, product)) or ()
                if not any(_same_product(canonical_product(part), form)
                           for part in parts for form in alone_forms):
                    continue
            if spelling == product:
                hits.setdefault(spelling, (vendor, product, spelling, "own"))
                continue
            forms = forms_of.get((vendor, product)) or {canonical_product(product, strip): "own"}
            if not filed:
                # Another vendor's record: the product's own name, whole. An alias or a family
                # name is the vendor's word for its product, and the vendor's names mean nothing
                # in another vendor's entry: stripped of Ivanti's, "MobileIron Core" was
                # "core", and a MobileIron question counted WordPress's Core as its product
                # under another vendor.
                strip = set()
                forms = {canonical_product(product): "own"}
            found = sorted(((FORM_RELATIONS.index(relation), index, part, relation)
                            for index, part in enumerate(parts)
                            for form, relation in forms.items()
                            if _same_product(canonical_product(part, strip), form)))
            if found:
                _, _, part, relation = found[0]
                hits.setdefault(spelling, (vendor, product, part, relation))
    return hits


def product_labels(resolved, record, any_vendor=False):
    """The record's spellings that name a resolved product, sorted, each saying how where the
    spelling is not simply the product's own name: "FortiOS (as FortiGate)", "FortiGate SSL
    VPN (a component of FortiGate)", "FortiOS and FortiProxy (FortiOS, as FortiGate)"."""
    out = []
    for spelling, (_, product, part, relation) in product_hits(
            resolved, record, any_vendor).items():
        if relation == "own":
            out.append(spelling)
            continue
        how = "a component of {}".format(product) if relation == "component" \
            else "as {}".format(product)
        out.append("{} ({})".format(spelling, how) if part == spelling
                   else "{} ({}, {})".format(spelling, part, how))
    return sorted(out)


# A catalogue entry filed under no product of its own: "Multiple Products" (eighteen vendors),
# "MobileIron Multiple Products", "Multiple Routers". Its product field names nothing, so the
# catalogue's description of each identifier is the only place the product is named.
CATCH_ALL_PRODUCT = re.compile(r"\bmultiple\b", re.I)

# The catalogue generator quotes the catalogue's description of each identifier in the summary,
# in one of two fixed forms, and ends the list with one of two fixed sentences. Read back here
# in those forms only; tests/test_consult_exposures.py holds every catalogue record to them, so
# a change of wording in the generator fails there rather than silently reading nothing.
_DESCRIBED_ONE = "The catalogue describes it as: "
_DESCRIBED_MANY = re.compile(r"The catalogue describes (?:each of them|the \d+ most recently "
                             r"added): ")
_DESCRIBED_END = re.compile(r" The other \d+ are described in the catalogue under their "
                            r"identifiers\.| \d+ of these identifiers (?:is|are) already carried "
                            r"by ")
# Where a description's subject ends: the catalogue writes "<vendor> <products> contain ...".
# A description that opens another way ("A remote code execution vulnerability exists in ...")
# yields a subject naming no product, and so names nothing here.
_DESCRIPTION_VERB = re.compile(r"\s+(?:contains?|has|have|is|are|could|allows?|fails?|does|do|"
                               r"uses?|may|can|expose[sd]?|exists?)\b")


def catch_all_record(record):
    """Is this a catalogue exposure whose every product entry is a catch-all?"""
    products = (record.get("who") or {}).get("products") or []
    return (record.get("record_type") == "exposure" and KEV_TAG in (record.get("tags") or [])
            and bool(products) and all(CATCH_ALL_PRODUCT.search(p) for p in products))


def catalogue_descriptions(record):
    """{identifier: the catalogue's description of it}, as a catalogue record's summary quotes
    them, newest first; {} for any other record. A record carrying more than the generator
    describes holds the rest by identifier only, and they are absent here."""
    if KEV_TAG not in (record.get("tags") or []) or record.get("record_type") != "exposure":
        return {}
    summary = (record.get("what") or {}).get("summary") or ""
    ids = list((record.get("what") or {}).get("vulnerabilities") or [])
    if len(ids) == 1 and _DESCRIBED_ONE in summary:
        body = summary.split(_DESCRIBED_ONE, 1)[1]
        end = _DESCRIBED_END.search(body)
        return {ids[0]: (body[:end.start()] if end else body).strip()}
    start = _DESCRIBED_MANY.search(summary)
    if not start:
        return {}
    body = summary[start.end():]
    end = _DESCRIBED_END.search(body)
    body = body[:end.start()] if end else body
    # Split only at an identifier the record carries, followed by ": ", so a description
    # mentioning another identifier ("CVE-2025-59719 pertains to the same problem") stays whole.
    cuts = [(m.start(), m.end(), m.group(1)) for m in re.finditer(r"(CVE-\d{4}-\d{4,7}): ", body)
            if m.group(1) in ids]
    return {identifier: body[end_at:(cuts[i + 1][0] if i + 1 < len(cuts) else len(body))].strip()
            for i, (_, end_at, identifier) in enumerate(cuts)}


def catalogue_hits(resolved, record):
    """For a catalogue record filed under a catch-all product, {identifier: (vendor, product,
    part, relation)} for each identifier whose catalogue description names a resolved product.

    The description's subject is read exactly as product_hits() reads a product entry, under
    the record's own vendor, so a product is named here only where it would be named in the
    product field: whole, by one of its product_forms(), in a part of a list. Until 0.43.0 the
    tier read who.products alone, so "Fortinet Multiple Products", whose catalogue text names
    FortiOS for five of its six exploited identifiers, was "not the product asked about" for
    FortiGate and listed below a PSIRT record none of whose fifteen identifiers was exploited.
    """
    if not catch_all_record(record):
        return {}
    vendor = (record.get("who") or {}).get("vendor")
    out = {}
    for identifier, text in catalogue_descriptions(record).items():
        verb = _DESCRIPTION_VERB.search(text)
        subject = description_subject(text[:verb.start()]) if verb else ""
        if not subject:
            continue
        hits = product_hits(resolved, {"who": {"vendor": vendor, "products": [subject]}})
        if subject in hits:
            out[identifier] = hits[subject]
    return out


def description_subject(text):
    """A description's subject as a product list product_parts() can split.

    Two catalogue spellings are rewritten: a possessive ("MobileIron's Core") drops its "'s",
    and "A B & C", where C is one word, is two products sharing a qualifier, "A B" and "A C":
    the catalogue writes "Ivanti MobileIron's Core & Connector, Sentry, and ..." for the product
    now named Endpoint Manager Mobile. Where C is longer ("Traffic Manager & Universal Gateway")
    the ampersand is a plain list separator.
    """
    text = re.sub(r"(\w)'s\b", r"\1", text.strip())
    parts = []
    for part in re.split(r"\s*,\s*", text):
        left, _, right = part.partition(" & ")
        if right and len(right.split()) == 1 and len(left.split()) > 1:
            part = "{}, {} {}".format(left, " ".join(left.split()[:-1]), right)
        elif right:
            part = "{}, {}".format(left, right)
        parts.append(part)
    return ", ".join(parts)


def catalogue_labels(resolved, record):
    """catalogue_hits() grouped for printing: [(label, [identifiers])], the label the part of
    the description naming the product, without a leading vendor name, and how it names it
    ("FortiOS (as FortiGate)"), identifiers newest first as the summary gives them."""
    grouped = collections.OrderedDict()
    vendor = (record.get("who") or {}).get("vendor") or ""
    for identifier, (_, product, part, relation) in catalogue_hits(resolved, record).items():
        # The catalogue opens each description with the vendor, so "Fortinet FortiOS" and
        # "FortiOS" are one spelling; the vendor is dropped where it leads.
        if vendor and part.lower().startswith(vendor.lower() + " "):
            part = part[len(vendor) + 1:]
        label = part if relation == "own" else "{} ({})".format(
            part, "a component of {}".format(product) if relation == "component"
            else "as {}".format(product))
        # One spelling whatever its case: the catalogue writes "Workspace ONE Access" and
        # "Workspace One Access" in one record.
        label = next((seen for seen in grouped if seen.lower() == label.lower()), label)
        grouped.setdefault(label, []).append(identifier)
    return list(grouped.items())


def product_identifiers(resolved, record):
    """The identifiers a `product`-tier exposure holds as the asked product's own: every one
    where the product field names the product, and for a catch-all entry only those whose
    catalogue description names it. [] for an exposure outside the tier."""
    if product_matches(resolved, record):
        return list((record.get("what") or {}).get("vulnerabilities") or [])
    return sorted(catalogue_hits(resolved, record))


def _contains_any(words, sequences):
    """Does any non-empty sequence of `sequences` stand as whole words inside `words`?"""
    return any(seq and _contains(words, tuple(seq)) for seq in sequences)


def refused_terms(record, resolved):
    """The question words that may not reach this record, because it is what they were refused as.

    A word the resolver refused as a vendor's product, or as a vendor, cannot reach a record
    filed under that vendor, or a record about a class of product whose entries name it; a
    word refused as a class cannot reach a record carrying that class. Every other record it
    may still reach: "edge" was refused as Microsoft Edge and still finds the records tagged
    about edge devices, and "iOS" refused as Cisco's still finds Apple's.
    """
    meanings = resolved.get("refused_meanings") or ()
    if not meanings:
        return set()
    who = record.get("who") or {}
    vendor = tuple(normalise(who.get("vendor") or "").split())
    classes = set(who.get("product_class") or [])
    entries = [normalise(p).split() for p in who.get("products") or []]
    generic = who.get("vendor") in SENTINEL_VENDORS
    names_of = resolved.get("refused_names") or {}
    out = set()
    for kind, alias, targets in meanings:
        if kind == "class":
            hit = bool(classes & set(targets))
        else:
            seqs = set().union(*(names_of.get(t) or {tuple(normalise(t).split())}
                                 for t in targets))
            hit = vendor in seqs or (generic and any(
                _contains(words, seq) for words in entries for seq in seqs if seq))
        if hit:
            out |= set(alias.split())
    return out


def score(record, resolved, patterns=None):
    """Higher is a better match. Zero means do not return it."""
    who = record.get("who", {})
    classes = set(who.get("product_class", []))

    points = 0
    reasons = []

    named_vendor = vendor_reason(record, resolved)
    if named_vendor:
        points += 4
        reasons.append(named_vendor)
    named_products = product_labels(resolved, record)
    if named_products:
        points += 6
        reasons.append("product {}".format(", ".join(named_products)))
    hit_classes = classes & resolved["classes"]
    if hit_classes:
        points += 3
        reasons.append("class {}".format(", ".join(sorted(hit_classes))))

    # Sector only ever lifts a record that already matched on technology. On its own it must
    # not qualify anything, or asking about one firewall in a water utility returns every
    # record ever reported in the water sector, which buries the answer.
    tech_points = points
    sectors = set(record.get("who2", {}).get("target_sectors", []))
    hit_sectors = sectors & resolved["sectors"]
    if tech_points > 0 and hit_sectors:
        points += 4
        reasons.append("sector {}".format(", ".join(sorted(hit_sectors))))
    elif tech_points > 0 and resolved["sectors"] and "cross_sector" in sectors:
        points += 1
        reasons.append("cross-sector")

    hay = None
    if not points:
        # Classes contribute their suffix, not their prefix. A product class is
        # written "app.cicd", and normalising the dot to a space made the prefix a
        # free-text token, so "app" matched every app.* record equally: archivers
        # and ERP ranked alongside the CI/CD records actually asked for. The prefix
        # is taxonomy scaffolding and names nothing; the suffix carries the meaning.
        hay = free_text_haystacks(record, patterns)
        for term in sorted(set(resolved["terms"]) - refused_terms(record, resolved)):
            # Word boundary, not substring. A substring test made short terms match
            # inside longer words: "app" hit "appliance" and "application", so a
            # query naming a CI/CD class returned firewalls and historians ranked
            # alongside genuine matches, with nothing on screen to show why.
            pattern_re = r"\b{}\b".format(re.escape(term))
            for tier, worth in FREE_TEXT_TIERS:
                # First tier wins, so a term present both as a tag and in the prose
                # scores once, at the tighter of the two. Naming the tier in the
                # reason is what lets a reader see that a finding arrived on loose
                # prose rather than by name.
                if re.search(pattern_re, hay[tier]):
                    points += worth
                    reasons.append("term {} ({})".format(term, tier))
                    break
        # A vendor or product the resolver admitted is searched as its whole phrase, and in
        # names only: "check point" inside a product name is the vendor, while "point" in a
        # record's prose was "entry point", "mount point" or "point of sale".
        worth = dict(FREE_TEXT_TIERS)["name-fragment"]
        for phrase in sorted(resolved.get("name_phrases") or ()):
            if re.search(r"\b{}\b".format(re.escape(phrase)), hay["name-fragment"]):
                points += worth
                reasons.append("term {} (name-fragment)".format(phrase))
    elif resolved["terms"]:
        # The words left over once the technology resolved are what the caller asked ABOUT it:
        # "boot image implant" after "Fortinet FortiGate". They were never tested against a
        # record that matched by name, so they reordered nothing. They are reported here and
        # score nothing, so this ordering is unchanged and consult.py can use them within a
        # group of equally named findings.
        hay = free_text_haystacks(record, patterns)
        for term in sorted(set(resolved["terms"]) - refused_terms(record, resolved)):
            pattern_re = r"\b{}\b".format(re.escape(term))
            for tier in ("tag", "pattern", "summary"):
                if re.search(pattern_re, hay[tier]):
                    reasons.append("refine term {} ({})".format(term, tier))
                    break

    # A vendor match alone is weaker than a vendor plus the right class.
    if named_vendor and resolved["classes"] and not hit_classes:
        points -= 2

    return points, reasons


# What a generated exposure's identifiers say about themselves (0.44.0). A generated record's
# class is one value for every identifier it carries, so a firewall's management-interface
# flaw sat on CONTROL with its forwarding flaws. The generators read each identifier's own
# catalogue description, advisory title or database description with the table in
# locus-map.json identifier_reading and write what.identifier_signals; validate.py re-reads what
# a record quotes with the same functions. They live here, and nowhere else, because the
# generators load this file from the bundle they write into, so the rule that wrote an entry
# and the rule that checks it are one piece of code.
_READING = {}


def identifier_reading(locus_map):
    """locus-map.json identifier_reading, compiled, or None where the map carries no table.

    {"fields": {tag: [field, ...]}, "undecomposed": set, "prefix": str, "rules": [(rule,
    locus, class, regex), ...], "unless": {rule: regex}}. A rule's `unless` names words that
    put the text in another sense, and a text they match is not read by that rule. Cached per
    map object: the generators and validate.py read every identifier through it. A pattern that
    does not compile raises, and validate.py checks the table before it reads any record
    through it."""
    table = (locus_map or {}).get("identifier_reading")
    if not isinstance(table, dict):
        return None
    cached = _READING.get(id(locus_map))
    if cached is not None and cached[0] is locus_map:
        return cached[1]
    compiled = {
        "fields": {tag: list(fields or ()) for tag, fields in (table.get("fields") or {}).items()},
        "undecomposed": set(table.get("undecomposed_classes") or ()),
        "prefix": table.get("class_requires_prefix") or "",
        "rules": [(rule.get("rule"), rule.get("locus"), rule.get("class"),
                   re.compile(rule.get("pattern") or ""))
                  for rule in table.get("rules") or () if isinstance(rule, dict)],
        "unless": {rule.get("rule"): re.compile(rule["unless"])
                   for rule in table.get("rules") or ()
                   if isinstance(rule, dict) and rule.get("unless")},
    }
    _READING[id(locus_map)] = (locus_map, compiled)
    return compiled


def _earliest(rules, text, unless=None):
    """(rule, locus, class, phrase) of the earliest match in `text` over `rules`, ties in rule
    order, or None. Earliest in the text rather than first in the table, so adding a rule never
    re-keys text an earlier rule already read. A rule whose `unless` words the text carries
    does not read it."""
    best = None
    for name, locus, cls, regex in rules:
        if (unless or {}).get(name) is not None and unless[name].search(text or ""):
            continue
        found = regex.search(text or "")
        if found and (best is None or found.start() < best[0]):
            best = (found.start(), name, locus, cls, found.group(0))
    return best[1:] if best else None


def read_identifier(texts, read_class, locus_map, held=()):
    """(locus entry, class entry) for one identifier, each {"rule", "locus"|"class", "phrase",
    "field"} or None.

    `texts` is [(field, text), ...] in the table's field order. Within a text the earliest match
    wins; the first text that yields one decides. The class rule is read the same way and
    independently. `read_class` is False on a record that may not take a class reading, and a
    class in `held` is one the record already carries, so it is not read again."""
    table = identifier_reading(locus_map)
    if not table:
        return None, None
    locus_rules = [r for r in table["rules"] if r[1]]
    class_rules = [r for r in table["rules"] if r[2] and r[2] not in set(held)] if read_class else []
    entries = []
    for rules, kind in ((locus_rules, "locus"), (class_rules, "class")):
        found = None
        for field, text in texts:
            hit = _earliest(rules, text, table.get("unless"))
            if hit:
                name, locus, cls, phrase = hit
                found = {"rule": name, kind: locus if kind == "locus" else cls,
                         "phrase": phrase, "field": field}
                break
        entries.append(found)
    return entries[0], entries[1]


def identifier_signals(record, texts_by_id, locus_map):
    """what.identifier_signals for one generated exposure: the entries, "id" first, in
    what.vulnerabilities order and locus before class, or [] where the record is not read.

    `texts_by_id` is {identifier: [(field, text), ...]} from the generator's own row store; a
    field the table does not name for the record's tag is not read. A record whose first
    product class is in undecomposed_classes is not read at all, and a class reading needs a
    class beginning with class_requires_prefix on the record. The one function the generators
    call, and the one validate.py holds a record's entries to."""
    table = identifier_reading(locus_map)
    if not table or record.get("record_type") != "exposure":
        return []
    tag = next((t for t in table["fields"] if t in (record.get("tags") or [])), None)
    if tag is None:
        return []
    nonproduct = set((locus_map or {}).get("nonproduct_class") or [])
    classes = list((record.get("who") or {}).get("product_class") or [])
    productive = [c for c in classes if c not in nonproduct]
    if productive and productive[0] in table["undecomposed"]:
        return []
    read_class = bool(table["prefix"]) and any(c.startswith(table["prefix"]) for c in classes)
    fields = table["fields"][tag]
    out = []
    for identifier in (record.get("what") or {}).get("vulnerabilities") or []:
        texts = sorted(((f, t) for f, t in texts_by_id.get(identifier) or () if f in fields),
                       key=lambda pair: fields.index(pair[0]))
        for entry in read_identifier(texts, read_class, locus_map, held=classes):
            if entry:
                out.append(dict([("id", identifier)] + list(entry.items())))
    return out


def identifier_classes(record):
    """{class: [identifiers]} a generated exposure's what.identifier_signals read as a class."""
    out = {}
    for entry in ((record or {}).get("what") or {}).get("identifier_signals") or []:
        if isinstance(entry, dict) and entry.get("class"):
            out.setdefault(entry["class"], []).append(entry.get("id"))
    return out


# How an exposure relates to the question, closest first. An exposure is a vulnerability fact
# with no detection logic, so unlike an observation it transfers nothing to another vendor's
# product: a CVE in Cisco's firewall says nothing about Check Point's. The first four tiers
# name the vendor asked about; the rest are counted by consult.py and not listed there, and
# query.py lists them after every named tier, labelled. `other-products-of-vendor` is the vendor
# tier when the question also named a product or a class the record does not carry.
EXPOSURE_TIERS = ("product", "vendor-class", "vendor", "other-products-of-vendor",
                  "product-name-other-vendor", "class-only", "prose-only")


def exposure_tier(record, resolved, reasons=()):
    """Which of EXPOSURE_TIERS an exposure is in for this question, or None for no relation.

    A catalogue record filed under a catch-all product ("Multiple Products") is in the product
    tier when the catalogue's own description of any of its identifiers names the product
    asked about (catalogue_hits()); EXPOSURE_MATCH then says which identifiers do.

    A class a generated exposure's identifiers read by their own text (identifier_classes())
    reaches the vendor-class tier and nothing below it: "Check Point VPN" listed none of the
    three Check Point identifiers the catalogue describes as VPN flaws, and read for a question
    naming no vendor the same class took "VPN gateway" from 30 class-only exposures to 71.
    """
    same_vendor = vendor_reason(record, resolved) is not None
    if product_matches(resolved, record) or catalogue_hits(resolved, record):
        return "product"
    asked = set(resolved.get("classes") or ())
    hit_class = set((record.get("who") or {}).get("product_class") or []) & asked
    if same_vendor and (hit_class or set(identifier_classes(record)) & asked):
        return "vendor-class"
    if same_vendor:
        return "other-products-of-vendor" \
            if resolved.get("products") or resolved.get("classes") else "vendor"
    if product_matches(resolved, record, any_vendor=True):
        return "product-name-other-vendor"
    if hit_class:
        return "class-only"
    if any(r.startswith("term ") for r in reasons or ()):
        return "prose-only"
    return None


KEV_TAG = "known-exploited-catalogue"


def identifier_carriers(records):
    """{identifier: set of the observation ids carrying it}, over every observation.

    What an exposure means when it says an identifier is "already carried by an observation
    record": query.py prints the carriers under each exposure it lists, and consult.py's
    EXPOSURE_DETECTION_HELD reads the same map, so the two cannot name different records.
    """
    out = collections.defaultdict(set)
    for record in records:
        if record.get("record_type", "observation") == "observation":
            for identifier in (record.get("what") or {}).get("vulnerabilities") or []:
                out[identifier].add(record.get("id"))
    return out


def carried_by(exposure, carriers):
    """{observation id: sorted identifiers of this exposure it carries}."""
    out = collections.defaultdict(set)
    for identifier in (exposure.get("what") or {}).get("vulnerabilities") or []:
        for rid in carriers.get(identifier, ()):
            out[rid].add(identifier)
    return {rid: sorted(ids) for rid, ids in sorted(out.items())}


# What a record reached only through the identifier join scores. The identifier is the
# product's own, catalogued against it, so the record documents that product's flaw in use:
# it is worth what naming the product is worth, and it is never added to a record that
# already names the product. Its detection logic may still be written for another product in
# the same incident, which the reason says.
IDENTIFIER_POINTS = 6


def kev_identifiers(records):
    """Every identifier a catalogue record in this corpus carries."""
    return {v for r in records if KEV_TAG in (r.get("tags") or [])
            for v in (r.get("what") or {}).get("vulnerabilities") or []}


def exposure_kind(record, kev_ids):
    """EXPLOITED when any identifier is in the catalogue, ADVISORY from a government advisory,
    otherwise DISCLOSED. Read from the identifiers, never from a tag another generator wrote."""
    ids = set((record.get("what") or {}).get("vulnerabilities") or [])
    if ids & kev_ids or KEV_TAG in (record.get("tags") or []):
        return "EXPLOITED"
    if (record.get("where") or {}).get("source_type") == "government_advisory":
        return "ADVISORY"
    return "DISCLOSED"


def held_date(record):
    """The record's date as it holds it, at its precision: 2022, 2026-08 or 2026-08-15."""
    when = record.get("when") or {}
    value = when.get("published") or when.get("observed_end") or when.get("observed_start") or ""
    return str(value)[:10]


def date_key(record):
    """The record's date as YYYY-MM-DD, missing parts as 00, so it sorts; '' when undated.

    A sort key only: 2026-08-00 is not a date, and the JSON tie-break printed it as one, so a
    consumer parsing it failed. What a record holds is printed with held_date()."""
    value = held_date(record)
    if not value:
        return ""
    parts = (value.split("-") + ["00", "00"])[:3]
    return "-".join(p.zfill(2) for p in parts)


# --- ties in the observation listing -----------------------------------------------------
# 67 of 73 "Linux kernel" observations tie at score 3 on class alone, and the tie fell to the
# record id: the 20 shown were the first 20 ids, none of them naming Linux and seven carrying
# Windows-only markers. Ties now fall to whether the record mentions what was named, then to
# whether its markers fit the platform asked about, then to recency, and only then to the id.
# score() is untouched: these decide order between equal scores and never qualify a record.

# Marker content that commits a detection to a platform. Generic unix counts for Linux and
# macOS both. curl and wget are deliberately absent, because curl.exe ships with Windows.
# A Windows file extension is Windows's whatever the name before it: the dot is a word
# boundary, so until 0.43.0 "bash.exe" read as the Unix shell, and a pattern whose markers
# are all Windows binaries was offered to a Linux question as fitting Linux.
_WINDOWS_EXTENSIONS = r"exe|dll|ps1|bat|cmd|lnk|vbs|hta|msi|sys|cpl|chm"
PLATFORM_INDICATORS = (
    ("windows", re.compile(
        r"(?i)(\.(" + _WINDOWS_EXTENSIONS + r")\b|\b[a-z]:\\|\\(windows|users|"
        r"programdata|system32|appdata)\\|%(temp|appdata|programdata|localappdata)%|\bhk(lm|cu|"
        r"ey_)|\b(powershell|rundll32|regsvr32|mshta|certutil|wmic|schtasks|lsass|svchost|"
        r"spoolsv|bitsadmin|wsmprovhost|winrs)\b)")),
    ("unix", re.compile(
        r"(?i)((^|[\s\"'(|^])/(tmp|etc|var|usr|bin|sbin|dev/shm|root|home|opt|lib)\b|\.(so|sh|"
        r"elf)\b|\b(bash|chmod|chown|crontab|sudo|sudoers|visudo|useradd|usermod|groupadd|"
        r"bash_history|zsh_history|histfile|histsize|nohup|setuid)\b(?!\.(" + _WINDOWS_EXTENSIONS
        + r")\b))")),
    ("linux", re.compile(
        r"(?i)(\b(systemd|systemctl|journalctl|insmod|modprobe|ld_preload|auditd|apt|apt-get|"
        r"yum|dnf|dpkg|rpm)\b|ld\.so\.preload|(^|[\s\"'(|^])/proc/)")),
    ("macos", re.compile(
        r"(?i)(\b(dscl|launchctl|osascript|sysadminctl|launchd)\b|\.plist\b|/library/"
        r"(launchagents|launchdaemons))")),
)
WINDOWS_MARKER_TYPES = {"registry_key", "registry_value_name", "registry_data",
                        "scheduled_task_name"}
# Where no marker commits, the record's own names may.
NAMED_PLATFORMS = (("windows", re.compile(r"\bwindows\b")),
                   ("linux", re.compile(r"\b(linux|red hat|ubuntu|debian|centos|suse)\b")),
                   ("unix", re.compile(r"\b(unix|freebsd|solaris)\b")),
                   ("macos", re.compile(r"\bmacos\b")))
PLATFORMS = ("windows", "linux", "macos", "unix")


def marker_platforms(markers):
    found = set()
    for marker in markers or []:
        if marker.get("type") in WINDOWS_MARKER_TYPES:
            found.add("windows")
            continue
        values = marker.get("value")
        values = values if isinstance(values, list) else [values]
        text = " ".join(str(v) for v in values if v is not None) \
            + " " + str(marker.get("expr") or "")
        for platform, pattern in PLATFORM_INDICATORS:
            if pattern.search(text):
                found.add(platform)
    return found


def record_platforms(record, patterns=None):
    """The platforms a record's detections are written for, from marker content first."""
    found = set()
    for how in record.get("how") or []:
        pattern = (patterns or {}).get(how.get("pattern_id")) or {}
        markers = how.get("markers") or pattern.get("markers")
        found |= marker_platforms(markers)
    if found:
        return found
    who = record.get("who") or {}
    text = normalise(" ".join([who.get("vendor") or ""] + list(who.get("products") or [])))
    return {platform for platform, rx in NAMED_PLATFORMS if rx.search(text)}


def question_platforms(resolved, aliases):
    """The platforms the question names, from the curated `platform_of` table."""
    table = aliases.get("platform_of") or {}
    keys = {normalise(v) for v in resolved.get("vendors") or ()}
    for vendor, product in resolved.get("product_pairs") or ():
        keys.add(normalise(product))
        keys.add(normalise("{} {}".format(vendor, product)))
    return {table[k] for k in keys if k in table}


def platform_fit(have, want):
    """+1 when the record fits a platform asked about, -1 when it fits none, 0 when unknown."""
    if not have or not want:
        return 0
    have = set(have) | ({"linux", "macos"} if "unix" in have else set())
    want = set(want) | ({"linux", "macos"} if "unix" in want else set())
    return 1 if have & want else -1


def identity_tokens(resolved, aliases):
    """The words that name what resolved, minus the ones that are also ordinary words."""
    vendors = set(resolved.get("vendors") or ())
    products = set(resolved.get("products") or ()) - set(resolved.get("vendorless_products") or ())
    out = {k for k, v in (aliases.get("vendor_aliases") or {}).items() if v in vendors}
    out |= {k for k, v in (aliases.get("product_aliases") or {}).items()
            if v.get("product") in products and v.get("vendor") in vendors}
    out |= {normalise(v) for v in vendors} | {normalise(p) for p in products}
    out -= set(aliases.get("ambiguous_aliases") or {})
    out -= set(aliases.get("ambiguous_vendor_aliases") or {})
    out -= {normalise(v) for v in SENTINEL_VENDORS}
    out.discard("")
    return out


def identity_mention(record, tokens, patterns=None):
    """2 when a name the question resolved is in the record's names or tags, 1 in its summary."""
    if not tokens:
        return 0
    hay = free_text_haystacks(record, patterns)
    for tier, worth in (("name-fragment", 2), ("tag", 2), ("summary", 1)):
        if any(re.search(r"\b{}\b".format(re.escape(t)), hay[tier]) for t in tokens):
            return worth
    return 0


def record_loci(record, patterns, locus_map, locus_for, order=()):
    """The distinct LOCUS of a record's how-blocks, or of the record itself when it has none.

    Question-independent, as every script that places a block without a question places it,
    so a line here and a consultation's finding for the same block print the same plane.
    """
    hows = record.get("how") or []
    if hows:
        found = {locus_for(record, how, (patterns or {}).get(how.get("pattern_id")),
                           locus_map)[0] for how in hows}
    else:
        found = {locus_for(record, None, None, locus_map)[0]}
    rank = {name: i for i, name in enumerate(order or ())}
    return sorted(found, key=lambda name: (rank.get(name, len(rank)), name))


def _descending(text):
    """A sort key that orders strings descending inside an ascending sort; '' sorts last."""
    return (0 if text else 1, tuple(-ord(c) for c in text))


def brief(record, reasons=(), tier=None, loci=(), carried=None, handset=False, named=None):
    """One line per record.

    The default, because a technology with real history returns thirty-odd records
    and the full form of that runs to roughly ten thousand tokens. Reading all of
    it to answer one question is the slow path. This is enough to choose which
    records deserve the full form, which is what --full then gives.

    `loci` is the plane or planes the record's blocks sit in, printed on the line: SKILL.md
    sends a caller here first, and until 0.43.0 no line, header or key on this path said
    which plane anything sat in, or that one was missing.

    `carried` is an exposure's carried_by(): the observations holding its identifiers, named
    on a line of their own. The catalogue record said an identifier was "already carried by
    an observation record" and nothing on this path said which.

    `handset` marks an exposure corpus/schema/scope.json keeps out of a consultation. This is
    the path SKILL.md starts a caller on, and a Pixel catalogue record was listed fourth for
    "Linux kernel" with nothing saying handsets are out of scope.

    `named` is catalogue_labels() for a catch-all catalogue record in the product tier: which
    identifiers the catalogue's description says are the product's, since its product field
    ("Multiple Products") says nothing.
    """
    who = record["who"]
    what = record["what"]
    kind = "exp" if record.get("record_type") == "exposure" else "obs"
    fid = sorted({h["fidelity"] for h in record.get("how", [])})
    # First sentence carries the scenario; the rest is qualification.
    summary = re.split(r"(?<=[.;])\s", what["summary"].strip())[0]
    if len(summary) > 132:
        summary = summary[:129].rstrip() + "..."
    # A record that matched only on free text is a weak match. Say so on the line,
    # because otherwise it ranks silently alongside a vendor or class match and the
    # caller has no way to tell a real answer from a coincidence of wording.
    weak = "  <- weak match, free text only" if reasons and all(
        r.startswith("term ") for r in reasons) else ""
    # An exposure says how it relates to the question, because the exposure listing is
    # ordered by that relation and a class-only CVE in another vendor's product reads like
    # one about yours unless the line says otherwise.
    related = "  [{}]".format(tier) if tier else ""
    if handset:
        related += "  <- handset record, out of scope (corpus/schema/scope.json)"
    planes = "  loci={}".format(",".join(loci)) if loci else ""
    joined = [r for r in reasons or () if r.startswith("identifier ")]
    if joined:
        weak = "  <- reached by {}".format("; ".join(joined))
    line = "{:<3} {:<62} [{}{}] {} {}{}{}{}\n      {}".format(
        kind, record["id"], what["role"],
        "/" + ",".join(fid) if fid else "",
        who["vendor"], "/".join(who["products"])[:40], planes, related, weak, summary)
    if named:
        line += "\n      catalogue description names the product: {}".format("; ".join(
            "{} in {}".format(label, ", ".join(ids)) for label, ids in named))
    if carried:
        line += "\n      identifiers also carried by: {}".format("; ".join(
            "{} ({})".format(rid, ", ".join(ids)) for rid, ids in carried.items()))
    return line


def unnamed_actor(who2):
    """What `who2` says about the actor when it names none.

    `unattributed` is one value of `actor_type`, not the absence of a name. Printed for every
    record whose `actors` list was empty, it made 36 state-nexus records read as unattributed,
    8 of them beside `attribution_confidence: high`: a joint advisory can attribute an
    intrusion to a state without naming the group, and the corpus records exactly that.
    """
    kind = who2.get("actor_type") or "unattributed"
    if kind == "unattributed":
        return "unattributed"
    return "no actor named; actor_type {}, attribution {}".format(
        kind, who2.get("attribution_confidence") or "unstated")


def summarise(record, patterns, verbose):
    who = record["who"]
    what = record["what"]
    source = record["where"]
    when = record.get("when", {})
    actors = record.get("who2", {}).get("actors", [])

    lines = []
    kind = record.get("record_type", "observation")
    lines.append("{}  [{}{}]".format(record["id"], record["status"],
                                     "" if kind == "observation" else " / exposure"))
    lines.append("  who    {} {} ({})".format(who["vendor"], "/".join(who["products"]), ", ".join(who["product_class"])))
    lines.append("  what   [{}] {}".format(what["role"], what["summary"]))
    if what.get("vulnerabilities"):
        lines.append("         {}".format(", ".join(what["vulnerabilities"])))
    sectors = record.get("who2", {}).get("target_sectors", [])
    typed = (record.get("who2", {}).get("actor_type") or "unattributed") != "unattributed"
    if actors or sectors or typed:
        lines.append("  who2   {}{}".format(", ".join(actors) or unnamed_actor(record.get("who2", {})),
                                            "  [sectors: {}]".format(", ".join(sectors)) if sectors else ""))
    date = when.get("observed_start") or when.get("published") or "undated"
    lines.append("  when   {}".format(date))
    lines.append("  where  {} / {}".format(source["publisher"], source["title"]))

    for how in record.get("how", []):
        head = "  how    [{}/{}] {}".format(how["fidelity"], how["confidence"], how["logic"])
        lines.append(head)
        if verbose:
            if how.get("evidence_type"):
                lines.append("           needs: {}".format(", ".join(how["evidence_type"])))
            if how.get("dataset_hint"):
                lines.append("           datasets: {}".format(", ".join(how["dataset_hint"])))
            for field in how.get("fields", []):
                lines.append("           {} {} {!r}".format(field.get("xdm") or field.get("raw"), field["op"], field["value"]))
            pid = how.get("pattern_id")
            if pid and pid in patterns:
                lines.append("           pattern: {} ({})".format(pid, patterns[pid].get("name", "")))
    return "\n".join(lines)


def below_floor(args, floors):
    """The error line for the first count argument below its floor, or None.

    Shared by every script that takes a count, so one flag cannot mean two things in two
    places. `type=int` accepted anything, and every cap here is applied as a slice, so a
    negative value was read from the END of the ranking: `--exposure-limit -1` listed all
    but the last exposure, and `consult.py --limit 0` announced that the resolver matched
    nothing over ninety-seven matches. The main listing of each script takes 1 or more; a
    secondary block may take 0, which lists none of it and leaves the rest of the answer
    intact.
    """
    for flag, floor in floors:
        value = getattr(args, flag.lstrip("-").replace("-", "_"), None)
        if value is not None and value < floor:
            return "ERROR: {} must be {} or more (got {})".format(flag, floor, value)
    return None


def main():
    parser = argparse.ArgumentParser(description="Query the advisory corpus.")
    parser.add_argument("query", help="What the caller has, in their own words.")
    parser.add_argument("--corpus", default=os.path.join(BUNDLE_ROOT, "corpus"))
    parser.add_argument("--role", help="Only return records whose what.role is this role. "
                                       "It is one value per record, not per product or class "
                                       "the record names.")
    parser.add_argument("--sector", help="Restrict to records reported in this sector, as a hard filter rather than a ranking boost. Accepts a vocab value or an alias.")
    parser.add_argument("--limit", type=int, default=20, help="Maximum observations to return, 1 or more.")
    parser.add_argument("--exposure-limit", type=int, default=10, help="Maximum exposure records to return, reported separately after the observations. 0 lists none; the header still counts them.")
    parser.add_argument("--json", action="store_true", help="Emit matching records as JSON.")
    parser.add_argument("--full", action="store_true",
                        help="Full record detail rather than one line each. Needed to read "
                             "detection logic and caveats; costs roughly ten times the output.")
    parser.add_argument("--pattern-limit", type=int, default=6,
                        help="Maximum library patterns to show (patterns no record cites). "
                             "0 lists none.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detection fields and datasets.")
    args = parser.parse_args()
    refused = below_floor(args, (("--limit", 1), ("--exposure-limit", 0), ("--pattern-limit", 0)))
    if refused:
        print(refused, file=sys.stderr)
        return 2

    with open(os.path.join(args.corpus, "schema", "aliases.json"), "r", encoding="utf-8") as handle:
        aliases = normalise_alias_keys(json.load(handle))

    records, patterns = load_corpus(args.corpus)
    resolved = resolve(args.query, aliases)

    sector_filter = None
    if args.sector:
        with open(os.path.join(args.corpus, "schema", "vocab.json"), "r",
                  encoding="utf-8") as handle:
            vocab = json.load(handle)
        # An unrecognised value used to filter anyway: every record lacking that sector and
        # lacking cross_sector was dropped, so a typo returned a smaller answer that read like
        # the whole one, and the resolver line printed sectors=- while the filter was live.
        known = (set(aliases.get("sector_aliases", {}).values())
                 | set(aliases.get("sector_aliases", {}))
                 | set(vocab.get("target_sector") or []))
        sector_filter = aliases.get("sector_aliases", {}).get(
            args.sector.lower(), args.sector)
        if args.sector.lower() not in known and sector_filter not in known:
            print("ERROR: --sector {} is not a sector this corpus knows. Known values live in "
                  "corpus/schema/aliases.json under sector_aliases.".format(args.sector),
                  file=sys.stderr)
            return 2
    def kept(record):
        if args.role and record.get("what", {}).get("role") != args.role:
            return False
        if args.sector:
            secs = record.get("who2", {}).get("target_sectors", [])
            if sector_filter not in secs and "cross_sector" not in secs:
                return False
        return True

    hits = []
    for record in records:
        if not kept(record):
            continue
        points, reasons = score(record, resolved, patterns)
        if points > 0:
            hits.append((points, reasons, record))

    # The identifier join. An exposure naming the product asked about lists that product's
    # identifiers, and an observation carrying one of them documents the product's flaw in
    # use even where it is filed under another product: "Linux kernel" never reached the one
    # observation about an exploited kernel flaw, a GeoServer intrusion that escalated through
    # it, although the kernel's own catalogue record said the identifier was carried. Such a
    # record is reached, or lifted where a class alone reached it, and says by what.
    # consult.py does not turn this into findings: a finding is one detection block, and the
    # carrying record's blocks are written for the product it is filed under, so it names
    # the record on EXPOSURE_DETECTION_HELD instead.
    carriers = identifier_carriers(records)
    joined = collections.defaultdict(lambda: collections.defaultdict(set))
    for _, reasons, rec in hits:
        if rec.get("record_type") == "exposure" and exposure_tier(rec, resolved, reasons) == "product":
            # Only the product's own: in a catch-all catalogue entry, an identifier whose
            # description names another of the vendor's products is not this product's flaw.
            own = set(product_identifiers(resolved, rec))
            for rid, ids in carried_by(rec, carriers).items():
                for identifier in ids:
                    if identifier in own:
                        joined[rid][identifier].add(rec["id"])
    by_id = {rec["id"]: rec for rec in records}
    at = {rec["id"]: index for index, (_, _, rec) in enumerate(hits)}
    for rid in sorted(joined):
        record = by_id[rid]
        if not kept(record):
            continue
        reason = "identifier {} (in {})".format(
            ", ".join(sorted(joined[rid])),
            "; ".join(sorted({e for es in joined[rid].values() for e in es})))
        if rid in at:
            points, reasons, _ = hits[at[rid]]
            if any(r.startswith("product ") for r in reasons):
                continue
            hits[at[rid]] = (points + IDENTIFIER_POINTS, reasons + [reason], record)
        else:
            hits.append((IDENTIFIER_POINTS, [reason], record))

    # Observations carry detection logic and answer "what should I watch for", so they lead.
    # Exposures are bulk-generated vulnerability facts; they are useful but must never bury
    # the observations, so they are ranked and reported separately.
    observations = [h for h in hits if h[2].get("record_type", "observation") == "observation"]
    exposures = [h for h in hits if h[2].get("record_type") == "exposure"]

    # Observations: score first, then the tie-break. The id used to break every tie, so 67
    # "Linux kernel" records tied at 3 were listed in id order and none of the 20 shown named
    # Linux. Ties now go to the record carrying more of the question's leftover words, then to
    # one naming what resolved, then to one whose markers fit the platform asked about, then
    # to the newer, and only then to the id.
    tokens = identity_tokens(resolved, aliases)
    wanted = question_platforms(resolved, aliases)
    tiebreak = {}
    for _, reasons, record in observations:
        platforms = record_platforms(record, patterns)
        tiebreak[record["id"]] = {
            "refined_by": sorted({r.split()[2] for r in reasons if r.startswith("refine term ")}),
            "identity_mention": identity_mention(record, tokens, patterns),
            "platform_fit": platform_fit(platforms, wanted),
            "platforms": sorted(platforms),
            "published": held_date(record) or None,
        }

    def observation_order(hit):
        t = tiebreak[hit[2]["id"]]
        return (-hit[0], -len(t["refined_by"]), -t["identity_mention"], -t["platform_fit"],
                _descending(date_key(hit[2])), hit[2]["id"])
    observations.sort(key=observation_order)

    # Exposures: by how they relate to the question, then exploited before advised before
    # disclosed, then newest, then id. Ranked on score, a Cisco firewall KEV record tied a
    # Check Point one for "Check Point firewall" at 3 on class alone and the id decided.
    kev_ids = kev_identifiers(records)
    tier_of = {rec["id"]: exposure_tier(rec, resolved, reasons) for _, reasons, rec in exposures}
    kind_order = ("EXPLOITED", "ADVISORY", "DISCLOSED")
    exposures.sort(key=lambda h: (
        EXPOSURE_TIERS.index(tier_of[h[2]["id"]]) if tier_of[h[2]["id"]] in EXPOSURE_TIERS
        else len(EXPOSURE_TIERS),
        kind_order.index(exposure_kind(h[2], kev_ids)), _descending(date_key(h[2])), h[2]["id"]))
    by_tier = {tier: 0 for tier in EXPOSURE_TIERS}
    for _, _, rec in exposures:
        tier = tier_of[rec["id"]] or "unrelated"
        by_tier[tier] = by_tier.get(tier, 0) + 1

    # The library's classes, from the whole match set and never from the capped listing. They
    # were inferred from the capped list, so the library's scope and the "M" in "N of M
    # shown" moved with --limit and --exposure-limit: "Oracle" matched 3 library patterns at
    # the default caps and 29 uncapped, and "Splunk" lost its library block at
    # --exposure-limit 0. A class is taken only from a record matched by name, class or
    # sector; a free-text match lends its classes only when nothing matched by name, and the
    # header then says so, because one weak Adobe match added a class worth twenty patterns.
    if resolved["classes"]:
        pattern_classes, library_basis, basis_count = set(resolved["classes"]), "resolved", 0
    else:
        structured = [rec for _, reasons, rec in observations + exposures
                      if any(r.startswith(STRUCTURED_REASONS) for r in reasons)]
        weak = [rec for _, _, rec in observations + exposures] if not structured else []
        source = structured or weak
        pattern_classes = {c for rec in source
                           for c in (rec.get("who", {}).get("product_class") or [])}
        library_basis = "inferred" if structured else "inferred-weak"
        basis_count = len(source)

    hits = observations[: args.limit] + exposures[: args.exposure_limit]
    # Counted after truncation, because the header reports both numbers. Reporting only
    # the match count over a truncated listing is how a reader concludes the corpus holds
    # twenty observations when it matched forty-two and the rest were capped away.
    shown_obs = sum(1 for _, _, rec in hits
                    if rec.get("record_type", "observation") == "observation")
    shown_exp = len(hits) - shown_obs

    # Patterns cited by a record already surface through that record. Patterns that no
    # record cites have no incident here behind them -- each says in derived_from where it
    # came from, and the listing prints it -- and would otherwise be unreachable: query.py
    # only ever used patterns to enrich records.
    # They are matched on the classes they apply to and reported in their own block.
    cited = {h.get("pattern_id") for rec in records for h in (rec.get("how") or [])}

    # Fall back to the classes the matched records declare when the query itself
    # resolved to none, computed above over the whole match set. A vendor-only alias ("SAP",
    # "Splunk") used to return records and no patterns at all, because this block keyed on
    # the query alone. That is backwards: matching a vendor's records establishes the class
    # just as well as naming it, and class-level transfer is the thing the skill exists to do.

    library, library_matched = [], 0
    if pattern_classes:
        for pid, pat in patterns.items():
            if pid in cited or not pat.get("markers"):
                continue
            if pattern_classes & set(pat.get("applies_to_classes") or []):
                corr = pat.get("external_corroboration") or {}
                weight = corr.get("sigma_rules", 0) + corr.get("splunk_detections", 0)
                fit = platform_fit(marker_platforms(pat.get("markers")), wanted)
                library.append((fit, weight, pat))
        # A pattern written for another platform sinks below every neutral or fitting one,
        # whatever its weight. The weight counts public rules tagging any technique the
        # pattern cites, on every platform, and both public rule sets are mostly Windows: 4
        # of the 6 patterns shown for "Linux kernel" carried Windows-only markers.
        library.sort(key=lambda t: (-t[0], -t[1], t[2]["id"]))
        library_matched = len(library)
        library = library[: args.pattern_limit]

    # The plane each shown record sits in. consult.py imports this module at its top, so the
    # ladder is imported here, when it is needed, rather than at this module's top.
    import consult as C  # noqa: E402
    locus_map = C.load_locus_map(args.corpus)
    scope = C.load_scope(args.corpus)
    handset_of = {rec["id"]: C.handset_record(rec, scope) for _, _, rec in hits
                  if rec.get("record_type") == "exposure"}
    locus_order = tuple(locus_map.get("locus_order") or ())
    loci_of = {rec["id"]: record_loci(rec, patterns, locus_map, C.locus_for, locus_order)
               for _, _, rec in hits}
    shown_loci = collections.Counter(name for _, _, rec in hits for name in loci_of[rec["id"]])

    def sorted_list(key):
        return sorted(resolved.get(key) or ())

    if args.json:
        print(json.dumps({
            # What the question was taken to mean, and what it was not, so a JSON consumer can
            # read the resolution rather than infer it from the records that came back.
            "resolved": {key: sorted_list(key) for key in (
                "vendors", "products", "classes", "sectors", "terms", "resolved_by", "gated")},
            "records": [dict({"score": p, "matched_on": r, "record": rec,
                              "loci": loci_of[rec["id"]]},
                             **({"exposure_tier": tier_of[rec["id"]],
                                 "exposure_kind": exposure_kind(rec, kev_ids),
                                 # The observations carrying this exposure's identifiers, by
                                 # id, with the identifiers each carries.
                                 "carried_by": carried_by(rec, carriers),
                                 # For a catch-all catalogue entry in the product tier, each
                                 # identifier whose description names the product, and how.
                                 "catalogue_names": {
                                     identifier: label for label, ids in (
                                         catalogue_labels(resolved, rec)
                                         if tier_of[rec["id"]] == "product" else [])
                                     for identifier in ids},
                                 # Kept out of a consultation by the handset decision.
                                 "handset": handset_of.get(rec["id"], False)}
                                if rec.get("record_type") == "exposure"
                                else {"tiebreak": tiebreak[rec["id"]]}))
                        for p, r, rec in hits],
            "library_patterns": [pat for _, _, pat in library],
            # The classes the library was matched on, and where they came from: resolved from
            # the question, inferred from records matched by name, class or sector, or
            # inferred-weak from free-text matches when nothing matched by name.
            "library_classes": sorted(pattern_classes),
            "library_classes_basis": library_basis,
            # A caller reading JSON cannot see that a listing was capped, and these arrays
            # are capped by default. Shipping the match counts beside them is the only way
            # the consumer can tell a short answer from a complete one.
            "counts": {
                "observations_shown": shown_obs, "observations_matched": len(observations),
                "exposures_shown": shown_exp, "exposures_matched": len(exposures),
                "exposures_by_tier": by_tier,
                "library_patterns_shown": len(library),
                "library_patterns_matched": library_matched,
                "loci_over_shown": {name: shown_loci.get(name, 0) for name in locus_order},
                "records_in_corpus": len(records),
            },
        }, indent=2))
        return 0

    print("query: {!r}".format(args.query))
    print("resolved to: vendors={} products={} classes={} sectors={}".format(
        sorted(resolved["vendors"]) or "-", sorted(resolved["products"]) or "-",
        sorted(resolved["classes"]) or "-", sorted(resolved["sectors"]) or "-"))
    print("resolved by: {}".format("; ".join(sorted_list("resolved_by")) or "nothing"))
    if resolved.get("gated"):
        print("gated: {} - matched an alias and was not admitted. Name the technology if one "
              "of these is what you meant.".format("; ".join(sorted_list("gated"))))
    print("{} of {} observation(s) and {} of {} exposure(s) shown, of {} records in corpus".format(
        shown_obs, len(observations), shown_exp, len(exposures), len(records)))
    if exposures:
        print("exposures by relation to the question: {}".format(", ".join(
            "{}={}".format(k, v) for k, v in by_tier.items())))
    if hits:
        # Records per plane over what is listed below, not over the match set, so the counts
        # describe what was emitted. A record whose blocks sit in two planes counts in both.
        print("LOCUS over shown: {}; ABSENT={}".format(
            " ".join("{}={}".format(name, shown_loci.get(name, 0)) for name in locus_order),
            ",".join(name for name in locus_order if not shown_loci.get(name)) or "none"))
    capped = []
    if len(observations) > shown_obs:
        capped.append("--limit for the {} observation(s)".format(len(observations)))
    if len(exposures) > shown_exp:
        capped.append("--exposure-limit for the {} exposure(s)".format(len(exposures)))
    if library_matched > len(library):
        # SKILL.md said this line names the library cap too, and until 0.43.0 it never did.
        capped.append("--pattern-limit for the {} library pattern(s)".format(library_matched))
    if capped:
        print("OUTPUT CAPPED: raise {}. What is missing is the tail of the ranking, not "
              "the corpus.".format(" and ".join(capped)))
    print()

    full = args.full or args.verbose
    for points, reasons, record in hits:
        tier = tier_of.get(record["id"]) if record.get("record_type") == "exposure" else None
        if full:
            print(summarise(record, patterns, args.verbose))
            extra = ""
            if record["id"] in tiebreak:
                t = tiebreak[record["id"]]
                extra = ("; tie-break refined_by={} names={} platform_fit={:+d} platforms={} "
                         "published={}").format(
                    ",".join(t["refined_by"]) or "-", t["identity_mention"], t["platform_fit"],
                    ",".join(t["platforms"]) or "-", t["published"] or "undated")
            elif tier:
                extra = "; exposure {} {}{}".format(
                    tier, exposure_kind(record, kev_ids),
                    "; handset record, out of scope" if handset_of.get(record["id"]) else "")
                named = catalogue_labels(resolved, record) if tier == "product" else []
                if named:
                    extra += "; catalogue description names the product: {}".format("; ".join(
                        "{} in {}".format(label, ", ".join(ids)) for label, ids in named))
                held = carried_by(record, carriers)
                if held:
                    extra += "; identifiers also carried by {}".format("; ".join(
                        "{} ({})".format(rid, ", ".join(ids)) for rid, ids in held.items()))
            extra += "; loci={}".format(",".join(loci_of[record["id"]]))
            print("  match  {} ({}){}\n".format(points, "; ".join(reasons), extra))
        else:
            print(brief(record, reasons, tier, loci_of[record["id"]],
                        carried_by(record, carriers) if tier else None,
                        handset_of.get(record["id"], False),
                        catalogue_labels(resolved, record) if tier == "product" else None))
    if not full and hits:
        print("\nfull detail for any of the above, including detection logic and caveats:")
        print("  python3 scripts/query.py {!r} --full".format(args.query))
        # Observation ids: an exposure holds no how-block, so emit_xql.py hands off nothing
        # for one, and the footer sat under a listing that includes exp- ids.
        print("  python3 scripts/emit_xql.py <observation-id> --json    # the rule-authoring "
              "handoff; exposures carry no detection logic")

    if library:
        if library_basis == "resolved":
            scope = "this technology class"
        else:
            scope = "classes inferred from {} {}record(s) ({})".format(
                basis_count, "free-text-only matched " if library_basis == "inferred-weak"
                else "matched ", ", ".join(sorted(pattern_classes)))
        print("library patterns for {}, cited by no record yet: "
              "{} of {} shown{}\n".format(
                  scope, len(library), library_matched,
                  "; raise --pattern-limit for the rest" if library_matched > len(library) else ""))
        for fit, weight, pat in library:
            print("{}  [{} / {}]".format(pat["id"], pat.get("fidelity", "?"), pat.get("rule_shape", "?")))
            print("  {}".format(pat.get("name", "")))
            print("  derived from: {}".format("; ".join(
                str(x) for x in pat.get("derived_from") or [] if x) or "not recorded"))
            if weight:
                # The count is per technique and platform-blind, so it says how widely the
                # technique is written about, not how many implementations of this pattern exist.
                print("  {} Sigma/Splunk rule(s) tag a technique this pattern cites (any "
                      "platform)".format(weight))
            if fit < 0:
                print("  written for another platform than the one asked about; listed last")
            print()

    if not hits and not library:
        scope = C.load_scope(args.corpus)
        words = C.handset_words(resolved, scope)
        handset = C.handset_names(resolved, scope)
        # Nothing matched, so every word reached nothing; one written as a name that is neither
        # a handset name nor a refused alias's ("Kandji iPad") may be the product managing the
        # devices, or something on the handset, as consult.py says.
        unknown = C.unknown_names(resolved, resolved["terms"], scope, args.query) \
            if words else []
        if handset and not unknown:
            # consult.py's refusal for the same words: a handset name is never an alias to add.
            print("Nothing matched. {}, which this corpus does not advise on; no alias is to be "
                  "added.".format(C.handset_listed(handset, "in corpus/schema/scope.json")))
        elif handset:
            print("Nothing matched. {}, which this corpus does not advise on; a handset name is "
                  "never an alias to add. {} reached no record: if {} the product that enrols and "
                  "manages these devices, it needs an entry in corpus/schema/aliases.json with "
                  "class app.mdm; if {} something on the handset, nothing is to be added."
                  .format(C.handset_listed(handset, "in corpus/schema/scope.json"),
                          ", ".join(unknown), *(["it names"] * 2 if len(unknown) == 1
                                                else ["they name"] * 2)))
        elif words:
            print("Nothing matched. Either the corpus has no coverage, or {} needs an entry in "
                  "corpus/schema/aliases.json. {}".format(" or ".join(unknown) or "the term",
                                                          C.never_add_text(words)))
        else:
            print("Nothing matched. Either the corpus has no coverage, or the term needs an entry in corpus/schema/aliases.json.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
