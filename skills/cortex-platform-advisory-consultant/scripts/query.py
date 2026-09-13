#!/usr/bin/env python3
# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Look up corpus observations for a technology described in ordinary words.

    python3 scripts/query.py "I have a Cisco FW"
    python3 scripts/query.py "fortigate" --json
    python3 scripts/query.py "email gateway" --role victim

Resolution order: explicit product alias, explicit vendor alias, explicit class
alias, then substring match against vendor and product names. Anything the
query resolves to is reported, so a caller can see why a record came back.

Python 3.9+, standard library only.
"""

import argparse
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
    return re.sub(r"[^a-z0-9 ]+", " ", text.lower()).strip()


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
        if not isinstance(entries, dict):
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


def corroborated(text, alias, vendor):
    """Does an ambiguous alias sit near its vendor, or is it just the words?

    See "ambiguous_aliases" in corpus/schema/aliases.json for why the list is curated rather
    than derived. Any vendor token counts, which is the lenient direction on purpose: the
    cost of a missed corroboration is a vendor-level answer, and the cost of a false one is
    a confident answer about the wrong product.

    Matched as a token sequence rather than by scanning for a single token, so a multi-word
    alias works. An earlier version indexed by token equality, which found nothing for
    "device management" and returned True -- a gate that reads as though it is protecting a
    two-word alias while being a no-op on it. Failing closed is the other half of that: if
    the sequence cannot be located, the alias does not resolve.
    """
    tokens = text.split()
    vendor_tokens = {t for t in normalise(vendor).split() if t}
    if not vendor_tokens:
        # who.vendor "any" -- a class of product rather than somebody's. Nothing to be near.
        return True
    parts = alias.split()
    width = len(parts)
    spans = []
    for i in range(len(tokens) - width + 1):
        window = tokens[i:i + width]
        # Trailing "s" is optional on the last token only, matching the regex in resolve().
        if window[:-1] == parts[:-1] and window[-1] in (parts[-1], parts[-1] + "s"):
            spans.append((i, i + width))
    if not spans:
        return False
    return any(vendor_tokens & set(tokens[max(0, s - AMBIGUITY_WINDOW):e + AMBIGUITY_WINDOW])
               for s, e in spans)


def resolve(query, aliases):
    """Turn a free-text query into vendor, product and class constraints."""
    text = normalise(query)
    resolved = {"vendors": set(), "products": set(), "classes": set(), "sectors": set(), "terms": set()}
    ambiguous = aliases.get("ambiguous_aliases", {})

    # Longest alias first so "next gen firewall" wins over "firewall". Once an alias matches,
    # its span is blanked out so a shorter overlapping alias cannot also match: "water utility"
    # must resolve to water alone, not to water and electric because "utility" is also a term.
    remaining = text
    for table, key in (
        (aliases["product_aliases"], "products"),
        (aliases["vendor_aliases"], "vendors"),
        (aliases["class_aliases"], "classes"),
        (aliases.get("sector_aliases", {}), "sectors"),
    ):
        for alias in sorted(table, key=len, reverse=True):
            # Trailing "s" is optional so "HMIs" and "firewalls" resolve like the singular.
            pattern = r"\b{}s?\b".format(re.escape(alias))
            match = re.search(pattern, remaining)
            if not match:
                continue
            value = table[alias]
            # An ambiguous single-token alias resolves only next to its vendor. Blanking the
            # span instead, the way classes and sectors are handled below, would break the
            # "Cisco ASA" case the comment there is protecting, so the gate is on the match
            # rather than on the text.
            if key == "products" and alias in ambiguous \
                    and not corroborated(text, alias, value["vendor"]):
                continue
            if key == "products":
                resolved["products"].add(value["product"])
                resolved["vendors"].add(value["vendor"])
                if value.get("product_class"):
                    # A product may belong to more than one class, and saying so is the
                    # difference between an answer and a thinner answer that reads as a
                    # safer one. Moving EPMM from app.rmm to app.mdm alone took the
                    # question from 74 findings to 17: the MDM records arrived, and the
                    # fleet-management context that had been carrying it left.
                    klass = value["product_class"]
                    resolved["classes"].update(klass if isinstance(klass, list) else [klass])
            elif key == "classes" and isinstance(value, list):
                # A class alias may name more than one class, because one word often does.
                # "mdm" is a fleet-management console AND remote management tooling, and
                # answering it from app.mdm alone dropped the question from 63 findings to
                # 4 -- a thinner answer reading as a safer one. SKILL.md says to name every
                # class the technology behaves as; this lets the alias table do that too.
                resolved[key].update(value)
            else:
                resolved[key].add(value)
            # Blank the matched span for sector and class resolution, where overlap is the
            # problem. Vendor and product spans stay readable so "Cisco ASA" resolves both.
            if key in ("sectors", "classes"):
                remaining = remaining[: match.start()] + " " * (match.end() - match.start()) + remaining[match.end():]

    resolved["terms"] = {w for w in text.split() if w not in NOISE and len(w) > 2}
    return resolved


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
# consult.py gives a *resolved* vendor, product or class, and the two printed as one
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
# as identity, which fails open: an unrecognised reason shape would silently be given
# the tightest tier and full weight.
STRUCTURED_REASONS = ("vendor ", "product ", "class ", "sector ", "cross-sector")

# Tightest first. consult.py derives its own ordering from this so that a tier added
# here cannot be silently dropped there.
TIER_ORDER = ("identity",) + tuple(name for name, _ in FREE_TEXT_TIERS)


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


def score(record, resolved, patterns=None):
    """Higher is a better match. Zero means do not return it."""
    who = record.get("who", {})
    vendor = who.get("vendor", "")
    products = who.get("products", [])
    classes = set(who.get("product_class", []))

    points = 0
    reasons = []

    if vendor in resolved["vendors"]:
        points += 4
        reasons.append("vendor {}".format(vendor))
    if resolved["products"] & set(products):
        points += 6
        reasons.append("product {}".format(", ".join(sorted(resolved["products"] & set(products)))))
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

    if not points:
        # Classes contribute their suffix, not their prefix. A product class is
        # written "app.cicd", and normalising the dot to a space made the prefix a
        # free-text token, so "app" matched every app.* record equally: archivers
        # and ERP ranked alongside the CI/CD records actually asked for. The prefix
        # is taxonomy scaffolding and names nothing; the suffix carries the meaning.
        hay = free_text_haystacks(record, patterns)
        for term in resolved["terms"]:
            # Word boundary, not substring. A substring test made short terms match
            # inside longer words: "app" hit "appliance" and "application", so a
            # query naming a CI/CD class returned firewalls and historians ranked
            # alongside genuine matches, with nothing on screen to show why.
            pattern_re = r"\b{}\b".format(re.escape(term))
            for tier, worth in FREE_TEXT_TIERS:
                # First tier wins, so a term present both as a tag and in the prose
                # scores once, at the tighter of the two. Naming the tier in the
                # reason is what lets a reader see that a finding arrived on loose
                # prose rather than on identity.
                if re.search(pattern_re, hay[tier]):
                    points += worth
                    reasons.append("term {} ({})".format(term, tier))
                    break

    # A vendor match alone is weaker than a vendor plus the right class.
    if vendor in resolved["vendors"] and resolved["classes"] and not hit_classes:
        points -= 2

    return points, reasons


def brief(record, reasons=()):
    """One line per record.

    The default, because a technology with real history returns thirty-odd records
    and the full form of that runs to roughly ten thousand tokens. Reading all of
    it to answer one question is the slow path. This is enough to choose which
    records deserve the full form, which is what --full then gives.
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
    return "{:<3} {:<62} [{}{}] {} {}{}\n      {}".format(
        kind, record["id"], what["role"],
        "/" + ",".join(fid) if fid else "",
        who["vendor"], "/".join(who["products"])[:40], weak, summary)


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
    if actors or sectors:
        lines.append("  who2   {}{}".format(", ".join(actors) or "unattributed",
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


def main():
    parser = argparse.ArgumentParser(description="Query the advisory corpus.")
    parser.add_argument("query", help="What the caller has, in their own words.")
    parser.add_argument("--corpus", default=os.path.join(BUNDLE_ROOT, "corpus"))
    parser.add_argument("--role", help="Only return records where the technology played this role.")
    parser.add_argument("--sector", help="Restrict to records reported in this sector, as a hard filter rather than a ranking boost. Accepts a vocab value or an alias.")
    parser.add_argument("--limit", type=int, default=20, help="Maximum observations to return.")
    parser.add_argument("--exposure-limit", type=int, default=10, help="Maximum exposure records to return, reported separately after the observations.")
    parser.add_argument("--json", action="store_true", help="Emit matching records as JSON.")
    parser.add_argument("--full", action="store_true",
                        help="Full record detail rather than one line each. Needed to read "
                             "detection logic and caveats; costs roughly ten times the output.")
    parser.add_argument("--pattern-limit", type=int, default=6,
                        help="Maximum library patterns to show (patterns no record cites).")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detection fields and datasets.")
    args = parser.parse_args()

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
    hits = []
    for record in records:
        if args.role and record.get("what", {}).get("role") != args.role:
            continue
        if args.sector:
            want = sector_filter
            secs = record.get("who2", {}).get("target_sectors", [])
            if want not in secs and "cross_sector" not in secs:
                continue
        points, reasons = score(record, resolved, patterns)
        if points > 0:
            hits.append((points, reasons, record))

    # Observations carry detection logic and answer "what should I watch for", so they lead.
    # Exposures are bulk-generated vulnerability facts; they are useful but must never bury
    # the observations, so they are ranked and reported separately.
    hits.sort(key=lambda h: (h[2].get("record_type", "observation") != "observation", -h[0], h[2]["id"]))
    observations = [h for h in hits if h[2].get("record_type", "observation") == "observation"]
    exposures = [h for h in hits if h[2].get("record_type") == "exposure"]
    hits = observations[: args.limit] + exposures[: args.exposure_limit]
    # Counted after truncation, because the header reports both numbers. Reporting only
    # the match count over a truncated listing is how a reader concludes the corpus holds
    # twenty observations when it matched forty-two and the rest were capped away.
    shown_obs = sum(1 for _, _, rec in hits
                    if rec.get("record_type", "observation") == "observation")
    shown_exp = len(hits) - shown_obs

    # Patterns cited by a record already surface through that record. Patterns that no
    # record cites are derived from technique space rather than from an incident, and
    # would otherwise be unreachable: query.py only ever used patterns to enrich records.
    # They are matched on the classes they apply to and reported in their own block.
    cited = {h.get("pattern_id") for rec in records for h in (rec.get("how") or [])}

    # Fall back to the classes the matched records declare when the query itself
    # resolved to none. A vendor-only alias ("SAP", "Splunk") used to return records
    # and no patterns at all, because this block keyed on the query alone. That is
    # backwards: matching a vendor's records establishes the class just as well as
    # naming it, and class-level transfer is the thing the skill exists to do.
    pattern_classes = resolved["classes"] or {
        c for _, _, rec in hits for c in (rec.get("who", {}).get("product_class") or [])}

    library, library_matched = [], 0
    if pattern_classes:
        for pid, pat in patterns.items():
            if pid in cited or not pat.get("markers"):
                continue
            if pattern_classes & set(pat.get("applies_to_classes") or []):
                corr = pat.get("external_corroboration") or {}
                weight = corr.get("sigma_rules", 0) + corr.get("splunk_detections", 0)
                library.append((weight, pat))
        library.sort(key=lambda t: (-t[0], t[1]["id"]))
        library_matched = len(library)
        library = library[: args.pattern_limit]

    if args.json:
        print(json.dumps({
            "records": [{"score": p, "matched_on": r, "record": rec} for p, r, rec in hits],
            "library_patterns": [pat for _, pat in library],
            # A caller reading JSON cannot see that a listing was capped, and these arrays
            # are capped by default. Shipping the match counts beside them is the only way
            # the consumer can tell a short answer from a complete one.
            "counts": {
                "observations_shown": shown_obs, "observations_matched": len(observations),
                "exposures_shown": shown_exp, "exposures_matched": len(exposures),
                "library_patterns_shown": len(library),
                "library_patterns_matched": library_matched,
                "records_in_corpus": len(records),
            },
        }, indent=2))
        return 0

    print("query: {!r}".format(args.query))
    print("resolved to: vendors={} products={} classes={} sectors={}".format(
        sorted(resolved["vendors"]) or "-", sorted(resolved["products"]) or "-",
        sorted(resolved["classes"]) or "-", sorted(resolved["sectors"]) or "-"))
    print("{} of {} observation(s) and {} of {} exposure(s) shown, of {} records in corpus".format(
        shown_obs, len(observations), shown_exp, len(exposures), len(records)))
    capped = []
    if len(observations) > shown_obs:
        capped.append("--limit for the {} observation(s)".format(len(observations)))
    if len(exposures) > shown_exp:
        capped.append("--exposure-limit for the {} exposure(s)".format(len(exposures)))
    if capped:
        print("OUTPUT CAPPED: raise {}. What is missing is the tail of the ranking, not "
              "the corpus.".format(" and ".join(capped)))
    print()

    full = args.full or args.verbose
    for points, reasons, record in hits:
        if full:
            print(summarise(record, patterns, args.verbose))
            print("  match  {} ({})\n".format(points, "; ".join(reasons)))
        else:
            print(brief(record, reasons))
    if not full and hits:
        print("\nfull detail for any of the above, including detection logic and caveats:")
        print("  python3 scripts/query.py {!r} --full".format(args.query))
        print("  python3 scripts/emit_xql.py <record-id> --json    # the rule-authoring handoff")

    if library:
        print("library patterns for this technology class, cited by no record yet: "
              "{} of {} shown{}\n".format(
                  len(library), library_matched,
                  "; raise --pattern-limit for the rest" if library_matched > len(library) else ""))
        for weight, pat in library:
            print("{}  [{} / {}]".format(pat["id"], pat.get("fidelity", "?"), pat.get("rule_shape", "?")))
            print("  {}".format(pat.get("name", "")))
            if weight:
                print("  corroborated by {} external detection rule(s)".format(weight))
            print()

    if not hits and not library:
        print("Nothing matched. Either the corpus has no coverage, or the term needs an entry in corpus/schema/aliases.json.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
