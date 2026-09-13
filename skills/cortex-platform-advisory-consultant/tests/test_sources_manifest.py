# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The shipped provenance manifest is derived, and must stay derived.

SOURCES.md used to be the full sync record: 4,489 lines of routes, pass logs, per-source
backlogs and the quality verdicts this estate holds on other people's research. It shipped to
a public repository, and the bundle's own README said it did not.

It is maintainer-side now, and what ships in its place is generated from the corpus by
`scripts/build_manifest.py`. That choice is what these tests protect. A manifest transcribed
by hand from a document nobody outside the estate can read would rot precisely where nobody
can check it -- which is the failure this bundle has already paid for once, in a release-gate
comment whose hand-typed counts went stale and then decided something.

Derived from the corpus, it is falsifiable by anyone holding the bundle.
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import build_manifest as B  # noqa: E402

MANIFEST = os.path.join(ROOT, "SOURCES.md")


def records():
    path = os.path.join(ROOT, "corpus", "observations", "observations.jsonl")
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def test_the_manifest_on_disk_matches_what_the_corpus_would_produce():
    """The whole argument for deriving it. If this fails, regenerate rather than hand-edit."""
    done = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "build_manifest.py"),
                           "--check"], capture_output=True, text=True, cwd=ROOT)
    assert done.returncode == 0, done.stdout + done.stderr


def test_every_publisher_in_the_corpus_appears_in_the_manifest():
    """The drift that matters to a reader: holding a record whose source the manifest omits."""
    text = open(MANIFEST, encoding="utf-8").read()
    missing = sorted({(r.get("where") or {}).get("publisher", "").strip()
                      for r in records()} - {""} - {p for p in
                     {(r.get("where") or {}).get("publisher", "").strip() for r in records()}
                     if p and p in text})
    assert not missing, "publishers in the corpus but not in SOURCES.md: {}".format(missing)


def test_the_manifest_declares_itself_derived():
    """A generated file that does not say so invites the hand-edit that silently un-derives it."""
    head = open(MANIFEST, encoding="utf-8").read()[:1200]
    assert "Do not hand-edit" in head
    assert "scripts/build_manifest.py" in head


def test_the_full_sync_record_does_not_ship():
    """It moved to a maintainer-side tree that does not ship. Nothing under the bundle
    should reintroduce it."""
    for name in ("TODO.md",):
        assert not os.path.exists(os.path.join(ROOT, name)), \
            "{} is maintainer-side and must not ship".format(name)
    # SOURCES.md exists, but as the derived manifest -- not as the sync record. The sync
    # record's shape is unmistakable: numbered per-source sections and _ingest/ commands.
    text = open(MANIFEST, encoding="utf-8").read()
    assert "_ingest/" not in text, "the derived manifest carries a maintainer-only path"
    assert "\n## 1." not in text, "the derived manifest looks like the full sync record"


def test_restricted_sources_are_declared_without_being_identified():
    """The manifest names publishers, which every restricted record's own title already does.

    `where.title` on a restricted record reads '<Publisher> commentary on <subject>', so the
    publisher is public by construction. What must not appear is anything narrowing that to a
    single report -- no URL, no identifier, no exact date.
    """
    text = open(MANIFEST, encoding="utf-8").read()
    restricted = [r for r in records()
                  if (r.get("where") or {}).get("disclosure") == "restricted"]
    assert restricted, "no restricted records; this assertion would be vacuous"
    assert "restricted" in text, "the manifest does not tell a reader which sources are abstracted"
    for record in restricted:
        url = (record.get("where") or {}).get("url")
        assert not url, "restricted record {} carries a url".format(record.get("id"))


# The estate's own restricted detection library is a source we own and may abstract from.
# Another organisation's licensed subscription is not, and must never reach a public corpus.
OWN_RESTRICTED_LIBRARY = "Restricted detection library"


def test_no_third_party_licensed_intelligence_ships():
    """A licensed subscription belongs to whoever pays for it, and abstracting a report does not
    make its analysis ours to publish.

    This is the check that did not exist. 95 records abstracted from one vendor's OT
    intelligence subscription shipped in a corpus destined for a public repository, carrying the
    publisher's name in `where.publisher` and in every record title. `disclosure: restricted`
    marked them accurately and gated nothing -- it is a provenance label, never a
    publish/no-publish flag, and reading it as one is how the estate convinced itself the corpus
    was safe.

    Our own restricted library is exempt because we own it. The rule is about whose material it
    is, not how sensitive it is.
    """
    offenders = {}
    for record in records():
        where = record.get("where") or {}
        types = where.get("source_type") or ""
        if "licensed_intel" not in str(types):
            continue
        publisher = where.get("publisher") or "(unnamed)"
        if publisher != OWN_RESTRICTED_LIBRARY:
            offenders.setdefault(publisher, []).append(record.get("id"))
    assert not offenders, (
        "third-party licensed intelligence in a corpus that ships publicly: "
        + "; ".join(
            "{} ({} records, e.g. {})".format(p, len(ids), ids[0])
            for p, ids in sorted(offenders.items())
        )
        + ". Abstracting it does not make it publishable."
    )


def test_a_pattern_reachable_only_from_restricted_records_declares_it():
    """A pattern is the DERIVATIVE, and the derivative is the part with operational value.

    Removing restricted observations does not remove the detection logic distilled out of them:
    the observation is a citation wrapper, the pattern holds the `logic`, `caveat` and
    `xql_sketch`. `patterns.jsonl` carries no `disclosure` field at all, so a filter keyed on the
    observation's marker leaves the patterns standing. That gap was real -- 103 patterns reachable
    only from one vendor's records carried no provenance of any kind, while the 7 from our own
    restricted library all carried `derived_from`. The convention existed and was applied to 7 of
    110.

    So any pattern whose only citations are restricted must say so on itself. Then a reader can
    see what a pattern came from without reconstructing the reverse index, and a strip of
    restricted material is one operation rather than two.
    """
    import collections

    observations = list(records())
    restricted = {
        r.get("id")
        for r in observations
        if (r.get("where") or {}).get("disclosure") == "restricted"
    }
    if not restricted:
        return  # nothing restricted ships; the assertion below would be vacuous

    cited = collections.defaultdict(set)
    for record in observations:
        for how in record.get("how") or []:
            if how.get("pattern_id"):
                cited[how["pattern_id"]].add(record.get("id"))

    path = os.path.join(ROOT, "corpus", "patterns", "patterns.jsonl")
    with open(path, encoding="utf-8") as handle:
        patterns = {
            json.loads(line)["id"]: json.loads(line)
            for line in handle
            if line.strip()
        }

    undeclared = [
        pid
        for pid, ids in cited.items()
        if ids and ids <= restricted and not (patterns.get(pid) or {}).get("derived_from")
    ]
    assert not undeclared, (
        "these patterns are reachable ONLY from restricted records and declare no provenance, so "
        "a filter on the observation's disclosure marker would leave them behind: "
        + ", ".join(sorted(undeclared))
    )


def test_no_shipped_page_states_a_corpus_count_that_is_wrong():
    """A count typed into prose is a copy of the corpus, and a copy falls behind.

    This bundle already knows that -- the docstring at the top of this file describes a
    release-gate comment whose hand-typed counts went stale and then decided something, and
    SOURCES.md was made derived for exactly that reason. The prose was not. Stripping 95 records
    and 103 patterns left three shipped statements claiming 1,216 and 536, including the skill's
    own `description:`, which is the first thing a reader of a public skills repository sees.

    THE CHECK MATCHES PHRASES THAT CLAIM TOTALITY, not numbers near the word "corpus". Two
    looser designs were tried and both gave wrong advice, which is the failure mode this estate
    refuses to ship: a magnitude band flagged a worked example's match-set size, and a
    proximity cue then flagged the same example because its own caveat used the word "corpus".
    A page is full of legitimate subset counts. Only a claim of the form "a corpus of N records"
    or "the corpus holds N records" asserts the total, so only those are judged.
    """
    import re

    records_on_disk = sum(1 for line in open(
        os.path.join(ROOT, "corpus", "observations", "observations.jsonl"),
        encoding="utf-8") if line.strip())
    patterns_on_disk = sum(1 for line in open(
        os.path.join(ROOT, "corpus", "patterns", "patterns.jsonl"),
        encoding="utf-8") if line.strip())

    # Descriptive words may sit between the number and the noun -- the skill's own
    # description says "a corpus of 1,121 threat advisory records" -- so allow a short
    # run of them. Without that the description went unchecked and this test passed on
    # a stale total, which is the one outcome worse than not having the check.
    gap = r"[A-Za-z ]{0,30}?"
    totality = [
        re.compile(r"corpus of ([0-9][0-9,]*)" + gap + r"(record|pattern)", re.I),
        re.compile(r"corpus holds ([0-9][0-9,]*)" + gap + r"(record|pattern)", re.I),
        re.compile(r"([0-9][0-9,]*) (record|pattern)s? in `corpus/", re.I),
        re.compile(r"holds ([0-9][0-9,]*) (record|pattern)s? and ([0-9][0-9,]*) (pattern)", re.I),
    ]
    wrong = []
    checked = 0
    for name in ("SKILL.md", "README.md"):
        text = open(os.path.join(ROOT, name), encoding="utf-8").read()
        for pattern in totality:
            for match in pattern.finditer(text):
                pairs = [(match.group(1), match.group(2))]
                if match.lastindex and match.lastindex >= 4:
                    pairs.append((match.group(3), match.group(4)))
                for number, noun in pairs:
                    checked += 1
                    stated = int(number.replace(",", ""))
                    actual = records_on_disk if noun.lower() == "record" else patterns_on_disk
                    if stated != actual:
                        wrong.append("{}: claims the corpus holds {} {}s, it holds {}".format(
                            name, number, noun.lower(), actual))
    assert checked >= 4, (
        "matched only {} corpus-total claim(s); the skill description, the README line and "
        "the SKILL.md corpus statement should all be judged, and a regex that silently stops "
        "matching one of them makes this test pass on a stale number".format(checked)
    )
    assert not wrong, "shipped prose states a corpus total that is wrong:\n  " + "\n  ".join(wrong)
