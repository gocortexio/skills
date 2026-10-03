# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""What query.py lists first when scores tie.

67 of 73 "Linux kernel" observations tied at score 3 on class alone, and query.py broke every
tie on the record id: the 20 shown were the first 20 ids, none of them naming Linux, seven of
them carrying Windows-only markers, while the records that did name Linux sat at ranks 22 to
41. Its library block had the mirror defect: it ranked patterns on public rule counts that
are per technique and platform-blind, so four of the six patterns shown for "Linux kernel"
were written for Windows.

score() is untouched. Ties now go to the record carrying more of the question's leftover
words, then to one naming what resolved, then to one whose markers fit the platform the
question names, then to the newer, and only then to the id. The library block sinks a pattern
written for another platform below every neutral or fitting one.

Run with PYTHONDONTWRITEBYTECODE=1 (LAW A26).
"""
import json
import os
import re
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import query as Q  # noqa: E402

RAW = json.load(open(os.path.join(ROOT, "corpus", "schema", "aliases.json"), encoding="utf-8"))
ALIASES = Q.normalise_alias_keys(RAW)
RECORDS, PATTERNS = Q.load_corpus(os.path.join(ROOT, "corpus"))
# pat-indirect-command-execution joined in 0.43.0: its markers are Windows binaries only, and
# "bash.exe" among them read as the Unix shell, so it was shown for "Linux kernel" as fitting
# Linux. The list stays a regression list; the scan below is what catches the next one.
WINDOWS_ONLY_PATTERNS = ["pat-library-loader-utility-abuse",
                         "pat-windows-remote-management-execution",
                         "pat-background-transfer-service-abuse",
                         "pat-trusted-developer-utility-compilation",
                         "pat-indirect-command-execution"]
WINDOWS_FILE = re.compile(r"(?i)^[^\s/\\]+\.(exe|dll|ps1|bat|cmd|lnk|vbs|hta|msi|sys|cpl|chm)$")


def query(*args):
    done = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "query.py"), *args],
                          capture_output=True, text=True, cwd=ROOT)
    assert done.returncode == 0, done.stderr
    return done.stdout


def observations(question, limit=20):
    data = json.loads(query(question, "--json", "--limit", str(limit), "--exposure-limit", "0"))
    return [r for r in data["records"] if "tiebreak" in r]


def key(row):
    t = row["tiebreak"]
    return (row["score"], len(t["refined_by"]), t["identity_mention"], t["platform_fit"])


def test_linux_kernel_leads_with_records_that_name_linux():
    rows = observations("Linux kernel")
    first = rows[0]["record"]
    text = Q.normalise(" ".join(first["who"]["products"]) + " " + first["what"]["summary"])
    assert re.search(r"\blinux\b", text), first["id"]
    keys = [key(r) for r in rows]
    assert keys == sorted(keys, reverse=True), keys


def test_no_windows_only_record_is_listed_for_a_linux_question():
    rows = observations("Linux kernel")
    assert not [r["record"]["id"] for r in rows if r["tiebreak"]["platforms"] == ["windows"]]


def test_equal_keys_fall_back_to_recency_then_id():
    rows = observations("Linux kernel", limit=200)
    for a, b in zip(rows, rows[1:]):
        if key(a) != key(b):
            continue
        pa, pb = a["tiebreak"]["published"], b["tiebreak"]["published"]
        ids = (a["record"]["id"], b["record"]["id"])
        assert pa or not pb, "an undated record precedes a dated one: {}".format(ids)
        if pa and pb and pa != pb:
            assert pa > pb, ids
        elif pa == pb:
            assert ids[0] < ids[1], ids


def test_the_question_platform_comes_from_the_curated_table():
    assert Q.question_platforms(Q.resolve("Linux kernel", ALIASES), ALIASES) == {"linux"}
    assert Q.question_platforms(Q.resolve("Microsoft Windows", ALIASES), ALIASES) == {"windows"}
    assert Q.question_platforms(Q.resolve("Fortinet FortiGate", ALIASES), ALIASES) == set()
    assert set(RAW["platform_of"].values()) <= set(Q.PLATFORMS)


@pytest.mark.parametrize("pattern_id,expected", [
    ("pat-library-loader-utility-abuse", {"windows"}),
    ("pat-windows-remote-management-execution", {"windows"}),
])
def test_a_windows_pattern_classifies_as_windows(pattern_id, expected):
    assert Q.marker_platforms(PATTERNS[pattern_id]["markers"]) == expected


def test_a_linux_pattern_fits_linux_and_not_windows():
    platforms = Q.marker_platforms(
        PATTERNS["pat-linux-privilege-escalation-via-permitted-binary"]["markers"])
    assert "windows" not in platforms and platforms & {"linux", "unix"}, platforms
    assert Q.platform_fit(platforms, {"linux"}) == 1
    assert Q.platform_fit(platforms, {"windows"}) == -1


def test_a_pattern_written_for_both_fits_both():
    platforms = Q.marker_platforms(PATTERNS["pat-command-history-cleared"]["markers"])
    assert {"unix", "windows"} <= platforms, platforms
    assert Q.platform_fit(platforms, {"linux"}) == Q.platform_fit(platforms, {"windows"}) == 1


def test_curl_alone_commits_to_no_platform():
    """curl.exe ships with Windows, so curl says nothing about the host."""
    assert Q.marker_platforms([{"type": "process_name", "match": "equals", "value": "curl"}]) == set()
    assert Q.platform_fit(set(), {"linux"}) == 0


def test_a_windows_binary_named_like_a_unix_command_is_windows():
    """The dot before an extension is a word boundary, so "bash.exe" matched the Unix word
    "bash" and a Windows-only pattern read as written for both."""
    assert Q.marker_platforms([{"type": "process_name", "value": "bash.exe"}]) == {"windows"}
    assert Q.marker_platforms([{"type": "process_name", "value": "bash"}]) == {"unix"}
    assert Q.marker_platforms([{"type": "process_name", "value": "/bin/bash"}]) == {"unix"}
    assert Q.marker_platforms(PATTERNS["pat-indirect-command-execution"]["markers"]) == {"windows"}


def test_no_windows_file_in_any_marker_reads_as_another_platform():
    """Every marker value in the corpus that is a bare Windows file name, scanned: the four-name
    list above could not catch the fifth, and this can."""
    values = []
    for pattern in PATTERNS.values():
        values += [m.get("value") for m in pattern.get("markers") or []]
    for record in RECORDS:
        for how in record.get("how") or []:
            values += [m.get("value") for m in how.get("markers") or []]
    flat = [v for value in values for v in (value if isinstance(value, list) else [value])
            if isinstance(v, str) and WINDOWS_FILE.match(v.strip())]
    assert flat
    wrong = sorted({v for v in flat if Q.marker_platforms([{"value": v}]) - {"windows"}})
    assert not wrong, wrong


def test_library_block_does_not_lead_with_windows_only_patterns_for_linux():
    shown = re.findall(r"^(pat-[\w-]+)", query("Linux kernel"), re.M)
    assert shown
    assert not set(shown) & set(WINDOWS_ONLY_PATTERNS), shown


def test_library_block_for_windows_excludes_linux_only():
    shown = re.findall(r"^(pat-[\w-]+)", query("Windows"), re.M)
    assert shown and "pat-linux-privilege-escalation-via-permitted-binary" not in shown, shown


def test_library_corroboration_line_names_the_technique_scope():
    """The count is per technique on every platform, not implementations of this pattern."""
    out = query("Windows")
    lines = [l for l in out.splitlines() if "Sigma/Splunk" in l]
    assert lines and all("tag a technique" in l and "(any platform)" in l for l in lines)
    assert "corroborated by" not in out


# The plane each listed record sits in. SKILL.md sends a caller to query.py first, and until
# 0.43.0 nothing on that path -- no line, header or JSON key -- said which plane a record sat in,
# or that a plane was absent from the answer.
VOCAB = json.load(open(os.path.join(ROOT, "corpus", "schema", "vocab.json"), encoding="utf-8"))


def test_query_lines_carry_a_locus():
    out = query("Cisco ASA")
    lines = [l for l in out.splitlines() if l.startswith(("obs ", "exp "))]
    assert lines
    for line in lines:
        m = re.search(r"  loci=([A-Z,]+)", line)
        assert m, line
        assert set(m.group(1).split(",")) <= set(VOCAB["locus"]), line
    header = re.search(r"^LOCUS over shown: (.*); ABSENT=(\S+)$", out, re.M)
    assert header, out[:600]
    counts = dict(re.findall(r"([A-Z]+)=(\d+)", header.group(1)))
    assert set(counts) == set(VOCAB["locus"])
    assert sum(int(v) for v in counts.values()) >= len(lines)
    absent = [] if header.group(2) == "none" else header.group(2).split(",")
    assert sorted(absent) == sorted(k for k, v in counts.items() if v == "0")


def test_query_json_records_carry_their_loci():
    data = json.loads(query("Cisco ASA", "--json"))
    assert data["records"]
    for row in data["records"]:
        assert row["loci"] and set(row["loci"]) <= set(VOCAB["locus"]), row["record"]["id"]
    shown = data["counts"]["loci_over_shown"]
    assert sum(shown.values()) >= len(data["records"])


def test_a_listed_locus_is_the_one_a_consultation_prints():
    """Question-independent: the same ladder, with no question, for every block."""
    import consult as C
    locus_map = C.load_locus_map(os.path.join(ROOT, "corpus"))
    data = json.loads(query("PAN-OS", "--json", "--limit", "40"))
    for row in data["records"]:
        record = row["record"]
        expected = {C.locus_for(record, how, PATTERNS.get(how.get("pattern_id")), locus_map)[0]
                    for how in record.get("how") or []} \
            or {C.locus_for(record, None, None, locus_map)[0]}
        assert set(row["loci"]) == expected, record["id"]


# The consultation's FINDINGS order. query.py and the LIBRARY block ordered by platform fit and
# the findings did not, so "Linux kernel" led with a Chrome record's Windows extension and DLL
# search-order blocks under a header that honestly said CLASS-LEVEL.

def consult_findings(question, *extra):
    done = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "consult.py"), question,
                           "--today", "2026-09-25", *extra], capture_output=True, text=True,
                          cwd=ROOT, timeout=300)
    assert done.returncode == 0, done.stderr
    rows = []
    for chunk in done.stdout.split("=== FINDING ")[1:]:
        keys = dict(re.findall(r"^([A-Z_]+): (.*)$", chunk, re.M))
        basis = keys["PRIORITY_BASIS"]
        rows.append({
            "key": keys["FINDING_KEY"], "pattern": keys["PATTERN_ID"],
            "group": int(re.search(r"\(group (\d+)", basis).group(1)),
            "sector": re.search(r"; sector=([^;]+);", basis).group(1),
            "refined": re.search(r"; refined_by=(\S+)$", basis).group(1),
            "fit": int(re.search(r"; platform_fit=([+-]?\d+) \(", basis).group(1)),
            "score": float(re.search(r"score=([0-9.]+)/", basis).group(1))})
    return done.stdout, rows


def run_key(row):
    return (row["group"], row["sector"] == "-",
            -(0 if row["refined"] == "-" else len(row["refined"].split(","))))


def test_findings_sink_a_block_written_for_another_platform():
    out, rows = consult_findings("Linux kernel", "--no-locus-spread", "--limit", "400")
    assert "then blocks whose markers are written for the platform the question names" in out
    for a, b in zip(rows, rows[1:]):
        if run_key(a) == run_key(b):
            assert (a["fit"], a["score"]) >= (b["fit"], b["score"]), (a["key"], b["key"])
    assert rows[0]["fit"] == 1, rows[0]
    fits = {r["fit"] for r in rows}
    assert fits == {1, 0, -1}, "fixture no longer exercises all three fits"
    # The Chrome record's Windows DLL search-order block, rank 2 before, now sits below every
    # neutral or fitting block of its group.
    dll = next(i for i, r in enumerate(rows) if r["key"].startswith(
        "obs-google-chrome-patch-gap-chain-to-browser-process-injection#")
        and r["pattern"] == "pat-dll-hijack-search-order")
    assert rows[dll]["fit"] == -1
    assert not [r for r in rows[dll + 1:] if run_key(r) == run_key(rows[dll]) and r["fit"] > -1]


def test_the_fit_reads_the_markers_the_finding_prints():
    """Per block, from the markers MARKERS prints: the block's own, else its pattern's."""
    import consult as C
    _, rows = consult_findings("Microsoft Windows", "--no-locus-spread", "--limit", "60")
    wanted = {"windows"}
    by_id = {r["id"]: r for r in RECORDS}
    for row in rows:
        record_id, index = row["key"].rsplit("#how", 1)
        how = by_id[record_id]["how"][int(index)]
        platforms = Q.marker_platforms(C.markers_of(how, PATTERNS.get(how.get("pattern_id")))[0])
        assert row["fit"] == Q.platform_fit(platforms, wanted), row["key"]


def test_a_question_naming_no_platform_orders_as_before():
    _, rows = consult_findings("Fortinet FortiGate", "--no-locus-spread", "--limit", "40")
    assert rows and {r["fit"] for r in rows} == {0}


def test_a_record_naming_no_actor_is_unattributed_only_when_it_says_so():
    """`--full` printed "unattributed" for every record whose `actors` list was empty.

    36 state-nexus records name no group, because the advisories behind them attribute to a
    state without naming one, and 8 of those carry `attribution_confidence: high`. They read
    as unattributed. The line now falls back to the record's own `actor_type`.
    """
    for record in RECORDS:
        who2 = record.get("who2") or {}
        if who2.get("actors"):
            continue
        line = Q.unnamed_actor(who2)
        kind = who2.get("actor_type") or "unattributed"
        if kind == "unattributed":
            assert line == "unattributed"
        else:
            assert "actor_type {}".format(kind) in line and "unattributed" not in line, (
                record["id"], line)
    out = query("managed service provider", "--full", "--limit", "60")
    block = out.split("obs-generic-managed-service-provider-as-route-to-customers", 1)[1]
    who2 = next(l for l in block.splitlines() if l.startswith("  who2"))
    assert "actor_type state_nexus, attribution high" in who2, who2


def test_tiebreak_published_is_a_date_as_the_record_holds_it():
    """A month-precision record printed tiebreak.published 2026-08-00, which no date parser
    reads: the sort key's padding leaked into the JSON."""
    rows = observations("Linux kernel", limit=200)
    held = [r["tiebreak"]["published"] for r in rows if r["tiebreak"]["published"]]
    assert held and not [p for p in held if p.endswith("-00")]
    assert "2026-08" in held
