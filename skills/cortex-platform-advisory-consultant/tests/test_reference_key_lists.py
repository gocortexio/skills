# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The key lists the references print are the keys the scripts print.

`references/answering-another-session.md` is what a session consuming this skill reads to
learn what it can parse, and a key list written by hand drifts the moment a release adds a
line. 0.43.0 added `MATCH_TIER`, `FINDING_KEY` and `SLOT` to every finding and ten header
lines, and the page listed none of them for `consult.py`. These tests read the lists out of
the page and hold them to real output, both ways: nothing printed that the page does not
name, and nothing named that no probe below prints.

Run with PYTHONDONTWRITEBYTECODE=1 (LAW A26).
"""
import pathlib
import re
import subprocess
import sys

import pytest

BUNDLE = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = BUNDLE / "scripts"
PAGE = BUNDLE / "references" / "answering-another-session.md"
TODAY = "2026-09-25"

KEY = re.compile(r"^([A-Z][A-Z0-9_]*):")


def documented(marker, last):
    """The backticked keys from `marker` up to and including `last`, in page order."""
    text = " ".join(PAGE.read_text(encoding="utf-8").split())
    found = re.search(re.escape(marker) + r"(.*?`" + re.escape(last) + r"`)", text)
    assert found, "the page no longer carries the list opening {!r}".format(marker)
    return re.findall(r"`([A-Z][A-Z0-9_]*)`", found.group(1))


def run(script, *argv):
    done = subprocess.run([sys.executable, str(SCRIPTS / script), *argv],
                          capture_output=True, text=True, timeout=300)
    assert done.returncode in (0, 1), "{} exited {}: {}".format(script, done.returncode,
                                                                 done.stderr)
    return done.stdout


def consult_header(question, *extra):
    """Column-zero keys of the header, stopping at the first block or advice banner."""
    keys, complete = [], False
    for line in run("consult.py", question, "--today", TODAY, *extra).splitlines():
        if line.startswith("=== ") and line != "=== CONSULTATION ===":
            complete = line == "=== END HEADER ==="
            break
        found = KEY.match(line)
        if found:
            keys.append(found.group(1))
    return keys, complete


# Each probe exists to make at least one conditional line print, so that between them every
# key the page names is printed somewhere.
PROBES = [
    ("Fortinet FortiGate", ("--role", "victim", "--limit", "1")),        # ROLE_FILTER, UNDERSERVED
    ("Fortinet", ("--covered", "T1190", "--rank-by", "gap")),            # CLASSES_FROM_VENDOR, DEMOTION
    ("Zorblax Edge Gateway 9000", ()),                                   # MECHANISM_WARNING
    ("key exchange appliance", ()),                                      # GATED
    ("Samsung", ()),                                                     # EXPOSURES_ONLY
    ("Portkey", ()),                                                     # UNRESOLVED
    ("Okta", ("--role", "telemetry_source")),                            # a filter keeping nothing
]


@pytest.fixture(scope="module")
def headers():
    return [consult_header(question, *extra) for question, extra in PROBES]


def test_every_consultation_header_key_is_documented_and_every_documented_key_prints(headers):
    page = documented("**Consultation header keys**", "CONTRACT")
    printed = {key for keys, _ in headers for key in keys}
    # NO_FINDINGS is named in the prose after the list: it is the filtered-to-nothing line.
    undocumented = printed - set(page) - {"NO_FINDINGS"}
    assert not undocumented, "consult.py prints header keys the page does not name: {}".format(
        sorted(undocumented))
    never = set(page) - printed
    assert not never, "the page names header keys no probe prints: {}".format(sorted(never))


def test_a_complete_consultation_header_prints_in_the_documented_order(headers):
    page = documented("**Consultation header keys**", "CONTRACT")
    position = {key: index for index, key in enumerate(page)}
    for (question, _), (keys, complete) in zip(PROBES, headers):
        if not complete:
            continue
        order = [position[key] for key in keys if key in position]
        assert order == sorted(order), "{!r} prints its header out of the page's order: {}".format(
            question, keys)


def test_the_consultation_finding_keys_are_the_documented_list_in_order():
    page = documented("**Consultation finding keys**", "METHODOLOGY")
    out = run("consult.py", "Fortinet FortiGate", "--today", TODAY, "--limit", "4")
    blocks, current = [], None
    for line in out.splitlines():
        if line.startswith("=== FINDING "):
            current = []
        elif line.startswith("=== END FINDING "):
            blocks.append(current)
            current = None
        elif current is not None:
            found = KEY.match(line)
            if found and found.group(1) not in current:
                current.append(found.group(1))
    assert blocks, "no finding printed"
    for block in blocks:
        assert block == page, "a finding's keys differ from the page's list:\n{}\n{}".format(
            block, page)


def advise_blocks(*argv):
    out = run("advise.py", "--no-verify", *argv)
    header, blocks, current = [], [], None
    for line in out.splitlines():
        if line.startswith("--- PATTERN_ID:"):
            current = []
            blocks.append(current)
            continue
        if line.startswith("=== ") or line.startswith("#"):
            continue
        found = KEY.match(line)
        if not found:
            continue
        target = header if current is None else current
        if found.group(1) not in target:
            target.append(found.group(1))
    return header, blocks


def test_the_advise_keys_are_the_documented_lists():
    fields = documented("one key per line:", "RESPONSE_DOCTRINE")
    heads = set(documented("The header opens with", "NO_MATCH"))
    for argv in (["--attack", "T1003"], ["--patterns", "pat-log-forwarding-gap,pat-nonexistent"],
                 ["--attack", "T1550.002"], ["a device stops sending logs"]):
        header, blocks = advise_blocks(*argv)
        extra = set(header) - heads
        assert not extra, "advise.py {} prints header keys the page does not name: {}".format(
            argv, sorted(extra))
        for block in blocks:
            assert block == fields, "advise.py {} prints pattern keys {} where the page lists {}" \
                .format(argv, block, fields)
