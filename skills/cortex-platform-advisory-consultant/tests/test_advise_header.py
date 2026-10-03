# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the advise.py header contract.

A calling session is told to read the header before the findings, so the header is the
only part of the output guaranteed to be read. That makes a wrong count worse than a
missing one: until 0.11.1 the headline printed the number of free-text arguments, so
every exact selection announced "SHAPES: 0" above the patterns it went on to print --
`--attack T1190` denied 48 findings in the line a caller reads first.

The invariant these tests hold is that the header count and the findings underneath it
cannot disagree, whichever path selected them. They run the CLI rather than the
functions, because the contract is the printed text.

Run with PYTHONDONTWRITEBYTECODE=1 (LAW A26).
"""
import pathlib
import re
import subprocess
import sys

import pytest

BUNDLE = pathlib.Path(__file__).resolve().parents[1]
ADVISE = BUNDLE / "scripts" / "advise.py"

# A pattern id and an ATT&CK id that the shipped corpus really carries. If either stops
# selecting, that is a corpus regression and these tests should say so rather than skip.
KNOWN_PATTERN = "pat-webserver-spawns-shell"
KNOWN_ATTACK = "T1190"


def run(*argv):
    """Invoke advise.py offline. --no-verify keeps curl out of the test run."""
    done = subprocess.run(
        [sys.executable, str(ADVISE), "--no-verify", *argv],
        capture_output=True, text=True, timeout=120)
    return done.returncode, done.stdout


def header_int(stdout, key):
    m = re.search(r"^{}: (\d+)".format(re.escape(key)), stdout, re.M)
    assert m, "no {} line in header:\n{}".format(key, stdout[:400])
    return int(m.group(1))


def printed_blocks(stdout):
    return len(re.findall(r"^--- PATTERN_ID:", stdout, re.M))


@pytest.mark.parametrize("argv", [
    pytest.param(["--patterns", KNOWN_PATTERN], id="exact-pattern-id"),
    pytest.param(["--attack", KNOWN_ATTACK], id="exact-attack-id"),
    pytest.param(["webserver spawns shell"], id="free-text"),
    pytest.param(["--patterns", KNOWN_PATTERN, "--attack", KNOWN_ATTACK], id="both-exact"),
])
def test_findings_count_matches_what_was_printed(argv):
    """The regression: the header must count findings, never the arguments asked for."""
    code, out = run(*argv)
    assert code == 0, out
    blocks = printed_blocks(out)
    assert blocks > 0, "selection returned nothing:\n{}".format(out[:400])
    assert header_int(out, "FINDINGS") == blocks


@pytest.mark.parametrize("argv", [
    pytest.param(["--patterns", KNOWN_PATTERN], id="exact-pattern-id"),
    pytest.param(["--attack", KNOWN_ATTACK], id="exact-attack-id"),
])
def test_exact_selection_never_reports_zero(argv):
    """The specific shape of the defect: findings printed under a header claiming none."""
    _, out = run(*argv)
    assert header_int(out, "FINDINGS") > 0
    assert "FINDINGS: 0" not in out


def test_selected_by_breakdown_accounts_for_every_finding():
    code, out = run("--patterns", KNOWN_PATTERN, "--attack", KNOWN_ATTACK,
                    "webserver spawns shell")
    assert code == 0, out
    m = re.search(r"^SELECTED_BY: exact pattern id (\d+), exact ATT&CK id (\d+), "
                  r"free-text guess (\d+) across (\d+) shape", out, re.M)
    assert m, out[:400]
    by_pattern, by_attack, by_text, shapes = (int(g) for g in m.groups())
    assert by_pattern + by_attack + by_text == header_int(out, "FINDINGS")
    assert by_pattern == 1
    assert by_attack >= 1
    assert shapes == 1, "the argument count is still reported, just no longer as the total"


def test_free_text_is_counted_as_a_guess_not_an_exact_selection():
    """A guess must never be tallied under an exact-selection column."""
    _, out = run("webserver spawns shell")
    m = re.search(r"^SELECTED_BY: exact pattern id (\d+), exact ATT&CK id (\d+), "
                  r"free-text guess (\d+)", out, re.M)
    assert m, out[:400]
    assert (int(m.group(1)), int(m.group(2))) == (0, 0)
    assert int(m.group(3)) == printed_blocks(out)


@pytest.mark.parametrize("argv,expect", [
    pytest.param(["--patterns", "pat-does-not-exist"], "by exact id", id="unknown-pattern"),
    pytest.param(["--attack", "T9999"], "by exact id", id="uncited-attack"),
    pytest.param(["zzzznomatchanywhere"], "overlapped any shape", id="free-text"),
])
def test_nothing_selected_exits_one_and_says_which_path_failed(argv, expect):
    """An exact selection returning nothing is a different failure from a guess missing,
    and a caller cannot act on it without being told which happened."""
    code, out = run(*argv)
    assert code == 1
    assert "NO_MATCH:" in out
    assert expect in out
    assert header_int(out, "FINDINGS") == 0


def test_locus_observed_is_consult_placement():
    """LOCUS is the library placement from applies_to_classes; LOCUS_OBSERVED is where the
    citing blocks sit, as a consultation places them, and it is on every pattern.

    pat-forge-token-clones-private-repositories-en-masse is SUPPLY by its first-listed class,
    and its only citing block sits on DATA: nothing on its block used to say so.
    """
    code, out = run("--patterns", "pat-forge-token-clones-private-repositories-en-masse,"
                                  "pat-shadow-copy-deletion")
    assert code == 0, out
    blocks = re.split(r"^--- PATTERN_ID: ", out, flags=re.M)[1:]
    assert len(blocks) == 2
    observed = [re.search(r"^LOCUS_OBSERVED: (.*)$", b, re.M) for b in blocks]
    assert all(observed), "every pattern carries LOCUS_OBSERVED, so the key set stays fixed"
    assert "DATA=1" in observed[0].group(1)
    for block, line in zip(blocks, observed):
        counts = [int(n) for n in re.findall(r"[A-Z]+=(\d+)", line.group(1).split(" (")[0])]
        blocks_cited = int(re.search(r"^OBSERVED: yes, \d+ record\(s\), (\d+) how-block\(s\)",
                                     block, re.M).group(1))
        assert sum(counts) == blocks_cited
        assert "input=applies_to_classes" in re.search(r"^LOCUS_BASIS: (.*)$", block, re.M).group(1)


def test_url_liveness_counts_what_it_printed_unchecked():
    """Under --no-verify the header said "0 re-checked this run, 0 unreachable" while 4 of 13
    printed URLs had no verdict in the cache at all and printed exactly as a live one does."""
    import datetime
    import json
    sys.path.insert(0, str(BUNDLE / "scripts"))
    import advise as A  # noqa: E402
    code, out = run("--patterns", "pat-edge-appliance-integrity-mismatch,"
                                  "pat-credential-dump-lsass-access")
    assert code == 0
    cache = json.loads((BUNDLE / "corpus" / "reference" / "url-liveness.json").read_text())
    body = out.split("=== END HEADER ===")[1]
    # The URLs the header counts: each record line's and each ATTACK line's.
    urls = set(re.findall(r"^   \[[A-Z?]+\] obs-.* \| (https?://\S+)", body, re.M))
    urls |= set(re.findall(r"^   T[0-9.]+ +(https?://\S+)", body, re.M))
    today = datetime.date.today()

    def fresh(url):
        entry = cache.get(url)
        return bool(entry) and (today - datetime.date.fromisoformat(
            entry.get("checked", "1970-01-01"))).days <= A.STALE_DAYS
    line = re.search(r"^URL_LIVENESS: (\d+) distinct URLs, 0 re-checked this run, 0 unreachable "
                     r"this run \(network, not a verdict\), (\d+) with no fresh verdict in the "
                     r"cache and printed unchecked, with no marker", out, re.M)
    assert line, out[:2500]
    assert int(line.group(1)) == len(urls)
    assert int(line.group(2)) == sum(1 for u in urls if not fresh(u))
    # advise.py prints no STATUS key: its CONTRACT named one, where the [SEED] bracket is what
    # a record line carries.
    contract = re.search(r"^CONTRACT: (.*)$", out, re.M).group(1)
    assert ("[SEED] marks a record that is unconfirmed: it was not fully re-read against its "
            "source, or its source supports only part of it") in contract
    assert "STATUS: SEED means" not in contract


def test_contract_names_what_is_printed():
    """The CONTRACT said LOCUS_OBSERVED counts citing records, when it counts how-blocks, and
    named a SOURCE_DISCLOSURE key no advise.py block prints."""
    code, out = run("--attack", "T1003")
    assert code == 0, out
    contract = re.search(r"^CONTRACT: (.*)$", out, re.M).group(1)
    assert "citing how-blocks sit" in contract and "citing records sit" not in contract
    assert "SOURCE_DISCLOSURE" not in contract
    assert not re.search(r"^SOURCE_DISCLOSURE: ", out, re.M)
