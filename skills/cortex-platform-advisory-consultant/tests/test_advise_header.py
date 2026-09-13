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
