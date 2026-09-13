# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The URL-liveness cache is the one thing this bundle writes, and it had two ways to lie.

Both were invisible in normal use, which is why they need tests rather than care.

1. `--corpus` threaded through every loader in advise.py and stopped at the cache. A run
   against another corpus read and WROTE the installed bundle's own cache, and the header
   printed a relpath of the module global, which rendered identically either way -- so the
   output positively suggested the flag had been honoured.

2. A transport failure wrote `unreachable` over whatever a URL's entry held and re-stamped
   `checked`, suppressing any re-check for the full staleness window. The shipped cache holds
   215 URLs all checked on one day, so the FIRST offline run after they go stale would have
   turned 208 known-live sources into 208 apparently dead ones for a fortnight, and every
   REFERENCES line would have carried '<<< unreachable' -- which reads as a claim about the
   source, not about the caller's network.
"""
import datetime
import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import advise as A  # noqa: E402

URL = "https://example.invalid/technique/T9999/"


def _corpus(tmp_path, entry):
    ref = tmp_path / "reference"
    ref.mkdir(parents=True)
    (ref / "url-liveness.json").write_text(json.dumps({URL: entry}), encoding="utf-8")
    return str(tmp_path)


def test_the_cache_follows_corpus_rather_than_the_installed_bundle(tmp_path, monkeypatch):
    """The whole point of --corpus. Write into a scratch corpus, leave the bundle alone."""
    fresh = datetime.date.today().isoformat()
    corpus = _corpus(tmp_path, {"checked": "1970-01-01", "title": "old", "state": "live"})
    monkeypatch.setattr(A.subprocess, "run", lambda *a, **k: type(
        "R", (), {"returncode": 0, "stdout": b"<title>New Title</title>"})())

    before = open(os.path.join(ROOT, "corpus", "reference", "url-liveness.json"),
                  encoding="utf-8").read()
    cache, todo, unreachable = A.liveness([URL], True, corpus)
    after = open(os.path.join(ROOT, "corpus", "reference", "url-liveness.json"),
                 encoding="utf-8").read()

    assert before == after, "a --corpus run wrote to the installed bundle's cache"
    written = json.loads((tmp_path / "reference" / "url-liveness.json").read_text(encoding="utf-8"))
    assert written[URL]["state"] == "live"
    assert written[URL]["checked"] == fresh


@pytest.mark.parametrize("boom", [OSError("no curl"), subprocess.TimeoutExpired("curl", 40)])
def test_a_transport_failure_never_overwrites_a_verdict(tmp_path, monkeypatch, boom):
    """No network is not evidence that a source is dead."""
    held = {"checked": "1970-01-01", "title": "Brute Force, Technique T1110", "state": "live"}
    corpus = _corpus(tmp_path, dict(held))

    def explode(*args, **kwargs):
        raise boom
    monkeypatch.setattr(A.subprocess, "run", explode)

    cache, todo, unreachable = A.liveness([URL], True, corpus)

    assert unreachable == 1, "the run did not report the URL as unreachable"
    assert cache[URL] == held, "a transport failure overwrote a live verdict"
    on_disk = json.loads((tmp_path / "reference" / "url-liveness.json").read_text(encoding="utf-8"))
    assert on_disk[URL]["state"] == "live"
    assert on_disk[URL]["checked"] == "1970-01-01", \
        "`checked` was re-stamped, which suppresses the re-check for the staleness window"


def test_an_empty_page_is_still_recorded_as_deprecated():
    """The fix must not cost the signal the cache was built for.

    A URL that was live and is now empty is a deprecated technique -- that is how the whole
    T1562 family was caught -- so 'reachable but empty' must stay distinguishable from
    'could not reach it'.
    """
    assert "DEPRECATED-OR-EMPTY" in open(
        os.path.join(ROOT, "scripts", "advise.py"), encoding="utf-8").read()


@pytest.mark.parametrize("markup", [
    b'<title data-react-helmet="true">Uncloaking VoidProxy</title>',
    b"<title lang='en'>Uncloaking VoidProxy</title>",
    b'<title\n  data-rh="true">Uncloaking VoidProxy</title>',
])
def test_a_title_carrying_attributes_is_not_read_as_an_empty_page(tmp_path, monkeypatch, markup):
    """A third way the check could lie, and the one that outlived the other two.

    The cache was carrying seven non-live verdicts on pages that answer 200 with 160 KB or
    more, and the recorded diagnosis was that those publishers render the title in
    JavaScript. For Okta that is not what happens: the title is in the served markup and
    carries an attribute, so a pattern requiring a bare open tag misses it and files a live
    page as DEPRECATED-OR-EMPTY. Five of the seven cleared on their own when their
    publishers changed markup, which would have left this failing quietly on two.
    """
    corpus = _corpus(tmp_path, {"checked": "1970-01-01", "title": "", "state": "live"})
    monkeypatch.setattr(A.subprocess, "run", lambda *a, **k: type(
        "R", (), {"returncode": 0, "stdout": markup})())

    cache, todo, unreachable = A.liveness([URL], True, corpus)

    assert cache[URL]["title"] == "Uncloaking VoidProxy"
    assert cache[URL]["state"] == "live", \
        "a title carrying an attribute was read as an empty page"


def test_an_element_whose_name_merely_starts_with_title_is_not_a_title(tmp_path, monkeypatch):
    """The fix must widen the tag, not the name. <titlebar> is not <title>."""
    corpus = _corpus(tmp_path, {"checked": "1970-01-01", "title": "", "state": "live"})
    monkeypatch.setattr(A.subprocess, "run", lambda *a, **k: type(
        "R", (), {"returncode": 0, "stdout": b"<titlebar>chrome</titlebar>"})())

    cache, todo, unreachable = A.liveness([URL], True, corpus)

    assert cache[URL]["state"] == "DEPRECATED-OR-EMPTY"
