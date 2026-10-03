# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""What advise.py selects, and what it says about everything it did not.

Three selection paths shipped defects a caller could not see:

- Free text could not reach a pattern by the words in its own id. lsass, dcsync,
  kerberoasting, impacket and "helpdesk impersonation" each returned nothing, "pre-auth"
  matched every pre-X compound on "pre", and "edge appliance" and "edge appliances" disagreed.
- An ATT&CK parent selected only the patterns citing the parent itself: T1003 found 2 of the
  family's patterns, and T1684, where ATT&CK 19.2 moved Impersonation, found none. A revoked
  id was indistinguishable from a typo, and an id cited only by records pointed nowhere.
- A shape that matched nothing vanished from the answer, and a match already shown under an
  earlier selection was dropped without a word to the shape that found it.

Expected counts are computed from the corpus rather than written in, so a new record or
pattern moves the expectation and not the test.

Run with PYTHONDONTWRITEBYTECODE=1 (LAW A26).
"""
import pathlib
import re
import subprocess
import sys

import pytest

BUNDLE = pathlib.Path(__file__).resolve().parents[1]
ADVISE = BUNDLE / "scripts" / "advise.py"

sys.dont_write_bytecode = True
sys.path.insert(0, str(BUNDLE / "scripts"))
import advise as A  # noqa: E402
import query as Q  # noqa: E402

RECORDS, PATTERNS = Q.load_corpus(str(BUNDLE / "corpus"))
CITES = {pid: {t.upper() for t in p.get("technique") or []} for pid, p in PATTERNS.items()}
ATTACK = A.C.load_attack(str(BUNDLE / "corpus"))
VOCAB = A.C.load_vocab(str(BUNDLE / "corpus"))
CITING = A.load(str(BUNDLE / "corpus"))[3]


def run(*argv):
    done = subprocess.run([sys.executable, str(ADVISE), "--no-verify", *argv],
                          capture_output=True, text=True, timeout=300, cwd=str(BUNDLE))
    return done.returncode, done.stdout, done.stderr


def first_pattern(stdout):
    m = re.search(r"^--- PATTERN_ID: (\S+)", stdout, re.M)
    return m.group(1) if m else None


def printed(stdout):
    return re.findall(r"^--- PATTERN_ID: (\S+)", stdout, re.M)


def header_int(stdout, key):
    m = re.search(r"^{}: (\d+)".format(re.escape(key)), stdout, re.M)
    assert m, stdout[:600]
    return int(m.group(1))


# --- free text ------------------------------------------------------------------------------

@pytest.mark.parametrize("shape,expected", [
    ("lsass", "pat-credential-dump-lsass-access"),
    ("dcsync", "pat-dcsync-replication-request"),
    ("kerberoasting", "pat-kerberoasting-service-ticket-requests"),
    ("impacket", "pat-impacket-protocol-tooling"),
    ("helpdesk impersonation", "pat-helpdesk-impersonation-by-voice-or-sms"),
    ("web server spawning a shell", "pat-webserver-spawns-shell"),
])
def test_id_vocabulary_reaches_its_pattern(shape, expected):
    code, out, _ = run(shape)
    assert code == 0, out[-400:]
    assert first_pattern(out) == expected


def test_plural_and_singular_agree():
    _, singular, _ = run("edge appliance")
    _, plural, _ = run("edge appliances")
    assert first_pattern(singular) and first_pattern(singular) == first_pattern(plural)


def test_hyphen_fragment_alone_selects_nothing():
    _, out, _ = run("pre-auth RCE on VPN appliances")
    assert not re.search(r"overlap on (\S+, )*pre[ ,(]", out), out
    assert "pat-safe-mode-boot-configuration-change" not in out
    assert first_pattern(out) == "pat-preauth-by-design-endpoint-reached-from-internet"


def test_a_common_word_alone_is_not_a_match():
    """'credential' returned three patterns at score 0.8 on one word most patterns carry."""
    code, out, _ = run("credential")
    assert code == 1 and "NO_MATCH" in out


def test_match_basis_names_the_rarest_word_first():
    _, out, _ = run("lsass memory dumping")
    m = re.search(r"^MATCH_BASIS: free-text overlap on (\S+?),", out, re.M)
    assert m and m.group(1) == "lsass", out[:1500]


def test_technique_id_typed_as_text_points_at_attack():
    code, out, _ = run("T1003.001")
    assert "--attack T1003.001" in out
    assert "SUGGEST_ATTACK: T1003.001 (LSASS Memory)" in out


def test_technique_name_points_at_its_id_and_selects_nothing_by_it():
    _, out, _ = run("LSASS Memory")
    assert "SUGGEST_ATTACK: T1003.001 (LSASS Memory) - --attack T1003.001" in out
    for line in re.findall(r"^MATCH_BASIS: .*$", out, re.M):
        assert line.startswith("MATCH_BASIS: free-text overlap on"), line


# --- ATT&CK selection -----------------------------------------------------------------------

def family(parent):
    direct = sorted(pid for pid, cites in CITES.items() if parent in cites)
    subs = sorted(pid for pid, cites in CITES.items()
                  if parent not in cites and any(c.startswith(parent + ".") for c in cites))
    return direct, subs


def selected_by(out):
    m = re.search(r"^SELECTED_BY: exact pattern id (\d+), exact ATT&CK id (\d+), free-text guess "
                  r"(\d+) across (\d+) shape\(s\) asked; of the ATT&CK selections, (\d+) cite a "
                  r"requested id, (\d+) cite a sub-technique of a requested parent, (\d+) cite "
                  r"MITRE's replacement for a revoked id, (\d+) cite a sub-technique of such a "
                  r"replacement$", out, re.M)
    assert m, out[:800]
    return [int(g) for g in m.groups()]


def test_parent_selects_its_sub_techniques():
    direct, subs = family("T1003")
    assert "pat-credential-dump-lsass-access" in subs and "pat-dcsync-replication-request" in subs
    code, out, _ = run("--attack", "T1003")
    assert code == 0
    assert sorted(printed(out)) == sorted(direct + subs)
    assert header_int(out, "FINDINGS") == len(direct) + len(subs)
    by_pattern, by_attack, by_text, _, cite, sub, repl, under = selected_by(out)
    assert by_pattern + by_attack + by_text == header_int(out, "FINDINGS")
    assert (cite, sub, repl, under) == (len(direct), len(subs), 0, 0)
    assert len(re.findall(r"^MATCH_BASIS: selected by T1003\.\d+.* of requested T1003", out, re.M)) \
        == len(subs)


def test_attack_exact_disables_expansion():
    direct, _ = family("T1003")
    _, out, _ = run("--attack", "T1003", "--attack-exact")
    assert header_int(out, "FINDINGS") == len(direct)
    assert "sub-techniques not expanded (--attack-exact)" in out


def test_parent_with_no_direct_citation_is_not_no_match():
    direct, subs = family("T1684")
    assert not direct and subs
    code, out, _ = run("--attack", "T1684")
    assert code == 0
    assert header_int(out, "FINDINGS") == len(subs)


def test_a_sub_technique_request_names_the_parent_only_patterns():
    only = [pid for pid, cites in CITES.items() if "T1003" in cites and "T1003.001" not in cites]
    assert only
    _, out, _ = run("--attack", "T1003.001")
    assert "ATTACK_PARENT_ONLY: {} pattern(s) cite the parent T1003 but not T1003.001; " \
           "--attack T1003 includes them".format(len(only)) in out


def test_revoked_attack_id_names_its_replacement_and_follows_it():
    """Followed to T1685, the id is answered as --attack T1685 is: its citers and, T1685 being
    a live parent, the citers of its sub-techniques, each labelled by what it cites."""
    replaced, under = family("T1685")
    code, out, _ = run("--attack", "T1562.001")
    assert code == 0
    assert "ATTACK_REQUESTED: T1562.001 (Disable or Modify Tools) -> REVOKED in ATT&CK" in out
    assert "replaced by T1685 (Disable or Modify Tools): followed, {} pattern(s): {} cite " \
           "T1685, {} cite a sub-technique of it".format(
               len(replaced) + len(under), len(replaced), len(under)) in out
    assert sorted(printed(out)) == sorted(replaced + under)
    bases = re.findall(r"^MATCH_BASIS: (.*)$", out, re.M)
    assert bases.count("selected via T1685, MITRE's replacement for revoked T1562.001") \
        == len(replaced)
    assert len([b for b in bases if re.match(
        r"selected by T1685\.\d+(, T1685\.\d+)*, (a sub-technique|sub-techniques) of T1685, "
        r"MITRE's replacement for revoked T1562\.001 - the pattern cites neither", b)]) \
        == len(under)
    assert selected_by(out)[4:] == [0, 0, len(replaced), len(under)]


def test_deprecated_id_says_so():
    code, out, _ = run("--attack", "T1064")
    assert code == 1
    assert "ATTACK_REQUESTED: T1064 (Scripting) -> DEPRECATED in ATT&CK" in out


def test_unknown_id_is_not_called_revoked():
    code, out, _ = run("--attack", "T9999")
    assert code == 1
    assert "not an id in the shipped" in out
    assert "REVOKED" not in out
    assert "by exact id" in out


def test_every_requested_id_is_accounted_for_on_stdout():
    _, out, _ = run("--attack", "T1190,T1562.001,T9999")
    lines = re.findall(r"^ATTACK_REQUESTED: (\S+)", out, re.M)
    assert lines == ["T1190", "T1562.001", "T9999"]


def test_rejected_pattern_id_is_on_stdout():
    code, out, _ = run("--patterns", "pat-webserver-spawns-shell,pat-typo-here,T1190")
    assert code == 0
    assert "PATTERNS_REJECTED: pat-typo-here (no such pattern id); T1190 (an ATT&CK id - use " \
           "--attack)" in out
    assert header_int(out, "FINDINGS") == 1


def test_record_only_technique_points_at_its_patterns():
    blocks = [(r["id"], h.get("pattern_id")) for r in RECORDS for h in r.get("how") or []
              if "T1550.002" in {t.upper() for t in h.get("technique") or []}]
    assert blocks and not any("T1550.002" in cites for cites in CITES.values())
    code, out, _ = run("--attack", "T1550.002")
    assert code == 1
    assert "ATTACK_RECORD_ONLY: T1550.002 is cited by {} how-block(s)".format(len(blocks)) in out
    assert "pat-credential-dump-lsass-access" in out
    assert "see ATTACK_RECORD_ONLY" in re.search(r"^ATTACK_REQUESTED: .*$", out, re.M).group(0)


# --- shapes ---------------------------------------------------------------------------------

THREE = ["webserver spawns shell", "zzzznomatchqq", "web server spawning a shell"]


def test_every_shape_gets_a_banner():
    code, out, _ = run(*THREE)
    assert code == 0
    banners = re.findall(r"^### SHAPE: SELECTION: free-text-guess -- (.*)$", out, re.M)
    assert banners == THREE
    assert out.count("SHAPE_RESULT: no pattern overlapped this shape") == 1
    assert "SHAPES_EMPTY: 1 of 3" in out
    assert header_int(out, "FINDINGS") == len(printed(out))


def test_deduplicated_match_is_named():
    _, out, _ = run(*THREE)
    third = out.split("### SHAPE: SELECTION: free-text-guess -- web server spawning a shell")[1]
    result = re.search(r"SHAPE_RESULT: .*", third).group(0)
    assert "already shown above" in result and "pat-webserver-spawns-shell" in result


def test_every_basis_is_counted_explicitly():
    """The free-text column was the remainder, so a new basis counted as a guess."""
    _, out, _ = run("--patterns", "pat-webserver-spawns-shell", "--attack", "T1003,T1562.001",
                    "lsass")
    by_pattern, by_attack, by_text, shapes, cite, sub, repl, under = selected_by(out)
    assert by_pattern + by_attack + by_text == header_int(out, "FINDINGS")
    assert cite + sub + repl + under == by_attack
    assert by_text == len(re.findall(r"^MATCH_BASIS: free-text overlap", out, re.M))


def test_stemmer_keeps_double_s_words_whole():
    assert A._stem("lsass") == "lsass" and A._stem("access") == "access"
    assert A._stem("spawning") == A._stem("spawns") == A._stem("spawn")
    assert A._stem("appliances") == A._stem("appliance")
    assert A._stem("logging") == A._stem("logs")
    assert "pre" not in A._terms("pre-auth") and {"preauth", "auth"} <= A._terms("pre-auth")


# --- 0.43.0, batch V5: what a selection leaves out, and free text past its fitted words ----

def test_record_only_blocks_are_reported_when_the_id_also_selected_patterns():
    """ATTACK_RECORD_ONLY printed only when an id selected nothing. `--attack T1190` returned
    50 patterns and said nothing of 21 T1190 how-blocks under 12 patterns that do not list it,
    seven of whose records -- four of them exploitation of a management interface -- appeared
    nowhere in the answer."""
    selected = {pid for pid, cites in CITES.items() if "T1190" in cites}
    blocks = [(r["id"], h.get("pattern_id")) for r in RECORDS for h in r.get("how") or []
              if "T1190" in {t.upper() for t in h.get("technique") or []}
              and h.get("pattern_id") not in selected]
    assert selected and blocks, "fixture no longer has T1190 blocks outside its patterns"
    code, out, _ = run("--attack", "T1190")
    assert code == 0
    requested = re.search(r"^ATTACK_REQUESTED: T1190 .*$", out, re.M).group(0)
    assert "{} further how-block(s) cite it under patterns that do not list it".format(
        len(blocks)) in requested
    line = re.search(r"^ATTACK_RECORD_ONLY: T1190 is cited by (\d+) how-block\(s\) whose pattern "
                     r"does not list it: (.*?) - select them with --patterns(.*)$", out, re.M)
    assert line and int(line.group(1)) == len(blocks), out[:3000]
    assert line.group(2).split(", ") == sorted({p for _, p in blocks if p})
    unseen = sorted({rid for rid, _ in blocks} - {
        r["id"] for r in RECORDS if r["id"] in {rid for rid, _ in blocks}
        and any(h.get("pattern_id") in selected for h in r.get("how") or [])})
    assert unseen, "fixture: every record now cites a T1190 pattern"
    assert line.group(3).endswith(": " + ", ".join(unseen)), line.group(3)
    for rid in unseen:
        assert out.count(rid) == 1, rid
    assert "obs-f5-big-ip-management-interface-exploitation" in unseen


def test_a_selected_pattern_block_is_not_record_only():
    """A block citing a revoked id under a pattern citing its replacement is selected, and a
    block citing a sub-technique under a pattern that --attack <parent> selects is too."""
    _, out, _ = run("--attack", "T1562.001")
    assert "ATTACK_RECORD_ONLY: T1562.001" not in out
    code, out, _ = run("--attack", "T1003")

    def in_family(tid):
        return tid.upper() == "T1003" or tid.upper().startswith("T1003.")
    outside = [r["id"] for r in RECORDS for h in r.get("how") or []
               if any(in_family(t) for t in h.get("technique") or [])
               and not any(in_family(t) for t in CITES.get(h.get("pattern_id"), set()))]
    m = re.search(r"^ATTACK_RECORD_ONLY: T1003 is cited by (\d+) how-block", out, re.M)
    assert (int(m.group(1)) if m else 0) == len(outside)


@pytest.mark.parametrize("word,stem", [
    ("exploitation", "exploit"), ("exploitations", "exploit"), ("exploited", "exploit"),
    ("impersonation", "imperson"), ("impersonate", "imperson"),
    ("escalation", "escal"), ("escalated", "escal"), ("injection", "inject"),
    ("injected", "inject"), ("management", "manag"), ("managed", "manag"),
    ("administrator", "administr"), ("administration", "administr"),
])
def test_derivational_endings_meet_their_verb(word, stem):
    """_stem left "exploitation" whole, so it never met "exploit", which 69 patterns carry."""
    assert A._stem(word) == stem


def test_short_words_ending_in_at_stay_whole_and_a_stop_word_stays_stopped():
    assert A._stem("threat") == "threat" and A._stem("format") == "format"
    # "execution" is a stop word; its plural must not come back in as "execut".
    assert "execution" in A.C.STOPWORDS and not A._terms("executions")


def free_text(shape, per_shape=None):
    argv = [shape] + (["--per-shape", str(per_shape)] if per_shape else [])
    code, out, _ = run(*argv)
    return code, out, printed(out)


@pytest.mark.parametrize("shape,expected", [
    ("DC sync", "pat-dcsync-replication-request"),
    ("IIS spawning cmd.exe", "pat-webserver-spawns-shell"),
    ("w3wp spawns powershell", "pat-webserver-spawns-shell"),
])
def test_synonyms_outside_the_fitted_vocabulary_reach_the_obvious_pattern_first(shape, expected):
    """The regression set above is the vocabulary the matcher was tuned on. "DC sync" ranked
    three sync patterns over DCSync; "IIS spawning cmd.exe" and "w3wp spawns powershell"
    ranked pat-print-spooler-abuse first on an alphabetical tie."""
    code, out, got = free_text(shape)
    assert code == 0 and got and got[0] == expected, got


@pytest.mark.parametrize("shape,expected", [
    ("webshell", {"technique": "T1505.003"}),
    ("vishing", {"pattern": "pat-helpdesk-impersonation-by-voice-or-sms"}),
    ("mimikatz", {"pattern": "pat-commodity-offensive-tooling-baseline"}),
])
def test_a_defenders_word_is_not_reported_as_an_absence(shape, expected):
    """Each came back NO_MATCH, exit 1, calling itself "a reportable finding", over a Web Shell
    technique seven patterns cite, a Teams vishing record citing the helpdesk pattern and a
    marker naming mimikatz. Their words were in the markers and the citing records."""
    code, out, got = free_text(shape)
    assert code == 0 and "NO_MATCH" not in out, out[-600:]
    if "pattern" in expected:
        assert expected["pattern"] in got, got
    else:
        assert expected["technique"] in CITES[got[0]], got
    for line in re.findall(r"^MATCH_BASIS: .*$", out, re.M):
        assert line.endswith("VERIFY THIS IS THE RIGHT PATTERN BEFORE CITING IT"), line


def match_basis_of(out, pid):
    block = out.split("--- PATTERN_ID: {}\n".format(pid), 1)[1].split("\n--- PATTERN_ID:", 1)[0]
    return re.search(r"^MATCH_BASIS: (.*)$", block, re.M).group(1)


def detects_appliance_exploitation(pid):
    pattern = PATTERNS[pid]
    return ("T1190" in CITES[pid] and pattern.get("fidelity") in A.DETECTION_GRADE
            and any(c.startswith("network.") for c in pattern.get("applies_to_classes") or []))


@pytest.mark.parametrize("shape", [
    "exploitation of edge network appliances",
    "edge appliance exploitation",
    "exploiting edge appliances",
])
def test_edge_appliance_exploitation_returns_a_detection_of_the_exploitation(shape):
    """The shape returned three patterns named for edge appliances, integrity, reboots and a
    trusted proxy, and no T1190 pattern; the first fix returned one, an inventory item about
    which product classes recur on the exploited list, kept for the word "exploitation", while
    the patterns detecting exploitation of an appliance ranked eighth to fourteenth. A
    detection (alert or hunt) of T1190 on a network appliance class is now among the three,
    and its MATCH_BASIS says it is there for the behaviour the shape names."""
    code, out, got = free_text(shape)
    assert code == 0 and len(got) == 3
    hits = [pid for pid in got if detects_appliance_exploitation(pid)]
    assert hits, got
    basis = match_basis_of(out, hits[0])
    assert "kept for the behaviour the shape names: it cites T1190 (Exploit Public-Facing " \
           "Application), which exploit" in basis, basis
    assert "--attack T1190 selects every pattern citing it" in basis
    assert basis.endswith("VERIFY THIS IS THE RIGHT PATTERN BEFORE CITING IT")
    result = re.search(r"SHAPE_RESULT: 3 new, 0 already shown above; (\d+) pattern\(s\) "
                       r"overlapped this shape, (\d+) cut by --per-shape 3", out)
    assert result and int(result.group(1)) - 3 == int(result.group(2)) > 0, out[:1500]


def test_the_behaviour_slot_needs_three_slots():
    _, out, got = free_text("exploitation of edge network appliances", per_shape=2)
    assert "kept for" not in out and len(got) == 2


@pytest.mark.parametrize("shape,kept", [
    ("pass the hash", "pat-local-credential-store-extraction"),
    ("firmware implant on a router", None),
    ("cloud storage bucket made public", None),
    ("oauth consent phishing", None),
    ("brute force against a vpn", None),
    ("configuration change on a network device", "pat-network-device-config-or-route-change"),
])
def test_the_behaviour_slot_stays_out_of_shapes_it_is_not_needed_for(shape, kept):
    """The slot it replaces fired on 'pass' ("never passed review"), 'implant' and 'made',
    displacing a relevant third guess for "pass the hash" and "firmware implant on a
    router", and labelled natural third guesses it had not moved. A shape spelling a whole
    ATT&CK name names that technique only (Pass the Hash, which no pattern cites), a guess
    above citing the behaviour keeps the slot shut, and a pick must meet every other word."""
    code, out, got = free_text(shape)
    assert code == 0 and "kept for" not in out, [
        line for line in out.splitlines() if "kept for" in line]
    if kept:
        assert kept in got, got


def test_a_spelled_technique_name_is_the_only_one_it_names():
    matcher = A.Matcher(PATTERNS, ATTACK, CITING, VOCAB.get("product_class"))
    forms, _, _ = matcher.shape_forms("pass the hash")
    assert not matcher.named(forms, ["T1550.002"])
    assert "T1550.003" in matcher.named(forms)
    forms, _, _ = matcher.shape_forms("exploitation of edge network appliances")
    assert "T1190" in matcher.named(forms)


def test_ransomware_encryption_returns_an_encryption_detection():
    """"ransomware encryption" lost its T1486 patterns from the three returned once the stemmer
    let "encryption" meet "encrypted": two log patterns whose descriptions carry both words
    took the second and third places."""
    code, out, got = free_text("ransomware encryption")
    assert code == 0
    hits = [pid for pid in got if "T1486" in CITES[pid]
            and PATTERNS[pid].get("fidelity") in A.DETECTION_GRADE]
    assert hits, got
    assert "it cites T1486 (Data Encrypted for Impact)" in match_basis_of(out, hits[0])


def test_a_split_word_is_met_only_whole():
    """"helpdesk impersonation" filled its second and third places on "help (in helpdesk)" and
    "desk (in helpdesk)" alone."""
    code, out, got = free_text("helpdesk impersonation")
    assert code == 0 and got[0] == "pat-helpdesk-impersonation-by-voice-or-sms"
    for line in re.findall(r"^MATCH_BASIS: .*$", out, re.M):
        assert ("help (in helpdesk)" in line) == ("desk (in helpdesk)" in line), line
    parts = [(frozenset({"help", "desk"}), frozenset({"help", "desk"}))]
    assert A.whole({"help", "imperson"}, parts) == {"imperson"}
    assert A.whole({"help", "desk", "imperson"}, parts) == {"help", "desk", "imperson"}
    # A half the caller also wrote as a word of its own stands alone.
    assert A.whole({"desk"}, [(frozenset({"help", "desk"}), frozenset({"help"}))]) == {"desk"}


def test_record_only_does_not_tell_the_caller_to_select_what_is_already_returned():
    """`--attack T1190,T1078` told the caller, for T1190, to select with --patterns a pattern
    T1078 had returned, and for T1078 two that T1190 had."""
    code, out, _ = run("--attack", "T1190,T1078")
    assert code == 0
    returned = set(printed(out))
    lines = re.findall(r"^ATTACK_RECORD_ONLY: .*$", out, re.M)
    assert len(lines) == 2, lines
    moved = 0
    for line in lines:
        m = re.search(r"does not list it: (.*?) - select them with --patterns", line)
        assert m and not set(m.group(1).split(", ")) & returned, line
        back = re.search(r"; (\d+) of their pattern\(s\) returned here by another selection: "
                         r"(.*?);", line)
        if back:
            names = back.group(2).split(", ")
            assert int(back.group(1)) == len(names) and set(names) <= returned, line
            moved += len(names)
    assert moved, lines


def test_a_typed_id_that_selects_patterns_is_not_called_an_absence():
    code, out, _ = run("T1003.001")
    assert code == 1
    line = re.search(r"^NO_MATCH: .*$", out, re.M).group(0)
    assert "reportable finding" not in line and "run --attack T1003.001" in line
    assert "not an absence from the corpus" in line
    code, out, _ = run("zzzznomatchqq")
    assert code == 1 and "reportable finding" in out


# --- 0.43.0, batch R4: a revoked parent's family -------------------------------------------

def revoked_family(parent):
    """What --attack <revoked parent> must reach, read from the reference: MITRE's replacement
    for it and for each of its revoked sub-techniques, and each replacement's sub-techniques
    where it is a parent."""
    followed = [ATTACK[parent]["replaced_by"]] + sorted(
        ATTACK[t]["replaced_by"] for t in ATTACK
        if t.startswith(parent + ".") and ATTACK[t].get("revoked") and ATTACK[t].get("replaced_by"))
    reached = set()
    for new in followed:
        reached |= {pid for pid, cites in CITES.items() if new in cites
                    or ("." not in new and any(c.startswith(new + ".") for c in cites))}
    return reached


def test_a_revoked_parent_reaches_its_whole_family():
    """--attack T1562 followed it to T1685 and stopped: 20 of the 31 patterns in its family,
    with nothing said of the 11 citing a sub-technique of T1685 or the replacement of a revoked
    sub-technique of T1562 (host firewall, cloud network exposure, safe-mode boot)."""
    assert ATTACK["T1562"]["revoked"]
    expected = revoked_family("T1562")
    direct = {pid for pid, cites in CITES.items() if "T1685" in cites}
    assert len(expected) > len(direct)
    for pid in ("pat-host-firewall-rule-modification", "pat-safe-mode-boot-configuration-change",
                "pat-cloud-network-exposure-opened", "pat-windows-event-log-cleared",
                "pat-cloud-api-surface-outside-audit-coverage"):
        assert pid in expected, pid
    code, out, _ = run("--attack", "T1562")
    assert code == 0
    assert set(printed(out)) == expected
    assert header_int(out, "FINDINGS") == len(expected)
    by_pattern, by_attack, by_text, _, cite, sub, repl, under = selected_by(out)
    assert (cite, sub) == (0, 0) and repl + under == len(expected) and under >= 1
    line = re.search(r"^ATTACK_REQUESTED: T1562 .*$", out, re.M).group(0)
    m = re.search(r"followed, (\d+) pattern\(s\): (\d+) cite T1685, (\d+) cite the replacement "
                  r"of one of its own revoked sub-techniques \(([^)]*)\), (\d+) cite only a "
                  r"sub-technique of one of them", line)
    assert m, line
    assert int(m.group(1)) == len(expected) == int(m.group(2)) + int(m.group(3)) + int(m.group(5))
    assert int(m.group(2)) == len(direct)
    assert "T1686" in m.group(4).split(", ") and "T1688" in m.group(4).split(", ")
    assert "ATTACK_RECORD_ONLY: T1562 " not in out


def test_attack_exact_follows_the_replacement_alone():
    direct = sorted(pid for pid, cites in CITES.items() if "T1685" in cites)
    _, out, _ = run("--attack", "T1562", "--attack-exact")
    assert sorted(printed(out)) == direct
    assert "sub-techniques of T1685, and T1562's own revoked sub-techniques, not followed " \
           "(--attack-exact)" in out


def test_a_record_only_line_names_the_ids_its_blocks_cite():
    """--attack T1003 said 2 how-blocks "cite it" when one of them cites T1003.001 only."""
    code, out, _ = run("--attack", "T1003")
    assert code == 0
    line = re.search(r"^ATTACK_RECORD_ONLY: T1003 .*$", out, re.M).group(0)
    blocks = [h for r in RECORDS for h in r.get("how") or []
              if h.get("pattern_id") not in A.AttackIndex(PATTERNS, RECORDS, ATTACK, "19.2").selects(
                  "T1003")
              and any(t.upper() == "T1003" or t.upper().startswith("T1003.")
                      for t in h.get("technique") or [])]
    cited = sorted({t.upper() for h in blocks for t in h.get("technique") or []
                    if t.upper() == "T1003" or t.upper().startswith("T1003.")})
    assert len(cited) > 1, cited
    assert ", as {},".format(" and ".join(
        "{} ({})".format(t, sum(1 for h in blocks if t in {x.upper() for x in h["technique"]}))
        for t in cited)) in line
    requested = re.search(r"^ATTACK_REQUESTED: T1003 .*$", out, re.M).group(0)
    assert "further how-block(s) cite it or what it reaches under patterns" in requested
