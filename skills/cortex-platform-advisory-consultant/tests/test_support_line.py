# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""How well-backed a finding is, on the axis nothing else in the block reported.

Ranking weighs recency and CORROBORATION names independent accounts, but until 0.21.0
nothing said when anybody last confirmed the source still says what the record claims.
A reader weighing twelve findings had no way to tell the well-attested from the
never-revisited. These tests hold the line in place and, more importantly, hold its
flags honest: a flag on every finding is noise, and a flag on none is a lie.
"""
import datetime
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import consult as C  # noqa: E402

TODAY = datetime.date(2026, 8, 19)


def records():
    path = os.path.join(ROOT, "corpus", "observations", "observations.jsonl")
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def test_every_finding_carries_a_support_line():
    out = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "consult.py"),
                          "Cisco ASA", "--limit", "8", "--today", "2026-08-19"],
                         capture_output=True, text=True, cwd=ROOT).stdout
    blocks = out.split("=== FINDING ")[1:]
    assert blocks
    assert all("SUPPORT:" in b for b in blocks)


def test_a_well_attested_record_carries_no_flags():
    """If everything is flagged the flags mean nothing."""
    good = {"status": "verified",
            "when": {"published": "2026-08-01"},
            "where": {"retrieved": "2026-08-18", "verified": True}}
    line = C.support(good, TODAY)
    assert "[" not in line, line
    assert "published=2026-08-01" in line and "source_last_read=2026-08-18" in line


def test_missing_read_date_and_verification_are_flagged():
    bare = {"status": "verified", "when": {"published": "2026-08-01"}, "where": {}}
    line = C.support(bare, TODAY)
    assert "NO_READ_DATE" in line and "VERIFICATION_UNSTATED" in line


def test_missing_publication_date_says_what_it_costs():
    """age_days() silently ranks an undated record as 3650 days old; the flag must say so."""
    undated = {"status": "verified", "when": {},
               "where": {"retrieved": "2026-08-18", "verified": True}}
    line = C.support(undated, TODAY)
    assert "NO_PUBLICATION_DATE:ranked-as-3650d" in line


def test_seed_status_is_flagged():
    seed = {"status": "seed", "when": {"published": "2026-08-01"},
            "where": {"retrieved": "2026-08-18", "verified": True}}
    assert "SEED" in C.support(seed, TODAY)


def test_age_is_reported_but_never_flagged():
    """Staleness duplicates PRIORITY_BASIS days_since_published and fires on KEV by design."""
    old = {"status": "verified", "when": {"published": "2019-01-01"},
           "where": {"retrieved": "2026-08-18", "verified": True}}
    line = C.support(old, TODAY)
    assert "published=2019-01-01" in line
    assert "[" not in line, "age alone must not raise a flag: {}".format(line)


def test_flags_stay_a_minority_of_the_corpus():
    """A flag has to be a signal. If most findings carry one it is decoration."""
    obs = [r for r in records() if r.get("record_type") == "observation"]
    flagged = sum(1 for r in obs if "[" in C.support(r, TODAY))
    assert flagged < len(obs) / 2, "{} of {} observations flagged".format(flagged, len(obs))


def consult(question, *extra):
    return subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "consult.py"), question,
                           "--today", "2026-10-01", *extra],
                          capture_output=True, text=True, cwd=ROOT).stdout


def test_a_seed_banner_says_which_meaning_applies():
    """Seed has two meanings, and the banner asserted one of them for every seed record.

    The Fortinet family record was re-read on 2026-09-25 and held as seed because its post
    supports only half of it. Its STATUS line said "source not re-read" directly above its
    own `verified=yes`; it then named both meanings and pointed at notes nothing prints, the
    same line on the block the post supports and on the one it does not. A re-read seed now
    says per block whether its source supports it (how[].unconfirmed), and the banner names
    the meaning that applies.
    """
    lines = consult("Fortinet FortiGate", "--limit", "500").splitlines()
    key = "obs-fortinet-product-family-breadth-and-management-reach#how"
    status = {lines[i][len("FINDING_KEY: "):]: lines[i + 1] for i, line in enumerate(lines)
              if line.startswith("FINDING_KEY: " + key)}
    assert status[key + "0"] == ("STATUS: SEED  <<< SEED - the source was re-read and supports "
                                 "this block, not the whole record; unconfirmed: how[1]")
    assert status[key + "1"] == ("STATUS: SEED  <<< SEED - NOT CONFIRMED: the source was re-read "
                                 "and does not support this block")
    block = next(b for b in "\n".join(lines).split("=== FINDING ")[1:]
                 if "FINDING_KEY: " + key + "1" in b)
    support = next(l for l in block.splitlines() if l.startswith("SUPPORT:"))
    assert "verified=yes" in support and "[SEED]" in support
    assert not any(l.rstrip().endswith("(its notes say which)") for l in lines)


# The first twelve FINDING_KEYs at b17f576, before the seed support moved any STATUS line or
# confidence. Confidence feeds no ranking, so neither answer may move.
UNMOVED = {
    "Fortinet FortiGate": [
        "obs-fortinet-fortios-ssl-vpn-exploitation#how0",
        "obs-fortinet-ssl-vpn-implant-that-reinstates-itself-after-update#how1",
        "obs-fortinet-appliance-implant-persisting-in-the-boot-image#how1",
        "obs-fortinet-ssl-vpn-auth-bypass-with-two-factor-enabled#how1",
        "obs-fortinet-appliance-implant-persisting-in-the-boot-image#how2",
        "obs-fortinet-ssl-vpn-implant-that-reinstates-itself-after-update#how0",
        "obs-fortinet-ssl-vpn-auth-bypass-with-two-factor-enabled#how0",
        "obs-fortinet-fortios-ssl-vpn-exploitation#how1",
        "obs-fortinet-product-family-breadth-and-management-reach#how0",
        "obs-fortinet-product-family-breadth-and-management-reach#how1",
        "obs-fortinet-fortimanager-unregistered-device-config-theft#how1",
        "obs-fortinet-fortimanager-unregistered-device-config-theft#how0"],
    "Cisco ASA": [
        "obs-cisco-vpn-without-mfa-ransomware-entry#how1",
        "obs-cisco-vpn-without-mfa-ransomware-entry#how0",
        "obs-cisco-asa-vpn-webvpn-implant#how1",
        "obs-cisco-asa-vpn-webvpn-implant#how0",
        "obs-cisco-secure-firewall-management-center-static-credential-login#how1",
        "obs-cisco-secure-firewall-management-center-static-credential-login#how0",
        "obs-cisco-secure-firewall-management-center-static-credential-login#how2",
        "obs-paloaltonetworks-globalprotect-command-injection#how0",
        "obs-cisco-router-legacy-vulnerability-and-management-protocol-targeting#how2",
        "obs-cisco-ios-xe-router-pivot-and-container-evasion#how2",
        "obs-cisco-router-legacy-vulnerability-and-management-protocol-targeting#how1",
        "obs-cisco-ios-xe-router-pivot-and-container-evasion#how1"],
}


def test_seed_support_moves_no_ranking():
    for question, keys in UNMOVED.items():
        shown = [l[len("FINDING_KEY: "):] for l in consult(question).splitlines()
                 if l.startswith("FINDING_KEY: ")]
        assert shown == keys, question


def test_a_seed_record_read_for_one_block_never_says_its_source_was_not_re_read():
    """ArcaneDoor's post was fetched on 2026-10-02 and read for the record's title and how[1],
    whose confidence moved on that reading, and both blocks still printed "the source was not
    re-read". where.verified false records that the whole record was not re-read, and STATUS
    now says that; the read of one block is recorded in the record's notes."""
    lines = consult("Cisco ASA").splitlines()
    key = "obs-cisco-asa-vpn-webvpn-implant#how"
    status = {lines[i][len("FINDING_KEY: "):]: lines[i + 1] for i, line in enumerate(lines)
              if line.startswith("FINDING_KEY: " + key)}
    assert sorted(status) == [key + "0", key + "1"]
    for line in status.values():
        assert line == ("STATUS: SEED  <<< SEED - NOT CONFIRMED: written from general knowledge, "
                        "and not fully re-read against its source")
    # Every wording, not one phrase: the SUPPORT flag beneath said SOURCE_NOT_RE-READ, and a
    # test matching only "the source was not re-read" passed beside it.
    support = {lines[i][len("FINDING_KEY: "):]: next(
        l for l in lines[i:] if l.startswith("SUPPORT: ")) for i, line in enumerate(lines)
        if line.startswith("FINDING_KEY: " + key)}
    for line in support.values():
        assert line.endswith("[NO_READ_DATE SOURCE_NOT_FULLY_RE-READ SEED]"), line
    assert not NOT_RE_READ.search("\n".join(lines))
    record = next(r for r in records() if r["id"] == "obs-cisco-asa-vpn-webvpn-implant")
    assert record["where"]["verified"] is False and "retrieved" not in record["where"]
    assert "On 2026-10-02 the source was fetched and read for its title and how[1] only" \
        in record["notes"]


# "Not re-read", in any spelling, where the record was read for one block: not fully re-read is
# what where.verified false records.
NOT_RE_READ = re.compile(r"not (?:been )?re-read|NOT_RE-READ", re.I)


def test_every_definition_of_seed_says_not_fully_re_read():
    """The fix that reworded STATUS left SKILL.md's Reading the result, the schema's unconfirmed
    description and the SUPPORT flag saying the source had not been re-read at all."""
    skill = open(os.path.join(ROOT, "SKILL.md"), encoding="utf-8").read()
    for sentence in re.findall(r"Seed means[^.]*\.", " ".join(skill.split())):
        assert not NOT_RE_READ.search(sentence), sentence
    schema = json.load(open(os.path.join(ROOT, "corpus", "schema", "observation.schema.json"),
                            encoding="utf-8"))
    props = schema["properties"]
    texts = [props["status"]["description"],
             props["where"]["properties"]["verified"]["description"],
             props["how"]["items"]["properties"]["unconfirmed"]["description"]]
    for text in texts:
        assert not NOT_RE_READ.search(text), text
    flags = set()
    for record in records():
        for flag in C.support(record, TODAY).split("[")[-1].rstrip("]").split():
            flags.add(flag)
    assert "SOURCE_NOT_FULLY_RE-READ" in flags and not NOT_RE_READ.search(" ".join(flags))
