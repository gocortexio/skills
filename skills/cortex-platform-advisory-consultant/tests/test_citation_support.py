# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A record may carry only what the source it cites supports.

The schema holds one citation per record, and corroborations are defined as independent
accounts of the same thing. A synthesis of several posts therefore has no honest home, and
six watchTowr records were exactly that: one-shot batch scripts wrote one record per product
group from several posts and cited one. The Ivanti record cited a post about CVE-2025-22457
and carried six more identifiers, two further products and a second exploit chain. Its 2026
identifiers came from the KEV records next door, which is the fabrication-by-adjacency shape,
and the KEV generator then counted them as observation coverage, so the EPMM and Sentry
exposure records sent readers to X-Forwarded-For logic for unrelated flaws. Every one of
those records carried `status: verified` with no read date. A title restoration had since
corrected the titles and nothing else, because nothing compared what a record carries with
the page it cites.

These tests are the comparison that can be made without a network: an identifier is not
newer than its source, a single-source study does not observe past its own publication, a
verified record says when its source was read, and a public title is the publisher's own.

Run with PYTHONDONTWRITEBYTECODE=1 (LAW A26).
"""
import html
import json
import os
import re
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import consult as C  # noqa: E402
RECORDS = []
with open(os.path.join(ROOT, "corpus", "observations", "observations.jsonl"), encoding="utf-8") as h:
    for line in h:
        if line.strip():
            RECORDS.append(json.loads(line))
BY_ID = {r["id"]: r for r in RECORDS}
with open(os.path.join(ROOT, "corpus", "reference", "url-liveness.json"), encoding="utf-8") as h:
    LIVENESS = json.load(h)

# Regenerated from a catalogue every pass, so their titles and dates are the generator's.
GENERATED = ("exp-kev-", "exp-zdi-", "exp-nvd-", "exp-psirt-")
HANDWRITTEN = [r for r in RECORDS if not r["id"].startswith(GENERATED)]


def public(record):
    return (record.get("where") or {}).get("disclosure") == "public"


# ---------------------------------------------------------------- identifiers and dates

NEWER_IDENTIFIER_EXEMPT = {
    "obs-simplehelp-remote-support-ransomware-entry":
        "AA23-352A was revised on 2025-06-04 and the revision names CVE-2024-57727",
}


def test_a_record_carries_no_identifier_newer_than_its_source():
    """A CVE year after the source's publication year cannot have come from that source.

    Before 0.43.0 this failed on the Ivanti, Citrix, security monitoring and Juniper
    syntheses, each carrying 2026 identifiers on a 2023 to 2025 post, and on the F5 record,
    which carried a 2023 identifier from a second, uncited ransomware advisory.
    """
    bad = []
    for record in HANDWRITTEN:
        if record["id"] in NEWER_IDENTIFIER_EXEMPT:
            continue
        published = ((record.get("when") or {}).get("published") or "")[:4]
        if not published.isdigit():
            continue
        late = [c for c in (record.get("what") or {}).get("vulnerabilities") or []
                if c.startswith("CVE-") and int(c[4:8]) > int(published)]
        if late:
            bad.append("{} is published {} and carries {}".format(record["id"], published, late))
    assert not bad, "\n".join(bad)
    assert all(rid in BY_ID for rid in NEWER_IDENTIFIER_EXEMPT), "an exemption names a missing record"


RESEARCH = ("independent_research", "vendor_research", "academic_research")
OBSERVED_PAST_PUBLICATION_EXEMPT = {
    "obs-microsoft-entra-id-administrative-units-conceal-and-protect-privilege":
        "the publisher revised the permissions detail in February 2025, as the record's notes say",
}


def test_single_source_research_does_not_observe_past_its_own_publication():
    """One study cannot report what happened after it was published.

    This is the discriminator that caught all six watchTowr syntheses, whose observed_end
    was the crawl date of the publisher's index rather than anything the cited post said,
    including the two whose late identifiers shared the post's own year. It also caught a
    2023 tunnel-abuse post observed to 2026.
    """
    bad = []
    for record in HANDWRITTEN:
        where = record.get("where") or {}
        if where.get("source_type") not in RESEARCH or where.get("corroborations"):
            continue
        if record["id"] in OBSERVED_PAST_PUBLICATION_EXEMPT:
            continue
        when = record.get("when") or {}
        end, published = (when.get("observed_end") or "")[:7], (when.get("published") or "")[:7]
        if end and published and end > published:
            bad.append("{} observes to {} on a source published {}".format(record["id"], end, published))
    assert not bad, "\n".join(bad)


# The identifiers each watchTowr post names, read from the posts on 2026-09-25. A record may
# carry fewer; it may not carry one its post does not name.
WATCHTOWR_POSTS = {
    "obs-ivanti-connect-secure-recurring-preauth-memory-corruption": {"CVE-2025-22457"},
    "obs-citrix-netscaler-recurring-memory-disclosure-from-auth-endpoint":
        {"CVE-2023-4966", "CVE-2025-5777", "CVE-2025-6543"},
    "obs-fortinet-product-family-breadth-and-management-reach": {"CVE-2024-55591"},
    "obs-generic-managed-file-transfer-class-recurrence-across-vendors": {"CVE-2025-10035", "CVE-2023-0669"},
    "obs-generic-security-monitoring-platform-as-the-objective": {"CVE-2022-26377", "CVE-2023-46747"},
    "obs-juniper-scheduled-release-cycle-and-web-management-exposure":
        {"CVE-2023-36844", "CVE-2023-36845", "CVE-2023-36846"},
}


@pytest.mark.parametrize("rid", sorted(WATCHTOWR_POSTS))
def test_a_watchtowr_record_carries_only_identifiers_its_post_names(rid):
    carried = set((BY_ID[rid].get("what") or {}).get("vulnerabilities") or [])
    assert carried <= WATCHTOWR_POSTS[rid], "{} carries {} its post does not name".format(
        rid, sorted(carried - WATCHTOWR_POSTS[rid]))


def test_the_x_forwarded_for_record_carries_only_its_post():
    """TODO item 7. The post names one identifier and three products."""
    record = BY_ID["obs-ivanti-connect-secure-recurring-preauth-memory-corruption"]
    assert record["what"]["vulnerabilities"] == ["CVE-2025-22457"]
    assert record["who"]["products"] == ["Connect Secure", "Policy Secure", "ZTA Gateway"]
    assert "app.rmm" not in record["who"]["product_class"]
    assert [h.get("pattern_id") for h in record["how"]] == ["pat-appliance-crash-following-pre-auth-request"]


def test_the_chain_block_moved_to_the_record_whose_sources_carry_the_pair():
    """The CVE-2023-46805 / CVE-2024-21887 chain block now sits on the record that cites
    AA25-239A and AA24-060B, both of which name the pair, so the pattern keeps its three
    citing records. That record's first block already described the same chain, requests
    reaching an authenticated endpoint with no authentication, under the post-disclosure
    scanning pattern, so an Ivanti answer printed one detection twice under two patterns.
    The duplicate is gone and its logging caveat joined the chain block."""
    record = BY_ID["obs-ivanti-connect-secure-chained-exploitation"]
    assert {"CVE-2023-46805", "CVE-2024-21887"} <= set(record["what"]["vulnerabilities"])
    cited = [h.get("pattern_id") for h in record["how"]]
    assert cited.count("pat-chained-vulnerability-exploit-path") == 1
    assert "pat-vpn-appliance-post-disclosure-scanning" not in cited
    citing = {r["id"] for r in RECORDS for h in r.get("how") or []
              if h.get("pattern_id") == "pat-chained-vulnerability-exploit-path"}
    assert len(citing) == 3, sorted(citing)


@pytest.mark.parametrize("rid", [
    "obs-fortinet-product-family-breadth-and-management-reach",
    "obs-juniper-scheduled-release-cycle-and-web-management-exposure",
    "obs-generic-incident-response-trend-base-rates-2022-2026",
])
def test_a_thesis_the_cited_post_does_not_make_is_held_as_seed(rid):
    """Cut to its post, each of these would argue nothing its title does not; their theses
    came from several posts under one citation. Seed is the schema's word for unconfirmed,
    and consult.py prints it. The Talos record argues a series of eighteen quarterly reports
    and cites the last of them."""
    assert BY_ID[rid]["status"] == "seed"
    assert BY_ID[rid].get("notes", "").startswith("Seed."), "a seed record says which half its source supports"


# Every percentage the cited Talos post states, read from it on 2026-09-25.
TALOS_Q2_PERCENTAGES = {"14", "15", "17", "18", "20", "25", "31", "35", "42", "65"}
NUMBER_WORD = (r"(?:one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|"
               r"fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|"
               r"sixty|seventy|eighty|ninety|hundred)(?:-\w+)?")


def test_the_base_rate_record_states_only_figures_its_report_gives():
    """The record summarised eighteen quarters and cited one report. Its logging range,
    'eighteen to forty-two percent of engagements, every year', had as its two ends that
    report's 42 percent against 18 percent the quarter before. A percentage in its prose is
    now one the cited report states, and none is spelled out, which is how the series
    figures were written."""
    record = BY_ID["obs-generic-incident-response-trend-base-rates-2022-2026"]
    prose = " ".join([record["what"]["summary"]] + [
        "{} {}".format(h.get("logic", ""), h.get("caveat", "")) for h in record["how"]])
    stated = set(re.findall(r"\b(\d+) percent", prose))
    assert stated <= TALOS_Q2_PERCENTAGES, sorted(stated - TALOS_Q2_PERCENTAGES)
    assert not re.search(r"(?i)\b" + NUMBER_WORD + r"(?: to " + NUMBER_WORD + r")? percent", prose)
    when = record["when"]
    assert "2026-04" <= when["observed_start"][:7] and when["observed_end"][:7] <= "2026-06"


def test_a_second_advisory_about_another_incident_is_its_own_record():
    """C13. The J-Web record cited AA24-317A, the 2023 routinely exploited list, and carried
    AA22-158A as a corroboration. AA22-158A is a 2022 campaign that harvested router
    configurations with stolen credentials, not a second account of the list, and the
    record's harvesting and configuration detections, its state attribution, its
    telecommunications sector and its 2020 start all came from it."""
    assert "obs-juniper-junos-jweb-and-config-exfiltration" not in BY_ID
    jweb = BY_ID["obs-juniper-junos-jweb-routinely-exploited-web-management"]
    router = BY_ID["obs-juniper-router-config-harvested-with-stolen-radius-credentials"]
    assert jweb["where"]["url"].endswith("/aa24-317a") and not jweb["where"].get("corroborations")
    assert router["where"]["url"].endswith("/aa22-158a")
    assert set(jweb["what"]["impact"]) == {"rce", "auth_bypass"}
    assert jweb["who2"]["attribution_confidence"] == "none", "AA24-317A attributes nothing"
    assert jweb["when"]["observed_start"] >= "2023"
    assert [h["pattern_id"] for h in router["how"]] == [
        "pat-scripted-device-config-harvesting", "pat-network-device-config-or-route-change"]
    assert router["what"]["vulnerabilities"] == [], "AA22-158A names no Juniper identifier"


def test_the_monitoring_platform_record_claims_only_what_its_post_shows():
    """The QRadar post shows credentials read from ingested logs, tampering with incident
    records and watching the defenders. Lateral movement and supply chain rested on a claim
    about integration secrets the post never makes, cut with it."""
    record = BY_ID["obs-generic-security-monitoring-platform-as-the-objective"]
    assert set(record["what"]["impact"]) == {"credential_theft", "defence_evasion", "reconnaissance"}


def test_the_file_transfer_record_claims_only_what_its_post_shows():
    """The GoAnywhere post shows an authentication bypass to a deserialisation sink the vendor
    rated as command injection. It says nothing of data taken or of a supply chain; both came
    with the five-vendor class argument, which was cut."""
    record = BY_ID["obs-generic-managed-file-transfer-class-recurrence-across-vendors"]
    assert set(record["what"]["impact"]) == {"rce", "auth_bypass"}


def test_the_seed_fortinet_record_names_the_impact_its_thesis_carries():
    """The FortiOS post supports the bypass and the super_admin session it yields. Lateral
    movement is the family thesis, reaching the managed devices from the manager, so the
    notes name it with the thesis; configuration theft came only from the FortiManager
    identifier that was cut, and is cut with it."""
    record = BY_ID["obs-fortinet-product-family-breadth-and-management-reach"]
    assert set(record["what"]["impact"]) == {"rce", "auth_bypass", "privilege_escalation", "lateral_movement"}
    assert "lateral_movement" in record["notes"]


def test_a_state_nexus_record_names_an_actor_no_other_record_calls_criminal():
    """C13. The F5 record cites AA21-200B, an overview of Chinese state-sponsored activity,
    and carried RansomHub, the operator from a later ransomware advisory it does not cite,
    as its only actor with a state nexus and high confidence. The corpus types RansomHub as a
    ransomware affiliate everywhere else, which is the discriminator: a record whose every
    actor another record calls criminal has taken its actors from somewhere else."""
    types = {}
    for record in RECORDS:
        who2 = record.get("who2") or {}
        for actor in who2.get("actors") or []:
            types.setdefault(actor.lower(), set()).add(who2.get("actor_type"))
    bad = []
    for record in RECORDS:
        who2 = record.get("who2") or {}
        actors = who2.get("actors") or []
        if who2.get("actor_type") == "state_nexus" and actors \
                and all(types[a.lower()] - {"state_nexus"} for a in actors):
            bad.append("{} is state_nexus and names only {}".format(record["id"], actors))
    assert not bad, "\n".join(bad)


# AA21-200B, read 2026-09-25: "political, economic, military, educational, and critical
# infrastructure" targets, then "managed service providers, semiconductor companies, the
# Defense Industrial Base (DIB), universities, and medical institutions".
AA21_200B_SECTORS = {"government", "defence", "education", "healthcare", "manufacturing", "cross_sector"}


def test_the_f5_record_carries_only_its_advisory():
    """C13. Its CVE-2023-46747 and the ransomware clause were cut first; the operator's name
    stayed in who2 and printed beside 'Chinese state-sponsored actors' in the summary. The
    advisory names no group. Its healthcare and manufacturing sectors are the advisory's own
    medical institutions and semiconductor companies, and are kept."""
    record = BY_ID["obs-f5-big-ip-management-interface-exploitation"]
    who2 = record["who2"]
    assert who2["actors"] == ["Chinese state-sponsored cyber actors"]
    assert (who2["actor_type"], who2["attribution_confidence"]) == ("state_nexus", "high")
    assert set(who2["target_sectors"]) <= AA21_200B_SECTORS
    assert record["what"]["vulnerabilities"] == ["CVE-2020-5902"]
    assert "config_exfiltration" not in record["what"]["impact"], "the advisory never says it"
    assert record["when"]["observed_end"][:7] <= "2021-07"


# The red team advisories, read 2026-09-25. AA23-059A assessed a critical infrastructure
# organisation in 2022; AA24-326A a critical infrastructure organisation, undated; AA24-193A a
# federal civilian executive branch organisation from early 2023.
RED_TEAM = {
    "obs-generic-legacy-host-without-endpoint-agent": ({"cross_sector"}, None),
    "obs-generic-dmz-to-internal-reachability": ({"cross_sector", "government"}, "2023"),
    "obs-microsoft-active-directory-forged-ticket-and-delegation-abuse": ({"cross_sector"}, "2022"),
    "obs-generic-partner-trust-and-transitive-credentials": ({"government"}, "2023"),
    "obs-generic-unrestricted-outbound-to-cloud-ranges": ({"government"}, "2023"),
}


@pytest.mark.parametrize("rid", sorted(RED_TEAM))
def test_a_red_team_record_carries_its_own_assessment_sectors_and_year(rid):
    """The red team records were written from three advisories at once, and kept the union
    of their sectors and the earliest year after the titles were restored. A sector is now
    one an advisory the record cites assessed, and the start is a year one of them gives:
    the legacy-host record cites AA24-326A alone, which dates nothing but its release, so it
    has no observed range. The DMZ record's government sector is its corroboration's, the
    same first finding in the federal assessment."""
    sectors, start = RED_TEAM[rid]
    record = BY_ID[rid]
    assert set(record["who2"]["target_sectors"]) == sectors
    assert record["when"].get("observed_start") == start


def test_the_router_campaign_record_carries_only_the_campaign_sector():
    """AA22-158A's router campaign ran against telecommunications companies and network
    service providers. Government appears there as an audience, and public and private
    sector organisations as targets of the wider exploitation its identifier list covers,
    which this record does not carry."""
    record = BY_ID["obs-juniper-router-config-harvested-with-stolen-radius-credentials"]
    assert record["who2"]["target_sectors"] == ["communications"]


# ---------------------------------------------------------------- read dates

READ_OWED = {
    "obs-generic-edge-appliance-exploitable-surface-recurrence":
        "cites the publisher's index; its counts come from the 2026-07-02 sitemap capture, and the "
        "vendor-naming count is a judgement that has not been re-derived",
    "obs-generic-mobile-network-observed-techniques-from-fight":
        "the technique counts need the knowledge base's data release, which has not been re-read",
    "obs-generic-ai-platform-incidents-from-atlas":
        "the technique and case-study counts need the knowledge base's data release, which has not "
        "been re-read",
}


def test_a_verified_record_records_when_its_source_was_read():
    """The schema defines verified as a human or a fetch confirming the source says this, so
    a verified record with no read date is a claim nobody can date. Applied to independent
    research first, where every synthesis sat; the other families follow as they are re-read.
    """
    bad = []
    for record in HANDWRITTEN:
        where = record.get("where") or {}
        if record.get("status") != "verified" or not public(record) \
                or where.get("source_type") != "independent_research":
            continue
        if record["id"] in READ_OWED:
            if where.get("retrieved"):
                bad.append("{} now has a read date; drop it from READ_OWED".format(record["id"]))
        elif not where.get("retrieved") or where.get("verified") is not True:
            bad.append("{} is verified with no read date".format(record["id"]))
    assert not bad, "\n".join(bad)


# ---------------------------------------------------------------- titles

# The shapes a paraphrase or a synthesis took. Descriptive phrases are case-insensitive;
# "<Publisher> on <topic>" is matched only against a lower-case topic, so a real title such
# as "Ransomware Attacks on Critical Infrastructure" does not trip it.
DESCRIPTIVE = re.compile(
    r"(?i:\b(research (on|across|into)|commentary on|analysis of|disclosure of|investigation into|"
    r"measurement of|evaluation of|combined from|parts \d+ to \d+|quarterly trend reporting|"
    r"\d+ posts spanning)\b)|^\S+( \S+){0,3} on [a-z]|^(?i:joint advisory) \S+ on ")
REAL_TITLES = {
    "AppleJeus: Analysis of North Korea's Cryptocurrency Malware": "CISA's own title for AA21-048A",
    "Rust Supply Chain Attack on arrayref: Significant Overlap with DPRK Campaigns": "Wiz's own title",
}


def test_no_public_citation_carries_a_descriptive_title():
    """A public source has a title of its own. The 2026-09-13 restoration matched three
    phrasings and missed the rest, so 22 records still cited a description: 'research
    across', 'investigation into', 'combined from three published assessments', '<Publisher>
    on <topic>'. Restricted sources are different: their abstract title is required.

    Generated records are read too since 0.43.0, so a generator is held to the same phrases.
    The ZDI generator's "Coordinated disclosure advisories for <product>", written over one
    advisory of up to forty, matched none of them; it now cites the listing by its own
    title, which tests/test_generated_claims.py pins."""
    bad = ["{}: {!r}".format(r["id"], r["where"]["title"]) for r in RECORDS
           if public(r) and r["where"]["title"] not in REAL_TITLES
           and DESCRIPTIVE.search(r["where"]["title"])]
    assert not bad, "cites a description, not a title:\n" + "\n".join(bad)


def _norm(title):
    t = html.unescape(title)
    for a, b in (("\u2018", "'"), ("\u2019", "'"), ("\u201c", '"'), ("\u201d", '"'),
                 ("\u2013", "-"), ("\u2014", "-"), ("\u2122", ""), ("\u00a0", " ")):
        t = t.replace(a, b)
    t = re.sub(r"^\[\d{4}\.\d{4,5}\]\s*", "", t)  # arXiv prefixes its <title> with the id
    t = re.sub(r"\bU\.S\.", "US", t)
    return re.sub(r"\s+", " ", t).strip().lower()


# The page's <title> is not what the record should cite. Four are SEO titles over a headline
# the record cites; two are knowledge bases whose landing page carries the brand alone.
TITLE_DIVERGES = {
    "obs-generic-untrusted-fork-code-runs-with-repository-token": "Wiz: SEO <title>, headline in h1",
    "obs-amazon-codebuild-webhook-actor-filter-matched-on-substring": "Wiz: SEO <title>, headline in h1",
    "obs-sangoma-switchvox-pa-sql-injection-exploited": "Horizon3: SEO <title>, headline in h1",
    "obs-simplehelp-federated-login-minting-privileged-technician": "Horizon3: SEO <title>, headline in h1",
    "obs-generic-mobile-network-observed-techniques-from-fight": "knowledge base, cited by what it is",
    "obs-generic-ai-platform-incidents-from-atlas": "knowledge base, cited by what it is",
}
# What the cache holds for a page that answered with an error rather than itself.
NOT_A_PAGE_TITLE = {"403 Forbidden", "Temporary outage - We're on it!"}


def test_a_public_title_matches_the_cached_page_title():
    """The liveness cache records each page's own <title>. The record's title must be that
    title, allowing only for a trailing ' | Site' or ' - Site'."""
    bad = []
    for record in HANDWRITTEN:
        where = record.get("where") or {}
        page = (LIVENESS.get(where.get("url")) or {}).get("title")
        if not public(record) or not page:
            continue
        if record["id"] in TITLE_DIVERGES or page in NOT_A_PAGE_TITLE:
            continue
        ours, theirs = _norm(where["title"]), _norm(page)
        if theirs != ours and not re.match(re.escape(ours) + r" [|-] [^|]+( \| [^|]+)?$", theirs):
            bad.append("{} cites {!r}; the page is titled {!r}".format(record["id"], where["title"], page))
    assert not bad, "\n".join(bad)
    assert all(rid in BY_ID for rid in TITLE_DIVERGES), "an allowance names a missing record"


# ---------------------------------------------------------------- response doctrine

with open(os.path.join(ROOT, "corpus", "reference", "response-doctrine.json"), encoding="utf-8") as h:
    DOCTRINE = json.load(h)["doctrine"]


def _advisory(url):
    return url.rstrip("/").rsplit("/", 1)[-1]


def _supports(source):
    """A source's supporting words: one passage, or a list of passages from the same page."""
    words = source.get("supports") or []
    return [words] if isinstance(words, str) else list(words)


# Each rule's sources, read on 2026-09-30. The appliance-rebuild rule cited AA25-239A, an
# espionage advisory with no word of a factory reset, a rebuild or a reimage in it; the reset
# survival is AA24-060B's lab finding, and AA25-022A's victims replaced their appliances. The
# simultaneity half of the containment rule is AA25-239A's and had been cited to AA22-264A,
# which carries only the Albania escalation. The backup rule's offline backup is AA22-040A's.
DOCTRINE_SOURCES_READ = {
    "doc-collect-before-mitigate": {"aa20-245a"},
    "doc-out-of-band-coordination": {"aa20-245a"},
    "doc-containment-assumes-adversary-watching": {"aa22-264a", "aa25-239a"},
    "doc-verify-offline-backup-before-containment": {"aa22-264a", "aa22-040a"},
    "doc-communications-plan-for-attacker-publication": {"aa22-264a"},
    "doc-communications-plan-for-direct-third-party-contact": {"aa22-152a"},
    "doc-remediation-scope-all-exposed-access": {"aa22-040a"},
    "doc-appliance-rebuild-not-factory-reset": {"aa24-060b", "aa25-022a"},
    "doc-check-published-recovery-tooling": {"aa23-039a"},
    "doc-emergency-plan-names-degraded-states": {"aa20-049a"},
    "doc-investigation-capability-portfolio": {"aa20-245a"},
    "doc-retention-must-outlast-dwell-time": {"aa20-245a"},
}

# A specific claim a rule makes, and the words a source must use for the rule to cite it for
# that claim. Read over the rule and its detail; the source's `supports` must carry the second.
DOCTRINE_CLAIMS = (
    (r"(?i)factory reset", r"(?i)factory reset"),
    (r"(?i)simultaneous", r"(?i)simultaneous"),
    (r"(?i)\boffline\b", r"(?i)\boffline\b"),
    (r"(?i)out of band|out-of-band", r"(?i)out-of-band"),
    (r"(?i)claims? credit", r"(?i)claimed credit"),
    (r"(?i)a year ago|one year", r"(?i)one year"),
    (r"(?i)harass", r"(?i)harassment|harassing"),
    (r"(?i)within a week", r"(?i)within a week"),
    (r"(?i)disk wiping", r"(?i)destructive malware|wip(er|ing)"),
    (r"(?i)recovery (tooling|guidance and scripts)", r"(?i)recovery script|does not encrypt"),
)


def test_a_doctrine_source_carries_the_words_it_is_cited_for():
    """A rule is a summary; the source it cites must say the thing summarised. Nothing held a
    rule to its advisory, so the appliance-rebuild rule, printed on every network finding,
    cited an advisory that says nothing about resets. Each source now carries `supports`, the
    advisory's own words for the claim, read on 2026-09-30, and a rule naming one of the
    specific claims above cites a source whose words carry it."""
    bad = []
    for did, entry in sorted(DOCTRINE.items()):
        sources = entry.get("sources") or []
        if not sources:
            bad.append("{} cites nothing".format(did))
        for source in sources:
            words = _supports(source)
            if not words or any(len(w) < 20 or not w.isascii() for w in words):
                bad.append("{} cites {} with no ASCII `supports`".format(did, _advisory(source["url"])))
        prose = "{} {}".format(entry.get("rule", ""), entry.get("detail", ""))
        for claim, needed in DOCTRINE_CLAIMS:
            if re.search(claim, prose) and not any(re.search(needed, w)
                                                   for s in sources for w in _supports(s)):
                bad.append("{} claims {!r} and no source it cites says it".format(did, claim))
    assert not bad, "\n".join(bad)


def test_a_doctrine_rule_cites_the_advisories_read_for_it():
    cited = {did: {_advisory(s["url"]) for s in entry.get("sources") or []}
             for did, entry in DOCTRINE.items()}
    assert cited == DOCTRINE_SOURCES_READ
    rebuild = DOCTRINE["doc-appliance-rebuild-not-factory-reset"]
    assert "aa25-239a" not in {_advisory(s["url"]) for s in rebuild["sources"]}


def test_a_doctrine_source_carries_its_publisher_title():
    """The rebuild rule cited AA25-239A by a title with 'Worldwide' dropped, while the records
    citing the same page had it right. A doctrine title is now the page's own where the liveness
    cache holds it, and the title every record citing the same page carries."""
    record_titles = {}
    for record in RECORDS:
        where = record.get("where") or {}
        if where.get("url") and where.get("title"):
            record_titles.setdefault(where["url"], set()).add(where["title"])
    bad = []
    for did, entry in sorted(DOCTRINE.items()):
        for source in entry.get("sources") or []:
            url, title = source["url"], source["title"]
            page = (LIVENESS.get(url) or {}).get("title")
            if page and not re.match(re.escape(_norm(title)) + r"( [|-] [^|]+)?$", _norm(page)):
                bad.append("{}: {!r}, the page is titled {!r}".format(did, title, page))
            if record_titles.get(url) and title not in record_titles[url]:
                bad.append("{}: {!r}, the records citing it say {}".format(
                    did, title, sorted(record_titles[url])))
    assert not bad, "\n".join(bad)


# ---------------------------------------------------------------- records read 2026-09-30

def test_the_cloud_service_appliance_record_carries_only_its_advisory():
    """AA25-022A names four Cloud Service Appliance identifiers as exploited, says outright that
    CVE-2025-0282 and CVE-2025-0283 in Connect Secure are unrelated to it, and mentions
    CVE-2024-9381 only in the title of a vendor advisory it links. The record carried all
    three, Connect Secure as a product and the VPN concentrator class first, so a Connect
    Secure catalogue record named it as holding detection for its flaw."""
    record = BY_ID["obs-ivanti-cloud-service-appliance-chained-exploitation"]
    four = {"CVE-2024-8963", "CVE-2024-9379", "CVE-2024-8190", "CVE-2024-9380"}
    assert set(record["what"]["vulnerabilities"]) == four
    assert record["who"]["products"] == ["Cloud Service Appliance"]
    assert "network.vpn_gateway" not in record["who"]["product_class"]
    assert "Connect Secure" not in json.dumps(record["who"])
    for how in record["how"]:
        for item in (how.get("markers") or []) + (how.get("fields") or []):
            values = item.get("value") if isinstance(item.get("value"), list) else [item.get("value")]
            assert not {v for v in values if str(v).startswith("CVE-")} - four, item
    assert "government" not in record["who2"]["target_sectors"], "the advisory names no sector"
    assert "obs-ivanti-cloud-service-appliance-chained-exploitation" not in \
        BY_ID["exp-kev-ivanti-connect-secure-policy-secure-and-zta-gateways"]["what"]["summary"]


# AA23-213A names the API path three times, NCSC-NO's hunt among them, and its template probes
# a second route under the same prefix. These are product API paths, not indicators.
EPMM_PATHS_NAMED = ("/mifs/aad/api/v2/authorized/users?adminDeviceSpaceId=1", "/mifs/aad/api/v2/ping")


def test_the_epmm_record_matches_the_path_its_advisory_names_and_invents_none():
    """The marker read (?i)/mifs/(aa|rs)/api/v2/: a segment one letter short of the advisory's,
    joined to a route from a 2025 report on a different chain, so it matched neither path the
    advisory names. Its file-path literals came from that 2025 report and a path no source
    carries; the advisory says only that the second flaw writes files with the web application
    server's privileges, which is now the condition."""
    record = BY_ID["obs-ivanti-epmm-authentication-bypass-and-arbitrary-file-write-chain"]
    urls = [m for h in record["how"] for m in h.get("markers") or [] if m["type"] == "url_path"]
    assert len(urls) == 1
    for path in EPMM_PATHS_NAMED:
        assert re.search(urls[0]["value"], path), path
    assert not re.search(urls[0]["value"], "/mifs/rs/api/v2/featureusage")
    assert not [m for h in record["how"] for m in h.get("markers") or []
                if m["type"] in ("file_path", "process_path")]
    writes = [m for m in record["how"][1]["markers"] if m["type"] == "computed"]
    assert writes and "web application server" in writes[0]["expr"]


# Microsoft 365 audit operations and licensing, none of which AA26-204A mentions.
NOT_IN_AA26_204A = ("MailItemsAccessed", "New-InboxRule", "Set-Mailbox", "MailboxExport",
                    "licensing tier", "Microsoft 365")


def test_the_session_token_record_carries_nothing_its_zimbra_advisory_lacks():
    """AA26-204A is about a Zimbra webmail campaign and recounts the group's earlier cloud-mail
    campaigns. The record printed Microsoft 365 audit operations as source-specific markers and
    a Microsoft licensing caveat under that citation, and the Zimbra identifier, which its own
    notes contradicted by calling the access exploit-free. Its only typed session marker,
    now() - session_start > 0, was true of every session."""
    record = BY_ID["obs-generic-session-token-theft-bypassing-authentication"]
    text = json.dumps(record)
    assert not [w for w in NOT_IN_AA26_204A if w in text]
    assert record["what"]["vulnerabilities"] == []
    assert "obs-generic-session-token-theft-bypassing-authentication" not in \
        BY_ID["exp-kev-synacor-zimbra-collaboration-suite-zcs"]["what"]["summary"]
    session = record["how"][0]["markers"]
    assert session and all(m.get("expr") != "now() - session_start" for m in session)
    assert "count_distinct" in session[0]["expr"] and session[0]["value"] >= 1
    # The same always-true test survived as a legacy field, printed as `session_age_hours gt 0`.
    assert not [f for f in record["how"][0].get("fields") or []
                if f.get("op") == "gt" and f.get("value") == 0]


def test_the_session_token_mailbox_block_prints_no_operation_its_advisory_lacks():
    """Cut from the record, the operations still printed: a block with no markers of its own
    prints its pattern's, so a consultation listed the five Microsoft 365 operations as MARKERS
    and the emitter as the live filter, under the Zimbra advisory's citation and beside a caveat
    saying the advisory names no operation. The block carries the signal that caveat names, the
    account's volume against its own history, as its own condition."""
    record = BY_ID["obs-generic-session-token-theft-bypassing-authentication"]
    how = record["how"][1]
    assert how["pattern_id"] == "pat-mailbox-bulk-access-and-forwarding"
    markers, _ = C.markers_of(how, {"markers": [{"type": "cloud_operation", "match": "in",
                                                 "value": ["MailItemsAccessed"]}]})
    assert markers == how.get("markers"), "the block falls back to its pattern's markers"
    assert [m["type"] for m in markers] == ["computed"] and "baseline" in markers[0]["expr"]
    # A volume per window against a baseline is counted, as every other such block's is.
    assert how["rule_shape"] == "threshold"
    assert "worth alerting on individually" not in how["logic"]
    done = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "emit_xql.py"),
                           record["id"] + "#how1"], capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    assert not [w for w in NOT_IN_AA26_204A + ("Add-MailboxPermission", "New-TransportRule")
                if w in done.stdout], done.stdout
    assert "filter=none" in done.stdout and "// REQUIRES" in done.stdout, done.stdout


def test_the_integrity_block_says_whose_paths_its_advisory_gives():
    """AA20-259A, read again on 2026-10-01, gives the three web shell and tunnel paths the
    integrity block matches for the NetScaler flaw alone, and none for Pulse Secure or F5. The
    block's caveat said the paths were "specific to two products", which invited reading the
    block as the Pulse appliance's on an Ivanti question."""
    how = BY_ID["obs-generic-remote-access-appliance-compromise-for-access-resale"]["how"][0]
    assert how["pattern_id"] == "pat-edge-appliance-integrity-mismatch"
    assert "two products" not in how["caveat"]
    assert "only for the 2019 NetScaler flaw" in how["caveat"]
    assert not re.search(r"(?i)pulse|f5|big-ip", how["logic"] + " " + how["caveat"])


# ---------------------------------------------------------------- identifiers against the page
#
# corpus/reference/advisory-identifiers.json holds the identifiers each CISA advisory and analysis
# report page names, read from a maintainer-side copy of the page's text. A record whose every
# cited source is listed there may carry only identifiers one of them names.

import copy  # noqa: E402

import validate as V  # noqa: E402

with open(os.path.join(ROOT, "corpus", "reference", "advisory-identifiers.json"),
          encoding="utf-8") as h:
    ADVISORIES = json.load(h)["advisories"]
AA22_011A = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-011a"
AA22_321A = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-321a"


def check(records):
    problems = []
    counts = V.check_cited_advisory_identifiers([(r["id"], r) for r in records], ADVISORIES,
                                                problems)
    return counts, [str(p) for p in problems]


def test_a_record_citing_only_held_advisories_carries_only_identifiers_they_name():
    """Before this check the corpus held two records carrying an identifier the one advisory
    they cite never names: the FortiOS username-case MFA exposure, CVE-2020-12812 on AA22-011A,
    and the PaperCut exposure, CVE-2023-27351 on AA23-131A. Both said `verified` with a read
    date."""
    (checked, partial, unheld), problems = check(RECORDS)
    assert checked >= 170, "the check reaches fewer records than it did when written"
    assert not problems, "\n".join(problems)


def test_the_identifier_check_refuses_what_its_advisory_never_names():
    """The MFA exposure as it stood, on AA22-011A, is refused by name. A corroborating advisory
    that names the identifier clears it; a corroboration held nowhere leaves the record
    undecided rather than passed or failed; a note naming an identifier is prose."""
    record = copy.deepcopy(BY_ID["exp-fortinet-fortios-mfa-bypass-username-case"])
    record["where"]["url"] = AA22_011A
    record["notes"] = "Carries nothing: CVE-1999-0001 is named in prose only."
    _, problems = check([record])
    assert len(problems) == 1 and "carries CVE-2020-12812" in problems[0], problems
    record["where"]["corroborations"] = [{"publisher": "FBI, CISA and HHS", "url": AA22_321A}]
    (checked, _, _), problems = check([record])
    assert checked == 1 and not problems, problems
    record["where"]["corroborations"] = [{"publisher": "Example", "url": "https://example.org/"}]
    (checked, partial, _), problems = check([record])
    assert (checked, partial) == (0, 1) and not problems, problems


def test_the_mfa_bypass_exposure_cites_the_advisory_that_names_its_flaw():
    """AA22-011A lists seventeen identifiers and not CVE-2020-12812, and names neither
    ransomware nor a second-factor bypass; the record also called its actor state-nexus beside a
    summary saying ransomware actors. AA22-321A describes the username-case bypass in those
    words and ties it to Hive affiliates."""
    record = BY_ID["exp-fortinet-fortios-mfa-bypass-username-case"]
    assert "CVE-2020-12812" not in ADVISORIES[AA22_011A]["identifiers"]
    assert record["where"]["url"] == AA22_321A
    assert "CVE-2020-12812" in ADVISORIES[AA22_321A]["identifiers"]
    assert record["where"]["title"] == "#StopRansomware: Hive Ransomware"
    assert record["who2"]["actor_type"] == "ransomware_affiliate"
    assert record["who2"]["actors"] == ["Hive"]
    assert record["when"]["published"] == "2022-11-17"


def test_the_papercut_exposure_carries_only_what_its_advisory_reports():
    """AA23-131A names CVE-2023-27350 alone and reports the Bl00dy Ransomware Gang exploiting
    it; the record also carried CVE-2023-27351, a state-sponsored group and credential theft."""
    record = BY_ID["exp-papercut-mf-ng-improper-access-control"]
    assert record["what"]["vulnerabilities"] == ["CVE-2023-27350"]
    assert "state-sponsored" not in record["what"]["summary"]
    assert "credential_theft" not in record["what"]["impact"]


def test_validate_says_how_many_records_it_held_to_their_pages():
    done = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "validate.py")],
                          capture_output=True, text=True, timeout=300, cwd=ROOT)
    line = [l for l in done.stdout.splitlines() if l.startswith("cited advisory identifiers:")]
    assert line and re.search(r": \d+ record\(s\) cite only CISA pages held", line[0]), line
