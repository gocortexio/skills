# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""`any` and `Multiple` are not vendors, and no alias may name them as one.

corpus/README.md defines `who.vendor: any` as a record that covers a class of product rather
than somebody's product, and `Multiple` as a catalogue entry spanning several vendors. Two
vendor aliases pointed at `any`: "we are an MSP" resolved `vendors=any` and consult.py called
the answer `RESOLUTION: product`, with 389 findings all claiming to name the technology, and
"impacket secretsdump against a DC" did the same from a tool name alone. Two product aliases
were generic in the same way: "package manager" named the npm registry, and "cargo", the
Rust build tool, named a single crate.

This file holds both halves. The data half: those four aliases are gone and no vendor alias
names a sentinel. The resolver half: twenty product aliases still name `any` or `Multiple`
as their vendor (git, npm, yarn, pypi, suricata, github actions and others), and each one put
the sentinel into RESOLVED_TO, so the 131 `any` records scored as vendor matches and "npm supply
chain" returned 512 findings under `RESOLUTION: product`. A sentinel is now never a resolved
vendor, never a record's vendor match and never a corroborator.

Run with PYTHONDONTWRITEBYTECODE=1 (LAW A26).
"""
import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import query as Q  # noqa: E402

RAW = json.load(open(os.path.join(ROOT, "corpus", "schema", "aliases.json"), encoding="utf-8"))
ALIASES = Q.normalise_alias_keys(RAW)
SENTINELS = {"any", "Multiple"}
RECORDS, PATTERNS = Q.load_corpus(os.path.join(ROOT, "corpus"))


def consult(*args):
    return subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "consult.py")]
                          + list(args) + ["--today", "2026-09-25"],
                          capture_output=True, text=True, cwd=ROOT)


def test_no_vendor_alias_points_at_a_sentinel():
    bad = sorted(k for k, v in RAW["vendor_aliases"].items() if v in SENTINELS)
    assert not bad, "vendor aliases naming a sentinel: {}".format(bad)


@pytest.mark.parametrize("table,key", [
    ("vendor_aliases", "msp"),
    ("vendor_aliases", "impacket"),
    ("product_aliases", "package manager"),
    ("product_aliases", "cargo"),
    ("ambiguous_aliases", "cargo"),
    ("product_aliases", "rust crate"),
    ("product_aliases", "crates.io"),
    ("product_aliases", "crates io"),
])
def test_the_generic_aliases_stay_removed(table, key):
    assert key not in RAW[table], "{} is back in {}".format(key, table)


@pytest.mark.parametrize("question", ["Rust crate", "a malicious crate on crates.io"])
def test_a_rust_crate_question_is_the_library_class_and_not_one_crate(question):
    """"rust crate" and "crates.io" named arrayref, one crate, as "cargo" did before it was
    removed. They are the library class now, and the leftover "rust" breaks the tie."""
    resolved = Q.resolve(question, ALIASES)
    assert not resolved["products"], resolved["resolved_by"]
    assert "dev.library" in resolved["classes"], resolved["resolved_by"]
    done = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "query.py"),
                           "Rust crate", "--json", "--limit", "1"],
                          capture_output=True, text=True, cwd=ROOT)
    first = json.loads(done.stdout)["records"][0]["record"]["id"]
    assert first == "obs-generic-rust-crate-hijack-executes-at-compile-time", first


@pytest.mark.parametrize("question", [
    "we are an MSP",
    "impacket secretsdump against a DC",
    "does any package manager run install scripts",
    "cargo build pulled a new crate",
])
def test_these_questions_name_no_sentinel_vendor(question):
    assert not Q.resolve(question, ALIASES)["vendors"] & SENTINELS, question


def test_the_msp_question_still_reaches_its_class():
    """The class alias carried it all along; the vendor alias only added a false vendor."""
    resolved = Q.resolve("we are an MSP", ALIASES)
    assert resolved["classes"] == {"app.msp"}
    assert not resolved["vendors"]


# --- the resolver half ----------------------------------------------------------------

def test_the_sentinel_set_is_the_one_the_resolver_uses():
    assert Q.SENTINEL_VENDORS == SENTINELS


@pytest.mark.parametrize("question", [
    "git", "npm supply chain", "yarn", "pypi", "Suricata IDS",
    "GitHub Actions self-hosted runners", "we are an MSP", "impacket secretsdump",
    "Rust crate", "TrickBot", "Laravel",
])
def test_no_alias_resolves_a_sentinel_vendor(question):
    assert not Q.resolve(question, ALIASES)["vendors"] & SENTINELS, question


@pytest.mark.parametrize("alias", sorted(
    k for k, v in ALIASES["product_aliases"].items() if v["vendor"] in SENTINELS))
def test_a_product_alias_naming_no_vendor_still_resolves_its_product(alias):
    """The product is real; only the vendor is not. It resolves, and says it names no vendor."""
    entry = ALIASES["product_aliases"][alias]
    resolved = Q.resolve(alias, ALIASES)
    assert entry["product"] in resolved["products"], alias
    assert entry["product"] in resolved["vendorless_products"], alias
    assert not resolved["vendors"] & SENTINELS, alias


def test_a_class_of_product_record_is_never_matched_as_a_vendor():
    """131 records carry who.vendor any; none may score as a vendor match for npm."""
    resolved = Q.resolve("npm supply chain", ALIASES)
    generic = [r for r in RECORDS if r["who"]["vendor"] in SENTINELS]
    assert len(generic) > 100
    for record in generic:
        reasons = Q.score(record, resolved, PATTERNS)[1]
        assert "vendor any" not in reasons and "vendor Multiple" not in reasons, record["id"]


def test_a_hand_built_resolution_naming_a_sentinel_still_matches_no_vendor():
    """score() guards the sentinel itself, so a caller building the dict by hand is safe too."""
    record = next(r for r in RECORDS if r["who"]["vendor"] == "any")
    resolved = {"vendors": {"any"}, "products": set(), "classes": set(), "sectors": set(),
                "terms": set()}
    points, reasons = Q.score(record, resolved, PATTERNS)
    assert not any(r.startswith("vendor ") for r in reasons), reasons


def test_a_sentinel_vendor_corroborates_nothing():
    """It returned True, so an ambiguous alias of a class-of-product vendor always resolved."""
    assert not Q.corroborated("does any package manager run install scripts",
                              "package manager", "any")
    assert not Q.corroborated("multiple routers", "routers", "Multiple")


@pytest.mark.parametrize("question,first_contains", [
    ("GitHub Actions", "GitHub Actions"),
    ("Impacket", "Impacket"),
])
def test_the_answer_now_leads_with_the_technology_asked_about(question, first_contains):
    """Before: 418 and 382 findings, each led by an any-vendor session-token record, because
    every generic record arrived as a vendor match. Now GitHub Actions is answered from the
    records naming it, and Impacket, a tool rather than a vendor, from its own record by name.
    Where a class analogue outranks the named records, as Log4j does for "npm supply chain",
    that is the ranking's grouping, which is a separate change."""
    out = consult(question, "--limit", "12").stdout
    first = [l for l in out.splitlines() if l.startswith("TECHNOLOGY:")][0]
    assert first_contains in first, first


def test_the_msp_question_is_not_reported_as_product_resolution():
    out = consult("we are an MSP", "--limit", "3").stdout
    assert "RESOLUTION: product" not in out
    assert "RESOLUTION: CLASS-LEVEL (inferred)" in out



# --- a class-of-product record's entries name a product only as a question would -------------

@pytest.mark.parametrize("question", [
    "Sophos Firewall", "D-Link routers", "QNAP network attached storage",
    "SonicWall firewall appliances",
])
def test_a_generic_noun_in_a_class_record_is_not_the_vendor_product(question):
    """product_matches() let any entry of an `any` record match under the question's vendor, so
    two records listing "firewalls" answered "Sophos Firewall" RESOLUTION: product and dropped
    CLASS_LEVEL_WARNING, though no record names Sophos. The four were CLASS-LEVEL before the
    matcher went in, and are again: "firewall", "routers" and "network attached storage" are
    Sophos's, D-Link's and QNAP's only beside the vendor, and a record naming no vendor never
    puts it there."""
    resolved = Q.resolve(question, ALIASES)
    assert resolved["products"], question
    generic = [r["id"] for r in RECORDS
               if r["who"]["vendor"] in SENTINELS and Q.product_matches(resolved, r)]
    assert not generic, generic
    out = consult(question, "--limit", "3").stdout
    assert "RESOLUTION: CLASS-LEVEL (inferred)" in out, question
    assert "CLASS_LEVEL_WARNING:" in out, question


@pytest.mark.parametrize("question,record_id,entry", [
    ("Synacor Zimbra Collaboration Suite",
     "obs-generic-ai-orchestrated-intrusion-of-internet-facing-web-servers",
     "Zimbra Collaboration Suite"),
    ("Microsoft Active Directory",
     "obs-generic-helpdesk-impersonation-to-ransomware-deployment", "Active Directory"),
    ("Anysphere Cursor",
     "obs-generic-coding-agent-actions-are-attributed-to-the-developer-who-ran-it", "Cursor"),
    ("Broadcom ESXi",
     "obs-generic-hive-ransomware-as-a-service-with-log-and-recovery-destruction",
     "VMware ESXi"),
])
def test_a_class_record_still_names_a_product_it_lists_by_name(question, record_id, entry):
    """What the gate keeps. An entry naming the vendor ("VMware ESXi") or standing as an alias
    of the product on its own ("Zimbra Collaboration Suite", "Active Directory") is the
    product. So is "Cursor": its gate exists for the text cursor and pagination, and in a list
    of coding agents the only rival reading of an entry is a class of product, which cursor
    is not."""
    record = next(r for r in RECORDS if r["id"] == record_id)
    assert Q.product_matches(Q.resolve(question, ALIASES), record) == {entry}


def test_a_gated_word_names_a_product_in_a_class_record_only_where_reviewed():
    """Every entry of an `any` or `Multiple` record that a gated product alias matches on its
    own, with no name for the vendor in the entry, and whether it counted. Such an entry
    counts unless the alias reads as a class; a new one fails here, so it is decided rather
    than inherited."""
    single = Q.singular_only(ALIASES)
    seen = {}
    for alias, value in ALIASES["product_aliases"].items():
        if alias not in ALIASES["ambiguous_aliases"] or value["vendor"] in SENTINELS:
            continue
        for record in RECORDS:
            if record["who"]["vendor"] not in SENTINELS:
                continue
            for entry in record["who"].get("products") or []:
                if not Q._same_product(Q.canonical_product(entry), tuple(alias.split())):
                    continue
                named = not Q.reads_as_class(alias, ALIASES["class_aliases"], single)
                seen[(entry, value["vendor"])] = named
    assert seen == {
        ("Cursor", "Anysphere"): True,
        ("firewalls", "Sophos"): False,
        ("routers", "D-Link"): False,
        ("network attached storage", "QNAP"): False,
    }, seen
