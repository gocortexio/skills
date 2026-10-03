# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""What kind of answer a consultation is, decided once and stated on the RESOLUTION line.

Until 0.43.0 one tally decided the mode: a finding naming the vendor or product asked about
made it `product - the corpus holds records naming this technology`. That tally could not
tell a product from its vendor's other lines, and could not see exposures at all. Asked as
questions, the 1,454 vendor and product alias keys measured before this change showed three
kinds of mislabelled answer:

- A vendor's other product lines read as the product. 196 printed RESOLUTION: product with
  no finding naming the product, "FortiSandbox" and "IOS XR" among them, and no
  CLASS_LEVEL_WARNING.
- The vendor's records were denied. 129, "FortiMail" and "Panorama" among them, printed "no
  vendor or product the corpus holds records for" over findings naming the vendor.
- Exposure records were denied. "Linux kernel" was told "The corpus holds no record naming
  it" over exposure records that do, and 234 names held only as exposures, Sitecore and Zoho
  among them, exited 1 as UNRESOLVED.

The mode is now decided by `resolution_mode()` from `mode_counts()`, which reads MATCH_TIER,
so the mode and the MATCH_TIERS line cannot disagree. CLASS_LEVEL_WARNING is the one gating
key and prints for every mode except `product` and `mechanism`.

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
import consult as C  # noqa: E402
import query as Q  # noqa: E402

TODAY = "2026-09-25"
ALIASES = Q.normalise_alias_keys(json.load(open(os.path.join(ROOT, "corpus", "schema",
                                                             "aliases.json"), encoding="utf-8")))
RECORDS, PATTERNS = Q.load_corpus(os.path.join(ROOT, "corpus"))


def run(*args):
    return subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "consult.py")]
                          + list(args) + ["--today", TODAY],
                          capture_output=True, text=True, cwd=ROOT, timeout=180)


def line(out, key):
    found = [l for l in out.splitlines() if l.startswith(key + ":")]
    return found[0] if found else None


@pytest.mark.parametrize("question", ["Fortinet FortiMail", "Apache Superset",
                                      "Palo Alto Panorama", "Fortinet FortiSandbox"])
def test_a_product_no_observation_names_is_vendor_level(question):
    done = run(question, "--limit", "12")
    out = done.stdout
    assert done.returncode == 0
    assert line(out, "RESOLUTION").startswith("RESOLUTION: VENDOR-LEVEL - no observation names")
    assert line(out, "CLASS_LEVEL_WARNING"), out[:800]
    assert "MATCH_TIERS: product=0," in out
    product = Q.resolve(question, ALIASES)["products"]
    assert all(p in line(out, "CLASS_LEVEL_WARNING") for p in product)


@pytest.mark.parametrize("question", ["Cisco ASA", "PAN-OS", "Ivanti EPMM", "Broadcom ESXi",
                                      "Check Point Quantum", "Fortinet", "Cisco"])
def test_a_named_product_or_vendor_with_observations_stays_product(question):
    out = run(question, "--limit", "3").stdout
    assert line(out, "RESOLUTION").startswith("RESOLUTION: product"), line(out, "RESOLUTION")
    assert "CLASS_LEVEL_WARNING:" not in out


def test_a_class_level_answer_counts_the_exposures_that_name_it():
    """Three exposure records name the Linux kernel; the header said none did. The third is
    KSMBD, the kernel's own SMB server, a component of the kernel under product_families
    since 0.43.0."""
    done = run("Linux kernel", "--limit", "3")
    out = done.stdout
    assert done.returncode == 0
    mode = line(out, "RESOLUTION")
    assert mode.startswith("RESOLUTION: CLASS-LEVEL (inferred) - no observation is about "
                           "Linux Kernel"), mode
    assert "exposure records: 3 name Linux Kernel" in mode, mode
    assert "holds no record naming it" not in out
    assert "3 exposure record(s) do" in line(out, "CLASS_LEVEL_WARNING")


def test_the_class_warning_does_not_deny_an_exposure():
    out = run("NVIDIA Triton", "--limit", "3").stdout
    assert "holds no record naming it" not in out
    assert "1 name NVIDIA Triton Inference Server" in line(out, "RESOLUTION")


@pytest.mark.parametrize("question", ["Sitecore", "Zoho", "Hewlett Packard Enterprise"])
def test_a_vendor_held_only_as_exposures_answers(question):
    done = run(question)
    out = done.stdout
    assert done.returncode == 0, "an answer the corpus holds must not exit as nothing matched"
    mode = line(out, "RESOLUTION")
    assert mode.startswith("RESOLUTION: EXPOSURES_ONLY - "), mode
    assert "--as" in mode, "the re-ask route must be printed"
    assert "NOTHING MATCHED" not in out
    assert line(out, "CLASS_LEVEL_WARNING")
    assert "FINDINGS: 0 shown of 0 matched" in out
    assert "exposure record(s) name it" in line(out, "METHODOLOGY")


def test_a_resolved_name_with_no_record_of_any_kind_is_unresolved():
    done = run("Nutanix")
    out = done.stdout
    assert done.returncode == 1
    assert line(out, "RESOLUTION").startswith(
        "RESOLUTION: UNRESOLVED - Nutanix resolved against the alias table, but no "
        "observation or exposure")
    assert "add the vendor, product and product class to corpus/schema/aliases.json" not in out
    assert line(out, "CLASS_LEVEL_WARNING")


def test_vendor_other_class_alone_is_never_product():
    """The Guardsquare shape: a vendor resolved beside classes, and the only findings naming
    the vendor are its other product lines."""
    resolved = {"vendors": {"Android"}, "products": set(), "classes": {"app.cicd"}}
    counts = {"vendor_other_class": 1, "class": 40}
    assert C.resolution_mode(resolved, [], counts) == "vendor-level"
    assert C.resolution_mode(resolved, [], dict(counts, vendor=1)) == "product"
    product = {"vendors": {"Fortinet"}, "products": {"FortiMail"}, "classes": {"server.mail"}}
    assert C.resolution_mode(product, [], {"vendor": 5, "class": 9}) == "vendor-level"
    assert C.resolution_mode(product, [], {"product": 1, "vendor": 5}) == "product"
    assert C.resolution_mode(product, [], {"class": 9}) == "class-level-inferred"
    assert C.resolution_mode(product, ["app.rmm"], {"product": 1}) == "class-level-declared"


def test_resolution_mode_counts_exposures():
    sitecore = {"vendors": {"Sitecore"}, "products": set(), "classes": set()}
    assert C.resolution_mode(sitecore, [], {"named_exposures": 4}) == "exposures-only"
    assert C.resolution_mode(sitecore, [], {"named_exposures": 0}) == "unresolved"
    assert C.resolution_mode(sitecore, [], {"loose": 3, "named_exposures": 4}) \
        == "name-without-observations"
    nothing = {"vendors": set(), "products": set(), "classes": set()}
    assert C.resolution_mode(nothing, [], {"loose": 3}) == "mechanism"
    assert C.resolution_mode(nothing, [], {}) == "unresolved"


def test_the_mode_counts_are_the_match_tiers():
    """mode_counts() reads MATCH_TIER, so the mode and the tally line agree by construction."""
    out = run("Fortinet FortiMail", "--limit", "1").stdout
    tiers = dict(part.split("=") for part in
                 re.search(r"^MATCH_TIERS: (.*?)  \(", out, re.M).group(1).split(", "))
    assert int(tiers["product"]) == 0 and int(tiers["vendor-other-class"]) > 0, tiers


@pytest.mark.parametrize("mode,warned", [
    ("product", False), ("mechanism", False), ("vendor-level", True),
    ("class-level-inferred", True), ("class-level-declared", True),
    ("name-without-observations", True), ("exposures-only", True), ("unresolved", True),
])
def test_one_gating_key_for_every_mode_but_product_and_mechanism(mode, warned):
    resolved = {"vendors": {"Acme"}, "products": {"Widget"}, "classes": {"app.rmm"},
                "product_pairs": {("Acme", "Widget")}}
    text, warning = C.resolution_text(mode, resolved, ["app.rmm"], [])
    assert text.startswith(C.MODE_LABELS[mode])
    assert bool(warning) is warned
    assert "record naming it" not in (warning or "") + text, "say observation, never record"


def sampled_vendors(step=12):
    return sorted(set(ALIASES["vendor_aliases"].values()) - Q.SENTINEL_VENDORS)[::step]


@pytest.mark.parametrize("vendor", sampled_vendors())
def test_a_name_exposures_carry_is_never_told_nothing_names_it(vendor):
    """Swept over every twelfth vendor the alias table knows: wherever an exposure record
    names the vendor, the consultation exits 0 and no line denies it."""
    resolved = Q.resolve(vendor, ALIASES)
    if not resolved["vendors"]:
        pytest.skip("{} is gated on its own".format(vendor))
    named = C.exposures_naming(RECORDS, resolved)
    done = run(vendor, "--limit", "1")
    mode = line(done.stdout, "RESOLUTION")
    if named:
        assert done.returncode == 0, (vendor, mode)
        assert "no observation or exposure" not in mode, (vendor, mode)
        assert not mode.startswith("RESOLUTION: UNRESOLVED"), (vendor, mode)
    assert "record naming it" not in done.stdout, vendor


def test_every_resolution_label_is_in_the_mode_table():
    """SKILL.md's mode table is how a caller learns what a RESOLUTION line means, and it had
    fallen behind the code: NAME_WITHOUT_RECORDS was in the table after the mode that printed
    it had been renamed in the design, and `mechanism` was never a row."""
    with open(os.path.join(ROOT, "SKILL.md"), encoding="utf-8") as handle:
        rows = [l for l in handle.read().splitlines() if l.startswith("| `")]
    for mode, label in C.MODE_LABELS.items():
        assert any(row.startswith("| `" + label) for row in rows), (mode, label)
    assert not any("identity" in row or "NAME_WITHOUT_RECORDS" in row for row in rows)
