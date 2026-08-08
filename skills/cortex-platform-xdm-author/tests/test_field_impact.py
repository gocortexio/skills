# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Guards for ``assets/field_impact.json``.

The registry answers "did version X change the MEANING of field F" for a
consumer that measures a field against an installed model during a
migration -- the `cortex-content-pack-go-again` phase 900 STEP ZERO
precondition.

The load-bearing property is that ABSENCE means "no impact" rather than
"nobody wrote it down". That only holds if the registry cannot fall
behind the changelog, so these tests derive the expected content from
``CHANGELOG.md`` rather than trusting the registry to be maintained:
every version section must have an entry, and every ``xdm.`` path named
in that section must be classified into exactly one bucket.
"""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _helpers import bundle_root  # noqa: E402


REGISTRY = bundle_root() / "assets" / "field_impact.json"
CHANGELOG = bundle_root() / "CHANGELOG.md"
SKILL = bundle_root() / "SKILL.md"

BUCKETS = ("meaning_changed", "mandatory_changed", "banned", "mentioned_only")

# Deliberately the same shape used to derive the registry: a backtick is
# optional because the changelog quotes some paths and not others, and a
# trailing period is sentence punctuation rather than part of the path.
XDM_PATH = re.compile(r"`?(xdm\.[a-z0-9_.*]+)`?")


def _registry() -> dict:
    return json.loads(REGISTRY.read_text(encoding="utf-8"))


def _changelog_sections() -> dict:
    """Version heading -> the body of that version's entry."""
    text = CHANGELOG.read_text(encoding="utf-8")
    out = {}
    for part in re.split(r"^## ", text, flags=re.M)[1:]:
        head, _, body = part.partition("\n")
        out[head.strip()] = body
    return out


def _paths_in(body: str) -> set:
    return {m.rstrip(".") for m in XDM_PATH.findall(body)}


def _fields_of(entry: dict) -> list:
    """Every field named anywhere in an entry, with duplicates kept so a
    field listed in two buckets is visible rather than silently merged."""
    return [item["field"] for bucket in BUCKETS for item in entry[bucket]]


class TestRegistryShape(unittest.TestCase):
    def test_parses_and_declares_its_schema(self):
        reg = _registry()
        self.assertEqual(reg["schema_version"], 1)
        self.assertEqual(reg["bundle"], "cortex-platform-xdm-author")
        self.assertIsInstance(reg["versions"], list)

    def test_every_entry_has_every_bucket_and_a_completeness_claim(self):
        for entry in _registry()["versions"]:
            ver = entry["version"]
            self.assertIn("complete", entry, f"{ver} makes no completeness claim")
            self.assertIsInstance(entry["complete"], bool, ver)
            for bucket in BUCKETS:
                self.assertIn(bucket, entry, f"{ver} is missing {bucket}")
                self.assertIsInstance(entry[bucket], list, f"{ver}.{bucket}")

    def test_no_duplicate_versions(self):
        vers = [e["version"] for e in _registry()["versions"]]
        self.assertEqual(len(vers), len(set(vers)), f"duplicate versions: {vers}")

    def test_a_field_appears_in_at_most_one_bucket_per_version(self):
        # The whole point is a single unambiguous answer per field per
        # version. Two buckets would let a consumer read either one.
        for entry in _registry()["versions"]:
            fields = _fields_of(entry)
            dupes = {f for f in fields if fields.count(f) > 1}
            self.assertFalse(
                dupes, f"{entry['version']}: field in more than one bucket: {dupes}"
            )

    def test_meaning_changes_carry_a_migration_instruction(self):
        # A meaning change without was/now/migration is the prose this
        # registry exists to replace.
        for entry in _registry()["versions"]:
            for item in entry["meaning_changed"]:
                for key in ("field", "was", "now", "migration"):
                    self.assertIn(
                        key, item, f"{entry['version']} {item.get('field')}: no {key}"
                    )
                    self.assertTrue(str(item[key]).strip(), f"{entry['version']}: empty {key}")

    def test_other_buckets_carry_their_own_justification(self):
        for entry in _registry()["versions"]:
            for item in entry["mandatory_changed"]:
                self.assertIn(item["change"], ("added", "narrowed", "removed"), item)
                self.assertTrue(item["detail"].strip(), item)
            for item in entry["banned"]:
                self.assertTrue(item["reason"].strip(), item)
            for item in entry["mentioned_only"]:
                # This is the bucket the whole request turned on: a bare
                # field name here would be the "four packs touched
                # event.type" answer that stops the reader.
                self.assertTrue(
                    item["note"].strip(),
                    f"{entry['version']} {item['field']}: mentioned_only needs a note "
                    "saying why there is no impact",
                )


class TestRegistryMatchesChangelog(unittest.TestCase):
    """The registry is derived from the changelog, so it cannot be stale
    without one of these failing."""

    def test_every_changelog_version_has_an_entry(self):
        missing = set(_changelog_sections()) - {
            e["version"] for e in _registry()["versions"]
        }
        self.assertFalse(
            missing,
            f"CHANGELOG.md has versions with no field_impact.json entry: "
            f"{sorted(missing)}. Absence in the registry reads as 'no impact', so a "
            f"missing entry is a false negative for anyone migrating across it.",
        )

    def test_no_entry_for_a_version_that_does_not_exist(self):
        extra = {e["version"] for e in _registry()["versions"]} - set(
            _changelog_sections()
        )
        self.assertFalse(extra, f"registry names unreleased versions: {sorted(extra)}")

    def test_the_current_bundle_version_has_an_entry(self):
        frontmatter = SKILL.read_text(encoding="utf-8").split("---")[1]
        current = next(
            line.split(":", 1)[1].strip()
            for line in frontmatter.splitlines()
            if line.startswith("version:")
        )
        self.assertIn(
            current,
            {e["version"] for e in _registry()["versions"]},
            f"SKILL.md is at {current} and the registry does not cover it",
        )

    def test_every_field_named_in_a_changelog_entry_is_classified(self):
        # This is what makes complete=true mean something. A path the
        # changelog mentions and the registry ignores is exactly the
        # "meaning unchanged, and nobody said so" gap.
        sections = _changelog_sections()
        for entry in _registry()["versions"]:
            if not entry["complete"]:
                continue
            named = set(_fields_of(entry))
            in_prose = _paths_in(sections[entry["version"]])
            unclassified = in_prose - named
            self.assertFalse(
                unclassified,
                f"{entry['version']} claims complete=true but does not classify "
                f"{sorted(unclassified)}. Put each in meaning_changed, "
                f"mandatory_changed, banned or mentioned_only.",
            )

    def test_no_registry_field_is_absent_from_its_changelog_entry(self):
        # The other direction: a classification for a field the entry
        # never mentions is either a typo or a claim with no source.
        sections = _changelog_sections()
        for entry in _registry()["versions"]:
            in_prose = _paths_in(sections[entry["version"]])
            for field in _fields_of(entry):
                self.assertIn(
                    field,
                    in_prose,
                    f"{entry['version']} classifies {field}, which its changelog "
                    f"entry never names",
                )


class TestTheAnswersItGives(unittest.TestCase):
    """Pins the answers the consumer actually queries for, so a future
    edit that changes them has to be deliberate."""

    def _entry(self, version: str) -> dict:
        return next(e for e in _registry()["versions"] if e["version"] == version)

    def test_auth_service_reversed_at_1_9_0(self):
        fields = [i["field"] for i in self._entry("1.9.0")["meaning_changed"]]
        self.assertEqual(fields, ["xdm.auth.service"])

    def test_auth_service_also_moved_at_1_6_1_and_that_one_was_the_error(self):
        item = self._entry("1.6.1")["meaning_changed"][0]
        self.assertEqual(item["field"], "xdm.auth.service")
        self.assertIn("WRONG", item["migration"])

    def test_event_type_is_a_meaning_change_at_1_7_0_not_at_2_0_2_or_2_0_3(self):
        # The case that motivated the registry: event.type is named in
        # three versions and only one of them moved it.
        self.assertIn(
            "xdm.event.type",
            [i["field"] for i in self._entry("1.7.0")["meaning_changed"]],
        )
        for quiet in ("2.0.2", "2.0.3"):
            entry = self._entry(quiet)
            self.assertEqual(entry["meaning_changed"], [], quiet)
            self.assertIn(
                "xdm.event.type", [i["field"] for i in entry["mentioned_only"]], quiet
            )

    def test_target_resource_name_is_mandatory_not_meaning(self):
        entry = self._entry("1.8.23")
        self.assertEqual(entry["meaning_changed"], [])
        item = entry["mandatory_changed"][0]
        self.assertEqual(item["field"], "xdm.target.resource.name")
        self.assertEqual(item["change"], "added")

    def test_the_three_cloud_source_type_paths_are_banned_at_1_8_1(self):
        banned = {i["field"] for i in self._entry("1.8.1")["banned"]}
        self.assertEqual(
            banned,
            {
                "xdm.source.cloud.source_type",
                "xdm.target.cloud.source_type",
                "xdm.intermediate.cloud.source_type",
            },
        )


class TestQueryCLI(unittest.TestCase):
    """``scripts/field_impact.py`` is what the consumer actually calls, so
    the exit-code contract it branches on is pinned here."""

    SCRIPT = bundle_root() / "scripts" / "field_impact.py"

    def _run(self, *args):
        import subprocess

        return subprocess.run(
            [sys.executable, str(self.SCRIPT), *args],
            capture_output=True, text=True,
        )

    def test_unchanged_field_exits_zero_and_says_why_each_mention_was_harmless(self):
        # The case the registry was requested for: the field is named in
        # two of the three versions crossed and moved in neither.
        r = self._run("--field", "xdm.event.type", "--from", "2.0.0", "--to", "2.0.3")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("[OK]", r.stdout)
        self.assertIn("mentioned, no impact", r.stdout)

    def test_meaning_change_exits_one_and_names_was_and_now(self):
        r = self._run("--field", "xdm.auth.service", "--from", "1.8.1", "--to", "2.0.0")
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("[CHANGED]", r.stdout)
        self.assertIn("was:", r.stdout)
        self.assertIn("now:", r.stdout)

    def test_the_range_is_a_union_not_just_the_endpoint(self):
        # 2.0.0 itself only RESTATES the reversal; the change is 1.9.0's.
        # Querying the endpoint alone must not report it, and querying the
        # range must -- this is what a grep over one version's entry gets
        # wrong.
        endpoint = self._run("--field", "xdm.auth.service", "--from", "1.9.1", "--to", "2.0.0")
        self.assertEqual(endpoint.returncode, 0, endpoint.stdout)
        spanning = self._run("--field", "xdm.auth.service", "--from", "1.8.24", "--to", "2.0.0")
        self.assertEqual(spanning.returncode, 1, spanning.stdout)

    def test_the_from_version_is_exclusive(self):
        # A consumer already ON 1.9.0 has its change; crossing FROM it
        # must not re-report it.
        already = self._run("--field", "xdm.auth.service", "--from", "1.9.0", "--to", "2.0.0")
        self.assertEqual(already.returncode, 0, already.stdout)
        onto = self._run("--field", "xdm.auth.service", "--from", "1.8.24", "--to", "1.9.0")
        self.assertEqual(onto.returncode, 1, onto.stdout)

    def test_banned_field_exits_one(self):
        r = self._run("--field", "xdm.source.cloud.source_type", "--from", "1.8.0", "--to", "1.8.1")
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("[BANNED]", r.stdout)

    def test_mandatory_change_is_not_a_meaning_change(self):
        # Comparable values, different population -- so it must NOT exit
        # non-zero and stop a migration that is fine to proceed with.
        r = self._run("--field", "xdm.target.resource.name", "--from", "1.8.22", "--to", "1.8.23")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("[MANDATORY]", r.stdout)

    def test_json_output_is_parseable(self):
        r = self._run("--field", "xdm.event.type", "--from", "1.6.1", "--to", "1.7.0", "--json")
        payload = json.loads(r.stdout)
        self.assertEqual(payload["verdict"], "meaning_changed")
        self.assertEqual(payload["versions_read"], ["1.7.0"])

    def test_unknown_version_cannot_answer_rather_than_guessing(self):
        r = self._run("--version", "9.9.9")
        self.assertEqual(r.returncode, 2, r.stdout)


if __name__ == "__main__":
    unittest.main()
