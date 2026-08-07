# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for ``scripts/scaffold_rule.py``.

The scaffolder turns a profile_log.py worksheet into a starter MODEL
rule. The contract these tests pin: the output always lints clean (the
self-gate), is deterministic, wires the high-confidence scalar anchors
into the drain stage with type-correct wrapping, never duplicates a
target, and routes array / XDM_CONST leaves to the header TODO block
instead of emitting a broken assignment.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from _helpers import bundle_root  # noqa: E402

SCRIPTS = bundle_root() / "scripts"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


_scaffold = _load("scaffold_rule")
_profile = _load("profile_log")
_lint = _load("lint_rule")


def _worksheet(fixture: str) -> dict:
    text = (FIXTURES / fixture).read_text(encoding="utf-8")
    return _profile.profile(str(FIXTURES / fixture), text)


def _make(fixture: str, **kw) -> str:
    ws = _worksheet(fixture)
    return _scaffold.scaffold(
        ws,
        kw.get("vendor", "Acme"),
        kw.get("product", "Demo"),
        kw.get("dataset", "acme_demo_raw"),
        kw.get("min_frequency", 3),
    )


class TestScaffoldOutput(unittest.TestCase):
    def test_kv_scaffold_lints_clean(self):
        rule = _make("sample.kv")
        errors = [v for v in _lint.lint(rule) if v["severity"] == "error"]
        self.assertEqual(errors, [], f"scaffold should self-gate clean: {errors}")

    def test_json_scaffold_lints_clean(self):
        rule = _make("acmeshield_waf.log", vendor="AcmeShield", product="WAF")
        errors = [v for v in _lint.lint(rule) if v["severity"] == "error"]
        self.assertEqual(errors, [], f"scaffold should self-gate clean: {errors}")

    def test_deterministic(self):
        a = _make("sample.kv")
        b = _make("sample.kv")
        self.assertEqual(a, b)

    def test_has_model_header_and_terminator(self):
        rule = _make("sample.kv")
        self.assertIn("[MODEL: dataset=acme_demo_raw]", rule)
        self.assertTrue(rule.rstrip().endswith(";"))
        self.assertIn("xdm.observer.vendor = \"Acme\"", rule)
        self.assertIn("xdm.observer.product = \"Demo\"", rule)

    def test_high_confidence_anchor_wired(self):
        rule = _make("sample.kv")
        # src_ip is a strong anchor for xdm.source.ipv4.
        self.assertIn("xdm.source.ipv4 = tmp_src_ip", rule)

    def test_integer_field_wrapped(self):
        rule = _make("sample.kv")
        # spt -> xdm.source.port (Number) must be wrapped to_integer(to_number()).
        self.assertIn("xdm.source.port = to_integer(to_number(tmp_spt))", rule)

    def test_no_duplicate_target(self):
        rule = _make("acmeshield_waf.log", vendor="AcmeShield", product="WAF")
        # Only the hardcoded xdm.event.type assignment should appear.
        assign_lines = [
            ln for ln in rule.splitlines()
            if ln.strip().startswith("xdm.event.type =")
        ]
        self.assertEqual(len(assign_lines), 1, assign_lines)

    def test_array_leaves_routed_to_todo(self):
        rule = _make("acmeshield_waf.log", vendor="AcmeShield", product="WAF")
        # transactions[].* leaves must not be extracted; they belong in the
        # TODO block, not the alter stages.
        self.assertNotIn("transactions[].http.method =", rule)
        self.assertIn("Pattern D'", rule)

    def test_array_xdm_field_uses_arraycreate(self):
        # A leaf whose top anchor is an Array-type XDM field must be wrapped.
        ws = {
            "detected_format": "json",
            "record_count": 1,
            "fields": [
                {
                    "path": "mac",
                    "leaf": "mac",
                    "type": "string",
                    "xdm_candidates": [
                        {"xdm_path": "xdm.source.host.mac_addresses",
                         "frequency": 50, "score": 100}
                    ],
                }
            ],
            "object_arrays": [],
        }
        rule = _scaffold.scaffold(ws, "Acme", "Demo", "acme_demo_raw")
        self.assertIn(
            "xdm.source.host.mac_addresses = if(tmp_mac != null, "
            "arraycreate(tmp_mac), null)",
            rule,
        )
        errors = [v for v in _lint.lint(rule) if v["severity"] == "error"]
        self.assertEqual(errors, [])


class TestScaffoldSyslogStage0(unittest.TestCase):
    """A syslog worksheet must gain the Stage 0 envelope layer before the
    payload: PRI-anchored host capture, the function-form priority decode
    in separate alter stages, and the envelope drains seeded as a
    fallback."""

    def _rule(self) -> str:
        return _make("syslog_cortexgrid.log", vendor="CortexGrid",
                     product="Sentinel", dataset="cortexgrid_sentinel_raw")

    def test_emits_pri_and_host_capture(self):
        rule = self._rule()
        self.assertIn('regextract(_raw_log, "^<(\\d{1,3})>")', rule)
        self.assertIn(
            "tmp_syslog_host_raw = coalesce(tmp_host_5424, tmp_host_3164)", rule
        )
        # NIL-hostname guard: RFC 5424 permits "-" for HOSTNAME; the
        # scaffold nulls it rather than mapping the literal dash.
        self.assertIn(
            'tmp_syslog_host = if(tmp_syslog_host_raw != "-", tmp_syslog_host_raw)',
            rule,
        )

    def test_stage0_is_relay_aware(self):
        # HARD RULE: the emitted envelope must be prepend-robust -- the RFC
        # 3164 host and the origin PRI are captured through a greedy ^.*
        # prefix so a relay-prepended header is skipped to the origin.
        rule = self._rule()
        self.assertIn(
            'tmp_host_3164  = arrayindex(regextract(_raw_log, '
            '"^.*<\\d{1,3}>[A-Za-z]{3}', rule
        )
        # PRI is coalesce(origin-greedy, first) -- the ^<( fallback remains.
        self.assertIn(
            'regextract(_raw_log, "^.*<(\\d{1,3})>[A-Za-z]{3}', rule
        )
        self.assertIn('regextract(_raw_log, "^<(\\d{1,3})>")', rule)
        # No ERR-030 self-flag from the relay-aware envelope captures.
        self.assertNotIn("ERR-030", [v["rule_id"] for v in _lint.lint(rule)])

    def test_facility_and_severity_in_separate_alters(self):
        rule = self._rule()
        # Severity reads the facility temp, so they cannot share an alter
        # (ERR-024). The decode must be split across two stages.
        self.assertIn("tmp_pri_facility = to_integer(divide(tmp_pri, 8))", rule)
        self.assertIn(
            "tmp_pri_severity = to_integer(subtract(tmp_pri, "
            "multiply(tmp_pri_facility, 8)))",
            rule,
        )

    def test_envelope_drains_present(self):
        rule = self._rule()
        self.assertIn("xdm.observer.name = tmp_syslog_host", rule)
        self.assertIn("xdm.event.log_level = tmp_pri_log_level", rule)
        self.assertIn("xdm.alert.severity = tmp_pri_sev_band", rule)

    def test_self_gates_clean_including_envelope_lints(self):
        rule = self._rule()
        ids = [v["rule_id"] for v in _lint.lint(rule)]
        self.assertNotIn("WARN-040", ids)  # PRI-anchored, not vendor-anchored
        self.assertNotIn("WARN-041", ids)  # severity is decoded
        errors = [v for v in _lint.lint(rule) if v["severity"] == "error"]
        self.assertEqual(errors, [], f"syslog scaffold not clean: {errors}")

    def test_non_syslog_has_no_stage0(self):
        rule = _make("sample.kv")
        self.assertNotIn("tmp_pri_facility", rule)
        self.assertNotIn("tmp_syslog_host", rule)


class TestScaffoldAuthMandatory(unittest.TestCase):
    """When the profiler flags an authentication event, the scaffold pads
    the mandatory fields that have an official placeholder, sets
    xdm.event.type to an authentication value, and lists the un-paddable
    mandatory fields as TODOs. It always self-gates clean (no errors)."""

    def _rule(self) -> str:
        return _make("auth_event.jsonl", vendor="Okta", product="SystemLog",
                     dataset="okta_systemlog_raw")

    def test_event_type_is_authentication(self):
        self.assertIn('xdm.event.type = "authentication"', self._rule())

    def test_paddable_fields_seeded(self):
        rule = self._rule()
        self.assertIn(
            "xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION)",
            rule,
        )
        # xdm.auth.service is NOT paddable: the role is decided per
        # event type, so a seeded default would assert a flow shape the
        # scaffolder cannot know. It is a must-extract TODO instead.
        self.assertNotIn('xdm.auth.service = "Login"', rule)
        self.assertIn("xdm.auth.service             -- AUTH MANDATORY", rule)
        self.assertIn(
            "xdm.network.ip_protocol = XDM_CONST.IP_PROTOCOL_IP", rule
        )

    def test_operation_is_not_blind_padded(self):
        # xdm.event.operation is an XDM_CONST.OPERATION_TYPE enum with no
        # neutral member, so the scaffold must NOT emit a guessed
        # AUTH_LOGIN; it is a must-extract TODO the author derives.
        rule = self._rule()
        self.assertNotIn("xdm.event.operation = XDM_CONST", rule)
        self.assertIn("xdm.event.operation", rule)  # present as a TODO line

    def test_unpaddable_fields_listed_as_todo(self):
        rule = self._rule()
        # upn / operation / original_event_type / outcome / target.resource
        # .name cannot be padded with a safe value, so they appear as AUTH
        # MANDATORY TODOs for the author.
        self.assertIn("AUTH MANDATORY", rule)
        self.assertIn("xdm.source.user.upn", rule)
        self.assertIn("xdm.event.operation", rule)
        self.assertIn("xdm.target.resource.name", rule)

    def test_target_resource_name_is_never_padded(self):
        # The contrast with xdm.target.ipv4 is the point: an empty target
        # ADDRESS is honest, an empty target IDENTITY is not. A padded
        # target is how an inverted auth rule passes the linter, so the
        # scaffold must never seed a placeholder here (WARN-055).
        rule = self._rule()
        self.assertNotIn('xdm.target.resource.name = ""', rule)
        self.assertNotIn("xdm.target.resource.name = null", rule)

    def test_self_gates_clean(self):
        errors = [v for v in _lint.lint(self._rule())
                  if v["severity"] == "error"]
        self.assertEqual(errors, [], f"auth scaffold not error-clean: {errors}")

    def test_non_auth_worksheet_has_no_auth_block(self):
        rule = _make("sample.kv")
        self.assertNotIn('xdm.event.type = "authentication"', rule)
        self.assertNotIn("EVENT_TAG_AUTHENTICATION", rule)
        self.assertNotIn("AUTH MANDATORY", rule)


class TestScaffoldNetworkMandatory(unittest.TestCase):
    """When the profiler flags a network event, the scaffold pads the
    mandatory fields that have a type-valid placeholder, sets
    xdm.event.type to a network value, emits the story tag, and lists
    the un-paddable fields as TODOs. Always self-gates clean."""

    def _rule(self) -> str:
        return _make("network_event.jsonl", vendor="AcmeFW", product="NGFW",
                     dataset="acmefw_ngfw_raw")

    def test_event_type_and_tag(self):
        rule = self._rule()
        self.assertIn('xdm.event.type = "network"', rule)
        self.assertIn(
            "xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_NETWORK)", rule
        )

    def test_paddable_fields_seeded(self):
        rule = self._rule()
        self.assertIn(
            "xdm.network.ip_protocol = XDM_CONST.IP_PROTOCOL_IP", rule
        )
        self.assertIn(
            'xdm.network.protocol_layers = arraycreate("IP")', rule
        )
        self.assertIn(
            "xdm.network.http.url_category = XDM_CONST.URL_CATEGORY_UNKNOWN",
            rule,
        )
        self.assertIn("xdm.source.is_internal_ip = false", rule)
        self.assertIn("xdm.target.is_internal_ip = false", rule)

    def test_anchor_wired_fields_not_overwritten(self):
        # src_ip is wired from the log by the anchor loop; the network pad
        # must not duplicate the target.
        rule = self._rule()
        self.assertIn("xdm.source.ipv4 = tmp_src_ip", rule)
        assigns = [ln for ln in rule.splitlines()
                   if ln.strip().startswith("xdm.source.ipv4 =")]
        self.assertEqual(len(assigns), 1, assigns)

    def test_self_gates_clean(self):
        errors = [v for v in _lint.lint(self._rule())
                  if v["severity"] == "error"]
        self.assertEqual(errors, [], f"network scaffold not clean: {errors}")

    def test_syslog_network_composes_with_stage0(self):
        rule = _make("network_event_syslog.log", vendor="AcmeFW",
                     product="NGFW", dataset="acmefw_ngfw_raw")
        # Stage 0 envelope AND the network block in the same scaffold.
        self.assertIn("tmp_pri_facility = to_integer(divide(tmp_pri, 8))", rule)
        self.assertIn("xdm.observer.name = tmp_syslog_host", rule)
        self.assertIn(
            "xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_NETWORK)", rule
        )
        errors = [v for v in _lint.lint(rule) if v["severity"] == "error"]
        self.assertEqual(errors, [], f"syslog network scaffold: {errors}")

    def test_dual_worksheet_merges_tags_once(self):
        # Synthetic worksheet carrying BOTH story detections: exactly one
        # merged tags assignment, and outcome is NOT padded (the stricter
        # authentication vocabulary forbids OUTCOME_UNKNOWN).
        ws = {
            "detected_format": "jsonl",
            "record_count": 1,
            "fields": [],
            "object_arrays": [],
            "authentication": {"detected": True, "signals": []},
            "network": {"detected": True, "signals": []},
        }
        rule = _scaffold.scaffold(ws, "AcmeVPN", "Gateway", "acmevpn_gw_raw")
        self.assertIn(
            "xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION, "
            "XDM_CONST.EVENT_TAG_NETWORK)",
            rule,
        )
        tags_lines = [ln for ln in rule.splitlines()
                      if ln.strip().startswith("xdm.event.tags =")]
        self.assertEqual(len(tags_lines), 1, tags_lines)
        self.assertIn('xdm.event.type = "authentication"', rule)
        self.assertNotIn("xdm.event.outcome = XDM_CONST.OUTCOME_UNKNOWN", rule)
        errors = [v for v in _lint.lint(rule) if v["severity"] == "error"]
        self.assertEqual(errors, [], f"dual scaffold not clean: {errors}")

    def test_non_network_worksheet_has_no_network_block(self):
        # The IdP login fixture detects authentication only.
        rule = _make("auth_event.jsonl", vendor="Okta", product="SystemLog")
        self.assertNotIn("EVENT_TAG_NETWORK", rule)
        self.assertNotIn("NETWORK MANDATORY", rule)
        self.assertNotIn("xdm.target.sent_bytes", rule)


class TestScaffoldCli(unittest.TestCase):
    def test_stdin_pipe_exit_zero(self):
        ws = json.dumps(_worksheet("sample.kv"))
        cp = subprocess.run(
            [sys.executable, str(SCRIPTS / "scaffold_rule.py"), "-",
             "--vendor", "Acme", "--product", "Demo"],
            input=ws, capture_output=True, text=True, check=False,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("[MODEL: dataset=acme_demo_raw]", cp.stdout)

    def test_bad_json_exits_two(self):
        cp = subprocess.run(
            [sys.executable, str(SCRIPTS / "scaffold_rule.py"), "-"],
            input="not json", capture_output=True, text=True, check=False,
        )
        self.assertEqual(cp.returncode, 2)


class TestScaffoldProvenanceBlock(unittest.TestCase):
    """Every generated rule carries the regexable GOCORTEX_SKILLS
    provenance block; name / version come from SKILL.md, model and the
    warning count from the build environment (or the self-lint)."""

    def test_block_present_with_all_keys(self):
        rule = _make("sample.kv")
        for key in (
            "// Generated via",
            'GOCORTEX_SKILLS_MODEL="',
            'GOCORTEX_SKILLS_SKILL_NAME="cortex-platform-xdm-author"',
            'GOCORTEX_SKILLS_SKILL_VERSION="',
            'GOCORTEX_SKILLS_SKILL_WARNING_COUNT="',
            'GOCORTEX_SKILLS_SOURCE_BASIS="',
        ):
            self.assertIn(key, rule, key)
        # The placeholder must be resolved to a concrete count.
        self.assertNotIn("__PENDING__", rule)
        # With no reference supplied, the scaffolder defaults to sample-only.
        self.assertIn('GOCORTEX_SKILLS_SOURCE_BASIS="sample-only"', rule)

    def test_env_overrides_model_count_and_basis(self):
        env = dict(os.environ)
        env["GOCORTEX_SKILLS_MODEL"] = "test-model-x"
        env["GOCORTEX_SKILLS_SKILL_WARNING_COUNT"] = "3"
        env["GOCORTEX_SKILLS_SOURCE_BASIS"] = "spec-backed"
        ws = json.dumps(_worksheet("sample.kv"))
        cp = subprocess.run(
            [sys.executable, str(SCRIPTS / "scaffold_rule.py"), "-",
             "--vendor", "Acme", "--product", "Demo"],
            input=ws, capture_output=True, text=True, check=False, env=env,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn('GOCORTEX_SKILLS_MODEL="test-model-x"', cp.stdout)
        self.assertIn('GOCORTEX_SKILLS_SKILL_WARNING_COUNT="3"', cp.stdout)
        self.assertIn('GOCORTEX_SKILLS_SOURCE_BASIS="spec-backed"', cp.stdout)


if __name__ == "__main__":
    unittest.main()
