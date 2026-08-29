# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Behavioural tests for ``scripts/lint_rule.py``.

Each fixture under ``tests/fixtures/`` exercises one of the parser-
conformance rules the bundled linter is responsible for. The tests
both import the ``lint()`` function directly and shell out to the CLI
to confirm the exit-code contract.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _helpers import bundle_root  # noqa: E402


FIXTURES = Path(__file__).resolve().parent / "fixtures"
LINT_SCRIPT = bundle_root() / "scripts" / "lint_rule.py"


def _load_lint():
    """Import ``lint()`` from the bundled script without making the
    script a permanent member of any package."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("lint_rule", LINT_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


_lint_mod = _load_lint()
lint = _lint_mod.lint


def _load_profiler():
    import importlib.util

    script = bundle_root() / "scripts" / "profile_log.py"
    spec = importlib.util.spec_from_file_location("profile_log", script)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _rule_ids(fixture_name: str) -> list:
    source = (FIXTURES / fixture_name).read_text(encoding="utf-8")
    return [v["rule_id"] for v in lint(source)]


_REF_FIELD_RE = re.compile(r"^\|\s*`(xdm\.[a-z0-9_.]+)`\s*\|")


def _mandatory_fields_from_reference(reference: Path) -> set:
    """Extract the mandatory authentication-story XDM fields from the
    canonical "Mandatory fields" table in the bundled reference doc.

    The table lists one backtick-quoted ``xdm.*`` field per row; the
    section ends at the next ``## `` heading. This is the in-bundle source
    of truth for the linter and profiler ``_AUTH_MANDATORY`` copies."""
    fields = set()
    in_section = False
    for line in reference.read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            in_section = line.startswith("## Mandatory fields")
            continue
        if in_section:
            match = _REF_FIELD_RE.match(line)
            if match:
                fields.add(match.group(1))
    return fields


def _fields_from_reference_section(reference: Path, heading: str) -> set:
    """Extract the backtick-quoted ``xdm.*`` fields from one named section
    of a reference doc. Used for sets that are conditionally rather than
    unconditionally mandatory, which live outside the main table."""
    fields = set()
    in_section = False
    for line in reference.read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            in_section = line.startswith(heading)
            continue
        if in_section:
            match = _REF_FIELD_RE.match(line)
            if match:
                fields.add(match.group(1))
    return fields


class TestCleanFixture(unittest.TestCase):
    """A well-formed rule must produce zero violations."""

    def test_no_violations(self):
        ids = _rule_ids("clean_rule.xql")
        self.assertEqual(ids, [], f"expected silence, got {ids}")


class TestSyntacticRules(unittest.TestCase):
    """Each fixture must surface its target rule id."""

    cases = [
        ("err012_infix_arithmetic.xql", "ERR-012"),
        ("err013_compound_null_guard.xql", "ERR-013"),
        ("err014_bareword_boolean.xql", "ERR-014"),
        ("err015_to_number_into_integer_field.xql", "ERR-015"),
        ("err016_invented_path.xql", "ERR-016"),
        ("err017_arraymap_passthrough.xql", "ERR-017"),
        ("err018_missing_cast.xql", "ERR-018"),
        ("err019_unused_temp.xql", "ERR-019"),
        ("err019_unused_temp_raw.xql", "ERR-019"),
        ("err020_invented_target.xql", "ERR-020"),
        ("err024_sibling_reference.xql", "ERR-024"),
        ("err025_concat_hidden.xql", "ERR-025"),
        ("err027_anchor_read.xql", "ERR-027"),
        ("err028_underscore_temp.xql", "ERR-028"),
        ("err029_banned_cloud_source_type.xql", "ERR-029"),
        ("err034_unquoted_reserved_read.xql", "ERR-034"),
        ("warn014_quoted_const.xql", "WARN-014"),
        ("warn035_scalar_into_array.xql", "WARN-035"),
        ("warn037_loglevel_severity.xql", "WARN-037"),
        ("warn038_missing_host_ipv4.xql", "WARN-038"),
        ("warn039_payload_in_description.xql", "WARN-039"),
        ("warn040_vendor_anchored_header.xql", "WARN-040"),
        ("warn041_pri_no_severity.xql", "WARN-041"),
        ("warn042_auth_mandatory.xql", "WARN-042"),
        ("warn043_network_mandatory.xql", "WARN-043"),
        ("warn049_hardcoded_path.xql", "WARN-049"),
        ("warn055_auth_target_resource.xql", "WARN-055"),
        ("warn057_identity_without_user.xql", "WARN-057"),
        ("warn057_diverged_mirror.xql", "WARN-057"),
        ("info013_overmapping.xql", "INFO-013"),
    ]

    def test_each_fixture_fires(self):
        for fixture, expected in self.cases:
            with self.subTest(fixture=fixture, rule=expected):
                ids = _rule_ids(fixture)
                self.assertIn(
                    expected,
                    ids,
                    f"{fixture}: expected {expected} in {ids}",
                )


class TestCliContract(unittest.TestCase):
    """End-to-end: command-line invocation, exit codes, JSON shape."""

    def _run(self, fixture: str, extra: list = ()) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(LINT_SCRIPT), str(FIXTURES / fixture), *extra],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_clean_exit_zero_and_empty_json(self):
        cp = self._run("clean_rule.xql")
        self.assertEqual(cp.returncode, 0, cp.stderr)
        parsed = json.loads(cp.stdout)
        self.assertEqual(parsed, [])

    def test_error_exits_one_and_emits_violation(self):
        cp = self._run("err012_infix_arithmetic.xql")
        self.assertEqual(cp.returncode, 1, cp.stderr)
        parsed = json.loads(cp.stdout)
        self.assertTrue(parsed, "expected at least one violation")
        self.assertEqual(parsed[0]["rule_id"], "ERR-012")
        self.assertEqual(parsed[0]["severity"], "error")
        self.assertIn("line", parsed[0])
        self.assertIn("message", parsed[0])

    def test_missing_file_exits_two(self):
        cp = subprocess.run(
            [sys.executable, str(LINT_SCRIPT), "/nonexistent/rule.xql"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(cp.returncode, 2)

    def test_text_format(self):
        cp = self._run("err012_infix_arithmetic.xql", ["--format", "text"])
        self.assertEqual(cp.returncode, 1)
        self.assertIn("ERR-012", cp.stdout)


class TestAuthMandatoryListsInSync(unittest.TestCase):
    """The linter and profiler each carry a copy of the authentication
    mandatory set. Both must stay identical to the canonical list so the
    advisory WARN-042 and the profiler checklist never drift apart.

    The canonical list ships inside the bundle as the "Mandatory fields"
    table in ``references/authentication-mapping.md``, so this drift-guard
    is fully self-contained and runs in a standalone checkout with no
    external file or environment configuration."""

    @classmethod
    def setUpClass(cls) -> None:
        reference = (
            bundle_root()
            / "references"
            / "authentication-mapping.md"
        )
        cls.expected = _mandatory_fields_from_reference(reference)
        # The reference heading promises exactly 15 mandatory fields; a
        # mismatch means the table itself drifted.
        if len(cls.expected) != 15:
            raise AssertionError(
                "expected 15 mandatory fields in the reference table, "
                "found %d" % len(cls.expected)
            )

    def test_linter_list_matches_reference(self):
        self.assertEqual(set(_lint_mod._AUTH_MANDATORY), self.expected)

    def test_profiler_list_matches_reference(self):
        prof = _load_profiler()
        self.assertEqual(set(prof._AUTH_MANDATORY), self.expected)


class TestWarn042AuthMandatory(unittest.TestCase):
    """WARN-042 auto-detects an authentication event and warns (never
    blocks) for each unmapped mandatory authentication-story field."""

    _COMPLETE_AUTH = """[MODEL: dataset=acme_idp_raw]
filter _raw_log != null
| alter
    tmp_upn = json_extract_scalar(_raw_log, "$.user"),
    tmp_src = json_extract_scalar(_raw_log, "$.src_ip"),
    tmp_dst = json_extract_scalar(_raw_log, "$.dst_ip"),
    tmp_sport = json_extract_scalar(_raw_log, "$.src_port"),
    tmp_dport = json_extract_scalar(_raw_log, "$.dst_port"),
    tmp_svc = json_extract_scalar(_raw_log, "$.service"),
    tmp_app = json_extract_scalar(_raw_log, "$.target_app"),
    tmp_action = json_extract_scalar(_raw_log, "$.action"),
    tmp_result = json_extract_scalar(_raw_log, "$.result")
| alter
    xdm.event.type = "authentication",
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION),
    xdm.event.operation = XDM_CONST.OPERATION_TYPE_AUTH_LOGIN,
    xdm.event.original_event_type = tmp_action,
    xdm.event.outcome = if(tmp_result = "success", XDM_CONST.OUTCOME_SUCCESS,
        tmp_result != null, XDM_CONST.OUTCOME_FAILED),
    xdm.auth.service = tmp_svc,
    xdm.source.user.upn = tmp_upn,
    xdm.source.user.identity_type = if(
        tmp_upn != null, XDM_CONST.IDENTITY_TYPE_USER,
        XDM_CONST.IDENTITY_TYPE_UNKNOWN),
    xdm.source.user.user_type = if(
        tmp_upn contains "$", XDM_CONST.USER_TYPE_MACHINE_ACCOUNT,
        lowercase(tmp_upn) ~= "^svc[-_.]|service", XDM_CONST.USER_TYPE_SERVICE_ACCOUNT,
        XDM_CONST.USER_TYPE_REGULAR),
    xdm.source.ipv4 = tmp_src,
    xdm.source.port = to_integer(to_number(tmp_sport)),
    xdm.target.ipv4 = tmp_dst,
    xdm.target.port = to_integer(to_number(tmp_dport)),
    xdm.target.resource.name = tmp_app,
    xdm.network.ip_protocol = XDM_CONST.IP_PROTOCOL_TCP
;
"""

    def test_fires_for_each_missing_mandatory_field(self):
        ids = _rule_ids("warn042_auth_mandatory.xql")
        # The fixture maps 5 of 15 mandatory fields, so 10 should be flagged.
        self.assertEqual(ids.count("WARN-042"), 10, ids)

    def test_only_warning_severity_so_exit_stays_zero(self):
        source = (FIXTURES / "warn042_auth_mandatory.xql").read_text(
            encoding="utf-8"
        )
        sev = {v["severity"] for v in lint(source) if v["rule_id"] == "WARN-042"}
        self.assertEqual(sev, {"warning"})

    def test_silent_on_non_auth_rule(self):
        ids = _rule_ids("clean_rule.xql")
        self.assertNotIn("WARN-042", ids)

    def test_silent_when_all_mandatory_mapped(self):
        ids = [v["rule_id"] for v in lint(self._COMPLETE_AUTH)]
        self.assertNotIn("WARN-042", ids)

    def test_value_conformance_flags_forbidden_literals(self):
        # All 15 mandatory fields are present, so none should be flagged as
        # missing. Eight, however, carry a value the authentication story
        # forbids (event.type, event.operation, event.outcome, auth.service,
        # source.ipv4, target.ipv4, network.ip_protocol, and the bare
        # possibly-not-UPN-shaped identifier assigned to source.user.upn).
        # identity_type and user_type carry valid enum members here, so they
        # are not flagged.
        source = (FIXTURES / "warn042_auth_bad_values.xql").read_text(
            encoding="utf-8"
        )
        vios = [v for v in lint(source) if v["rule_id"] == "WARN-042"]
        self.assertEqual(len(vios), 8, [v["message"] for v in vios])
        self.assertEqual({v["severity"] for v in vios}, {"warning"})

    def test_value_conformance_silent_on_temp_sourced_values(self):
        # The complete fixture maps auth.service and outcome from temps and
        # source.ipv4 from a temp. Value conformance must never second-guess
        # a runtime-resolved value, so it stays silent here.
        vios = [v for v in lint(self._COMPLETE_AUTH) if v["rule_id"] == "WARN-042"]
        self.assertEqual(vios, [])

    _DYNAMIC_AUTH = """[MODEL: dataset=acme_idp_raw]
filter _raw_log != null
| alter
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION),
    xdm.event.type = event_type_col,
    xdm.event.operation = op_col,
    xdm.event.original_event_type = action_col,
    xdm.event.outcome = outcome_col,
    xdm.auth.service = svc_col,
    xdm.source.user.upn = upn_col,
    xdm.source.user.identity_type = identity_col,
    xdm.source.user.user_type = user_type_col,
    xdm.source.ipv4 = src_ip,
    xdm.source.port = to_integer(to_number(sport_col)),
    xdm.target.ipv4 = dst_ip,
    xdm.target.port = to_integer(to_number(dport_col)),
    xdm.target.resource.name = target_app_col,
    xdm.network.ip_protocol = proto_col
;
"""

    def test_value_conformance_silent_on_bare_column_mappings(self):
        # Direct raw-column mappings (no leading underscore) are not static
        # literals. Value conformance must not mistake src_ip / proto_col
        # for hard-coded values, even though they are not temps.
        vios = [v for v in lint(self._DYNAMIC_AUTH) if v["rule_id"] == "WARN-042"]
        self.assertEqual(vios, [])

    def _account_class_rule(self, field: str, rhs: str) -> str:
        # A minimal auth-marked rule that maps <field> = <rhs>, used to probe
        # the source.user account-class value-conformance branches.
        return (
            "[MODEL: dataset=acme_idp_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            "    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION),\n"
            "    xdm.source.user.upn = user_col,\n"
            f"    {field} = {rhs}\n"
            ";\n"
        )

    def test_identity_type_raw_literal_flagged(self):
        # A raw string on identity_type (not the XDM enum) is a value error.
        vios = [
            v for v in lint(self._account_class_rule(
                "xdm.source.user.identity_type", '"user"'))
            if v["rule_id"] == "WARN-042"
            and "identity_type is assigned a raw literal" in v["message"]
        ]
        self.assertEqual(len(vios), 1, vios)
        self.assertEqual(vios[0]["severity"], "warning")

    def test_user_type_raw_literal_flagged(self):
        # A raw string on user_type (not the XDM enum) is a value error.
        vios = [
            v for v in lint(self._account_class_rule(
                "xdm.source.user.user_type", '"regular"'))
            if v["rule_id"] == "WARN-042"
            and "user_type is assigned a raw literal" in v["message"]
        ]
        self.assertEqual(len(vios), 1, vios)
        self.assertEqual(vios[0]["severity"], "warning")

    def test_account_class_enum_members_not_flagged(self):
        # The correct XDM_CONST enum members (including a derived if-chain)
        # must never trip value conformance.
        for field, rhs in (
            ("xdm.source.user.identity_type", "XDM_CONST.IDENTITY_TYPE_USER"),
            ("xdm.source.user.user_type", "XDM_CONST.USER_TYPE_REGULAR"),
            ("xdm.source.user.user_type",
             'if(user_col contains "$", XDM_CONST.USER_TYPE_MACHINE_ACCOUNT, '
             "XDM_CONST.USER_TYPE_REGULAR)"),
        ):
            vios = [
                v for v in lint(self._account_class_rule(field, rhs))
                if v["rule_id"] == "WARN-042" and "raw literal" in v["message"]
            ]
            self.assertEqual(vios, [], (field, rhs, vios))

    def test_auth_service_role_token_accepted(self):
        # xdm.auth.service carries the ROLE the system played in the
        # authentication flow. "SP" / "IDP" are the documented values and
        # "Universal" is the house value for a non-IdP source; matching
        # folds case, as XQL does.
        for rhs in ('"IDP"', '"SP"', '"Universal"', '"idp"', '"universal"'):
            vios = [
                v for v in lint(self._account_class_rule(
                    "xdm.auth.service", rhs))
                if v["rule_id"] == "WARN-042" and "auth.service" in v["message"]
            ]
            self.assertEqual(vios, [], (rhs, vios))

    def test_auth_service_name_flagged(self):
        # A service NAME in the role field is the defect this check
        # exists for -- it is what this bundle itself taught until 1.9.0.
        for rhs in ('"Kerberos"', '"TACACS+"', '"OAuth2"', '"Login"',
                    '"SSH"'):
            vios = [
                v for v in lint(self._account_class_rule(
                    "xdm.auth.service", rhs))
                if v["rule_id"] == "WARN-042"
                and "authentication service NAME" in v["message"]
            ]
            self.assertEqual(len(vios), 1, (rhs, vios))
            self.assertEqual(vios[0]["severity"], "warning")

    def test_auth_service_dynamic_value_not_flagged(self):
        # The linter must never guess a runtime value. A raw column, a
        # temp, and an if()-chain that already returns a role on some
        # branch are all left alone.
        for rhs in ("svc_col", "tmp_svc",
                    'if(tmp_a = "x", "IDP", "SSH")'):
            vios = [
                v for v in lint(self._account_class_rule(
                    "xdm.auth.service", rhs))
                if v["rule_id"] == "WARN-042" and "auth.service" in v["message"]
            ]
            self.assertEqual(vios, [], (rhs, vios))

    def test_auth_service_if_chain_of_names_flagged(self):
        # Shipped rules assign this field from an if()-chain far more
        # often than from a bare literal, so a check that only reads
        # static literals would be nearly inert. Predicate literals are
        # not values and must not appear in the finding.
        rhs = ('if(tmp_is_ssh = "yes", "SSH", '
               'tmp_login_port = "23", "Telnet")')
        vios = [
            v for v in lint(self._account_class_rule(
                "xdm.auth.service", rhs))
            if v["rule_id"] == "WARN-042"
            and "authentication service NAME" in v["message"]
        ]
        self.assertEqual(len(vios), 1, vios)
        self.assertIn('"SSH", "Telnet"', vios[0]["message"])
        self.assertNotIn('"yes"', vios[0]["message"])
        self.assertNotIn('"23"', vios[0]["message"])

    def test_target_resource_placeholder_flagged_as_warn055(self):
        # The no-pad rule for the authentication target. A placeholder
        # satisfies the mandatory-field check while leaving the event with
        # no record of what was logged into -- the state an inverted rule
        # passes the linter in -- so it is flagged separately.
        for rhs in ('""', '"-"', '"N/A"', '"unknown"', '"null"'):
            vios = [
                v for v in lint(self._account_class_rule(
                    "xdm.target.resource.name", rhs))
                if v["rule_id"] == "WARN-055"
            ]
            self.assertEqual(len(vios), 1, (rhs, vios))
            self.assertEqual(vios[0]["severity"], "warning")

    def test_target_resource_real_value_not_flagged(self):
        # A derived value is the norm; a MEANINGFUL constant is legitimate
        # too (a dedicated portal or console feed really does have one
        # constant target). Neither may trip WARN-055.
        for rhs in ("app_col", "tmp_app", '"AWS Console"', '"SSL-VPN"',
                    'if(tmp_eid = 4768, tmp_svc, tmp_computer)'):
            vios = [
                v for v in lint(self._account_class_rule(
                    "xdm.target.resource.name", rhs))
                if v["rule_id"] == "WARN-055"
            ]
            self.assertEqual(vios, [], (rhs, vios))

    def test_target_resource_padding_fixture_exits_zero(self):
        # Advisory only: the padded fixture reports WARN-055 and nothing
        # else, and the exit code stays 0.
        ids = _rule_ids("warn055_auth_target_resource.xql")
        self.assertEqual(ids, ["WARN-055"], ids)

    def test_warn055_silent_on_non_auth_rule(self):
        ids = _rule_ids("clean_rule.xql")
        self.assertNotIn("WARN-055", ids)

    _SIGNAL_ONLY_AUTH = """[MODEL: dataset=acme_idp_raw]
filter _raw_log != null
| alter
    xdm.event.original_event_type = "user.login",
    xdm.source.user.upn = user_col
;
"""

    def test_classifies_auth_from_event_signal_without_marker(self):
        # No explicit XDM marker (no EVENT_TAG_AUTHENTICATION,
        # OPERATION_TYPE_AUTH_*, or "authentication" in event.type), but
        # original_event_type carries an auth literal. WARN-042 must still
        # classify the rule as authentication and flag the unmapped
        # mandatory fields.
        vios = [v for v in lint(self._SIGNAL_ONLY_AUTH) if v["rule_id"] == "WARN-042"]
        self.assertTrue(vios, "signal-only auth rule should trigger WARN-042")
        self.assertEqual({v["severity"] for v in vios}, {"warning"})
        # original_event_type and source.user.upn are mapped; the rest of
        # the mandatory set is missing and must be reported.
        msgs = " ".join(v["message"] for v in vios)
        self.assertIn("xdm.event.outcome", msgs)
        self.assertIn("xdm.auth.service", msgs)

    def test_classifies_auth_from_operation_literal_signal(self):
        # The literal signal must work across every event-semantic field,
        # including xdm.event.operation carrying an auth literal.
        source = (
            "[MODEL: dataset=acme_idp_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    xdm.event.operation = "signin",\n'
            "    xdm.source.user.upn = user_col\n"
            ";\n"
        )
        vios = [v for v in lint(source) if v["rule_id"] == "WARN-042"]
        self.assertTrue(vios, "operation literal signal should trigger WARN-042")

    def test_no_auth_classification_without_signal_or_marker(self):
        # A MODEL rule with an event type that has no auth token and no
        # marker must never be classified as authentication.
        source = (
            "[MODEL: dataset=acme_web_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    xdm.event.original_event_type = "file.download",\n'
            "    xdm.source.user.upn = user_col\n"
            ";\n"
        )
        vios = [v for v in lint(source) if v["rule_id"] == "WARN-042"]
        self.assertEqual(vios, [])


class TestErr027Branches(unittest.TestCase):
    """ERR-027 has two detail branches: a self-referential anchor lift
    (`tmp_x = coalesce(tmp_x, ...)`) and a bare read of an underscore field
    never assigned in the rule. Lock both so a future change cannot
    silently collapse one."""

    def _err027(self, source: str) -> list:
        return [v for v in lint(source) if v["rule_id"] == "ERR-027"]

    def test_both_branches_fire(self):
        source = (FIXTURES / "err027_anchor_read.xql").read_text(encoding="utf-8")
        hits = self._err027(source)
        names = {v["line"]: v["message"] for v in hits}
        joined = " ".join(names.values())
        self.assertIn("only ever assigned from its own value", joined)
        self.assertIn("read but never assigned", joined)
        self.assertGreaterEqual(len(hits), 2, f"expected both branches, got {hits}")

    def test_self_sufficient_derivation_is_silent(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            "    tmp_resource_type = json_extract_scalar(_raw_log, \"$.resource_type\"),\n"
            "    tmp_action_class = if(tmp_resource_type != null,\n"
            "        arrayindex(split(tmp_resource_type, \"_\"), 0))\n"
            "| alter\n"
            "    xdm.target.resource.type = tmp_resource_type\n"
            ";\n"
        )
        self.assertEqual(self._err027(source), [])

    def test_reserved_underscores_are_silent(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            "    xdm.event.id = _id,\n"
            "    xdm.event.type = _log_type\n"
            ";\n"
        )
        self.assertEqual(self._err027(source), [])


class TestStructuralRules(unittest.TestCase):
    """The cheap structural checks (terminal semicolon, trailing comma,
    self-reference, quoted dataset, leading pipe, _time in MODEL) fire on
    minimal inline sources."""

    def _ids(self, source: str) -> list:
        return [v["rule_id"] for v in lint(source)]

    def test_err009_missing_semicolon(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "alter\n"
            '    tmp_x = json_extract_scalar(_raw_log, "$.x")\n'
            "| alter\n"
            "    xdm.event.id = tmp_x\n"
        )
        self.assertIn("ERR-009", self._ids(source))

    def test_err010_trailing_comma(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "alter\n"
            '    tmp_x = json_extract_scalar(_raw_log, "$.x")\n'
            "| alter\n"
            "    xdm.event.id = tmp_x,\n"
            ";\n"
        )
        self.assertIn("ERR-010", self._ids(source))

    def test_err011_self_reference(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "alter\n"
            '    tmp_x = json_extract_scalar(_raw_log, "$.x")\n'
            "| alter\n"
            "    xdm.target.ipv4 = coalesce(xdm.target.ipv4, tmp_x)\n"
            ";\n"
        )
        self.assertIn("ERR-011", self._ids(source))

    def test_warn015_quoted_dataset(self):
        source = (
            '[MODEL: dataset="demo_raw"]\n'
            "alter\n"
            '    tmp_x = json_extract_scalar(_raw_log, "$.x")\n'
            "| alter\n"
            "    xdm.event.id = tmp_x\n"
            ";\n"
        )
        self.assertIn("WARN-015", self._ids(source))

    def test_warn017_leading_pipe(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "| alter\n"
            '    tmp_x = json_extract_scalar(_raw_log, "$.x")\n'
            "| alter\n"
            "    xdm.event.id = tmp_x\n"
            ";\n"
        )
        self.assertIn("WARN-017", self._ids(source))

    def test_warn018_time_in_model(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "alter\n"
            '    _time = parse_epoch(json_extract_scalar(_raw_log, "$.ts"), "MILLIS")\n'
            "| alter\n"
            "    xdm.event.type = \"ALERT\"\n"
            ";\n"
        )
        self.assertIn("WARN-018", self._ids(source))


class TestGcRawGating(unittest.TestCase):
    """ERR-019 (unused temp) and ERR-025 (concat-hidden temp) are a hard
    block only on _gc_raw datasets. On a plain _raw dataset the same
    shapes are tolerated by the live tenant, so the linter stays silent."""

    def _ids(self, source: str) -> list:
        return [v["rule_id"] for v in lint(source)]

    def test_err019_fires_on_plain_raw(self):
        # Cortex rejects an unused field on EVERY dataset, so ERR-019 is no
        # longer scoped to _gc_raw: tmp_dead is extracted but never used.
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "alter\n"
            '    tmp_used = json_extract_scalar(_raw_log, "$.id"),\n'
            '    tmp_dead = json_extract_scalar(_raw_log, "$.never")\n'
            "| alter\n"
            "    xdm.event.id = tmp_used\n"
            ";\n"
        )
        self.assertIn("ERR-019", self._ids(source))

    def test_err019_silent_when_temp_feeds_a_chain(self):
        # A temp consumed through coalesce()/another temp is USED and must
        # not be flagged (guards the false positive the old reach analysis
        # produced on multi-line if() chains).
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "alter\n"
            '    tmp_a = json_extract_scalar(_raw_log, "$.a"),\n'
            '    tmp_b = json_extract_scalar(_raw_log, "$.b")\n'
            "| alter\n"
            "    tmp_user = coalesce(tmp_a, tmp_b)\n"
            "| alter\n"
            "    xdm.source.user.username = tmp_user\n"
            ";\n"
        )
        self.assertNotIn("ERR-019", self._ids(source))

    def test_err019_fires_on_gc_raw(self):
        source = (
            "[MODEL: dataset=demo_gc_raw]\n"
            "alter\n"
            '    tmp_used = json_extract_scalar(_raw_log, "$.id"),\n'
            '    tmp_dead = json_extract_scalar(_raw_log, "$.never")\n'
            "| alter\n"
            "    xdm.event.id = tmp_used\n"
            ";\n"
        )
        self.assertIn("ERR-019", self._ids(source))

    def test_err025_silent_on_plain_raw(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "alter\n"
            '    tmp_note = json_extract_scalar(_raw_log, "$.note")\n'
            "| alter\n"
            '    xdm.event.description = concat("Note: ", tmp_note)\n'
            ";\n"
        )
        self.assertNotIn("ERR-025", self._ids(source))


class TestWarn037SeverityLogLevel(unittest.TestCase):
    """WARN-037 fires on a log-level word in a VALUE position of an
    xdm.alert.severity assignment, but NOT on a comparison condition that
    tests for that word (the correct banding input)."""

    def _w37(self, source: str) -> list:
        return [v for v in lint(source) if v["rule_id"] == "WARN-037"]

    def test_value_position_fires(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    tmp_level = json_extract_scalar(_raw_log, "$.level")\n'
            "| alter\n"
            "    xdm.alert.severity = if(\n"
            '        tmp_level = "warning", "Warning",\n'
            '        tmp_level != null, tmp_level)\n'
            ";\n"
        )
        self.assertEqual(len(self._w37(source)), 1)

    def test_condition_only_is_silent(self):
        # The log-level word appears ONLY as a comparison input; the result
        # is a proper band. This is the correct banding and must not fire.
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    tmp_level = json_extract_scalar(_raw_log, "$.level")\n'
            "| alter\n"
            "    xdm.alert.severity = if(\n"
            '        tmp_level = "warning", "Medium",\n'
            '        tmp_level = "error", "High",\n'
            '        tmp_level != null, "Low")\n'
            ";\n"
        )
        self.assertEqual(self._w37(source), [])

    def test_direct_assignment_fires(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    tmp_level = json_extract_scalar(_raw_log, "$.level")\n'
            "| alter\n"
            '    xdm.alert.severity = "Error"\n'
            ";\n"
        )
        self.assertEqual(len(self._w37(source)), 1)

    def test_substring_value_not_flagged(self):
        # A descriptive value that merely contains a log-level word is fine.
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    tmp_n = json_extract_scalar(_raw_log, "$.n")\n'
            "| alter\n"
            '    xdm.alert.subcategory = "Error Page Probe",\n'
            "    xdm.alert.severity = if(tmp_n != null, \"High\")\n"
            ";\n"
        )
        self.assertEqual(self._w37(source), [])


class TestWarn038HostCompanion(unittest.TestCase):
    """WARN-038 fires when a named host has an IP but no ipv4_addresses
    companion, and stays silent once the companion is present."""

    def _w38(self, source: str) -> list:
        return [v for v in lint(source) if v["rule_id"] == "WARN-038"]

    def test_silent_when_the_hostname_names_the_observer(self):
        """On a flow-bearing record the hostname is routinely the device
        that EMITTED the log while the address is a flow endpoint. Hanging
        the flow address off the emitter is populated, non-empty and
        WRONG, and every host-based join would silently use it."""
        source = (
            "[MODEL: dataset=router_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    tmp_syslog_host = arrayindex(regextract(_raw_log, "> (\\S+) "), 0),\n'
            '    tmp_fw_dip = arrayindex(regextract(_raw_log, "TCP \\S+ (\\S+)"), 0)\n'
            "| alter\n"
            "    xdm.observer.name = tmp_syslog_host,\n"
            "    xdm.target.host.hostname = tmp_syslog_host,\n"
            "    xdm.target.ipv4 = tmp_fw_dip\n"
            ";\n"
        )
        self.assertEqual(self._w38(source), [])

    def test_silent_when_the_address_is_a_pad(self):
        """arraycreate("") is junk -- satisfying the advisory would turn a
        correct semantically-empty pad into a meaningless value."""
        source = (
            "[MODEL: dataset=ise_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    tmp_server = json_extract_scalar(_raw_log, "$.server"),\n'
            '    tmp_is_auth = if(_raw_log contains "AUTHEN", "y")\n'
            "| alter\n"
            "    xdm.target.host.hostname = tmp_server,\n"
            '    xdm.target.ipv4 = if(tmp_is_auth != null, "")\n'
            ";\n"
        )
        self.assertEqual(self._w38(source), [])

    def test_silent_on_a_bare_empty_string_address(self):
        source = (
            "[MODEL: dataset=ise_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    tmp_server = json_extract_scalar(_raw_log, "$.server")\n'
            "| alter\n"
            "    xdm.target.host.hostname = tmp_server,\n"
            '    xdm.target.ipv4 = ""\n'
            ";\n"
        )
        self.assertEqual(self._w38(source), [])

    def test_is_advisory_and_phrased_as_a_question(self):
        """A confident wrong fix here is invisible, so the finding must
        not read as an instruction."""
        source = (
            "[MODEL: dataset=agent_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    tmp_host = json_extract_scalar(_raw_log, "$.host"),\n'
            '    tmp_ip = json_extract_scalar(_raw_log, "$.host_ip")\n'
            "| alter\n"
            "    xdm.target.host.hostname = tmp_host,\n"
            "    xdm.target.ipv4 = tmp_ip\n"
            ";\n"
        )
        vios = self._w38(source)
        self.assertEqual(len(vios), 1)
        self.assertEqual(vios[0]["severity"], "info")
        self.assertIn("IF the two name the SAME host", vios[0]["message"])
        self.assertIn("does NOT apply", vios[0]["message"])

    def test_silent_when_companion_present(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    tmp_asset = json_extract_scalar(_raw_log, "$.asset"),\n'
            '    tmp_dst = json_extract_scalar(_raw_log, "$.dst")\n'
            "| alter\n"
            "    xdm.target.ipv4 = tmp_dst,\n"
            "    xdm.target.host.hostname = tmp_asset,\n"
            "    xdm.target.host.ipv4_addresses = if(tmp_dst != null, "
            "arraycreate(tmp_dst), null)\n"
            ";\n"
        )
        self.assertEqual(self._w38(source), [])

    def test_silent_when_no_hostname(self):
        # Only the IP, no named host -- nothing to companion.
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    tmp_dst = json_extract_scalar(_raw_log, "$.dst")\n'
            "| alter\n"
            "    xdm.target.ipv4 = tmp_dst\n"
            ";\n"
        )
        self.assertEqual(self._w38(source), [])


class TestInfo013OverMapping(unittest.TestCase):
    """INFO-013 fires on a temp spread across 3+ entity families, but not
    on the documented source/target mirror (two families), and not when
    the extra families are the event / observer metadata sinks."""

    def _i13(self, source: str) -> list:
        return [v for v in lint(source) if v["rule_id"] == "INFO-013"]

    def test_silent_on_source_target_mirror(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    tmp_ip = json_extract_scalar(_raw_log, "$.ip")\n'
            "| alter\n"
            "    xdm.source.ipv4 = tmp_ip,\n"
            "    xdm.target.ipv4 = tmp_ip\n"
            ";\n"
        )
        self.assertEqual(self._i13(source), [])

    def test_silent_when_extra_family_is_event(self):
        # A URL legitimately lives in target + network + the event summary;
        # the event sink must not push it over the threshold.
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    tmp_url = json_extract_scalar(_raw_log, "$.url")\n'
            "| alter\n"
            "    xdm.target.url = tmp_url,\n"
            "    xdm.network.http.url = tmp_url,\n"
            '    xdm.event.description = concat("URL: ", tmp_url)\n'
            ";\n"
        )
        self.assertEqual(self._i13(source), [])

    def test_silent_on_a_gate_conditioning_many_families(self):
        """A boolean gate decides WHETHER the story is padded, never what
        the fields hold. Conditional padding is the prescribed idiom for
        claiming a story only where its mandatory set can be populated,
        so one gate legitimately conditions several entity families."""
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    tmp_src_ip = arrayindex(regextract(_raw_log, "from (\\S+)"), 0)\n'
            "| alter\n"
            '    tmp_has_peer = if(tmp_src_ip != null, "y")\n'
            "| alter\n"
            "    xdm.network.protocol_layers = "
            'if(tmp_has_peer != null, arraycreate("IP")),\n'
            '    xdm.source.ipv6 = if(tmp_has_peer != null, ""),\n'
            '    xdm.target.ipv6 = if(tmp_has_peer != null, ""),\n'
            "    xdm.source.sent_bytes = if(tmp_has_peer != null, to_integer(0))\n"
            ";\n"
        )
        self.assertEqual(self._i13(source), [])

    def test_fires_when_the_gate_value_itself_is_mapped(self):
        """The exemption is positional, not name-based: the same temp used
        in a VALUE position across three families is still over-mapping."""
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    tmp_v = json_extract_scalar(_raw_log, "$.v")\n'
            "| alter\n"
            "    xdm.network.rule = tmp_v,\n"
            "    xdm.source.ipv6 = tmp_v,\n"
            "    xdm.target.ipv6 = tmp_v\n"
            ";\n"
        )
        self.assertEqual(len(self._i13(source)), 1)

    def test_counts_the_default_branch_as_a_value(self):
        """if(c, v, default) -- the trailing default reaches the field."""
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    tmp_g = json_extract_scalar(_raw_log, "$.g"),\n'
            '    tmp_v = json_extract_scalar(_raw_log, "$.v")\n'
            "| alter\n"
            '    xdm.network.rule = if(tmp_g != null, "x", tmp_v),\n'
            '    xdm.source.ipv6 = if(tmp_g != null, "x", tmp_v),\n'
            '    xdm.target.ipv6 = if(tmp_g != null, "x", tmp_v)\n'
            ";\n"
        )
        vios = self._i13(source)
        self.assertEqual(len(vios), 1)
        self.assertIn("tmp_v", vios[0]["message"])

    def test_fires_on_three_entity_families(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    tmp_thing = json_extract_scalar(_raw_log, "$.thing")\n'
            "| alter\n"
            "    xdm.source.user.username = tmp_thing,\n"
            "    xdm.target.user.username = tmp_thing,\n"
            "    xdm.alert.name = tmp_thing\n"
            ";\n"
        )
        hits = self._i13(source)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "info")


class TestWarn039PayloadInDescription(unittest.TestCase):
    """WARN-039 fires when the whole payload (via _raw_log or
    to_json_string) is assigned to xdm.event.description, and stays silent
    on a proper concat() summary over scalar temps."""

    def _w39(self, source: str) -> list:
        return [v for v in lint(source) if v["rule_id"] == "WARN-039"]

    def test_fires_on_to_json_string(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    tmp_d = json_extract_scalar(_raw_log, "$.d")\n'
            "| alter\n"
            "    xdm.event.description = to_json_string(detail)\n"
            ";\n"
        )
        self.assertEqual(len(self._w39(source)), 1)

    def test_silent_on_concat_summary(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    tmp_act = json_extract_scalar(_raw_log, "$.action")\n'
            "| alter\n"
            "    xdm.observer.action = tmp_act,\n"
            '    xdm.event.description = concat("Action: ", tmp_act)\n'
            ";\n"
        )
        self.assertEqual(self._w39(source), [])


class TestNetworkMandatoryListsInSync(unittest.TestCase):
    """The linter and profiler each carry a copy of the network mandatory
    set. Both must stay identical to the canonical list -- the "Mandatory
    fields" table in ``references/network-mapping.md`` -- so the advisory
    WARN-043 and the profiler checklist never drift apart. Fully
    self-contained: runs in a standalone checkout."""

    @classmethod
    def setUpClass(cls) -> None:
        reference = bundle_root() / "references" / "network-mapping.md"
        cls.expected = _mandatory_fields_from_reference(reference)
        if len(cls.expected) != 17:
            raise AssertionError(
                "expected 17 mandatory fields in the network reference "
                "table, found %d" % len(cls.expected)
            )
        cls.expected_http = _fields_from_reference_section(
            reference, "## The HTTP set"
        )
        if len(cls.expected_http) != 3:
            raise AssertionError(
                "expected 3 conditional HTTP fields in the network "
                "reference, found %d" % len(cls.expected_http)
            )

    def test_linter_list_matches_reference(self):
        self.assertEqual(set(_lint_mod._NETWORK_MANDATORY), self.expected)

    def test_profiler_list_matches_reference(self):
        prof = _load_profiler()
        self.assertEqual(set(prof._NETWORK_MANDATORY), self.expected)

    def test_http_set_is_not_in_the_unconditional_set(self):
        """The three HTTP leaves are conditional, so a rule with no HTTP
        layer must never be asked for them."""
        self.assertEqual(
            self.expected & self.expected_http, set(),
            "an HTTP leaf leaked back into the unconditional mandatory set",
        )

    def test_linter_http_list_matches_reference(self):
        self.assertEqual(
            set(_lint_mod._NETWORK_HTTP_MANDATORY), self.expected_http
        )

    def test_profiler_http_list_matches_reference(self):
        prof = _load_profiler()
        self.assertEqual(
            set(prof._NETWORK_HTTP_MANDATORY), self.expected_http
        )


class TestWarn043HttpSetIsConditional(unittest.TestCase):
    """The three xdm.network.http.* leaves complete the story for an
    HTTP-bearing event. A router SSH login or an SNMP failure has no HTTP
    layer, and padding a header name, header value and URL category onto
    it asserts a protocol the source never saw."""

    def _rule(self, extra: str = "") -> str:
        return (
            "[MODEL: dataset=router_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            "    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_NETWORK),\n"
            '    xdm.event.type = "network",\n'
            "    xdm.event.outcome = XDM_CONST.OUTCOME_SUCCESS,\n"
            "    xdm.network.ip_protocol = XDM_CONST.IP_PROTOCOL_TCP,\n"
            '    xdm.network.protocol_layers = arraycreate("IP", "TCP"),\n'
            '    xdm.source.host.device_id = "",\n'
            '    xdm.source.ipv4 = "192.0.2.1",\n'
            '    xdm.source.ipv6 = "",\n'
            "    xdm.source.is_internal_ip = false,\n"
            "    xdm.source.port = to_integer(1024),\n"
            "    xdm.source.sent_bytes = to_integer(0),\n"
            '    xdm.target.host.device_id = "",\n'
            '    xdm.target.ipv4 = "192.0.2.9",\n'
            '    xdm.target.ipv6 = "",\n'
            "    xdm.target.is_internal_ip = false,\n"
            "    xdm.target.port = to_integer(22),\n"
            "    xdm.target.sent_bytes = to_integer(0)"
            + extra
            + "\n;\n"
        )

    def _http_findings(self, source: str) -> list:
        return [
            v
            for v in lint(source)
            if v["rule_id"] == "WARN-043"
            and "network.http" in v["message"]
        ]

    def test_no_http_layer_is_not_asked_for_the_http_set(self):
        self.assertEqual(self._http_findings(self._rule()), [])

    def test_a_url_claims_an_http_layer(self):
        vios = self._http_findings(
            self._rule(',\n    xdm.target.url = "http://example.test/a"')
        )
        self.assertEqual(len(vios), 3, [v["message"] for v in vios])

    def test_another_http_field_claims_an_http_layer(self):
        vios = self._http_findings(
            self._rule(",\n    xdm.network.http.method = XDM_CONST.HTTP_METHOD_GET")
        )
        self.assertEqual(len(vios), 3, [v["message"] for v in vios])

    def test_http_in_protocol_layers_claims_an_http_layer(self):
        source = self._rule().replace(
            'arraycreate("IP", "TCP")', 'arraycreate("IP", "TCP", "HTTP")'
        )
        self.assertEqual(len(self._http_findings(source)), 3)

    def test_partial_http_set_is_completed(self):
        """Claim the layer and the set is all-or-nothing."""
        vios = self._http_findings(
            self._rule(',\n    xdm.network.http.url_category = '
                       "XDM_CONST.URL_CATEGORY_UNKNOWN")
        )
        self.assertEqual(len(vios), 2, [v["message"] for v in vios])
        self.assertTrue(all("http_header" in v["message"] for v in vios))

    def test_http_finding_explains_the_condition(self):
        vios = self._http_findings(
            self._rule(',\n    xdm.target.url = "http://example.test/a"')
        )
        self.assertIn("claims an HTTP layer", vios[0]["message"])


class TestWarn043NetworkMandatory(unittest.TestCase):
    """WARN-043 auto-detects a network event (conservatively: only the
    EVENT_TAG_NETWORK marker or a "network" event.type value) and warns,
    never blocks, per unmapped mandatory network-story field."""

    _COMPLETE_NETWORK = """[MODEL: dataset=acmefw_raw]
filter _raw_log != null
| alter
    tmp_act = json_extract_scalar(_raw_log, "$.action"),
    tmp_src = json_extract_scalar(_raw_log, "$.src_ip"),
    tmp_dst = json_extract_scalar(_raw_log, "$.dst_ip"),
    tmp_sport = json_extract_scalar(_raw_log, "$.src_port"),
    tmp_dport = json_extract_scalar(_raw_log, "$.dst_port"),
    tmp_sent = json_extract_scalar(_raw_log, "$.bytes_out"),
    tmp_rcvd = json_extract_scalar(_raw_log, "$.bytes_in")
| alter
    xdm.observer.vendor = "AcmeFW",
    xdm.event.type = "network",
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_NETWORK),
    xdm.event.outcome = if(tmp_act = "allow", XDM_CONST.OUTCOME_SUCCESS, tmp_act != null, XDM_CONST.OUTCOME_FAILED, XDM_CONST.OUTCOME_UNKNOWN),
    xdm.network.ip_protocol = XDM_CONST.IP_PROTOCOL_TCP,
    xdm.network.protocol_layers = arraycreate("TCP"),
    xdm.network.http.http_header.header = "",
    xdm.network.http.http_header.value = "",
    xdm.network.http.url_category = XDM_CONST.URL_CATEGORY_UNKNOWN,
    xdm.source.ipv4 = tmp_src,
    xdm.source.ipv6 = "",
    xdm.source.is_internal_ip = if(incidr(tmp_src, "10.0.0.0/8"), true, false),
    xdm.source.port = to_integer(to_number(tmp_sport)),
    xdm.source.sent_bytes = to_integer(to_number(tmp_sent)),
    xdm.source.host.device_id = "",
    xdm.target.ipv4 = tmp_dst,
    xdm.target.ipv6 = "",
    xdm.target.is_internal_ip = if(incidr(tmp_dst, "10.0.0.0/8"), true, false),
    xdm.target.port = to_integer(to_number(tmp_dport)),
    xdm.target.sent_bytes = to_integer(to_number(tmp_rcvd)),
    xdm.target.host.device_id = ""
;
"""

    def _w43(self, source: str) -> list:
        return [v for v in lint(source) if v["rule_id"] == "WARN-043"]

    def test_complete_rule_is_silent(self):
        self.assertEqual(self._w43(self._COMPLETE_NETWORK), [])

    def test_fires_per_missing_field(self):
        # The fixture maps type, tags and source.ipv4 -> 17 of 20 missing.
        source = (FIXTURES / "warn043_network_mandatory.xql").read_text(
            encoding="utf-8"
        )
        findings = self._w43(source)
        self.assertEqual(len(findings), 14, [f["message"] for f in findings])
        self.assertTrue(all(f["severity"] == "warning" for f in findings))

    def test_event_type_marker_alone_fires(self):
        # No tag, but event.type resolves to "network" -- still classified.
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    xdm.event.type = "network"\n;\n'
        )
        self.assertTrue(self._w43(source))

    def test_dual_rule_gets_both_advisories(self):
        source = (
            "[MODEL: dataset=vpn_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    tmp_u = json_extract_scalar(_raw_log, "$.user")\n'
            "| alter\n"
            '    xdm.event.type = "authentication",\n'
            "    xdm.event.tags = arraycreate("
            "XDM_CONST.EVENT_TAG_AUTHENTICATION, "
            "XDM_CONST.EVENT_TAG_NETWORK),\n"
            "    xdm.source.user.upn = tmp_u\n;\n"
        )
        ids = [v["rule_id"] for v in lint(source)]
        self.assertIn("WARN-042", ids)
        self.assertIn("WARN-043", ids)

    def test_duplicate_tags_assignment_flagged(self):
        source = (
            "[MODEL: dataset=vpn_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            "    xdm.event.tags = arraycreate("
            "XDM_CONST.EVENT_TAG_AUTHENTICATION),\n"
            "    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_NETWORK)\n"
            ";\n"
        )
        dup = [v for v in lint(source) if "more than once" in v["message"]]
        self.assertEqual(len(dup), 1)
        self.assertEqual(dup[0]["rule_id"], "WARN-053")

    def test_outcome_conformance_allows_unknown_pad(self):
        # OUTCOME_UNKNOWN is the documented network padding value; only a
        # const outside the network vocabulary is flagged.
        good = self._COMPLETE_NETWORK
        self.assertEqual(self._w43(good), [])
        bad = good.replace(
            "if(tmp_act = \"allow\", XDM_CONST.OUTCOME_SUCCESS, tmp_act != null, "
            "XDM_CONST.OUTCOME_FAILED, XDM_CONST.OUTCOME_UNKNOWN)",
            "XDM_CONST.OUTCOME_PARTIAL",
        )
        flagged = [v for v in self._w43(bad) if "OUTCOME_PARTIAL" in v["message"]]
        self.assertEqual(len(flagged), 1)

    def test_protocol_layers_scalar_literal_flagged(self):
        bad = self._COMPLETE_NETWORK.replace(
            'xdm.network.protocol_layers = arraycreate("TCP")',
            'xdm.network.protocol_layers = "TCP"',
        )
        flagged = [v for v in self._w43(bad) if "bare scalar" in v["message"]]
        self.assertEqual(len(flagged), 1)

    def test_non_network_rules_untouched(self):
        for fixture in ("clean_rule.xql", "warn042_auth_mandatory.xql"):
            with self.subTest(fixture=fixture):
                self.assertNotIn("WARN-043", _rule_ids(fixture))


class TestWorkedExamplesLintClean(unittest.TestCase):
    """Behaviour-parity guard: every shipped worked-example rule must lint
    clean (zero error-severity findings). This is the bundle's gold
    standard, so a future rule that mis-fires on a real production rule is
    caught here."""

    def _model_rule(self, md_path: Path) -> str:
        lines = md_path.read_text(encoding="utf-8").splitlines()
        start = next(
            (i for i, ln in enumerate(lines) if ln.startswith("[MODEL:")), None
        )
        if start is None:
            return ""
        end = next(
            (j for j in range(start, len(lines)) if lines[j].strip() == "```"),
            len(lines),
        )
        return "\n".join(lines[start:end]) + "\n"

    def test_all_worked_examples_clean(self):
        we_dir = bundle_root() / "references" / "worked-examples"
        md_files = sorted(we_dir.glob("*.md"))
        self.assertGreaterEqual(len(md_files), 5, "expected 5 walkthroughs")
        for md in md_files:
            rule = self._model_rule(md)
            if not rule.strip():
                continue
            with self.subTest(example=md.name):
                errors = [
                    v for v in lint(rule) if v["severity"] == "error"
                ]
                self.assertEqual(
                    errors,
                    [],
                    f"{md.name}: worked-example rule should lint clean, "
                    f"got {[(v['rule_id'], v['line']) for v in errors]}",
                )


class TestStoryMarkerEdgeCases(unittest.TestCase):
    """Edge-case guards for the story markers and value conformance."""

    def test_temp_names_do_not_fire_markers(self):
        # EC2: marker words are matched against quoted literals only -- a
        # temp named _network_type / _authentication_kind on the RHS must
        # not classify the rule into a story.
        base = (
            "[MODEL: dataset=x_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    {temp} = json_extract_scalar(_raw_log, "$.t")\n'
            "| alter\n"
            '    xdm.observer.vendor = "V",\n'
            "    xdm.event.type = {temp}\n;\n"
        )
        ids = _rule_ids_from(base.format(temp="tmp_network_type"))
        self.assertNotIn("WARN-043", ids)
        ids = _rule_ids_from(base.format(temp="tmp_authentication_kind"))
        self.assertNotIn("WARN-042", ids)
        # The literal forms must still classify.
        lit = base.replace("xdm.event.type = {temp}",
                           'xdm.event.type = "network"')
        self.assertIn("WARN-043", _rule_ids_from(lit.format(temp="tmp_t")))

    def test_static_upn_flagged(self):
        # EC3: upn is the story correlation key -- a static or empty
        # literal is as damaging as leaving it unmapped.
        rule = (
            "[MODEL: dataset=x_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    tmp_u = json_extract_scalar(_raw_log, "$.u")\n'
            "| alter\n"
            '    xdm.observer.vendor = "V",\n'
            '    xdm.event.type = "authentication",\n'
            '    xdm.source.user.upn = ""\n;\n'
        )
        hits = [v for v in lint(rule)
                if v["rule_id"] == "WARN-042"
                and "correlation key" in v["message"]]
        self.assertEqual(len(hits), 1, hits)
        # A raw-mapped upn is never second-guessed.
        ok = rule.replace('xdm.source.user.upn = ""',
                          "xdm.source.user.upn = tmp_u")
        self.assertEqual(
            [v for v in lint(ok) if "correlation key" in v["message"]], []
        )

    def test_bare_identifier_upn_flagged(self):
        # The upn must ALWAYS be UPN-shaped: a bare identifier whose name
        # does not itself indicate a UPN source is flagged; UPN-named
        # identifiers and the shape-guard idiom stay silent.
        base = (
            "[MODEL: dataset=x_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    {t} = json_extract_scalar(_raw_log, "$.u")\n'
            "| alter\n"
            '    xdm.observer.vendor = "V",\n'
            '    xdm.event.type = "authentication",\n'
            "    xdm.source.user.upn = {rhs}\n;\n"
        )

        def shape_hits(t, rhs):
            return [v for v in lint(base.format(t=t, rhs=rhs))
                    if "UPN-shaped" in v["message"]]

        self.assertEqual(len(shape_hits("tmp_user", "tmp_user")), 1)
        self.assertEqual(len(shape_hits("tmp_username", "tmp_username")), 1)
        self.assertEqual(shape_hits("tmp_upn", "tmp_upn"), [])
        self.assertEqual(shape_hits("tmp_email", "tmp_email"), [])
        guard = ('if(tmp_user contains "@", tmp_user, tmp_user != null, '
                 'concat(tmp_user, "@localhost"))')
        self.assertEqual(shape_hits("tmp_user", guard), [])

    def test_duplicate_tags_flagged_on_auth_only_rule(self):
        # EC7: the overwrite hazard exists without any network marker.
        rule = (
            "[MODEL: dataset=x_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    xdm.observer.vendor = "V",\n'
            '    xdm.event.type = "authentication",\n'
            "    xdm.event.tags = arraycreate("
            "XDM_CONST.EVENT_TAG_AUTHENTICATION),\n"
            "    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_MFA)\n;\n"
        )
        dups = [v for v in lint(rule) if "more than once" in v["message"]]
        self.assertEqual(len(dups), 1)
        # The duplicate-tags hazard is a tag-shape defect, not a member of
        # either story's mandatory set, so it carries its own id: sharing
        # one made the two impossible to filter or suppress separately.
        self.assertEqual(dups[0]["rule_id"], "WARN-053")
        # On a dual rule the finding is still reported exactly once,
        # never doubled by both story checks.
        dual = rule.replace("EVENT_TAG_MFA", "EVENT_TAG_NETWORK")
        dups2 = [v for v in lint(dual) if "more than once" in v["message"]]
        self.assertEqual(len(dups2), 1)
        # Same id on a dual rule too: one hazard, one code, reported once.
        self.assertEqual(dups2[0]["rule_id"], "WARN-053")


def _rule_ids_from(source: str) -> list:
    return [v["rule_id"] for v in lint(source)]


class TestMultiFormatExamplesFullyClean(unittest.TestCase):
    """The multi-format walkthroughs (06 Okta, 07 FortiGate, 08 TACACS+)
    are the story gold standards: EVERY rule block in them must lint with
    zero findings of ANY severity -- no WARN-042/043 stragglers, no
    envelope warnings -- not merely zero errors."""

    _EXAMPLES = (
        "06-okta-authentication-multi-format.md",
        "07-fortigate-network-multi-format.md",
        "08-cisco-tacacs-aaa-multi-shape.md",
    )

    def test_every_block_completely_clean(self):
        we_dir = bundle_root() / "references" / "worked-examples"
        for name in self._EXAMPLES:
            doc = (we_dir / name).read_text(encoding="utf-8")
            rules = re.findall(r"(\[MODEL:.*?;)", doc, re.DOTALL)
            self.assertTrue(rules, f"{name}: no MODEL blocks found")
            for i, rule in enumerate(rules):
                with self.subTest(example=name, block=i):
                    findings = lint(rule)
                    self.assertEqual(
                        findings,
                        [],
                        f"{name} block {i}: expected zero findings, got "
                        f"{[(v['rule_id'], v['line']) for v in findings]}",
                    )


class TestCascadeHint(unittest.TestCase):
    """INFO-012 fires when two parser-conformance violations land
    within a single source line of each other."""

    def test_info012_fires_on_adjacent_violations(self):
        source = (
            "[MODEL: dataset=demo_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            "    tmp_x = json_extract_scalar(_raw_log, \"$.x\"),\n"
            "    tmp_y = json_extract_scalar(_raw_log, \"$.y\")\n"
            "| alter\n"
            "    xdm.event.duration = tmp_x - tmp_y,\n"
            "    xdm.target.port = to_number(tmp_y)\n"
            ";\n"
        )
        ids = [v["rule_id"] for v in lint(source)]
        self.assertIn("ERR-012", ids)
        self.assertIn("ERR-015", ids)
        self.assertIn("INFO-012", ids)


class TestWarn044Process(unittest.TestCase):
    """WARN-044 is the process / command-execution advisory. Its one
    high-signal check is the executable-parent misuse: a value assigned to
    xdm.*.process.executable (a Number container) instead of a leaf."""

    def _rule(self, target: str) -> str:
        return (
            "[MODEL: dataset=acme_edr_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    tmp_p = json_extract_scalar(_raw_log, "$.image")\n'
            "| alter\n"
            f"    {target} = tmp_p,\n"
            "    xdm.source.process.name = tmp_p\n"
            ";\n"
        )

    def test_executable_parent_flagged(self):
        for side in ("source", "target", "intermediate"):
            vios = [
                v for v in lint(self._rule(f"xdm.{side}.process.executable"))
                if v["rule_id"] == "WARN-044"
            ]
            self.assertEqual(len(vios), 1, (side, vios))
            self.assertEqual(vios[0]["severity"], "warning")

    def test_executable_leaf_not_flagged(self):
        for leaf in ("executable.path", "executable.filename"):
            vios = [
                v for v in lint(self._rule(f"xdm.source.process.{leaf}"))
                if v["rule_id"] == "WARN-044"
            ]
            self.assertEqual(vios, [], (leaf, vios))

    def test_advisory_only_exit_zero(self):
        # WARN-044 is warning severity, so a rule whose only issue is the
        # executable-parent misuse must not raise an error-severity finding.
        vios = lint(self._rule("xdm.source.process.executable"))
        sev = {v["severity"] for v in vios if v["rule_id"] == "WARN-044"}
        self.assertEqual(sev, {"warning"})

    def test_silent_on_non_process_rule(self):
        ids = _rule_ids("clean_rule.xql")
        self.assertNotIn("WARN-044", ids)


class TestWarn045EventTagEnum(unittest.TestCase):
    """xdm.event.tags is a closed six-member enum; an invented tag is
    flagged (WARN-045, advisory), the six real members are not."""

    def _rule(self, tags_rhs: str) -> str:
        return (
            "[MODEL: dataset=x_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    xdm.observer.vendor = "V",\n'
            '    xdm.event.type = "network",\n'
            f"    xdm.event.tags = {tags_rhs}\n;\n"
        )

    def test_invented_tag_flagged(self):
        rule = self._rule(
            "arraycreate(XDM_CONST.EVENT_TAG_NETWORK, XDM_CONST.EVENT_TAG_IAM)"
        )
        vios = [v for v in lint(rule) if v["rule_id"] == "WARN-045"]
        self.assertEqual(len(vios), 1, vios)
        self.assertEqual(vios[0]["severity"], "warning")
        self.assertIn("EVENT_TAG_IAM", vios[0]["message"])

    def test_all_six_members_accepted(self):
        rule = self._rule(
            "arraycreate("
            "XDM_CONST.EVENT_TAG_AUTHENTICATION, XDM_CONST.EVENT_TAG_NETWORK, "
            "XDM_CONST.EVENT_TAG_CLOUD, XDM_CONST.EVENT_TAG_SAAS, "
            "XDM_CONST.EVENT_TAG_ONPREM, XDM_CONST.EVENT_TAG_VPN)"
        )
        self.assertNotIn("WARN-045", _rule_ids_from(rule))

    def test_per_record_if_chain_accepted(self):
        rule = self._rule(
            "if(tmp_x != null, "
            "arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION, "
            "XDM_CONST.EVENT_TAG_SAAS), null)"
        )
        self.assertNotIn("WARN-045", _rule_ids_from(rule))


class TestWarn046CatchAll(unittest.TestCase):
    """A content filter beyond `_raw_log != null` drops records unless the
    rule carries the GOCORTEX_UNMODELLED catch-all sentinel (WARN-046,
    advisory)."""

    def test_content_filter_without_catchall_flagged(self):
        rule = (
            "[MODEL: dataset=x_raw]\n"
            "filter _raw_log != null\n"
            '| filter _raw_log contains "type=AUTH"\n'
            "| alter\n"
            '    xdm.observer.vendor = "V"\n;\n'
        )
        vios = [v for v in lint(rule) if v["rule_id"] == "WARN-046"]
        self.assertEqual(len(vios), 1, vios)
        self.assertEqual(vios[0]["severity"], "warning")

    def test_content_filter_with_sentinel_not_flagged(self):
        rule = (
            "[MODEL: dataset=x_raw]\n"
            "filter _raw_log != null\n"
            '| filter _raw_log contains "type=AUTH"\n'
            "| alter\n"
            '    xdm.observer.vendor = "V",\n'
            '    xdm.event.original_event_type = "GOCORTEX_UNMODELLED"\n;\n'
        )
        self.assertNotIn("WARN-046", _rule_ids_from(rule))

    def test_null_guard_only_not_flagged(self):
        rule = (
            "[MODEL: dataset=x_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    xdm.observer.vendor = "V"\n;\n'
        )
        self.assertNotIn("WARN-046", _rule_ids_from(rule))


class TestErr028ReservedUnderscore(unittest.TestCase):
    """A skill-authored scratch temp must use tmp_; a _-prefixed temp is a
    hard error (ERR-028) because the _ namespace is reserved for platform /
    system fields. Reading _raw_log / _time is fine."""

    def _ids(self, source: str) -> list:
        return [v["rule_id"] for v in lint(source)]

    def test_underscore_temp_flagged(self):
        rule = (
            "[MODEL: dataset=x_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n"
            '    _user = arrayindex(regextract(_raw_log, "user=(\\w+)"), 0)\n'
            "| alter\n"
            "    xdm.source.user.username = _user\n;\n"
        )
        vios = [v for v in lint(rule) if v["rule_id"] == "ERR-028"]
        self.assertTrue(vios)
        self.assertEqual(vios[0]["severity"], "error")

    def test_tmp_temp_not_flagged(self):
        rule = (
            "[MODEL: dataset=x_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n"
            '    tmp_user = arrayindex(regextract(_raw_log, "user=(\\w+)"), 0)\n'
            "| alter\n"
            "    xdm.source.user.username = tmp_user\n;\n"
        )
        self.assertNotIn("ERR-028", self._ids(rule))

    def test_reading_platform_underscore_field_not_flagged(self):
        # Reading _raw_log (and the filter guard) must never trip ERR-028;
        # only ASSIGNING a _-prefixed field does.
        rule = (
            "[MODEL: dataset=x_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n"
            "    xdm.event.description = _raw_log\n;\n"
        )
        self.assertNotIn("ERR-028", self._ids(rule))

    def test_time_assignment_stays_warn018_not_err028(self):
        # _time has its own advisory WARN-018; ERR-028 exempts it to avoid
        # double-reporting the same line.
        rule = (
            "[MODEL: dataset=x_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n"
            "    _time = to_timestamp(1700000000)\n;\n"
        )
        ids = self._ids(rule)
        self.assertIn("WARN-018", ids)
        self.assertNotIn("ERR-028", ids)


class TestWarn048IncompleteHttpMap(unittest.TestCase):
    """WARN-048 flags an xdm.network.http.response_code if()-chain that maps
    fewer status codes than the authoritative crosswalk, and stays silent on
    the complete chain and on a single-const assignment."""

    def _ids(self, source: str) -> list:
        return [v["rule_id"] for v in lint(source)]

    _HEAD = (
        "[MODEL: dataset=web_raw]\nfilter\n    _raw_log != null\n| alter\n"
        "    tmp_status = to_integer(to_number(_raw_log))\n| alter\n"
    )

    def _complete_chain(self) -> str:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "http_status_map", bundle_root() / "scripts" / "http_status_map.py")
        mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(mod)
        return mod.render("tmp_status")

    def test_partial_multiline_chain_flagged(self):
        rule = (
            self._HEAD
            + "    xdm.network.http.response_code = if(\n"
            "        tmp_status = 200, XDM_CONST.HTTP_RSP_CODE_OK,\n"
            "        tmp_status = 404, XDM_CONST.HTTP_RSP_CODE_NOT_FOUND,\n"
            "        tmp_status = 500, "
            "XDM_CONST.HTTP_RSP_CODE_INTERNAL_SERVER_ERROR)\n;\n"
        )
        self.assertIn("WARN-048", self._ids(rule))

    def test_partial_single_line_chain_flagged(self):
        rule = (
            self._HEAD
            + "    xdm.network.http.response_code = if(tmp_status = 200, "
            "XDM_CONST.HTTP_RSP_CODE_OK, null)\n;\n"
        )
        self.assertIn("WARN-048", self._ids(rule))

    def test_complete_chain_not_flagged(self):
        rule = self._HEAD + "    " + self._complete_chain() + "\n;\n"
        self.assertNotIn("WARN-048", self._ids(rule))

    def test_single_const_not_flagged(self):
        # A fixed-response source mapping to one constant is not a partial
        # chain over status codes.
        rule = (
            "[MODEL: dataset=web_raw]\nfilter\n    _raw_log != null\n| alter\n"
            "    xdm.network.http.response_code = XDM_CONST.HTTP_RSP_CODE_OK\n;\n"
        )
        self.assertNotIn("WARN-048", self._ids(rule))


class TestWarn050EndpointNoOperation(unittest.TestCase):
    """WARN-050 flags an endpoint event (a process / file / registry entity is
    mapped) that never assigns xdm.event.operation, and stays silent when the
    operation verb is present or when the rule is not an endpoint event."""

    def _ids(self, source: str) -> list:
        return [v["rule_id"] for v in lint(source)]

    _HEAD = "[MODEL: dataset=win_raw]\nfilter\n    _raw_log != null\n| alter\n"

    def test_process_without_operation_flagged(self):
        rule = (
            self._HEAD
            + '    tmp_img = json_extract_scalar(_raw_log, "$.Image")\n'
            "| alter\n"
            "    xdm.source.process.executable.path = tmp_img\n;\n"
        )
        self.assertIn("WARN-050", self._ids(rule))

    def test_registry_without_operation_flagged(self):
        rule = (
            self._HEAD
            + '    tmp_k = json_extract_scalar(_raw_log, "$.TargetObject")\n'
            "| alter\n"
            "    xdm.target.registry.key = tmp_k\n;\n"
        )
        self.assertIn("WARN-050", self._ids(rule))

    def test_process_with_operation_not_flagged(self):
        rule = (
            self._HEAD
            + '    tmp_img = json_extract_scalar(_raw_log, "$.Image")\n'
            "| alter\n"
            "    xdm.source.process.executable.path = tmp_img,\n"
            "    xdm.event.operation = XDM_CONST.OPERATION_TYPE_PROCESS_CREATE\n;\n"
        )
        self.assertNotIn("WARN-050", self._ids(rule))

    def test_non_endpoint_rule_not_flagged(self):
        rule = (
            self._HEAD
            + '    tmp_ip = json_extract_scalar(_raw_log, "$.src")\n'
            "| alter\n"
            "    xdm.source.ipv4 = tmp_ip\n;\n"
        )
        self.assertNotIn("WARN-050", self._ids(rule))


class TestWarn049HardcodedLiteral(unittest.TestCase):
    """WARN-049 flags a hardcoded sample-derived literal (path / host / IP /
    ID) baked into a contains / = branch, and stays silent on standard
    tokens, identity strings and XDM_CONST values."""

    def _ids(self, source: str) -> list:
        return [v["rule_id"] for v in lint(source)]

    _HEAD = "[MODEL: dataset=x_raw]\nfilter\n    _raw_log != null\n| alter\n"

    def test_path_literal_flagged(self):
        rule = (
            self._HEAD
            + '    tmp_t = if(requestUri contains "/keys/", "appkey")\n'
            "| alter\n    xdm.alert.subcategory = tmp_t\n;\n"
        )
        self.assertIn("WARN-049", self._ids(rule))

    def test_ip_literal_flagged(self):
        rule = (
            self._HEAD
            + '    tmp_g = if(tmp_h = "10.0.0.5", "gw", tmp_h)\n'
            "| alter\n    xdm.source.host.hostname = tmp_g\n;\n"
        )
        self.assertIn("WARN-049", self._ids(rule))

    def test_standard_token_not_flagged(self):
        rule = (
            self._HEAD
            + '    tmp_svc = if(lowercase(tmp_raw) contains "kerberos", '
            '"Kerberos", tmp_raw)\n'
            "| alter\n    xdm.auth.service = tmp_svc\n;\n"
        )
        self.assertNotIn("WARN-049", self._ids(rule))

    def test_identity_and_const_not_flagged(self):
        rule = (
            self._HEAD
            + '    tmp_o = if(tmp_r contains "PERMIT", '
            "XDM_CONST.OUTCOME_SUCCESS, XDM_CONST.OUTCOME_FAILED)\n"
            "| alter\n"
            '    xdm.observer.vendor = "Cisco",\n'
            '    xdm.observer.product = "SecureX",\n'
            '    xdm.event.type = "authentication",\n'
            "    xdm.event.outcome = tmp_o\n;\n"
        )
        self.assertNotIn("WARN-049", self._ids(rule))

    def test_regex_match_operand_not_flagged(self):
        # A `~= "regex"` operand is a regular expression, not a customer
        # literal, even when it contains a slash (e.g. Azure operationName
        # verb suffixes). WARN-049 must not treat it as a hardcoded value.
        rule = (
            self._HEAD
            + '    tmp_v = if(tmp_op ~= "/write$", "w", tmp_op ~= "/delete$", "d")\n'
            "| alter\n    xdm.event.description = tmp_v\n;\n"
        )
        self.assertNotIn("WARN-049", self._ids(rule))


class TestWarn051UnguardedProseAccount(unittest.TestCase):
    """An account captured from qualifier-bearing prose, with an unquoted
    group directly after the qualifier word and no guard, yields the
    qualifier itself on a masked line -- 'invalid' or 'Masked', neither an
    account. A quote-delimited or key= capture is bounded and safe, and a
    rule that guards the value is fine, so both stay silent. Advisory: the
    absence of a guard is inferred."""

    def _rule(self, pattern: str, guard: bool = False) -> str:
        mid = (
            '    tmp_a = if(tmp_raw != "invalid" and tmp_raw != "Masked", tmp_raw)\n'
            if guard
            else "    tmp_a = tmp_raw\n"
        )
        return (
            "[MODEL: dataset=x_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n"
            f'    tmp_raw = arrayindex(regextract(_raw_log, "{pattern}"), 0)\n'
            "| alter\n" + mid + "| alter\n"
            "    xdm.source.user.username = tmp_a\n;\n"
        )

    def test_unquoted_capture_after_qualifier_flagged(self):
        ids = _rule_ids_from(self._rule(r"password for (\S+)"))
        self.assertIn("WARN-051", ids)

    def test_bare_user_prefix_flagged(self):
        self.assertIn("WARN-051", _rule_ids_from(self._rule(r"user (\S+)")))

    def test_guarded_capture_is_silent(self):
        ids = _rule_ids_from(self._rule(r"password for (\S+)", guard=True))
        self.assertNotIn("WARN-051", ids)

    def test_quote_delimited_capture_is_silent(self):
        """The quotes bound the value, so a qualifier word cannot be
        captured in its place."""
        ids = _rule_ids_from(self._rule(r"User\s+'(\S+)'"))
        self.assertNotIn("WARN-051", ids)

    def test_key_anchored_capture_is_silent(self):
        ids = _rule_ids_from(self._rule(r"\buser=([^\s]+)"))
        self.assertNotIn("WARN-051", ids)

    def test_reported_once_per_capture_not_per_field(self):
        """username and upn commonly take the same temp; the root cause is
        the one missing guard, so it is reported once."""
        rule = (
            "[MODEL: dataset=x_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n"
            '    tmp_raw = arrayindex(regextract(_raw_log, "password for (\\S+)"), 0)\n'
            "| alter\n"
            "    xdm.source.user.username = tmp_raw,\n"
            "    xdm.source.user.upn = tmp_raw\n;\n"
        )
        vios = [v for v in lint(rule) if v["rule_id"] == "WARN-051"]
        self.assertEqual(len(vios), 1, vios)
        self.assertEqual(vios[0]["severity"], "warning")

    def test_non_syslog_structured_source_is_silent(self):
        rule = (
            "[MODEL: dataset=x_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n"
            '    tmp_a = json_extract_scalar(_raw_log, "$.user")\n'
            "| alter\n    xdm.source.user.username = tmp_a\n;\n"
        )
        self.assertNotIn("WARN-051", _rule_ids_from(rule))


class TestWarn052CaseQualifiedCapture(unittest.TestCase):
    """XQL folds case, so an uppercase character class does not restrict
    what a group captures. A capture reached through whitespace with no
    literal anchor and qualified only by case takes whatever token sits in
    that position, leaving the field populated with a plausible but wrong
    value. A group introduced by a literal is structurally anchored and
    stays silent."""

    def _rule(self, pattern: str) -> str:
        return (
            "[MODEL: dataset=x_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n"
            f'    tmp_tag = arrayindex(regextract(_raw_log, "{pattern}"), 0)\n'
            "| alter\n    xdm.event.original_event_type = tmp_tag\n;\n"
        )

    def test_positional_case_qualified_capture_flagged(self):
        ids = _rule_ids_from(self._rule(r"\s+\S+\s+([A-Z][A-Z0-9_]{3,}):"))
        self.assertIn("WARN-052", ids)

    def test_purely_positional_uppercase_capture_flagged(self):
        ids = _rule_ids_from(self._rule(r"^\S+\s+\S+\s+([A-Z]+)"))
        self.assertIn("WARN-052", ids)

    def test_sigil_anchored_capture_is_silent(self):
        """A % sigil plus the severity digit identify the token."""
        ids = _rule_ids_from(self._rule(r"%([\w\-]+) :"))
        self.assertNotIn("WARN-052", ids)

    def test_literal_word_anchored_capture_is_silent(self):
        ids = _rule_ids_from(self._rule(r"CHECK_HOST\s*\S*\s*([A-Z]+)\s*"))
        self.assertNotIn("WARN-052", ids)

    def test_label_anchored_capture_is_silent(self):
        ids = _rule_ids_from(self._rule(r"descr: ([A-Z]{2,})\s/"))
        self.assertNotIn("WARN-052", ids)

    def test_enumerated_vendor_tags_are_silent(self):
        """The alternation IS the qualifier, so no case reliance remains."""
        ids = _rule_ids_from(
            self._rule(r"\s(PFE_FW_SYSLOG_ETH_IP|DDOS_PROTOCOL_VIOLATION_SET):")
        )
        self.assertNotIn("WARN-052", ids)

    def test_severity_is_advisory(self):
        vios = [
            v
            for v in lint(self._rule(r"\s+\S+\s+([A-Z][A-Z0-9_]{3,}):"))
            if v["rule_id"] == "WARN-052"
        ]
        self.assertEqual(len(vios), 1, vios)
        self.assertEqual(vios[0]["severity"], "warning")


class TestWarn054GreedyTailComparisonKey(unittest.TestCase):
    """A capture that runs to the end of the line inherits any trailing
    whitespace the device emitted. The field stays populated, non-empty
    and non-sentinel, so only an exact comparison reveals it -- and that
    fails as an empty result set rather than an error. Scoped to fields
    that are compared, not displayed."""

    def _rule(self, pattern: str, field: str = "xdm.target.process.command_line") -> str:
        return (
            "[MODEL: dataset=x_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n"
            f'    tmp_v = arrayindex(regextract(_raw_log, "{pattern}"), 0)\n'
            f"| alter\n    {field} = tmp_v\n;\n"
        )

    def test_greedy_tail_into_command_line_flagged(self):
        ids = _rule_ids_from(self._rule(r":\s+\S*[#>]\s+(.+)$"))
        self.assertIn("WARN-054", ids)

    def test_star_tail_without_dollar_flagged(self):
        ids = _rule_ids_from(self._rule(r"cmd_data=(.*)"))
        self.assertIn("WARN-054", ids)

    def test_greedy_tail_into_original_event_type_flagged(self):
        ids = _rule_ids_from(
            self._rule(r"STP State \->\s*(.+)", "xdm.event.original_event_type")
        )
        self.assertIn("WARN-054", ids)

    def test_delimiter_closed_capture_is_silent(self):
        """A group closed by a quote cannot take whitespace outside it."""
        ids = _rule_ids_from(self._rule(r"command\s+'(.+)'"))
        self.assertNotIn("WARN-054", ids)

    def test_content_terminated_capture_is_silent(self):
        ids = _rule_ids_from(self._rule(r":\s+\S*[#>]\s+(.*\S)"))
        self.assertNotIn("WARN-054", ids)

    def test_displayed_field_is_silent(self):
        """A description legitimately wants the tail."""
        ids = _rule_ids_from(self._rule(r"reason=(.+)$", "xdm.event.description"))
        self.assertNotIn("WARN-054", ids)

    def test_alias_is_followed_and_reported_once(self):
        rule = (FIXTURES / "warn054_greedy_tail_comparison_key.xql").read_text()
        vios = [v for v in lint(rule) if v["rule_id"] == "WARN-054"]
        self.assertEqual(len(vios), 1, vios)
        self.assertEqual(vios[0]["severity"], "warning")
        self.assertIn("command_line", vios[0]["message"])

    def test_recommendation_carries_the_corrected_pattern(self):
        vios = [
            v for v in lint(self._rule(r":\s+\S*[#>]\s+(.+)$"))
            if v["rule_id"] == "WARN-054"
        ]
        self.assertIn(r"(.*\S)", vios[0]["recommendation"])


class TestWarn047PrependFragile(unittest.TestCase):
    """A syslog rule must extract identically whether the record arrives
    direct or behind a relay-prepended header. A ^-anchored / positional
    body capture (or an everything-after-the-header grab) breaks on the
    other form, so it is BLOCKED as ERR-030 (error severity, exit 1 --
    modelling both arrival forms in one rule is a hard requirement, not
    an advisory). The relay-aware envelope captures and token-anchored
    bodies are exempt; non-syslog rules are never examined."""

    def _syslog_head(self) -> str:
        # A rule is 'syslog' once it carries the PRI/envelope capture.
        return (
            "[MODEL: dataset=x_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n"
            '    tmp_pri = to_integer(to_number(arrayindex(regextract('
            '_raw_log, "^<(\\d{1,3})>"), 0))),\n'
        )

    def test_positional_body_capture_flagged(self):
        rule = (
            self._syslog_head()
            + '    tmp_m = arrayindex(regextract(_raw_log, '
            '"^%(\\w+-\\d-\\w+):"), 0)\n'
            "| alter\n"
            "    xdm.event.original_event_type = tmp_m,\n"
            "    xdm.event.log_level = if(tmp_pri != null, "
            "XDM_CONST.LOG_LEVEL_INFORMATIONAL)\n;\n"
        )
        vios = [v for v in lint(rule) if v["rule_id"] == "ERR-030"]
        self.assertEqual(len(vios), 1, vios)
        self.assertEqual(vios[0]["severity"], "error")

    def test_escaped_angle_bracket_envelope_is_exempt(self):
        """`^\\<` is the same envelope anchor as `^<` -- XQL rules commonly
        escape it -- so it must not be flagged. Before this was fixed the
        escape defeated the exemption and a correctly written envelope
        capture was reported as prepend-fragile, which now blocks."""
        rule = (
            "[MODEL: dataset=x_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n"
            '    tmp_pri = to_integer(arrayindex(regextract('
            '_raw_log, "^\\<(\\d{1,3})\\>"), 0))\n'
            "| alter\n"
            "    xdm.event.log_level = if(tmp_pri != null, "
            "XDM_CONST.LOG_LEVEL_INFORMATIONAL)\n;\n"
        )
        self.assertNotIn("ERR-030", _rule_ids_from(rule))

    def test_everything_after_header_grab_flagged(self):
        rule = (
            self._syslog_head()
            + '    tmp_body = arrayindex(regextract(_raw_log, '
            '"^<\\d{1,3}>[A-Za-z]{3}\\s+\\d+\\s+[\\d:]+\\s+\\S+\\s+(.*)"), 0)\n'
            "| alter\n"
            "    xdm.event.description = tmp_body,\n"
            "    xdm.event.log_level = if(tmp_pri != null, "
            "XDM_CONST.LOG_LEVEL_INFORMATIONAL)\n;\n"
        )
        self.assertIn("ERR-030", _rule_ids_from(rule))

    def test_token_anchored_body_not_flagged(self):
        rule = (
            self._syslog_head()
            + '    tmp_m = arrayindex(regextract(_raw_log, '
            '"%(\\w+-\\d-\\w+):"), 0)\n'
            "| alter\n"
            "    xdm.event.original_event_type = tmp_m,\n"
            "    xdm.event.log_level = if(tmp_pri != null, "
            "XDM_CONST.LOG_LEVEL_INFORMATIONAL)\n;\n"
        )
        self.assertNotIn("ERR-030", _rule_ids_from(rule))

    def test_relay_aware_envelope_not_flagged(self):
        rule = (
            "[MODEL: dataset=x_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n"
            '    tmp_host = arrayindex(regextract(_raw_log, '
            '"^.*<\\d{1,3}>[A-Za-z]{3}\\s+\\d+\\s+[\\d:]+\\s+(\\S+)\\s"), 0)\n'
            "| alter\n"
            "    xdm.observer.name = tmp_host\n;\n"
        )
        self.assertNotIn("ERR-030", _rule_ids_from(rule))

    def test_non_syslog_positional_capture_not_flagged(self):
        # A CLF web-access rule anchors the client IP on ^ but is not syslog,
        # so the prepend rule does not apply.
        rule = (
            "[MODEL: dataset=clf_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n"
            '    tmp_ip = arrayindex(regextract(_raw_log, '
            '"^(\\d{1,3}(?:\\.\\d{1,3}){3})"), 0)\n'
            "| alter\n"
            "    xdm.source.ipv4 = tmp_ip\n;\n"
        )
        self.assertNotIn("ERR-030", _rule_ids_from(rule))


class TestErr034UnquotedReservedRead(unittest.TestCase):
    """ERR-034: reading a raw column whose NAME is a query-language
    construct, without backticks, fails the pack install with an opaque
    101704. The escape is a backtick, so the quoted form is correct and
    must stay silent."""

    def _rule(self, body: str) -> str:
        return (
            "[MODEL: dataset=acme_demo_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n"
            f"    {body}\n"
            "| alter\n"
            "    xdm.event.id = tmp_x\n;\n"
        )

    def test_fixture_fires_once_at_error_severity(self):
        source = (FIXTURES / "err034_unquoted_reserved_read.xql").read_text(
            encoding="utf-8"
        )
        vios = [v for v in lint(source) if v["rule_id"] == "ERR-034"]
        self.assertEqual(len(vios), 1, [v["message"] for v in vios])
        self.assertEqual(vios[0]["severity"], "error")

    def test_reserved_set_membership_is_pinned(self):
        # This set is MIRRORED by hand into RESERVED_COLUMNS in the
        # content-pack bundle's scripts/preflight_release.py, and neither
        # repository can see the other. The two tests below iterate a
        # hard-coded name list, so both would have passed a tenth member
        # without a word -- which is how a mirrored list drifts while each
        # side believes itself current, exactly what happened before 1.9.1
        # when that gate's patterns were still case-sensitive. This pin is
        # what routed the 2.1.3 `config` report to both bundles instead of
        # to one, so it has now earned its keep rather than merely being
        # prudent.
        self.assertEqual(
            _lint_mod._ERR034_RESERVED,
            ("tag", "view", "config", "target", "fields", "transaction",
             "table", "filter", "in"),
            "ERR-034's reserved set changed. Update this pin, the two "
            "name lists below, and RESERVED_COLUMNS in the content-pack "
            "bundle's scripts/preflight_release.py -- then MESSAGE that "
            "bundle in the same change, per SKILL.md 'Called as an "
            "instrument'. Note that `out` is deliberately excluded and "
            "must not be added on symmetry with `in`.",
        )

    def test_every_reserved_name_flagged_bare(self):
        # The set is corpus-derived, not guessed. Each must fire when read
        # bare in value position.
        for name in ("tag", "view", "config", "target", "fields",
                     "transaction", "table", "filter", "in"):
            ids = _rule_ids_from(self._rule(f"tmp_x = {name}"))
            self.assertIn("ERR-034", ids, f"{name} should fire: {ids}")

    def test_backticked_read_is_the_correct_form_and_silent(self):
        # 328 shipped upstream rules read these columns backticked and never
        # bare. Flagging the escape would flag the fix.
        for name in ("tag", "view", "config", "target", "fields",
                     "transaction", "table", "filter", "in"):
            ids = _rule_ids_from(self._rule(f"tmp_x = `{name}`"))
            self.assertNotIn("ERR-034", ids, f"`{name}` must be silent: {ids}")

    def test_membership_operator_in_is_not_a_column_read(self):
        # `in` is reserved AND is the membership operator, and the reason it
        # was excluded from the set until 1.9.1 was a fear of exactly this
        # firing. It does not: the read patterns only match in VALUE
        # position, and the operator follows an identifier. Measured at 570
        # operator uses in the corpus with zero matches.
        for expr in ('tmp_x = if(evt in ("a", "b"), "y")',
                     'tmp_x = if(evt not in ("a"), "y")'):
            ids = _rule_ids_from(self._rule(expr))
            self.assertNotIn("ERR-034", ids, f"{expr} must be silent: {ids}")

    def test_the_code_registry_names_every_reserved_word(self):
        # The --list-codes docstring is a FOURTH copy of this set, and
        # SKILL.md points authors at it as the single source of truth for
        # the code list. Nothing compared it to the tuple, so it lost `in`
        # in 1.9.1 and still said seven names five releases later -- an
        # author following the documented instruction read a list one name
        # short of the check that was actually running. A copy is only
        # safe if something compares it, which is the same argument that
        # put TestReadmeCodeListMatchesTheLinter in test_doc_consistency.
        # Parse the parenthesised list rather than searching the prose. A
        # substring test over the description is worthless for the short
        # names -- `in` occurs inside "install", "naming" and "line", so
        # the check would have passed throughout the five releases the
        # list was actually wrong, which is the one case it exists for.
        entry = next(
            e for e in _lint_mod.code_table() if e["code"] == "ERR-034"
        )
        listed = re.search(r"construct \(([^)]*)\)", entry["description"])
        self.assertIsNotNone(
            listed,
            "ERR-034's --list-codes description no longer carries a "
            f"`construct (...)` name list: {entry['description']}",
        )
        self.assertEqual(
            {n.strip() for n in listed.group(1).split("/")},
            set(_lint_mod._ERR034_RESERVED),
            "ERR-034's --list-codes name list disagrees with "
            "_ERR034_RESERVED. It is what `scripts/lint_rule.py "
            "--list-codes` prints and what SKILL.md sends authors to, so "
            "a name missing here is a name the documentation denies is "
            "reserved.",
        )

    def test_config_stage_keyword_is_not_a_column_read(self):
        # `config` is reserved AND names a query STAGE, the same collision
        # `in` has with the membership operator. Every settings form must
        # stay silent; the corpus carries 12 of them in shipped MODEL
        # rules, all `config case_sensitive = true`.
        #
        # The PARENTHESISED cases are the ones that matter. They put the
        # word directly after '(' and therefore into value position, and
        # they fired before the stage lookahead was added -- a false
        # ERR-034 on valid XQL, which is the failure mode that teaches an
        # author to mute the checker.
        for stage in ("| config case_sensitive = true",
                      "| config timeframe = 24h",
                      "| config max_runtime_minutes = 5",
                      "| config case_sensitive = false, timeframe = 7d",
                      "    (config timeframe = 24h",
                      "    (config case_sensitive = false, timeframe = 7d"):
            source = (
                "[MODEL: dataset=acme_demo_raw]\n"
                "filter\n    _raw_log != null\n"
                "| alter\n    tmp_x = api_key_id\n"
                "| alter\n    xdm.event.id = tmp_x\n"
                f"{stage}\n;\n"
            )
            ids = _rule_ids_from(source)
            self.assertNotIn("ERR-034", ids, f"{stage} must be silent: {ids}")

    def test_config_read_as_a_column_still_fires(self):
        # The shape that cost five tenant uploads on a GitHub Enterprise
        # Cloud audit source: a raw column called `config`, read bare
        # inside json_extract_scalar. The stage lookahead above must not
        # have bought this silence too -- a column read is followed by
        # ',', ')' or an operator, never by an identifier and an '='.
        for expr in ('tmp_x = json_extract_scalar(config, "$.url")',
                     "tmp_x = to_number(config)",
                     "tmp_x = arrayindex(config, 0)",
                     "tmp_x = config"):
            ids = _rule_ids_from(self._rule(expr))
            self.assertIn("ERR-034", ids, f"{expr} should fire: {ids}")

    def test_out_is_an_ordinary_column_name(self):
        # `out` always arrives paired with `in` on a CEF firewall source, so
        # it is tempting to reserve it on symmetry. The corpus says no: it
        # is read BARE in value position 8 times in shipped upstream rules
        # (to_integer(out) on the sent-bytes mapping) and never backticked,
        # which is the timestamp/dst pattern rather than the target one.
        # Reserving it would call 8 rules that demonstrably install broken.
        ids = _rule_ids_from(self._rule("tmp_x = to_number(out)"))
        self.assertNotIn("ERR-034", ids, ids)

    def test_controls_not_flagged(self):
        # Words that merely LOOK like query constructs. timestamp (39 bare
        # value-position reads) and dst (146) are demonstrably ordinary
        # column names. contains, call and values are untested rather than
        # proven safe -- the corpus holds no column of those names at all
        # (1428 of contains's 1429 occurrences are the OPERATOR) -- but
        # flagging any of them would still be a false positive, so the
        # check must stay silent on all six.
        for name in ("timestamp", "call", "contains", "dst", "values",
                     "count"):
            ids = _rule_ids_from(self._rule(f"tmp_x = {name}"))
            self.assertNotIn("ERR-034", ids, f"{name} must be silent: {ids}")

    def test_longer_identifiers_not_flagged(self):
        # The word boundary must keep these out: the name is a prefix or a
        # suffix, not the whole column.
        for name in ("view_name", "preview", "etag", "header_fields",
                     "target_ip", "tagging", "configuration", "config_id"):
            ids = _rule_ids_from(self._rule(f"tmp_x = {name}"))
            self.assertNotIn("ERR-034", ids, f"{name} must be silent: {ids}")

    def test_function_call_of_the_same_name_not_flagged(self):
        ids = _rule_ids_from(self._rule('tmp_x = filter(a, "b")'))
        self.assertNotIn("ERR-034", ids, ids)

    def test_arraycreate_position_flagged_bare(self):
        # After "(" is a read position too, not just after "=".
        ids = _rule_ids_from(self._rule("tmp_x = arraycreate(tag)"))
        self.assertIn("ERR-034", ids, ids)

    def test_xdm_target_path_not_flagged(self):
        # xdm.target.* is a field path, not a column read.
        rule = (
            "[MODEL: dataset=acme_demo_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n    tmp_x = src_ip\n"
            "| alter\n    xdm.target.ipv4 = tmp_x\n;\n"
        )
        self.assertNotIn("ERR-034", _rule_ids_from(rule), rule)

    def test_name_inside_a_string_literal_not_flagged(self):
        ids = _rule_ids_from(
            self._rule('tmp_x = json_extract_scalar(_raw_log, "$.view")')
        )
        self.assertNotIn("ERR-034", ids, ids)

    def test_name_inside_a_line_comment_not_flagged(self):
        ids = _rule_ids_from(self._rule("tmp_x = src_ip  // reads view here"))
        self.assertNotIn("ERR-034", ids, ids)

    def test_name_inside_a_block_comment_not_flagged(self):
        # Nothing else in the linter strips block comments. Upstream rules
        # carry long block headers naming the very fields they map.
        rule = (
            "[MODEL: dataset=acme_demo_raw]\n"
            "filter\n    _raw_log != null\n"
            "/* header: this rule maps view and tag and target\n"
            "   across several lines */\n"
            "| alter\n    tmp_x = src_ip\n"
            "| alter\n    xdm.event.id = tmp_x\n;\n"
        )
        self.assertNotIn("ERR-034", _rule_ids_from(rule), rule)

    def test_block_comment_does_not_shift_line_numbers(self):
        # Blanking preserves the newlines, so the reported line must be the
        # real one even with a multi-line block comment above it.
        rule = (
            "[MODEL: dataset=acme_demo_raw]\n"
            "filter\n    _raw_log != null\n"
            "/* a\n   multi\n   line */\n"
            "| alter\n"
            "    tmp_x = view\n"
            "| alter\n    xdm.event.id = tmp_x\n;\n"
        )
        vios = [v for v in lint(rule) if v["rule_id"] == "ERR-034"]
        self.assertEqual(len(vios), 1, vios)
        self.assertEqual(vios[0]["line"], 8, vios)


class TestStripLineCommentEscapedQuote(unittest.TestCase):
    """_strip_line_comment toggled its in-string state on every quote,
    including an escaped one, so a line carrying an escaped quote left it
    believing it was still inside a string and every // after that read as
    code. Every check that strips line comments was affected."""

    def test_escaped_quote_does_not_swallow_the_comment(self):
        line = r'    tmp_x = trim("@element", "\""),  // strip the quote'
        self.assertNotIn("//", _lint_mod._strip_line_comment(line))

    def test_double_slash_inside_a_string_is_preserved(self):
        line = r'    tmp_x = concat("a//b", "c"),  // trailing comment'
        out = _lint_mod._strip_line_comment(line)
        self.assertIn("a//b", out)
        self.assertNotIn("trailing comment", out)


if __name__ == "__main__":
    unittest.main()


class TestWarn057IdentityMirror(unittest.TestCase):
    """The recommended identity mirror. The tier's whole design rests on
    NEVER reporting an absent mirror: every rule written before this tier
    existed maps user.* without one, and a check that fired on those would
    report findings on correct, complete work -- the failure mode that
    teaches authors to mute a checker. Only a mirror that is present and
    wrong is reported."""

    def _auth(self, body: str) -> str:
        return (
            "[MODEL: dataset=acme_idp_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    tmp_u = json_extract_scalar(_raw_log, "$.user"),\n'
            '    tmp_alt = json_extract_scalar(_raw_log, "$.alt")\n'
            "| alter\n"
            "    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION),\n"
            f"{body}\n"
            ";\n"
        )

    def _ids(self, rule: str):
        return [v for v in lint(rule) if v["rule_id"] == "WARN-057"]

    def test_absence_is_never_reported(self):
        # The load-bearing assertion of the whole tier.
        for body in (
            "    xdm.source.user.upn = tmp_u",
            "    xdm.source.user.username = tmp_u,\n    xdm.source.user.domain = tmp_alt",
        ):
            self.assertEqual(self._ids(self._auth(body)), [], body)

    def test_matched_mirror_is_silent(self):
        rule = self._auth(
            "    xdm.source.user.upn = tmp_u,\n"
            "    xdm.source.identity.upn = tmp_u"
        )
        self.assertEqual(self._ids(rule), [])

    def test_reformatted_mirror_is_still_matched(self):
        # Whitespace and line breaks carry no meaning across a derivation,
        # so an author who wrapped one half must not be flagged.
        rule = self._auth(
            '    xdm.source.user.upn = if(tmp_u contains "@", tmp_u,'
            ' tmp_u != null, concat(tmp_u, "@localhost")),\n'
            '    xdm.source.identity.upn = if(tmp_u contains "@", tmp_u,\n'
            '        tmp_u != null, concat(tmp_u, "@localhost"))'
        )
        self.assertEqual(self._ids(rule), [])

    def test_identity_without_user_is_reported(self):
        rule = self._auth("    xdm.source.identity.upn = tmp_u")
        vios = self._ids(rule)
        self.assertEqual(len(vios), 1, vios)
        self.assertEqual(vios[0]["severity"], "warning")
        self.assertIn("never written instead of it", vios[0]["message"])

    def test_diverged_pair_is_reported_as_a_question(self):
        rule = self._auth(
            "    xdm.source.user.upn = tmp_u,\n"
            "    xdm.source.identity.upn = tmp_alt"
        )
        vios = self._ids(rule)
        self.assertEqual(len(vios), 1, vios)
        self.assertEqual(vios[0]["severity"], "warning")
        # Phrased as a question, per the WARN-038 shape: the linter cannot
        # see intent, only difference.
        self.assertIn("IF these are meant to carry", vios[0]["message"])
        self.assertIn("does NOT apply", vios[0]["message"])
        self.assertTrue(
            vios[0]["recommendation"].startswith("Decide which derivation"),
            vios[0]["recommendation"],
        )

    def test_each_side_is_independent(self):
        rule = self._auth(
            "    xdm.source.user.upn = tmp_u,\n"
            "    xdm.source.identity.upn = tmp_u,\n"
            "    xdm.target.identity.username = tmp_alt"
        )
        vios = self._ids(rule)
        self.assertEqual(len(vios), 1, vios)
        self.assertIn("xdm.target.identity.username", vios[0]["message"])

    def test_fixtures_are_advisory_only(self):
        # Warning severity, so still exit 0: the tier is recommended and
        # a defective mirror must not block a release the twin's own
        # missing-field check would let through.
        for name in (
            "warn057_identity_without_user.xql",
            "warn057_diverged_mirror.xql",
        ):
            with self.subTest(fixture=name):
                path = bundle_root() / "tests" / "fixtures" / name
                proc = subprocess.run(
                    [sys.executable, str(LINT_SCRIPT), str(path)],
                    capture_output=True, text=True,
                )
                self.assertEqual(proc.returncode, 0, proc.stdout)

    def test_silent_on_non_auth_and_complete_auth(self):
        self.assertNotIn("WARN-057", _rule_ids("clean_rule.xql"))
        self.assertEqual(
            self._ids(TestWarn042AuthMandatory._COMPLETE_AUTH), []
        )


class TestWarn057CorpusSweep(unittest.TestCase):
    """The permanent measurement gate. A check was withdrawn from this
    bundle in 2.1.4 for firing on the bundle's own prescribed idioms, and
    the lesson recorded there was that measuring once before release is
    not enough. This sweeps every fixture and every MODEL block in every
    worked example on every run."""

    def _model_blocks(self, path: Path):
        lines = path.read_text(encoding="utf-8").splitlines()
        out, i = [], 0
        while i < len(lines):
            if lines[i].startswith("[MODEL:"):
                j = i
                while j < len(lines) and lines[j].strip() != "```":
                    j += 1
                out.append("\n".join(lines[i:j]) + "\n")
                i = j
            i += 1
        return out

    def test_no_fixture_fires_except_the_purpose_built_ones(self):
        for path in sorted((bundle_root() / "tests" / "fixtures").glob("*.xql")):
            if path.name.startswith("warn057_"):
                continue
            with self.subTest(fixture=path.name):
                vios = [
                    v for v in lint(path.read_text(encoding="utf-8"))
                    if v["rule_id"] == "WARN-057"
                ]
                self.assertEqual(vios, [], f"{path.name}: {vios}")

    def test_no_worked_example_block_fires(self):
        we_dir = bundle_root() / "references" / "worked-examples"
        swept = mirrored = 0
        for md in sorted(we_dir.glob("*.md")):
            for k, block in enumerate(self._model_blocks(md)):
                swept += 1
                if ".identity." in block:
                    mirrored += 1
                with self.subTest(example=md.name, block=k):
                    vios = [
                        v for v in lint(block) if v["rule_id"] == "WARN-057"
                    ]
                    self.assertEqual(vios, [], f"{md.name} block {k}: {vios}")
        self.assertGreaterEqual(swept, 15, "sweep found too few MODEL blocks")
        # The gate must not pass vacuously: the examples really do carry
        # mirrors, so a regression in the check has something to fire on.
        self.assertGreaterEqual(
            mirrored, 5, "no mirrored blocks swept -- gate is hollow"
        )


class TestIdentityMirrorListsInSync(unittest.TestCase):
    """The mirror set is written down in four places. Three-way drift is
    what the WARN-042 mandatory-list guard exists to prevent; this is the
    same guard for the recommended tier."""

    def test_lint_profiler_and_scaffolder_agree(self):
        import importlib.util

        def _load(name, filename):
            spec = importlib.util.spec_from_file_location(
                name, bundle_root() / "scripts" / filename
            )
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod

        lr = _load("lr_sync", "lint_rule.py")
        pl = _load("pl_sync", "profile_log.py")
        sc = _load("sc_sync", "scaffold_rule.py")

        leaves = set(lr._IDENTITY_MIRROR_LEAVES)
        self.assertEqual(len(lr._IDENTITY_MIRROR_LEAVES), 6)
        self.assertEqual(
            {p.rsplit(".", 1)[1] for p in pl._AUTH_IDENTITY_MIRROR}, leaves
        )
        self.assertEqual(
            {i.rsplit(".", 1)[1] for _u, i in sc._AUTH_RECOMMENDED}, leaves
        )
        # Every scaffolder pair really is a pair: same side, same leaf.
        for user_field, ident_field in sc._AUTH_RECOMMENDED:
            self.assertEqual(
                user_field.replace(".user.", ".identity."), ident_field
            )

    def test_reference_table_names_the_same_leaves(self):
        doc = (
            bundle_root() / "references" / "authentication-mapping.md"
        ).read_text(encoding="utf-8")
        section = doc.split("## Recommended fields (the identity mirror)")[1]
        section = section.split("\n## ")[0]
        for leaf in ("upn", "identity_type", "user_type", "username",
                     "identifier", "domain"):
            self.assertIn(f"`user.{leaf}` -> `identity.{leaf}`", section)


class TestMirrorInteractionsWithExistingChecks(unittest.TestCase):
    """A mirrored pair doubles the number of user-ish assignments in a
    rule. These pin the checks that count or categorise such assignments,
    so the mirror cannot quietly double a finding or invent a new one."""

    _PROSE = """[MODEL: dataset=acme_syslog_raw]
filter _raw_log != null
| alter
    tmp_acct = arrayindex(regextract(_raw_log, "for (\\\\S+)"), 0)
| alter
    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION),
    xdm.source.user.username = tmp_acct,
    xdm.source.identity.username = tmp_acct
;
"""

    def test_warn051_reports_the_unguarded_capture_once_not_twice(self):
        # WARN-051 flags a prose-captured account with no redaction guard.
        # The mirror feeds the same temp to a second field; the finding is
        # about the CAPTURE, so it must stay a single finding.
        vios = [v for v in lint(self._PROSE) if v["rule_id"] == "WARN-051"]
        self.assertLessEqual(len(vios), 1, vios)

    def test_mirror_does_not_raise_info013_over_mapping(self):
        # INFO-013 counts XDM entity FAMILIES a temp reaches. user and
        # identity are both on the same side, so a mirror adds no family
        # and must not push a rule over the threshold.
        vios = [v for v in lint(self._PROSE) if v["rule_id"] == "INFO-013"]
        self.assertEqual(vios, [], vios)

    def test_mirror_does_not_change_the_mandatory_count(self):
        # The tier is additive: WARN-042 sees the same 15 either way.
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "lr_count", bundle_root() / "scripts" / "lint_rule.py"
        )
        lr = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lr)
        self.assertEqual(len(lr._AUTH_MANDATORY), 15)
        for path in lr._AUTH_MANDATORY:
            self.assertNotIn(".identity.", path)


class TestMirrorTwinReadIsNotADivergence(unittest.TestCase):
    """Writing `identity.<X> = user.<X>` is the intuitive way to say "the
    same value", and it is wrong in a way worth separating from a real
    divergence. Inside one alter stage Cortex evaluates every target in
    parallel, so the read returns the pre-stage value and the rule is
    rejected -- that is ERR-024's fault to report, not a value mismatch.
    Across stages the read is legitimate and the values are identical by
    construction, so nothing should fire at all."""

    def _rule(self, body: str) -> str:
        return (
            "[MODEL: dataset=acme_idp_raw]\n"
            "filter _raw_log != null\n"
            "| alter\n"
            '    tmp_u = json_extract_scalar(_raw_log, "$.u")\n'
            "| alter\n"
            "    xdm.event.tags = arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION),\n"
            f"{body}\n;\n"
        )

    def test_same_stage_twin_read_is_err024_not_a_divergence(self):
        rule = self._rule(
            "    xdm.source.user.upn = tmp_u,\n"
            "    xdm.source.identity.upn = xdm.source.user.upn"
        )
        vios = lint(rule)
        codes = {v["rule_id"] for v in vios}
        self.assertIn("ERR-024", codes)
        self.assertNotIn(
            "WARN-057", codes,
            "a structurally broken twin read must not also be reported as a "
            "value divergence -- that sends the author hunting for a "
            "mismatch that does not exist",
        )
        err = next(v for v in vios if v["rule_id"] == "ERR-024")
        self.assertIn("sibling field", err["message"])
        self.assertIn("repeats the derivation", err["recommendation"])

    def test_later_stage_twin_read_is_clean(self):
        rule = self._rule(
            "    xdm.source.user.upn = tmp_u\n"
            "| alter\n"
            "    xdm.source.identity.upn = xdm.source.user.upn"
        )
        codes = {
            v["rule_id"] for v in lint(rule)
            if v["rule_id"] in ("ERR-024", "WARN-057")
        }
        self.assertEqual(codes, set(), "same value by construction")

    def test_err024_does_not_match_a_path_prefix(self):
        # xdm.source.user must not match inside xdm.source.user.upn.
        rule = self._rule(
            "    xdm.source.user.upn = tmp_u,\n"
            "    xdm.source.user.username = tmp_u"
        )
        codes = {v["rule_id"] for v in lint(rule)}
        self.assertNotIn("ERR-024", codes)


class TestWarn057SeverityMirrorsItsTwin(unittest.TestCase):
    """The mirror check reports at the severity the twin's own
    mandatory-set check reports at. WARN-042 names a MANDATORY
    authentication field and returns exit 0; a defect in the recommended
    mirror beside it cannot reasonably be stricter than that."""

    def test_warn057_is_warning_severity(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "lr_sev", bundle_root() / "scripts" / "lint_rule.py"
        )
        lr = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lr)
        src = (bundle_root() / "scripts" / "lint_rule.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('"WARN-057",\n                        "warning",', src)

    def test_a_defective_mirror_still_exits_zero(self):
        for name in (
            "warn057_identity_without_user.xql",
            "warn057_diverged_mirror.xql",
        ):
            with self.subTest(fixture=name):
                proc = subprocess.run(
                    [sys.executable, str(LINT_SCRIPT),
                     str(bundle_root() / "tests" / "fixtures" / name)],
                    capture_output=True, text=True,
                )
                self.assertEqual(proc.returncode, 0, proc.stdout)
