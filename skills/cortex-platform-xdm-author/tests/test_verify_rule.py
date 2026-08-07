# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for ``scripts/verify_rule.py``.

The verifier runs a MODEL rule over a sample offline. These tests pin the
evaluator subset that matters: json_extract_scalar + nested paths, the
null guard, banded if-chains, the arrow operator, arraymap / arrayfilter
with @element, the filter stage, and the --expect diff. Unsupported
constructs must raise rather than guess.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _helpers import bundle_root  # noqa: E402

SCRIPTS = bundle_root() / "scripts"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


_v = _load("verify_rule")


PATTERN_A = (
    "[MODEL: dataset=acme_demo_raw]\n"
    "filter\n"
    "    _raw_log != null\n"
    "| alter\n"
    '    _id = json_extract_scalar(_raw_log, "$.event_id"),\n'
    '    _ip = json_extract_scalar(_raw_log, "$.client.ip"),\n'
    '    _score = to_number(json_extract_scalar(_raw_log, "$.risk_score")),\n'
    '    _outcome = json_extract_scalar(_raw_log, "$.outcome")\n'
    "| alter\n"
    "    _severity = if(\n"
    '        _score >= 80, "Critical",\n'
    '        _score >= 50, "High",\n'
    '        _score >= 30, "Medium",\n'
    '        _score != null, "Low")\n'
    "| alter\n"
    '    xdm.observer.vendor = "Acme",\n'
    "    xdm.event.id = _id,\n"
    "    xdm.source.ipv4 = _ip,\n"
    "    xdm.alert.severity = _severity,\n"
    "    xdm.event.outcome = if(_outcome = \"ok\", XDM_CONST.OUTCOME_SUCCESS, "
    "XDM_CONST.OUTCOME_FAILED)\n"
    ";\n"
)


class TestEvaluator(unittest.TestCase):
    def test_nested_extract_and_banding(self):
        rec = {"event_id": "e1", "client": {"ip": "10.0.0.5"},
               "risk_score": 92, "outcome": "ok"}
        out = _v.evaluate_rule(PATTERN_A, rec)
        self.assertEqual(out["xdm.event.id"], "e1")
        self.assertEqual(out["xdm.source.ipv4"], "10.0.0.5")
        self.assertEqual(out["xdm.alert.severity"], "Critical")
        self.assertEqual(out["xdm.event.outcome"], "XDM_CONST.OUTCOME_SUCCESS")

    def test_band_medium_and_failed(self):
        rec = {"event_id": "e2", "client": {"ip": "10.0.0.9"},
               "risk_score": 40, "outcome": "bad"}
        out = _v.evaluate_rule(PATTERN_A, rec)
        self.assertEqual(out["xdm.alert.severity"], "Medium")
        self.assertEqual(out["xdm.event.outcome"], "XDM_CONST.OUTCOME_FAILED")

    def test_filter_drops_record(self):
        rule = (
            "[MODEL: dataset=demo_raw]\n"
            'filter\n    _raw_log = null\n'
            "| alter\n    xdm.event.id = \"x\"\n;\n"
        )
        self.assertIsNone(_v.evaluate_rule(rule, {"a": 1}))

    def test_arrow_arraymap_arrayfilter_with_element(self):
        rule = (
            "[MODEL: dataset=demo_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n"
            "    _offender_ip = arrayindex(arrayfilter(arraymap(participants -> [],\n"
            '        if("@element" -> role = "offender", "@element" -> ip, null)),\n'
            '        "@element" != null), 0),\n'
            '    _cats = arraystring(categories -> [], ", ")\n'
            "| alter\n"
            "    xdm.source.ipv4 = _offender_ip,\n"
            '    xdm.event.description = concat("Cats: ", _cats)\n'
            ";\n"
        )
        rec = {
            "participants": [
                {"role": "victim", "ip": "10.0.0.1"},
                {"role": "offender", "ip": "203.0.113.7"},
            ],
            "categories": ["brute", "dos"],
        }
        out = _v.evaluate_rule(rule, rec)
        self.assertEqual(out["xdm.source.ipv4"], "203.0.113.7")
        self.assertEqual(out["xdm.event.description"], "Cats: brute, dos")

    def test_json_string_column_cast(self):
        # categories arrives as a JSON STRING; `-> []` must parse it.
        rule = (
            "[MODEL: dataset=demo_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n"
            '    _joined = arraystring(categories -> [], "|")\n'
            "| alter\n"
            "    xdm.event.description = _joined\n;\n"
        )
        rec = {"categories": "[\"a\",\"b\"]"}
        out = _v.evaluate_rule(rule, rec)
        self.assertEqual(out["xdm.event.description"], "a|b")

    def test_coalesce_first_non_null(self):
        rule = (
            "[MODEL: dataset=demo_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n"
            "    xdm.source.user.username = coalesce("
            'json_extract_scalar(_raw_log, "$.a"), '
            'json_extract_scalar(_raw_log, "$.b"))\n;\n'
        )
        out = _v.evaluate_rule(rule, {"b": "bob"})
        self.assertEqual(out["xdm.source.user.username"], "bob")

    def test_unsupported_function_raises(self):
        rule = (
            "[MODEL: dataset=demo_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n    xdm.event.id = nonexistent_fn(_raw_log)\n;\n"
        )
        with self.assertRaises(_v.UnsupportedConstruct):
            _v.evaluate_rule(rule, {"a": 1})


class TestCli(unittest.TestCase):
    def _write(self, name: str, text: str) -> Path:
        p = Path(self._dir.name) / name
        p.write_text(text, encoding="utf-8")
        return p

    def setUp(self):
        import tempfile
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.rule = self._write("rule.xql", PATTERN_A)
        self.sample = self._write(
            "sample.jsonl",
            '{"event_id":"e1","client":{"ip":"10.0.0.5"},"risk_score":92,"outcome":"ok"}\n',
        )

    def test_cli_json_output(self):
        cp = subprocess.run(
            [sys.executable, str(SCRIPTS / "verify_rule.py"),
             str(self.rule), str(self.sample)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        parsed = json.loads(cp.stdout)
        self.assertEqual(parsed[0]["xdm.alert.severity"], "Critical")

    def test_cli_expect_match(self):
        expect = self._write(
            "expect.json",
            '[{"xdm.alert.severity":"Critical","xdm.source.ipv4":"10.0.0.5"}]',
        )
        cp = subprocess.run(
            [sys.executable, str(SCRIPTS / "verify_rule.py"),
             str(self.rule), str(self.sample), "--expect", str(expect)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)

    def test_cli_expect_mismatch_exits_one(self):
        expect = self._write(
            "expect.json", '[{"xdm.alert.severity":"Low"}]'
        )
        cp = subprocess.run(
            [sys.executable, str(SCRIPTS / "verify_rule.py"),
             str(self.rule), str(self.sample), "--expect", str(expect)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(cp.returncode, 1)
        self.assertIn("mismatch", cp.stderr)

    def test_cli_missing_file_exits_two(self):
        cp = subprocess.run(
            [sys.executable, str(SCRIPTS / "verify_rule.py"),
             "/nope.xql", str(self.sample)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(cp.returncode, 2)


class TestRecordLevelClassification(unittest.TestCase):
    """Worked example 08 must classify PER RECORD: an auth shape gets the
    authentication tag, a command-accounting record becomes a process
    event with the command on target.process.command_line and NO auth
    tag, and an unrecognised line falls through to the catch-all."""

    def _rule(self) -> str:
        import re
        doc = (
            bundle_root() / "references" / "worked-examples"
            / "08-cisco-tacacs-aaa-multi-shape.md"
        ).read_text(encoding="utf-8")
        return re.findall(r"```\n(\[MODEL:.*?\n;)", doc, re.DOTALL)[0]

    def test_auth_shape(self):
        line = ('<14>Jun 19 09:50:01 aaa01 tacacsd[10]: type=AUTHENTICATION '
                'action=PERMIT user="bob" src_ip=10.0.35.9 dvc_ip=10.0.34.10')
        out = _v.evaluate_rule(self._rule(), line)
        self.assertEqual(out["xdm.event.type"], "authentication")
        self.assertEqual(out["xdm.event.tags"],
                         ["XDM_CONST.EVENT_TAG_AUTHENTICATION"])

    def test_command_accounting_is_process(self):
        line = ('<14>Jun 19 09:51:59 aaa01 tacacsd[25]: type=ACCOUNTING '
                'action=Stop user="alice" dvc_ip=10.0.34.10 '
                'cmd="show bgp neighbors"')
        out = _v.evaluate_rule(self._rule(), line)
        self.assertEqual(out["xdm.event.type"], "process")
        self.assertIsNone(out["xdm.event.tags"])
        self.assertEqual(out["xdm.target.process.command_line"],
                         "show bgp neighbors")
        self.assertEqual(out["xdm.event.operation"],
                         "XDM_CONST.OPERATION_TYPE_AUDIT")
        self.assertIsNone(out["xdm.event.outcome"])

    def test_unrecognised_line_catch_all(self):
        line = ('<14>Jun 19 09:52:10 aaa01 tacacsd[7]: Inconsistent lengths '
                'in PostSearchHook createreturnattrs')
        out = _v.evaluate_rule(self._rule(), line)
        self.assertEqual(out["xdm.event.type"], "GOCORTEX_UNMODELLED")
        self.assertIsNone(out["xdm.event.tags"])
        self.assertEqual(out["xdm.event.original_event_type"],
                         "GOCORTEX_UNMODELLED")


class TestBackslashStringSplit(unittest.TestCase):
    """A regex string literal that ends in an even run of backslashes
    (a Windows DOMAIN\\user split ends `...\\\\"`) must not swallow the
    assignment boundary in _split_assignments -- the escaped-backslash-
    before-quote case."""

    def test_domain_user_split(self):
        rule = (
            "[MODEL: dataset=win_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n"
            '    tmp_u = json_extract_scalar(_raw_log, "$.User")\n'
            "| alter\n"
            '    xdm.source.user.domain = arrayindex(regextract(to_string(tmp_u), "^([^\\\\\\\\]+)\\\\\\\\"), 0),\n'
            '    xdm.source.user.username = arrayindex(regextract(to_string(tmp_u), "\\\\\\\\([^\\\\\\\\]+)$"), 0)\n'
            ";\n"
        )
        out = _v.evaluate_rule(rule, json.dumps({"User": "ACME\\alice"}))
        self.assertEqual(out["xdm.source.user.domain"], "ACME")
        self.assertEqual(out["xdm.source.user.username"], "alice")


class TestRawLogBinding(unittest.TestCase):
    """A record carrying an explicit ``_raw_log`` column must have that
    value bound, not the record's JSON text. Overwriting it silently
    changes the subject of every regex: a ^-anchored pattern stops
    matching and a trailing capture picks up JSON syntax."""

    _RULE = (
        "[MODEL: dataset=t_raw]\n"
        "filter\n    _raw_log != null\n"
        "| alter\n"
        '    xdm.event.description = _raw_log\n'
        ";\n"
    )

    def test_explicit_raw_log_column_wins(self):
        line = "<190>Jul 29 02:02:26 host sshd: Accepted for alice"
        out = _v.evaluate_rule(self._RULE, {"_raw_log": line})
        self.assertEqual(out["xdm.event.description"], line)

    def test_json_record_without_raw_log_is_synthesised(self):
        rec = {"user": "alice", "action": "login"}
        out = _v.evaluate_rule(self._RULE, rec)
        self.assertEqual(out["xdm.event.description"], json.dumps(rec))

    def test_anchored_pattern_matches_explicit_raw_log(self):
        rule = (
            "[MODEL: dataset=t_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n"
            '    tmp_pri = arrayindex(regextract(_raw_log, "^<(\\\\d+)>"), 0)\n'
            "| alter\n"
            "    xdm.event.description = tmp_pri\n"
            ";\n"
        )
        out = _v.evaluate_rule(rule, {"_raw_log": "<190>Jul 29 host msg"})
        self.assertEqual(out["xdm.event.description"], "190")


class TestPrependCheck(unittest.TestCase):
    """A syslog rule must model both arrival forms in one rule: direct off
    the device, and behind a relay that prepends its own header. That is a
    testable property -- evaluate each record twice and compare -- and the
    check is the mandatory proof, because static lint cannot establish it."""

    _LINE = "<190>Jul 29 02:02:26 rtr01 sshd[123]: Accepted password for alice from 10.0.0.5 port 22 ssh2"

    _FRAGILE = (
        "[MODEL: dataset=x_raw]\n"
        "filter\n    _raw_log != null\n"
        "| alter\n"
        '    tmp_host = arrayindex(regextract(_raw_log, '
        '"^<\\d{1,3}>\\w{3}\\s+\\d+\\s\\S+\\s(\\S+)"), 0)\n'
        "| alter\n"
        "    xdm.observer.name = tmp_host\n;\n"
    )

    _ROBUST = (
        "[MODEL: dataset=x_raw]\n"
        "filter\n    _raw_log != null\n"
        "| alter\n"
        '    tmp_user = arrayindex(regextract(_raw_log, '
        '"password for (\\S+)"), 0)\n'
        "| alter\n"
        "    xdm.source.user.username = tmp_user\n;\n"
    )

    def test_relay_prefix_only_changes_raw_text(self):
        rec = {"_raw_log": self._LINE, "other": "kept"}
        out = _v.prepend_relay(rec)
        self.assertTrue(out["_raw_log"].endswith(self._LINE))
        self.assertGreater(len(out["_raw_log"]), len(self._LINE))
        self.assertEqual(out["other"], "kept")

    def test_token_anchored_rule_is_identical_under_prepend(self):
        diffs = _v.prepend_check(self._ROBUST, [{"_raw_log": self._LINE}])
        self.assertEqual(diffs, [])

    def test_positional_rule_reports_the_changed_field(self):
        diffs = _v.prepend_check(self._FRAGILE, [{"_raw_log": self._LINE}])
        self.assertTrue(diffs)
        fields = {d["field"] for d in diffs}
        self.assertIn("xdm.observer.name", fields)
        d = next(d for d in diffs if d["field"] == "xdm.observer.name")
        # direct gives the origin host; relayed gives the relay's host,
        # which is precisely the defect the check exists to surface.
        self.assertEqual(d["direct"], "rtr01")
        self.assertNotEqual(d["relayed"], "rtr01")

    def test_text_output_states_the_outcome(self):
        clean = _v._format_prepend_check([], 3)
        self.assertIn("identical", clean)
        diffs = _v.prepend_check(self._FRAGILE, [{"_raw_log": self._LINE}])
        broken = _v._format_prepend_check(diffs, 1)
        self.assertIn("does not model both arrival forms", broken)


class TestCoverage(unittest.TestCase):
    """Coverage summary. A match count is not evidence a capture works:
    the doubled-quote trap matches every record and captures the empty
    string, which must be reported rather than read as full coverage."""

    def test_counts_populated_and_empty(self):
        results = [
            {"xdm.source.user.username": "", "xdm.observer.action": "PERMIT"},
            {"xdm.source.user.username": "", "xdm.observer.action": "DENY"},
            {"xdm.source.user.username": "alice", "xdm.observer.action": None},
        ]
        cov = _v.coverage(results)
        self.assertEqual(cov["records"], 3)
        self.assertEqual(cov["mapped"], 3)
        user = cov["fields"]["xdm.source.user.username"]
        self.assertEqual(user["populated"], 3)
        self.assertEqual(user["empty"], 2)
        action = cov["fields"]["xdm.observer.action"]
        self.assertEqual(action["populated"], 2)
        self.assertEqual(action["empty"], 0)

    def test_sentinel_fallback_is_counted_and_flagged(self):
        """A field defaulting to the catch-all sentinel is non-null and
        non-empty, so a population count reports it as healthy. It has to
        be counted as its own state or the failure is invisible."""
        results = [
            {"xdm.event.description": "real body"},
            {"xdm.event.description": "GOCORTEX_UNMODELLED"},
            {"xdm.event.description": "GOCORTEX_UNMODELLED"},
        ]
        cov = _v.coverage(results)
        slot = cov["fields"]["xdm.event.description"]
        self.assertEqual(slot["populated"], 3)
        self.assertEqual(slot["empty"], 0)
        self.assertEqual(slot["sentinel"], 2)
        text = _v._format_coverage(cov)
        self.assertIn("sentinel", text)
        self.assertIn("[WARN]", text)

    def test_working_field_is_not_flagged(self):
        cov = _v.coverage([{"xdm.event.id": "a"}, {"xdm.event.id": "b"}])
        self.assertEqual(cov["fields"]["xdm.event.id"]["sentinel"], 0)
        self.assertNotIn("[WARN]", _v._format_coverage(cov))

    def test_dropped_records_counted_separately(self):
        cov = _v.coverage([{"xdm.event.id": "1"}, None, None])
        self.assertEqual(cov["records"], 3)
        self.assertEqual(cov["mapped"], 1)
        self.assertEqual(cov["dropped_by_filter"], 2)

    def test_all_empty_field_is_flagged_as_a_defect_not_a_statistic(self):
        """A field populated on every record and empty on every record
        satisfies the mandatory set, the null check and the population
        ratio at once. It is a defect, and the usual cause is padding a
        value that could have been derived, so the message says so."""
        cov = _v.coverage([{"xdm.source.user.username": ""}] * 4)
        text = _v._format_coverage(cov)
        self.assertIn("xdm.source.user.username", text)
        self.assertIn("[DEFECT]", text)
        self.assertIn("derive", text)


class TestBacktickQuotedColumn(unittest.TestCase):
    """The backtick escape ERR-034 prescribes must be verifiable.

    lint_rule.py accepted `in` and verify_rule.py died on it, so a rule
    that followed the bundle's own remediation could not be verified
    offline -- and --coverage and --prepend-check are the only offline
    proof steps in the workflow.
    """

    def test_backticked_identifier_tokenises_as_a_column(self):
        toks = [t for t in _v._tokenise("to_number(`in`)")
                if t[0] != "eof"]
        self.assertEqual(
            toks,
            [("ident", "to_number"), ("punct", "("),
             ("ident", "in"), ("punct", ")")],
        )

    def test_backticked_keyword_is_not_a_keyword(self):
        # The whole point of quoting is that `in` is a COLUMN here. Emitting
        # it as a kw token would make the parser read a membership operator.
        self.assertEqual(
            [t for t in _v._tokenise("`in`") if t[0] != "eof"],
            [("ident", "in")],
        )

    def test_bare_in_is_still_the_membership_operator(self):
        toks = [t for t in _v._tokenise('evt in ("a")')
                if t[0] != "eof"]
        self.assertIn(("kw", "in"), toks)

    def test_backticked_column_evaluates(self):
        rule = (
            "[MODEL: dataset = fg_raw]\n"
            "filter\n    _raw_log != null\n"
            "| alter\n    tmp_b = to_number(`in`)\n"
            "| alter\n    xdm.target.sent_bytes = to_integer(tmp_b)\n;\n"
        )
        row = _v.evaluate_rule(rule, {"_raw_log": "x", "in": "4096"})
        self.assertEqual(row["xdm.target.sent_bytes"], 4096)


class TestBundleVersionReporting(unittest.TestCase):
    def test_lint_rule_reports_a_version(self):
        # A pinned worktree silently keeps an author on the version they
        # started from; nothing else in the authoring path surfaces it.
        v = _load("lint_rule").bundle_version()
        self.assertRegex(v, r"^\d+\.\d+\.\d+$", v)


if __name__ == "__main__":
    unittest.main()
