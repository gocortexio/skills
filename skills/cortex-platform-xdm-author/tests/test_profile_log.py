# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Behavioural tests for ``scripts/profile_log.py``.

Mirrors the test_lint_rule.py shape: import the ``profile()`` function
directly for fast assertions, and shell out via ``subprocess`` to
exercise the CLI exit-code and output-format contract.

Headline fixture is ``acmeshield_waf.log`` (enhanced WAF telemetry
with object-arrays, header-pair arrays, optional fields, and null
values) -- the dataset the spec calls out as the accuracy-collapse
case for manual log analysis.
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _helpers import bundle_root  # noqa: E402


FIXTURES = Path(__file__).resolve().parent / "fixtures"
PROFILE_SCRIPT = bundle_root() / "scripts" / "profile_log.py"


def _load_module():
    """Import ``profile_log`` from the bundled script without making
    the script a permanent member of any package."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("profile_log", PROFILE_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


_pl = _load_module()
profile = _pl.profile
infer_type = _pl.infer_type


def _profile_fixture(name: str) -> dict:
    text = (FIXTURES / name).read_text(encoding="utf-8")
    return profile(str(FIXTURES / name), text)


# --------------------------------------------------------------------
# Headline fixture: enhanced AcmeShield WAF
# --------------------------------------------------------------------


class TestAcmeShieldWaf(unittest.TestCase):
    """The spec's accuracy-collapse case: nested object-arrays,
    header-pair arrays, a clear phase discriminator, and a
    deliberately-null optional field."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.ws = _profile_fixture("acmeshield_waf.log")
        cls.fields = {f["path"]: f for f in cls.ws["fields"]}

    def test_detected_format_is_json(self) -> None:
        self.assertEqual(self.ws["detected_format"], "json")

    def test_record_count_matches_sample(self) -> None:
        self.assertEqual(self.ws["record_count"], 2)

    def test_nested_array_path_surfaces(self) -> None:
        """``transactions[].http.method`` must be discoverable -- this
        is the central path the spec calls out as needing the profiler
        to recover."""
        self.assertIn("transactions[].http.method", self.fields)
        self.assertEqual(self.fields["transactions[].http.method"]["type"], "string")

    def test_transactions_array_discriminator_is_phase(self) -> None:
        """The ``transactions[]`` object-array must report its
        ``phase`` discriminator with values request and response so the
        agent knows to phase-filter the projection."""
        oa = next(
            (a for a in self.ws["object_arrays"] if a["path"] == "transactions[]"),
            None,
        )
        self.assertIsNotNone(oa, "no transactions[] entry in object_arrays")
        self.assertEqual(oa["discriminator"], "phase")
        self.assertEqual(sorted(oa["values"]), ["request", "response"])

    def test_session_user_id_null_rate_is_half(self) -> None:
        """``session.user_id`` is null in event 1 and present in
        event 2, so the recorded null rate must be 0.5."""
        f = self.fields.get("session.user_id")
        self.assertIsNotNone(f, "session.user_id not in field list")
        self.assertAlmostEqual(f["null_rate"], 0.5, places=2)

    def test_header_pair_array_surfaces_named_keys(self) -> None:
        """The ``{name, value}`` header arrays must surface each named
        header as its own synthetic field so the agent does not have
        to invent the routing -- the user-agent header in particular
        must be picked up because it carries a high-frequency XDM
        candidate (``xdm.source.user_agent``)."""
        path = "transactions[].http.headers[name=User-Agent]"
        f = self.fields.get(path)
        self.assertIsNotNone(f, f"{path} not in field list")
        self.assertEqual(f["leaf"], "User-Agent")
        # XDM candidate suggestion should land xdm.source.user_agent
        # near the top.
        suggested = [c["xdm_path"] for c in (f.get("xdm_candidates") or [])]
        self.assertIn(
            "xdm.source.user_agent",
            suggested,
            f"expected xdm.source.user_agent in candidates, got {suggested}",
        )

    def test_xdm_candidate_for_client_ip(self) -> None:
        """``network.client.ip`` is the canonical source-IPv4 sink and
        must surface ``xdm.source.ipv4`` as a top candidate."""
        f = self.fields["network.client.ip"]
        self.assertEqual(f["type"], "ip")
        top = [c["xdm_path"] for c in f["xdm_candidates"][:2]]
        self.assertIn("xdm.source.ipv4", top)

    def test_boolean_type_inference(self) -> None:
        """``action.intercepted`` and ``transactions[].http.body_truncated``
        are JSON booleans -- the type inference must report them as
        ``boolean``, not ``string``."""
        self.assertEqual(self.fields["action.intercepted"]["type"], "boolean")
        self.assertEqual(
            self.fields["transactions[].http.body_truncated"]["type"], "boolean"
        )

    def test_timestamp_type_inference(self) -> None:
        self.assertEqual(self.fields["timestamp"]["type"], "timestamp")


# --------------------------------------------------------------------
# CEF fixture
# --------------------------------------------------------------------


class TestCef(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ws = _profile_fixture("sample.cef")
        cls.fields = {f["path"]: f for f in cls.ws["fields"]}

    def test_detected_format_is_cef(self) -> None:
        self.assertEqual(self.ws["detected_format"], "cef")

    def test_cef_headers_surface(self) -> None:
        for required in (
            "cef_vendor",
            "cef_product",
            "cef_signature_id",
            "cef_severity",
        ):
            self.assertIn(required, self.fields, f"{required} missing from CEF profile")

    def test_extension_kv_fields_surface(self) -> None:
        # Standard CEF extension tokens -- src / dst / spt / dpt -- must
        # be picked up by the kv parser embedded in the CEF reader.
        for required in ("src", "dst", "spt", "dpt", "act", "suser"):
            self.assertIn(required, self.fields, f"{required} missing from CEF profile")

    def test_src_field_gets_xdm_candidate(self) -> None:
        cands = self.fields["src"]["xdm_candidates"]
        self.assertTrue(
            cands and cands[0]["xdm_path"] == "xdm.source.ipv4",
            f"expected xdm.source.ipv4 top, got {cands}",
        )


# --------------------------------------------------------------------
# Key=value fixture
# --------------------------------------------------------------------


class TestKv(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ws = _profile_fixture("sample.kv")
        cls.fields = {f["path"]: f for f in cls.ws["fields"]}

    def test_detected_format_is_kv(self) -> None:
        self.assertEqual(self.ws["detected_format"], "kv")

    def test_quoted_values_decoded(self) -> None:
        # ``user="alice@example.com"`` -- the quotes must be stripped.
        self.assertEqual(self.fields["user"]["sample"], "alice@example.com")

    def test_src_ip_gets_xdm_candidate(self) -> None:
        cands = self.fields["src_ip"]["xdm_candidates"]
        self.assertTrue(cands)
        self.assertEqual(cands[0]["xdm_path"], "xdm.source.ipv4")


# --------------------------------------------------------------------
# CLI contract -- mirrors test_lint_rule.py TestCliContract
# --------------------------------------------------------------------


class TestCliContract(unittest.TestCase):
    def _run(self, fixture: str, extra=()) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(PROFILE_SCRIPT), str(FIXTURES / fixture), *extra],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_clean_run_emits_json_worksheet(self) -> None:
        cp = self._run("acmeshield_waf.log")
        self.assertEqual(cp.returncode, 0, cp.stderr)
        parsed = json.loads(cp.stdout)
        self.assertEqual(parsed["detected_format"], "json")
        self.assertEqual(parsed["record_count"], 2)
        self.assertTrue(parsed["fields"], "fields array empty")
        self.assertTrue(parsed["object_arrays"], "object_arrays array empty")

    def test_text_format(self) -> None:
        cp = self._run("acmeshield_waf.log", ["--format", "text"])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("detected_format: json", cp.stdout)
        self.assertIn("transactions[]", cp.stdout)

    def test_missing_file_exits_two(self) -> None:
        cp = subprocess.run(
            [sys.executable, str(PROFILE_SCRIPT), "/nonexistent/sample.log"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(cp.returncode, 2)

    def test_no_argv_exits_one(self) -> None:
        cp = subprocess.run(
            [sys.executable, str(PROFILE_SCRIPT)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(cp.returncode, 1)


# --------------------------------------------------------------------
# Cleanup-pass regression coverage
# --------------------------------------------------------------------


class TestIntDiscriminator(unittest.TestCase):
    """An object-array discriminated by an integer field (HTTP status,
    severity level, etc.) must be detected and surfaced. The pre-cleanup
    detector had a dead int branch that silently filtered ints out."""

    def test_int_discriminator_is_detected_and_stringified(self) -> None:
        import json
        import tempfile

        payload = [
            {
                "requests": [
                    {"status": 200, "url": "/a"},
                    {"status": 302, "url": "/b"},
                ]
            },
            {
                "requests": [
                    {"status": 403, "url": "/c"},
                    {"status": 200, "url": "/d"},
                ]
            },
        ]
        with tempfile.NamedTemporaryFile(
            "w", suffix=".log", delete=False
        ) as tmp:
            tmp.write(json.dumps(payload))
            tmp_path = tmp.name
        try:
            with open(tmp_path, encoding="utf-8") as fh:
                ws = profile(tmp_path, fh.read())
        finally:
            Path(tmp_path).unlink(missing_ok=True)

        oa = next(
            (a for a in ws["object_arrays"] if a["path"] == "requests[]"),
            None,
        )
        self.assertIsNotNone(oa, "requests[] not in object_arrays")
        self.assertEqual(oa["discriminator"], "status")
        self.assertEqual(sorted(oa["values"]), ["200", "302", "403"])


class TestIpv6FalsePositives(unittest.TestCase):
    """MAC addresses and bare clock times must not be mis-tagged as ip.
    Real IPv4s and IPv6s must still be typed as ip."""

    def test_mac_is_string_not_ip(self) -> None:
        self.assertEqual(infer_type("aa:bb:cc:dd:ee:ff"), "string")

    def test_clock_time_is_string_not_ip(self) -> None:
        self.assertEqual(infer_type("12:34:56"), "string")
        self.assertEqual(infer_type("09:00"), "string")
        self.assertEqual(infer_type("23:59:59.123"), "string")

    def test_ipv4_still_typed_as_ip(self) -> None:
        self.assertEqual(infer_type("191.96.12.44"), "ip")

    def test_real_ipv6_is_typed_as_ip(self) -> None:
        # Spot a few canonical IPv6 forms.
        self.assertEqual(infer_type("2001:0db8:85a3:0000:0000:8a2e:0370:7334"), "ip")
        self.assertEqual(infer_type("fe80::1"), "ip")
        self.assertEqual(infer_type("::1"), "ip")

    def test_acmeshield_client_ip_still_ip(self) -> None:
        """Smoke guard: the headline AcmeShield fixture's
        ``network.client.ip`` must still type as ip after the
        tightening."""
        ws = _profile_fixture("acmeshield_waf.log")
        fields = {f["path"]: f for f in ws["fields"]}
        self.assertEqual(fields["network.client.ip"]["type"], "ip")


class TestPatternRecommendation(unittest.TestCase):
    """The worksheet recommends an extraction pattern from the detected
    format and object-array shape."""

    def test_json_recommends_a_and_flags_d_prime(self) -> None:
        ws = _profile_fixture("acmeshield_waf.log")
        rec = ws["recommended_pattern"]
        self.assertEqual(rec["primary"], "A")
        # The object-arrays with discriminators surface a Pattern D' note.
        joined = " ".join(rec["also"])
        self.assertIn("Pattern D'", joined)
        self.assertIn("transactions[]", joined)

    def test_cef_recommends_b(self) -> None:
        ws = _profile_fixture("sample.cef")
        self.assertEqual(ws["recommended_pattern"]["primary"], "B")

    def test_kv_recommends_a(self) -> None:
        ws = _profile_fixture("sample.kv")
        self.assertEqual(ws["recommended_pattern"]["primary"], "A")

    def test_recommendation_in_text_output(self) -> None:
        cp = subprocess.run(
            [sys.executable, str(PROFILE_SCRIPT),
             str(FIXTURES / "sample.cef"), "--format", "text"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("pattern:", cp.stdout)
        self.assertIn("B --", cp.stdout)


class TestAuthenticationDetection(unittest.TestCase):
    """The profiler auto-detects authentication events from field names
    and sample values, and surfaces the mandatory mapping checklist."""

    def test_detects_auth_event_fixture(self) -> None:
        ws = _profile_fixture("auth_event.jsonl")
        auth = ws["authentication"]
        self.assertTrue(auth["detected"], auth)
        self.assertEqual(len(auth["mandatory_fields"]), 15)
        self.assertIn("xdm.source.user.upn", auth["mandatory_fields"])
        self.assertTrue(auth["signals"], "expected at least one signal")

    def test_silent_on_non_auth_sample(self) -> None:
        ws = profile("bytes.jsonl", '{"src_ip":"1.1.1.1","bytes":5}\n')
        self.assertFalse(ws["authentication"]["detected"])
        self.assertEqual(ws["authentication"]["signals"], [])

    def test_does_not_false_match_author_field(self) -> None:
        ws = profile("doc.jsonl", '{"author":"jane","title":"report"}\n')
        self.assertFalse(ws["authentication"]["detected"])

    def test_detection_in_text_output(self) -> None:
        cp = subprocess.run(
            [sys.executable, str(PROFILE_SCRIPT),
             str(FIXTURES / "auth_event.jsonl"), "--format", "text"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("authentication:", cp.stdout)

    def test_detects_auth_buried_in_positional_syslog(self) -> None:
        # Positional syslog collapses every line into a single _message
        # field. In this Nokia 7705 SAR sample the first records are
        # non-auth (tacplus status, MAF filter match, cli_user_io); the
        # authentication lines are a minority buried later. A
        # first-record-only scan would miss them -- the value scan must
        # walk every record.
        ws = _profile_fixture("nokia_syslog_auth.log")
        self.assertIn(ws["detected_format"], ("syslog-3164", "syslog-5424"))
        auth = ws["authentication"]
        self.assertTrue(auth["detected"], auth)
        self.assertEqual(len(auth["mandatory_fields"]), 15)
        value_signals = [s for s in auth["signals"] if s["kind"] == "value"]
        self.assertTrue(value_signals, auth["signals"])
        self.assertTrue(
            all(s["field"] == "_message" for s in value_signals), auth["signals"]
        )

    def test_silent_on_positional_syslog_without_auth(self) -> None:
        # The same wrapper carrying only non-auth events (tacplus status,
        # MAF filter match, cli_user_io) must not false-fire now that the
        # value scan walks every record.
        ws = _profile_fixture("nokia_syslog_noauth.log")
        self.assertIn(ws["detected_format"], ("syslog-3164", "syslog-5424"))
        self.assertFalse(ws["authentication"]["detected"], ws["authentication"])
        self.assertEqual(ws["authentication"]["signals"], [])


class TestNetworkDetection(unittest.TestCase):
    """detect_network is deliberately conservative: distinctive traffic
    vocabulary, allow/deny action values, protocol names, or the complete
    transport 5-tuple -- never a bare IP. It is independent of the
    authentication block (an event can be both stories)."""

    def test_detects_json_flow_record(self) -> None:
        ws = _profile_fixture("network_event.jsonl")
        net = ws["network"]
        self.assertTrue(net["detected"], net)
        self.assertEqual(len(net["mandatory_fields"]), 17)
        kinds = {s["kind"] for s in net["signals"]}
        # A flow record carries all three signal kinds.
        self.assertIn("name", kinds)
        self.assertIn("value", kinds)
        self.assertIn("structure", kinds)

    def test_detects_syslog_flow_record_via_values(self) -> None:
        # Syslog collapses each line into _message, so only the value
        # signal is available -- it must carry detection on its own.
        ws = _profile_fixture("network_event_syslog.log")
        self.assertIn(ws["detected_format"], ("syslog-3164", "syslog-5424"))
        net = ws["network"]
        self.assertTrue(net["detected"], net)
        value_signals = [s for s in net["signals"] if s["kind"] == "value"]
        self.assertTrue(value_signals, net["signals"])
        self.assertTrue(
            all(s["field"] == "_message" for s in value_signals),
            net["signals"],
        )

    def test_independent_of_authentication(self) -> None:
        # The IdP login fixture is authentication-only: no protocol field,
        # no allow/deny vocabulary, so the network block must stay silent.
        ws = _profile_fixture("auth_event.jsonl")
        self.assertTrue(ws["authentication"]["detected"])
        self.assertFalse(ws["network"]["detected"], ws["network"])

    def test_ids_waf_profile_is_also_network(self) -> None:
        # Network is the foundational layer: a WAF / IDS event describes a
        # network connection first and a security judgement second, so the
        # WAF fixture must carry the network block on top of its primary
        # role (it holds the transport 5-tuple and block/allow vocabulary).
        ws = _profile_fixture("acmeshield_waf.log")
        self.assertTrue(ws["network"]["detected"], ws["network"])

    def test_auth_with_full_transport_is_dual(self) -> None:
        # An authentication event that carries the complete transport
        # tuple (both endpoints, a port, a protocol) is ALSO a network
        # connection -- both story blocks must fire.
        import tempfile
        rec = ('{"eventtype": "vpn.login", "user": "alice@example.com", '
               '"result": "success", "src_ip": "198.51.100.23", '
               '"src_port": 51820, "dst_ip": "10.0.0.1", '
               '"dst_port": 443, "protocol": "tcp"}')
        with tempfile.NamedTemporaryFile(
            "w", suffix=".jsonl", delete=False
        ) as fh:
            fh.write(rec + "\n")
            path = Path(fh.name)
        try:
            ws = profile(str(path), path.read_text(encoding="utf-8"))
        finally:
            path.unlink()
        self.assertTrue(ws["authentication"]["detected"], ws["authentication"])
        self.assertTrue(ws["network"]["detected"], ws["network"])

    def test_bare_ip_never_fires(self) -> None:
        # A record whose only network-ish content is an IP address field
        # must not be classified as a network event.
        import tempfile
        rec = ('{"user": "alice", "operation": "file_saved", '
               '"client_ip": "10.0.0.5", "document": "report.docx"}')
        with tempfile.NamedTemporaryFile(
            "w", suffix=".jsonl", delete=False
        ) as fh:
            fh.write(rec + "\n")
            path = Path(fh.name)
        try:
            ws = profile(str(path), path.read_text(encoding="utf-8"))
        finally:
            path.unlink()
        self.assertFalse(ws["network"]["detected"], ws["network"])
        self.assertEqual(ws["network"]["signals"], [])

    def test_detection_in_text_output(self) -> None:
        cp = subprocess.run(
            [sys.executable, str(PROFILE_SCRIPT),
             str(FIXTURES / "network_event.jsonl"), "--format", "text"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("network:", cp.stdout)
        self.assertIn("WARN-043", cp.stdout)

    def test_unknown_positional_text_still_scanned(self) -> None:
        # A raw AWS VPC Flow export is positional text with no priority,
        # no key=value and no month header: format stays "unknown", but
        # the records must still surface as _message lines so the value
        # scan sees the ACCEPT / REJECT vocabulary.
        import tempfile
        lines = (
            "2 123456789010 eni-0a1b 10.20.30.40 203.0.113.9 51544 443 6 "
            "25 20000 1782648001 1782648061 ACCEPT OK\n"
            "2 123456789010 eni-0a1b 10.20.30.41 198.51.100.7 40122 53 17 "
            "1 96 1782648002 1782648062 REJECT OK\n"
        )
        with tempfile.NamedTemporaryFile(
            "w", suffix=".log", delete=False
        ) as fh:
            fh.write(lines)
            path = Path(fh.name)
        try:
            ws = profile(str(path), path.read_text(encoding="utf-8"))
        finally:
            path.unlink()
        self.assertEqual(ws["detected_format"], "unknown")
        self.assertGreater(ws["record_count"], 0)
        self.assertTrue(ws["network"]["detected"], ws["network"])

    def test_login_field_name_is_not_an_auth_event(self) -> None:
        # "login=alice@example.com" inside a proxy web log is user
        # ATTRIBUTION (a field name), not a login event: the trailing "="
        # guard must keep the sample out of the authentication story while
        # the action vocabulary still classifies it as network.
        import tempfile
        line = (
            '<14>Jun 30 12:00:01 nss01 ZS-WEB: datetime=2026-06-30,'
            "action=Allowed,urlcategory=Business,serverip=203.0.113.9,"
            "clientip=10.20.30.40,login=alice@example.com\n"
        )
        with tempfile.NamedTemporaryFile(
            "w", suffix=".log", delete=False
        ) as fh:
            fh.write(line)
            path = Path(fh.name)
        try:
            ws = profile(str(path), path.read_text(encoding="utf-8"))
        finally:
            path.unlink()
        self.assertFalse(ws["authentication"]["detected"],
                         ws["authentication"])
        self.assertTrue(ws["network"]["detected"], ws["network"])

    def test_aaa_permit_deny_stays_authentication_only(self) -> None:
        # AAA precision rule: a TACACS+ gateway logs PERMIT / DENY as the
        # AUTHENTICATION outcome with no transport flow behind it. The
        # action-family vocabulary alone, inside an authentication event,
        # must not classify the sample as network -- the suppression is
        # reported so the author can see why.
        ws = _profile_fixture("tacacs_aaa.log")
        self.assertIn(ws["detected_format"], ("syslog-3164", "syslog-5424"))
        self.assertTrue(ws["authentication"]["detected"])
        net = ws["network"]
        self.assertFalse(net["detected"], net)
        self.assertIn("suppressed", net)

    def test_authorization_only_sample_is_authentication(self) -> None:
        # Edge case EC1: a log of ONLY "Authorization permitted / denied"
        # lines (no login lines) is an authentication-story event. Before
        # the authorization vocabulary was added it detected as
        # auth=False, network=True -- exactly backwards.
        import tempfile
        lines = "\n".join([
            '<14>Jun 19 09:51:59 aaa05.syd.example.local tacacsd[13844]: '
            '00000000 Authorization permitted for alice.admin at '
            '10.0.64.10, group Net Admins A, args service=shell cmd=show',
            '<14>Jun 19 13:42:14 legacy-aaa01.syd.example.local '
            'consumer_tacacs[2490]: Authorization denied for svc_vm at '
            '10.0.72.10: No context found. Expired?',
        ])
        with tempfile.NamedTemporaryFile(
            "w", suffix=".log", delete=False
        ) as fh:
            fh.write(lines + "\n")
            path = Path(fh.name)
        try:
            ws = profile(str(path), path.read_text(encoding="utf-8"))
        finally:
            path.unlink()
        self.assertTrue(ws["authentication"]["detected"],
                        ws["authentication"])
        self.assertFalse(ws["network"]["detected"], ws["network"])

    def test_ip_port_pair_lifts_aaa_suppression(self) -> None:
        # Edge case EC6: a mixed AAA + firewall syslog whose flow lines
        # quote BOTH endpoints as IP:port (but never a protocol word)
        # carries real flows -- suppression must lift. A single lone
        # IP:port (the TACACS chatter shape) must NOT lift it, which
        # test_aaa_permit_deny_stays_authentication_only pins.
        import tempfile
        lines = "\n".join([
            '<14>Jun 30 12:00:01 fw01 fw: action=allow '
            'src=10.0.0.5:51544 dst=203.0.113.9:443 bytes=1220',
            '<14>Jun 30 12:00:02 fw01 fw: action=deny '
            'src=10.0.0.6:40122 dst=198.51.100.7:53 bytes=96',
            '<14>Jun 30 12:00:03 fw01 vpn: user alice login success '
            'from 198.51.100.23',
        ])
        with tempfile.NamedTemporaryFile(
            "w", suffix=".log", delete=False
        ) as fh:
            fh.write(lines + "\n")
            path = Path(fh.name)
        try:
            ws = profile(str(path), path.read_text(encoding="utf-8"))
        finally:
            path.unlink()
        self.assertTrue(ws["authentication"]["detected"])
        self.assertTrue(ws["network"]["detected"], ws["network"])

    def test_pri_stripped_syslog_detected(self) -> None:
        # Edge case EC5: a relay can strip the <NNN> priority token; the
        # line is still syslog and must reach the syslog path. Pure
        # key=value samples must not be shadowed by the relaxed pattern.
        fmt = _pl.detect_format(
            "Jun 19 09:51:59 host1 app[1]: user session opened\n"
        )
        self.assertEqual(fmt, "syslog-3164")
        kv_text = (FIXTURES / "sample.kv").read_text(encoding="utf-8")
        self.assertEqual(_pl.detect_format(kv_text), "kv")

    def test_protocol_token_lifts_aaa_suppression(self) -> None:
        # The same suppression must NOT apply when real flow evidence is
        # present: the firewall syslog fixture carries login-free action
        # words AND proto=tcp/udp tokens, and an auth log that names a
        # protocol keeps both stories.
        ws = _profile_fixture("network_event_syslog.log")
        self.assertTrue(ws["network"]["detected"], ws["network"])
        # WAF fixture: structure signal lifts it too.
        ws2 = _profile_fixture("acmeshield_waf.log")
        self.assertTrue(ws2["network"]["detected"], ws2["network"])


class TestProcessDetection(unittest.TestCase):
    """detect_process is conservative: distinctive process / command
    vocabulary or an executable-path value, never a bare pid. It is
    independent of the auth block -- a command-accounting record is both
    reachable by AAA vocabulary and a command execution."""

    def test_detects_command_accounting(self) -> None:
        # A TACACS+-style accounting record with a command is a command
        # execution, not (only) authentication.
        ws = profile(
            "acct.jsonl",
            '{"user":"alice.admin","cmd":"show running-config",'
            '"device":"core-sw-01","pid":"4210"}\n',
        )
        proc = ws["process"]
        self.assertTrue(proc["detected"], proc)
        self.assertIn("xdm.source.process.command_line",
                      proc["recommended_fields"])

    def test_detects_endpoint_process(self) -> None:
        ws = profile(
            "edr.jsonl",
            '{"process_name":"powershell.exe","command_line":"-enc ...",'
            '"pid":"900"}\n',
        )
        self.assertTrue(ws["process"]["detected"], ws["process"])

    def test_detects_exe_path_value(self) -> None:
        # No process field name, but a value is an executable path.
        ws = profile(
            "val.jsonl",
            '{"detail":"launched C:\\\\Windows\\\\System32\\\\cmd.exe"}\n',
        )
        self.assertTrue(ws["process"]["detected"], ws["process"])
        self.assertTrue(
            any(s["kind"] == "value" for s in ws["process"]["signals"]),
            ws["process"]["signals"],
        )

    def test_no_false_fire_on_pid_only(self) -> None:
        # A lone pid is weak corroboration, never a trigger.
        ws = profile("hc.jsonl", '{"pid":"55","message":"health check ok"}\n')
        self.assertFalse(ws["process"]["detected"], ws["process"])

    def test_no_false_fire_on_plain_log(self) -> None:
        ws = profile("plain.jsonl", '{"src_ip":"1.1.1.1","bytes":5}\n')
        self.assertFalse(ws["process"]["detected"])


class TestClassificationBlock(unittest.TestCase):
    """The worksheet surfaces a per-record classification summary so a
    mixed feed is not collapsed into one story."""

    def test_mixed_feed_reports_multiple_kinds(self) -> None:
        # A TACACS+ feed with a login AND a command-accounting record must
        # report BOTH families and flag the sample as multi-kind, so the
        # author classifies per record instead of stamping one story.
        lines = "\n".join([
            '<14>Jun 19 09:50:01 aaa01 tacacsd[10]: type=AUTHENTICATION '
            'action=PERMIT user="bob" src_ip=10.0.35.9',
            '<14>Jun 19 09:51:59 aaa01 tacacsd[25]: type=ACCOUNTING '
            'action=Stop user="alice" dvc_ip=10.0.34.10 '
            'cmd="show bgp neighbors"',
        ])
        ws = profile("mixed.log", lines + "\n")
        clf = ws["classification"]
        self.assertIn("authentication", clf["families_detected"])
        self.assertIn("process", clf["families_detected"])
        self.assertTrue(clf["multi_kind"])
        self.assertIn("GOCORTEX_UNMODELLED", clf["guidance"])
        self.assertIn("per record", clf["guidance"].lower())

    def test_classification_always_present(self) -> None:
        ws = profile("plain.jsonl", '{"src_ip":"1.1.1.1","bytes":5}\n')
        self.assertIn("classification", ws)
        self.assertIn("families_detected", ws["classification"])


class TestMitreDetection(unittest.TestCase):
    """The profiler flags a MITRE reference by field name or ATT&CK-id
    value, and does not false-fire on a benign log."""

    def test_detects_name_and_value(self) -> None:
        ws = profile(
            "a.jsonl",
            '{"alert":"phish","mitre_technique":"T1566","category":"Initial Access"}\n',
        )
        m = ws["mitre"]
        self.assertTrue(m["detected"], m)
        kinds = {(s["field"], s["kind"]) for s in m["signals"]}
        self.assertIn(("mitre_technique", "name"), kinds)
        self.assertIn(("mitre_technique", "value"), kinds)
        self.assertIn("xdm.alert.mitre_techniques", m["target_fields"])

    def test_no_false_fire(self) -> None:
        ws = profile("b.jsonl", '{"src_ip":"1.1.1.1","bytes":5}\n')
        self.assertFalse(ws["mitre"]["detected"], ws["mitre"])


class TestCiscoCatalyst(unittest.TestCase):
    """Cisco IOS/IOS-XE Catalyst syslog: SEC_LOGIN success/failure lines
    (auth) mixed with LINK/SYS events profile as authentication."""

    def test_sec_login_detected(self) -> None:
        ws = _profile_fixture("cisco_catalyst_syslog.log")
        self.assertIn(ws["detected_format"], ("syslog-3164", "syslog-5424"))
        self.assertTrue(ws["authentication"]["detected"], ws["authentication"])


class TestCiscoWlc(unittest.TestCase):
    """Cisco WLC AireOS security syslog (AAA Authentication Failure for
    UserName, 802.1X/DOT1X) profiles as authentication."""

    def test_aireos_auth_detected(self) -> None:
        ws = _profile_fixture("cisco_wlc_syslog.log")
        self.assertIn(ws["detected_format"], ("syslog-3164", "syslog-5424"))
        self.assertTrue(ws["authentication"]["detected"], ws["authentication"])

    def test_relay_prepend_advisory_detected(self) -> None:
        # The fixture carries a relay-wrapped WLC line (device restated its
        # timestamp) and a double-<PRI> relayed line; the advisory fires.
        ws = _profile_fixture("cisco_wlc_syslog.log")
        relay = ws["syslog_relay"]
        self.assertTrue(relay["detected"], relay)
        kinds = {s["kind"] for s in relay["signals"]}
        self.assertTrue(
            {"double-pri", "wrapped-device-message"} & kinds, relay
        )


class TestSyslogRelayAdvisory(unittest.TestCase):
    """detect_syslog_relay flags a prepend shape (double <PRI> or a
    transport header in front of a device that restates its timestamp) and
    stays silent on a direct single-header line."""

    def test_direct_single_header_not_flagged(self) -> None:
        line = "<190>Jun 30 12:00:04 sw1 %SEC_LOGIN-5-LOGIN_SUCCESS: ok"
        self.assertFalse(_pl.detect_syslog_relay(line)["detected"])

    def test_double_pri_flagged(self) -> None:
        line = ("<190>Jun 30 12:00:10 relay01 "
                "<134>Jun 30 12:00:04 originhost app: msg")
        out = _pl.detect_syslog_relay(line)
        self.assertTrue(out["detected"])
        self.assertEqual(out["signals"][0]["kind"], "double-pri")

    def test_wrapped_device_message_flagged(self) -> None:
        line = ("<134>Jul 14 15:41:24 relay.example.net wlc01: *task: "
                "Jul 14 15:41:24.640: %APF-6-USER_NAME_CREATED: ...")
        out = _pl.detect_syslog_relay(line)
        self.assertTrue(out["detected"])
        self.assertEqual(out["signals"][0]["kind"], "wrapped-device-message")


class TestHpeSwitch(unittest.TestCase):
    """HPE ArubaOS-Switch event log (Event 3362: User <name> logged in
    from <ip> to SSH/WebUI/Console session) profiles as authentication."""

    def test_aos_switch_login_detected(self) -> None:
        ws = _profile_fixture("hpe_switch_syslog.log")
        self.assertIn(ws["detected_format"], ("syslog-3164", "syslog-5424"))
        self.assertTrue(ws["authentication"]["detected"], ws["authentication"])


class TestHuaweiVrp(unittest.TestCase):
    """Huawei VRP router syslog: SSH/AAA login lines are authentication and
    the SHELL CMDRECORD line is a command record, so the sample is
    multi-kind (authentication + process)."""

    def test_vrp_multi_kind(self) -> None:
        ws = _profile_fixture("huawei_rt_syslog.log")
        self.assertIn(ws["detected_format"], ("syslog-3164", "syslog-5424"))
        self.assertTrue(ws["authentication"]["detected"], ws["authentication"])
        fams = ws["classification"]["families_detected"]
        self.assertIn("authentication", fams)
        self.assertIn("process", fams)


class TestCelonisAudit(unittest.TestCase):
    """Celonis Audit Log API events (userId / userRole / event / ipAddress)
    profile as authentication, and the distinctive userRole field resolves
    to xdm.source.user.roles (added from the authoritative audit spec)."""

    def test_celonis_audit_is_authentication(self) -> None:
        ws = _profile_fixture("celonis_audit.jsonl")
        self.assertTrue(ws["authentication"]["detected"], ws["authentication"])

    def test_userrole_resolves_to_roles(self) -> None:
        ws = _profile_fixture("celonis_audit.jsonl")
        cand = {}
        for f in ws["fields"]:
            cand[f["path"]] = [c["xdm_path"] for c in (f.get("xdm_candidates") or [])]
        self.assertIn("xdm.source.user.roles", cand.get("userRole", []))


class TestCloudDetection(unittest.TestCase):
    """The cloud detector recognises the CloudTrail shape and names the
    provider, and stays silent on a non-cloud JSON source."""

    def test_cloudtrail_detected_as_aws(self):
        ws = _profile_fixture("aws_cloudtrail.jsonl")
        cloud = ws.get("cloud") or {}
        self.assertTrue(cloud.get("detected"))
        self.assertEqual(cloud.get("provider"), "aws")

    def test_azure_detected(self):
        ws = _profile_fixture("microsoft_azure.jsonl")
        cloud = ws.get("cloud") or {}
        self.assertTrue(cloud.get("detected"))
        self.assertEqual(cloud.get("provider"), "azure")

    def test_gcp_detected(self):
        ws = _profile_fixture("gcp_cloud_audit.jsonl")
        cloud = ws.get("cloud") or {}
        self.assertTrue(cloud.get("detected"))
        self.assertEqual(cloud.get("provider"), "gcp")

    def test_non_cloud_json_not_flagged(self):
        ws = _profile_fixture("auth_event.jsonl")
        self.assertFalse((ws.get("cloud") or {}).get("detected"))


if __name__ == "__main__":
    unittest.main()
