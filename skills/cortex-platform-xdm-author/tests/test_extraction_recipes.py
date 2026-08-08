# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the extraction-recipe layer (references/extraction-recipes.md).

Each recipe is a complete MODEL rule that must (a) lint with zero
error-severity findings and (b) extract the pinned values from its sample
line through the offline verifier. This guarantees every recipe shipped
in the reference is provably correct, not merely plausible. A final test
asserts the reference file actually carries each recipe, so the doc and
the verified rules cannot silently drift apart.
"""

from __future__ import annotations

import re
import json
import importlib.util
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _helpers import bundle_root, read_text  # noqa: E402

SCRIPTS = bundle_root() / "scripts"
RECIPES_DOC = bundle_root() / "references" / "extraction-recipes.md"
SROS_FIXTURE = bundle_root() / "tests" / "fixtures" / "nokia_sros_event_token.log"
SROS_SHAPES = bundle_root() / "tests" / "fixtures" / "nokia_sros_account_shapes.log"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


_lint = _load("lint_rule")
_verify = _load("verify_rule")


# name -> (rule, sample line, {expected xdm target: value})
RECIPES = {
    "kv": (
        r'''[MODEL: dataset=vendor_kv_raw]
filter
    _raw_log != null
| alter
    tmp_user = arrayindex(regextract(_raw_log, "\buser=([^\s]+)"), 0),
    tmp_msg = arrayindex(regextract(_raw_log, "msg=\"([^\"]*)\""), 0)
| alter
    xdm.source.user.username = tmp_user,
    xdm.event.description = tmp_msg
;''',
        'ts=2026-07-09 user=alice.admin action=login msg="Login succeeded"',
        {"xdm.source.user.username": "alice.admin",
         "xdm.event.description": "Login succeeded"},
    ),
    "tuple": (
        r'''[MODEL: dataset=vendor_fw_raw]
filter
    _raw_log != null
| alter
    tmp_src_ip = arrayindex(regextract(_raw_log, "src=(\d{1,3}(?:\.\d{1,3}){3})"), 0),
    tmp_src_port = arrayindex(regextract(_raw_log, "src=\d{1,3}(?:\.\d{1,3}){3}:(\d{1,5})"), 0),
    tmp_dst_ip = arrayindex(regextract(_raw_log, "dst=(\d{1,3}(?:\.\d{1,3}){3})"), 0)
| alter
    xdm.source.ipv4 = tmp_src_ip,
    xdm.source.port = to_integer(to_number(tmp_src_port)),
    xdm.target.ipv4 = tmp_dst_ip
;''',
        'action=accept src=10.0.0.5:51000 dst=93.184.216.34:443 proto=tcp',
        {"xdm.source.ipv4": "10.0.0.5", "xdm.source.port": 51000,
         "xdm.target.ipv4": "93.184.216.34"},
    ),
    "cef": (
        r'''[MODEL: dataset=vendor_cef_raw]
filter
    _raw_log != null
| alter
    tmp_cef_name = arrayindex(split(_raw_log, "|"), 5),
    tmp_suser = arrayindex(regextract(_raw_log, "suser=([^\s]+)"), 0)
| alter
    xdm.event.original_event_type = tmp_cef_name,
    xdm.source.user.username = tmp_suser
;''',
        'CEF:0|Acme|Box|1.0|100|User login|5|src=10.0.0.5 suser=alice',
        {"xdm.event.original_event_type": "User login",
         "xdm.source.user.username": "alice"},
    ),
    "leef": (
        r'''[MODEL: dataset=vendor_leef_raw]
filter
    _raw_log != null
| alter
    tmp_leef_evt = arrayindex(split(_raw_log, "|"), 4),
    tmp_usr = arrayindex(regextract(_raw_log, "usrName=([^\s\t]+)"), 0)
| alter
    xdm.event.original_event_type = tmp_leef_evt,
    xdm.source.user.username = tmp_usr
;''',
        'LEEF:2.0|Acme|Box|1.0|4624|usrName=alice src=10.0.0.5',
        {"xdm.event.original_event_type": "4624",
         "xdm.source.user.username": "alice"},
    ),
    "syslog3164": (
        r'''[MODEL: dataset=vendor_nix_raw]
filter
    _raw_log != null
| alter
    tmp_host = arrayindex(regextract(_raw_log, "^.*(?:<\d{1,3}>)?[A-Za-z]{3}\s+\d+\s+[\d:]+\s+(\S+)\s"), 0),
    tmp_proc = arrayindex(regextract(_raw_log, "(\w+)\[\d+\]:"), 0),
    tmp_pid = arrayindex(regextract(_raw_log, "\[(\d+)\]:"), 0)
| alter
    xdm.observer.name = tmp_host,
    xdm.source.process.name = tmp_proc,
    xdm.source.process.pid = to_integer(to_number(tmp_pid))
;''',
        'Jun 19 09:51:59 host01 sshd[1234]: Accepted password for alice',
        {"xdm.observer.name": "host01", "xdm.source.process.name": "sshd",
         "xdm.source.process.pid": 1234},
    ),
    "scalars": (
        r'''[MODEL: dataset=vendor_text_raw]
filter
    _raw_log != null
| alter
    tmp_ip = arrayindex(regextract(_raw_log, "\b(\d{1,3}(?:\.\d{1,3}){3})\b"), 0),
    tmp_mac = arrayindex(regextract(_raw_log, "\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b"), 0),
    tmp_email = arrayindex(regextract(_raw_log, "\b([\w.+-]+@[\w.-]+\.\w+)\b"), 0)
| alter
    xdm.source.ipv4 = tmp_ip,
    xdm.source.host.mac_addresses = arraycreate(tmp_mac),
    xdm.source.user.upn = tmp_email
;''',
        'Login from 10.0.0.5 (aa:bb:cc:dd:ee:ff) by alice@corp.example.com',
        {"xdm.source.ipv4": "10.0.0.5",
         "xdm.source.user.upn": "alice@corp.example.com"},
    ),
    "sros": (
        r'''[MODEL: dataset=vendor_sros_raw]
filter
    _raw_log != null
| alter
    // Anchor on the SEVERITY, a closed documented vendor enum. Anchoring
    // on the router instance instead (a literal "Base ") silently drops
    // every event inside a named VPRN, which is where the customer-VPN
    // traffic is.
    tmp_sros_app  = arrayindex(regextract(_raw_log, "\s([A-Z][A-Z0-9_]{1,15})-(?:CLEARED|CRITICAL|MAJOR|MINOR|WARNING|INDETERMINATE)-"), 0),
    tmp_sros_sev  = arrayindex(regextract(_raw_log, "\s[A-Z][A-Z0-9_]{1,15}-(CLEARED|CRITICAL|MAJOR|MINOR|WARNING|INDETERMINATE)-"), 0),
    tmp_sros_evt  = arrayindex(regextract(_raw_log, "\s[A-Z][A-Z0-9_]{1,15}-(?:CLEARED|CRITICAL|MAJOR|MINOR|WARNING|INDETERMINATE)-([A-Za-z0-9_]+)-\d+"), 0),
    tmp_sros_evid = arrayindex(regextract(_raw_log, "\s[A-Z][A-Z0-9_]{1,15}-(?:CLEARED|CRITICAL|MAJOR|MINOR|WARNING|INDETERMINATE)-[A-Za-z0-9_]+-(\d+)"), 0),
    tmp_sros_rtr  = arrayindex(regextract(_raw_log, "\s\d+\s(\S+)\s[A-Z][A-Z0-9_]{1,15}-(?:CLEARED|CRITICAL|MAJOR|MINOR|WARNING|INDETERMINATE)-"), 0),
    // The subject is only an account when it is a single token: the
    // command events also fire for script-driven CLI, where it names the
    // mechanism. A SHAPE test, never an allowlist -- an account of
    // "${jndi" is an injection attempt and must stay visible.
    tmp_sros_subject  = arrayindex(regextract(_raw_log, "-\d+\s\[(\S+)\]"), 0),
    tmp_sros_body_usr = arrayindex(regextract(_raw_log, "\bUser (\S+)"), 0)
| alter
    // The body names the user on some applications and writes a bare
    // "User from <ip>" on others, where the account is ONLY in the
    // subject bracket. Guard the literal, then prefer the subject on the
    // user-authentication events.
    tmp_sros_body_user = if(tmp_sros_body_usr != "from", tmp_sros_body_usr),
    tmp_sros_is_userevt = if(tmp_sros_evt ~= "^(cli|ssh|ftp|grpc|netconf)_user_(login|logout)", "y")
| alter
    tmp_sros_user = if(
        tmp_sros_is_userevt = "y", coalesce(tmp_sros_subject, tmp_sros_body_user),
        tmp_sros_body_user)
| alter
    xdm.event.original_event_type = concat(tmp_sros_app, "-", tmp_sros_evt),
    xdm.event.id = tmp_sros_evid,
    xdm.source.user.username = tmp_sros_user,
    // DERIVE the UPN rather than padding it: the device carries an
    // account and no domain, and @localhost states that the account is
    // local to the device, which is true for an appliance login.
    xdm.source.user.upn = if(
        tmp_sros_user contains "@", tmp_sros_user,
        tmp_sros_user != null, concat(tmp_sros_user, "@localhost")),
    xdm.observer.name = tmp_sros_rtr,
    xdm.event.log_level = if(
        tmp_sros_sev = "CRITICAL", XDM_CONST.LOG_LEVEL_CRITICAL,
        tmp_sros_sev = "MAJOR", XDM_CONST.LOG_LEVEL_ERROR,
        tmp_sros_sev = "MINOR", XDM_CONST.LOG_LEVEL_WARNING,
        tmp_sros_sev = "WARNING", XDM_CONST.LOG_LEVEL_WARNING,
        tmp_sros_sev = "CLEARED", XDM_CONST.LOG_LEVEL_INFORMATIONAL,
        tmp_sros_sev = "INDETERMINATE", XDM_CONST.LOG_LEVEL_INFORMATIONAL)
;''',
        '<187>Jul 30 23:25:20 172.20.209.230 host-4746bb28: 18249532 vprn170 USER-MINOR-cli_user_login-2001 [user_575b9419]:  User from 172.25.220.157 logged in',
        {"xdm.event.original_event_type": "USER-cli_user_login",
         "xdm.event.id": "2001",
         "xdm.source.user.username": "user_575b9419",
         "xdm.source.user.upn": "user_575b9419@localhost",
         "xdm.observer.name": "vprn170"},
    ),
    "ios_bracket": (
        r'''[MODEL: dataset=vendor_ios_raw]
filter
    _raw_log != null
| alter
    tmp_ios_event = arrayindex(regextract(_raw_log, "%([\w]+-\d-\w+):"), 0),
    tmp_ios_user = arrayindex(regextract(_raw_log, "\[user: ?([^\]]+)\]"), 0),
    tmp_ios_src = arrayindex(regextract(_raw_log, "\[Source: ?(\d{1,3}(?:\.\d{1,3}){3})\]"), 0)
| alter
    xdm.event.original_event_type = tmp_ios_event,
    xdm.source.user.username = tmp_ios_user,
    xdm.source.ipv4 = tmp_ios_src
;''',
        '<190>Jun 30 12:00:04 sw1 %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin] [Source: 10.0.0.5] [localport: 22] at 12:00:04 UTC',
        {"xdm.event.original_event_type": "SEC_LOGIN-5-LOGIN_SUCCESS",
         "xdm.source.user.username": "admin",
         "xdm.source.ipv4": "10.0.0.5"},
    ),
    "vrp_paren_kv": (
        r'''[MODEL: dataset=vendor_vrp_raw]
filter
    _raw_log != null
| alter
    tmp_vrp_event = arrayindex(regextract(_raw_log, "%%\d*\w+/\d/(\w+)"), 0),
    tmp_vrp_user = arrayindex(regextract(_raw_log, "UserName=([^,)]+)"), 0),
    tmp_vrp_ip = arrayindex(regextract(_raw_log, "IPAddress=([^,)]+)"), 0)
| alter
    xdm.event.original_event_type = tmp_vrp_event,
    xdm.source.user.username = tmp_vrp_user,
    xdm.source.ipv4 = tmp_vrp_ip
;''',
        '<190>Jun 30 12:00:04 rtr1 %%01SSH/4/SSH_FAIL(l):Failed to login through SSH. (UserName=admin, IPAddress=10.0.0.5)',
        {"xdm.event.original_event_type": "SSH_FAIL",
         "xdm.source.user.username": "admin",
         "xdm.source.ipv4": "10.0.0.5"},
    ),
    "clf": (
        r'''[MODEL: dataset=vendor_clf_raw]
filter
    _raw_log != null
| alter
    tmp_clf_ip = arrayindex(regextract(_raw_log, "^(\d{1,3}(?:\.\d{1,3}){3})"), 0),
    tmp_clf_method = arrayindex(regextract(_raw_log, "\"(\w+) \S+ HTTP/\d"), 0),
    tmp_clf_url = arrayindex(regextract(_raw_log, "\"\w+ (\S+) HTTP/\d"), 0),
    tmp_clf_ua = arrayindex(regextract(_raw_log, "\"([^\"]*)\"\s*$"), 0)
| alter
    xdm.source.ipv4 = tmp_clf_ip,
    xdm.network.http.method = tmp_clf_method,
    xdm.network.http.url = tmp_clf_url,
    xdm.source.user_agent = tmp_clf_ua
;''',
        '10.0.0.5 - alice [30/Jun/2025:12:00:04 +0000] "GET /app/login HTTP/1.1" 200 1234 "https://portal.example.com/" "Mozilla/5.0 (Windows NT 10.0)"',
        {"xdm.source.ipv4": "10.0.0.5",
         "xdm.network.http.method": "GET",
         "xdm.network.http.url": "/app/login",
         "xdm.source.user_agent": "Mozilla/5.0 (Windows NT 10.0)"},
    ),
    "wlc_prepend": (
        r'''[MODEL: dataset=cisco_wlc_raw]
filter
    _raw_log != null
| alter
    tmp_wlc_host     = arrayindex(regextract(_raw_log, "^.*<\d{1,3}>[A-Za-z]{3}\s+\d+\s+[\d:]+\s+(\S+)\s"), 0),
    tmp_wlc_mnemonic = arrayindex(regextract(_raw_log, "%(\w+-\d-\w+):"), 0),
    tmp_wlc_mac      = arrayindex(regextract(_raw_log, "for mobile ([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})"), 0)
| alter
    xdm.observer.name = tmp_wlc_host,
    xdm.event.original_event_type = tmp_wlc_mnemonic,
    xdm.source.host.mac_addresses = arraycreate(tmp_wlc_mac)
;''',
        '<134>Jul 14 15:41:24 wlc-mgmt.example.net wlc01: *apfReceiveTask: Jul 14 15:41:24.640: %APF-6-USER_NAME_CREATED: [SS]apf_ms.c:9003 Username entry (3E-A8-8D-20-D1-1E) with length (17) created for mobile 3e:a8:8d:20:d1:1e',
        {"xdm.observer.name": "wlc-mgmt.example.net",
         "xdm.event.original_event_type": "APF-6-USER_NAME_CREATED",
         "xdm.source.host.mac_addresses": ["3e:a8:8d:20:d1:1e"]},
    ),
}


class TestExtractionRecipes(unittest.TestCase):
    def test_recipes_lint_clean(self):
        for name, (rule, _s, _e) in RECIPES.items():
            errs = [v for v in _lint.lint(rule) if v["severity"] == "error"]
            self.assertEqual(errs, [], f"{name}: {[v['rule_id'] for v in errs]}")

    def test_recipes_extract_expected_values(self):
        for name, (rule, sample, expected) in RECIPES.items():
            out = _verify.evaluate_rule(rule, sample)
            for path, want in expected.items():
                self.assertEqual(
                    out.get(path), want,
                    f"{name}: {path} got {out.get(path)!r}, want {want!r}",
                )

    def test_mac_recipe_wraps_array(self):
        # The MAC leaf is an array field; the recipe must wrap it.
        out = _verify.evaluate_rule(*RECIPES["scalars"][:2])
        self.assertEqual(
            out.get("xdm.source.host.mac_addresses"), ["aa:bb:cc:dd:ee:ff"]
        )

    def test_clf_recipe_on_tomcat_fixture(self):
        # The Combined Log Format recipe extracts HTTP fields from a real
        # Tomcat access-log fixture (a different line than the doc sample).
        fixture = (
            bundle_root() / "tests" / "fixtures" / "apache_tomcat_access.log"
        ).read_text(encoding="utf-8").splitlines()
        rule = RECIPES["clf"][0]
        out = _verify.evaluate_rule(rule, fixture[1])  # the POST /app/admin 403 line
        self.assertEqual(out.get("xdm.network.http.method"), "POST")
        self.assertEqual(out.get("xdm.network.http.url"), "/app/admin")
        self.assertEqual(out.get("xdm.source.ipv4"), "10.0.0.9")

    def test_recipe5_prepend_tolerant_across_arrival_shapes(self):
        # HARD RULE: the same source arrives no-PRI, with a PRI, and
        # relay-prepended -- the prepend-tolerant host must yield the origin
        # host (host01) in every form, and proc/pid are token-anchored.
        rule = RECIPES["syslog3164"][0]
        base = "sshd[1234]: Accepted password for alice"
        shapes = {
            "no-PRI": f"Jun 19 09:51:59 host01 {base}",
            "PRI": f"<134>Jun 19 09:51:59 host01 {base}",
            "relayed": (
                "<190>Jun 30 12:00:10 relay01 "
                f"<134>Jun 19 09:51:59 host01 {base}"
            ),
        }
        for name, line in shapes.items():
            out = _verify.evaluate_rule(rule, line)
            self.assertEqual(out.get("xdm.observer.name"), "host01", name)
            self.assertEqual(out.get("xdm.source.process.name"), "sshd", name)
            self.assertEqual(out.get("xdm.source.process.pid"), 1234, name)

    def test_wlc_recipe_direct_and_prepend_identical(self):
        # The WLC recipe extracts the identical mnemonic + MAC whether the
        # line is relay-prepended or direct off the box (host is only present
        # in the prepended envelope). Proves the hard rule end to end.
        rule = RECIPES["wlc_prepend"][0]
        prepended = RECIPES["wlc_prepend"][1]
        direct = (
            "*apfReceiveTask: Jul 14 15:41:24.640: %APF-6-USER_NAME_CREATED: "
            "[SS]apf_ms.c:9003 Username entry (3E-A8-8D-20-D1-1E) with length "
            "(17) created for mobile 3e:a8:8d:20:d1:1e"
        )
        op = _verify.evaluate_rule(rule, prepended)
        od = _verify.evaluate_rule(rule, direct)
        for out in (op, od):
            self.assertEqual(
                out.get("xdm.event.original_event_type"),
                "APF-6-USER_NAME_CREATED",
            )
            self.assertEqual(
                out.get("xdm.source.host.mac_addresses"),
                ["3e:a8:8d:20:d1:1e"],
            )
        # Host is sourced from the envelope, so only the prepended form has it.
        self.assertEqual(op.get("xdm.observer.name"), "wlc-mgmt.example.net")
        self.assertIsNone(od.get("xdm.observer.name"))

    def test_wlc_recipe_on_a_deep_hostname_and_ha_task(self):
        # The HA-SSO variant: a four-label hostname with hyphens in the
        # leftmost label, and a task name the direct-arrival samples do
        # not carry. Both are what the greedy envelope capture has to
        # survive, so this shape is held separately from line 269's.
        rule = RECIPES["wlc_prepend"][0]
        line = (
            "<134>Jul 14 15:41:24 wlc332-ha-mgmt.au.example.net wlc12-active: "
            "*haSSOServiceTask3: Jul 14 15:41:24.640: %APF-6-USER_NAME_CREATED: "
            "[SS]apf_ms.c:9003 Username entry (3E-A8-8D-20-D1-1E) with length "
            "(17) created for mobile 3e:a8:8d:20:d1:1e"
        )
        out = _verify.evaluate_rule(rule, line)
        self.assertEqual(
            out.get("xdm.observer.name"), "wlc332-ha-mgmt.au.example.net"
        )
        self.assertEqual(
            out.get("xdm.event.original_event_type"), "APF-6-USER_NAME_CREATED"
        )
        self.assertEqual(
            out.get("xdm.source.host.mac_addresses"), ["3e:a8:8d:20:d1:1e"]
        )

    def test_sros_recipe_never_captures_the_word_from(self):
        """The principal is written two ways on this vendor. Some
        applications name the account in the body; others write a bare
        'User from <ip>' and carry the account only in the bracketed
        subject. A plain '\\bUser (\\S+)' captures the literal 'from' on
        every record of the second shape -- not null, not empty, not the
        catch-all, and it lints clean, so no count-based check sees it.
        Downstream it groups an entire event family under one fictional
        account. This asserts the guard directly."""
        rule = RECIPES["sros"][0]
        lines = (
            SROS_FIXTURE.read_text(encoding="utf-8").strip().splitlines()
        )
        self.assertEqual(len(lines), 4, "fixture should carry all four shapes")
        for line in lines:
            out = _verify.evaluate_rule(rule, {"_raw_log": line})
            self.assertNotEqual(
                out.get("xdm.source.user.username"),
                "from",
                f"captured the literal 'from' as the principal: {line[:90]}",
            )

    def test_sros_recipe_across_both_principal_shapes(self):
        """Body-named and subject-only records must both resolve the same
        account, and a record with no principal must resolve none rather
        than inventing one."""
        rule = RECIPES["sros"][0]
        lines = SROS_FIXTURE.read_text(encoding="utf-8").strip().splitlines()
        body_named, subject_only, no_user, command_io = lines
        self.assertEqual(
            _verify.evaluate_rule(rule, {"_raw_log": body_named})
            .get("xdm.source.user.username"),
            "user_575b9419",
        )
        self.assertEqual(
            _verify.evaluate_rule(rule, {"_raw_log": subject_only})
            .get("xdm.source.user.username"),
            "user_575b9419",
        )
        # A routing-protocol MD5 failure names a peer, not a principal.
        self.assertIsNone(
            _verify.evaluate_rule(rule, {"_raw_log": no_user})
            .get("xdm.source.user.username")
        )
        self.assertEqual(
            _verify.evaluate_rule(rule, {"_raw_log": no_user})
            .get("xdm.event.original_event_type"),
            "SECURITY-tmnxMD5AuthFailure",
        )
        # Command I/O keeps its identity; routing it to the process family
        # is the rule author's job, but the token must parse.
        self.assertEqual(
            _verify.evaluate_rule(rule, {"_raw_log": command_io})
            .get("xdm.event.original_event_type"),
            "USER-cli_config_io",
        )

    def test_sros_recipe_parses_named_vprn_instances(self):
        """Anchoring the token on the literal router instance 'Base' drops
        every event inside a named VPRN, which is where customer-VPN
        activity is. The severity enum is the stable anchor."""
        rule = RECIPES["sros"][0]
        lines = SROS_FIXTURE.read_text(encoding="utf-8").strip().splitlines()
        for line in lines:
            out = _verify.evaluate_rule(rule, {"_raw_log": line})
            self.assertIsNotNone(
                out.get("xdm.event.original_event_type"),
                f"event token not parsed: {line[:90]}",
            )
        # vprn-scoped records resolve their routing instance, not "Base".
        self.assertEqual(
            _verify.evaluate_rule(rule, {"_raw_log": lines[0]})
            .get("xdm.observer.name"),
            "vprn170",
        )

    def test_sros_recipe_derives_upn_rather_than_padding_it(self):
        """A device carrying an account and no domain can always CONSTRUCT
        a UPN. Padding it with an empty string satisfies the mandatory set,
        the null check and the population ratio at once, while the account
        sits in the record and no operator pivoting on a UPN can find it.
        Derive, do not pad."""
        rule = RECIPES["sros"][0]
        for line in SROS_SHAPES.read_text(encoding="utf-8").strip().splitlines()[:2]:
            out = _verify.evaluate_rule(rule, {"_raw_log": line})
            self.assertEqual(
                out.get("xdm.source.user.upn"), "user_90226669@localhost"
                if "90226669" in line else "user_575b9419@localhost",
            )
            self.assertNotEqual(out.get("xdm.source.user.upn"), "")

    def test_sros_recipe_account_is_a_shape_test_not_an_allowlist(self):
        """The subject is only an account when it is a single token: the
        command events also fire for script-driven CLI, where it names the
        mechanism. The test must be on SHAPE, because the same field
        carries hostile input that has to stay visible."""
        rule = RECIPES["sros"][0]
        lines = SROS_SHAPES.read_text(encoding="utf-8").strip().splitlines()
        injection, script_driven = lines[2], lines[3]
        # A login attempt with an injection payload as the account is a
        # single token and is real security data: it must survive.
        out = _verify.evaluate_rule(rule, {"_raw_log": injection})
        self.assertEqual(out.get("xdm.source.user.username"), "${jndi")
        # A multi-word mechanism name is not an account and must not be
        # mapped as one.
        out = _verify.evaluate_rule(rule, {"_raw_log": script_driven})
        self.assertIsNone(out.get("xdm.source.user.username"))
        self.assertIsNone(out.get("xdm.source.user.upn"))

    def test_sros_shape_test_accepts_a_machine_account(self):
        """The shape test must stay a test of SHAPE. Tightening it into a
        character allowlist would flag every Active Directory machine
        account, since a computer account legitimately ends in a dollar
        sign -- a failure that presents as a tuning problem rather than a
        design error, so it would likely be patched with exclusions
        instead of corrected."""
        rule = RECIPES["sros"][0]
        line = (
            "<187>Jul 30 23:25:20 172.20.209.230 host-4746bb28: 18249532 "
            "vprn170 USER-MINOR-cli_user_login-2001 [WIN-DC01$]:  "
            "User from 172.25.220.157 logged in"
        )
        out = _verify.evaluate_rule(rule, {"_raw_log": line})
        self.assertEqual(out.get("xdm.source.user.username"), "WIN-DC01$")

    def test_doc_carries_every_recipe(self):
        # The reference and these verified rules must not drift apart: each
        # recipe's dataset header must appear verbatim in the doc.
        doc = RECIPES_DOC.read_text(encoding="utf-8")
        for name, (rule, _s, _e) in RECIPES.items():
            header = rule.splitlines()[0]  # [MODEL: dataset=..._raw]
            self.assertIn(header, doc, f"{name}: {header} missing from doc")
            # The header alone is not enough: the body drifted twice while
            # the header matched, so the tests passed against their own
            # stale copy while the shipped recipe was wrong. Compare the
            # whole rule.
            self.assertIn(
                rule, doc,
                f"{name}: the verified rule and the reference have drifted; "
                "the doc is the source of truth, so copy it back into "
                "RECIPES rather than editing around it",
            )


class TestNokiaNfmpNestedApplicationHeader(unittest.TestCase):
    """Recipe 14 / walkthrough 16: an application writing its OWN header
    inside a syslog message.

    Each assertion pins a trap that produces a populated but wrong field
    rather than a visible failure, which is why they are worth a test
    each rather than a line of prose."""

    RULE = bundle_root() / "tests" / "fixtures" / "nokia_nfmp.xql"
    SAMPLE = bundle_root() / "tests" / "fixtures" / "nokia_nfmp.jsonl"
    DOC = (
        bundle_root() / "references" / "worked-examples"
        / "16-nokia-nfmp-management-plane.md"
    )

    @classmethod
    def setUpClass(cls) -> None:
        cls.rule = cls.RULE.read_text(encoding="utf-8")
        cls.records = [
            json.loads(ln)
            for ln in cls.SAMPLE.read_text(encoding="utf-8").splitlines()
            if ln.strip()
        ]
        cls.out = [_verify.evaluate_rule(cls.rule, r) for r in cls.records]

    def _row(self, needle: str) -> dict:
        for rec, out in zip(self.records, self.out):
            if needle in rec:
                return out
        self.fail(f"no fixture record containing {needle!r}")

    def test_rule_lints_clean(self):
        findings = _lint.lint(self.rule)
        self.assertEqual([f for f in findings if f["severity"] == "error"], [])
        self.assertEqual(findings, [], findings)

    def test_bracket_capture_drops_the_inner_space(self):
        """The vendor writes "[198.51.100.28 ]" -- the space is INSIDE the
        delimiter, so a delimiter-anchored capture keeps it and the
        address never compares equal to the same address without it."""
        out = self._row("management IP Address")
        self.assertEqual(out["xdm.target.ipv4"], "198.51.100.28")

    def test_empty_class_field_does_not_drop_the_record(self):
        """The JVM record carries an empty class (`><>`). A `+` capture
        would fail the whole header and silently drop every field."""
        out = self._row("JVM MEMORY")
        self.assertEqual(
            out["xdm.event.original_event_type"], "GOCORTEX_UNMODELLED"
        )
        # the record is still classified and still carries its severity
        self.assertEqual(out["xdm.event.type"], "nfmp_platform")
        self.assertEqual(
            out["xdm.event.log_level"], "XDM_CONST.LOG_LEVEL_INFORMATIONAL"
        )
        self.assertEqual(out["xdm.source.process.name"], "MemoryMonitorPrintTimer")

    def test_logged_in_is_not_treated_as_authentication(self):
        """`EXCEPTION logged in java.net.ConnectException` is the phrase
        meaning written-to-a-log. Nothing in this rule may tag it."""
        out = self._row("EXCEPTION logged in")
        self.assertNotIn("xdm.event.tags", out)
        self.assertIsNone(out.get("xdm.source.user.username"))
        self.assertEqual(out["xdm.event.type"], "nfmp_mediation")

    def test_no_record_claims_the_authentication_story(self):
        """The whole source: not one authentication tag anywhere."""
        for rec, out in zip(self.records, self.out):
            self.assertNotIn("xdm.event.tags", out, rec[:70])

    def test_could_not_login_is_also_not_authentication(self):
        out = self._row("Could not login")
        self.assertIsNone(out.get("xdm.source.user.username"))

    def test_thread_capture_survives_colons_and_parentheses(self):
        """The ZooKeeper thread name carries an address, colons and its
        own parentheses; the `<>` delimiter is the only safe bound."""
        out = self._row("Could not login")
        self.assertIn("SendThread(", out["xdm.source.process.name"])
        self.assertIn(":2181", out["xdm.source.process.name"])

    def test_audit_record_is_a_command_execution_not_a_login(self):
        out = self._row("User Activity for User")
        self.assertEqual(out["xdm.event.operation"], "XDM_CONST.OPERATION_TYPE_AUDIT")
        self.assertIsNotNone(out["xdm.target.process.command_line"])
        self.assertEqual(out["xdm.source.user.username"], "4008225")

    def test_audit_thread_records_the_access_channel(self):
        """http_8080 is the web interface; an internal worker is not."""
        web = self._row("http_8080")
        self.assertEqual(web["xdm.source.process.name"], "http_8080 task-11")
        self.assertEqual(web["xdm.event.outcome"], "XDM_CONST.OUTCOME_FAILED")

    def test_continuation_lines_reach_the_catch_all(self):
        for needle in ("#011at java.lang.Thread.run", "DbConnection{"):
            out = self._row(needle)
            self.assertEqual(
                out["xdm.event.original_event_type"], "GOCORTEX_UNMODELLED"
            )
            self.assertEqual(out["xdm.event.type"], "nfmp_continuation")

    def test_severity_needs_integer_division(self):
        """divide() yields a float, so the quotient must be coerced before
        being multiplied back. Without it every record decodes as severity
        0 and every log level comes out ERROR."""
        broken = self.rule.replace(
            "to_integer(divide(tmp_pri, 8))", "divide(tmp_pri, 8)"
        )
        self.assertNotEqual(broken, self.rule, "the guarded idiom moved")
        out = _verify.evaluate_rule(broken, self.records[-1])
        self.assertEqual(out["xdm.event.log_level"], "XDM_CONST.LOG_LEVEL_ERROR")
        # the shipped rule gets it right on the same record
        self.assertEqual(
            self.out[-1]["xdm.event.log_level"],
            "XDM_CONST.LOG_LEVEL_INFORMATIONAL",
        )

    def test_every_record_is_mapped(self):
        """The catch-all keeps the datamodel row count equal to raw."""
        self.assertEqual(len(self.out), len(self.records))
        for out in self.out:
            self.assertIsNotNone(out.get("xdm.event.original_event_type"))

    def test_walkthrough_carries_the_verified_rule_verbatim(self):
        doc = self.DOC.read_text(encoding="utf-8")
        body = "\n".join(
            ln for ln in self.rule.splitlines()
            if not ln.startswith("// SPDX") and ln.strip() != "//"
        ).rstrip()
        self.assertIn(
            body, doc,
            "walkthrough 16 and tests/fixtures/nokia_nfmp.xql have drifted",
        )


class TestCiscoMessageToken(unittest.TestCase):
    """Recipe 15: the %FACILITY-SUBFACILITY-SEVERITY-MNEMONIC token.

    Cisco documents SUBFACILITY as optional and as one OR two extra
    hyphenated codes, and documents a card-prefixed form that wraps a
    second complete token. A pattern that assumes three parts fails to
    match the first and captures the WRAPPER on the second."""

    FIXTURE = bundle_root() / "tests" / "fixtures" / "cisco_message_shapes.log"
    TOK = r".*%([A-Z][A-Z0-9_]*(?:-[A-Z][A-Z0-9_]*)*)-(\d)-([A-Z0-9_]+):(?!SLOT\d)"
    NAIVE = r"%([A-Z][A-Z0-9_]+)-(\d)-([A-Z0-9_]+)"

    @classmethod
    def setUpClass(cls) -> None:
        cls.lines = [
            l for l in cls.FIXTURE.read_text(encoding="utf-8").splitlines() if l.strip()
        ]

    def _tok(self, line, pattern=None):
        m = re.search(pattern or self.TOK, line)
        return m.groups() if m else None

    def _line(self, needle):
        for l in self.lines:
            if needle in l:
                return l
        self.fail(f"no fixture line containing {needle!r}")

    def test_plain_token(self):
        self.assertEqual(
            self._tok(self._line("TOOMANY_AUTHFAILS")),
            ("LOGIN", "3", "TOOMANY_AUTHFAILS"),
        )

    def test_two_part_subfacility_is_kept_with_the_facility(self):
        """DIAG-SP-STDBY names the component that emitted the record.
        Keeping it is information; discarding it is loss."""
        self.assertEqual(
            self._tok(self._line("RUN_MINIMUM")),
            ("DIAG-SP-STDBY", "6", "RUN_MINIMUM"),
        )

    def test_naive_pattern_cannot_match_a_subfacility(self):
        """The reason this recipe exists: the obvious pattern does not
        mis-parse a subfacility message, it drops it entirely."""
        self.assertIsNone(
            self._tok(self._line("RUN_MINIMUM"), self.NAIVE)
        )

    def test_card_wrapper_yields_the_inner_event(self):
        self.assertEqual(
            self._tok(self._line("SLOT5")), ("LINK", "3", "UPDOWN")
        )

    def test_naive_pattern_captures_the_card_wrapper(self):
        """The dangerous case: VIP-3-MSG is not an event, and a rule
        using the naive pattern reports it as one."""
        self.assertEqual(
            self._tok(self._line("SLOT5"), self.NAIVE), ("VIP", "3", "MSG")
        )

    def test_card_wrapper_alone_yields_nothing(self):
        """A wrapper with no inner message must be null, not the
        wrapper -- otherwise the guard has bought nothing."""
        self.assertIsNone(self._tok("%VIP-3-MSG:SLOT5 inner message lost"))

    def test_continuation_part_has_no_token(self):
        self.assertIsNone(self._tok(self._line("CONTINUATION #02")))

    def test_relay_prepended_line_still_resolves(self):
        relayed = "<13>Jan  1 00:00:00 relay rl[1]: " + self._line("SLOT5")
        self.assertEqual(self._tok(relayed), ("LINK", "3", "UPDOWN"))

    def test_every_fixture_line_resolves_or_is_a_continuation(self):
        for l in self.lines:
            tok = self._tok(l)
            if tok is None:
                self.assertIn("**MSG", l, f"unclassified non-continuation: {l[:80]}")
            else:
                self.assertRegex(tok[0], r"^[A-Z]")
                self.assertIn(tok[1], list("01234567"))

    def test_recipe_documents_the_pattern_and_the_traps(self):
        doc = (bundle_root() / "references" / "extraction-recipes.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("Recipe 15", doc)
        self.assertIn("SUBFACILITY", doc)
        self.assertIn("CONTINUATION", doc)

    def test_the_recipe_uses_no_lookaround(self):
        """The engine does not support lookaround and does not say so --
        the query hangs. The lookahead this recipe once carried is gone,
        and no shipped pattern may reintroduce one."""
        doc = (bundle_root() / "references" / "extraction-recipes.md").read_text(
            encoding="utf-8"
        )
        for m in re.finditer(r'regextract\([^,]+,\s*"((?:[^"\\]|\\.)*)"', doc):
            self.assertNotRegex(
                m.group(1), r"\(\?[=!<]",
                f"lookaround reintroduced into a shipped pattern: {m.group(1)}",
            )
        self.assertIn("NO lookahead or lookbehind", doc)

    def test_severity_five_is_notification_not_notice(self):
        """Cisco's own word for level 5, which differs from RFC 3164.

        This assertion used to read a file outside the bundle and was
        wrapped in ``if path.is_file()``, so for anyone without that
        tree it executed nothing and reported ok. It now checks the
        shipped reference, which carries the same claim and is what an
        author actually reads."""
        doc = read_text("references/extraction-recipes.md")
        self.assertIn("notification", doc)
        self.assertIn("RFC 3164", doc)



class TestWlcClientSession(unittest.TestCase):
    """APF, MM and PEM are three coupled state machines over ONE client
    session -- the controller prints all three states for one mobile in
    PEM-3-BADWLANID2. There is no AuditSessionID: the station MAC is the
    only key that joins them."""

    FIXTURE = bundle_root() / "tests" / "fixtures" / "cisco_message_shapes.log"
    TOK = r".*%([A-Z][A-Z0-9_]*(?:-[A-Z][A-Z0-9_]*)*)-(\d)-([A-Z0-9_]+):(?!SLOT\d)"
    MAC = r"\b([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b"
    STATION = "00:1a:2b:3c:4d:5e"

    @classmethod
    def setUpClass(cls) -> None:
        cls.lines = [
            l for l in cls.FIXTURE.read_text(encoding="utf-8").splitlines() if l.strip()
        ]

    def _line(self, mnem):
        for l in self.lines:
            m = re.search(self.TOK, l)
            if m and m.group(3) == mnem:
                return l
        self.fail(f"no fixture line for {mnem}")

    def _mac(self, line):
        m = re.search(self.MAC, line)
        return m.group(1) if m else None

    def test_session_records_share_the_station_mac(self):
        """The MAC is the join key across all three facilities."""
        for mnem in ("GUESTIN", "GUEST_ASSIGNED_IP", "WEBAUTHFAIL",
                     "CLIENT_SHUNNED", "AUTH_FAILED", "GUESTOUT"):
            self.assertEqual(
                self._mac(self._line(mnem)), self.STATION, mnem
            )

    def test_the_three_facilities_are_all_present(self):
        facs = {
            re.search(self.TOK, l).group(1)
            for l in self.lines
            if re.search(self.TOK, l)
        }
        self.assertTrue({"APF", "MM", "PEM"} <= facs, facs)

    def test_guestin_and_guestout_bind_account_mac_and_address(self):
        """The only records that make a wireless session attributable."""
        for mnem in ("GUESTIN", "GUESTOUT"):
            line = self._line(mnem)
            self.assertEqual(self._mac(line), self.STATION)
            user = re.search(r"user account \(([^)]+)\)", line)
            addr = re.search(r"IP address (\d{1,3}(?:\.\d{1,3}){3})", line)
            self.assertIsNotNone(user, mnem)
            self.assertIsNotNone(addr, mnem)
            self.assertEqual(user.group(1), "guest_4471")

    def test_guestin_and_guestout_form_a_matched_pair(self):
        """The only login/logout pair the controller emits, so the only
        one that yields a session duration."""
        gin, gout = self._line("GUESTIN"), self._line("GUESTOUT")
        self.assertEqual(self._mac(gin), self._mac(gout))
        self.assertLess(self.lines.index(gin), self.lines.index(gout))

    def test_apf_and_pem_bind_the_same_thing_with_different_delimiters(self):
        """PEM writes the MAC bare; APF brackets all three values. Two
        records for one binding that cannot share a capture."""
        pem = self._line("GUESTIN")
        apf = self._line("GUEST_ASSIGNED_IP")
        self.assertEqual(self._mac(pem), self._mac(apf))
        self.assertRegex(apf, r"MAC Address \([0-9a-fA-F:]+\)")
        self.assertRegex(pem, r"MAC address [0-9a-fA-F:]+,")
        # and the capitalisation differs between the two facilities
        self.assertIn("Guest user logged in", pem)
        self.assertIn("Guest User (", apf)

    def test_member_added_is_a_different_mac_from_the_station(self):
        """A mobility member is a peer CONTROLLER, not a client. Mapping
        its MAC as a station identity would invent a session."""
        self.assertNotEqual(self._mac(self._line("MEMBER_ADDED")), self.STATION)

    def test_client_shunned_carries_the_causal_address(self):
        line = self._line("CLIENT_SHUNNED")
        self.assertIn("IDS shun event", line)
        self.assertRegex(line, r"for \d{1,3}(?:\.\d{1,3}){3}")

    def test_reference_records_the_coupled_state_machines(self):
        """The controller proves APF, MM and PEM are one session by
        printing all three states for one mobile, and the station MAC is
        the only key that joins them. Same story as the test above: this
        read a tree outside the bundle behind an ``is_file()`` guard and
        so asserted nothing for anyone who did not have it."""
        text = read_text("references/authentication-mapping.md")
        self.assertIn("BADWLANID2", text)
        self.assertIn("STATION MAC is the correlation key", text)



class TestWlcDetectionFacilities(unittest.TestCase):
    """CIDS and WPS are named after security functions and neither logs
    the detections. The enforcement lives in MM and APF. This is the
    facility-name false friend at its sharpest, and it fails quietly: a
    rule keyed on the plausible facility lints clean and reports zero
    detections forever."""

    FIXTURE = bundle_root() / "tests" / "fixtures" / "cisco_message_shapes.log"
    TOK = r".*%([A-Z][A-Z0-9_]*(?:-[A-Z][A-Z0-9_]*)*)-(\d)-([A-Z0-9_]+):(?!SLOT\d)"
    MAC = r"\b([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b"

    @classmethod
    def setUpClass(cls) -> None:
        cls.lines = [
            l for l in cls.FIXTURE.read_text(encoding="utf-8").splitlines() if l.strip()
        ]

    def _line(self, mnem):
        for l in self.lines:
            m = re.search(self.TOK, l)
            if m and m.group(3) == mnem:
                return l
        self.fail(f"no fixture line for {mnem}")

    def test_wps_alarm_is_split_and_the_subject_is_in_the_continuation(self):
        """The first record has the detector and everything about the
        signature -- and not who did it."""
        head = self._line("SIG_ALARM_OFF")
        cont = self._line("SIG_ALARM_OFF_CONT")
        # the head carries the detecting AP, the signature and the counters
        self.assertIn("sig ", head)
        self.assertRegex(head, r"hits=\d+")
        self.assertRegex(head, r"channel=\d+")
        # ... but the offending station is only in the continuation
        self.assertIn("source mac=", cont)
        self.assertNotIn("source mac=", head)
        self.assertIsNotNone(re.search(self.MAC, cont))

    def test_the_continuation_is_adjacent_to_its_head(self):
        """Correlation is by adjacency; nothing in the continuation
        identifies which alarm it belongs to."""
        i = self.lines.index(self._line("SIG_ALARM_OFF"))
        j = self.lines.index(self._line("SIG_ALARM_OFF_CONT"))
        self.assertEqual(j, i + 1)

    def test_the_continuation_carries_no_signature_identity(self):
        """Which is why it cannot be classified on its own."""
        cont = self._line("SIG_ALARM_OFF_CONT")
        self.assertNotIn("sig ", cont)
        self.assertNotIn("hits=", cont)
        self.assertTrue(cont.rstrip().endswith(re.search(self.MAC, cont).group(1)))

    def test_cids_record_is_a_control_failure_not_a_detection(self):
        """A sensor asked for an enforcement and it was not applied, so
        the client stayed connected."""
        line = self._line("SHUN_LIST_ENTRY_CREATE_FAIL")
        self.assertIn("Unable to create shun-list entry", line)
        self.assertRegex(line, r"\d{1,3}(?:\.\d{1,3}){3}")

    def test_the_successful_shun_comes_from_mm_not_cids(self):
        """The whole point: CIDS has no successful-shun record."""
        shun = self._line("CLIENT_SHUNNED")
        self.assertRegex(shun, self.TOK)
        self.assertEqual(re.search(self.TOK, shun).group(1), "MM")

    def test_capwap_join_rejection_names_the_ap(self):
        line = self._line("DISC_MAX_JOIN")
        self.assertIn("Rejecting discovery request", line)
        self.assertIsNotNone(re.search(self.MAC, line))

    def test_reference_records_the_facility_owner_rule(self):
        doc = (bundle_root() / "references" / "record-classification.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("feature OWNER", doc)
        for fac in ("SSHPM", "CIDS", "WPS"):
            self.assertIn(fac, doc)



if __name__ == "__main__":
    unittest.main()
