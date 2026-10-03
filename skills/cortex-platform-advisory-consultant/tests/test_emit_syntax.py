# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""What emit_xql.py prints as XQL is XQL, and says what the markers say.

The skeleton is deliberately incomplete: dataset, grouping, windows and every <bound> are the
rule author's. Until 0.43.0 it was also wrong, and nothing tested what it printed:

- 574 of 704 blocks pasted a computed marker's pseudo-code into the live filter, aggregates
  and English connectives included, and a marker valued false was appended to a compound
  expression so that it bound to the last word of it. A strict clause grammar rejected 1108
  of the 1670 live clause lines.
- group_name defaulted to the ACTOR's groups, so the ESX Admins creation the block exists to
  catch did not match; a Log4j LDAP callback was tested on the layer-4 protocol enum, which
  never holds "ldap"; 38 cloud audit actions were bound to the derived OPERATION_TYPE enum.
- every backslash was doubled, so `\\s` asked for a literal backslash and an s: a silent zero.
- clauses from two different events were joined with and, which no single event satisfies,
  and the absence skeleton filtered for a zero count that comp can never produce.
- the text printed no caveat, and the JSON dropped the legacy field tests and cut the
  countermeasures at twelve with no count.

Run with PYTHONDONTWRITEBYTECODE=1 (LAW A26).
"""
import json
import pathlib
import re
import shutil
import subprocess
import sys

import pytest

BUNDLE = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = BUNDLE / "scripts"
CORPUS = BUNDLE / "corpus"

sys.dont_write_bytecode = True
sys.path.insert(0, str(SCRIPTS))
import consult as C  # noqa: E402
import emit_xql as E  # noqa: E402
import validate as V  # noqa: E402

XDM_FIELDS = json.loads((CORPUS / "schema" / "xdm-fields.json").read_text(encoding="utf-8"))
VOCAB = json.loads((CORPUS / "schema" / "vocab.json").read_text(encoding="utf-8"))
RECORDS = E.load(str(CORPUS))
PATTERNS = E.load_patterns(str(CORPUS))

# The clause grammar, with no nested quantifier over a group that can match empty: the naive
# nested form backtracks catastrophically on this output.
STRING = r'"(?:[^"\\]|\\.)*"'
ATOM = r'(?:' + STRING + r'|-?\d+(?:\.\d+)?|true|false|XDM_CONST\.[A-Z0-9_]+)'
FIELD = r'xdm\.[a-z0-9_.]+'
CLAUSE = (r'(?:' + FIELD + r' (?:=|~=|contains|>|<) ' + ATOM + r'|' + FIELD + r' in \(' + ATOM
          + r'(?:, ' + ATOM + r')*\))')
ONE_CLAUSE = re.compile(r'^' + CLAUSE + r'$')
ALTERNATIVE = re.compile(r'^\(' + CLAUSE + r'(?: and ' + CLAUSE + r')*\)$')
LIVE_PREFIXES = ("| filter ", "         and ", "         or ")
HEADER = re.compile(r"^// (\S+) :: how\[(\d+)\]  pattern=(\S+)  fidelity=(\S+)  shape=(\S+)  "
                    r"locus=(\S+)  filter=(\S+)  key=(\S+)$")


def run(*argv):
    done = subprocess.run([sys.executable, str(SCRIPTS / "emit_xql.py"), *argv],
                          capture_output=True, text=True, timeout=300)
    assert done.returncode == 0, done.stderr
    return done.stdout, done.stderr


@pytest.fixture(scope="module")
def everything():
    return run("--all")


@pytest.fixture(scope="module")
def handoffs():
    out, _ = run("--all", "--json")
    return json.loads(out)


def blocks(stdout):
    """(header match, [lines]) per block, in printed order."""
    out, current = [], None
    for line in stdout.splitlines():
        m = HEADER.match(line)
        if m:
            current = (m, [])
            out.append(current)
        elif current is not None:
            current[1].append(line)
    return out


def live_lines(lines):
    return [l for l in lines if l.startswith(LIVE_PREFIXES) and not l.startswith("| filter hits")]


def clause_bodies(lines):
    bodies = []
    for line in live_lines(lines):
        body = next(line[len(p):] for p in LIVE_PREFIXES if line.startswith(p))
        if body.startswith("("):
            bodies.extend(re.findall(CLAUSE, body[1:-1]))
        else:
            bodies.append(body)
    return bodies


def block(stdout, key):
    for m, lines in blocks(stdout):
        if m.group(8) == key:
            return m, lines
    raise AssertionError("no block {}".format(key))


def all_markers():
    for record in RECORDS:
        for how in record.get("how") or []:
            for marker in how.get("markers") or []:
                yield marker
    for pattern in PATTERNS.values():
        for marker in pattern.get("markers") or []:
            yield marker


# ------------------------------------------------------------------------------- E-1

def test_every_live_clause_parses(everything):
    out, _ = everything
    bad, total = [], 0
    for line in live_lines(out.splitlines()):
        total += 1
        body = next(line[len(p):] for p in LIVE_PREFIXES if line.startswith(p))
        if not (ONE_CLAUSE.match(body) or ALTERNATIVE.match(body)):
            bad.append(line[:160])
    assert total > 300, "the census that measured this found 361 live clause lines"
    assert not bad, "{} of {} live clause lines fail the clause grammar: {}".format(
        len(bad), total, bad[:5])


def test_no_computed_expr_is_live(everything):
    out, _ = everything
    exprs = {m.get("expr") for m in all_markers() if m.get("type") == "computed"}
    live = "\n".join(live_lines(out.splitlines()))
    leaked = sorted(e for e in exprs if e and len(e) > 12 and e in live)
    assert not leaked, leaked[:5]


def test_negated_computed_renders_as_not_group(everything):
    out, _ = everything
    assert "// REQUIRES (computed, not a field test): NOT (all_sessions_terminated and" in out


def test_threshold_blocks_have_at_most_one_live_threshold(everything):
    out, _ = everything
    for m, lines in blocks(out):
        thresholds = [l for l in lines if l.startswith("| filter hits")]
        assert len(thresholds) <= 1, m.group(8)
        if thresholds:
            assert m.group(5) == "threshold" and m.group(7) != "none", m.group(8)


def test_filter_status_matches_what_was_printed(everything):
    out, _ = everything
    comment_kinds = ("// REQUIRES", "// UNBOUND", "// CLAUSE", "// FIELD", "// NO LIVE FILTER",
                     "// inventory precondition")
    for m, lines in blocks(out):
        status, live = m.group(7), bool(live_lines(lines))
        assert status in E.FILTER_STATUSES
        assert live == (status != "none"), m.group(8)
        commented = any(l.startswith(comment_kinds) for l in lines)
        if status == "complete":
            assert not commented, m.group(8)
        if status == "partial":
            assert commented, m.group(8)


# ------------------------------------------------------------------------------- E-2

def test_group_name_is_never_defaulted_to_the_actor(everything):
    out, _ = everything
    assert "group_name" not in E.DEFAULT_XDM
    _, lines = block(out, "obs-broadcom-esxi-hypervisor-encryption#how1")
    assert not any("xdm.source.user.groups" in l for l in live_lines(lines))
    assert 'xdm.target.user.username in ("ESX Admins")' in "\n".join(live_lines(lines))
    # An unbound group name asks for its field rather than guessing the actor's.
    assert "// UNBOUND: group_name equals \"provider\" -- the group acted on is a target" in out


def test_account_creation_names_the_account_created(everything):
    out, _ = everything
    for key in ("obs-generic-helpdesk-impersonation-to-ransomware-deployment#how1",
                "obs-microsoft-windows-clfs-privilege-escalation-and-account-creation#how0"):
        _, lines = block(out, key)
        live = "\n".join(live_lines(lines))
        assert "xdm.target.user.username ~=" in live, key
        assert "xdm.source.user.username" not in live, key


def test_array_fields_never_take_scalar_operators(everything):
    out, _ = everything
    arrays = {f for f, spec in XDM_FIELDS["fields"].items() if spec.get("array")}
    assert arrays, "the snapshot marks no array field"
    for body in clause_bodies(out.splitlines()):
        assert body.split(" ", 1)[0] not in arrays, body


# ------------------------------------------------------------------------------- E-3

def test_log4j_ldap_is_never_bound_to_ip_protocol(everything):
    out, _ = everything
    _, lines = block(out, "obs-broadcom-vmware-horizon-log4shell-exploitation#how0")
    assert 'xdm.network.ip_protocol = "ldap"' not in out
    assert 'xdm.network.application_protocol = "ldap"' in "\n".join(live_lines(lines))
    assert "protocol" not in E.DEFAULT_XDM


def test_log4j_skeleton_carries_the_server_role_and_external_constraints(everything):
    out, _ = everything
    m, lines = block(out, "obs-broadcom-vmware-horizon-log4shell-exploitation#how0")
    text = "\n".join(lines)
    assert "// FIELD (legacy fields[]): xdm.source.host.hostname exists" in text
    assert any("external" in l or "outside the estate" in l for l in lines
               if l.startswith(("// REQUIRES", "// LOGIC", "//   ")))
    assert m.group(7) == "partial"


# ------------------------------------------------------------------------------- E-4

def test_every_block_prints_its_caveat_and_logic(everything):
    out, _ = everything
    headers = len(re.findall(r":: how\[", out))
    assert headers == len(re.findall(r"^// CAVEAT: ", out, re.M))
    assert headers == len(re.findall(r"^// LOGIC: ", out, re.M))
    assert out.count(E.BANNER) == 1


def test_every_header_names_a_locus_as_a_consultation_would(everything):
    out, _ = everything
    by_id = {r["id"]: r for r in RECORDS}
    locus_map = C.load_locus_map(str(CORPUS))
    seen = 0
    for m, _ in blocks(out):
        assert m.group(6) in VOCAB["locus"], m.group(0)
        record = by_id[m.group(1)]
        how = record["how"][int(m.group(2))]
        pattern = PATTERNS.get(how.get("pattern_id")) or {}
        assert m.group(6) == C.locus_for(record, how, pattern, locus_map)[0], m.group(8)
        seen += 1
    assert seen > 600


def test_unbound_lines_carry_the_value(everything):
    """The zone here was UNBOUND until the zone names were flagged as a site's own; it now
    prints as a normalised requirement, which carries the value as an unbound line does."""
    out, _ = everything
    assert any(l.startswith("// UNBOUND: scheduled_task_name regex ") and "session updater" in l
               for l in out.splitlines())
    _, lines = block(out, "obs-broadcom-vmware-horizon-log4shell-trojanised-utility-loader#how1")
    assert any(l.startswith("// REQUIRES (normalised, not a source literal): <field> in [")
               and "disaster_recovery" in l for l in lines)


def test_no_prose_line_can_be_miscounted_as_a_header(everything):
    """CAVEAT and LOGIC are corpus prose; a ':: how[' inside one would break the tally test."""
    out, _ = everything
    assert len(re.findall(r":: how\[", out)) == len(blocks(out))


# ------------------------------------------------------------------------------- E-5

def expected_regex_body(pattern):
    """The marker's pattern, token by token: every escape kept once, a quote as \\x22 whether
    or not it was escaped, and a final escaped backslash as the class [\\\\]."""
    tokens, i = [], 0
    while i < len(pattern):
        step = 2 if pattern[i] == "\\" else 1
        tokens.append(pattern[i:i + step])
        i += step
    tokens = [r"\x22" if t in ('"', '\\"') else t for t in tokens]
    if tokens and tokens[-1] == "\\\\":
        tokens[-1] = "[\\\\]"
    return "".join(tokens)


def test_regex_marker_values_reach_xql_verbatim(everything):
    out, _ = everything
    assert r'~= "(?i)(nc\.exe|netcat|ncat\.exe|snscan)"' in out
    assert r"nc\\.exe" not in out
    for marker in all_markers():
        if marker.get("match") != "regex" or marker.get("type") == "computed":
            continue
        b = E.bind(marker, XDM_FIELDS)
        if b.kind != "clause":
            continue
        body = b.text.split(" ~= ", 1)[1][1:-1]
        assert body == expected_regex_body(str(marker["value"])), (marker["value"], b.text)


def test_prefix_suffix_are_escaped_literals(everything):
    out, _ = everything
    _, lines = block(out, "obs-cloudflare-workers-as-gatekeeper-and-lure-loader-for-phishing#how0")
    assert r'~= "\.workers\.dev$"' in "\n".join(live_lines(lines))
    assert not re.search(r'~= "\.?[a-z]+\.dev\$"', out.replace(r"\.dev", "")), \
        "an unescaped dot in a suffix matches any character"


def test_numeric_literals_are_quoted_for_string_fields(everything):
    out, _ = everything
    for body in clause_bodies(out.splitlines()):
        if body.startswith("xdm.event.id "):
            assert not re.search(r"(?:= |\(|, )\d", body), body


def test_no_backslash_sits_before_a_closing_quote(everything):
    out, _ = everything
    for body in clause_bodies(out.splitlines()):
        for literal in re.findall(STRING, body):
            assert not literal[:-1].endswith("\\") or literal[:-1].endswith("\\\\\\"), body


def test_values_are_rendered_by_type():
    fields = XDM_FIELDS
    # a trailing directory separator becomes the one-character class, not a doubled escape
    b = E.bind({"type": "file_path", "match": "contains", "value": "\\Users\\Public\\"}, fields)
    assert b.text == r'xdm.target.file.path ~= "\\Users\\Public[\\]"'
    # a double quote in a plain value becomes the hex escape inside an equivalent regex
    b = E.bind({"type": "command_line", "match": "contains", "value": 'for /f "x"'}, fields)
    assert b.text == r'xdm.target.process.command_line ~= "for /f \x22x\x22"'
    # a lookaround RE2 cannot run is refused, never printed
    b = E.bind({"type": "process_name", "match": "regex", "value": "^(?!cmd).*$"}, fields)
    assert b.status == "unrenderable" and "lookaround" in b.reason
    # a range is not an address
    b = E.bind({"type": "ip", "match": "equals", "value": "10.0.0.0/8"}, fields)
    assert b.status == "unrenderable" and "incidr" in b.reason
    # a number on a Number field is bare, on a String field quoted
    assert E.bind({"type": "port", "match": "in", "value": [443, 8443]}, fields).text \
        == "xdm.target.port in (443, 8443)"
    assert E.bind({"type": "event_id", "match": "equals", "value": 4720}, fields).text \
        == 'xdm.event.id = "4720"'


# ------------------------------------------------------------------------------- E-6

def test_every_live_field_is_in_the_bundled_xdm_snapshot(everything):
    out, _ = everything
    for body in clause_bodies(out.splitlines()):
        assert body.split(" ", 1)[0] in XDM_FIELDS["fields"], body


def test_default_bindings_exist():
    missing = {t: f for t, f in E.DEFAULT_XDM.items() if f not in XDM_FIELDS["fields"]}
    assert not missing, missing
    assert set(E.NO_DEFAULT).isdisjoint(E.DEFAULT_XDM)


def test_enum_fields_only_take_members(everything):
    out, _ = everything
    enum_fields = {f for f, spec in XDM_FIELDS["fields"].items()
                   if spec["type"].startswith("XDM_CONST.")}
    members = {c for spec in XDM_FIELDS["enums"].values() for c in spec.get("members") or []}
    for body in clause_bodies(out.splitlines()):
        field = body.split(" ", 1)[0]
        if field == "xdm.event.outcome":
            # The one enum a query compares as its rendered string (test_outcome_* below).
            assert set(re.findall(STRING, body)) <= {'"{}"'.format(s) for s in
                                                     E.OUTCOME_RENDERED.values()}, body
            assert "XDM_CONST" not in body, body
        elif field in enum_fields:
            constants = re.findall(r"XDM_CONST\.[A-Z0-9_]+", body)
            assert constants and set(constants) <= members, body
            assert '"' not in body, body


def test_management_plane_cloud_operations_bind_the_raw_action(everything):
    out, _ = everything
    _, lines = block(out, "obs-amazon-cloudtrail-disabled-mid-intrusion#how0")
    assert 'xdm.event.original_event_type in ("StopLogging"' in "\n".join(live_lines(lines))
    assert 'xdm.event.operation in ("' not in out
    assert not any(m.get("xdm") == "xdm.event.operation" for m in all_markers()
                   if m.get("type") == "cloud_operation")
    # What does bind the enum names its members: a removal, on the history pattern.
    for m in all_markers():
        if m.get("xdm") == "xdm.event.operation":
            assert E.bind(m, XDM_FIELDS).status == "bound", m


def test_the_snapshot_is_what_the_emitter_reads():
    """Types and members only; a field is added by copying its line from the XDM schema."""
    for field, spec in XDM_FIELDS["fields"].items():
        assert field.startswith("xdm."), field
        if spec["type"].startswith("XDM_CONST."):
            assert spec["type"] in XDM_FIELDS["enums"], field
    for name, enum in XDM_FIELDS["enums"].items():
        for literal, constant in (enum.get("literals") or {}).items():
            assert constant in enum["members"], (name, literal)


def _corpus_copy(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    for part in ("observations", "patterns", "schema"):
        shutil.copytree(CORPUS / part, corpus / part)
    return corpus


def _validate(corpus):
    done = subprocess.run([sys.executable, str(SCRIPTS / "validate.py"), "--corpus", str(corpus)],
                          capture_output=True, text=True, timeout=300)
    return done.returncode, done.stdout


def _inject(corpus, marker, combine=None, labels=None):
    """Replace the first marked block's markers with `marker` (and optional extra keys)."""
    path = corpus / "observations" / "observations.jsonl"
    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    for row in rows:
        for how in row.get("how") or []:
            if how.get("markers"):
                how["markers"] = marker if isinstance(marker, list) else [marker]
                how.pop("combine", None)
                if combine:
                    how["combine"] = combine
                path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
                return row["id"]
    raise AssertionError("no marked block to inject into")


@pytest.mark.parametrize("marker,expected", [
    pytest.param({"type": "file_name", "match": "in", "value": ["a.db"],
                  "xdm": "xdm.target.file.name"}, "not a field of the bundled XDM snapshot",
                 id="field-not-in-xdm"),
    pytest.param({"type": "cloud_operation", "match": "in", "value": ["StopLogging"],
                  "xdm": "xdm.event.operation"}, "is not one of its members",
                 id="raw-action-on-operation-enum"),
    pytest.param({"type": "process_name", "match": "regex", "value": "^(?!cmd).*\\.exe$"},
                 "lookaround", id="re2-lookaround"),
])
def test_validate_refuses_a_binding_the_skeleton_could_not_honour(tmp_path, marker, expected):
    corpus = _corpus_copy(tmp_path)
    _inject(corpus, marker)
    code, out = _validate(corpus)
    assert code == 1, out[-600:]
    assert expected in out, out[-900:]


def test_validate_accepts_the_shipped_bindings(tmp_path):
    corpus = _corpus_copy(tmp_path)
    code, out = _validate(corpus)
    assert code == 0, out[-900:]
    assert "marker bindings: skipped" not in out


# ------------------------------------------------------------------------------- E-7

def test_marker_the_record_says_not_to_conjoin_is_not_conjoined(everything):
    """The stomp_ext marker's own note says it is a separate, earlier file event."""
    out, _ = everything
    _, lines = block(out, "obs-google-chrome-bluemoon-exploit-kit-renderer-breakout#how3")
    for line in live_lines(lines):
        assert not ("stomp_ext" in line and "Secure Preferences" in line), line
    text = "\n".join(lines)
    assert text.index("// EVENT extract:") < text.index("// EVENT forge:") \
        < text.index("// EVENT relaunch:")
    assert "// sequence: EVENT extract, then forge, then relaunch, in that order" in text


def test_a_block_that_does_not_say_how_its_markers_combine_is_not_conjoined(everything):
    out, _ = everything
    _, lines = block(out, "obs-generic-kimsuky-targeted-individual-intelligence-collection#how1")
    assert not live_lines(lines)
    assert any(l.startswith("// NO LIVE FILTER: clauses span 2 event types") for l in lines)
    assert any(l.startswith("// CLAUSE (process): ") for l in lines)


def test_no_live_conjunction_tests_one_field_twice_unless_the_block_says_all(everything):
    out, _ = everything
    for m, lines in blocks(out):
        if any(l.startswith("// COMBINE: all") for l in lines):
            continue
        fields = [b.split(" ", 1)[0] for b in clause_bodies(
            [l for l in lines if not l.startswith("         or ")])]
        if any(l.startswith("         or ") for l in lines):
            continue
        assert len(fields) == len(set(fields)), m.group(8)


def test_any_prints_alternatives_joined_with_or(everything):
    out, _ = everything
    _, lines = block(out, "obs-cisco-router-firmware-backdoor-and-cli-output-manipulation#how4")
    live = live_lines(lines)
    assert live[0].startswith("| filter (xdm.target.registry.key ~= ")
    assert live[1].startswith("         or (xdm.target.process.name ~= ")


def test_inventory_blocks_have_no_live_pipeline(everything):
    out, _ = everything
    inventory = [(m, lines) for m, lines in blocks(out) if m.group(5) == "inventory"]
    assert inventory
    for m, lines in inventory:
        assert not live_lines(lines), m.group(8)
        assert not any(l.startswith("datamodel dataset") for l in lines), m.group(8)


def test_absence_never_prints_hits_eq_zero(everything):
    out, _ = everything
    assert "filter hits = 0" not in out
    for m, lines in blocks(out):
        if m.group(5) == "absence":
            assert any(l.startswith("// ABSENCE: ") for l in lines), m.group(8)


@pytest.mark.parametrize("markers,combine,expected", [
    pytest.param([{"type": "process_name", "value": "a.exe", "event": "one"},
                  {"type": "domain", "value": "b.example"}], "any",
                 "once one carries a label every one must", id="partial-labels"),
    pytest.param([{"type": "process_name", "value": "a.exe", "event": "one"},
                  {"type": "domain", "value": "b.example", "event": "two"}], None,
                 "sets no combine", id="labels-without-combine"),
])
def test_validate_refuses_an_incoherent_combination(tmp_path, markers, combine, expected):
    corpus = _corpus_copy(tmp_path)
    _inject(corpus, markers, combine)
    code, out = _validate(corpus)
    assert code == 1, out[-600:]
    assert expected in out, out[-900:]


# ------------------------------------------------------------------------------- E-8

def test_handoff_carries_fields_from_source(handoffs):
    log4j = next(h for h in handoffs
                 if h["finding_key"] == "obs-broadcom-vmware-horizon-log4shell-exploitation#how0")
    assert any(f.get("xdm") == "xdm.source.host.hostname" and f.get("op") == "exists"
               for f in log4j["fields_from_source"])
    assert log4j["filter_status"] == "partial"


def test_handoff_marker_bindings_cover_every_marker(handoffs):
    for h in handoffs:
        rows = h["marker_bindings"]
        assert len(rows) == len(h["markers_from_source"]) + len(h["markers_from_pattern"])
        assert {r["status"] for r in rows} <= set(E.BINDING_STATUSES), h["finding_key"]
        assert h["filter_status"] in E.FILTER_STATUSES


# ------------------------------------------------------------------------------- E-9

def test_dataset_line_is_xql(everything):
    out, _ = everything
    assert not re.search(r"^dataset = \[", out, re.M)
    assert not re.search(r"^dataset = ", out, re.M), "a live pipeline over xdm.* opens on datamodel"
    for m, lines in blocks(out):
        for i, line in enumerate(lines):
            if line.startswith("| filter ") and not line.startswith("| filter hits"):
                assert lines[i - 1].startswith("datamodel dataset = "), m.group(8)
    _, lines = block(out, "obs-cisco-asa-vpn-webvpn-implant#how0")
    assert "datamodel dataset = cisco_asa_raw" in lines


# ------------------------------------------------------------------------------- E-10

def test_handoff_countermeasures_are_unique_tactic_ordered_and_counted(handoffs):
    d3fend = E.load_d3fend(str(CORPUS))
    rank = {name: i for i, name in enumerate(d3fend.get("tactic_order") or [])}
    for h in handoffs:
        ids = [c["id"] for c in h["countermeasures"]]
        assert len(ids) == len(set(ids)), h["finding_key"]
        order = [rank.get(c.get("tactic"), len(rank)) for c in h["countermeasures"]]
        assert order == sorted(order), h["finding_key"]
        assert h["countermeasures_shown"] == len(ids) <= 12
        assert h["countermeasures_total"] == len(ids) + len(h["countermeasures_not_shown"])


def test_handoff_selects_as_a_consultation_does(handoffs):
    d3fend = E.load_d3fend(str(CORPUS))
    by_key = {h["finding_key"]: h for h in handoffs}
    for record in RECORDS[:400]:
        for i, how in enumerate(record.get("how") or []):
            h = by_key.get(C.finding_key(record, i))
            if not h:
                continue
            pattern = PATTERNS.get(how.get("pattern_id")) or {}
            selection = C.select_countermeasures(how, pattern, d3fend, limit=12)
            assert [c["id"] for c in h["countermeasures"]] == selection.chosen, h["finding_key"]
            # How D3FEND reaches each control travels with it, as a consultation prints it.
            assert [c["mapping"] for c in h["countermeasures"]] == [
                "direct" if selection.grade[c] == "direct" else "inferred-" + selection.grade[c]
                for c in selection.chosen], h["finding_key"]


# ------------------------------------------------------------ after review: literals and digests

def all_items():
    """(marker or legacy field, operator) for every literal the corpus holds."""
    for marker in all_markers():
        yield marker, marker.get("match", "equals")
    for record in RECORDS:
        for how in record.get("how") or []:
            for item in how.get("fields") or []:
                yield item, item.get("op")


def test_no_literal_holds_a_doubled_separator(everything):
    """The AV-exclusion key was `Windows Defender\\\\Exclusions\\\\Paths` in a filter=complete
    block at alert fidelity: two backslashes per separator, which no registry key contains."""
    for item, op in all_items():
        if op == "regex" or item.get("type") == "computed":
            continue
        value = item.get("value")
        for v in (value if isinstance(value, list) else [value]):
            assert not (isinstance(v, str) and "\\\\" in v[1:]), (item, v)
    out, _ = everything
    _, lines = block(out, "obs-generic-ai-orchestrated-intrusion-of-internet-facing-web-servers#how1")
    assert r'xdm.target.registry.key contains "Windows Defender\Exclusions\Paths"' \
        in "\n".join(live_lines(lines))


def test_file_digests_bind_by_their_length(everything):
    """MD5s were tested live against xdm.target.file.sha256, and SHA-1s beside SHA256s."""
    for length, field in E.FILE_DIGEST_XDM.items():
        spec = XDM_FIELDS["fields"][field]
        assert E.DIGEST_HEX[spec["type"]] == length, field
    assert "file_hash" not in E.DEFAULT_XDM
    md5 = "1f239db751ce9a374eb9f908c74a31c9"
    sha1 = "912342f1c840a42f6b74132f8a7c4ffe7d40fb77"
    sha256 = "a196c6b8ffcb97ffb276d04f354696e2391311db3841ae16c8c9f56f36a38e92"
    b = E.bind({"type": "file_hash", "match": "in", "value": [md5]}, XDM_FIELDS)
    assert b.text == 'xdm.target.file.md5 in ("{}")'.format(md5)
    b = E.bind({"type": "file_hash", "match": "in", "value": [sha256]}, XDM_FIELDS)
    assert b.field == "xdm.target.file.sha256" and b.status == "bound"
    b = E.bind({"type": "file_hash", "match": "in", "value": [sha1]}, XDM_FIELDS)
    assert b.status == "unbound" and "SHA-1" in b.reason and not b.fault
    b = E.bind({"type": "file_hash", "match": "in", "value": [md5, sha256]}, XDM_FIELDS)
    assert b.status == "unbound" and b.fault and "split it" in b.reason
    b = E.bind({"type": "file_hash", "match": "in", "value": [md5],
                "xdm": "xdm.target.file.sha256"}, XDM_FIELDS)
    assert b.status == "unrenderable" and b.fault
    # Corpus-wide: every live digest clause holds digests of its field's length.
    digest_fields = {f: E.DIGEST_HEX[s["type"]] for f, s in XDM_FIELDS["fields"].items()
                     if s["type"] in E.DIGEST_HEX}
    out, _ = everything
    seen = 0
    for body in clause_bodies(out.splitlines()):
        field = body.split(" ", 1)[0]
        if field in digest_fields:
            seen += 1
            for literal in re.findall(STRING, body):
                assert len(literal) - 2 == digest_fields[field], body
    assert seen >= 3
    _, lines = block(out, "obs-generic-state-sponsored-ransomware-with-false-criminal-branding#how2")
    assert "xdm.target.file.md5 in (" in "\n".join(live_lines(lines))
    m, lines = block(out, "obs-generic-wiper-disguised-as-ransomware#how0")
    assert sha1 not in "\n".join(live_lines(lines))
    assert any(l.startswith("// UNBOUND: file_hash") and sha1 in l for l in lines)
    assert m.group(7) == "partial"


def test_a_list_value_keeps_every_alternative():
    """bind() kept the first element of a list on equals and contains and called it bound."""
    fields = XDM_FIELDS
    b = E.bind({"type": "url_path", "match": "contains",
                "value": ["/dana-na/", "/dana-ws/", "/dana-cached/", "/dana-admin/"]}, fields)
    assert b.text == 'xdm.network.http.url ~= "(?:/dana-na/|/dana-ws/|/dana-cached/|/dana-admin/)"'
    assert E.bind({"type": "process_name", "match": "equals", "value": ["a.exe", "b.exe"]},
                  fields).text == 'xdm.target.process.name in ("a.exe", "b.exe")'
    assert E.bind({"type": "port", "match": "equals", "value": [443, 8443]}, fields).text \
        == "xdm.target.port in (443, 8443)"
    assert E.bind({"type": "ip", "match": "equals", "value": ["10.1.1.1", "10.1.1.2"]},
                  fields).text == 'xdm.target.ipv4 in ("10.1.1.1", "10.1.1.2")'
    assert E.bind({"type": "domain", "match": "suffix", "value": [".workers.dev", ".pages.dev"]},
                  fields).text \
        == r'xdm.network.dns.dns_question.name ~= "(?:\.workers\.dev|\.pages\.dev)$"'
    for marker in ({"type": "process_name", "match": "regex", "value": ["a", "b"]},
                   {"type": "port", "match": "gt", "value": [1, 2]}):
        b = E.bind(marker, fields)
        assert b.status == "unrenderable" and b.fault, marker
    # Across the corpus, a bound marker's clause names every value it holds.
    for marker in all_markers():
        value = marker.get("value")
        b = E.bind(marker, fields)
        if (b.kind == "clause" and isinstance(value, list) and marker.get("match") != "regex"
                and "XDM_CONST." not in b.text and b.field != "xdm.event.outcome"):
            for v in value:
                assert re.sub(r"\\(.)", r"\1", str(v)).lower() in \
                    re.sub(r"\\(.)", r"\1", b.text).lower(), (v, b.text)


@pytest.mark.parametrize("pattern,construct", [
    ("(?P<x>a)(?P=x)", "named backreference"),
    ("a++", "possessive"),
    ("a*+b", "possessive"),
    ("(ab){2}+", "possessive"),
    ("(?(1)a|b)", "conditional"),
    ("(?#note)a", "comment"),
    ("(?x)a b", "inline flag"),
    ("(?<=a)b", "lookaround"),
    ("(?>a)", "atomic"),
    ("(a)\\1", "backreference"),
])
def test_re2_refuses_what_re2_cannot_run(pattern, construct):
    assert construct in (E.re2_refusal(pattern) or ""), pattern


@pytest.mark.parametrize("pattern", [
    "(?i)(nc\\.exe|netcat)", "a+?b*?c{1,2}?", "[+*]+x", "\\++", "(?i:ab)+", "[]a]+", "x{2,}",
    "(?P<name>a)b",
])
def test_re2_accepts_what_re2_can_run(pattern):
    assert E.re2_refusal(pattern) is None, pattern


def test_every_shipped_regex_runs_under_re2():
    for marker in all_markers():
        if marker.get("match") == "regex" and marker.get("type") != "computed":
            assert E.re2_refusal(str(marker["value"])) is None, marker["value"]


@pytest.mark.parametrize("marker,expected", [
    pytest.param({"type": "registry_key", "match": "contains",
                  "value": "Windows Defender\\\\Exclusions\\\\Paths"}, "holds a doubled backslash",
                 id="doubled-separator"),
    pytest.param({"type": "file_hash", "match": "in",
                  "value": ["1f239db751ce9a374eb9f908c74a31c9",
                            "912342f1c840a42f6b74132f8a7c4ffe7d40fb77"]}, "split it",
                 id="mixed-digests"),
    pytest.param({"type": "file_hash", "match": "in", "value": ["1f239db751ce9a374eb9f908c74a31c9"],
                  "xdm": "xdm.target.file.sha256"}, "is not a digest of 64", id="md5-on-sha256"),
    pytest.param({"type": "process_name", "match": "regex", "value": ["a.exe", "b.exe"]},
                 "takes one pattern", id="regex-list"),
    pytest.param({"type": "process_name", "match": "regex", "value": "(?P<x>a)(?P=x)"},
                 "named backreference", id="re2-named-backreference"),
    pytest.param({"type": "event_outcome", "match": "equals", "value": "DENIED"},
                 "is not one of its members", id="default-bound-enum-literal"),
])
def test_validate_refuses_a_literal_the_skeleton_would_get_wrong(tmp_path, marker, expected):
    corpus = _corpus_copy(tmp_path)
    _inject(corpus, marker)
    code, out = _validate(corpus)
    assert code == 1, out[-600:]
    assert expected in out, out[-900:]


def test_validate_accepts_a_sha1_it_cannot_bind(tmp_path):
    """A SHA-1 is a real indicator with no XDM home: UNBOUND in the skeleton, not an error."""
    corpus = _corpus_copy(tmp_path)
    _inject(corpus, {"type": "file_hash", "match": "in",
                     "value": ["912342f1c840a42f6b74132f8a7c4ffe7d40fb77"]})
    code, out = _validate(corpus)
    assert code == 0, out[-900:]


# ------------------------------------------------------------ after review: the threshold stage

def test_threshold_skeleton_bins_as_a_stage(everything):
    """`comp ... by <grouping_key>, bin(_time, <window>)` is not XQL: bin is a stage."""
    out, _ = everything
    # A computed marker's own expression may say bin(); it prints as a comment, never as XQL.
    assert not [l for l in out.splitlines() if "bin(" in l and not l.startswith("//")]
    seen = 0
    for m, lines in blocks(out):
        if m.group(5) != "threshold" or m.group(7) == "none":
            continue
        if not any(l.startswith("| filter hits") for l in lines):
            continue
        seen += 1
        i = lines.index("| bin _time span = <window>")
        assert lines[i + 1] == "| comp count() as hits by <grouping_key>, _time", m.group(8)
        assert lines[i + 2].startswith("| filter hits > <bound>"), m.group(8)
    assert seen >= 20


# ------------------------------------------------------------ after the second review

# The correlation-author bundle's predicate for the comparison that fails a whole pack install
# (ERR-CORR-OUTCOME-CONST): the field is xdm.event.outcome, or the constant is an OUTCOME one.
OUTCOME_CONST = re.compile(r"(xdm\.[A-Za-z0-9_.]+)\s*(?:=|!=|==|in \()\s*(XDM_CONST\.[A-Za-z0-9_]+)")


def test_outcome_is_compared_as_its_rendered_string(everything):
    """`xdm.event.outcome = XDM_CONST.OUTCOME_FAILED` fails the whole pack install with a 101704
    naming nothing; the skeleton printed it live in 17 blocks, 12 at alert fidelity."""
    fields = XDM_FIELDS
    assert E.bind({"type": "event_outcome", "value": "SUCCESS"}, fields).text \
        == 'xdm.event.outcome = "SUCCESS"'
    assert E.bind({"type": "event_outcome", "value": "FAILURE"}, fields).text \
        == 'xdm.event.outcome = "FAILED"'
    assert E.bind({"type": "event_outcome", "match": "in", "value": ["SUCCESS", "FAILED"]},
                  fields).text == 'xdm.event.outcome in ("SUCCESS", "FAILED")'
    # A member whose rendered string is not recorded is not guessed, and is not the marker's
    # fault: the literal is a member.
    b = E.bind({"type": "event_outcome", "value": "PARTIAL"}, fields)
    assert b.status == "enum_literal" and not b.fault and "not recorded" in b.reason
    out, _ = everything
    live = live_lines(out.splitlines())
    for line in live:
        for field, const in OUTCOME_CONST.findall(line):
            assert field != "xdm.event.outcome" and not const.startswith(
                "XDM_CONST.OUTCOME_"), line
        assert "XDM_CONST.OUTCOME_" not in line, line
    _, lines = block(out, "obs-fortinet-fortios-ssl-vpn-exploitation#how0")
    # The integrity_check beside it is the corpus's word, a requirement since batch R4.
    assert '| filter xdm.event.outcome = "FAILED"' in live_lines(lines)
    assert sum('xdm.event.outcome' in l for l in live) >= 12


URL_PROBES = {
    # The last two are scheme-less, as a proxy logs host/path and host:port/path; the anchor
    # made the authority optional only after a scheme, and never matched them.
    "/beacon": (["/beacon", "/beacon?id=1", "http://203.0.113.10:4444/beacon", "HTTPS://h/beacon#x",
                 "203.0.113.10:4444/beacon", "evil.example/beacon?id=1"],
                ["/beacons", "/x/beacon", "http://h/x/beacon", "http://h/beacon/x",
                 "h/x/beacon", "evil.example/beacons"]),
}


def test_a_path_is_tested_where_it_sits_in_the_whole_url(everything):
    """xdm.network.http.url holds the full requested URL, so `= "/beacon"` could never match."""
    fields = XDM_FIELDS
    b = E.bind({"type": "url_path", "match": "equals", "value": "/beacon"}, fields)
    assert b.status == "bound" and b.text.startswith('xdm.network.http.url ~= "^')
    pattern = b.text.split(" ~= ", 1)[1][1:-1]
    yes, no = URL_PROBES["/beacon"]
    for url in yes:
        assert re.search(pattern, url, re.I), url
    for url in no:
        assert not re.search(pattern, url, re.I), url
    b = E.bind({"type": "url_path", "match": "prefix",
                "value": ["/latest/meta-data/iam/security-credentials/"]}, fields)
    pattern = b.text.split(" ~= ", 1)[1][1:-1]
    assert re.search(pattern, "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
                              "node-role")
    assert re.search(pattern, "169.254.169.254/latest/meta-data/iam/security-credentials/node-role")
    assert not re.search(pattern, "http://h/x/latest/meta-data/iam/security-credentials/")
    assert not re.search(pattern, "169.254.169.254/x/latest/meta-data/iam/security-credentials/")
    b = E.bind({"type": "url_path", "match": "suffix", "value": ".php"}, fields)
    pattern = b.text.split(" ~= ", 1)[1][1:-1]
    assert re.search(pattern, "http://h/a/index.php?x=1") and not re.search(pattern, "/phpx")
    # A value that is not a path cannot be tested whole against a URL; a regex anchored at the
    # start of a path would test the scheme; an API route has no default field.
    for marker, expected in (
            ({"type": "url_path", "match": "equals", "value": "beacon"}, "beginning with /"),
            ({"type": "url_path", "match": "regex", "value": "(?i)^/api/"}, "anchored")):
        b = E.bind(marker, fields)
        assert b.status == "unrenderable" and b.fault and expected in b.reason, marker
    b = E.bind({"type": "api_path", "match": "equals", "value": "/api/v1/validate/code"}, fields)
    assert b.status == "unbound" and not b.fault and "api_path" in E.NO_DEFAULT
    # Corpus-wide: no live clause tests a whole-URL field with = or in.
    out, _ = everything
    for body in clause_bodies(out.splitlines()):
        field, op = body.split(" ", 2)[:2]
        if field in E.URL_FIELDS:
            assert op in ("~=", "contains"), body
    _, lines = block(out, "obs-amazon-kubernetes-node-credentials-to-cloud-account-takeover#how0")
    assert any("/latest/meta-data/iam/security-credentials/" in l and " ~= " in l
               for l in live_lines(lines))


def test_the_hypervisor_chain_is_three_events_in_order(everything):
    """A management-audit password reset, an SSH session and a VMFS write were one filter."""
    out, _ = everything
    m, lines = block(out, "obs-broadcom-vmware-esxi-credential-reset-and-direct-hypervisor-"
                          "encryption#how0")
    text = "\n".join(lines)
    assert text.index("// EVENT reset:") < text.index("// EVENT ssh:") \
        < text.index("// EVENT encrypt:")
    assert "// sequence: EVENT reset, then ssh, then encrypt, in that order" in text
    for line in live_lines(lines):
        assert not ("original_event_type" in line and "xdm.target.file" in line), line


def _render(how, pattern=None):
    record = {"id": "obs-probe", "who": {"product_class": ["endpoint.os"]}, "how": [how]}
    rendered, combine = E.effective(how, pattern or {})
    lines, status, _ = E.render(record, rendered, 0, pattern or {}, C.load_locus_map(str(CORPUS)),
                                XDM_FIELDS, combine, how)
    return "\n".join(lines).splitlines(), status


def test_an_audit_action_and_an_endpoint_artefact_are_two_events_in_a_chain():
    """Only where the shape spans events: a storage audit's read can name its object as a file."""
    markers = [{"type": "cloud_operation", "value": "ResetPassword"},
               {"type": "file_path", "match": "prefix", "value": "/vmfs/volumes/"}]
    for shape in ("sequence", "correlation"):
        lines, status = _render({"rule_shape": shape, "markers": markers})
        assert status == "none", shape
        assert any("span 2 event types (audit, file)" in l for l in lines), lines
        assert any(l.startswith("// CLAUSE (audit): ") for l in lines), lines
    lines, status = _render({"rule_shape": "single_event", "markers": markers})
    assert status == "complete"
    # A user agent is carried by the audit itself.
    lines, status = _render({"rule_shape": "sequence", "markers": [
        {"type": "cloud_operation", "value": "InvokeModel"},
        {"type": "user_agent", "value": "Python/3.12 aiohttp/3.9.1"}]})
    assert status == "complete"


def test_an_alternative_carries_the_condition_that_gives_it_fidelity(everything):
    """Under combine: any each arm fires alone, so an arm holding only the act -- an exclusion
    cmdlet, a Run dialog history write -- matched every one of them under filter=complete."""
    out, _ = everything
    _, lines = block(out, "obs-generic-ai-orchestrated-intrusion-of-internet-facing-web-servers#how1")
    arms = [l for l in live_lines(lines)]
    assert arms[0] == ('| filter (xdm.target.process.command_line contains "Add-MpPreference" and '
                       'xdm.target.process.command_line contains "inetsrv")')
    _, lines = block(out, "obs-generic-fake-captcha-clipboard-paste-execution#how0")
    run_history = [l for l in live_lines(lines) if "RunMRU" in l]
    assert len(run_history) == 1 and "xdm.target.registry.data ~= " in run_history[0]
    assert E.DEFAULT_XDM["registry_data"] in XDM_FIELDS["fields"]
    assert "registry_data" in VOCAB["marker_type"]
    # The history pattern's registry and file arms test a removal, not any write.
    lines, _ = _render({"pattern_id": "pat-command-history-cleared", "fidelity": "hunt"},
                       PATTERNS["pat-command-history-cleared"])
    arms = live_lines(lines)
    assert len(arms) == 3
    assert "OPERATION_TYPE_REGISTRY_DELETE_KEY" in arms[1] and "RunMRU" in arms[1]
    assert "OPERATION_TYPE_FILE_REMOVE" in arms[2] and "bash_history" in arms[2]


def test_the_backdoor_account_logs_in_on_an_event_of_its_own(everything):
    """The INSERT is run by someone else: the new account's name is not its actor."""
    out, _ = everything
    _, lines = block(out, "obs-nacos-auth-bypass-and-backdoor-admin-written-to-backing-store#how0")
    for line in live_lines(lines):
        assert not ("xadmin" in line and "INSERT INTO" in line), line
    text = "\n".join(lines)
    assert "// EVENT login:" in text and "// EVENT write:" in text
    assert "// correlation: join EVENT login, write on <join_key>" in text


def test_a_path_literal_is_expanded_and_an_extension_has_no_dot(everything):
    """`%TEMP%\\rust-setup.ps1` and `.lnk` were live literals no event holds."""
    fields = XDM_FIELDS
    for marker, expected in (
            ({"type": "file_path", "match": "in", "value": ["%TEMP%\\a.ps1"]}, "%TEMP%"),
            ({"type": "process_path", "match": "regex", "value": "(?i)%APPDATA%\\\\x"},
             "%APPDATA%"),
            ({"type": "file_extension", "match": "in", "value": [".lnk", "url"]}, "'.lnk'")):
        b = E.bind(marker, fields)
        assert b.status == "unrenderable" and b.fault and expected in b.reason, marker
    # A command line holds what was typed, variables and all.
    assert E.bind({"type": "command_line", "match": "contains", "value": "%TEMP%\\a.ps1"},
                  fields).status == "bound"
    out, _ = everything
    live = "\n".join(live_lines(out.splitlines()))
    assert not re.search(r'xdm\.target\.file\.(path|filename)[^\n]*%[A-Za-z_]+%', live)
    assert 'extension in (".' not in live and 'extension = ".' not in live
    _, lines = block(out, "obs-generic-rust-crate-hijack-executes-at-compile-time#how0")
    text = "\n".join(lines)
    assert "// EVENT spawn:" in text and "// EVENT write:" in text
    assert "%TEMP%" not in "\n".join(live_lines(lines))


@pytest.mark.parametrize("pattern", [
    "abc\\z", "\\p{L}+", "\\pL\\PN", "[\\p{Greek}x]", "(?U)a+", "(?i-s)x", "ab(?i)cd",
    "\\Qa.b\\E+", "\\x{41}", "[[:alpha:]]+", "a{0,3}",
])
def test_re2_accepts_its_own_constructs_whichever_python_runs(pattern):
    """Python 3.9 refused \\z, \\p and a mid-pattern flag as compile errors, as the marker's
    fault, though RE2 runs every one of them."""
    assert E.re2_refusal(pattern) is None, pattern


@pytest.mark.parametrize("pattern,construct", [
    ("a{,3}", "literal text"),
    ("(?<name>abc)", "(?P<name>...)"),
    ("a{1001}", "at most 1000"),
    ("\\u0041", "\\u"),
    ("\\C", "one byte"),
])
def test_re2_refuses_by_name_where_the_engines_differ(pattern, construct):
    assert construct in (E.re2_refusal(pattern) or ""), pattern


@pytest.mark.parametrize("marker,expected", [
    pytest.param({"type": "file_path", "match": "in", "value": ["%TEMP%\\rust-setup.ps1"]},
                 "unexpanded %TEMP%", id="unexpanded-variable"),
    pytest.param({"type": "file_extension", "match": "equals", "value": ".locked"},
                 "without its dot", id="dotted-extension"),
    pytest.param({"type": "url_path", "match": "equals", "value": "beacon"},
                 "beginning with /", id="url-path-not-a-path"),
    pytest.param({"type": "url_path", "match": "regex", "value": "(?i)^/api/"},
                 "anchored at the start of a path", id="url-regex-anchored-on-path"),
    pytest.param({"type": "process_name", "match": "regex", "value": "a{,3}"},
                 "literal text", id="re2-open-lower-bound"),
])
def test_validate_refuses_what_the_second_review_found(tmp_path, marker, expected):
    corpus = _corpus_copy(tmp_path)
    _inject(corpus, marker)
    code, out = _validate(corpus)
    assert code == 1, out[-600:]
    assert expected in out, out[-900:]


def test_validate_refuses_a_legacy_field_no_event_holds(tmp_path):
    """fields[] is forwarded verbatim in the handoff, and the binder never reads it."""
    corpus = _corpus_copy(tmp_path)
    path = corpus / "observations" / "observations.jsonl"
    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    how = next(h for r in rows for h in r.get("how") or [] if h.get("fields"))
    how["fields"] = [{"xdm": "xdm.target.file.path", "op": "in", "value": ["%TEMP%\\a.ps1"]},
                     {"xdm": "xdm.target.file.extension", "op": "in", "value": [".lnk"]}]
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    code, out = _validate(corpus)
    assert code == 1, out[-600:]
    assert "unexpanded variable" in out and "leading dot" in out, out[-900:]


def test_pattern_sketches_hold_to_the_skeletons_rules():
    """xql_sketch is pseudo-code no script reads, and it carried every defect the skeleton was
    fixed for: 22 bin() calls, ten sketches naming fields XDM lacks, three string tests on the
    OPERATION_TYPE enum and a bare event id."""
    names = set(XDM_FIELDS["schema_field_names"])
    assert len(names) == XDM_FIELDS["schema_fields_in_source"]
    assert set(XDM_FIELDS["fields"]) <= names
    sketches = {pid: p["xql_sketch"] for pid, p in PATTERNS.items() if p.get("xql_sketch")}
    assert len(sketches) > 150
    for pid, sketch in sketches.items():
        assert "bin(" not in sketch, pid
        for field in re.findall(r"xdm\.[A-Za-z0-9_.]*[A-Za-z0-9_]", sketch):
            assert field in names, (pid, field)
        assert not re.search(r'xdm\.event\.operation(?![\w.])\s*(?:~=|!?=\s*")', sketch), pid
    ssh = sketches["pat-ssh-brute-force"]
    assert ssh.startswith("datamodel dataset = ") and "| bin _time span = 1h | comp " in ssh
    # A sketch reading a vendor's own columns keeps the raw stage that carries them.
    assert sketches["pat-kerberoasting-service-ticket-requests"].startswith("dataset = ")


@pytest.mark.parametrize("sketch,expected", [
    ("dataset = <x> | comp count() by xdm.source.ipv4, bin(_time, 1h)", "bin is a stage"),
    ("datamodel dataset = <x> | filter xdm.target.file.name = \"a\"", "xdm.target.file.name"),
    ("datamodel dataset = <x> | filter xdm.event.operation ~= \"(?i)add\"", "OPERATION_TYPE"),
    ("datamodel dataset = <x> | filter xdm.event.outcome = XDM_CONST.OUTCOME_FAILED",
     "fails a pack install"),
    ("datamodel dataset = <x> | filter xdm.event.id in (4720)", "bare number"),
    ("datamodel dataset = <x> | filter xdm.network.http.response_code = XDM_CONST.NOPE",
     "XDM_CONST.NOPE"),
])
def test_validate_refuses_a_sketch_defect(tmp_path, sketch, expected):
    corpus = _corpus_copy(tmp_path)
    path = corpus / "patterns" / "patterns.jsonl"
    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    rows[0]["xql_sketch"] = sketch
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    code, out = _validate(corpus)
    assert code == 1, out[-600:]
    assert expected in out, out[-900:]


# ------------------------------------------------------ third review: what an unkeyed list joins

def test_no_unkeyed_list_joins_an_event_identifier_with_an_artefact():
    """The emitter counts xdm.event.* as neutral, so an unkeyed list joining an event identifier
    with a process, file, registry, DNS or HTTP marker printed as one event: the log-cleared
    identifiers with the command line of the utility that clears logs, alert and complete."""
    lists = [("{}#how{}".format(r["id"], i), h.get("markers"), h.get("combine"))
             for r in RECORDS for i, h in enumerate(r.get("how") or [])]
    lists += [(pid, p.get("markers"), p.get("combine")) for pid, p in PATTERNS.items()]
    joined = [(ident, E.unkeyed_event_kind_join(markers, XDM_FIELDS, combine))
              for ident, markers, combine in lists if markers]
    assert not [j for j in joined if j[1]], [j for j in joined if j[1]]
    # The helper sees what it is for, and a key silences it.
    markers = [{"type": "event_id", "match": "in", "value": [1102, 104], "xdm": "xdm.event.id"},
               {"type": "command_line", "match": "regex", "value": "(?i)wevtutil\\s+cl"}]
    assert E.unkeyed_event_kind_join(markers, XDM_FIELDS) == (["xdm.event.id"], ["process"])
    assert E.unkeyed_event_kind_join(markers, XDM_FIELDS, "any") is None
    assert E.unkeyed_event_kind_join(markers[:1], XDM_FIELDS) is None


def test_the_blocks_the_third_review_named_print_their_events_apart(everything):
    out, _ = everything
    hive = "obs-generic-hive-ransomware-as-a-service-with-log-and-recovery-destruction"
    m, lines = block(out, hive + "#how1")
    assert m.group(4) == "alert" and m.group(7) == "complete"
    assert live_lines(lines) == ['| filter (xdm.event.id in ("1102", "104"))',
                                 '         or (xdm.target.process.command_line ~= '
                                 '"(?i)(wevtutil\\s+cl|Clear-EventLog)")']
    _, lines = block(out, hive + "#how5")
    live = live_lines(lines)
    assert len(live) == 2 and live[1].startswith("         or (xdm.target.file.filename = ")
    # The reload and the configuration write are two events, the write after the reload. The
    # write is named by this corpus's word for it, so it is a requirement for its event and
    # not a filter, and the sequence still names both.
    _, lines = block(out, "obs-cisco-asa-vpn-webvpn-implant#how0")
    text = "\n".join(lines)
    assert text.index("// EVENT reload:") < text.index("// REQUIRES for EVENT config (normalised")
    assert "// sequence: EVENT reload, then config, in that order" in text
    for line in live_lines(lines):
        assert not ("xdm.event.id" in line and "xdm.event.type" in line), line
    # Three independent checks, each with the qualifier its own logic gives it. The service
    # check names its event by this corpus's word, so it is a requirement, and its absence from
    # the filter is said.
    m, lines = block(out, "obs-generic-impacket-toolkit-and-long-term-multi-actor-access#how0")
    assert m.group(7) == "partial" and len(live_lines(lines)) == 2
    assert any(l.startswith("// NO LIVE FILTER for EVENT service: ") for l in lines)
    for label in ("session", "service", "interpreter"):
        assert any(l.startswith("// REQUIRES for EVENT {} ".format(label)) for l in lines), label


@pytest.mark.parametrize("pid,arm", [
    ("pat-windows-event-log-cleared", '(xdm.event.id in ("1102", "104"))'),
    ("pat-audit-policy-tampering", '(xdm.event.id in ("4719", "1102"))'),
    ("pat-local-account-created-on-endpoint", '(xdm.event.id in ("4720", "4732"))'),
    ("pat-directory-object-permission-modified", '(xdm.event.id in ("5136", "4670", "4662"))'),
    ("pat-container-image-or-workload-introduced", "(xdm.event.original_event_type ~= "),
])
def test_an_event_identifier_is_an_alternative_of_its_own(pid, arm):
    """Each pattern's logic reads 'the events, and the utilities': alternatives, never one
    event holding an identifier and a command line."""
    lines, _ = _render({"pattern_id": pid, "fidelity": "alert"}, PATTERNS[pid])
    live = live_lines(lines)
    assert len(live) >= 2 and all(l.startswith(("| filter (", "         or (")) for l in live)
    assert any(arm in l for l in live), live
    for line in live:
        assert not ("xdm.event." in line and "xdm.target.process." in line), line


def test_an_alternative_reaches_every_form_its_logic_names():
    """The conjunction made branches unreachable: useradd, dscl and sysadminctl behind a Windows
    process list, and every discovery utility but four behind the account-discovery regex,
    under a threshold of more than four distinct utilities."""
    lines, _ = _render({"pattern_id": "pat-local-account-created-on-endpoint"},
                       PATTERNS["pat-local-account-created-on-endpoint"])
    command = [l for l in live_lines(lines) if "command_line" in l][0]
    for form in ('"useradd"', '"dscl"', '"sysadminctl"'):
        assert form in command, form
    lines, _ = _render({"pattern_id": "pat-host-discovery-command-burst"},
                       PATTERNS["pat-host-discovery-command-burst"])
    arms = live_lines(lines)
    assert len(arms) == 2 and '"systeminfo.exe"' in arms[0] and "command_line" not in arms[0]
    assert all("xdm.source.process.name in (" in arm for arm in arms)
    lines, _ = _render({"pattern_id": "pat-com-object-hijacking"},
                       PATTERNS["pat-com-object-hijacking"])
    arms = live_lines(lines)
    assert "TreatAs" in arms[1] and "registry.value" not in arms[1]
    assert "TreatAs" not in arms[0]


def test_a_labelled_requirement_qualifies_its_event_alone():
    lines, status = _render({"pattern_id": "pat-dcom-remote-object-lateral-movement"},
                            PATTERNS["pat-dcom-remote-object-lateral-movement"])
    assert status == "partial"
    assert "// REQUIRES for EVENT network (computed, not a field test): followed_by_a_session_" \
           "to_a_dynamic_high_port_on_the_same_host" in lines
    assert "// REQUIRES for EVENT spawn (computed, not a field test): NOT (interactive_session_" \
           "exists_for_user_on_host)" in lines
    # An unlabelled requirement still qualifies the whole list.
    lines, _ = _render({"pattern_id": "pat-host-discovery-command-burst"},
                       PATTERNS["pat-host-discovery-command-burst"])
    assert any(l.startswith("// REQUIRES (computed, not a field test): count_distinct(") for l in lines)


def _inject_pattern(corpus, pid, **changes):
    path = corpus / "patterns" / "patterns.jsonl"
    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    for row in rows:
        if row["id"] == pid:
            row.update(changes)
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


@pytest.mark.parametrize("markers,combine,expected", [
    pytest.param([{"type": "event_id", "match": "in", "value": [1102], "xdm": "xdm.event.id"},
                  {"type": "command_line", "match": "regex", "value": "(?i)wevtutil"}], None,
                 "joins xdm.event.id with process marker(s) and sets no combine",
                 id="event-id-with-command-line"),
    pytest.param([{"type": "cloud_operation", "match": "in", "value": ["GetObject"]},
                  {"type": "file_name", "match": "equals", "value": "x.tfstate"}], None,
                 "joins xdm.event.original_event_type with file marker(s)", id="action-with-file"),
    pytest.param([{"type": "process_name", "value": "a.exe", "event": "one"},
                  {"type": "computed", "match": "equals", "value": True, "expr": "x",
                   "event": "two"}], "any", "which no event-bound marker in the list carries",
                 id="requirement-labelled-for-no-event"),
])
def test_validate_refuses_what_the_third_review_found(tmp_path, markers, combine, expected):
    corpus = _corpus_copy(tmp_path)
    _inject(corpus, markers, combine)
    code, out = _validate(corpus)
    assert code == 1, out[-600:]
    assert expected in out, out[-900:]


def test_validate_accepts_an_event_identifier_the_list_says_how_to_combine(tmp_path):
    corpus = _corpus_copy(tmp_path)
    _inject(corpus, [{"type": "event_id", "match": "in", "value": [1102], "xdm": "xdm.event.id",
                      "event": "cleared"},
                     {"type": "command_line", "match": "regex", "value": "(?i)wevtutil",
                      "event": "utility"},
                     {"type": "computed", "match": "equals", "value": True, "expr": "x",
                      "event": "utility"}], "any")
    code, out = _validate(corpus)
    assert code == 0, out[-900:]


# ------------------------------------------------------------- third review: the match list

@pytest.mark.parametrize("match", ["not_equals", "startswith", "not_in", None])
def test_an_unknown_match_is_refused_and_never_printed_as_equality(match):
    """not_equals fell through to = and printed the clause it negates, live."""
    b = E.bind({"type": "process_name", "match": match, "value": "x.exe"}, XDM_FIELDS)
    assert b.kind == "unbound" and b.status == "unrenderable" and b.fault, b
    assert b.field is None and "is not one of" in b.reason
    lines, status = _render({"rule_shape": "single_event", "markers": [
        {"type": "process_name", "match": match, "value": "x.exe"},
        {"type": "command_line", "match": "contains", "value": "y"}]})
    assert not any("x.exe" in l for l in live_lines(lines)), lines
    assert status == "partial"


def test_every_contract_match_is_bound():
    assert E.MATCH_VALUES == tuple(json.loads((CORPUS / "schema" / "observation.schema.json")
                                              .read_text(encoding="utf-8"))["properties"]["how"]
                                   ["items"]["properties"]["markers"]["items"]["properties"]
                                   ["match"]["enum"])
    for match, value in (("equals", "a.exe"), ("contains", "a"), ("prefix", "a"),
                         ("suffix", ".exe"), ("regex", "(?i)a"), ("in", ["a.exe", "b.exe"])):
        b = E.bind({"type": "process_name", "match": match, "value": value}, XDM_FIELDS)
        assert b.kind == "clause", (match, b)


@pytest.mark.parametrize("marker,expected", [
    pytest.param({"type": "process_name", "match": "not_equals", "value": "x.exe"},
                 "'not_equals' is not one of", id="negated-match"),
    pytest.param({"type": "process_nam", "match": "equals", "value": "x.exe"},
                 "is not in vocab marker_type", id="unknown-type"),
    pytest.param({"type": "process_name", "match": "in", "value": "x.exe"},
                 "match is 'in' so value must be an array", id="in-without-list"),
    pytest.param({"type": "process_name", "match": "equals", "value": "x.exe", "negate": True},
                 "unknown key 'negate'", id="unknown-key"),
])
def test_validate_holds_a_pattern_marker_to_the_record_contract(tmp_path, marker, expected):
    """A pattern's markers got the binding check alone, which read an unknown match as =."""
    corpus = _corpus_copy(tmp_path)
    pid = "pat-host-firewall-rule-modification"
    markers = list(PATTERNS[pid]["markers"])
    markers[0] = dict(marker, event=markers[0].get("event")) if markers[0].get("event") else marker
    _inject_pattern(corpus, pid, markers=markers)
    code, out = _validate(corpus)
    assert code == 1, out[-600:]
    assert expected in out and pid in out, out[-900:]


def test_a_negation_never_prints_as_its_positive(everything):
    """pat-device-admin-from-unexpected-source held its source zone as a positive test with a
    note saying the rule is the negation, and the skeleton printed the inverse, live."""
    out, _ = everything
    assert 'xdm.source.zone = "management"' not in out
    zone = [m for m in PATTERNS["pat-device-admin-from-unexpected-source"]["markers"]
            if "management_network" in (m.get("expr") or "")]
    assert zone == [{"type": "computed", "match": "equals", "value": False,
                     "expr": "source_in_management_network", "note": zone[0]["note"]}]
    _, lines = block(out, "obs-cisco-ios-xe-router-pivot-and-container-evasion#how2")
    assert "// REQUIRES (computed, not a field test): NOT (source_in_management_network)" in lines



# ------------------------------------------------- the condition that gives a block its fidelity

# A pattern whose own sketch excludes the estate's address ranges says the destination being
# outside is the signal; ports alone match every internal directory bind or file-share session.
EXTERNAL_SKETCH = re.compile(r"incidr\([^)]*<internal_cidr>\)\s*=\s*false")
EXTERNAL_CONDITION = re.compile(r"(?i)outside|external|incidr")


def test_a_block_whose_pattern_needs_an_external_destination_carries_it(everything):
    """The Log4j block printed `xdm.target.port in (389, 636, 1099, 1389)` at fidelity=alert,
    which matches every internal LDAP bind in a directory estate; the external destination its
    caveat calls the signal was prose, and filter=partial came only from an unrelated legacy
    hostname field. The Horizon and state-affiliated blocks citing the same pattern carried it
    as a condition. The Outlook NTLM block had the same shape on ports 445 and 139."""
    out, _ = everything
    missing = []
    for record in RECORDS:
        for i, how in enumerate(record.get("how") or []):
            pattern = PATTERNS.get(how.get("pattern_id")) or {}
            if not how.get("markers") or not EXTERNAL_SKETCH.search(pattern.get("xql_sketch") or ""):
                continue
            if not any(m.get("type") == "computed"
                       and EXTERNAL_CONDITION.search((m.get("expr") or "")) for m in how["markers"]):
                missing.append("{}#how{}".format(record["id"], i))
    assert not missing, missing
    for key in ("obs-apache-log4j-rapid-mass-exploitation#how2",
                "obs-microsoft-outlook-no-interaction-credential-leak#how0"):
        m, lines = block(out, key)
        assert m.group(7) == "partial", key
        assert any(l.startswith("// REQUIRES") and "outside the estate" in l for l in lines), key


# ---------------------------------------------------------- the process on a connection is its actor

def test_a_connections_process_is_bound_as_its_actor(everything):
    """A network event's connecting process is xdm.source.process, as the platform and the
    xdm-author bundle map it. The tunnel-client block printed its port and its image on
    xdm.target.process, the process acted upon, as one event under fidelity=alert and
    filter=complete, and the water-treatment block joined the remote access tool's image the
    same way with the control-network zone; no single event satisfies either."""
    out, _ = everything
    joined = []
    for record in RECORDS:
        for i, how in enumerate(record.get("how") or []):
            if E.acted_upon_process_on_a_connection(how.get("markers"), XDM_FIELDS, how.get("combine")):
                joined.append("{}#how{}".format(record["id"], i))
    for pid, pattern in PATTERNS.items():
        if E.acted_upon_process_on_a_connection(pattern.get("markers"), XDM_FIELDS,
                                                pattern.get("combine")):
            joined.append(pid)
    assert not joined, joined
    _, lines = block(out, "obs-generic-remote-access-appliance-compromise-for-access-resale#how3")
    live = "\n".join(live_lines(lines))
    assert "xdm.target.port in (7557)" in live and "xdm.source.process.name ~= " in live
    assert "xdm.target.process" not in live
    _, lines = block(out, "obs-generic-water-treatment-setpoint-manipulation-caught-by-operator#how1")
    assert "xdm.target.process" not in "\n".join(live_lines(lines))


def test_a_process_is_not_tested_for_a_network_zone_on_one_event(everything):
    """pat-control-service-stopped reads the control-network zone from inventory because a
    process event carries no network zone, and the water-treatment block, moved in the same
    change, still tested the remote access tool's image and xdm.source.zone on one event. The
    host's own events name the process and a network device's name the zone; no single event
    names both. Reasoned from which telemetry carries each field, as the pattern's is, not
    measured on a tenant."""
    out, _ = everything

    def joined(markers, combine=None):
        if combine == "any" and not any(m.get("event") for m in markers or []):
            return False  # alternatives, each its own event
        events = {}
        for m in markers or []:
            field = E.bind(m, XDM_FIELDS).field or ""
            events.setdefault(m.get("event") or "", set()).add(field)
        return any(any(f.endswith(".zone") for f in fields)
                   and any(".process." in f for f in fields) for fields in events.values())
    found = ["{}#how{}".format(r["id"], i) for r in RECORDS
             for i, how in enumerate(r.get("how") or [])
             if joined(how.get("markers"), how.get("combine"))]
    found += [pid for pid, p in PATTERNS.items() if joined(p.get("markers"), p.get("combine"))]
    assert not found, found
    _, lines = block(out, "obs-generic-water-treatment-setpoint-manipulation-caught-by-operator#how1")
    assert "xdm.source.zone" not in "\n".join(live_lines(lines))
    assert any(l.startswith("// REQUIRES") and "control network" in l for l in lines), lines


@pytest.mark.parametrize("markers,combine,refused", [
    pytest.param([{"type": "port", "match": "in", "value": [7557]},
                  {"type": "process_name", "match": "equals", "value": "frpc.exe"}],
                 None, True, id="port-and-default-process"),
    pytest.param([{"type": "zone", "match": "in", "value": ["ot"], "xdm": "xdm.target.zone"},
                  {"type": "process_name", "match": "equals", "value": "vnc.exe",
                   "xdm": "xdm.target.process.name"}],
                 "all", True, id="zone-and-acted-upon-process"),
    pytest.param([{"type": "port", "match": "in", "value": [7557]},
                  {"type": "process_name", "match": "equals", "value": "frpc.exe",
                   "xdm": "xdm.source.process.name"}],
                 None, False, id="port-and-actor"),
    pytest.param([{"type": "port", "match": "in", "value": [7557]},
                  {"type": "process_name", "match": "equals", "value": "frpc.exe"}],
                 "any", False, id="alternatives"),
    pytest.param([{"type": "port", "match": "in", "value": [7557], "event": "session"},
                  {"type": "process_name", "match": "equals", "value": "frpc.exe", "event": "spawn"}],
                 "all", False, id="two-labelled-events"),
])
def test_validate_refuses_an_acted_upon_process_on_a_connection(tmp_path, markers, combine, refused):
    corpus = _corpus_copy(tmp_path)
    _inject(corpus, markers, combine=combine)
    code, out = _validate(corpus)
    said = "a connection's process is its actor" in out
    assert said == refused, out[-900:]
    if refused:
        assert code == 1, out[-600:]


# ------------------------------------------------------------------------------- printed forms

def test_a_precondition_and_a_missing_pattern_print_as_text_not_python(everything):
    """An inventory precondition over several identifiers printed Python's list repr, and a
    block citing no pattern printed pattern=None where consult.py prints PATTERN_ID: -."""
    out, _ = everything
    assert "// inventory precondition: [" not in out
    assert "  pattern=None  " not in out
    m, lines = block(out, "obs-ivanti-cloud-service-appliance-chained-exploitation#how0")
    assert ("// inventory precondition: CVE-2024-8963, CVE-2024-9379, CVE-2024-8190, "
            "CVE-2024-9380") in lines


# ---------------------------------------------------- 0.43.0, batch R4: normalised event words

# The event_type values a source writes as such, each with where it comes from. Every other
# event_type value in the corpus is this corpus's own word and must carry normalised: true, so
# a new value meets this list and a decision rather than printing as a live filter.
EVENT_TYPE_LITERALS = {
    "git.clone": "the action name in a code-hosting service's audit log",
    "OPERATION_TYPE_REGISTRY_DELETE_KEY": "an XDM_CONST.OPERATION_TYPE member",
    "OPERATION_TYPE_REGISTRY_DELETE_VALUE": "an XDM_CONST.OPERATION_TYPE member",
    "OPERATION_TYPE_FILE_REMOVE": "an XDM_CONST.OPERATION_TYPE member",
}


def _all_markers():
    for r in RECORDS:
        for i, how in enumerate(r.get("how") or []):
            for m in how.get("markers") or []:
                yield "{}#how{}".format(r["id"], i), m
    for pid, p in PATTERNS.items():
        for m in p.get("markers") or []:
            yield pid, m


def test_every_unflagged_event_type_is_a_source_literal():
    """Six filter=complete alert blocks tested xdm.event.type = "integrity_check",
    xdm.event.operation_sub_type = "account_create" or xdm.source.zone = "dmz": the corpus's
    words, which no source writes, so the filter never matches and reads as a true negative."""
    unflagged = {}
    for where, m in _all_markers():
        if m.get("type") == "event_type" and not m.get("normalised"):
            for v in (m["value"] if isinstance(m["value"], list) else [m["value"]]):
                unflagged.setdefault(str(v), where)
    assert set(unflagged) <= set(EVENT_TYPE_LITERALS), {
        v: w for v, w in unflagged.items() if v not in EVENT_TYPE_LITERALS}
    zones = [(w, m["value"]) for w, m in _all_markers()
             if m.get("type") == "zone" and not m.get("normalised")]
    assert not zones, zones


def test_a_normalised_marker_is_never_a_live_clause(everything):
    out, _ = everything
    flagged = {}
    for where, m in _all_markers():
        if m.get("normalised") and "#how" in where:
            values = m["value"] if isinstance(m["value"], list) else [m["value"]]
            flagged.setdefault(where, []).extend(str(v) for v in values)
    assert len(flagged) >= 14
    for key, values in flagged.items():
        m, lines = block(out, key)
        live = " ".join(clause_bodies(lines))
        for v in values:
            assert '"{}"'.format(v) not in live, (key, v)
        assert m.group(7) != "complete", key
        assert any(l.startswith("// REQUIRES (normalised, not a source literal): ")
                   or l.startswith("// REQUIRES for EVENT ") and "(normalised" in l
                   for l in lines), key


@pytest.mark.parametrize("key,field,word", [
    ("obs-fortinet-fortios-ssl-vpn-exploitation#how0", "xdm.event.type", "integrity_check"),
    ("obs-paloaltonetworks-globalprotect-command-injection#how0", "xdm.event.type",
     "integrity_check"),
    ("obs-microsoft-windows-clfs-privilege-escalation-and-account-creation#how0",
     "xdm.event.operation_sub_type", "account_create"),
    ("obs-generic-dmz-to-internal-reachability#how0", "xdm.source.zone", "dmz"),
])
def test_the_complete_alerts_on_corpus_words_are_no_longer_complete(everything, key, field, word):
    out, _ = everything
    m, lines = block(out, key)
    assert m.group(4) == "alert" and m.group(7) in ("partial", "none"), m.group(0)
    assert not [l for l in live_lines(lines) if word in l], lines
    assert any(l.startswith("// REQUIRES (normalised, not a source literal): {} ".format(field))
               and '"{}"'.format(word) in l for l in lines), lines


def test_normalised_binding_names_its_field_and_is_a_requirement():
    b = E.bind({"type": "event_type", "match": "equals", "value": "integrity_check",
                "xdm": "xdm.event.type", "normalised": True}, XDM_FIELDS)
    assert (b.kind, b.status, b.field) == ("requires", "normalised", "xdm.event.type")
    assert b.text == 'xdm.event.type = "integrity_check"'
    b = E.bind({"type": "zone", "match": "in", "value": ["backup"], "normalised": True},
               XDM_FIELDS)
    assert (b.kind, b.status, b.field) == ("requires", "normalised", None)
    assert "on the field it records it in" in b.reason


def test_normalised_binding_rows_carry_the_would_be_clause(handoffs):
    rows = [row for h in handoffs for row in h["marker_bindings"] if row["status"] == "normalised"]
    assert rows and all("clause" not in r and r.get("requires") for r in rows)


@pytest.mark.parametrize("markers,expected", [
    pytest.param([{"type": "process_name", "match": "equals", "value": "a.exe",
                   "normalised": True}], "normalised is set on a process_name marker",
                 id="flag-on-a-literal-type"),
    pytest.param([{"type": "event_type", "match": "equals", "value": "integrity_check",
                   "xdm": "xdm.event.type"}], "a word ", id="unflagged-copy-of-a-flagged-word"),
    pytest.param([{"type": "event_type", "match": "equals", "value": "OPERATION_TYPE_FILE_REMOVE",
                   "xdm": "xdm.event.operation", "normalised": True}], "XDM_CONST",
                 id="flag-on-an-enum-member"),
])
def test_validate_refuses_a_misused_normalised_flag(tmp_path, markers, expected):
    corpus = _corpus_copy(tmp_path)
    _inject(corpus, markers)
    code, out = _validate(corpus)
    assert code == 1 and expected in out, out[-900:]


def test_emit_refuses_a_target_beside_all():
    done = subprocess.run([sys.executable, str(SCRIPTS / "emit_xql.py"), "log4j", "--all"],
                          capture_output=True, text=True, timeout=300)
    assert done.returncode == 2 and "not both" in done.stderr


# ------------------------------------------------------------------- seed status in the handoff
#
# The handoff exported a block its own record calls unconfirmed with confidence high, full
# provenance and no status, verified or disclosure field, in JSON and in text alike, while
# consult.py printed STATUS: SEED for the same key and advise.py [SEED]. A rule author handed
# it could not obey SKILL.md rules 3 and 4. A re-read seed record now says per block whether
# its source supports it, and the handoff says which seed meaning applies.

SEED_RECORDS = {r["id"]: r for r in RECORDS if r.get("status") == "seed"}


@pytest.mark.parametrize("key,part,confidence", [
    ("obs-fortinet-product-family-breadth-and-management-reach#how1", "unconfirmed", "low"),
    ("obs-fortinet-product-family-breadth-and-management-reach#how0", "supported", "high"),
    ("obs-cisco-asa-vpn-webvpn-implant#how1", "unread", "medium"),
])
def test_a_seed_block_hands_off_its_status(handoffs, key, part, confidence):
    block_ = next(b for b in handoffs if b["finding_key"] == key)
    record = SEED_RECORDS[key.split("#")[0]]
    assert (block_["status"], block_["seed_support"], block_["confidence"]) == (
        "seed", part, confidence)
    assert {k: block_["provenance"][k] for k in ("disclosure", "retrieved", "verified")} == {
        k: record["where"].get(k) for k in ("disclosure", "retrieved", "verified")}


def test_every_handoff_carries_its_records_status_and_disclosure(handoffs):
    by_id = {r["id"]: r for r in RECORDS}
    parts = []
    for block_ in handoffs:
        record = by_id[block_["record_id"]]
        where = record.get("where") or {}
        assert block_["status"] == record["status"], block_["finding_key"]
        assert block_["seed_support"] == C.seed_support(record, block_["how_index"])
        assert block_["provenance"]["disclosure"] == where.get("disclosure")
        assert block_["provenance"]["verified"] == where.get("verified")
        assert block_["provenance"]["retrieved"] == where.get("retrieved")
        if block_["status"] == "seed":
            parts.append(block_["seed_support"])
    assert sorted(parts) == sorted(["supported"] * 4 + ["unconfirmed"] * 3 + ["unread"] * 2), \
        "the four seed records hold nine blocks, every one with markers"


def test_a_seed_skeleton_prints_the_status_line_a_consultation_prints(everything):
    out, _ = everything
    stated = {}
    for m, lines in blocks(out):
        if lines and lines[0].startswith("// STATUS:"):
            stated[m.group(8)] = lines[0]
    assert len(stated) == 9 and all(k.split("#")[0] in SEED_RECORDS for k in stated)
    for key, line in stated.items():
        record_id, index = key.split("#how")
        assert line == "// " + C.status_line(SEED_RECORDS[record_id], int(index)), key
    # The parity half: the line under the same FINDING_KEY in a consultation.
    for question in ("Fortinet FortiGate", "Cisco ASA"):
        done = subprocess.run([sys.executable, str(SCRIPTS / "consult.py"), question, "--limit",
                               "500", "--today", "2026-10-01"], capture_output=True, text=True,
                              timeout=300)
        lines = done.stdout.splitlines()
        seen = [(lines[i][len("FINDING_KEY: "):], lines[i + 1]) for i, line in enumerate(lines)
                if line.startswith("FINDING_KEY: ") and line[len("FINDING_KEY: "):] in stated]
        assert seen, question
        for key, status in seen:
            assert "// " + status == stated[key], key


def _problems(record):
    problems = []
    V.check_seed_support(record, "x", problems)
    return [p.message for p in problems]


def test_validate_refuses_support_a_record_does_not_have():
    def seed(verified, **block):
        return {"status": "seed", "where": {"verified": verified}, "how": [block]}
    unread = _problems(seed(False, confidence="high"))
    assert len(unread) == 1 and "confidence is high" in unread[0] and "(unread)" in unread[0]
    unset = _problems(seed(True, confidence="high"))
    assert len(unset) == 1 and "unconfirmed is unset" in unset[0], \
        "one problem per defect: the unset flag, not the confidence beside it"
    flagged = _problems(seed(True, confidence="high", unconfirmed=True))
    assert len(flagged) == 1 and "(unconfirmed)" in flagged[0]
    assert _problems(seed(True, confidence="high", unconfirmed=False)) == [], \
        "the half a re-read source supports keeps its confidence"
    assert _problems(seed(False, confidence="medium")) == []
    on_verified = _problems({"status": "verified", "where": {"verified": True},
                             "how": [{"confidence": "high", "unconfirmed": False}]})
    assert len(on_verified) == 1 and "set on a verified record" in on_verified[0]
    assert _problems({"status": "verified", "where": {"verified": False}, "how": []}) == [
        "status verified beside where.verified false"]


def test_validate_refuses_the_unconfirmed_flag_on_a_seed_never_fully_re_read():
    """The flag belongs to a seed whose source was re-read. seed_support() never reads it on
    one that was not, so on ArcaneDoor it was silently ignored and validate.py said nothing."""
    def unread(**block):
        return {"status": "seed", "where": {"verified": False}, "how": [block]}
    for flag in (True, False):
        problems = _problems(unread(confidence="medium", unconfirmed=flag))
        assert problems == ["how[0].unconfirmed is set on a seed record not fully re-read "
                            "against its source; only a re-read seed record has an "
                            "unconfirmed part"], problems
    # A separate defect from a high block beside it: both are said.
    both = _problems(unread(confidence="high", unconfirmed=False))
    assert len(both) == 2 and "(unread)" in both[1], both
    assert _problems({"status": "seed", "where": {}, "how": [{"unconfirmed": True}]}), \
        "where.verified unset is not a re-read either"


def test_the_shipped_seed_records_state_their_support(tmp_path):
    """Strip the seven flags and restore the four blocks to high: the corpus as it shipped
    before 0.44.0, which validated clean."""
    corpus = _corpus_copy(tmp_path)
    assert _validate(corpus)[0] == 0
    path = corpus / "observations" / "observations.jsonl"
    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    lowered = {"obs-cisco-asa-vpn-webvpn-implant": 1,
               "obs-fortinet-product-family-breadth-and-management-reach": 1,
               "obs-generic-incident-response-trend-base-rates-2022-2026": 0,
               "obs-juniper-scheduled-release-cycle-and-web-management-exposure": 0}
    for row in rows:
        if row["id"] in SEED_RECORDS:
            for how in row["how"]:
                how.pop("unconfirmed", None)
            row["how"][lowered[row["id"]]]["confidence"] = "high"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    code, out = _validate(corpus)
    assert code == 1
    assert "8 problem(s)" in out, out[-600:]
    assert out.count("unconfirmed is unset on a seed record whose source was re-read") == 7
    assert out.count("obs-cisco-asa-vpn-webvpn-implant): how[1].confidence is high on a block "
                     "that is not confirmed (unread)") == 1
