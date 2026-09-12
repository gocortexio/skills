#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: GoCortexIO
"""scaffold_rule.py <worksheet.json>   (or: profile_log.py ... | scaffold_rule.py -)

Turn a profile_log.py worksheet into a complete starter MODEL rule. The
output is a deterministic, lint-clean `[MODEL: dataset=..._raw]` skeleton:
a MAPPED-header comment block, an extraction stage with one `tmp_` temp
per mapped leaf, and an XDM drain stage wired from the worksheet's ranked
anchor candidates. Same worksheet in -> same rule out.

It is a starting point, not a finished rule. The drain stage covers the
high-confidence scalar mappings; fields that need an XDM_CONST if-chain,
banded scoring, or array-of-object projection are listed in the MAPPED
header's TODO / NOT MAPPED block for the author to complete.

The generated rule is run through the bundled linter before it is
printed; if any error-severity finding survives, the tool exits non-zero
and reports it, so a broken scaffold is never emitted silently.

Reads the worksheet from a path argument, or from stdin when the
argument is "-". Vendor / product / dataset default sensibly and can be
overridden with flags.

Exit codes:
    0   scaffold emitted and lints clean
    1   argument error, or the generated scaffold did not lint clean
    2   cannot read or parse the worksheet

Python 3.9+ stdlib only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _xdm_schema import load_xdm_paths  # noqa: E402
import lint_rule  # noqa: E402


# Formats whose fields arrive as parsed top-level columns (reference the
# column directly) versus formats carried in _raw_log as a JSON string
# (extract with json_extract_scalar).
_JSON_FORMATS = {"json", "jsonl"}
_COLUMN_FORMATS = {"kv", "csv", "tsv", "cef", "leef"}
_POSITIONAL_FORMATS = {"syslog-3164", "syslog-5424", "unknown"}
_SYSLOG_FORMATS = {"syslog-3164", "syslog-5424"}

_DEFAULT_MIN_FREQUENCY = 3

# Stage 0: the canonical RFC 3164 / 5424 envelope capture and priority
# decode (references/syslog-envelope.md). Anchored on the PRI token, never
# on a vendor literal; facility and severity sit in separate alter stages
# because severity reads the facility temp (a same-stage sibling reference
# is rejected -- ERR-024). A raw string so the regex backslashes survive.
#
# Prepend-robust (HARD RULE for syslog): the same source arrives direct off
# the box and behind an intermediate relay that prepends its own
# "<PRI> ts host" header (sometimes two). The greedy "^.*" prefix skips any
# relay header(s) to the innermost origin header, so host/PRI are the
# origin's, not the relay's -- and it stays byte-identical on a direct line.
# Body extraction (Stages 1+) MUST anchor on the payload's own token, never
# on ^ or a fixed offset, so it too matches both arrival forms.
_SYSLOG_STAGE0 = r"""| alter
    tmp_pri        = to_integer(to_number(coalesce(arrayindex(regextract(_raw_log, "^.*<(\d{1,3})>[A-Za-z]{3}\s+\d+\s+[\d:]+"), 0), arrayindex(regextract(_raw_log, "^<(\d{1,3})>"), 0)))),
    tmp_host_5424  = arrayindex(regextract(_raw_log, "^<\d{1,3}>\d+\s+\S+\s+(\S+)\s"), 0),
    tmp_host_3164  = arrayindex(regextract(_raw_log, "^.*<\d{1,3}>[A-Za-z]{3}\s+\d+\s+[\d:]+\s+(\S+)\s"), 0)
| alter
    tmp_syslog_host_raw = coalesce(tmp_host_5424, tmp_host_3164)
| alter
    tmp_syslog_host = if(tmp_syslog_host_raw != "-", tmp_syslog_host_raw)
| alter
    tmp_pri_facility = to_integer(divide(tmp_pri, 8))
| alter
    tmp_pri_severity = to_integer(subtract(tmp_pri, multiply(tmp_pri_facility, 8)))
| alter
    tmp_pri_log_level = if(
        tmp_pri_severity <= 2, XDM_CONST.LOG_LEVEL_CRITICAL,
        tmp_pri_severity = 3,  XDM_CONST.LOG_LEVEL_ERROR,
        tmp_pri_severity = 4,  XDM_CONST.LOG_LEVEL_WARNING,
        tmp_pri_severity = 5,  XDM_CONST.LOG_LEVEL_NOTICE,
        tmp_pri_severity != null, XDM_CONST.LOG_LEVEL_INFORMATIONAL),
    tmp_pri_sev_band = if(
        tmp_pri_severity <= 2, "Critical",
        tmp_pri_severity = 3,  "High",
        tmp_pri_severity = 4,  "Medium",
        tmp_pri_severity != null, "Low")"""

# Envelope-derived drains. severity / log_level are seeded from the
# priority fallback only; the author upgrades each to
# coalesce(<payload field>, tmp_pri_*) once the payload severity is parsed.
_SYSLOG_DRAINS = [
    "    xdm.observer.name = tmp_syslog_host",
    "    xdm.event.log_level = tmp_pri_log_level",
    "    xdm.alert.severity = tmp_pri_sev_band",
]
_SYSLOG_ENVELOPE_TARGETS = {
    "xdm.observer.name",
    "xdm.event.log_level",
    "xdm.alert.severity",
}

# Authentication-event mandatory mapping (references/authentication-mapping.md).
# When profile_log.py flags the sample as an authentication event, the
# scaffold pads the fields that have an official placeholder and lists the
# rest -- the ones the doc says must come from the raw log, never a static
# value -- as TODOs. The advisory WARN-042 then flags anything still
# unmapped. xdm.event.type is handled by the always-present drain line
# (set to "authentication" for an auth event) and xdm.event.tags by the
# merged story-tags emission (the tags array carries the union of the
# detected stories), so neither is repeated here.
# xdm.event.operation is NOT padded: it is an XDM_CONST.OPERATION_TYPE
# enum and there is no neutral member, so a blind default (e.g.
# AUTH_LOGIN) would assert an operation the log may not describe. It is a
# must-extract TODO instead -- the author derives the specific member, or
# leaves it unmapped when the event kind is unclear.
# xdm.source.user.identity_type IS padded, with IDENTITY_TYPE_USER: an
# authentication event carries a mandatory UPN, so the principal is a
# human user in the overwhelming majority of cases. This is not the
# operation problem -- USER is entailed by the auth context, not guessed,
# and a neutral member (IDENTITY_TYPE_UNKNOWN) exists as a fall-back. The
# author refines to MACHINE ($-suffixed account), BUILTIN (SYSTEM /
# service) or VIRTUAL (managed) per references/authentication-mapping.md.
# xdm.source.user.user_type is padded with USER_TYPE_REGULAR, the ~90%
# default (the enum has no UNKNOWN member). The scaffolder cannot key a
# derivation off the principal (the upn/username temp is not fixed here),
# so it seeds the safe default and the header lists user_type as a field
# to refine: the author replaces the pad with the name-convention match
# idiom ($ -> MACHINE_ACCOUNT; svc_/service/gserviceaccount ->
# SERVICE_ACCOUNT; else REGULAR) from references/authentication-mapping.md.
# xdm.target.resource.name is NOT padded, and the contrast with
# xdm.target.ipv4 just below it is the point. An empty xdm.target.ipv4
# honestly says "this record has no target address"; the placeholder is
# semantically empty. An empty xdm.target.resource.name would say "the
# target of this authentication is known and it is nothing", which is
# never true -- and a padded target is exactly how an inverted auth rule
# (source and target the wrong way round) passes the linter. It is a
# must-extract TODO, and WARN-055 flags a placeholder if one appears.
_AUTH_PADDABLE = [
    ("xdm.network.ip_protocol", "XDM_CONST.IP_PROTOCOL_IP"),
    ("xdm.source.port", "to_integer(0)"),
    ("xdm.source.user.identity_type", "XDM_CONST.IDENTITY_TYPE_USER"),
    ("xdm.source.user.user_type", "XDM_CONST.USER_TYPE_REGULAR"),
    ("xdm.target.ipv4", '""'),
    ("xdm.target.port", "to_integer(0)"),
]
# Mandatory fields that cannot be padded -- the doc requires a real value
# from the raw log. Auto-wired by the normal anchor loop when the source
# carries them; otherwise listed as TODO and flagged by WARN-042.
# The recommended identity mirror, as (user field, identity twin) pairs.
# Emitted as AUTH RECOMMENDED TODO comments, never as seeded values: the
# mirror must repeat its twin's derivation character for character, which
# is not known at scaffold time. Canonical source: the "Recommended
# fields (the identity mirror)" table in
# references/authentication-mapping.md. Mirrored in lint_rule.py and
# profile_log.py; a test pins the three lists together.
_AUTH_RECOMMENDED = [
    ("xdm.source.user.upn", "xdm.source.identity.upn"),
    ("xdm.source.user.identity_type", "xdm.source.identity.identity_type"),
    ("xdm.source.user.user_type", "xdm.source.identity.user_type"),
    ("xdm.source.user.username", "xdm.source.identity.username"),
    ("xdm.source.user.identifier", "xdm.source.identity.identifier"),
    ("xdm.source.user.domain", "xdm.source.identity.domain"),
]

_AUTH_MUST_EXTRACT = [
    ("xdm.auth.service",
     'the ROLE this system played, decided per event type: "IDP" when it '
     'validates the credential, "SP" when it initiates and relies on '
     'another to validate, "Universal" when the source is not a known '
     "IdP provider (local auth, TACACS+, SSH onto a device). Never a "
     "service name -- the protocol or mechanism goes to "
     "xdm.auth.auth_method or xdm.network.application_protocol"),
    ("xdm.event.operation",
     "the specific XDM_CONST.OPERATION_TYPE_* (AUTH_LOGIN for a password "
     "login, AUTH_MFA for MFA); leave unmapped rather than guessing when "
     "the event kind is unclear"),
    ("xdm.source.user.upn",
     "authenticated identity, ALWAYS UPN-shaped; when the raw value may "
     'be bare use if(tmp_u contains "@", tmp_u, tmp_u != null, '
     'concat(tmp_u, "@localhost"))'),
    ("xdm.source.ipv4",
     "real client source IP from the raw log (never static, empty, or a list)"),
    ("xdm.event.original_event_type",
     "raw vendor event name exactly as logged; for the catch-all default "
     'it to the sentinel: coalesce(tmp_vendor_event_type, "GOCORTEX_UNMODELLED")'),
    ("xdm.event.outcome",
     "XDM_CONST.OUTCOME_SUCCESS / OUTCOME_FAILED, on conclusive events only"),
    ("xdm.target.resource.name",
     "the device / application / service the principal authenticated TO "
     "(an explicit target or application field, a Kerberos service "
     "principal, the accessed device name, else its address); set it IN "
     "ADDITION to xdm.target.host.hostname / xdm.target.application.name / "
     "xdm.target.ipv4, and NEVER pad it -- a placeholder here leaves the "
     "event targetless while satisfying WARN-042 (WARN-055)"),
]

# Network-event mandatory mapping (references/network-mapping.md, the
# canonical in-bundle source). Same shape as the authentication
# block: pad what has an official placeholder, TODO-list what must come
# from the raw log. xdm.event.type and xdm.event.tags are handled by the
# always-present drain line and the merged story-tags emission, so
# neither is repeated here. xdm.event.outcome is padded OUTCOME_UNKNOWN
# for a network-only event but deliberately NOT on a dual event -- the
# authentication story allows SUCCESS / FAILED only, so there the
# outcome stays a must-extract TODO.
_NETWORK_PADDABLE = [
    ("xdm.event.outcome", "XDM_CONST.OUTCOME_UNKNOWN"),
    ("xdm.network.ip_protocol", "XDM_CONST.IP_PROTOCOL_IP"),
    ("xdm.network.protocol_layers", 'arraycreate("IP")'),
    ("xdm.source.host.device_id", '""'),
    ("xdm.source.ipv6", '""'),
    ("xdm.source.is_internal_ip", "false"),
    ("xdm.source.port", "to_integer(0)"),
    ("xdm.source.sent_bytes", "to_integer(0)"),
    ("xdm.target.host.device_id", '""'),
    ("xdm.target.ipv4", '""'),
    ("xdm.target.ipv6", '""'),
    ("xdm.target.is_internal_ip", "false"),
    ("xdm.target.port", "to_integer(0)"),
    ("xdm.target.sent_bytes", "to_integer(0)"),
]

# The three xdm.network.http.* leaves are NOT part of the unconditional
# network set. They are mandatory only for a network event that carries
# an HTTP layer, which is how lint_rule.py gates WARN-043
# (_rule_claims_http_layer). Padding them onto a router SSH login, an
# SNMP failure or a control-plane record asserts a protocol the source
# never saw, and this scaffolder used to do exactly that on every
# network-flagged sample -- emitting url_category = URL_CATEGORY_UNKNOWN
# for a plain syslog feed, labelled "network mandatory, padded".
_NETWORK_HTTP_PADDABLE = [
    ("xdm.network.http.http_header.header", '""'),
    ("xdm.network.http.http_header.value", '""'),
    ("xdm.network.http.url_category", "XDM_CONST.URL_CATEGORY_UNKNOWN"),
]

# Held deliberately identical to _HTTP_LAYER_FIELD_RE in lint_rule.py:
# the scaffolder must not pad what the linter would not ask for.
_HTTP_LAYER_TARGETS = ("xdm.target.url", "xdm.source.url")


def _claims_http_layer(used_targets) -> bool:
    """True when the anchor loop has already wired something that only
    exists on an HTTP record -- another xdm.network.http.* field, or a
    URL. Mirrors lint_rule._rule_claims_http_layer."""
    for t in used_targets:
        if t.startswith("xdm.network.http."):
            return True
        if t in _HTTP_LAYER_TARGETS:
            return True
    return False

# Process / command-execution recommended fields (references/process-mapping.md).
# NOT a mandatory story -- XDM has no process tag -- so these are never
# padded; they are listed as TODOs to map from the raw log when the
# profiler flags a process / command event. Advisory WARN-044 only guards
# the executable-parent misuse; it does not require this set.
_PROCESS_RECOMMEND = [
    ("xdm.source.process.name", "short process / image name"),
    ("xdm.source.process.command_line",
     "full command line the process ran (a process the event acts upon "
     "uses xdm.target.process.command_line; see process-mapping.md)"),
    ("xdm.source.process.pid", "process id: to_integer(to_number(...))"),
    ("xdm.source.process.executable.path",
     "full image path (a leaf; never xdm.source.process.executable, a Number)"),
]
_NETWORK_MUST_EXTRACT = [
    ("xdm.source.ipv4",
     'real client source IP from the raw log; "" only when IPv6-only'),
]


def _sanitise_temp(leaf: str, used: set) -> str:
    """Build a unique ``tmp_identifier`` from a leaf name. Skill scratch
    temps use the ``tmp_`` prefix; the ``_`` prefix is reserved by the
    platform for internal / system fields (ERR-028)."""
    base = re.sub(r"[^a-z0-9]+", "_", leaf.lower()).strip("_") or "field"
    name = "tmp_" + base
    if name not in used:
        used.add(name)
        return name
    i = 2
    while f"{name}_{i}" in used:
        i += 1
    final = f"{name}_{i}"
    used.add(final)
    return final


def _extract_expr(fmt: str, path: str) -> Optional[str]:
    """Extraction RHS for a leaf, or None if it needs hand-authoring
    (array-of-object projection, positional parsing)."""
    if "[" in path:
        # Array element or header-pair path -- needs Pattern D' projection.
        return None
    if fmt in _JSON_FORMATS:
        return f'json_extract_scalar(_raw_log, "$.{path}")'
    if fmt in _COLUMN_FORMATS:
        # Parsed into a top-level column; reference it directly.
        return path.split(".")[-1]
    # Positional / unknown: emit a JSON stub but flag it in the header.
    return f'json_extract_scalar(_raw_log, "$.{path}")'


def _title(s: str) -> str:
    return " ".join(w.capitalize() for w in re.split(r"[^A-Za-z0-9]+", s) if w) or s


def scaffold(
    worksheet: dict,
    vendor: str,
    product: str,
    dataset: str,
    min_frequency: int = _DEFAULT_MIN_FREQUENCY,
) -> str:
    fmt = worksheet.get("detected_format", "unknown")
    is_syslog = fmt in _SYSLOG_FORMATS
    is_auth = bool((worksheet.get("authentication") or {}).get("detected"))
    is_network = bool((worksheet.get("network") or {}).get("detected"))
    is_process = bool((worksheet.get("process") or {}).get("detected"))
    fields = worksheet.get("fields") or []
    schema = load_xdm_paths()

    used_temps: set = set()
    # Targets the drain stage always emits itself; a candidate must not
    # produce a duplicate assignment to any of them.
    used_targets: set = {
        "xdm.observer.vendor",
        "xdm.observer.product",
        "xdm.event.type",
    }
    if is_syslog:
        # Stage 0 emits these from the envelope; a candidate must not
        # duplicate them.
        used_targets |= _SYSLOG_ENVELOPE_TARGETS
    extractions: List[str] = []   # (temp, expr)
    drains: List[str] = []        # rendered "xdm.path = ..." lines
    mapping_rows: List[str] = []  # MAPPED-header "src -> dst" lines
    todo_rows: List[str] = []     # MAPPED-header TODO / NOT MAPPED lines

    for f in fields:
        path = f.get("path", "")
        leaf = f.get("leaf", path)
        cands = f.get("xdm_candidates") or []
        top = cands[0] if cands else None

        expr = _extract_expr(fmt, path)
        if expr is None:
            todo_rows.append(
                f"//   {path:<28} -- array / header-pair leaf; project per "
                "Pattern D' (see extraction-patterns.md)"
            )
            continue
        if not top or top.get("frequency", 0) < min_frequency:
            reason = (
                "no XDM anchor above the inclusion gate"
                if top
                else "no XDM anchor match"
            )
            todo_rows.append(f"//   {path:<28} -- {reason}")
            continue

        xdm_path = top["xdm_path"]
        meta = schema.get(xdm_path)
        if meta is None:
            todo_rows.append(
                f"//   {path:<28} -- candidate {xdm_path} not in schema; skip"
            )
            continue
        if xdm_path in used_targets:
            todo_rows.append(
                f"//   {path:<28} -- {xdm_path} already mapped; resolve the "
                "duplicate by hand"
            )
            continue

        temp = _sanitise_temp(leaf, used_temps)
        extractions.append(f"    {temp} = {expr}")

        if meta["const_group"]:
            # XDM_CONST-typed: a bare temp would lose the enum mapping.
            # Leave it for the author to complete with an if-chain.
            todo_rows.append(
                f"//   {path:<28} -> {xdm_path} (needs XDM_CONST."
                f"{meta['const_group']}_* if-chain)"
            )
            # Drain the temp into the description so it is not orphaned.
            drains.append(None)  # placeholder; replaced below
            extractions.pop()    # do not extract a temp we will not assign
            used_temps.discard(temp)
            continue

        used_targets.add(xdm_path)
        if meta["is_array"]:
            rhs = f"if({temp} != null, arraycreate({temp}), null)"
        elif meta["type"] == "Number":
            rhs = f"to_integer(to_number({temp}))"
        else:
            rhs = temp
        drains.append(f"    {xdm_path} = {rhs}")
        mapping_rows.append(f"//   {path:<28} -> {xdm_path}")

    drains = [d for d in drains if d is not None]

    if is_syslog:
        # The envelope mappings lead the header so the reader sees the
        # transport layer before the payload mappings.
        mapping_rows = [
            "//   (syslog envelope)            -> xdm.observer.name",
            "//   (syslog priority, fallback)  -> xdm.event.log_level",
            "//   (syslog priority, fallback)  -> xdm.alert.severity",
        ] + mapping_rows

    # Story tags: xdm.event.tags is an array, so an event that is both
    # authentication and network carries the UNION of the story markers in
    # ONE arraycreate(...) -- a second tags assignment would overwrite the
    # first (WARN-043 flags that).
    story_tags = []
    if is_auth:
        story_tags.append("XDM_CONST.EVENT_TAG_AUTHENTICATION")
    if is_network:
        story_tags.append("XDM_CONST.EVENT_TAG_NETWORK")
    if story_tags and "xdm.event.tags" not in used_targets:
        used_targets.add("xdm.event.tags")
        drains.append(
            f"    xdm.event.tags = arraycreate({', '.join(story_tags)})"
        )
        label = (
            "(story tags, merged)        " if len(story_tags) > 1
            else "(auth mandatory, padded)    " if is_auth
            else "(network mandatory, padded) "
        )
        mapping_rows.append(f"//   {label}-> xdm.event.tags")

    if is_auth:
        # Pad the mandatory fields that have an official placeholder; the
        # normal anchor loop above may already have mapped some from the
        # raw log, so only fill the gaps.
        for field, rhs in _AUTH_PADDABLE:
            if field not in used_targets:
                used_targets.add(field)
                drains.append(f"    {field} = {rhs}")
                mapping_rows.append(f"//   (auth mandatory, padded)    -> {field}")
        # The un-paddable mandatory fields must come from the raw log.
        # Whatever the anchor loop did not wire is listed for the author;
        # WARN-042 reminds at lint time.
        for field, hint in _AUTH_MUST_EXTRACT:
            if field not in used_targets:
                todo_rows.append(
                    f"//   {field:<28} -- AUTH MANDATORY (map from raw): {hint}"
                )

        # The recommended identity mirror. Emitted as TODO prose only --
        # never a seeded assignment, because the mirror must carry the
        # SAME derivation as its user twin and the scaffolder does not
        # know yet what that derivation will be.
        for user_field, ident_field in _AUTH_RECOMMENDED:
            todo_rows.append(
                f"//   {ident_field:<28} -- AUTH RECOMMENDED: mirror of "
                f"{user_field}, same right-hand side, appended beside it"
            )

    if is_network:
        for field, rhs in _NETWORK_PADDABLE:
            if field == "xdm.event.outcome" and is_auth:
                # The authentication story allows SUCCESS / FAILED only, so
                # on a dual event the OUTCOME_UNKNOWN pad would violate it;
                # the outcome stays a must-extract TODO (listed by the auth
                # block above).
                continue
            if field not in used_targets:
                used_targets.add(field)
                drains.append(f"    {field} = {rhs}")
                mapping_rows.append(
                    f"//   (network mandatory, padded) -> {field}"
                )
        # Only a record that carries an HTTP layer takes the HTTP leaves.
        # On anything else they assert a protocol the source never saw.
        if _claims_http_layer(used_targets):
            for field, rhs in _NETWORK_HTTP_PADDABLE:
                if field not in used_targets:
                    used_targets.add(field)
                    drains.append(f"    {field} = {rhs}")
                    mapping_rows.append(
                        f"//   (http layer, padded)        -> {field}"
                    )
        for field, hint in _NETWORK_MUST_EXTRACT:
            if field not in used_targets:
                todo_rows.append(
                    f"//   {field:<28} -- NETWORK MANDATORY (map from raw): "
                    f"{hint}"
                )

    if is_process:
        # Recommended, never padded. List whatever the anchor loop did not
        # already wire, so the author maps the process family from the raw
        # log. Advisory only (WARN-044 guards the executable-parent misuse).
        for field, hint in _PROCESS_RECOMMEND:
            if field not in used_targets:
                todo_rows.append(
                    f"//   {field:<34} -- PROCESS (recommended, map from "
                    f"raw): {hint}"
                )

    # Assemble. Observer + event.type are always present.
    header = _build_header(
        vendor, product, dataset, fmt, mapping_rows, todo_rows, is_auth,
        is_network, is_process,
    )

    body: List[str] = [f"[MODEL: dataset={dataset}]", "filter", "    _raw_log != null"]
    if is_syslog:
        # Stage 0 sits between the null guard and the payload extraction.
        body.append(_SYSLOG_STAGE0)
    if extractions:
        body.append("| alter")
        body.append(",\n".join(extractions))
    body.append("| alter")
    # For an authentication event xdm.event.type must resolve to a value
    # containing "authentication"; for a network event, "network". On a
    # dual event the authentication value wins the single string -- the
    # tags array already carries the network marker. Otherwise the author
    # sets the normalised category by hand.
    if is_auth:
        event_type_line = '    xdm.event.type = "authentication"'
    elif is_network:
        event_type_line = '    xdm.event.type = "network"'
    else:
        event_type_line = '    xdm.event.type = "ALERT"'  # TODO: set the normalised category
    drain_lines = [
        f'    xdm.observer.vendor = "{vendor}"',
        f'    xdm.observer.product = "{product}"',
        event_type_line,
    ]
    if is_syslog:
        drain_lines.extend(_SYSLOG_DRAINS)
    drain_lines.extend(drains)
    body.append(",\n".join(drain_lines))
    body.append(";")

    rule = header + "\n" + "\n".join(body) + "\n"
    return _stamp_warning_count(rule)


def _stamp_warning_count(rule: str) -> str:
    """Resolve the provenance warning-count placeholder. Prefer the build
    environment's value; otherwise self-lint and stamp the advisory count
    (comments do not affect the lint, so this is stable). Keeps the
    GOCORTEX_SKILLS_SKILL_WARNING_COUNT line overtly regexable."""
    import os

    env = os.environ.get("GOCORTEX_SKILLS_SKILL_WARNING_COUNT")
    if env is not None:
        count = _clean_env(env)
    else:
        count = str(
            sum(1 for f in lint_rule.lint(rule) if f["severity"] == "warning")
        )
    return rule.replace(_WARN_COUNT_PLACEHOLDER, count, 1)


def _skill_meta() -> tuple:
    """(name, version) from the bundle SKILL.md frontmatter, or
    ('unknown', 'unknown') if it cannot be read. Deterministic default so
    the provenance block is always populated even without env overrides."""
    name = ver = "unknown"
    try:
        skill = Path(__file__).resolve().parent.parent / "SKILL.md"
        for ln in skill.read_text(encoding="utf-8").splitlines()[:12]:
            m = re.match(r"\s*name:\s*(\S+)", ln)
            if m and name == "unknown":
                name = m.group(1)
            m = re.match(r"\s*version:\s*(\S+)", ln)
            if m and ver == "unknown":
                ver = m.group(1)
    except OSError:
        pass
    return name, ver


def _clean_env(value: str) -> str:
    """Keep a provenance value on one regexable line: no quotes/newlines."""
    return re.sub(r'[\r\n"]+', " ", value).strip()


# Placeholder the warning count is stamped into after the self-lint (see
# scaffold()). Kept overtly greppable.
_WARN_COUNT_PLACEHOLDER = "__PENDING__"


def _provenance_lines() -> List[str]:
    """The machine-regexable provenance block. NAME / VERSION come from
    SKILL.md (env can override); MODEL and the warning count come from the
    build environment. The `GOCORTEX_SKILLS_*` keys and quoted values give
    a stable grep / regex target in every generated rule."""
    import os

    name, ver = _skill_meta()
    model = _clean_env(os.environ.get("GOCORTEX_SKILLS_MODEL", "unknown"))
    skill_name = _clean_env(os.environ.get("GOCORTEX_SKILLS_SKILL_NAME", name))
    skill_ver = _clean_env(os.environ.get("GOCORTEX_SKILLS_SKILL_VERSION", ver))
    # Whether a source reference (OpenAPI spec, vendor mnemonic doc, ...)
    # informed the mapping, or only the raw sample was available. The
    # scaffolder sees only the sample, so it defaults to "sample-only"; the
    # author overrides to "spec-backed" (env or edit) once a reference is
    # used. A greppable audit signal for lower-confidence, review-worthy rules.
    basis = _clean_env(
        os.environ.get("GOCORTEX_SKILLS_SOURCE_BASIS", "sample-only")
    )
    return [
        "//",
        "// Generated via",
        f'// GOCORTEX_SKILLS_MODEL="{model}"',
        f'// GOCORTEX_SKILLS_SKILL_NAME="{skill_name}"',
        f'// GOCORTEX_SKILLS_SKILL_VERSION="{skill_ver}"',
        f'// GOCORTEX_SKILLS_SKILL_WARNING_COUNT="{_WARN_COUNT_PLACEHOLDER}"',
        f'// GOCORTEX_SKILLS_SOURCE_BASIS="{basis}"',
    ]


_SKILL_ISSUES_URL = "https://github.com/gocortexio/skills/issues"


def _footer_lines(dataset: str) -> List[str]:
    """The closing comment sections, in a fixed order so the header is
    predictable across every generated rule: the REVIEW UNMODELLED query,
    then the RAISE SKILL ISSUES pointer. Always emitted last (before the
    [MODEL: ...] body)."""
    return [
        "//",
        "// REVIEW UNMODELLED -- after deploying, list what this rule could",
        "// not classify, and grow it to cover those records:",
        f"//   datamodel dataset = {dataset}",
        '//   | filter xdm.event.original_event_type = "GOCORTEX_UNMODELLED"',
        f"//   | fields xdm.event.original_event_type, {dataset}._raw_log",
        "//",
        "// RAISE SKILL ISSUES -- if this rule mis-modelled something, please",
        "// open an issue and include the REVIEW UNMODELLED output above:",
        f"//   {_SKILL_ISSUES_URL}",
    ]


def _build_header(
    vendor: str,
    product: str,
    dataset: str,
    fmt: str,
    mapping_rows: List[str],
    todo_rows: List[str],
    is_auth: bool = False,
    is_network: bool = False,
    is_process: bool = False,
) -> str:
    lines = [
        "// SPDX-FileCopyrightText: GoCortexIO",
        "// SPDX-License-Identifier: AGPL-3.0-or-later",
        *_provenance_lines(),
        "//",
        f"// {vendor} {product} -- XDM Data Model Rule",
        f"// Dataset: {dataset}",
        f"// Vendor: {vendor} | Product: {product}",
        "//",
        f"// Starter rule scaffolded from a {fmt} sample. Review every",
        "// mapping, set xdm.event.type to the right normalised category,",
        "// and complete the TODO / NOT MAPPED entries below.",
        "//",
        "// NOTE: classify PER RECORD, not per feed. One dataset usually",
        "// carries several record kinds, so decide xdm.event.type and",
        "// xdm.event.tags from each record's own discriminators via if()",
        "// (end the tag if-chain with no default, so an unrecognised record",
        "// gets blank tags -- never a guessed marker). The tags below cover",
        "// the profiled shape only; add branches for the others.",
        "//",
        "// NOTE: never drop a record. Keep only filter _raw_log != null and",
        "// give any record the rule cannot classify the catch-all",
        '//   xdm.event.original_event_type = "GOCORTEX_UNMODELLED"',
        "// so a datamodel search returns the same row count as the raw",
        "// dataset. See references/record-classification.md.",
        "//",
        "// ALERT / EVENT FIELD MAPPING",
        "// ---------------------------",
        "//   (hardcoded)                  -> xdm.observer.vendor",
        "//   (hardcoded)                  -> xdm.observer.product",
    ]
    lines.extend(mapping_rows)
    if is_auth:
        lines.append("//")
        lines.append(
            "// NOTE: authentication event detected -- the XDM authentication "
            "story needs the full mandatory field set (see "
            "references/authentication-mapping.md). Paddable fields are seeded "
            "with the official placeholders above. The AUTH MANDATORY entries "
            "below MUST be mapped from the raw log -- set xdm.auth.service to "
            'the ROLE this system played per event type ("IDP" / "SP" / '
            '"Universal"), never to a service name, and derive the specific '
            "xdm.event.operation (never default to a guess), and name the "
            "authentication TARGET in xdm.target.resource.name rather than "
            "padding it (WARN-055) -- and the advisory WARN-042 flags any "
            "left unmapped."
        )
    if is_network:
        lines.append("//")
        lines.append(
            "// NOTE: network event detected -- the XDM network story needs "
            "the full mandatory field set (see references/network-mapping.md). "
            "Paddable fields are seeded with type-valid placeholders above; "
            "upgrade the pads the log can actually fill (protocol, ports, "
            "byte counts, is_internal_ip via incidr over RFC 1918). The "
            "NETWORK MANDATORY entries below MUST be mapped from the raw log "
            "-- the advisory WARN-043 flags any left unmapped."
        )
    if is_auth and is_network:
        lines.append("//")
        lines.append(
            "// NOTE: dual event (authentication AND network) -- "
            "xdm.event.tags carries the union of both story markers in ONE "
            "arraycreate(...); xdm.event.type keeps the authentication value."
        )
    if is_process:
        lines.append("//")
        lines.append(
            "// NOTE: process / command-execution signal detected -- map the "
            "xdm.*.process.* family the log provides (see "
            "references/process-mapping.md). This is a recommended set, not a "
            "mandatory story. Never assign to xdm.*.process.executable (a "
            "Number) -- use a leaf like executable.path. An AAA / "
            "network-device command-accounting (cmd=) record is a command "
            "execution, not authentication: map its command to "
            "xdm.target.process.command_line with operation OPERATION_TYPE_AUDIT "
            "and no outcome, not the authentication story. Advisory WARN-044."
        )
    if fmt in _SYSLOG_FORMATS:
        lines.append("//")
        lines.append(
            "// NOTE: Stage 0 decodes the RFC 3164 / 5424 envelope (priority "
            "+ host); see references/syslog-envelope.md. log_level and "
            "severity are seeded from the priority as a FALLBACK only -- once "
            "the payload severity is parsed, upgrade each to "
            "coalesce(<payload field>, tmp_pri_log_level)."
        )
        lines.append("//")
        lines.append(
            "// HARD RULE (syslog): this source arrives both direct off the "
            "box and behind a relay that prepends its own <PRI> header. Stage "
            "0 is already relay-aware (^.*); every payload field you extract "
            "below MUST anchor on its own token (regextract on key=/[field:]/ "
            "%MNEMONIC, never on ^ or 'everything after the header') so it "
            "matches BOTH forms even if the sample showed only one -- ERR-030."
        )
    if fmt in _POSITIONAL_FORMATS:
        lines.append(
            "//"
        )
        lines.append(
            f"// NOTE: {fmt} is positional; the json_extract_scalar stubs "
            "below are placeholders -- switch to Pattern B (regextract + "
            "split + arrayindex)."
        )
    if todo_rows:
        lines.append("//")
        lines.append("// TODO / NOT MAPPED")
        lines.extend(todo_rows)
        lines.append("//   _time                        -- Cortex sets _time automatically")
    lines.extend(_footer_lines(dataset))
    return "\n".join(lines)


def _load_worksheet(arg: str) -> dict:
    try:
        text = sys.stdin.read() if arg == "-" else Path(arg).read_text(encoding="utf-8")
    except OSError as exc:
        sys.stderr.write(f"error: cannot read worksheet {arg}: {exc}\n")
        sys.exit(2)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"error: worksheet is not valid JSON: {exc}\n")
        sys.exit(2)


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Scaffold a starter MODEL rule from a profile_log.py "
        "worksheet."
    )
    ap.add_argument("worksheet", help='worksheet JSON path, or "-" for stdin')
    ap.add_argument("--vendor", default="Vendor", help="vendor display name")
    ap.add_argument("--product", default="Product", help="product display name")
    ap.add_argument(
        "--dataset",
        default=None,
        help="dataset name (defaults to <vendor>_<product>_raw)",
    )
    ap.add_argument(
        "--min-frequency",
        type=int,
        default=_DEFAULT_MIN_FREQUENCY,
        help="anchor frequency inclusion gate (default 3)",
    )
    args = ap.parse_args(argv[1:])

    worksheet = _load_worksheet(args.worksheet)

    dataset = args.dataset
    if not dataset:
        v = re.sub(r"[^a-z0-9]+", "_", args.vendor.lower()).strip("_") or "vendor"
        p = re.sub(r"[^a-z0-9]+", "_", args.product.lower()).strip("_") or "product"
        dataset = f"{v}_{p}_raw"

    rule = scaffold(
        worksheet, args.vendor, args.product, dataset, args.min_frequency
    )

    # Self-gate: never emit a scaffold the linter would error on.
    findings = lint_rule.lint(rule)
    errors = [f for f in findings if f["severity"] == "error"]
    if errors:
        sys.stderr.write(
            "error: generated scaffold did not lint clean (this is a bug in "
            "scaffold_rule.py):\n"
        )
        for f in errors:
            sys.stderr.write(f"  line {f['line']} {f['rule_id']}: {f['message']}\n")
        return 1

    sys.stdout.write(rule)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
