<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Worked examples -- index

Sixteen production-derived walkthroughs, covering every extraction pattern and each mapping story. Each takes a synthesised raw log sample and walks through to a complete, validated `[MODEL: dataset=..._raw]` rule. Load only the walkthrough whose pattern matches the log in front of you.

The final XQL in each walkthrough is a complete, validated rule reproduced verbatim. The vendor name in each header is real because the rules target real log formats; you would use the same `xdm.observer.vendor` string when authoring against those products. The raw log samples are synthesised with fake addresses (`acme.local`, `10.0.0.1`, `alice@example.com`) so no real customer data is reproduced.

## Walkthroughs

| # | File | Vendor / dataset | Pattern | Notes |
| --- | --- | --- | --- | --- |
| 1 | [01-cisco-wsa-pattern-b.md](worked-examples/01-cisco-wsa-pattern-b.md) | Cisco WSA / `cisco_websecurityappliance_raw` | B (syslog-wrapped positional) | Shortest rule (~123 LOC). Start here for a syslog-based pack. |
| 2 | [02-aws-guardduty-nested-json.md](worked-examples/02-aws-guardduty-nested-json.md) | AWS GuardDuty / `amazon_aws_guardduty_raw` | D (nested JSON, cloud-native) | PascalCase/camelCase duals, directional-IP resolution, closed-list `XDM_CONST` mapping. Mid-length (~385 LOC). |
| 3 | [03-extrahop-revealx-pattern-d-prime.md](worked-examples/03-extrahop-revealx-pattern-d-prime.md) | ExtraHop RevealX / `extrahop_revealx_raw` | D' (role-filtered array of objects) | Hardest pattern: `participants[]` projected per-scalar, banded scoring, MITRE constant mapping, `-> []` JSON-string cast. |
| 4 | [04-trend-micro-vision-one-pattern-d.md](worked-examples/04-trend-micro-vision-one-pattern-d.md) | Trend Micro Vision One / `trendmicro_visionone_raw` | D (arrow operator on pre-parsed top-level columns; `_raw_log` is null) | `processChainInfo[0]` JSON re-extraction, `filters[]` projection, self-sufficient derivation of `tmp_source` / `tmp_severity_band` from raw. |
| 5 | [05-imperva-audit-trail-pattern-a.md](worked-examples/05-imperva-audit-trail-pattern-a.md) | Imperva Audit Trail / `imperva_audit_trail_raw` | A (`json_extract_scalar` on a top-level JSON-string column) | Smallest rule (~92 LOC). Pure `json_extract_scalar(to_string(<column>), "$.path")` idiom. |
| 6 | [06-okta-authentication-multi-format.md](worked-examples/06-okta-authentication-multi-format.md) | Okta / Identity Cloud | A (JSON) and B (RFC 5424 syslog) | One authentication event in two wire formats. Mandatory 15-field authentication-story mapping (WARN-042); extraction differs, XDM assignment is identical. |
| 7 | [07-fortigate-network-multi-format.md](worked-examples/07-fortigate-network-multi-format.md) | Fortinet / FortiGate | A (JSON) and B (RFC 3164 syslog, Stage 0 envelope) | One network event in two wire formats plus a dual authentication+network SSL-VPN branch. Mandatory 17-field network-story mapping (WARN-043); merged story tags in one arraycreate. |
| 8 | [08-cisco-tacacs-aaa-multi-shape.md](worked-examples/08-cisco-tacacs-aaa-multi-shape.md) | Cisco / Secure ACS TACACS+ | B (RFC 3164 syslog, Stage 0 envelope) | Nine AAA event shapes (structured kv, legacy freeform, chatter) through one rule: discriminator filter, shared coalesce drain, AAA topology, non-UPN identity policy, reason normalisation. |
| 9 | [09-sysmon-endpoint-multi-eventid.md](worked-examples/09-sysmon-endpoint-multi-eventid.md) | Microsoft / Sysmon | A (JSON) | Many EventIDs through one rule on the channel/verb model; endpoint events carry blank tags. |
| 10 | [10-windows-security-4688-process-creation.md](worked-examples/10-windows-security-4688-process-creation.md) | Microsoft / Windows Security | A (JSON) | Process creation; the executable-parent distinction WARN-044 exists to catch. |
| 11 | [11-linux-sudo-command.md](worked-examples/11-linux-sudo-command.md) | Linux / `sudo` | B (RFC 3164 syslog) | Command execution over syslog; the `COMMAND=` capture terminated on content, not end-of-line. |
| 12 | [12-windows-logon-kerberos.md](worked-examples/12-windows-logon-kerberos.md) | Microsoft / Windows Security | A (JSON) | 4624 / 4625 / 4768; the complete LOGON_TYPE list and the Kerberos crosswalk. |
| 13 | [13-aws-cloudtrail-multi-event.md](worked-examples/13-aws-cloudtrail-multi-event.md) | Amazon / AWS CloudTrail | D (nested JSON) | Operation verb DERIVED from `eventName`; many API actions through one rule. |
| 14 | [14-azure-activity-signin.md](worked-examples/14-azure-activity-signin.md) | Microsoft / Azure + Entra ID | D (nested JSON) | Activity and sign-in in one rule; dual CLOUD + AUTHENTICATION tagging. |
| 15 | [15-gcp-cloud-audit.md](worked-examples/15-gcp-cloud-audit.md) | Google / Cloud Audit Logs | D (nested JSON) | Verb from `methodName`, outcome from `status.code`. |
| 16 | [16-nokia-nfmp-management-plane.md](worked-examples/16-nokia-nfmp-management-plane.md) | Nokia / NFM-P (NSP) | B (syslog) + a nested application header | A management plane with NO authentication anywhere. Recipe 14 two-stage parse; `logged in` as a false friend; the audit trail as a command execution; continuation lines to the catch-all. |

## Each walkthrough follows the same structure

- Framing -- vendor, product, dataset, what the rule does.
- Synthesised raw log sample -- 3-5 lines of fake-but-faithful data.
- Field inventory -- what's in the sample, what data type, what it means.
- Pattern selection -- which extraction pattern from [extraction-patterns.md](extraction-patterns.md) applies and why.
- Field-anchor lookups -- what `scripts/lookup_anchor.py` returns for the key vendor fields, and what gets selected.
- The full rule -- verbatim from the corresponding pack's `datamodel.xql`.
- Key decisions called out -- banded scoring, companion pairs, NOT MAPPED reasoning, self-sufficient derivation.

## A MODEL rule never reads a parser-stamped anchor

Some packs have a parser (`parser.xql`) that stamps underscore anchor
columns (e.g. `tmp_wsa_http_method`, `tmp_action_type`, `tmp_severity_band`) at
ingest. A MODEL rule must NOT read those columns. Cortex validates a
MODEL rule statically against the dataset schema, where parser-only `_`
anchors do not exist, so a bare reference is rejected as "unknown field
`tmp_x`" BEFORE any `coalesce()` fallback can run. Earlier revisions of
these walkthroughs used a `coalesce(tmp_anchor, fallback_from_raw)` shape;
that shape is the bug. The rule must derive every value from the raw
dataset columns (or `_raw_log`) on its own. The linter enforces this as
ERR-027. ExtraHop's `tmp_detection_category` is the model to follow: the
parser stamps it, but the MODEL deliberately does not read it.
