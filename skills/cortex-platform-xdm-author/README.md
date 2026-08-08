<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# cortex-platform-xdm-author

A GoCortexIO skill bundle. Authors Palo Alto Networks Cortex XSIAM Data Model Rules in Cortex Query Language (XQL) from raw vendor log samples.

## Responsible use of AI
This project provides AI Skills to enhance and extend your AI workflows. However, the availability of these skills is not an encouragement, endorsement, or guarantee of safety for uploading confidential, proprietary, or sensitive data into third-party AI platforms.

This projects skills merely format or route data; the ultimate data security and compliance depend entirely on the underlying AI model or platform you choose to connect them to. In line with the Australian Signals Directorate (ASD) guidelines on [Data leaks and privacy breaches](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/artificial-intelligence-for-small-business#data-leaks-and-privacy-breaches), uploading un-anonymised corporate or personal data into public generative AI systems risks exposing private information, as external providers may retain and reuse your inputs.

Before deploying or experimenting with these skills in a professional setting, you must:

* Perform Internal Security Checks: Consult your organisation's IT security, InfoSec, or legal compliance teams to ensure the use of these tools aligns with your internal AI acceptable use frameworks.
* Verify Corporate AI Policies: Ensure your choice of third-party AI provider has been officially vetted and approved by your company or organisation for handling organisational data.
* Validate the AI Backend: Confirm that your underlying AI environment contractually guarantees data isolation and access control as outlined in the ASD's [AI Data Security Best Practices](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/ai-data-security#best-practices-to-secure-data-for-ai-based-systems).

Never feed data into a third-party AI system that has not been internally approved by your organisation or that you would not want publicly disclosed.

## What is in this bundle

- `SKILL.md` -- entry point for a host that supports the on-disk skill convention. Describes scope, inputs, outputs, the authoring workflow, and the hard rules.
- `CHANGELOG.md` -- per-version change history. Not loaded at runtime; provenance only.
- `references/` -- on-demand reference markdown covering XQL language surface, modelling rule structure, parser idioms, the XDM field list, the XDM_CONST closed-list constants, extraction and transformation patterns, verified extraction recipes for syslog / text / CEF / LEEF, the syslog Stage 0 envelope, the authentication / network / process mapping sets, per-record classification and the catch-all, pitfall traps, worked examples, and known compatibility issues.
- `scripts/` -- stdlib-only Python helpers covering the profile -> scaffold -> lint -> verify loop: `profile_log.py` (raw log sample to a JSON worksheet of fields, types, null rates, object-array discriminators, ranked XDM candidates, and a recommended extraction pattern), `scaffold_rule.py` (worksheet to a complete lint-clean starter rule), `lookup_anchor.py` (field-anchor index: forward, `--reverse`, `--related`), `xdm_const_mapper.py` (vendor values to XDM_CONST if-chains, or banded score chains), `mitre_map.py` (MITRE IDs / names to XDM_CONST.MITRE_* arraymap chains), `lint_rule.py` (structural, schema, and dataflow rule linter), and `verify_rule.py` (offline rule evaluation against a sample). Shared loaders `_anchor_index.py` and `_xdm_schema.py` keep the corpus and schema logic in one place.
- `assets/` -- the field-anchor synonym index (`field_anchors.json`) used by `lookup_anchor.py`, the authoritative MITRE ATT&CK crosswalk (`mitre_crosswalk.json`) used by `mitre_map.py`, the banned-field registry (`banned_fields.json`) that backs ERR-029, the HTTP status and Kerberos crosswalks (`http_status_crosswalk.json`, `kerberos_crosswalk.json`) rendered by `http_status_map.py` and `kerberos_map.py`, plus a MAPPED-header template for new rules.
- `tests/` -- Python stdlib bundle-integrity tests; see `tests/README.md`.
- `LICENSE` -- AGPL-3.0-or-later, shipped with the bundle so the licence travels with the content if the bundle is copied standalone.

## Compatible hosts

The bundle follows the on-disk skill convention: a `SKILL.md` at the bundle root plus optional `references/`, `scripts/`, and `assets/` siblings. Any host that loads skills from this layout can use it. The bundle is host-agnostic; nothing in it depends on a particular runner or model. If the host does not support the convention, the markdown is still usable as plain documentation.

## Standalone use

The only runtime dependency is Python 3.9+ stdlib.

- All `SKILL.md` and `references/` content is self-contained. The workflow, parser idioms, XDM schema, and `XDM_CONST` closed-list constants are documented in full.
- `scripts/profile_log.py` reads a raw log sample and emits a structured field worksheet with a recommended extraction pattern. Offline; uses only the shipped anchor index.
- `scripts/scaffold_rule.py` turns that worksheet into a complete, lint-clean starter rule (self-gated through the linter). It classifies per record, emits the catch-all for unmatched records and the commented REVIEW UNMODELLED query, and stamps each rule with a regexable `GOCORTEX_SKILLS_*` provenance block (model / skill name / version / lint warning count).
- `scripts/lookup_anchor.py` queries `assets/field_anchors.json` directly -- forward (field to `xdm.*`), `--reverse` (`xdm.*` to fields), and `--related` (companion fields).
- `scripts/xdm_const_mapper.py` and `scripts/mitre_map.py` emit the XDM_CONST if-chains and MITRE arraymap chains, mapping only to constants documented in the references.
- `scripts/lint_rule.py` runs the rule linter against a single rule file. It reads the XDM schema and XDM_CONST lists from the references and runs a dataflow pass over the rule, so structural, schema-aware, and dataflow checks all happen offline: ERR-009/010/011/012/013/014/015/016/017/018/019/020/024/025/027/028/029/030/031/032/033/034, WARN-014/015/017/018/035/037/038/039/040/041/042/043/044/045/046/048/049/050/051/052/053/054/055, and the INFO-012 cascade hint plus the INFO-013 over-mapping advisory. ERR-029 blocks assignment to a banned internal-only field (registry `assets/banned_fields.json`; see `references/banned-fields.md`). WARN-040 through WARN-046 back the syslog envelope, authentication / network mapping sets, the process / command-execution advisory, and per-record classification (WARN-045 invented EVENT_TAG, WARN-046 record-dropping filter with no catch-all). WARN-055 backs the one member of the authentication set that must never be padded, `xdm.target.resource.name` -- the entity the principal authenticated TO. ERR-019 is a hard block on EVERY dataset -- Cortex rejects an unused field ("Datamodel contains unused fields") regardless of the dataset suffix. Only ERR-025, the concat-hidden shape, stays scoped to `_gc_raw`; on a plain `_raw` dataset that shape is tolerated.
- `scripts/verify_rule.py` evaluates a rule against a sample offline and prints the resulting `xdm.*` map, so behaviour can be confirmed without a tenant.
- The MAPPED-header template in `assets/modeling_header_template.xql` is self-contained.

If no Python interpreter is available, fall back to the references as the authoritative checklist: walk [references/parser-idioms.md](references/parser-idioms.md) (ERR-012 through ERR-019, plus the (xi) / (xii) idioms), [references/modeling-rules.md](references/modeling-rules.md) (validation checklist), and [references/pitfall-traps.md](references/pitfall-traps.md) before emitting the rule.

## Installing

Copy or symlink the bundle directory into the skills directory the host expects. Consult the host's documentation for that path. Once the bundle is in place, the host loads `SKILL.md` automatically.

If the host does not support the on-disk skill convention, load `SKILL.md` and the references by hand into the session.

## Licence

AGPL-3.0-or-later. See [LICENSE](LICENSE).
