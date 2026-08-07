<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# tests/

Python stdlib integrity tests for the `cortex-platform-xdm-author` bundle.

These tests guard the bundle's own shape: JSON validity, SPDX headers, frontmatter ordering, doc-to-schema consistency, ASCII-only and no-emphasis text hygiene, MAPPED-header template completeness, and the bundled linter's behaviour on a small set of fixtures. They also exercise the user-facing path for linting an XQL rule via `../scripts/lint_rule.py`. The manual grep recipe in `../SKILL.md` is the documented fallback for hosts without Python.

## Run

From the bundle root:

```sh
python3 -m unittest discover -v -s tests
```

From anywhere:

```sh
python3 -m unittest discover -v -s /path/to/cortex-platform-xdm-author/tests
```

Python 3.9+ stdlib only. No `pip install`. No Node. No other dependencies.

## What each test guards

| File | Guards | Symptom of a regression |
| --- | --- | --- |
| `test_field_anchors.py` | Field-anchor JSON shape; top-1 candidate for about 13 well-known synonyms (`src`, `dst`, `user_agent`, `hostname`, etc.); the synonym normaliser matches the `lookup_anchor.py` rules; a gibberish input returns zero matches. | Anchor index regenerated and a known mapping drifted, or the JSON file corrupted. |
| `test_asset_integrity.py` | Required top-level files present; every source file UTF-8 decodes; every source file carries the AGPL-3.0-or-later SPDX header in its first 10 lines; SKILL.md line 1 is `---` with `name` plus `description` in the frontmatter; LICENSE first line names AGPL; every markdown file is ASCII-only outside fenced code blocks; markdown outside fenced code carries no bold or italic emphasis; no file contains the legacy "Built with the GoCortex XQL IDE" tagline. | A required file was renamed or removed, SPDX header lost, frontmatter regressed, LICENSE replaced, or a publish-blocker (em-dash, arrow glyph, bold prose, tagline) leaked back into the bundle. |
| `test_doc_consistency.py` | Every `xdm.` path cited in any reference file or the template appears in the authoritative `references/xdm-schema.md` list (or is on a documented allow-known-bad list of counter-examples); every `XDM_CONST.` cited likewise appears in `references/xdm-const.md`; every relative markdown link resolves to an existing file. | A reference invented a path or constant that does not exist, or a markdown link broke after a rename. |
| `test_header_template.py` | `assets/modeling_header_template.xql` contains every required MAPPED-header row (vendor / product / dataset, description, mapping section, NOT MAPPED block, SPDX); starts with a `//` comment; ends with `;`; no leading pipe on the first stage after the MODEL header. | Template rewrite dropped a required section, or introduced a structural defect every emitted rule would inherit. |
| `test_lint_rule.py` | The bundled `scripts/lint_rule.py` fires on fixtures that violate each covered rule -- structural (ERR-009/010/011, WARN-015/017/018), parser-conformance (ERR-012/013/014/015/016/017/018/024/027, INFO-012), schema-aware (ERR-020 invented path, WARN-014 quoted XDM_CONST, WARN-035 array-vs-scalar, WARN-037 log-level word echoed into `xdm.alert.severity`, WARN-038 missing host.ipv4_addresses companion, WARN-039 whole payload dumped into `xdm.event.description`, WARN-040 vendor-anchored syslog header, WARN-041 syslog priority captured but never decoded, WARN-042 authentication-story mandatory set, WARN-043 network-story mandatory set), dataflow (ERR-019 unused temp, ERR-025 concat-hidden temp), and the INFO-013 over-mapping advisory. Confirms ERR-019/ERR-025 fire only on `_gc_raw` datasets and stay silent on plain `_raw`, that WARN-037 flags a log-level word in a value position but not a comparison condition, that WARN-038 stays silent when the companion is present, that WARN-039 fires on `_raw_log` / `to_json_string` into the description but not on a concat() summary, that WARN-042 / WARN-043 fire per missing mandatory story field (with drift-guards pinning the linter and profiler lists to the reference tables), that WARN-042 accepts the `xdm.auth.service` role vocabulary (`SP` / `IDP` / `Universal`, case-folded) and flags a service NAME in its place -- including one reached through an `if()`-chain, which is how shipped rules usually assign the field, while leaving a chain that already returns a role on some branch alone and never reading a predicate literal as a returned value, that a dual authentication + network rule receives both advisories with ONE merged tags assignment, that INFO-013 stays silent on a source/target mirror, that every shipped worked-example rule lints clean (and every block of the multi-format story walkthroughs 06/07/08 lints with zero findings of any severity), and the CLI exit-code / JSON contract. | The linter regressed on a known trap, the dataflow/schema pass drifted, or a worked example stopped being a clean gold standard. |
| `test_syslog_envelope.py` | The syslog Stage 0 transport layer (`references/syslog-envelope.md`). Lint side: WARN-040 fires on a vendor-anchored header and stays silent on a PRI-anchored one; WARN-041 fires when the PRI is captured but neither `xdm.event.log_level` nor `xdm.alert.severity` is assigned; the canonical envelope fixture lints error-clean. Verify side: the offline verifier decodes `<134>` to severity 6 (Informational) and `<12>` to severity 4 (Warning, which only holds because `to_integer` truncates rather than rounds), captures the host from both the RFC 3164 and RFC 5424 positions, and degrades a PRI-stripped record to nulls. | The envelope idiom drifted, the priority arithmetic stopped truncating, or the host coalesce regressed. |
| `test_profile_log.py` | The bundled `scripts/profile_log.py` detects JSON, CEF, and key=value format fixtures; recovers nested array paths (`transactions[].http.method` on the AcmeShield WAF fixture); flags object-array discriminators (`phase` on the WAF transactions); surfaces named header-pair entries (`headers[name=User-Agent]`); computes null rates accurately (`session.user_id` null in event 1, present in event 2, null_rate 0.5); attaches plausible XDM candidate suggestions per field. Also smoke-tests the CLI (exit codes, text format, JSON shape). | Format detection, flattening, type inference, discriminator detection, or anchor lookup regressed. |
| `test_banned_fields.py` | The banned-field mechanism: `assets/banned_fields.json` shape (path/reason/alternative, no duplicates); no banned path listed in `references/xdm-schema.md`; the `references/banned-fields.md` table matches the registry; no shipped reference / worked example / SKILL.md / header template ASSIGNS a banned path (prose warnings are fine); the ERR-029 fixture fires ERR-029 and not ERR-020. | A banned internal-only field (e.g. `xdm.*.cloud.source_type`) crept back into the schema or a recommended mapping, the doc table drifted from the registry, or the linter stopped blocking the assignment. |
| `_helpers.py` | (Not a test file.) Shared bundle-root walker and file iterators used by the test files above. | -- |

## Adding a new integrity check

1. Decide which existing file it belongs in (or create a new `test_<topic>.py` if it is a new topic).
2. Import from `_helpers` (`bundle_root`, `read_text`, `read_json`, `iter_source_files`, `iter_reference_md_files`) rather than walking paths inline. That keeps location-of-bundle logic in one place.
3. If the check is a "deliberate counter-example is allowed" pattern (the ERR-016 examples in `pitfall-traps.md` reference non-existent paths on purpose), add the exception to the relevant `ALLOW_KNOWN_BAD_*` constant in `test_doc_consistency.py` with a one-line written reason.

## What these tests DON'T cover

- Full Cortex validation. The bundled linter performs the structural, schema, and dataflow checks offline, but it does not replace a live-tenant compile. A clean lint means those classes are absent, not that the rule is guaranteed to load.
- Host integration. Whether a particular host actually picks up the bundle correctly is not something Python can determine.
