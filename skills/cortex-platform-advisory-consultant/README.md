<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# cortex-platform-advisory-consultant

A GoCortexIO skill bundle. Somebody names a technology they run; the bundle returns what that technology, its product class or its vendor has historically been caught up in, and the detection logic that goes with each case.

Behind it sits a flat, machine-readable corpus of threat advisory observations. Each record answers six questions about one technology in one scenario from one source: who it is, what was observed, how it was seen, where the knowledge came from, who else was named, and when. The eventual output is Palo Alto Networks Cortex XQL.

## Responsible use of AI
This project provides AI Skills to enhance and extend your AI workflows. However, the availability of these skills is not an encouragement, endorsement, or guarantee of safety for uploading confidential, proprietary, or sensitive data into third-party AI platforms.

This project's skills merely format or route data; the ultimate data security and compliance depend entirely on the underlying AI model or platform you choose to connect them to. In line with the Australian Signals Directorate (ASD) guidelines on [Data leaks and privacy breaches](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/artificial-intelligence-for-small-business#data-leaks-and-privacy-breaches), uploading un-anonymised corporate or personal data into public generative AI systems risks exposing private information, as external providers may retain and reuse your inputs.

Before deploying or experimenting with these skills in a professional setting, you must:

* Perform Internal Security Checks: Consult your organisation's IT security, InfoSec, or legal compliance teams to ensure the use of these tools aligns with your internal AI acceptable use frameworks.
* Verify Corporate AI Policies: Ensure your choice of third-party AI provider has been officially vetted and approved by your company or organisation for handling organisational data.
* Validate the AI Backend: Confirm that your underlying AI environment contractually guarantees data isolation and access control as outlined in the ASD's [AI Data Security Best Practices](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/ai-data-security#best-practices-to-secure-data-for-ai-based-systems).

Never feed data into a third-party AI system that has not been internally approved by your organisation or that you would not want publicly disclosed.

## What is in this bundle

- `SKILL.md` -- entry point for a host that supports the on-disk skill convention.
- `corpus/` -- the knowledge store. `corpus/README.md` is the contract for adding to it.
- `scripts/consult.py` -- the consultation. Emits a fixed, machine-readable block per finding, ranked by criticality or by gap against what the caller already covers.
- `scripts/advise.py` -- answers another session's rule-design consult in one call: corroboration, observation, logic, caveat, telemetry and gaps per pattern.
- `scripts/query.py` -- free-text lookup over the corpus, brief by default.
- `scripts/emit_xql.py` -- the rule-authoring handoff for a single record. The XQL it prints is a skeleton for inspection, not a rule.
- `scripts/validate.py` -- schema, vocabulary, referential integrity and disclosure hygiene checks, over the records and over this bundle's prose.
- `scripts/build_manifest.py` -- regenerates `SOURCES.md` from the corpus; `--check` fails if it is out of date.
- `SOURCES.md` -- **derived** provenance manifest: every publisher represented in the corpus, its source type, how its records are cited, and how many there are.
- `LICENSE` -- AGPL-3.0-or-later, shipped with the bundle so the licence travels with the content.

The corpus ships complete. Nothing needs syncing or ingesting before the bundle answers a question, and a newer corpus arrives as a newer version of the skill. The **full** sync record -- routes, pass logs, per-source backlogs, and the decisions behind what was taken and what was refused -- is maintainer-side and is not part of a shipped bundle, and neither is the deferred-work list. What ships in their place is the derived `SOURCES.md` above, generated from the corpus so a reader can audit where the records came from without taking anyone's word for it.

Python 3.9+, standard library only. No third-party parser, no build step. `scripts/advise.py` calls `curl` to re-check cited URLs older than 14 days and writes the result back to `corpus/reference/url-liveness.json`; that is the only network access in the bundle, and `--no-verify` disables it. Two scripts write: that cache, and `scripts/build_manifest.py`, which regenerates `SOURCES.md` from the corpus unless it is run with `--check`. Nothing else in the bundle modifies a file.

## Source material and what gets committed

The corpus holds distilled observations, never source documents. Licensed intelligence in particular stays out of this repository entirely: stage it somewhere outside the working tree, distil it, and commit only the records.

Records drawn from licensed sources carry `where.disclosure: "restricted"`, an abstract citation of the form `<Publisher> commentary on <subject>`, no URL and no report identifier. The technical substance is kept in full; the source's identity and wording are not. `scripts/validate.py` fails the build if a report identifier survives into a record.

## Status

Version 0.40.2. The corpus holds 1,151 records and 475 patterns, and the validator reports no problems against it. Consultation, lookup, gap ranking and the single-record XQL handoff all work, and every finding carries a LOCUS saying where it sits.

Corpus population continues on the maintainer side, but the bundle answers questions today rather than waiting on it. The XQL that `scripts/emit_xql.py` prints remains a skeleton for a rule-authoring skill to consume, deliberately: this bundle does not write rules.

## Licence

AGPL-3.0-or-later. See [LICENSE](LICENSE). That covers this bundle's own work: the corpus records,
the patterns, the scripts and the prose.

### Third-party material, which the AGPL does not cover

Two shipped reference files are other people's work, reproduced under their own terms rather than
ours, and each carries its notice in its own `attribution` field:

- `corpus/reference/attack-techniques.json` -- MITRE ATT&CK, version 19.1, under the ATT&CK Terms
  of Use. "(c) 2026 The MITRE Corporation. This work is reproduced and distributed with the
  permission of The MITRE Corporation. ATT&CK(R) is a registered trademark of The MITRE
  Corporation."
- `corpus/reference/d3fend-countermeasures.json` -- MITRE D3FEND, version 1.5.0, under the MIT
  Licence, "Copyright (c) 2022 The MITRE Corporation". MIT requires its copyright and permission
  notices to travel with every copy, so the full licence text ships in that file's `licence_text`
  field.

Two public detection-rule corpora are not shipped, but patterns in this bundle are derived from
them or measured against them, and both carry terms of their own:

- `SigmaHQ/sigma`, under the Detection Rule License 1.1. 36 patterns name it in `derived_from` and
  292 in `external_corroboration.sources`.
- `splunk/security_content`, under Apache 2.0, in the same 36 and 292 patterns.

No rule text from either is reproduced here. What is carried is the fact that a comparable
detection exists upstream, which is why the corroboration is a count and a citation rather than a
copy.

`corpus/reference/response-doctrine.json` is distilled from public government advisories and each
entry cites the advisory it came from.

Stated here as well as in the data because a reader deciding whether to install reads this file and
does not open a 545 KB JSON. A blanket licence declaration that silently covers someone else's
material is wrong even when the attribution is present somewhere in the tree.
