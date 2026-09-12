<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

<div align="center">
  <img src="assets/skills.png" alt="Great Skills" width="600"/>
</div>

# GoCortexIO Skills

Portable skill bundles for doing cool stuff with the Palo Alto Networks Cortex Platform. Each subdirectory is one self-contained bundle: a SKILL.md entry point, on-demand `references/` markdown, optional `scripts/` and `assets/`, and an AGPL-3.0-or-later licence file. Bundles follow the on-disk skill convention: a `SKILL.md` at the bundle root plus optional `references/`, `scripts/`, and `assets/` siblings. Any host that loads skills from this layout can use them. Nothing in a bundle is tied to a particular runner or model.

## Available bundles

| Bundle | Purpose |
| --- | --- |
| [cortex-platform-xdm-author](skills/cortex-platform-xdm-author/) | Author Cortex XSIAM Data Model Rules in Cortex Query Language (XQL). Produce a complete `[MODEL: dataset=..._raw]` rule from raw vendor log samples, with a MAPPED-header comment block. MODEL-only. |

Each bundle is self-contained and installs on its own. The harness may point at an instrument, because dispatch is its job; an instrument never points back or sideways, so installing one does not oblige you to install the rest.

## Installing with Claude Code

This repository is a Claude Code plugin marketplace. From any Claude Code session:

```
/plugin marketplace add gocortexio/skills
/plugin install gocortex-skills@gocortexio-skills
```

The `gocortex-skills` plugin ships every bundle listed above. Install it and all five are available; a bundle you do not use costs nothing but disk. Pushed updates arrive with `/plugin marketplace update`.

## Installing a bundle by hand

A bundle is just a directory. Copy or symlink it into the skills directory the host expects, then start the host. Consult the host's documentation for the exact path. If the host does not support the on-disk skill convention, load `SKILL.md` and the references by hand into the session.

## Updating a bundle

The source-of-truth lives here. Edit files under `skills/<bundle-name>/`, then re-copy to any installed location or rely on a symlink. Commit changes to this folder; installed copies are local artefacts and should not be committed.

Several bundles carry derived reference material. `cortex-platform-xdm-author`'s `references/` are markdown snapshots of the upstream XDM schema, XQL functions, parser-conformance rules and field-anchor index; when the corresponding upstream source changes, re-derive the matching reference file so the bundle stays in sync. `cortex-platform-advisory-consultant` ships its corpus complete, and a newer corpus arrives as a newer version of the bundle rather than as a sync step.

## Scope

Each bundle states its own scope in its `SKILL.md`, and that statement is authoritative. Two worth knowing up front: `cortex-platform-xdm-author` covers Data Model Rules only -- Parsing Rules (`[INGEST: ...]`) and parser-stamped anchor columns are out of scope -- and `cortex-platform-advisory-consultant` answers from the corpus it ships, so it tells you when it holds no record for a product rather than inferring one.

## Runtime dependencies

Every bundle ships its executable helpers under its own `scripts/`. The largest set is `cortex-platform-xdm-author`'s, covering the profile -> scaffold -> lint -> verify loop:

- `profile_log.py` -- static profiler for raw log samples (fields, types, null rates, detection, recommended extraction pattern).
- `scaffold_rule.py` -- turns a profiler worksheet into a lint-clean starter rule.
- `lookup_anchor.py` -- query the shipped field-anchor synonym index (forward, `--reverse`, `--related`).
- `xdm_const_mapper.py` / `mitre_map.py` -- emit XDM_CONST if-chains and MITRE arraymap chains.
- `lint_rule.py` -- standalone syntactic / schema / dataflow linter for a single rule file.
- `verify_rule.py` -- evaluate a rule against a sample offline, no tenant required.

The other bundles ship the same way -- `cortex-platform-correlation-author` a correlation linter, `cortex-platform-advisory-consultant` its consultation, query and validation scripts, and the harness its release gate and publication sweep. All are Python 3.9+ stdlib only: no `pip install`, no Node, no network. They run anywhere a Python interpreter is available. If no Python is available, the reference markdown remains usable as a manual checklist; see the bundle's own `SKILL.md` for the fallback workflow.

## Licence

All bundles are released under the GNU Affero General Public Licence v3.0 or later (AGPL-3.0-or-later). Each bundle ships its own `LICENSE` copy so it remains licensed when installed standalone.
