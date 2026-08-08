<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Known XDM compatibility issues

IMPORTANT: fields listed here are NOT valid for general use. This is a list of fields that cause errors in specific contexts. For the canonical list of valid XDM fields, use [xdm-schema.md](xdm-schema.md).

## `xdm.alert.mitre_techniques` -- validator WARN-023

Promoted 2026-04.

- Symptom: the Cortex IDE validator emits WARN-023 ("XDM_CONST enum chain too large"). On `_gc_raw` datasets the type-checker crashes with an "internal error" cascade. On non-`_gc_raw` datasets the warning is non-blocking but appears on every rule that maps the field.
- Datasets: always fires on `_gc_raw` datasets (BLOCKING). Fires as a non-blocking warning on every other dataset, without exception -- it is a property of the field, not of any particular source.
- Workaround:
  1. On `_gc_raw` datasets, OMIT `xdm.alert.mitre_techniques` entirely. Map `xdm.alert.mitre_tactics` only -- the tactic enum is small enough for the validator.
  2. On non-`_gc_raw` datasets the field is still required by the spec because correlation depends on technique mapping. Accept the WARN-023 as the floor signal.
  3. NEVER work around this by inventing a technique-string field. The warning is on the canonical path and there is no alternative XDM sink for technique enumeration.
- Reference: WARN-023, verified 2026-04. A correct ExtraHop RevealX rule emits this warning intrinsically; it is expected, not a defect to chase.

## `xdm.target.process.integrity_level`

Crashes the Cortex IDE validator on `_gc_raw` datasets (XDM_CONST enum mapping crash). Same root cause as the MITRE issue above (oversized enum). Omit on `_gc_raw`; safe to map on other datasets if needed.

## `xdm.session_context_id`

Incompatible on `_gc_raw` datasets (causes internal error). Omit on `_gc_raw`. The field exists in the schema but is not part of the `_gc_raw` data model layer.

## `xdm.network.direction`

Not part of the selected data model on `_gc_raw` datasets. Omit. For direction metadata, include it in `xdm.event.description` or `xdm.event.operation_sub_type`.

## `xdm.source.process.parent_process.*`

These fields do NOT exist in the XDM schema. They always fail on every dataset. Use `xdm.source.process.*` for the immediate process and do not attempt to model the parent chain in this XDM category. The only valid parent field is `xdm.source.process.parent_id`.

## Root cause analysis

The "internal error" message is a generic fallback for at least three distinct problems:

1. Non-existent XDM fields -- always fail on every dataset.
2. Dataset-incompatible fields -- exist in the schema but not in the dataset's data model.
3. XDM_CONST enum mapping crashes -- valid field and valid constant, but the validator cannot handle the chain.

## Debugging methodology

When the validator returns "internal error", use binary search to isolate the offending field:

1. Start minimal (3-5 fields).
2. Add fields in batches.
3. Halve the failing batch until the single problematic field is identified.

The bundled `scripts/lint_rule.py` catches the structural, schema, and dataflow classes it covers, including the invented-path (ERR-020) and array-vs-scalar (WARN-035) checks most relevant to the "internal error" cases above. A clean exit means those classes are absent, not that the rule is guaranteed to load; the oversized-enum crashes in this file are environment-specific and still need a Cortex compile to confirm.
