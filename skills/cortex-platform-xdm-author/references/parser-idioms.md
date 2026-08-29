<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Cortex parser idioms -- read before writing any `alter` stage

These idioms are non-negotiable. Each was observed rejected by the live Cortex XSIAM parser in April 2026. They correspond to the parser-conformance category ERR-012 through ERR-019 plus INFO-012, and they are the highest-yield checks to run against any draft rule.

Apply every check below before emitting the rule. The bundled linter `scripts/lint_rule.py` runs its whole registry offline in one pass -- structural, schema-aware and dataflow checks alike -- so every idiom below is checked mechanically rather than from memory. It exits non-zero when any finding is error severity. Run `python3 scripts/lint_rule.py --list-codes` for the authoritative set: that command IS the registry, and a list restated here is a copy that falls behind it, which is exactly what happened when this paragraph claimed the linter skipped ERR-019.

## ERR-012 -- No infix arithmetic inside `alter`

Use the function form for all arithmetic in `alter`: `add()`, `subtract()`, `multiply()`, `divide()`. Infix `+ - * /` produces a cascade of generic parse errors pointing several lines downstream of the real defect.

```
// WRONG
tmp_duration = tmp_end_ms - tmp_start_ms
tmp_total    = tmp_bytes_in + tmp_bytes_out

// RIGHT
tmp_duration = subtract(tmp_end_ms, tmp_start_ms)
tmp_total    = add(tmp_bytes_in, tmp_bytes_out)
```

## ERR-013 -- No compound null-guard predicates inside `if()`

Cortex propagates null through arithmetic and most functions, so the outer guard is unnecessary. The parser rejects compound `and` / `or` predicates that contain two null comparisons inside an `if()`. Drop the guard or split into nested `if()` / `coalesce()`.

```
// WRONG
if(tmp_a != null and tmp_b != null, subtract(tmp_b, tmp_a), null)
if(tmp_x != null or  tmp_y != null, coalesce(tmp_x, tmp_y), null)

// RIGHT
subtract(tmp_b, tmp_a)
coalesce(tmp_x, tmp_y)
if(tmp_a != null, if(tmp_b != null, subtract(tmp_b, tmp_a), null), null)
```

## ERR-014 -- No bareword `= true` / `= false` on string-typed columns

When the source column is genuinely boolean-typed (rare for JSON-string columns), use the cast form. When it is a stringified boolean (common in arrow-extracted JSON), quote the literal. Bareword `true` / `false` against a string column is rejected by the parser. Stage parameters (for example `target ... append = true`) are unaffected; the rule applies to value comparisons, not stage parameters.

```
// WRONG
if(tmp_external = true, false, true)               // tmp_external is string-typed

// RIGHT
if(tmp_external = "true", false, true)             // quote the literal
if(to_boolean(tmp_external) = true, false, true)   // cast then compare unquoted
```

## ERR-015 -- `to_number()` returns float; wrap in `to_integer()` for integer fields

```
// WRONG
xdm.event.duration = to_number(tmp_duration_ms)

// RIGHT
xdm.event.duration = to_integer(to_number(tmp_duration_ms))
xdm.event.duration = to_integer(subtract(to_number(tmp_end_ms), to_number(tmp_start_ms)))
```

Integer-typed XDM fields that MUST receive `to_integer(to_number(...))`:

- `xdm.event.duration`
- `xdm.source.port`, `xdm.target.port`, `xdm.intermediate.port`
- `xdm.source.sent_bytes`, `xdm.target.sent_bytes`
- `xdm.source.sent_packets`, `xdm.target.sent_packets`
- `xdm.source.process.pid`, `xdm.target.process.pid`

## ERR-016 -- `xdm.event.start_time` / `xdm.event.end_time` DO NOT EXIST

Neither path is in the XDM schema. Fold start/end millisecond pairs into `xdm.event.duration`. Do not assign `_time`. Cortex sets it automatically.

```
// WRONG
xdm.event.start_time = tmp_start_ms
xdm.event.end_time   = tmp_end_ms

// RIGHT
xdm.event.duration   = to_integer(subtract(to_number(tmp_end_ms), to_number(tmp_start_ms)))
```

## ERR-017 -- No struct passthrough inside `arraymap()`

`arraymap` on an array of objects MUST project one scalar field per call via `"@element" -> field_name`. Returning the whole struct (`"@element"` on its own) is rejected, and binding a struct array to an `alter` target is also rejected. See [extraction-patterns.md](extraction-patterns.md) for the full per-scalar projection pattern.

```
// WRONG -- struct passthrough
tmp_offenders = arraymap(arrayfilter(participants -> [],
    "@element" -> role = "offender"), "@element")

// RIGHT -- per-scalar projection
tmp_offender_object_type = arrayindex(arrayfilter(arraymap(participants -> [],
    if("@element" -> role = "offender", "@element" -> object_type, null)),
    "@element" != null), 0)
```

## ERR-018 -- Cast JSON-string columns with `-> []` before array functions

Columns that arrive as JSON-string literals (commonly `participants`, `categories`, `mitre_tactics`, `mitre_techniques`, `properties`, `tags`, `filters`, `detail`) MUST be cast with the `-> []` array projection before being passed to any array function (`arraymap`, `arrayfilter`, `arraystring`, `arraydistinct`, `array_length`). For nested object access, use `column -> field_name` instead.

```
// WRONG
arraymap(participants, ...)
arrayfilter(categories, ...)
arraystring(mitre_tactics, ", ")

// RIGHT
arraymap(participants -> [], ...)
arrayfilter(categories -> [], ...)
arraystring(mitre_tactics -> [], ", ")
```

## ERR-019 -- Every underscore temp must reach an `xdm.*` assignment

Every `tmp_var` defined must, through any chain of intermediary assignments, eventually appear on the RHS of an `xdm.*` assignment. Cortex rejects orphans on `_gc_raw` datasets with the message "Data Model Rules contains unused fields" -- this is a hard block, not a warning. The chain may pass through both underscore-prefixed and bare intermediary names, and through multi-line `if()` / `concat()` / `arraymap()` bodies. Before writing the rule, scan every `tmp_var =` and trace it to an `xdm.*` consumer. If you cannot, delete the extraction.

## (xi) No sibling references inside a single `alter` stage

Cortex evaluates all targets in one `alter` in parallel, so a target cannot read a sibling temp defined in the same stage. The parser reports it as "unknown field `<tmp_var>`". Cross-temp derivations MUST be split across multiple `alter` stages, with later stages referencing only temps from prior stages.

```
// WRONG
| alter
    tmp_offender_ip       = if(tmp_obj_type = "ipaddr", tmp_obj_val, null),
    tmp_offender_ipv4_arr = arraycreate(tmp_offender_ip)

// RIGHT
| alter
    tmp_offender_ip       = if(tmp_obj_type = "ipaddr", tmp_obj_val, null)
| alter
    tmp_offender_ipv4_arr = arraycreate(tmp_offender_ip)
```

## (xii) `concat()` / `arraystring()` bodies do NOT count toward variable reach

The validator's reach analyser stops at function boundaries. It cannot credit a `tmp_var` whose only consumer is inside a `concat()` / `arraystring()` body. Cortex reports it as "Data Model Rules contains unused fields". Either inline the derivation directly into the `concat()` / `arraystring()` expression, or drain the temp through a bareword identity assignment first.

```
// WRONG -- tmp_categories_joined reported orphan
tmp_categories_joined = arraystring(tmp_categories_arr, ", "),
tmp_description       = concat("Cats: ", tmp_categories_joined)

// RIGHT -- inline the derivation
tmp_description = concat("Cats: ", arraystring(tmp_categories_arr, ", "))
```

## INFO-012 -- Cascade root cause: fix the earliest defect first

When the Cortex parser reports two or more errors on adjacent lines, the earliest one is almost always the root cause. The remaining errors are downstream cascade noise from the parser losing its position. Fix the first defect, recompile, and the rest typically vanish.

Most common cascade roots, in priority order:

1. ERR-012 -- infix arithmetic in `alter`
2. ERR-017 -- `arraymap` struct passthrough
3. ERR-018 -- missing `-> []` cast on a JSON-string column
4. ERR-013 -- compound null-guard predicate inside `if()`
5. ERR-014 -- bareword `true` / `false` on a string column

Do not chase the line number Cortex reports. Walk back to the nearest preceding `<lhs> =` line and start there.
