<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# XQL language reference

Covers the XQL language as used in data model rules (`[MODEL: dataset=..._raw]`). Data-model-specific structure lives in [modeling-rules.md](modeling-rules.md). Parsing rules (`[INGEST: ...]`) are out of scope for this skill -- see [../SKILL.md](../SKILL.md).

## Rule structure (shared rules)

- First stage after the header has NO leading pipe. Write `filter` or `alter`, not `| filter` or `| alter`. All subsequent stages DO use a leading pipe.
- The entire rule MUST end with a semicolon (`;`). The last field assignment before the semicolon must NOT have a trailing comma.
- Dataset names in the header are NOT quoted. Write `dataset=name_raw` not `dataset="name_raw"`.
- Intermediary (temporary) variables are prefixed with underscore, e.g. `tmp_client_ip`, `tmp_sender_addr`. Every intermediary variable MUST be consumed in a subsequent assignment or passed to another intermediary that is itself consumed. Unused intermediaries cause a BLOCKING validation error: "Data Model Rules contains unused fields".

See [parser-idioms.md](parser-idioms.md) for the twelve non-negotiable parser idioms.

## Extraction functions (used in alter stages)

### `json_extract_scalar(json_string, "$.path.to.field")`

Extracts a scalar value from a JSON string by JSON path. The first argument must be a string. If the column might not be a string, wrap with `to_string()`.

```
json_extract_scalar(to_string(imperva), "$.risk_reason")
```

### `regextract(string, "regex_with_capture_group")`

Returns an ARRAY of capture group matches. Always wrap with `arrayindex(..., 0)` to get the first match.

```
tmp_host = arrayindex(regextract(_raw_log, ">\w+\s+\d+\s+[\d:]+\s+(\S+)\s+accesslogs"), 0)
```

### `split(string, "delimiter")`

Splits a string into an array by delimiter.

```
tmp_parts = split(tmp_stripped_log, " ")
```

### `arrayindex(array, index)`

Returns the element at the given 0-based index from an array.

```
tmp_client_ip = arrayindex(tmp_parts, 2)
```

### `arraycreate(value1, value2, ...)`

Creates an array from scalar values. REQUIRED for Array-type XDM fields.

```
xdm.email.recipients = arraycreate(tmp_recipient)
```

### `arraymap(array, expression)`

Applies an expression to each array element. Use `"@element"` to reference the current item.

```
arraymap(detection_filters, json_extract_scalar("@element", "$.name"))
```

### `arrayfilter(array, condition)`

Filters array elements by condition. Use `"@element"` in the condition.

```
arrayfilter(ip_array, "@element" ~= "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
```

### `arraystring(array, delimiter)`

Joins array elements into a single string with delimiter.

```
arraystring(arraycreate("a", "b"), ", ")
```

### `arraydistinct(array)`

Removes duplicate values from an array.

### `arrayconcat(array1, array2)`

Merges two arrays into one.

### `array_length(array)`

Returns the number of elements in the array.

### `json_extract_array(json_string, "$.path.to.array")`

Extracts an array from a JSON string. Use instead of `json_extract_scalar` when the target value is a JSON array and the XDM field type is Array.

```
tmp_ip_list = json_extract_array(_raw_log, "$.network.ip_addresses")
```

## Transformation functions

### `coalesce(val1, val2, ...)`

Returns the first non-null value.

```
tmp_sender_ip = coalesce(senderIp, SourceIP)
```

### `concat(str1, str2, ...)`

Concatenates strings.

```
xdm.event.description = concat("Event: ", tmp_type, " from ", tmp_sender)
```

### `to_string(value)`

Converts to string. REQUIRED before passing `arrayindex()` output to `split()` or `regextract()`.

```
tmp_sub_a = arrayindex(split(to_string(tmp_result_status), "/"), 0)
```

### `to_number(string)` / `to_integer(string)` / `to_float(value)` / `to_boolean(value)`

Type conversions. `to_number()` returns a float -- integer XDM fields (duration, port, bytes, packets, pid) MUST be wrapped in `to_integer()`. See [parser-idioms.md](parser-idioms.md) idiom (iv) / ERR-015.

```
xdm.event.duration = to_integer(to_number(tmp_ms))
```

### `to_json_string(value)`

Converts a value to a JSON string representation.

### `uppercase(string)` / `lowercase(string)`

Case conversion.

```
tmp_normalised_action = lowercase(tmp_action_type)
```

### `incidr(ip_string, "cidr_range")`

Returns true if the IP address falls within the specified CIDR range. Use for filtering private/public IPs or matching known subnets. `incidr6()` is the IPv6 equivalent.

```
xdm.source.is_internal_ip = if(
    incidr(tmp_src_ip, "10.0.0.0/8") or
    incidr(tmp_src_ip, "172.16.0.0/12") or
    incidr(tmp_src_ip, "192.168.0.0/16"),
    true, false)
```

### `trim(string)` / `replace(string, "old", "new")`

Whitespace trim and string replacement.

### `if(condition1, value1, condition2, value2, ..., default_value)`

Multi-branch conditional. All conditions and values are positional arguments in a flat list. This is NOT if/else syntax -- it is a flat function call.

```
xdm.event.outcome = if(
    Action = "Acc",   XDM_CONST.OUTCOME_SUCCESS,
    Action = "Block", XDM_CONST.OUTCOME_FAILED,
    Action = "Hld",   XDM_CONST.OUTCOME_PARTIAL,
    XDM_CONST.OUTCOME_UNKNOWN)
```

FIRST MATCH WINS. Conditions are tested left to right and the value of the first TRUE one is returned; the rest are never reached. Two branches may therefore overlap, and when they do the ORDER is what decides the answer -- which several idioms in this bundle depend on rather than merely tolerate. The banded severity chain is the plainest case, since its last branch is true for every record the earlier ones already caught:

```
    tmp_pri_log_level = if(
        tmp_pri_severity <= 2,    XDM_CONST.LOG_LEVEL_CRITICAL,
        tmp_pri_severity = 3,     XDM_CONST.LOG_LEVEL_ERROR,
        tmp_pri_severity != null, XDM_CONST.LOG_LEVEL_INFORMATIONAL)
```

A severity of 2 satisfies branch one and branch three; it is CRITICAL because branch one is FIRST. Move that branch last and every record becomes INFORMATIONAL while the rule still lints, verifies and installs. `scripts/verify_rule.py` evaluates `if()` the same way, so `--coverage` reproduces the live ordering offline. See [record-classification.md](record-classification.md) for what this means when the branches are event classifiers rather than bands.

### `parse_epoch(string_value, "MILLIS" or "SECS")`

Parses epoch timestamp string to Timestamp type. `from_epoch` does NOT exist in XQL -- always use `parse_epoch`.

### Arithmetic: `add(a, b)` / `subtract(a, b)` / `multiply(a, b)` / `divide(a, b)`

Infix arithmetic inside `alter` is BANNED -- Cortex parser rejects it with a cascade of generic "parse error" lines. See [parser-idioms.md](parser-idioms.md) idiom (i) / ERR-012.

```
xdm.event.duration = to_integer(subtract(to_number(tmp_end_ms), to_number(tmp_start_ms)))
```

## Arrow operator (`->`)

Used for accessing fields in parsed JSON objects (not strings).

- One level: `column -> FieldName`
- Nested with dot notation: `column -> Parent.Child.Field`
- Array access: `column -> ArrayField[]`
- Inside `arraymap` / `arrayfilter`: use `"@element"` for per-element access.

Chained arrows (`a -> b -> c`) are INVALID. Use dot notation (`a -> b.c`) or `json_extract_scalar`.

JSON-string columns MUST be cast with `-> []` before any array function (`arraymap`, `arrayfilter`, `arraystring`, `arraydistinct`, `array_length`). See [parser-idioms.md](parser-idioms.md) idiom (vii) / ERR-018.

```
arraymap(participants -> [], ...)     // correct
arraymap(participants, ...)           // BLOCKED -- needs -> []
```

## Comparison operators

| Operator | Meaning |
| --- | --- |
| `=` | Equality (NOT `==`) |
| `!=` | Inequality |
| `~=` | Regex match |
| `contains` | Substring check |
| `in` | Set membership |
| `or` / `and` | Combine conditions inside `if()` branches |

### Matching is case-insensitive everywhere, and case cannot be tested

XQL folds case throughout: string comparison, `contains`, and regex via
`~=` and `regextract`. The consequences are worth stating plainly,
because one of them is a silent trap:

- `"value" = "VALUE"` is true.
- `subject ~= "SHOW CONFIGURATION"` matches a lowercase subject.
- `regextract(x, "([A-Z][A-Z0-9_]+)")` captures lowercase text. An
  uppercase character class does NOT restrict a capture to uppercase.
- `(?i)` is therefore redundant. It is harmless and reasonable to keep as
  a statement of intent, but it changes nothing, and no rule may depend
  on case-sensitivity because case-sensitivity cannot be requested.
- `uppercase(x) = x` is always true, so there is no in-query way to TEST
  for case either. Auditing a field for case means pulling the distinct
  values out and testing them outside the query.

The trap follows from the third point. An uppercase class is the obvious
way to express "this token is an identifier, not prose", and it does not
work -- see the hard rule below.

### Case can never qualify a capture; structure must

A capture is safe when the surrounding STRUCTURE identifies the token:

```
%FACILITY-SEVERITY-MNEMONIC:     anchored by the % sigil and the severity digit
key="value"                       anchored by the key name
AdminName=<value>                 anchored by the key name
```

A capture is NOT safe when it lifts an identifier out of free text and
relies on a character class to qualify it:

```
// WRONG -- the intent is "an uppercase vendor tag", but [A-Z] folds, so
// this captures whatever token sits in that position: a C function name,
// a word, anything
"%[A-Z]+-\d:\s+\S+\s+([A-Z][A-Z0-9_]{3,}):"
```

Where the position genuinely is free text, enumerate the documented
vendor tags and let anything else fall back to a structural identity:

```
// RIGHT -- the alternation IS the qualifier
"\s(PFE_FW_SYSLOG_ETH_IP|DDOS_PROTOCOL_VIOLATION_SET|DDOS_PROTOCOL_VIOLATION_CLEAR):"
```

That is not the sample-derived hardcoding WARN-049 forbids. These are
documented vendor message tags, the same class of value as
`UI_LOGIN_EVENT`, not literals observed in one customer's data. Lint
WARN-052 flags a case-qualified capture that has no literal anchor.

### Escape a metacharacter once, not twice

A double-escaped metacharacter returns HTTP 500 from the API with no
indication that escaping is the cause -- the failure reads as an
unsupported construct rather than a quoting error, which sends you
looking in the wrong place:

```
\\$\\{      rejected, 500 Internal Server Error
\$\{        works
```

When a compound pattern fails this way, test it ONE TOKEN AT A TIME
rather than trying to repair the whole expression. A single failing
token is obvious; the same token inside an alternation is not.

The 500 is the LUCKY version of this mistake. Double-escaping a
character CLASS does not fail loudly -- it silently asks a different
question:

```
\\s     a literal backslash followed by the letter s   -- matches nothing
\s      whitespace                                     -- what was meant
```

That pattern returns a clean zero. A clean zero is indistinguishable
from a true negative, so it reads as "the condition does not occur here"
and closes the investigation, while the noisy 500 version at least
announces that something is wrong.

So a zero result from a pattern you have not read is not evidence of
absence. Before acting on one, PRINT THE PATTERN AS THE PLATFORM
RECEIVES IT and read it. This bites hardest when the query is built by a
tool or a script, because the language building the string escapes it
once before the platform sees it at all -- a non-raw Python string is
the usual culprit. Where a mapped field comes back populated on no
record, `verify_rule.py --coverage` reports it, but it cannot tell you
whether the samples lack the event or the pattern was never capable of
matching. Only reading the emitted pattern separates those.

There is no negated regex operator. `not ~=` is rejected by the server
with a 500; negate the whole comparison instead:

```
// REJECTED -- there is no `not ~=` operator
filter tmp_msg not ~= "^debug"

// CORRECT -- negate the expression
filter not (tmp_msg ~= "^debug")
```

Do NOT combine null-comparisons with `and` / `or` inside `if()` predicates. Drop the guard (Cortex propagates null) or nest `if()` calls. See [parser-idioms.md](parser-idioms.md) idiom (ii) / ERR-013.

```
// BANNED
if(tmp_a != null and tmp_b != null, subtract(tmp_b, tmp_a), null)

// allowed
subtract(tmp_b, tmp_a)

// allowed (nested guards)
if(tmp_a != null, if(tmp_b != null, subtract(tmp_b, tmp_a), null), null)
```
