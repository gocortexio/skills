<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Extraction patterns -- A, B, C, D

These are the four canonical shapes for getting vendor fields out of `_raw_log` (or out of pre-parsed top-level columns). Pick the pattern that matches the structure of the incoming log; do NOT copy a skeleton verbatim.

For a complete, validated rule that exercises each pattern end to end, see the matching walkthrough in [worked-examples.md](worked-examples.md) rather than reconstructing from the skeleton.

## Decision tree -- which pattern applies?

```
Inspect _raw_log first.

_raw_log contains a JSON string                  -> Pattern A or C
_raw_log contains a syslog / text string         -> Pattern B
_raw_log is null, fields are top-level columns   -> Pattern D
```

Critical: calling `json_extract_scalar` on a null `_raw_log` returns null for EVERY field. If `_raw_log` is null, use Pattern D (arrow operator on top-level columns).

The bundled `scripts/profile_log.py` reports a `detected_format` field on its worksheet that maps onto the decision tree above (`json`, `jsonl` -> Pattern A or C depending on the column shape; `cef`, `leef`, `syslog-3164`, `syslog-5424` -> Pattern B; `kv` -> Pattern A applied to a parsed top-level column). When the worksheet's `object_arrays` section names a discriminator key (`phase`, `role`, `type`, etc.), Pattern D' applies and the projection must filter on that discriminator value before reading the inner scalars.

## Pattern A -- JSON field extraction (`json_extract_scalar`)

When: `_raw_log` is a JSON string, OR the parser delivers a single top-level column whose value is a JSON string.

```
alter
    tmp_<temp_a> = json_extract_scalar(<json_column>, "$.<field_a>"),
    tmp_<temp_b> = json_extract_scalar(<json_column>, "$.<nested>.<field_b>")
| alter
    <XDM_FIELD_1> = tmp_<temp_a>,
    <XDM_FIELD_2> = tmp_<temp_b>;
```

Always cast non-string columns with `to_string()` before passing to `json_extract_scalar`:

```
tmp_field = json_extract_scalar(to_string(<column>), "$.<path>")
```

## Pattern B -- Syslog / positional parsing (`split` + `arrayindex`)

When: `_raw_log` is a single string with positional, delimiter-separated fields (Squid-style, CSV, etc.).

For the recurring text shapes -- key=value pairs, a `src=IP:port dst=IP:port` transport tuple, CEF and LEEF headers, relay-stripped RFC 3164 syslog, and clean scalar capture (IP / MAC / email) from free text -- start from a verified recipe in [extraction-recipes.md](extraction-recipes.md) and adapt it to the sample, rather than composing the regex from scratch. Each recipe is a lint-clean rule proven end-to-end by the test suite, so it raises confidence in the field location and gives well-formed extraction. The recipes are starting points, not a substitute for reading the actual log.

For a syslog source (a `<NNN>` priority token at the start of `_raw_log`), parse the envelope first with the one canonical idiom in [syslog-envelope.md](syslog-envelope.md) -- it captures the host and decodes the priority once, the same way for every vendor -- then apply Pattern B to the payload body. Do not hand-roll a header regex anchored on a vendor literal; the linter flags that as WARN-040.

```
alter
    tmp_<inner> = arrayindex(regextract(_raw_log, "<wrapper_regex>"), 0)
| alter
    tmp_parts = split(tmp_<inner>, " ")
| alter
    tmp_<field_n> = arrayindex(tmp_parts, <N>)
| alter
    <XDM_FIELD> = tmp_<field_n>;
```

Rules:

- Always wrap `arrayindex()` output in `to_string()` before passing to `split()` or `regextract()`. Without the cast, you get a generic parse error.
- Hyphen `"-"` means empty in Squid format. Check `field != "-"` before assigning to XDM.
- The syslog hostname gives the observer / intermediary device identity.

## Pattern C -- Label/value array extraction (`regextract` on key/value)

When: A field contains a JSON-style array of `{label, value}` pairs and the labels you need are not at fixed JSON paths.

```
# string values
tmp_<temp> = arrayindex(regextract(<source>,
    "\"<Label Text>\"\s*,\s*\"value\"\s*:\s*\"([^\"]+)\""), 0)

# numeric values
tmp_<temp> = arrayindex(regextract(<source>,
    "\"<Label Text>\"\s*,\s*\"value\"\s*:\s*(\d+)"), 0)
```

## Pattern D -- Arrow operator on parsed JSON objects

When: `_raw_log` is null and the XSIAM ingestion parser has already broken the event into top-level columns whose values are JSON objects (not strings). Traverse with the arrow operator; append `{}` for sub-objects, `[]` for arrays.

```
alter
    tmp_<sub_obj> = <column> -> <Key>.<SubKey>{},
    tmp_<scalar>  = <column> -> <Key>.<Field>
| alter
    <XDM_FIELD> = tmp_<scalar>;
```

Note: chained arrows (`a -> b -> c`) are invalid. Use dot notation (`a -> b.c`) or `json_extract_scalar` for deep paths.

Note: for arrays of objects (e.g. `participants[]`), do NOT bind the filtered struct to an underscore temp and dereference it later. Cortex rejects struct-bound temps. Use the per-scalar projection (Pattern D' below).

## Pattern D' -- Role-filtered array of objects (per-scalar projection)

When: A column is an array of objects where each element has a discriminator field (`role`, `type`, `party`) and you need one or more scalar fields from the matching element.

Canonical pattern (verified against the live ExtraHop XDM model rule): project ONE scalar at a time inside `arraymap`, drop nulls with `arrayfilter`, then take `[0]`. Never bind the whole struct.

```
# DO NOT (parser rejects -- ERR-017)
alter
    tmp_chosen = arrayindex(arrayfilter(<array_column> -> [],
        "@element" -> <role_field> = "<role_value>"), 0)
| alter
    tmp_field_a = tmp_chosen -> <field_a>;     // struct passthrough -- BLOCKED

# DO (one alter line per scalar; repeat per field)
alter
    tmp_<chosen_field_a> = arrayindex(arrayfilter(arraymap(
        <array_column> -> [],
        if("@element" -> <role_field> = "<role_value>",
           "@element" -> <field_a>, null)),
        "@element" != null), 0),
    tmp_<chosen_field_b> = arrayindex(arrayfilter(arraymap(
        <array_column> -> [],
        if("@element" -> <role_field> = "<role_value>",
           "@element" -> <field_b>, null)),
        "@element" != null), 0)
| alter
    <XDM_FIELD_A> = tmp_<chosen_field_a>,
    <XDM_FIELD_B> = tmp_<chosen_field_b>;
```

Rules:

- Cast the JSON-string column ONCE per projection with `<col> -> []` (see [parser-idioms.md](parser-idioms.md) ERR-018). Without the cast, array functions reject the column.
- `arraymap` with an inner `if()` that returns the inner scalar when the role matches and null otherwise. Then `arrayfilter("@element" != null)` to drop non-matching positions, then `arrayindex(..., 0)` to take the first surviving scalar.
- One projection per inner field. Do NOT bind the filtered struct array to a temp variable.
- Inner field access uses `"@element" -> field_name` (lowercase as it appears in the source JSON).
- Mirror the projection set for victim/target with `role = "victim"`; do not reuse the offender variables.

## Pattern -- MITRE arraymap with no double-wrap

When: The log already provides an array of MITRE IDs and you need an array of XDM_CONST values. The arraymap result IS already an array -- do NOT wrap in `arraycreate()`.

```
alter
    tmp_<ids> = arraymap(<array_column> -> [], "@element" -> <id_field>)
| alter
    <XDM_FIELD> = arraymap(tmp_<ids>, if(
        "@element" = "<ID_1>", XDM_CONST.<NAME_1>,
        "@element" = "<ID_2>", XDM_CONST.<NAME_2>));
```

Contrast: when the log gives a SINGLE id (not an array), wrap with `arraycreate(if(...))` instead. The choice depends on the SHAPE of the source field, not on the destination. See [transformation-patterns.md](transformation-patterns.md) section "Array MITRE mapping" for the full ID->constant rule.

## Pattern -- Banded numeric scoring

When: A vendor numeric score (0-100, 1-10, etc.) needs to be mapped to a banded XDM severity string or `XDM_CONST.LOG_LEVEL_*`. Highest threshold first; final branch fires only when the score is non-null.

```
<XDM_FIELD> = if(
    <score> >= 80, "Critical",
    <score> >= 50, "High",
    <score> >= 30, "Medium",
    <score> != null, "Low");
```

For an XDM_CONST destination, every branch returns an `XDM_CONST.*` value, never a raw string. See [transformation-patterns.md](transformation-patterns.md) section "XDM_CONST-required fields".

## Pattern -- Object-type-gated IP mapping

When: A column may hold an IP, a hostname, a username, or a tenant identifier depending on a sibling discriminator (`object_type`, `entity_kind`). Assign `xdm.source.ipv4` only when the discriminator says the value is an IP.

```
alter
    tmp_<ip> = if(tmp_<object_type> = "ipaddr", tmp_<object_value>, null)
| alter
    xdm.source.ipv4 = tmp_<ip>,
    xdm.source.host.ipv4_addresses = if(tmp_<ip> != null, arraycreate(tmp_<ip>), null);
```

## Pattern -- Scalar-from-array via arrayindex + arrayfilter

When: A vendor array (e.g. `categories[]`) needs to populate a scalar XDM_CONST destination (e.g. `xdm.alert.category`). Map every array element to the closest XDM_CONST with `arraymap`+`if`, drop nulls with `arrayfilter`, then take the first match with `arrayindex`. First match wins. Preserve the full joined text in `xdm.event.description` for human context.

```
alter
    tmp_<joined> = arraystring(<array_column>, ", ")
| alter
    <XDM_SCALAR_FIELD> = arrayindex(arrayfilter(arraymap(<array_column>, if(
        "@element" ~= "(?i)<token_a>", XDM_CONST.<NAME_A>,
        "@element" ~= "(?i)<token_b>", XDM_CONST.<NAME_B>)),
        "@element" != null), 0),
    xdm.event.description = concat("Categories: ", tmp_<joined>);
```

## Anchor pattern -- risk-detection block (banded score + THREAT_CATEGORY scalar + offender/properties.* coalesce)

When: Pattern D detection logs that deliver a numeric `risk_score`, a vendor `categories[]` array, AND a `participants[]` role-tagged actor array with an offender entity (and possibly secondary identity hints under `properties.*`). This is the canonical ExtraHop-RevealX shape but the same anchor applies to any vendor that mixes these three signals (NDR / CDR / SIEM detections, CrowdStrike fac alerts, etc).

The three sub-patterns below MUST appear together; any one missing is a regression.

```
alter
    tmp_risk_score = to_number(risk_score),
    tmp_categories_arr = categories -> [],
    tmp_props_username = properties -> username,
    tmp_offender_username = arrayindex(arrayfilter(arraymap(participants -> [],
        if("@element" -> role = "offender", "@element" -> username, null)),
        "@element" != null), 0)
| alter
    // (1) banded severity -- NEVER raw to_string() on the score
    tmp_severity = if(
        tmp_risk_score >= 80, "Critical",
        tmp_risk_score >= 50, "High",
        tmp_risk_score >= 30, "Medium",
        tmp_risk_score != null, "Low"),
    tmp_log_level = if(
        tmp_risk_score >= 80, XDM_CONST.LOG_LEVEL_CRITICAL,
        tmp_risk_score >= 50, XDM_CONST.LOG_LEVEL_ERROR,
        tmp_risk_score >= 30, XDM_CONST.LOG_LEVEL_WARNING,
        tmp_risk_score != null, XDM_CONST.LOG_LEVEL_INFORMATIONAL),
    // (2) categorical enum array -> THREAT_CATEGORY scalar (first match)
    tmp_category_const = arrayindex(arrayfilter(arraymap(tmp_categories_arr, if(
        "@element" ~= "(?i)brute",        XDM_CONST.THREAT_CATEGORY_BRUTE_FORCE,
        "@element" ~= "(?i)phish",        XDM_CONST.THREAT_CATEGORY_PHISHING,
        "@element" ~= "(?i)dos|ddos",     XDM_CONST.THREAT_CATEGORY_DOS,
        "@element" ~= "(?i)botnet",       XDM_CONST.THREAT_CATEGORY_BOTNET,
        "@element" ~= "(?i)backdoor",     XDM_CONST.THREAT_CATEGORY_BACKDOOR,
        "@element" ~= "(?i)cryptominer",  XDM_CONST.THREAT_CATEGORY_CRYPTOMINER,
        "@element" ~= "(?i)exfil|data",   XDM_CONST.THREAT_CATEGORY_DATA_THEFT,
        "@element" ~= "(?i)code",         XDM_CONST.THREAT_CATEGORY_CODE_EXECUTION,
        "@element" ~= "(?i)hacktool",     XDM_CONST.THREAT_CATEGORY_HACKTOOL,
        "@element" ~= "(?i)post.?expl",   XDM_CONST.THREAT_CATEGORY_POST_EXPLOITATION,
        "@element" ~= "(?i)protocol",     XDM_CONST.THREAT_CATEGORY_PROTOCOL_ANOMALY)),
        "@element" != null), 0),
    // (3) properties.* identity fallback -- coalesce offender then properties
    tmp_user_username = coalesce(tmp_offender_username, tmp_props_username)
| alter
    xdm.alert.severity = tmp_severity,
    xdm.event.log_level = tmp_log_level,
    xdm.alert.category = tmp_category_const,
    xdm.source.user.username = tmp_user_username,
    xdm.target.user.username = tmp_user_username;
```

Explicitly rejected anti-patterns:

- `xdm.alert.severity = to_string(risk_score)` -- unbanded raw score.
- `xdm.alert.subcategory = arraystring(categories -> [], ", ")` as the sole outlet for `categories[]` -- bypasses THREAT_CATEGORY.
- Dropping `properties.*` with "no XDM sink available" when a `properties.username` (or any `*tmp_username`) is present and the offender username might be null.

## A note on intermediate variables

Scratch temporaries use the `tmp_` prefix (`tmp_user`, `tmp_src_ip`, ...). The `_` prefix is reserved by the platform for internal / system-generated fields (`_raw_log`, `_time`, `_message`, ...), so a rule must never CREATE a `_`-prefixed field -- the bundled `lint_rule.py` raises ERR-028 if it does. No explicit `| fields -...` cleanup stage is needed: an XDM MODEL rule surfaces only `xdm.*` fields, so `tmp_` temporaries never reach the datamodel regardless of name. (The linter therefore also omits INFO-006, the missing-cleanup finding; ignore it if a downstream linter reports it.)

Bare language keywords are reserved too, and the `tmp_` prefix is what keeps a temp clear of them. `tag` is the one that bites in practice, because it is the natural name for the `%FAC-SEV-MNEMONIC` token on a syslog source. It is rejected in SEARCH mode as well as in a rule:

```
// REJECTED -- bad query syntax: mismatched input 'tag'
| alter tag = arrayindex(regextract(_raw_log, "%([\w\-]+) :"), 0)

// CORRECT
| alter tmp_mnemonic = arrayindex(regextract(_raw_log, "%([\w\-]+) :"), 0)
```

Prefixing every scratch name with `tmp_` avoids the whole class without having to memorise the keyword list, which is the main reason the convention exists.

The prefix protects the name you CREATE and does nothing for the name you READ. A raw column whose own name is a language construct fails on the read alone, and no naming convention available to the rule can help, because the rule does not choose that name. This is the more expensive half of the class: it does not fail as a query, it fails the whole PACK INSTALL, with an opaque 101704 that names no field and no line, while the linter passes, `spellbook validate` passes, the modelling schema declares the column and the same read runs perfectly in SEARCH mode. Confirmed on a live tenant with two uploads differing by exactly one line:

```
// INSTALLED
| alter tmp_v = api_key_id

// FAILED the pack install -- the only change is reading a column named `view`
| alter tmp_v = api_key_id,
        tmp_view = view
```

Note that `tmp_view` is correctly prefixed.

The escape is a BACKTICK, and it is the established idiom rather than a workaround. Measured across 328 shipped upstream modelling rules, every column of this kind is read inside backticks and not one is read bare: `target` appears 31 times, always quoted; `fields` 13, `in` 10, `transaction` 6, and `tag`, `table` and `filter` twice each. So a rule that must read one of these columns reads it like this:

```
| alter xdm.event.tags = arraycreate(`tag`)
```

Which names qualify was derived from that corpus rather than from how SQL-ish a word looks, and the guess is a bad guide. Reserved: `view`, `tag` and `config` (all three confirmed by live-tenant bisection) plus `target`, `fields`, `in`, `transaction`, `table` and `filter` (never read bare in any shipped rule).

`in` was held out of the check until 1.9.0, on the reasoning that it is also the membership operator and flagging it would fire on every `action in (...)`. That was true of a cruder check and is false of this one, which measurement settles: the read patterns match only in VALUE position -- after `=`, `(` or `,` -- and the operator never appears there, because it follows an identifier. Re-measured against the corpus exactly as the check runs, with strings and comments stripped: 570 membership-operator uses, ZERO matched, against 9 backticked reads the check correctly accepts.

Its pair `out` is NOT reserved, and must not be added on symmetry. `out` arrives beside `in` on every CEF firewall, which makes the symmetry tempting, and the corpus refuses it: `out` is read BARE in value position 8 times in shipped rules -- `to_integer(out)` on the sent-bytes mapping -- and never backticked. That is the `timestamp` and `dst` pattern below, not the `target` pattern. Reserving it would invent a hazard and call 8 demonstrably installable rules broken. A pair is not evidence about both halves.

`config` is reserved as of 2.1.3, and it is the member that shows why corpus silence must never be read as safety. A GitHub Enterprise Cloud audit source spent five tenant uploads on it. The bisect needs THREE probes, not two, and the middle one is the one that gets skipped:

```
json_extract_scalar(config, "$.url")     -- 101704, install FAILED
xdm.target.url = url_path                -- INSTALLED
json_extract_scalar(`config`, "$.url")   -- INSTALLED
```

Feeding the same XDM field from a DIFFERENT column is what separates "this field is gated" from "this column NAME is gated". Skip it and the obvious conclusion is that `xdm.target.url` is a gated field, and the fix becomes not mapping a URL -- wrong, and expensive. The corpus holds zero bare and zero backticked reads of `config` (and zero of `configuration` either way), so on corpus evidence alone it looks exactly like `view`. It is not: of its 20 raw occurrences, the 12 that survive string and comment stripping are all the identical line `config case_sensitive = true`, which is XQL's own stage keyword. The linter had this written down all along -- `_STAGE_KEYWORDS` in `lint_rule.py` lists `config` beside `filter`, `fields` and `target`, three names that were already reserved -- and nothing compared that table to the reserved set. A word this bundle already classified as a language construct is a candidate whatever the corpus says.

The stage keyword also means `config` is the one member needing a false-positive guard. `config case_sensitive = true` opens a line and is out of value position, so it never fired; but the parenthesised form `(config timeframe = 24h` puts the word straight after `(` and did. The read pattern now excludes a name followed by an identifier and an `=`, which is the stage shape and never a column read.

Read the counterexample counts carefully, because it is easy to state them wrongly. `timestamp` is read bare in value position 39 times and `dst` 146, so both are demonstrably ordinary column names. `contains` and `call` are not evidence of anything: `contains` occurs 1429 times and 1428 of those are the OPERATOR, with zero value-position reads, so the corpus simply holds no column of that name. They are left out of the check because there is nothing to put them in on, which is a weaker claim than having measured them safe.

The evidence is also uneven within the reserved set. `target` is attested by 31 backticked reads across 12 vendors, `fields` by 13, `in` by 10 across 10 distinct rules, `transaction` by 6; `table` and `filter` by 2 each; `tag` by 2; `view` appears in the corpus in no form at all, and `config` appears in no form as a COLUMN. The three thinnest are exactly the three that live-tenant bisection confirmed, which is why the bisection was necessary. Corpus silence is not evidence of safety.

`lint_rule.py` raises ERR-034 on the unquoted read. Renaming the column at source is still preferable where you control what writes it, because the backtick must be repeated at every read and a missed one fails the same silent way.

## Category versus subcategory routing

Both `xdm.alert.category` and `xdm.alert.subcategory` are valid sinks for vendor classification text, but they sit at different levels of the XDM hierarchy and the choice between them is not interchangeable:

- `xdm.alert.category` is an enum-typed field. It MUST be assigned a value from the `XDM_CONST.THREAT_CATEGORY_*` closed list (see [xdm-const.md](xdm-const.md)). Use it when the vendor's classification text maps deterministically to one of the listed constants -- "Phishing", "Brute Force", "DoS", "Botnet", "Backdoor", "Cryptominer", "Data Theft", "Code Execution", "Hacktool", "Post-Exploitation", "Protocol Anomaly".
- `xdm.alert.subcategory` is a free-text String. It accepts the vendor's raw classification verbatim. Use it as the fallback when the vendor text does not match any THREAT_CATEGORY constant, and ALSO use it alongside `xdm.alert.category` to preserve the precise vendor wording when the category is a rough match.

The mandatory ordering when a vendor ships a `categories[]` array or a single classification string:

1. Try `xdm.alert.category` first via an `arrayindex(arrayfilter(arraymap(... XDM_CONST.THREAT_CATEGORY_*)))` chain (see the "Anchor pattern -- risk-detection block" below for the canonical shape).
2. ALSO populate `xdm.alert.subcategory` with the raw joined text (`arraystring(categories, ", ")` for arrays, or the bare string for scalars). This preserves the vendor wording even when the category match succeeded.
3. If step 1 produces no match for ANY array element, leave `xdm.alert.category` unassigned. Do NOT invent a constant; do NOT force the closest-looking match. The subcategory field carries the information.

Anti-pattern: `xdm.alert.subcategory = arraystring(categories, ", ")` as the sole outlet for the vendor categories. This bypasses the enum-typed `xdm.alert.category` entirely and downstream queries that filter on category will miss the rule. Always attempt the category mapping first.
