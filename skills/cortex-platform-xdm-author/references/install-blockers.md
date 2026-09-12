<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Install-blocking constructs

Five constructs cause the platform to reject a pack install with an opaque
101704 that names no field and no line. All were isolated by live-tenant
bisection, and all are measured at zero false positives against a corpus of
shipped rules. They are errors, not advisories: a rule carrying one lints
clean everywhere else and still cannot be installed.

The linter is the single source of truth for the code list; run
`python3 scripts/lint_rule.py --list-codes`. This file explains WHY each
construct is fatal, which the code list cannot.

## ERR-030 -- positional body capture on a syslog source

A payload field anchored on `^` or on a fixed offset rather than on its own
token. It reads correctly on the arrival form the sample happened to show and
silently mis-reads the other, because a relay prepends its own header and
shifts every offset. Blocked as an error rather than an advisory, because
static lint cannot prove the negative and the failure is invisible in the
sample. See [syslog-envelope.md](syslog-envelope.md).

## ERR-031 -- an XDM_CONST member that does not exist

A SECOND SHAPE, and it is not a banding problem. The VIRTUALIZATION story
marker is NOT a constant: there is no `EVENT_TAG_VIRTUALIZATION` member, and a
MODEL rule naming one fails the install the same opaque way. It is not a finer
member of a coarser enumeration, so the usual remedy -- band into the closed
list -- is wrong here and would file the record under a story it does not
belong to. The marker is a bare quoted string,
`xdm.event.tags = arraycreate("VIRTUALIZATION")`, which is what the upstream
VMware ESXi and vCenter rules write. ERR-031 carries this fix per member rather
than giving the generic advice. See
[house-conventions.md](house-conventions.md) and
[virtualization-mapping.md](virtualization-mapping.md).

The closed lists LOOK like well-known external enumerations and are not. The
member that seems obvious by analogy with the outside world is routinely
absent, and assigning it fails the install.

Syslog severity is the clearest case. Syslog defines eight levels; the
`LOG_LEVEL` closed list has only five members:

```
XDM_CONST.LOG_LEVEL_CRITICAL
XDM_CONST.LOG_LEVEL_ERROR
XDM_CONST.LOG_LEVEL_WARNING
XDM_CONST.LOG_LEVEL_NOTICE
XDM_CONST.LOG_LEVEL_INFORMATIONAL
```

There is no EMERGENCY, no ALERT and no DEBUG. Floor syslog 0 and 1 to
CRITICAL, and map 7 to INFORMATIONAL. The same trap recurs in the operation
verbs: there is no logout verb at all, so a logout record takes an honest
`xdm.event.type` and no invented operation.

Check every constant against [xdm-const.md](xdm-const.md) before assigning it.
If no member matches, omit the field.

## ERR-032 -- a regextract with more than one capturing group

`regextract` returns an array over a single group. A second group does not
give a second output; it changes what the first one means. It is also dead
weight, because `arrayindex()` reads one. Use one capturing group per
`regextract`, and use non-capturing groups `(?:...)` for grouping.

## ERR-033 -- a lookahead or lookbehind

The engine does not support lookaround and does not say so. The query HANGS
rather than failing, so the caller sees a timeout that reads like a crash in
whatever ran it, with nothing pointing at the regex. Rewrite the pattern
without lookaround; the recipes in
[extraction-recipes.md](extraction-recipes.md) are all lookaround-free.

## ERR-034 -- an unquoted read of a reserved raw column

The READ is the fault, not the assignment. A raw column whose NAME is a
query-language construct must be escaped with backticks when it is read:

```
alter tmp_target = `target`
```

The `tmp_` convention is no defence here, because it protects the name a rule
CREATES rather than the name it READS. Renaming the column at source is better
where you control what writes it. The backtick escape is what 328 shipped
upstream rules use, and they never omit it, so the check accepts it.

### Which names qualify, and why the guess is a bad guide

Membership was derived from a corpus, not from how SQL-ish a word looks:

- `timestamp` and `dst` are read bare in shipped rules and are demonstrably
  NOT reserved.
- `contains` and `call` turn out not to be column reads at all -- 1428 of
  `contains`'s 1429 occurrences are the operator -- so they are excluded for
  want of evidence rather than because they were measured safe. That is a
  distinction an earlier statement of this got wrong.
- `in` IS reserved as of 1.9.1. It was held out on the belief that flagging it
  would fire on every `action in (...)`, which measurement refutes: the read
  patterns only match in VALUE position and the operator follows an
  identifier. 570 operator uses in the corpus, zero matched, against 9
  backticked reads.
- `out` is NOT reserved and must not be added on symmetry with `in`. It is
  read bare 8 times in shipped rules, which makes it an ordinary column name
  like `timestamp` and `dst`.
- `config` IS reserved as of 2.1.3, isolated by live-tenant bisection over
  five uploads on a GitHub Enterprise Cloud audit source.

`config` is the one to argue from when a name looks safe because the corpus is
quiet. It is read neither bare nor backticked anywhere in the corpus, yet it
is fatal, and this linter's own `_STAGE_KEYWORDS` table had listed it as a
language construct all along, beside three names already reserved. The
evidence was in the bundle, unread, not merely missing.

Its bisect also needs THREE probes rather than two. Assigning the same value to
the XDM field from a DIFFERENT column is what proves the FIELD innocent, and
without that middle probe the wrong conclusion is that `xdm.target.url` is
gated rather than the column read.

### The set is mirrored

`_ERR034_RESERVED` in `scripts/lint_rule.py` is copied by hand into
`RESERVED_COLUMNS` in the pack-building harness's release gate, which gates the same fault at upload time. A change to the membership must be
announced to that bundle in the same change -- see the standing commitment in
SKILL.md under "Called as an instrument".
