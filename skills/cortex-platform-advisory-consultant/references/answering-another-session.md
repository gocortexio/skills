<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Answering another session's consult: one call, not six

Read this when another session asks this skill a rule-design question, rather than a person
asking about a technology they run.

A rule-design consult from another session -- "here are three shapes I am considering,
what does the corpus say" -- was costing **five to eight round trips**, each one a
hand-written search re-deriving the same three things. The corpus loads in 0.08s, so
none of that was compute; it was all latency. `scripts/advise.py` collapses it:

```sh
python3 scripts/advise.py --patterns pat-log-forwarding-gap,pat-log-restored-to-original-state --have syslog,auth_log
python3 scripts/advise.py --attack T1685.006
python3 scripts/advise.py "a device stops sending logs"   # best-effort, labelled as such
```

One invocation returns, per pattern: **CORROBORATED** (public rule-library counts) and
**OBSERVED** (citing records with verified URLs) as separate claims, full `logic`,
`CAVEAT_VERBATIM`, resolved ATT&CK links, telemetry and `DATA_GAP`.

**Prefer `--patterns` and `--attack`.** Free-text search is kept but demoted to a
labelled guess, because it is not reliable here: this corpus names patterns evocatively
rather than descriptively, so a search for audit-trail destruction returned a
cloud-network-exposure pattern whose `logic` happens to contain "provider audit trail".
Finding the right pattern is the part to do by judgement; assembling and verifying it is
the part that was costing the time.

**The label is the only thing marking it as a guess.** A free-text guess comes back in the
same confident format as an exact match: same blocks, same corroboration counts, same
verbatim caveat, same citable references. So read `MATCH_BASIS:` on every pattern before
reading any finding. Preferring the exact flags is not a substitute, because it is on the
occasions somebody falls back to free text that the line matters.

**URL liveness is cached with a date** in `corpus/reference/url-liveness.json`, re-checked
after 14 days. It pays for itself twice: it removes the per-consult verification cost, and
a URL that was live and is now empty is a deprecated technique -- which is how the whole
T1562 family was caught.
