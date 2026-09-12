<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Virtualization-story mapping

The VIRTUALIZATION story is an analytic that baselines an (ENTITY, ACTION) pair and
alerts on deviation from normal: this operator has never run this command on this
device, and today they did.

It was designed for hypervisor platforms, and the field names still carry that
history -- `vm.hostname`, `data_center.name`. The analytic behind them does not care.
Any record of the form "who did what to which thing" fits it, and the network-device
estate is where it earns the most, because a router does not otherwise tell you that
`wr erase` on `core-router-01` was the first time.

This is a RECOMMENDED tier, exactly like the identity mirror in
[authentication-mapping.md](authentication-mapping.md). Nothing here joins a mandatory
set, no advisory fires on its absence, and a rule that maps none of it is complete.
The law of the tier is the same one: APPEND, NEVER REPLACE. Every assignment below sits
BESIDE the field it mirrors and never instead of it.

## The tag

```
xdm.event.tags = arraycreate("VIRTUALIZATION")
```

A BARE QUOTED STRING, and this is the one place in the bundle where that is right.

There is no `XDM_CONST.EVENT_TAG_VIRTUALIZATION`. The platform REJECTS the symbol: a
MODEL rule that names it fails the pack install with an opaque 101704 naming nothing,
and the literal installs. That was bisected on a live tenant in both directions, with
the story's field assignments held fixed, so the failure is the symbol and not the
fields. Every other story marker this bundle prescribes IS a constant -- AUTHENTICATION,
NETWORK, CLOUD, SAAS, ONPREM, VPN -- so the string form here looks like a mistake, and
the next author to read this page will want to correct it. Do not: the correction costs
a failed install diagnosed through the 101704 procedure. The divergence is registered in
[house-conventions.md](house-conventions.md) with the measurement and with the one
result that would retire it.

THE VENDOR WRITES IT THIS WAY, which is where the spelling comes from rather than
from house preference. `VMwareESXi_2_9.xif` and `VMwareVcenter_2_9.xif` -- the
canonical upstream sources for this story, the vCenter block headed "Virtualization
Story general field mapping" -- both assign `arraycreate("VIRTUALIZATION")`. The
constant appears in no upstream modelling rule.

Three consequences worth carrying:

- The FIELD is not a closed enum, only the `EVENT_TAG` constant GROUP is. A bare
  string here is ordinary use of a string array, not an exception carved out for one
  story. See [xdm-const.md](xdm-const.md).
- No check can see this tag. ERR-031 and WARN-045 both match `EVENT_TAG_*`
  TOKENS, and a quoted string carries none, so nothing refuses a misspelling, a
  lower-case `"virtualization"` or a plural. The spelling above is the whole
  specification -- upper case, singular, no underscore -- and the VMware rules are
  the source to check it against.
- The CONSTANT is refused twice, and ERR-031 does it at ERROR severity so the lint
  exits 1. That is correct: the rule would fail the pack install. The fix both checks
  name is the string above, never a wider enum. Both are MODEL-only, so the symbol in
  an `[INGEST:...]` parsing rule is refused by nothing.

Merge it into the ONE `arraycreate(...)` the record already emits rather than adding a
second `tags` assignment -- a hypervisor login takes AUTHENTICATION as well, and a
TACACS+ command on a router takes only this one. Mixing forms in one call is expected
and correct: `arraycreate(XDM_CONST.EVENT_TAG_AUTHENTICATION, "VIRTUALIZATION")`. See
[record-classification.md](record-classification.md).

## The field set

All types are as `references/xdm-schema.md` declares them. The MIRRORS column names the field a
rule has usually already derived, because this tier costs no new extraction: derive into a temp in
stage N, assign both paths from that temp in the drain stage N+1.

### The story core

These three are what the analytic reads. Without the first two there is no (entity, action) pair
and the story should not be claimed at all.

| XDM target | Type | Mirrors | Notes |
| --- | --- | --- | --- |
| `xdm.target.virtualization.vm.hostname` | String | `xdm.target.resource.name`, else `xdm.target.host.hostname` | THE ENTITY acted upon. Frequently known only by ADDRESS on network-device AAA, which is acceptable: the field names the entity and an address is what the source knows it by. Never synthesise a name. |
| `xdm.target.virtualization.task.name` | String | `xdm.target.process.command_line`, else `xdm.event.operation_sub_type`, else `xdm.event.original_event_type` | THE ACTION performed. A name, not the full invocation; the detail belongs to the process family below. |
| `xdm.target.virtualization.data_center.name` | String | `xdm.target.cloud.project`, `xdm.target.cloud.project_id`, else `xdm.target.resource.parent_id` | THE ADMINISTRATIVE CONTAINER. LEAVE UNSET where the source has none rather than reaching for the nearest string. Not a location, and never the observer. |

### The supporting set

Already mandatory or conventional elsewhere. Listed so a rule claiming this story can check them
in one place, not because the story introduces them.

| XDM target | Type | Notes |
| --- | --- | --- |
| `xdm.event.tags` | array (enum) | Must include the bare string `"VIRTUALIZATION"` -- NOT a constant, see "The tag" above -- merged into the ONE `arraycreate(...)` the record already emits. |
| `xdm.source.user.username` | String | The operator who performed the action. The story baselines a person against an (entity, action) pair, so an unattributed record is a weak member of it. |
| `xdm.source.host.hostname` | String | Where the action came FROM, when the source names it. |
| `xdm.observer.name` | String | The system that witnessed and logged it. NOT the container: that is the mistake `data_center.name` exists to avoid. |
| `xdm.event.outcome` | string (enum) | Map a real outcome where one exists. Many command and audit records carry none; see "Outcome" below before asserting one. |
| `xdm.event.original_event_type` | String | The raw vendor event name exactly as logged. |
| `xdm.event.operation` | string (enum) | The coarse verb from the closed enum. |
| `xdm.event.operation_sub_type` | String | The vendor's own precise label, which the closed enum cannot express. Take it from the source's vocabulary; do not invent a classification the platform does not state (WARN-049). |

### The action's detail

The process family, mapped as `references/process-mapping.md` describes. Nothing here is specific
to this story except why it wants them.

| XDM target | Type | Notes |
| --- | --- | --- |
| `xdm.target.process.command_line` | String | The full invocation. `task.name` mirrors this on a command record, so the two carry the same value by design. |
| `xdm.target.process.name` | String | The executable or command verb. |
| `xdm.target.process.pid` | Number | The process id where the source reports one. |
| `xdm.target.process.identifier` | String | The vendor's own stable process identifier. |
| `xdm.target.process.causality_id` | String | The causality-chain key: the difference between "this command ran" and "this command ran from that session". Map it where the source supplies such a key and NEVER synthesise one, because an invented causality id joins chains that are not related. |

### Optional, where the source is a real virtualization platform

| XDM target | Type | Notes |
| --- | --- | --- |
| `xdm.target.virtualization.task.id` | String | The platform's task identifier, where distinct from its name. |
| `xdm.target.virtualization.data_store.name` | String | The datastore the entity lives on. Target side only. |

Two paths are NEVER assigned: `xdm.source.virtualization.vm` and `xdm.target.virtualization.vm`
are typed Number and are PARENT NODES, not the VM name. Map the leaf `.vm.hostname`.

## The three slots

Each slot is MIRRORED from a value the rule already derives. Nothing here needs a new
extraction, which is the whole reason this tier is cheap to adopt.

| Slot | Mirrors | Meaning |
| --- | --- | --- |
| `xdm.target.virtualization.vm.hostname` | `xdm.target.resource.name`, else `xdm.target.host.hostname` | THE ENTITY the action was performed on |
| `xdm.target.virtualization.task.name` | `xdm.target.process.command_line`, else `xdm.event.operation_sub_type`, else `xdm.event.original_event_type` | THE ACTION performed |
| `xdm.target.virtualization.data_center.name` | `xdm.target.cloud.project`, `xdm.target.cloud.project_id`, else `xdm.target.resource.parent_id` | THE ADMINISTRATIVE CONTAINER the entity lives in |

The container slot is the one to read carefully. It is NOT a physical location and it is
NOT the observer. It is the administrative scope the entity belongs to: a project, an
account, an organisation, a workspace, a tenant, a FortiManager ADOM. A datacentre is
one instance of that idea, not its definition.

WHERE THERE IS NO CONTAINER, LEAVE THE SLOT UNSET. Do not reach for the nearest
available string. The AAA server, the collector host and the syslog envelope host are
all the WITNESS, not the container, and the witness already has a home in
`xdm.observer.name`. A user group, a policy rule and a client CIDR each mean something
else. Filling this slot with any of them asserts a scope the source never stated, which
is what WARN-049 exists to refuse.

## What must be true before claiming the story

A story tag is a promise that the story's fields mean something on that record
([record-classification.md](record-classification.md)). The defining entity of this
story is THE THING ACTED UPON, and without it there is nothing to baseline.

- ENTITY and ACTION are the minimum. A record that cannot supply both must not claim the
  story, however well it fills the rest.
- The CONTAINER is desirable and not defining. A record with a real entity and a real
  action claims the story with `data_center.name` unset.

That order matters, and it rules out cases that look like a fit. A cloud API audit
record naming only a service label and an account id has an action and a container and
NO entity: a service DNS name is not a thing you baseline commands against. It does not
claim the story. Neither does an EDR detection, where the actor is malware rather than
an operator and the record belongs to the alert story.

## The mechanism: mirror in the drain stage

A target cannot read a sibling `xdm.*` field, and cannot read a temp defined in the SAME
`alter` stage. Both are ERR-024 and both BLOCK the install
([parser-idioms.md](parser-idioms.md) idiom (xi)).

So the mirror is not an alias. Derive into a temp in stage N, then assign BOTH paths from
that temp in the drain stage N+1, exactly as
[transformation-patterns.md](transformation-patterns.md) describes for mirroring:

```
| alter                                          // stage N
    tmp_command = coalesce(tmp_cmd_q, tmp_cmd_b),
    tmp_device  = coalesce(tmp_dvc_ip_kv, tmp_dvc_ip_tx)
| alter                                          // stage N+1, the xdm.* drain
    xdm.target.process.command_line       = tmp_command,
    xdm.target.virtualization.task.name   = tmp_command,
    xdm.target.ipv4                       = tmp_device,
    xdm.target.virtualization.vm.hostname = tmp_device
```

Both members of a pair take the SAME temp. A pair assigned from two different
derivations is the defect the identity mirror reports at WARN-057, and the same reading
applies here.

## The process family carries the action's detail

The `task.name` slot is a NAME. What the action actually WAS lives in the process family,
and a virtualization record of a command is better for carrying it:

```
xdm.target.process.name           the executable or command verb
xdm.target.process.command_line   the full invocation, arguments included
xdm.target.process.pid            the process id, where the source reports one
xdm.target.process.identifier     the vendor's own stable process identifier
xdm.target.process.causality_id   the causality-chain key that links this action to its origin
```

[process-mapping.md](process-mapping.md) owns how these are mapped and is not restated
here: it holds the actor-versus-target split, the parent-node trap on
`xdm.target.process.executable`, and the recipes. Read it before assigning any of them.

Two points belong to this story rather than to that one.

`command_line` is the field `task.name` mirrors on a command record, so the two carry the
same value by design. That is the mirror working, not a duplication to remove.

`causality_id` is the key that lets the analytic follow an action back to what caused it,
which is the difference between "this command ran" and "this command ran from that
session". Map it where the source supplies such a key. This bundle documents no
derivation for it and there is none to invent: a synthesised causality id would join
chains that are not related, so leave it unmapped where the source has no equivalent.

## Source side, and when it is right

The family exists on both sides and the two are NOT symmetric: `task.id`, `task.name`
and `data_store.uuid` exist only on the target side. The platform models the action as
target-side, which is the shape to follow.

Map to `xdm.target.virtualization.*` for the thing acted upon. Use the source side only
for the ORIGIN of a MOVE -- a migration, a clone, a storage relocation -- where the
record genuinely names both ends. A single-object operation has no origin and takes the
target side alone.

## Two traps

`xdm.source.virtualization.vm` and `xdm.target.virtualization.vm` are typed Number and
are PARENT NODES, not the VM name. Never assign them. Map the leaf
`virtualization.vm.hostname` instead. This is the same trap as
`xdm.*.process.executable` in [process-mapping.md](process-mapping.md).

The entity is frequently known only by ADDRESS. Network-device AAA identifies the
administered device by IPv4 and carries no device name at all, so `vm.hostname` receives
an address. That is acceptable and is not padding: the field names the entity, and an
address is what the source knows it by. It is not licence to synthesise a name.

## Outcome

The analytic wants an outcome, and many command and audit records do not carry one.
Where a real outcome exists, map it as usual. Where the source states nothing, an
asserted outcome is a claim the record does not make -- so if a rule asserts one to
complete the story, say so in the NOT MAPPED block with the reasoning, exactly as the
entity-field gate in [authentication-mapping.md](authentication-mapping.md) requires
before padding an entity.

## Where this fits across source kinds

Measured against the shipped modelling rules rather than assumed. Entity and action are
close to universal; the container is what separates the cases.

| Source kind | Entity | Action | Container |
| --- | --- | --- | --- |
| Cloud audit (project, account or organisation scoped) | resource name | method or operation | project / account / organisation |
| SaaS administration (workspace or tenant scoped) | resource name | event action | workspace / parent id |
| Network management systems | managed object | activity type | ADOM where the product has one, otherwise none |
| Network-device AAA command accounting | device, often by address | the command | none |
| Endpoint process creation | not supplied | the command | none |
| EDR and threat detections | not applicable | not applicable | not applicable |

The last two rows are the ones to respect. An endpoint process-creation record names the
process and its arguments but does not name a thing the process was performed ON, so it
has no entity and does not claim the story. A detection is the alert story and belongs
there.
