<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Virtualization-story mapping (PROVISIONAL DRAFT)

Status: provisional. This reference is a first draft derived from one
authoritative example -- the VMware ESXi content-pack modelling rule
published by Palo Alto Networks -- plus the `xdm.*.virtualization.*`
fields already present in [xdm-schema.md](xdm-schema.md). It has NOT
been confirmed against a live tenant, and the field set is expected to
change. Items marked TO CONFIRM are open questions, not settled
guidance. Do not treat this file as canon the way
[network-mapping.md](network-mapping.md) and
[authentication-mapping.md](authentication-mapping.md) are treated: the
mandatory-set advisory and the profiler auto-detection are deliberately
NOT wired up yet, because encoding a guessed field set into the linter
would have to be unpicked later.

## What this story is

VIRTUALIZATION is a DOMAIN tag, not an activity tag. The closed
`EVENT_TAG` set splits into two kinds: `AUTHENTICATION` and `NETWORK`
describe what happened, while `CLOUD`, `SAAS`, `ONPREM` and `VPN`
describe where it happened. VIRTUALIZATION belongs with the second
group -- it marks the platform the event came from, not the action the
record describes.

That has a direct consequence for how it is applied. In the reference
rule the tag is stamped on EVERY record from a shared field-mapping
block, while `xdm.event.type` carries the per-record semantics. The
activity mapping is then delegated to the ordinary families: a command
execution on a hypervisor is a process event that happens to be tagged
VIRTUALIZATION, and a login to a hypervisor is an authentication event
that happens to be tagged VIRTUALIZATION.

So this story COMPOSES with the others rather than replacing them:

- command / process activity -> [process-mapping.md](process-mapping.md)
- login / session activity -> [authentication-mapping.md](authentication-mapping.md)
- connection / transport detail -> [network-mapping.md](network-mapping.md)
- platform-specific objects (the VM, datastore, datacenter, task) ->
  the `xdm.*.virtualization.*` family documented below

## When this applies

TO CONFIRM: these signals are proposed, not yet implemented in
`scripts/profile_log.py`. They are written here first so the detection
can be built from a reviewed list rather than invented in code.

The story applies to a feed from a platform that runs or administers
workloads, and to command activity on managed infrastructure:

- Hypervisor platforms: VMware ESXi and vCenter, Microsoft Hyper-V,
  Proxmox VE, Nutanix AHV, Citrix XenServer, KVM / libvirt.
- Container platforms: Docker, Kubernetes, OpenShift (the node / control
  plane audit surface, not the application inside the container).
- Network infrastructure command activity: TACACS+ / RADIUS / Cisco ISE
  and network-device command accounting, where an operator issues
  commands against managed infrastructure and the command is cleanly
  extractable. These records are ALREADY mapped by the process family
  (see the AAA section of [process-mapping.md](process-mapping.md)); the
  addition here is that they also take the VIRTUALIZATION tag.

Proposed name signals (field / leaf paths): `vm_name`, `vm_id`, `vmid`,
`guest_os`, `datacenter`, `data_center`, `datastore`, `data_store`,
`hypervisor`, `esxi`, `vcenter`, `hostd`, `vpxa`, `vmkernel`, `task_id`,
`container_id`, `image_id`, `pod_name`, `namespace`, `cluster`.

Proposed value signals: hypervisor process names in a syslog tag
(`hostd`, `vpxa`, `vmkernel`, `vmx`, `libvirtd`, `dockerd`, `kubelet`),
VM lifecycle phrasing (`powered on`, `powered off`, `Created virtual
machine`, `Guest OS reboot`, `Registered`, `Removed`), bracketed
datastore paths (`[datastore1] vm/vm.vmx`), and task completion phrasing
(`Task Completed`).

Suppression: an application log that merely RUNS inside a VM or
container is not a virtualization event. The signal must come from the
platform's own management surface, not from the workload.

## The tag

```
xdm.event.tags = arraycreate("VIRTUALIZATION")
```

TO CONFIRM -- this is the single most important open question in this
file. The reference rule writes a bare quoted string, but
[xdm-schema.md](xdm-schema.md) types `xdm.event.tags` as the EVENT_TAG
constant group (Array), and the six documented members in
[xdm-const.md](xdm-const.md) do not include a virtualization member.
Two readings are possible:

1. The enum has a member our schema snapshot does not record, and the
   correct form is `XDM_CONST.EVENT_TAG_VIRTUALIZATION`.
2. The field tolerates a free string for tags outside the enum, and the
   bare string is correct.

Until a tenant settles it, follow the reference rule and emit the bare
string, because that is the form the published pack ships. Note that
lint WARN-045 does not currently fire on a bare-string tag (it only
scans `EVENT_TAG_*` tokens), so neither form is validated today.

A record on a virtualization feed can carry additional tags. A
hypervisor login takes AUTHENTICATION as well, and the tags are merged
into ONE `arraycreate(...)` per record, exactly as a dual
authentication-plus-network event does (see
[network-mapping.md](network-mapping.md) dual events).

## Provisional field set

TO CONFIRM -- proposed, not enforced. No WARN advisory is wired for this
story yet. The grouping below reflects what the reference rule maps.

Always, on every record of the feed:

| XDM target | Source |
| --- | --- |
| `xdm.event.tags` | includes VIRTUALIZATION (see above) |
| `xdm.event.type` | the per-record classification label |
| `xdm.event.operation` | the `OPERATION_TYPE` verb for the record |
| `xdm.event.operation_sub_type` | the precise semantic label (see below) |
| `xdm.event.description` | the platform message text |
| `xdm.observer.vendor` / `xdm.observer.product` | the platform identity |

The acting side, when the record names an operator or a process:

| XDM target | Source |
| --- | --- |
| `xdm.source.user.username` | the operator or service account |
| `xdm.source.host.hostname` | the host that emitted the record |
| `xdm.source.process.name` / `.pid` | the platform daemon that acted |

The platform objects acted upon, when present -- this is the part unique
to the story:

| XDM target | Source |
| --- | --- |
| `xdm.target.virtualization.vm.hostname` | the virtual machine name |
| `xdm.target.virtualization.data_center.name` | the datacenter |
| `xdm.target.virtualization.data_store.name` | the datastore |
| `xdm.target.virtualization.data_store.uuid` | the datastore UUID |
| `xdm.target.virtualization.task.id` | the platform task identifier |
| `xdm.target.virtualization.task.name` | the platform task name |
| `xdm.target.virtualization.script_name` | the script that ran |

## The `xdm.*.virtualization.*` family

The family already exists in [xdm-schema.md](xdm-schema.md). Two
structural points matter:

- The source and target sides are NOT symmetric. `task.id`, `task.name`
  and `data_store.uuid` exist only on the target side. Map platform
  objects to `xdm.target.virtualization.*`; the reference rule never
  uses the source side.
- `xdm.source.virtualization.vm` and `xdm.target.virtualization.vm` are
  typed Number and are parent nodes, not the VM name. Never assign them
  directly -- map the leaf `virtualization.vm.hostname` instead. This is
  the same trap as `xdm.*.process.executable` (see
  [process-mapping.md](process-mapping.md)).

## Operation and operation_sub_type: the two-layer pattern

The reference rule uses a two-layer classification that this skill has
not previously documented, and it is worth adopting generally:

- `xdm.event.operation` takes the coarse verb from the closed
  `OPERATION_TYPE` enum -- `CREATE`, `UPDATE`, `DELETE`, `EXECUTION`,
  `CONFIG_CHANGE`, `STATUS_CHANGE`, `AUTHENTICATION`, `AUTH_LOGIN`,
  `PROCESS_START`, `FILE_WRITE`, `FILE_REMOVE`, `REJECT`.
- `xdm.event.operation_sub_type` is a free String and takes the precise
  semantic label the enum cannot express: `User interactive`,
  `session opened`, `login success`, `login failed`, `VM Created`,
  `firewall config change`, `firewall status change`, `password change`,
  `file upload`, `file delete`, `crond process start`,
  `System process start`, `Script commands`, `ESXi Task`,
  `remote socket connection`, `keyboard interactive session`,
  `interactive session failed`.

The pairing keeps the closed enum honest while preserving the vendor's
own meaning in a queryable field. Take the sub-type value from the
source's own vocabulary; do not invent a classification the platform
does not state (WARN-049).

## Worked shapes

Drawn from the reference rule. TO CONFIRM against a tenant.

Command execution on a hypervisor shell. The platform daemon is the
source process, the command run is the target process, and the story
tag rides along:

```
| alter
    xdm.source.host.hostname = tmp_hostname,
    xdm.source.process.name = tmp_source_process,
    xdm.source.process.pid = to_integer(to_number(tmp_source_pid)),
    xdm.source.user.username = tmp_user_name,
    xdm.target.process.name = tmp_target_process_name,
    xdm.target.process.executable.path = tmp_target_process_path,
    xdm.target.process.command_line = tmp_command_line,
    xdm.event.operation = XDM_CONST.OPERATION_TYPE_EXECUTION,
    xdm.event.operation_sub_type = "User interactive",
    xdm.event.tags = arraycreate("VIRTUALIZATION")
```

A VM lifecycle operation, where the platform objects are the target:

```
| alter
    xdm.target.virtualization.vm.hostname = tmp_vm_name,
    xdm.target.virtualization.data_center.name = tmp_data_center_name,
    xdm.event.operation = XDM_CONST.OPERATION_TYPE_CREATE,
    xdm.event.operation_sub_type = "VM Created",
    xdm.event.tags = arraycreate("VIRTUALIZATION")
```

A platform task record:

```
| alter
    xdm.target.virtualization.task.name = tmp_task_name,
    xdm.target.virtualization.task.id = tmp_task_id,
    xdm.event.operation_sub_type = "ESXi Task",
    xdm.event.tags = arraycreate("VIRTUALIZATION")
```

## Open questions to settle

1. Tag form: `XDM_CONST.EVENT_TAG_VIRTUALIZATION` or the bare string
   `"VIRTUALIZATION"`. One probe line in a tenant settles it.
2. Whether any field in the proposed set is genuinely mandatory for the
   story to form, as the fixed sets in
   [network-mapping.md](network-mapping.md) and
   [authentication-mapping.md](authentication-mapping.md) are, or
   whether the story is recommended-only like
   [process-mapping.md](process-mapping.md).
3. Whether the source-side `xdm.source.virtualization.*` fields are ever
   correct, or whether the family is target-only in practice.
4. Whether container platforms map onto the same `virtualization.*`
   family or need different targets for pod / namespace / image.
5. Whether the tag is appropriate on network-infrastructure command
   accounting (TACACS+ and similar), or whether that stretches the
   domain too far.

Once settled, the story is wired up the same way as the other two:
detection in `scripts/profile_log.py`, a mirrored mandatory list and an
advisory check in `scripts/lint_rule.py`, drift-guard tests pinning the
two lists to the table above, and a step-6 pointer in `SKILL.md`.
