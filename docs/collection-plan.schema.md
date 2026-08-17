# Collection Plan input schema (v1)

The **collection plan** is the structured JSON input the collector
(`ssh-cmd-runner.ps1`) consumes to decide *which devices to reach* and *what to
collect from each*. It is a strict **superset** of the legacy CSV device list
(`IP,Category,OS,ExcludeCommands,AddCommands`).

**The collector OWNS this schema.** Reperio validates against it (Phase 1
follow-up C1) but does not define it. Any change here bumps `schema_version` and
must be flagged for the Reperio-side validator.

- **Current version:** `schema_version = 1`
- **Parsed by:** `ConvertFrom-CollectionPlanJson` (JSON) and
  `ConvertFrom-CollectionCsv` (transitional CSV) in `lib/CollectorCore.ps1`.
- **Round-trip contract:** `plan_id` is a passthrough. The collector echoes it in
  `collection-summary.json` (wired in Slice 2 / task 0d) so an ingest can be tied
  back to the plan that produced it.

---

## Top-level object

| Field            | Type    | Required | Notes |
|------------------|---------|----------|-------|
| `schema_version` | integer | no       | Defaults to `1`. Only `1` is accepted today; any other value is a hard error. |
| `plan_id`        | string  | no       | Opaque plan identity. Echoed to every device and (Slice 2) to the summary. |
| `defaults`       | object  | no       | Fallbacks applied to any device that omits the same field. See below. |
| `devices`        | array   | **yes**  | One entry per device. Must be non-empty. |

### `defaults` object (optional)

Provides plan-wide fallbacks. A device-level field always wins over the default.

| Field              | Type   | Notes |
|--------------------|--------|-------|
| `profile`          | string | Fallback profile when a device gives neither `profile` nor `groups`. If `defaults.profile` is also absent, the built-in default is `full`. |
| `credential_group` | string | Fallback credential group. |
| `ssh_options`      | object | Fallback SSH options (see below). |

---

## Device object

| Field              | Type          | Required | Notes |
|--------------------|---------------|----------|-------|
| `connect_ip`       | string        | **yes**  | Address (or resolvable name) the collector SSHes to. Empty/missing is a hard error. |
| `platform`         | string        | no       | One of the collector's known OS types (`cisco-switch-iosxe`, `cisco-router-iosxe`, `cisco-router-iosxr`, `cisco-switch-nxos`, `cisco-wlc-aireos`, `cisco-wlc-iosxe`). Optional here so a plan can defer platform detection, but required before command resolution. |
| `profile`          | string        | no*      | Named command **profile** (`full`, `l2-switch`, `l3-switch`, `router`, `bgp-heavy`, `wlc`). Resolves to a command set via the group catalog. |
| `groups`           | string[]      | no*      | Explicit feature-group list. **When present and non-empty, it takes precedence over `profile`.** |
| `exclude_commands` | string[]      | no       | Commands to drop from the resolved set. **Protected (`base` / `collector-only`) commands can never be excluded** (see "Protected (non-removable) groups"). |
| `add_commands`     | string[]      | no       | Extra commands appended after the resolved set (deduped). |
| `ssh_options`      | object        | no       | Per-device SSH tuning (see below). |
| `priority`         | integer       | no       | Optional ordering hint (lower = earlier). Non-integer is a hard error. |
| `credential_group` | string        | no       | Named credential set to authenticate with (resolved against the credential store; never inline secrets). |

\* If a device supplies **neither** `profile` **nor** a non-empty `groups`, it
falls back to `defaults.profile`, else the built-in default `full`.

### `ssh_options` object

Normalized to these four fields (any omitted field is `null` = "collector
default / auto"):

| Field                 | Type    | Maps to |
|-----------------------|---------|---------|
| `kex_algorithms`      | string  | `ssh -o KexAlgorithms=<value>` |
| `ciphers`             | string  | `ssh -o Ciphers=<value>` |
| `host_key_algorithms` | string  | `ssh -o HostKeyAlgorithms=<value>` |
| `pty`                 | boolean | Force (`true`) / suppress (`false`) PTY allocation; `null` = auto-detect. |

#### Merge semantics: `defaults.ssh_options` + device `ssh_options` (field-level)

A device's `ssh_options` is merged **field-by-field** over
`defaults.ssh_options`, **NOT** replaced wholesale. For each of the four fields
above:

- if the **device** supplies the field (a non-`null` value), the device value
  wins;
- otherwise the field is inherited from `defaults.ssh_options`;
- if neither supplies it, the field is `null` (collector default / auto).

This means a device that sets **only** `pty` still inherits the plan-wide
`kex_algorithms` / `ciphers` / `host_key_algorithms` defaults. (A wholesale
replace would silently drop those global crypto defaults, which breaks
connections to legacy gear that depends on them.)

`pty: false` is a **real value** (force-*suppress* PTY allocation), not
"absent" — it is preserved and is **not** overwritten by a `defaults.pty`. Only
an omitted / `null` `pty` inherits the default.

Example — with `defaults.ssh_options = { "kex_algorithms": "+dh1",
"ciphers": "+cbc" }` and device `ssh_options = { "pty": true }`, the device's
effective options are `{ kex_algorithms: "+dh1", ciphers: "+cbc",
host_key_algorithms: null, pty: true }`.

---

## Protected (non-removable) groups: `base` and `collector-only`

Two group names are **protected**: they are **always collected** and **cannot be
removed** by a profile choice or an `exclude_commands` entry. An exclude that
names one of their commands is silently ignored (the command still runs). They
are emitted first, in this order — `base`, then `collector-only` — ahead of the
selected feature groups. They are protected for **different reasons**:

| Group            | Reason it is protected | Operator-facing? |
|------------------|------------------------|------------------|
| `base`           | Identity commands, `show running-config`, and the per-platform sentinel — the minimum **Reperio** needs to key/process a device. | Yes — documented in the Help card and parsed by `COMMAND_MAP`. |
| `collector-only` | Commands the **collector itself** needs to operate. **Collector-internal** — never surfaced to operators as tunable/collectable data. | No — deliberately absent from BOTH the Help card AND `COMMAND_MAP`. |

`collector-only` is **RESERVED — currently empty**: no platform catalog defines a
member for it yet. The slot and its semantics ship now so that a future
collector-operational command has a home a profile choice or an `exclude` cannot
drop, and so it is unambiguously distinguished from `collect-only-ops` (below).

> **`collector-only` vs `collect-only-ops` — do not confuse them.**
> `collect-only-ops` is a normal, profile-selectable feature group holding
> **operator-facing informative** data (e.g. `show logging`, `show license all`):
> it reads as "safe to prune / operator-tunable" and pruning one only loses
> optional context. `collector-only` is the opposite: **collector-internal**,
> non-removable, and never advertised to operators — pruning one (if it could be
> pruned) would break collection itself.

### Sync-triangle placement (third divergence class)

The command-set **sync triangle** relates three collect/parse surfaces:

- `commands/*.txt` catalog (this repo) — what the collector **runs**;
- `platformCommands` in Reperio's `helpContent.ts` — what operators are **told**
  to collect;
- `COMMAND_MAP` in Reperio's `command_map.py` — what Reperio **parses**.

The triangle is **not** a flat 3-way mirror. Three legitimate divergence classes
exist; `collector-only` is the third:

1. **collect-only-forward** — in the collector (and the Help card's collect-only
   group) but not yet in `COMMAND_MAP` (no parser wired yet).
2. **parse-only-backward** — in `COMMAND_MAP` but intentionally **not** run by the
   collector (legacy/pre-split or wrong-syntax-for-this-platform parse-dispatch
   entries, e.g. the IOS-vs-NX-OS `show ip route vrf all` class).
3. **collector-only** — run by the collector (present in the group catalog) but
   intentionally absent from **BOTH** `platformCommands`/Help **AND**
   `COMMAND_MAP`, because it is collector-internal. Any member added to a
   `collector-only` group must **not** be mirrored into either Reperio surface.

---

## CSV back-compat (transitional)

The legacy CSV device list still parses via `ConvertFrom-CollectionCsv`:

- Columns: `IP` (→ `connect_ip`), `OS` (→ `platform`), optional `Category`
  (preserved as `category`), optional `ExcludeCommands` / `AddCommands`
  (comma-separated within the cell → `exclude_commands` / `add_commands`).
- Every CSV row maps to the **default `full` profile**.
- CSV is transitional and will be deprecated once JSON is stable; it is retained,
  not extended.

---

## Forward-compatibility (Slice 2+)

This schema is deliberately shaped so later slices attach without a breaking
change:

- **Version-guarded command variants (task 0c — IMPLEMENTED):** a group member is
  a plain string (unversioned, always collected) OR a version-guarded object.
  `Resolve-CommandVariant` (in `lib/CollectorCore.ps1`) selects the literal for a
  device's detected firmware version (`Get-DeviceFirmwareVersion` +
  `Compare-FirmwareVersion`). Two object shapes are accepted:
  - single-variant: `{ "command": "...", "min_version": "...", "max_version": "..." }`
  - multi-variant (a logical command whose syntax changed across a firmware
    boundary): `{ "variants": [ { "command", "min_version", "max_version" }, ... ],
    "on_unknown": "newest" | "skip" }`.
  When the device version is unknown/unparseable the resolver defaults to the
  **newest** variant (and logs a note); `on_unknown: "skip"` hard-skips instead,
  for commands where guessing wrong is harmful. Consumers must treat a group member
  as "either a string or an object with a `command`/`variants` field". Actual
  per-command variants are DATA added to the catalog as discovered; the mechanism
  ships in Slice 2 with a synthetic archetype (IOS-XE 17.2 syntax change) covered
  by the tests.
- **Richer summary round-trip (task 0d):** `plan_id` (and, later, per-device
  `priority` / `credential_group` / `ssh_options`) already ride on the plan so the
  v2 `collection-summary.json` can echo them.

---

## Example

```json
{
  "schema_version": 1,
  "plan_id": "acme-refresh-2026-08-17-001",
  "defaults": {
    "credential_group": "core-network",
    "profile": "full"
  },
  "devices": [
    {
      "connect_ip": "10.1.1.1",
      "platform": "cisco-switch-iosxe",
      "profile": "l2-switch",
      "priority": 10
    },
    {
      "connect_ip": "10.1.1.2",
      "platform": "cisco-router-iosxe",
      "groups": ["neighbors", "routing-bgp", "arp"],
      "exclude_commands": ["show running-config"],
      "add_commands": ["show clock"],
      "ssh_options": {
        "kex_algorithms": "+diffie-hellman-group1-sha1",
        "host_key_algorithms": "+ssh-rsa",
        "pty": true
      },
      "credential_group": "legacy-edge"
    }
  ]
}
```

In the second device, `exclude_commands: ["show running-config"]` is ignored
because `show running-config` is a base command.
