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
| `exclude_commands` | string[]      | no       | Commands to drop from the resolved set. **Base commands can never be excluded** (see "Non-removable base"). |
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

## Non-removable base

Every platform's `base` group (identity commands, `show running-config`, and the
per-platform sentinel) is **always collected** and **cannot be removed** by a
profile choice or an `exclude_commands` entry. An exclude that names a base
command is silently ignored (the base command still runs). This guarantees every
bundle carries the minimum Reperio needs to key a device.

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

- **Version-guarded command variants (task 0c):** a group's command is a plain
  string today. A future catalog may replace a string with an object
  (`{ "command": "...", "min_version": "...", "max_version": "..." }`) and the
  resolver will select by device firmware. Consumers must treat a group member as
  "either a string or an object with a `command` field".
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
