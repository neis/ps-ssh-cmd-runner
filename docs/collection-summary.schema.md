# Collection Summary output schema (v3)

`collection-summary.json` is the roll-up the collector (`ssh-cmd-runner.ps1`)
writes for every device in a run — including failed / skipped / cancelled devices
that have no per-device JSON. Reperio ingests it.

**The collector OWNS this schema.** Any change bumps `schema_version` and must be
flagged for the Reperio parser (Phase-3 follow-up **C2**: parse the structured
form, with a v1 free-text fallback for older bundles).

- **Current version:** `schema_version = 3`
- **What changed in v3 (Phase 3c 2P-b):** one new `failure_category` member,
  `connect_timeout` (see below). The document **shape is unchanged** from v2 —
  only the classifier's value domain grew. A v2 parser that treats an unknown
  `failure_category` as "unrecognized, keep `reason`" already tolerates v3
  bundles; this bump exists so Reperio can consume `connect_timeout` explicitly.
- **Built by:** `New-CollectionSummaryDocument` (top level) in
  `lib/CollectorCore.ps1`; per-device entries assembled in the collection loop.
- **Merge semantics (unchanged from v1):** the file MERGES across runs — each run
  upserts devices by IP, upgrade-only (a worse result never overwrites a better
  stored one). Re-running a subset updates only those entries.

---

## Top-level object

| Field            | Type    | Notes |
|------------------|---------|-------|
| `schema_version` | integer | `3`. |
| `plan_id`        | string  | **NEW in v2.** Echo of the input collection plan's `plan_id` (round-trip contract), so an ingest ties back to the plan that produced it. `null` on the legacy CSV path. |
| `generated`      | string  | `yyyy-MM-dd HH:mm:ss` write time. |
| `totals`         | object  | `total` / `success` / `warning` / `failed` / `skipped` / `cancelled` counts, recomputed from the merged device map. |
| `devices`        | object  | Map of `connect_ip` → device entry (below). |

## Device entry

| Field               | Type          | Notes |
|---------------------|---------------|-------|
| `category`          | string \| null | Device category (from input). |
| `os`                | string        | Platform / OS type. |
| `hostname`          | string        | Parsed device hostname (or `unknown`). |
| `status`            | string        | `Success` / `Warning` / `Failed` / `Skipped` / `Cancelled`. |
| `failure_category`  | string \| null | **NEW in v2.** Remediation-oriented category (below), or `null` for `Success`/`Warning` and for unclassified failures (keep `reason`). |
| `duration_seconds`  | number        | Whole-session wall-clock. |
| `reason`            | string        | Free-text status detail / error. |
| `run_timestamp`     | string        | Completion time. |
| `json_file`         | string \| null | Per-device JSON leaf filename, if any. |
| `connection`        | object \| null | **NEW in v2.** Captured working connection params — present only on a session that connected (below). `null` for skip/cancel. |
| `commands`          | array         | Per-command entries (below). |
| `excluded_commands` | string[]      | Per-device excludes. |
| `added_commands`    | string[]      | Per-device adds. |

### `failure_category` values (classifier: `Get-FailureCategory`)

Deterministic mapping from `status` + auth flag + `reason`. This set is the
**reference** for Reperio's v1 free-text fallback.

| Value                    | Trigger |
|--------------------------|---------|
| `auth_failed`            | Credential rejection (collector auth detector, or `Permission denied` / `Authentication failed` / `Too many authentication failures`). |
| `unreachable_ping`       | Pre-SSH **ICMP pre-check skipped** the device — SSH was **never attempted** (status `Skipped`, `No ping response`). No liveness signal at all. |
| `connect_timeout`        | **NEW in v3.** SSH **was attempted** but the host did not answer at the **TCP layer** — connect-level unreachability (`No route to host`, `Network is unreachable`, `connect to host … timed out`, `Host is down`). "Reached-for but unreachable" — distinct from `unreachable_ping` (never attempted), from `connection_refused` (an active RST = device present), and from `command_timeout` (device WAS reached). Typically seen when a `skip_ping: true` device is in fact down. |
| `connection_refused`     | `Connection refused` (active TCP RST — a device is present but refusing SSH). |
| `ssh_negotiation_failed` | SSH transport negotiation mismatch (`Unable to negotiate`, `no matching key exchange method / cipher / MAC / host key type`, `kex_exchange_identification`). |
| `command_timeout`        | Device-side / prompt-level timeout (`Commands timed out during processing`, `Timed out waiting for device prompt`). |
| `cancelled`              | Operator-initiated cancellation. |
| `null`                   | `Success` / `Warning`, or an unrecognized failure (the free-text `reason` is retained). |

### `connection` object (present on connected sessions)

| Field           | Type     | Notes |
|-----------------|----------|-------|
| `connect_ip`    | string   | The address SSHed to. |
| `ssh_options`   | string[] | The extra SSH options (`-o Kex/Ciphers/HostKeyAlgorithms=…`) that actually succeeded. |
| `pty_allocated` | boolean  | Whether the working session used a PTY (`-tt`). |
| `pty_retried`   | boolean  | Whether a `-T` first attempt failed and the collector retried with `-tt`. |

### Command entry

| Field      | Type           | Notes |
|------------|----------------|-------|
| `command`  | string         | The literal command. |
| `status`   | string         | `successful` / `timedout` / `notrun`. |
| `duration` | number \| null | **NEW in v2.** Per-command wall-clock seconds; `null` for `notrun`. |
