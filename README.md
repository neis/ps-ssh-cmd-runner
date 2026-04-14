# SSH CMD Runner

## SYNOPSIS

Connects to network devices via native OpenSSH and runs OS-specific commands, logging all output.

## DESCRIPTION

Reads a CSV device list containing IP addresses and operating system types, loads per-OS
command files from a commands directory, then connects to each device via ssh.exe. Output is
logged to individual files using the naming convention: `DeviceName_IPAddress_Timestamp.log`.
The device name is parsed from the SSH prompt (e.g., `Switch01#`, `user@router>`) or from
command output (e.g., `System Name` for Cisco WLC).
Failed connections are logged separately for follow-up.

Commands are sent one at a time and the script waits for the device prompt to return before
sending the next command. This guarantees output is captured in order and no command is sent
before the previous one has fully completed.

The appropriate paging-disable command (e.g., `terminal length 0`) is sent automatically
based on the device OS type, so it does not need to be included in command files.

Output is read character-by-character from stdout via a background runspace. This approach
handles devices (such as Cisco IOS) that send the CLI prompt without a trailing newline, which
would cause a line-based reader to block indefinitely.

Credentials are stored securely in **Windows Credential Manager** after first entry, so
subsequent runs do not re-prompt as long as the stored credentials remain valid.

## REQUIREMENTS

- Windows PowerShell 5.1 or later
- OpenSSH client (`ssh.exe`) available in PATH
  (Windows Optional Feature: _OpenSSH Client_, or Git for Windows)

## QUICK START

1. Create a `devices.txt` CSV file:

   ```csv
   IP,OS
   10.1.1.1,cisco-iosxe
   10.1.1.2,cisco-nxos
   10.1.1.3,cisco-wlc-aireos
   ```

2. Create a `commands/` directory with per-OS command files:

   ```
   commands/cisco-iosxe.txt
   commands/cisco-nxos.txt
   commands/cisco-wlc-aireos.txt
   ```

3. Run the script:
   ```powershell
   .\ssh-cmd-runner.ps1
   ```

See the `Examples/` directory for sample files.

## SUPPORTED OS TYPES

Each OS type defines automatic behaviors for paging, PTY allocation, and session teardown.

| OS Type            | Platform                              | Paging Command          | PTY    | Exit Sequence     |
| ------------------ | ------------------------------------- | ----------------------- | ------ | ----------------- |
| `cisco-iosxe`      | Cisco IOS / IOS-XE (Catalyst, ISR)    | `terminal length 0`     | Auto   | `exit`            |
| `cisco-iosxr`      | Cisco IOS-XR (ASR9000, NCS, CRS)      | `terminal length 0`     | Auto   | `exit`            |
| `cisco-nxos`       | Cisco NX-OS (Nexus 5K/7K/9K)          | `terminal length 0`     | Always | `exit`            |
| `cisco-wlc-aireos` | Cisco WLC AireOS (5520, etc.)    | `config paging disable` | Always | `logout` then `n` |
| `cisco-wlc-iosxe`  | Cisco WLC IOS-XE (Catalyst 9800) | `terminal length 0`     | Auto   | `exit`            |

**Paging Command** is sent silently after login and does not appear in log output.

**PTY**: "Always" means the script uses `-tt` (forced PTY allocation) for that OS type
without attempting `-T` first. "Auto" means the script starts with `-T` and auto-detects
whether PTY is needed (via `stty` error detection or zero-stdout fallback).

**Exit Sequence**: Commands sent to close the remote session cleanly. AireOS requires
`logout` followed by `n` to decline the save-config prompt (since `config paging disable`
is treated as a configuration change).

## CONFIGURATION FILE

All parameters can be set via a `config.json` file placed alongside the script. CLI arguments
always take precedence over config file values, which take precedence over built-in defaults.
Copy `[example] config.json` from the `Examples/` directory to `config.json` and edit as needed.

```json
{
  "DeviceListFile": "./devices.txt",
  "CommandsDirectory": "./commands",
  "LogDirectory": "./logs",
  "TimeoutSeconds": 10,
  "ExtraSSHOptions": [],
  "CommandDelayMs": 100,
  "CommandTimeoutSeconds": 30,
  "InitialPromptTimeoutSeconds": 60,
  "AllocatePTY": false,
  "PingTest": true,
  "JsonDirectory": "./json",
  "NetcortexDirectory": "./netcortex",
  "LogEnabled": true,
  "JsonEnabled": false,
  "JsonSessionFileEnabled": true,
  "NetcortexEnabled": false,
  "CredentialLabel": "SSH-CMD-Runner",
  "ClearCredentials": false,
  "CompressOutput": false,
  "CompressWhen": "Always",
  "DeleteAfterCompress": false,
  "MaxParallelJobs": 1,
  "HostnameColumnWidth": 16
}
```

## PARAMETERS

### DeviceListFile `[string]`

Path to a CSV file with `IP,OS` columns (header row required). Each row specifies a device
IP and its operating system type. See [Supported OS Types](#supported-os-types) for valid
values. Blank rows and rows where the IP starts with `#` are ignored. Default: `.\devices.txt`

### CommandsDirectory `[string]`

Directory containing per-OS command files. Each file must be named `<os-type>.txt`
(e.g. `cisco-iosxe.txt`, `cisco-nxos.txt`) matching the OS column in the device CSV.
Only files for OS types present in the device list are required. Default: `.\commands`

### LogDirectory `[string]`

Directory where per-device `.log` files will be saved. Created automatically if it does not
exist. Default: `.\logs`

### TimeoutSeconds `[int]`

SSH connection timeout in seconds applied to the initial handshake. Valid range: 5-120.
Default: `10`

### CommandDelayMs `[int]`

Delay in milliseconds to wait after receiving the device prompt before sending the next
command. Useful for slower devices or commands that produce large output where the prompt
may appear before the output buffer is fully flushed. Set to `0` for fastest operation.
Valid range: 0-10000. Default: `100`

### CommandTimeoutSeconds `[int]`

Maximum time in seconds to wait for the device to return its prompt after each command is
sent. Covers device processing time plus transmission of all output lines. Increase this
value for commands with large output (e.g. `show interface` on a chassis with many ports).
Valid range: 5-600. Default: `30`

> Note: `-TimeoutSeconds` controls the initial SSH connection handshake only.
> `-CommandTimeoutSeconds` governs the per-command wait.

### InitialPromptTimeoutSeconds `[int]`

Maximum time in seconds to wait for the first device prompt after login. This window covers
the full SSH authentication sequence, any MOTD/banner output, and the appearance of the CLI
prompt. Increase this value for devices that display long banners or authenticate slowly. This
setting applies only to the initial connection; per-command response waits are governed by
`CommandTimeoutSeconds`. Valid range: 5-300. Default: `60`

### AllocatePTY `[bool]`

Force pseudo-terminal (PTY) allocation using `-tt` instead of `-T` for all devices. When
`$false` (default), PTY allocation is determined per-device: OS types that require PTY
(`cisco-nxos`, `cisco-wlc-aireos`) always use `-tt`, while other OS types start with `-T`
and auto-detect PTY failures via `stty` error detection or zero-stdout fallback. Set to
`$true` to force PTY for all devices regardless of OS type. Default: `$false`

### PingTest `[bool]`

Send a single ICMP ping to each device before attempting SSH. Devices that do not respond
are skipped immediately, avoiding the full SSH connection timeout. Disable if your network
blocks ICMP but allows SSH. Default: `$true`

### ExtraSSHOptions `[string[]]`

Additional options passed directly to `ssh.exe`. Supply as an array of strings. Commonly
used for legacy devices that require older key exchange or cipher algorithms. See
[Legacy Device Support](#legacy-device-support) for details. Default: `[]`

### JsonDirectory `[string]`

Directory where JSON output files will be saved. Created automatically if it does not exist.
Each run produces a timestamped session summary plus one per-device file for each successful
connection. Default: `.\json`

### NetcortexDirectory `[string]`

Directory where per-device raw output text files will be saved. Created automatically if it
does not exist. Each successful device session produces a `.txt` file using the naming
convention `DeviceName_IPAddress_Timestamp.txt`. Default: `.\netcortex`

### LogEnabled `[bool]`

Enable or disable `.log` file output. When `$false`, no log files are written.
Default: `$true`

### JsonEnabled `[bool]`

Enable or disable JSON file output. When `$false`, no session or per-device `.json` files
are written. Default: `$false`

### JsonSessionFileEnabled `[bool]`

Enable or disable the session summary JSON file (`ssh-session-<timestamp>.json`).
When `$false`, per-device JSON files are still written if `JsonEnabled` is `$true`, but the
session summary file is skipped. Default: `$true`

### NetcortexEnabled `[bool]`

Enable or disable Netcortex raw output text files. When `$false`, no `.txt` files are
written to `NetcortexDirectory`. Default: `$false`

### CredentialLabel `[string]`

The target name used to store and retrieve credentials in Windows Credential Manager.
Allows different credential sets to be maintained for different environments.
Default: `"SSH-CMD-Runner"`

### ClearCredentials `[bool]`

When `$true`, deletes any stored credentials matching `CredentialLabel` before prompting
for new ones. Use this after a password rotation to force re-entry. Default: `$false`

### CompressOutput `[bool]`

When `$true`, creates a timestamped `.zip` archive of all output directories at the end of
the run using PowerShell's built-in `Compress-Archive`. Only directories that contain at
least one file are included. Default: `$false`

### CompressWhen `[string]`

Controls when the archive is created. `"Always"` archives regardless of device results.
`"SuccessOnly"` skips compression if any device failed. Default: `"Always"`

### DeleteAfterCompress `[bool]`

When `$true`, removes the original output directories after the archive is successfully
created. Has no effect if `CompressOutput` is `$false` or if archive creation fails.
Default: `$false`

### CompressOnly `[switch]`

Compresses existing output directories and exits immediately without connecting to any
devices. Useful for archiving output from a previous run. Ignores `CompressWhen` (always
compresses). Respects `DeleteAfterCompress` and output directory paths.

### MaxParallelJobs `[int]`

Maximum number of devices to process concurrently. When set to `1` (default), devices are
processed sequentially in the order listed in the device CSV. When set to `2` or higher,
devices are dispatched to a RunspacePool and processed in parallel. See
[Parallel Execution](#parallel-execution) for details. Valid range: 1-100. Default: `1`

### HostnameColumnWidth `[int]`

Minimum column width for the Hostname column in the parallel mode table output. Since
hostnames are not known until each device is connected, this setting controls the minimum
padding to keep the table aligned. Increase this value if your device hostnames are long
(e.g. `CORE-SWITCH-01-BUILDING-3`). Only affects parallel mode output formatting. Valid
range: 8-64. Default: `16`

### UpdateConfig `[switch]`

Compares your `config.json` against `Examples/[example] config.json` and adds any missing
parameters with their default values. Existing settings are never modified or removed. Use
this after updating the script to pick up new configuration options without manually editing
your config file. The script prints a summary of added parameters and exits.

## PARALLEL EXECUTION

When `MaxParallelJobs` is set to `2` or higher, the script processes multiple devices
concurrently using a PowerShell RunspacePool. This can significantly reduce total execution
time for large device lists.

### How It Works

Devices are dispatched from an internal queue as parallel slots become available. The console
displays a table that grows as devices are dispatched, with status columns updating in-place
as each device completes:

```
   # | IP              | OS               | Status    |   Time | Hostname         | Reason
-----+-----------------+------------------+-----------+--------+------------------+--------
 1/5 | 10.1.50.1       | cisco-iosxe      | OK        |  20.15 | s4500x-1         |
 2/5 | 10.1.50.2       | cisco-iosxe      | OK        |  22.03 | s3850x-1         |
 3/5 | 10.1.50.3       | cisco-iosxe      |           |        |                  |
 4/5 | 10.1.50.4       | cisco-nxos       | FAILED    |   0.00 |                  | Connection timed out
 5/5 | 10.1.50.5       | cisco-iosxe      | SKIPPED   |   0.00 |                  | No ping response
```

In sequential mode (`MaxParallelJobs = 1`), the original inline output format is used
instead of the table.

### Interrupt Handling (Ctrl+C)

Pressing Ctrl+C during execution triggers a graceful shutdown in both modes:

- **Sequential mode**: The current device session completes, then the script stops before
  the next device and proceeds to the summary.
- **Parallel mode**: All running SSH sessions are stopped, pending devices in the queue are
  cancelled, and the table is updated with `CANCELLED` status for affected devices.

In both cases, partial results are preserved and included in the summary report and any
enabled output files.

### Authentication Abort

If three consecutive devices return authentication failures, the script aborts automatically.
In parallel mode, all running jobs are cancelled and the device queue is drained. This
prevents wasting time against many devices with incorrect credentials.

### Resource Considerations

Each parallel SSH session spawns an `ssh.exe` process with a background stdout reader. High
values of `MaxParallelJobs` against large device lists will consume more system memory and
network connections. Some network devices may also rate-limit concurrent SSH sessions from
the same source IP. Start with a conservative value (e.g. `5`) and increase as needed.

## PER-OS COMMAND FILES

Command files live in the `CommandsDirectory` (default: `.\commands`). Each file is named
after its OS type with a `.txt` extension. Only files for OS types referenced in your device
CSV are required.

```
commands/
  cisco-iosxe.txt
  cisco-nxos.txt
  cisco-wlc-aireos.txt
  cisco-wlc-iosxe.txt
```

Each file contains one command per line. Blank lines and lines starting with `#` are ignored.
**Do not include paging-disable commands** (e.g. `terminal length 0`) in these files -- the
script sends the appropriate paging command automatically based on the OS type.

Example `commands/cisco-iosxe.txt`:

```
# Cisco IOS / IOS-XE discovery commands
show startup-config | include hostname
show version
show inventory
show cdp neighbors detail
show interface status
show ip route
show run
```

Example `commands/cisco-wlc-aireos.txt`:

```
# Cisco WLC AireOS discovery commands
show sysinfo
show inventory
show interface summary
show wlan summary
show ap summary
show run-config
```

### Netcortex Command Files (optional)

When `NetcortexEnabled` is `$true`, the script looks for an optional `netcortex/` subdirectory
inside the commands directory. These files define which commands appear in Netcortex output
and in what order.

```
commands/
  cisco-iosxe.txt              ← standard commands (log, JSON, all outputs)
  cisco-nxos.txt
  netcortex/
    cisco-iosxe.txt            ← Netcortex-specific list (subset + ordering)
    cisco-nxos.txt
```

**How merging works:** Commands from the Netcortex file that are not already in the standard
command file are automatically appended to the session command list. This ensures every
command Netcortex needs is actually executed during the SSH session, without duplicating
commands that are already in the standard list.

**How filtering works:** When generating Netcortex `.txt` output files, only commands listed
in the Netcortex command file are included, and they appear in the order defined in that
file — regardless of the order they were executed. Log and JSON outputs are unaffected
and continue to include all commands.

**Fallback:** If no Netcortex command file exists for an OS type, the Netcortex output
includes all commands in execution order (the original behavior).

## OUTPUT FILES

### Log Files

Each device session produces a `.log` file in `LogDirectory` using the naming convention
`DeviceName_IPAddress_Timestamp.log`. Each log file contains:

1. **Header** -- device name, IP, user, date, status, OS type, timeout settings, and PTY mode.
2. **Commands Sent** -- the full list of commands submitted to the device.
3. **Device Output** -- the captured session output.

Within the Device Output section, each command block follows this layout:

```
hostname#show version
... command output ...
hostname#
hostname#
hostname#show interfaces
... command output ...
```

The prompt is written alone (without a command) twice between each command block. Because
every non-blank line is either a prompt, a command echo, or device output, the log is
straightforward to parse programmatically.

If a command times out, any partial output received before the timeout is preserved in the
log under the PARTIAL OUTPUT section.

### JSON Output

When `JsonEnabled` is `$true`, the script writes a timestamped session summary JSON file
plus one per-device JSON file to `JsonDirectory`. The session summary includes OS type
breakdowns:

```json
{
  "summary": {
    "platform": "Microsoft Windows 10.0.22631",
    "engine": "PowerShell 5.1.22621.4391",
    "date": "2026-03-19 10:00:00",
    "result": { "total": 3, "success": 2, "failed": 1 },
    "devices": {
      "count": 3,
      "ip_addresses": ["10.1.1.1", "10.1.1.2", "10.1.1.3"],
      "failed_ip_addresses": ["10.1.1.3"]
    },
    "commands_directory": "./commands",
    "os_types": {
      "cisco-iosxe": {
        "device_count": 1,
        "command_count": 7,
        "commands": ["show version", "show inventory", "..."]
      },
      "cisco-nxos": {
        "device_count": 2,
        "command_count": 5,
        "commands": ["show version", "show inventory", "..."]
      }
    }
  }
}
```

### Netcortex Output

When `NetcortexEnabled` is `$true`, the script writes a plain-text file for each
successfully connected device to `NetcortexDirectory`. The filename uses the same
`DeviceName_IPAddress_Timestamp.txt` convention as the log files. These files contain the
raw device output with no header or formatting, suited for import into Netcortex or other
NMS platforms.

## SESSION COMPRESSION

When `CompressOutput` is `$true`, the script packages all output directories into a single
timestamped archive at the end of the run. Each output directory is individually zipped first,
then bundled into the outer archive:

```
ssh-session-20260303_143000.zip
  ├── logs.zip
  ├── json.zip
  └── netcortex.zip
```

The archive is created in the same directory as the script. Only directories that exist **and
contain at least one file** are included — empty directories are silently skipped.

| Parameter                      | Effect                                                         |
| ------------------------------ | -------------------------------------------------------------- |
| `CompressOutput = $true`       | Enable archiving at end of run                                 |
| `CompressWhen = "Always"`      | Archive regardless of device success/failure                   |
| `CompressWhen = "SuccessOnly"` | Skip archive if any device failed                              |
| `DeleteAfterCompress = $true`  | Remove source directories after a confirmed successful archive |
| `-CompressOnly`                | Archive existing directories and exit (no device connections)  |

## WINDOWS CREDENTIAL MANAGER

On first run the script prompts for a username and password, then stores them securely in
Windows Credential Manager under the label defined by `CredentialLabel` (default:
`"SSH-CMD-Runner"`). Subsequent runs retrieve the stored credentials automatically without
re-prompting.

**Rotate credentials** after a password change:

```powershell
.\ssh-cmd-runner.ps1 -ClearCredentials $true
```

**Use separate credentials** for different environments by specifying a unique label:

```powershell
.\ssh-cmd-runner.ps1 -CredentialLabel "SSH-PROD"
.\ssh-cmd-runner.ps1 -CredentialLabel "SSH-LAB"
```

## PTY ALLOCATION AND AUTO-DETECTION

The script supports two modes of SSH terminal allocation:

- **`-T`** (no PTY): Default for most devices. Works well for Cisco IOS/IOS-XE where PTY
  can cause echo complications.
- **`-tt`** (forced PTY): Required for devices whose login sequence depends on a terminal,
  such as NX-OS switches (which run `stty` during login) and AireOS WLCs.

PTY allocation is determined per-device based on OS type. OS types with `RequirePTY = true`
(`cisco-nxos`, `cisco-wlc-aireos`) always use `-tt`. Other OS types start with `-T` and
fall back to `-tt` automatically if:

1. **stty error detected** (fast, within 10s): The remote device produces
   `stty: Inappropriate ioctl for device` in stderr.
2. **Zero stdout timeout** (after full initial timeout): SSH connected but produced no
   output at all.

Setting `AllocatePTY = $true` globally forces `-tt` for all devices.

When PTY is active, the script sends `stty -echo` after login to suppress PTY echo, keeping
command output clean and prompt detection reliable.

## LEGACY DEVICE SUPPORT

Older network devices often require SSH algorithms that modern OpenSSH clients disable by
default. There are two ways to supply these settings.

### Option 1 -- ExtraSSHOptions parameter

Pass the required options directly on the command line or via `config.json`. Each `-o` flag
and its value must be a separate array element:

```powershell
.\ssh-cmd-runner.ps1 -ExtraSSHOptions '-o','KexAlgorithms=+diffie-hellman-group1-sha1',`
                                       '-o','HostKeyAlgorithms=+ssh-rsa'
```

Or in `config.json`:

```json
"ExtraSSHOptions": [
    "-o", "MACs=hmac-sha1,hmac-sha1-96",
    "-o", "KexAlgorithms=+diffie-hellman-group1-sha1",
    "-o", "HostKeyAlgorithms=+ssh-rsa"
]
```

### Option 2 -- SSH config file (recommended for permanent environments)

A per-user SSH config file at `~\.ssh\config` (i.e. `C:\Users\<you>\.ssh\config`) is read
automatically by `ssh.exe` for every connection. Placing legacy settings here removes the
need to pass `ExtraSSHOptions` at all and applies them to manual SSH sessions too.

Create or append to `~\.ssh\config`:

```
# Legacy device support — re-enable algorithms disabled by modern OpenSSH
Host 10.*
    User nimda
    Port 22
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null

    # Key exchange: group1-sha1 (IOS 12.x), group-exchange-sha1 (older IOS-XE),
    # group14-sha1 (mid-era devices)
    KexAlgorithms +diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1

    # Ciphers: CBC modes required by devices that don't support CTR or GCM
    Ciphers +aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc

    # MACs: SHA1-based MACs for older firmware
    MACs +hmac-sha1,hmac-sha1-96

    # Host key + pubkey: RSA (most legacy devices) and DSA (very old IOS 12.x)
    HostKeyAlgorithms +ssh-rsa,ssh-dss
    PubkeyAcceptedAlgorithms +ssh-rsa,ssh-dss

    # Keep long sessions alive through firewalls/NAT that drop idle connections
    ServerAliveInterval 60
    ServerAliveCountMax 3
```

The `+` prefix appends to the default algorithm list rather than replacing it, so modern
devices continue to negotiate the strongest available algorithms.

> **Note:** `StrictHostKeyChecking` and `UserKnownHostsFile` are already set by the script
> via `-o` flags. Including them here is optional but convenient for manual SSH sessions.

## SUPPORTED DEVICE PROMPT FORMATS

The script recognises the following prompt styles when detecting the CLI prompt and
parsing the device hostname from output:

| Vendor / OS        | Example prompt                          |
| ------------------ | --------------------------------------- |
| Cisco IOS / IOS-XE | `hostname#` `hostname>`                 |
| Cisco IOS-XR       | `RP/0/RSP0/CPU0:hostname#`              |
| Cisco NX-OS        | `hostname#` `hostname(config)#`         |
| Cisco WLC AireOS   | `(Cisco Controller) >`                  |
| Arista EOS         | `hostname#` `hostname>`                 |
| Juniper JunOS      | `user@hostname>` `user@hostname#`       |
| Palo Alto PAN-OS   | `user@hostname>` `user@hostname#`       |
| HP / Aruba         | `hostname#` `hostname>`                 |
| Linux-based NOS    | `user@hostname:~$` `[user@hostname ~]$` |

For Cisco WLC AireOS, the hostname is extracted from the `System Name` field in
`show sysinfo` output, since the WLC prompt does not contain the hostname.

## EXAMPLES

Run with all defaults (devices.txt CSV + commands/ directory in current folder):

    .\ssh-cmd-runner.ps1

Specify a custom device list and commands directory:

    .\ssh-cmd-runner.ps1 -DeviceListFile .\my-devices.csv -CommandsDirectory .\my-commands

Write logs to a custom directory with a longer connection timeout:

    .\ssh-cmd-runner.ps1 -LogDirectory "C:\Logs\Network" -TimeoutSeconds 30

Increase the per-command timeout for devices with verbose output:

    .\ssh-cmd-runner.ps1 -CommandTimeoutSeconds 120

Force PTY allocation for all devices (overrides per-OS defaults):

    .\ssh-cmd-runner.ps1 -AllocatePTY $true

Disable the pre-connection ping test (for networks that block ICMP):

    .\ssh-cmd-runner.ps1 -PingTest $false

Enable JSON and Netcortex output in addition to log files:

    .\ssh-cmd-runner.ps1 -JsonEnabled $true -NetcortexEnabled $true

Force fresh credential entry after a password rotation:

    .\ssh-cmd-runner.ps1 -ClearCredentials $true

Compress all output directories into a zip archive after the run:

    .\ssh-cmd-runner.ps1 -CompressOutput $true

Compress and remove source directories, but only if all devices succeeded:

    .\ssh-cmd-runner.ps1 -CompressOutput $true -CompressWhen SuccessOnly -DeleteAfterCompress $true

Archive existing output directories without running any device connections:

    .\ssh-cmd-runner.ps1 -CompressOnly

Archive existing output and clean up the source directories:

    .\ssh-cmd-runner.ps1 -CompressOnly -DeleteAfterCompress $true

Process up to 5 devices in parallel:

    .\ssh-cmd-runner.ps1 -MaxParallelJobs 5

Parallel execution with a wider hostname column for long device names:

    .\ssh-cmd-runner.ps1 -MaxParallelJobs 10 -HostnameColumnWidth 28

Update config.json with any new parameters added in recent script updates:

    .\ssh-cmd-runner.ps1 -UpdateConfig
