# SSH CMD Runner

## SYNOPSIS

Connects to network devices via native OpenSSH and runs a set of commands, logging all output.

## DESCRIPTION

Reads a list of device IPs from a text file (one IP per line), prompts for SSH credentials once,
reads commands from a file, then connects to each device via ssh.exe. Output is logged to
individual files using the naming convention: `DeviceName_IPAddress_Timestamp.log`.
The device name is parsed from the SSH prompt (e.g., `Switch01#`, `user@router>`).
Failed connections are logged separately for follow-up.

Commands are sent one at a time and the script waits for the device prompt to return before
sending the next command. This guarantees output is captured in order and no command is sent
before the previous one has fully completed.

Output is read character-by-character from stdout via a background runspace. This approach
handles devices (such as Cisco IOS) that send the CLI prompt without a trailing newline, which
would cause a line-based reader to block indefinitely.

Credentials are stored securely in **Windows Credential Manager** after first entry, so
subsequent runs do not re-prompt as long as the stored credentials remain valid.

## REQUIREMENTS

- Windows PowerShell 5.1 or later
- OpenSSH client (`ssh.exe`) available in PATH
  (Windows Optional Feature: _OpenSSH Client_, or Git for Windows)

## CONFIGURATION FILE

All parameters can be set via a `config.json` file placed alongside the script. CLI arguments
always take precedence over config file values, which take precedence over built-in defaults.
Copy `[example] config.json` to `config.json` and edit as needed.

```json
{
  "DeviceListFile": "./devices.txt",
  "CommandsFile": "./commands.txt",
  "LogDirectory": "./logs",
  "TimeoutSeconds": 10,
  "ExtraSSHOptions": [],
  "CommandDelayMs": 500,
  "CommandTimeoutSeconds": 30,
  "JsonDirectory": "./json",
  "NetcortexDirectory": "./netcortex",
  "LogEnabled": true,
  "JsonEnabled": false,
  "NetcortexEnabled": false,
  "CredentialLabel": "SSH-CMD-Runner",
  "ClearCredentials": false,
  "CompressOutput": false,
  "CompressWhen": "Always",
  "DeleteAfterCompress": false
}
```

## PARAMETERS

**DeviceListFile** `[string]`
Path to a text file containing one IP address per line. Blank lines and lines beginning
with `#` are ignored. Default: `.\devices.txt`

**CommandsFile** `[string]`
Path to a text file containing one command per line to execute on each device. Blank lines
and lines beginning with `#` are ignored. Default: `.\commands.txt`

**LogDirectory** `[string]`
Directory where per-device `.log` files will be saved. Created automatically if it does not
exist. Default: `.\logs`

**TimeoutSeconds** `[int]`
SSH connection timeout in seconds applied to the initial handshake. Valid range: 5–120.
Default: `10`

**CommandDelayMs** `[int]`
Delay in milliseconds to wait after receiving the device prompt before sending the next
command. Useful for slower devices or commands that produce large output where the prompt
may appear before the output buffer is fully flushed. Valid range: 100–10000. Default: `500`

**CommandTimeoutSeconds** `[int]`
Maximum time in seconds to wait for the device to return its prompt after each command is
sent. Covers device processing time plus transmission of all output lines. Increase this
value for commands with large output (e.g. `show interface` on a chassis with many ports).
Valid range: 5–600. Default: `30`

> Note: `-TimeoutSeconds` controls the initial SSH connection handshake only.
> `-CommandTimeoutSeconds` governs the per-command wait.

**ExtraSSHOptions** `[string[]]`
Additional options passed directly to `ssh.exe`. Supply as an array of strings. Commonly
used for legacy devices that require older key exchange or cipher algorithms. See
[Legacy Device Support](#legacy-device-support) for details. Default: `[]`

**JsonDirectory** `[string]`
Directory where JSON output files will be saved. Created automatically if it does not exist.
Each run produces a timestamped session summary plus one per-device file for each successful
connection. Default: `.\json`

**NetcortexDirectory** `[string]`
Directory where per-device raw output text files will be saved. Created automatically if it
does not exist. Each successful device session produces a `.txt` file using the naming
convention `DeviceName_IPAddress_Timestamp.txt`. Default: `.\netcortex`

**LogEnabled** `[bool]`
Enable or disable `.log` file output. When `$false`, no log files are written.
Default: `$true`

**JsonEnabled** `[bool]`
Enable or disable JSON file output. When `$false`, no session or per-device `.json` files
are written. Default: `$false`

**NetcortexEnabled** `[bool]`
Enable or disable Netcortex raw output text files. When `$false`, no `.txt` files are
written to `NetcortexDirectory`. Default: `$false`

**CredentialLabel** `[string]`
The target name used to store and retrieve credentials in Windows Credential Manager.
Allows different credential sets to be maintained for different environments.
Default: `"SSH-CMD-Runner"`

**ClearCredentials** `[bool]`
When `$true`, deletes any stored credentials matching `CredentialLabel` before prompting
for new ones. Use this after a password rotation to force re-entry. Default: `$false`

**CompressOutput** `[bool]`
When `$true`, creates a timestamped `.zip` archive of all output directories at the end of
the run using PowerShell's built-in `Compress-Archive`. Only directories that contain at
least one file are included. Default: `$false`

**CompressWhen** `[string]`
Controls when the archive is created. `"Always"` archives regardless of device results.
`"SuccessOnly"` skips compression if any device failed. Default: `"Always"`

**DeleteAfterCompress** `[bool]`
When `$true`, removes the original output directories after the archive is successfully
created. Has no effect if `CompressOutput` is `$false` or if archive creation fails.
Default: `$false`

## OUTPUT FILES

### Log Files

Each device session produces a `.log` file in `LogDirectory` using the naming convention
`DeviceName_IPAddress_Timestamp.log`. Each log file contains three sections:

1. **Header** — device name, IP, user, date, status, and timeout setting.
2. **Commands Sent** — the full list of commands that were submitted to the device.
3. **Device Output** — the captured session output.

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

### JSON Output

When `JsonEnabled` is `$true`, the script writes a timestamped JSON file to `JsonDirectory`
after all devices have been processed. The filename follows the convention
`ssh-output-<timestamp>.json`.

```json
{
  "summary": {
    "platform": "Microsoft Windows 10.0.22631",
    "engine": "PowerShell 7.5.4",
    "date": "2026-02-26 15:36:18",
    "result": { "total": 2, "success": 1, "failed": 1 },
    "devices": {
      "count": 2,
      "ip_addresses": ["10.1.50.1", "10.1.50.2"],
      "failed_ip_addresses": ["10.1.50.1"]
    },
    "commands": {
      "count": 3,
      "list": ["term len 0", "show switch", "show inventory"]
    }
  },
  "devices": [
    {
      "name": "s3850x-1",
      "ip": "10.1.50.2",
      "timestamp": "2026-02-26 15:36:48",
      "commands": [
        {
          "command": "show inventory",
          "raw_output": [
            "NAME: \"c38xx Stack\", DESCR: \"c38xx Stack\"",
            "PID: WS-C3850-48F-L    , VID: V07  , SN: FCW2046F0PD",
            ""
          ]
        }
      ]
    }
  ]
}
```

Key details:

- Only **successfully connected** devices appear in the `devices` array. Failed devices are
  listed in `summary.devices.failed_ip_addresses`.
- Each command's output is stored as **an array of strings** (`raw_output`), one element per
  output line. Blank lines are preserved as empty strings `""`.
- **Double-quotes** within device output are automatically escaped as `\"` by
  `ConvertTo-Json`.
- `summary.date` reflects the run start time; per-device `timestamp` reflects the completion
  time of that device's session.
- `summary.platform` and `summary.engine` are populated dynamically from the host OS and
  PowerShell version.

### Netcortex Output

When `NetcortexEnabled` is `$true`, the script writes a plain-text file for each
successfully connected device to `NetcortexDirectory`. The filename uses the same
`DeviceName_IPAddress_Timestamp.txt` convention as the log files. These files contain the
raw device output with no header or formatting, suited for import into Netcortex or other
NMS platforms.

## SESSION COMPRESSION

When `CompressOutput` is `$true`, the script packages all output directories into a single
timestamped archive at the end of the run:

```
ssh-session-20260303_143000.zip
```

The archive is created in the same directory as the script. Only directories that exist **and
contain at least one file** are included — empty directories are silently skipped.

| Parameter                      | Effect                                                         |
| ------------------------------ | -------------------------------------------------------------- |
| `CompressOutput = $true`       | Enable archiving                                               |
| `CompressWhen = "Always"`      | Archive regardless of device success/failure                   |
| `CompressWhen = "SuccessOnly"` | Skip archive if any device failed                              |
| `DeleteAfterCompress = $true`  | Remove source directories after a confirmed successful archive |

Example — compress and clean up after every run:

```powershell
.\ssh-cmd-runner.ps1 -CompressOutput $true -DeleteAfterCompress $true
```

Example — only compress when all devices succeeded:

```powershell
.\ssh-cmd-runner.ps1 -CompressOutput $true -CompressWhen SuccessOnly
```

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

## LEGACY DEVICE SUPPORT

Older network devices often require SSH algorithms that modern OpenSSH clients disable by
default. There are two ways to supply these settings.

### Option 1 — ExtraSSHOptions parameter

Pass the required options directly on the command line or via `config.json`. Each `-o` flag
and its value must be a separate array element:

```powershell
.\ssh-cmd-runner.ps1 -ExtraSSHOptions '-o','MACs=hmac-sha1,hmac-sha1-96',`
                                       '-o','KexAlgorithms=+diffie-hellman-group1-sha1',`
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

### Option 2 — SSH config file (recommended for permanent environments)

A per-host SSH config file at `~\.ssh\config` (i.e. `C:\Users\<you>\.ssh\config`) is read
automatically by `ssh.exe` for every connection. Placing legacy settings here removes the
need to pass `ExtraSSHOptions` at all and keeps the settings in one place regardless of
which tool initiates the SSH session.

Create or append to `~\.ssh\config`:

```
Host 10.*
  User nimda
  Port 22
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  MACs +hmac-sha1,hmac-sha1-96
  KexAlgorithms +diffie-hellman-group1-sha1,diffie-hellman-group14-sha1
  HostKeyAlgorithms +ssh-rsa
```

The `Host 10.*` wildcard matches any IP address beginning with `10.` Use a more specific
pattern (e.g. `Host 10.1.50.*`) to scope the settings to a particular subnet, or list
individual IPs with separate `Host` blocks.

| Directive                      | Purpose                                                       |
| ------------------------------ | ------------------------------------------------------------- |
| `User`                         | Default SSH username for matched hosts                        |
| `Port`                         | Default SSH port                                              |
| `StrictHostKeyChecking no`     | Do not abort when the host key is unknown or changed          |
| `UserKnownHostsFile /dev/null` | Discard host key checks entirely (lab/legacy use)             |
| `MACs`                         | Permitted message authentication code algorithms              |
| `KexAlgorithms`                | Permitted key exchange algorithms                             |
| `HostKeyAlgorithms +ssh-rsa`   | Re-enable RSA host keys (disabled by default in OpenSSH 8.8+) |

> **Note:** When `Host` directives in `~\.ssh\config` already cover the target devices,
> `ExtraSSHOptions` can be left empty (`[]`) and the `User` directive can be ignored in
> favour of the credential prompt.

## SUPPORTED DEVICE PROMPT FORMATS

The script recognises the following prompt styles when detecting the CLI prompt and
parsing the device hostname from output:

| Vendor / OS        | Example prompt                          |
| ------------------ | --------------------------------------- |
| Cisco IOS / IOS-XE | `hostname#` `hostname>`                 |
| Cisco NX-OS        | `hostname#` `hostname(config)#`         |
| Arista EOS         | `hostname#` `hostname>`                 |
| Juniper JunOS      | `user@hostname>` `user@hostname#`       |
| Palo Alto PAN-OS   | `user@hostname>` `user@hostname#`       |
| HP / Aruba         | `hostname#` `hostname>`                 |
| Linux-based NOS    | `user@hostname:~$` `[user@hostname ~]$` |

## EXAMPLES

Run with all defaults:

    .\ssh-cmd-runner.ps1

Specify device list and commands file explicitly:

    .\ssh-cmd-runner.ps1 -DeviceListFile .\devices.txt -CommandsFile .\commands.txt

Write logs to a custom directory with a longer connection timeout:

    .\ssh-cmd-runner.ps1 -LogDirectory "C:\Logs\Network" -TimeoutSeconds 30

Increase the per-command timeout for devices with verbose output:

    .\ssh-cmd-runner.ps1 -CommandTimeoutSeconds 60

Add a 1-second delay between commands for slower devices:

    .\ssh-cmd-runner.ps1 -CommandDelayMs 1000

Enable JSON and Netcortex output in addition to log files:

    .\ssh-cmd-runner.ps1 -JsonEnabled $true -NetcortexEnabled $true

Force fresh credential entry after a password rotation:

    .\ssh-cmd-runner.ps1 -ClearCredentials $true

Compress all output directories into a zip archive after the run:

    .\ssh-cmd-runner.ps1 -CompressOutput $true

Compress and remove source directories, but only if all devices succeeded:

    .\ssh-cmd-runner.ps1 -CompressOutput $true -CompressWhen SuccessOnly -DeleteAfterCompress $true

Connect to legacy devices using ExtraSSHOptions:

    .\ssh-cmd-runner.ps1 -ExtraSSHOptions '-o','KexAlgorithms=+diffie-hellman-group1-sha1','-o','HostKeyAlgorithms=+ssh-rsa'
