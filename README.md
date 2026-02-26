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

## LOG FORMAT

Each log file contains three sections:

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

## JSON OUTPUT

In addition to the per-device `.log` files, the script writes a single `output.json` file
to the JSON directory (default: `.\json\output.json`) after all devices have been processed.
The file is overwritten on every run.

### Structure

```json
{
  "summary": {
    "platform": "Windows",
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

### Key details

- Only **successfully connected** devices appear in the `devices` array. Devices that
  failed to connect are listed in `summary.devices.failed_ip_addresses`.
- Each command's output is stored as **an array of strings** (`raw_output`), one element
  per output line. Blank lines are preserved as empty strings `""`.
- **Double-quotes** within device output (e.g. `NAME: "Switch 1"`) are automatically
  escaped as `\"` by `ConvertTo-Json` — no manual handling is required.
- The `summary.date` reflects the run start time; per-device `timestamp` reflects the
  completion time of that device's session.

## REQUIREMENTS

- Windows PowerShell 5.1 or later
- OpenSSH client (`ssh.exe`) available in PATH
  (Windows Optional Feature: *OpenSSH Client*, or Git for Windows)

## PARAMETERS

**DeviceListFile** `[string]`
Path to a text file containing one IP address per line. Blank lines and lines beginning
with `#` are ignored. Default: `.\devices.txt`

**CommandsFile** `[string]`
Path to a text file containing one command per line to execute on each device. Blank lines
and lines beginning with `#` are ignored. Default: `.\commands.txt`

**LogDirectory** `[string]`
Directory where output logs will be saved. Created automatically if it does not exist.
Default: `.\logs`

**TimeoutSeconds** `[int]`
Per-command SSH timeout in seconds. Applied when waiting for the initial device prompt and
after each individual command. Valid range: 5–120. Default: `10`

**CommandDelayMs** `[int]`
Delay in milliseconds to wait after receiving the device prompt before sending the next
command. Useful for slower devices or commands that produce large output where the prompt
may appear before the output buffer is fully flushed. Valid range: 100–10000. Default: `500`

**JsonDirectory** `[string]`
Directory where `output.json` will be written. Created automatically if it does not exist.
The file is always named `output.json` and is overwritten on every run.
Default: `.\json`

**ExtraSSHOptions** `[string[]]`
Additional options passed directly to `ssh.exe`. Supply as an array of strings. Commonly
used for legacy devices that require older key exchange or cipher algorithms.

## EXAMPLES

Run with all defaults:

    .\ssh-cmd-runner.ps1

Specify device list and commands file explicitly:

    .\ssh-cmd-runner.ps1 -DeviceListFile .\devices.txt -CommandsFile .\commands.txt

Write logs to a custom directory with a longer timeout:

    .\ssh-cmd-runner.ps1 -LogDirectory "C:\Logs\Network" -TimeoutSeconds 30

Add a 1-second delay between commands for slower devices or large output:

    .\ssh-cmd-runner.ps1 -CommandDelayMs 1000

Write JSON output to a custom directory:

    .\ssh-cmd-runner.ps1 -JsonDirectory "C:\Data\NetworkJSON"

Connect to legacy devices requiring older SSH algorithms:

    .\ssh-cmd-runner.ps1 -ExtraSSHOptions '-o','KexAlgorithms=+diffie-hellman-group1-sha1','-o','HostKeyAlgorithms=+ssh-rsa'

## SUPPORTED DEVICE PROMPT FORMATS

The script recognises the following prompt styles when detecting the CLI prompt and
parsing the device hostname from output:

| Vendor / OS         | Example prompt              |
|---------------------|-----------------------------|
| Cisco IOS / IOS-XE  | `hostname#` `hostname>`     |
| Cisco NX-OS         | `hostname#` `hostname(config)#` |
| Arista EOS          | `hostname#` `hostname>`     |
| Juniper JunOS       | `user@hostname>` `user@hostname#` |
| Palo Alto PAN-OS    | `user@hostname>` `user@hostname#` |
| HP / Aruba          | `hostname#` `hostname>`     |
| Linux-based NOS     | `user@hostname:~$` `[user@hostname ~]$` |
