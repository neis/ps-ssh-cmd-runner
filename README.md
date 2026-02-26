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
