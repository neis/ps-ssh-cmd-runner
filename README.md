# SSH CMD Runner

## SYNOPSIS

Connects to network devices via native OpenSSH and runs a set of commands, logging all output.

## DESCRIPTION

Reads a list of device IPs from a text file (one IP per line), prompts for SSH credentials once,
reads commands from a file, then connects to each device via ssh.exe. Output is logged to
individual files using the naming convention: DeviceName_IPAddress_Date_Timestamp.log
The device name is parsed from the SSH prompt (e.g., "Switch01#", "user@router>").

## PARAMETERS

DeviceListFile [File]
Path to a text file containing one IP address per line. Blank lines and comments (#) are ignored.

CommandsFile [File]
Path to a text file containing one command per line to execute on each device.

LogDirectory [Path]
Directory where output logs will be saved. Created automatically if it doesn't exist.

TimeoutSeconds [Seconds]
SSH connection timeout in seconds. Default is 10.

ExtraSSHOptions [Arguments]
Additional SSH options passed directly to ssh.exe for legacy or special device support.
Supply as an array of strings, e.g. '-o','KexAlgorithms=+diffie-hellman-group1-sha1'

## EXAMPLES

    .\Invoke-NetworkSSH.ps1

    >Runs with defaults: devices.txt, commands.txt, .\SSH_Logs, 10s timeout.`

    .\Invoke-NetworkSSH.ps1 -DeviceListFile .\devices.txt -CommandsFile .\commands.txt

    .\Invoke-NetworkSSH.ps1 -LogDirectory "C:\Logs\Network" -TimeoutSeconds 15

    .\Invoke-NetworkSSH.ps1 -ExtraSSHOptions '-o','KexAlgorithms=+diffie-hellman-group1-sha1','-o','HostKeyAlgorithms=+ssh-rsa'

    >A common need is for legacy devices that require older key exchange and host key algorithms.
