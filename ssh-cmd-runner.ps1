#Requires -Version 5.1

<#
.SYNOPSIS
    Connects to network devices via native OpenSSH and runs a set of commands, logging all output.

.DESCRIPTION
    Reads a list of device IPs from a text file (one IP per line), prompts for SSH credentials once,
    reads commands from a file, then connects to each device via ssh.exe. Output is logged to
    individual files using the naming convention: DeviceName_IPAddress_Timestamp.log.
    The device name is parsed from the SSH prompt (e.g., "Switch01#", "user@router>").
    Failed connections are logged separately for follow-up.

.PARAMETER DeviceListFile
    Path to a text file containing one IP address per line. Blank lines and comments (#) are ignored.

.PARAMETER CommandsDirectory
    Directory containing per-OS command files. Each file must be named
    <os-type>.txt (e.g. cisco-iosxe.txt, cisco-nxos.txt) matching the OS
    column in the device CSV. Default is .\commands.

.PARAMETER LogDirectory
    Directory where output logs will be saved. Created automatically if it doesn't exist.

.PARAMETER TimeoutSeconds
    SSH connection timeout in seconds. Default is 10.

.PARAMETER ExtraSSHOptions
    Additional SSH options passed directly to ssh.exe for legacy or special device support.
    Supply as an array of strings, e.g. '-o','KexAlgorithms=+diffie-hellman-group1-sha1'

.PARAMETER CommandDelayMs
    Delay in milliseconds between sending each command to the device.
    Prevents output interleaving caused by commands arriving faster than
    the device can process them. Default is 100ms. Set to 0 for fastest
    operation, or increase for slower devices. Valid range: 0-10000.

.PARAMETER CommandTimeoutSeconds
    Maximum time in seconds to wait for a device to return its prompt after each
    command is sent. This covers device processing time plus the time to transmit
    all output lines. Increase this for commands with large output (e.g. show
    interface on a chassis with many ports). Default is 30.
    Note: -TimeoutSeconds controls only the initial SSH connection handshake.

.PARAMETER InitialPromptTimeoutSeconds
    Maximum time in seconds to wait for the first device prompt after login. This window
    covers the full SSH authentication sequence, any MOTD/banner output, and the appearance
    of the CLI prompt. Increase this value for devices that display long banners or
    authenticate slowly. Applies only to the initial connection wait; per-command waits
    are governed by CommandTimeoutSeconds. Valid range: 5-300. Default is 60.

.PARAMETER AllocatePTY
    Force pseudo-terminal (PTY) allocation by using -tt instead of -T when
    launching ssh.exe. Required for devices whose login sequence depends on a
    terminal (e.g. devices that run stty during startup). When $false (default),
    the script auto-detects stty failures and retries with PTY automatically.
    Set to $true to skip the failed first attempt for known PTY-dependent devices.

.PARAMETER PingTest
    When $true, sends a single ICMP ping to each device before attempting SSH.
    Devices that do not respond are skipped immediately, avoiding the full SSH
    connection timeout. Disable if your network blocks ICMP but allows SSH.
    Default is $true.

.PARAMETER JsonDirectory
    Directory where JSON output files will be saved. Created automatically if it doesn't exist.
    Each run produces a timestamped session summary (ssh-session-<timestamp>.json) plus one
    per-device file (<name>_<ip>_<timestamp>.json) for each successful connection.
    Default is .\json.

.PARAMETER NetcortexDirectory
    Directory where per-device raw output text files will be saved. Created automatically
    if it doesn't exist. Each successful device gets its own file using the naming
    convention: DeviceName_IPAddress_Timestamp.txt. Failed connections are skipped.
    Default is .\netcortex.

.PARAMETER LogEnabled
    Enable or disable log output files. When $false, no .log files are written to LogDirectory.
    Default is $true.

.PARAMETER JsonEnabled
    Enable or disable JSON output files. When $false, no session or per-device .json files
    are written to JsonDirectory. Default is $false.

.PARAMETER JsonSessionFileEnabled
    Enable or disable the session summary JSON file (ssh-session-<timestamp>.json).
    When $false, per-device JSON files are still written if JsonEnabled is $true, but the
    session summary file is skipped. Default is $true.

.PARAMETER NetcortexEnabled
    Enable or disable Netcortex raw output text files. When $false, no .txt files are written
    to NetcortexDirectory. Default is $false.

.PARAMETER CredentialLabel
    The target name used to store and retrieve credentials in Windows Credential Manager.
    Allows different credential sets to be stored for different environments.
    Default is "SSH-CMD-Runner".

.PARAMETER ClearCredentials
    When $true, deletes any stored credentials matching CredentialLabel before prompting
    for new ones. Useful after a password rotation. Default is $false.

.PARAMETER CompressOutput
    When $true, creates a compressed archive of all output directories at the end of the run.
    Uses PowerShell's built-in Compress-Archive to create a .zip archive. Default is $false.

.PARAMETER CompressWhen
    Controls when the archive is created. "Always" creates it regardless of device results.
    "SuccessOnly" skips compression if any device failed. Default is "Always".

.PARAMETER DeleteAfterCompress
    When $true, removes the original output directories after the archive is successfully
    created. Has no effect if CompressOutput is $false or if archive creation fails.
    Default is $false.

.PARAMETER CompressOnly
    When specified, compresses existing output directories and exits without connecting
    to any devices. Useful for archiving output from a previous run. Ignores CompressWhen
    (always compresses). Respects DeleteAfterCompress and output directory paths.

.EXAMPLE
    .\Invoke-NetworkSSH.ps1

    Runs with defaults: devices.txt, commands.txt, .\SSH_Logs, 10s timeout.

.EXAMPLE
    .\Invoke-NetworkSSH.ps1 -DeviceListFile .\devices.txt -CommandsFile .\commands.txt

.EXAMPLE
    .\Invoke-NetworkSSH.ps1 -LogDirectory "C:\Logs\Network" -TimeoutSeconds 15

.EXAMPLE
    .\Invoke-NetworkSSH.ps1 -ExtraSSHOptions '-o','KexAlgorithms=+diffie-hellman-group1-sha1','-o','HostKeyAlgorithms=+ssh-rsa'

    A common need is for legacy devices that require older key exchange and host key algorithms.

.EXAMPLE
    .\Invoke-NetworkSSH.ps1 -CommandDelayMs 1000

    Uses a 1-second delay between commands for slower devices or large output.

.EXAMPLE
    .\ssh-cmd-runner.ps1 -JsonDirectory "C:\Data\NetworkJSON"

    Writes the JSON output file to C:\Data\NetworkJSON\ instead of the default .\json\ folder.

.EXAMPLE
    .\ssh-cmd-runner.ps1 -NetcortexDirectory "C:\Data\NetcortexOutput"

    Writes per-device raw output files to C:\Data\NetcortexOutput\ instead of the default .\netcortex\ folder.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Path to file with one IP per line")]
    [string]$DeviceListFile = ".\devices.txt",

    [Parameter(Mandatory = $false, HelpMessage = "Directory with per-OS command files (default: .\commands)")]
    [string]$CommandsDirectory = ".\commands",

    [Parameter(Mandatory = $false)]
    [string]$LogDirectory = ".\logs",

    [Parameter(Mandatory = $false)]
    [ValidateRange(5, 120)]
    [int]$TimeoutSeconds = 10,

    [Parameter(Mandatory = $false, HelpMessage = "Additional SSH options for legacy/special devices (e.g. '-o','KexAlgorithms=+diffie-hellman-group1-sha1')")]
    [string[]]$ExtraSSHOptions = @(),

    [Parameter(Mandatory = $false, HelpMessage = "Delay in milliseconds between sending each command to the device (default 100)")]
    [ValidateRange(0, 10000)]
    [int]$CommandDelayMs = 100,

    [Parameter(Mandatory = $false, HelpMessage = "Seconds to wait for device prompt after each command (default 30). Increase for commands with large output.")]
    [ValidateRange(5, 600)]
    [int]$CommandTimeoutSeconds = 30,

    [Parameter(Mandatory = $false, HelpMessage = "Seconds to wait for the first device prompt after login, covering auth + banner + prompt (default 60). Separate from CommandTimeoutSeconds.")]
    [ValidateRange(5, 300)]
    [int]$InitialPromptTimeoutSeconds = 60,

    [Parameter(Mandatory = $false, HelpMessage = "Force PTY allocation (-tt) for devices requiring a terminal (default: false, auto-detects)")]
    [bool]$AllocatePTY = $false,

    [Parameter(Mandatory = $false, HelpMessage = "Ping each device before SSH to skip unreachable hosts (default: true)")]
    [bool]$PingTest = $true,

    [Parameter(Mandatory = $false, HelpMessage = "Directory where the JSON output file will be saved. Created automatically if it doesn't exist.")]
    [string]$JsonDirectory = ".\json",

    [Parameter(Mandatory = $false, HelpMessage = "Directory where per-device raw output text files will be saved. Created automatically if it doesn't exist.")]
    [string]$NetcortexDirectory = ".\netcortex",

    [Parameter(Mandatory = $false, HelpMessage = "Enable or disable log output files (default: true)")]
    [bool]$LogEnabled = $true,

    [Parameter(Mandatory = $false, HelpMessage = "Enable or disable JSON output files (default: false)")]
    [bool]$JsonEnabled = $false,

    [Parameter(Mandatory = $false, HelpMessage = "Enable or disable session summary JSON file (default: true)")]
    [bool]$JsonSessionFileEnabled = $true,

    [Parameter(Mandatory = $false, HelpMessage = "Enable or disable Netcortex raw output files (default: false)")]
    [bool]$NetcortexEnabled = $false,

    [Parameter(Mandatory = $false, HelpMessage = "Windows Credential Manager label used to store and retrieve SSH credentials (default: SSH-CMD-Runner)")]
    [string]$CredentialLabel = "SSH-CMD-Runner",

    [Parameter(Mandatory = $false, HelpMessage = "Clear stored credentials matching CredentialLabel and prompt for new ones (default: false)")]
    [bool]$ClearCredentials = $false,

    [Parameter(Mandatory = $false, HelpMessage = "Create a compressed archive of all output directories after the run (default: false)")]
    [bool]$CompressOutput = $false,

    [Parameter(Mandatory = $false, HelpMessage = "When to compress: Always or SuccessOnly (default: Always)")]
    [ValidateSet('Always', 'SuccessOnly')]
    [string]$CompressWhen = "Always",

    [Parameter(Mandatory = $false, HelpMessage = "Delete output directories after successful archive creation (default: false)")]
    [bool]$DeleteAfterCompress = $false,

    [Parameter(Mandatory = $false, HelpMessage = "Compress existing output directories and exit without processing devices")]
    [switch]$CompressOnly
)

# ---------------------------------------------
# CONFIG FILE LOADING
# Precedence: CLI args > config.json > param() defaults
# ---------------------------------------------
$_scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$configPath = Join-Path $_scriptRoot "config.json"

if (Test-Path $configPath -PathType Leaf) {
    try {
        $config = Get-Content $configPath -Raw | ConvertFrom-Json
    }
    catch {
        Write-Host "ERROR: config.json could not be parsed: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }

    $requiredKeys = @(
        'DeviceListFile', 'CommandsDirectory', 'LogDirectory', 'TimeoutSeconds',
        'ExtraSSHOptions', 'CommandDelayMs', 'CommandTimeoutSeconds', 'InitialPromptTimeoutSeconds',
        'AllocatePTY', 'PingTest',
        'JsonDirectory', 'NetcortexDirectory', 'LogEnabled', 'JsonEnabled', 'JsonSessionFileEnabled', 'NetcortexEnabled',
        'CredentialLabel', 'ClearCredentials',
        'CompressOutput', 'CompressWhen', 'DeleteAfterCompress'
    )
    $missingKeys = @($requiredKeys | Where-Object { $config.PSObject.Properties.Name -notcontains $_ })
    if ($missingKeys.Count -gt 0) {
        Write-Host "ERROR: config.json is missing required parameter(s): $($missingKeys -join ', ')" -ForegroundColor Red
        exit 1
    }

    if (-not $PSBoundParameters.ContainsKey('DeviceListFile'))        { $DeviceListFile        = $config.DeviceListFile }
    if (-not $PSBoundParameters.ContainsKey('CommandsDirectory'))     { $CommandsDirectory     = $config.CommandsDirectory }
    if (-not $PSBoundParameters.ContainsKey('LogDirectory'))          { $LogDirectory          = $config.LogDirectory }
    if (-not $PSBoundParameters.ContainsKey('TimeoutSeconds'))        { $TimeoutSeconds        = [int]$config.TimeoutSeconds }
    if (-not $PSBoundParameters.ContainsKey('ExtraSSHOptions'))       { $ExtraSSHOptions       = [string[]]$config.ExtraSSHOptions }
    if (-not $PSBoundParameters.ContainsKey('CommandDelayMs'))        { $CommandDelayMs        = [int]$config.CommandDelayMs }
    if (-not $PSBoundParameters.ContainsKey('CommandTimeoutSeconds'))        { $CommandTimeoutSeconds        = [int]$config.CommandTimeoutSeconds }
    if (-not $PSBoundParameters.ContainsKey('InitialPromptTimeoutSeconds')) { $InitialPromptTimeoutSeconds = [int]$config.InitialPromptTimeoutSeconds }
    if (-not $PSBoundParameters.ContainsKey('AllocatePTY'))              { $AllocatePTY              = [bool]$config.AllocatePTY }
    if (-not $PSBoundParameters.ContainsKey('PingTest'))                { $PingTest                = [bool]$config.PingTest }
    if (-not $PSBoundParameters.ContainsKey('JsonDirectory'))         { $JsonDirectory         = $config.JsonDirectory }
    if (-not $PSBoundParameters.ContainsKey('NetcortexDirectory'))        { $NetcortexDirectory        = $config.NetcortexDirectory }
    if (-not $PSBoundParameters.ContainsKey('LogEnabled'))            { $LogEnabled            = [bool]$config.LogEnabled }
    if (-not $PSBoundParameters.ContainsKey('JsonEnabled'))              { $JsonEnabled              = [bool]$config.JsonEnabled }
    if (-not $PSBoundParameters.ContainsKey('JsonSessionFileEnabled')) { $JsonSessionFileEnabled = [bool]$config.JsonSessionFileEnabled }
    if (-not $PSBoundParameters.ContainsKey('NetcortexEnabled'))       { $NetcortexEnabled       = [bool]$config.NetcortexEnabled }
    if (-not $PSBoundParameters.ContainsKey('CredentialLabel'))   { $CredentialLabel    = $config.CredentialLabel }
    if (-not $PSBoundParameters.ContainsKey('ClearCredentials'))  { $ClearCredentials   = [bool]$config.ClearCredentials }
    if (-not $PSBoundParameters.ContainsKey('CompressOutput'))       { $CompressOutput       = [bool]$config.CompressOutput }
    if (-not $PSBoundParameters.ContainsKey('CompressWhen'))         { $CompressWhen         = $config.CompressWhen }
    if (-not $PSBoundParameters.ContainsKey('DeleteAfterCompress'))  { $DeleteAfterCompress  = [bool]$config.DeleteAfterCompress }
}

# ---------------------------------------------
# INITIALIZE
# ---------------------------------------------
$ErrorActionPreference = "Stop"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Start a runtime transcript to capture all console output.
# Survives force-closed PowerShell windows — the transcript is flushed incrementally.
$runtimeLogDir = Join-Path $_scriptRoot "runtime-logs"
if (-not (Test-Path $runtimeLogDir)) { New-Item -ItemType Directory -Path $runtimeLogDir -Force | Out-Null }
$transcriptPath = Join-Path $runtimeLogDir "runtime-${timestamp}.log"
try { Start-Transcript -Path $transcriptPath -Append | Out-Null } catch { Write-Verbose "Transcript not available: $($_.Exception.Message)" }
$runDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$osPlatform = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription.Trim()
$psEngine = "PowerShell $($PSVersionTable.PSVersion.ToString())"
$separator = ("=" * 59)
$thinSep = ("-" * 40)

# Valid OS types and their session behaviors.
# PagingCommand       : sent silently after login to disable output paging
# RequirePTY          : force PTY allocation (-tt) for this OS (overrides AllocatePTY)
# ExitCommands        : sequence sent to close the session cleanly (e.g. "logout" then "n" for save prompt)
# InteractivePattern  : regex matching mid-command prompts that need auto-response "y"
#                       (e.g. WLC pagination "would you like to display the next N entries? (y/n)")
# SendInitialNewline  : send an empty line after SSH session starts to trigger the CLI prompt
#                       (some devices wait for a keystroke before displaying the prompt)
$validOSTypes = @{
    'cisco-iosxe'      = @{ PagingCommand = 'terminal length 0';     RequirePTY = $false; ExitCommands = @('exit');        InteractivePattern = ''; SendInitialNewline = $false }
    'cisco-iosxr'      = @{ PagingCommand = 'terminal length 0';     RequirePTY = $false; ExitCommands = @('exit');        InteractivePattern = ''; SendInitialNewline = $false }
    'cisco-nxos'       = @{ PagingCommand = 'terminal length 0';     RequirePTY = $true;  ExitCommands = @('exit');        InteractivePattern = ''; SendInitialNewline = $false }
    'cisco-wlc-aireos' = @{ PagingCommand = 'config paging disable'; RequirePTY = $true;  ExitCommands = @('logout', 'n'); InteractivePattern = '\(y/n\)\s*$'; SendInitialNewline = $true }
    'cisco-wlc-iosxe'  = @{ PagingCommand = 'terminal length 0';     RequirePTY = $false; ExitCommands = @('exit');        InteractivePattern = ''; SendInitialNewline = $false }
}

# Validate input files exist (skip when only compressing)
if (-not $CompressOnly -and -not (Test-Path $DeviceListFile -PathType Leaf)) {
    Write-Error "Device list file not found: '$DeviceListFile'"
    exit 1
}

# Verify ssh.exe is available (skip when only compressing)
if (-not $CompressOnly) {
    $sshPath = Get-Command ssh.exe -ErrorAction SilentlyContinue
    if (-not $sshPath) {
        Write-Error "ssh.exe not found in PATH. Install OpenSSH client (Windows Optional Feature) and retry."
        exit 1
    }
    Write-Verbose "Using SSH client: $($sshPath.Source)"
}

# Create log directory
if ($LogEnabled -and -not (Test-Path $LogDirectory)) {
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
}

# Create JSON output directory
if ($JsonEnabled -and -not (Test-Path $JsonDirectory)) {
    New-Item -ItemType Directory -Path $JsonDirectory -Force | Out-Null
}

# Create netcortex output directory
if ($NetcortexEnabled -and -not (Test-Path $NetcortexDirectory)) {
    New-Item -ItemType Directory -Path $NetcortexDirectory -Force | Out-Null
}

# Skip device and command loading when only compressing
if (-not $CompressOnly) {
    # Read device CSV (IP,OS columns with header row)
    # Pre-filter comment lines (# prefix) and blank lines before CSV parsing
    # so that free-form comments don't break Import-Csv column expectations.
    $csvLines = @(Get-Content $DeviceListFile | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_) -and -not $_.TrimStart().StartsWith('#')
    })
    if ($csvLines.Count -le 1) {
        # Need at least a header row + one data row
        Write-Error "No devices found in '$DeviceListFile'."
        exit 1
    }
    $devicesCsv = @($csvLines | ConvertFrom-Csv)
    if ($devicesCsv.Count -eq 0) {
        Write-Error "No devices found in '$DeviceListFile'."
        exit 1
    }

    # Validate required columns
    $csvColumns = $devicesCsv[0].PSObject.Properties.Name
    if ('IP' -notin $csvColumns -or 'OS' -notin $csvColumns) {
        Write-Error "Device CSV must have 'IP' and 'OS' columns. Found: $($csvColumns -join ', ')"
        exit 1
    }

    # Validate OS values and filter blanks/comments
    $devices = @()
    foreach ($row in $devicesCsv) {
        $ip = $row.IP.Trim()
        $os = $row.OS.Trim().ToLower()
        if ([string]::IsNullOrWhiteSpace($ip) -or $ip.StartsWith('#')) { continue }
        if ($os -notin $validOSTypes.Keys) {
            Write-Error "Unknown OS type '$os' for device $ip. Valid: $($validOSTypes.Keys -join ', ')"
            exit 1
        }
        $devices += [PSCustomObject]@{ IP = $ip; OS = $os }
    }

    if ($devices.Count -eq 0) {
        Write-Error "No valid devices found in '$DeviceListFile'."
        exit 1
    }

    # Validate commands directory exists
    if (-not (Test-Path $CommandsDirectory -PathType Container)) {
        Write-Error "Commands directory not found: '$CommandsDirectory'"
        exit 1
    }

    # Load per-OS command files for each OS type referenced in the device list
    $uniqueOSTypes = @($devices | ForEach-Object { $_.OS } | Sort-Object -Unique)
    $commandsByOS = @{}

    foreach ($osType in $uniqueOSTypes) {
        $cmdFile = Join-Path $CommandsDirectory "$osType.txt"
        if (-not (Test-Path $cmdFile -PathType Leaf)) {
            Write-Error "Command file not found for OS '$osType': '$cmdFile'"
            exit 1
        }
        $cmds = Get-Content $cmdFile |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -ne "" -and $_ -notmatch "^\s*#" }
        if ($cmds.Count -eq 0) {
            Write-Error "No valid commands found in '$cmdFile'."
            exit 1
        }
        $commandsByOS[$osType] = $cmds
    }

    # Load optional per-OS Netcortex command files. These define which commands
    # appear in Netcortex output and in what order. Commands in the Netcortex list
    # that are missing from the standard list are appended to the session command
    # list so they're actually executed during the SSH session.
    $netcortexCommandsByOS = @{}
    if ($NetcortexEnabled) {
        $netcortexDir = Join-Path $CommandsDirectory "netcortex"
        foreach ($osType in $uniqueOSTypes) {
            $ncFile = Join-Path $netcortexDir "$osType.txt"
            if (Test-Path $ncFile -PathType Leaf) {
                $ncCmds = Get-Content $ncFile |
                    ForEach-Object { $_.Trim() } |
                    Where-Object { $_ -ne "" -and $_ -notmatch "^\s*#" }
                if ($ncCmds.Count -gt 0) {
                    $netcortexCommandsByOS[$osType] = $ncCmds
                }
            }
        }

        # Merge Netcortex-only commands into the standard command list.
        # Standard commands keep their original order; Netcortex commands
        # not already present are appended at the end.
        foreach ($osType in @($netcortexCommandsByOS.Keys)) {
            $stdCmds = $commandsByOS[$osType]
            $stdSet  = [System.Collections.Generic.HashSet[string]]::new(
                [string[]]$stdCmds,
                [System.StringComparer]::OrdinalIgnoreCase
            )
            $additions = @($netcortexCommandsByOS[$osType] | Where-Object {
                -not $stdSet.Contains($_)
            })
            if ($additions.Count -gt 0) {
                $commandsByOS[$osType] = @($stdCmds) + $additions
            }
        }
    }

    # Pre-flight check: cisco-wlc-aireos devices require "show sysinfo" in their
    # command file to extract the device hostname. The WLC prompt does not reliably
    # contain the hostname, so the System Name field from this command is the only
    # source. Warn the user if it's missing and let them decide how to proceed.
    if ('cisco-wlc-aireos' -in $uniqueOSTypes) {
        $aireosCommands = $commandsByOS['cisco-wlc-aireos']
        $hasSysinfo = $aireosCommands | Where-Object { $_ -match '^\s*show\s+sysinfo\s*$' }
        if (-not $hasSysinfo) {
            Write-Host ""
            Write-Host "WARNING: cisco-wlc-aireos command file does not include 'show sysinfo'." -ForegroundColor Yellow
            Write-Host "  WLC AireOS devices require this command to determine the device hostname." -ForegroundColor Yellow
            Write-Host "  Without it, devices will be logged as 'unknown'." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  [S] Skip all cisco-wlc-aireos devices and continue" -ForegroundColor Cyan
            Write-Host "  [A] Abort the run" -ForegroundColor Cyan
            Write-Host ""
            $response = (Read-Host "  Choice (S/A)").ToUpper()
            if ($response -eq 'S') {
                Write-Host "  Skipping all cisco-wlc-aireos devices." -ForegroundColor Yellow
                $devices = @($devices | Where-Object { $_.OS -ne 'cisco-wlc-aireos' })
                $uniqueOSTypes = @($devices | ForEach-Object { $_.OS } | Sort-Object -Unique)
                if ($devices.Count -eq 0) {
                    Write-Host "  No devices remaining after skipping. Exiting." -ForegroundColor Red
                    exit 0
                }
            } else {
                Write-Host "  Run aborted." -ForegroundColor Red
                exit 1
            }
        }
    }
}

# ---------------------------------------------
# CREDENTIAL MANAGER (Windows native P/Invoke — no external modules)
# Must be defined before the credential management block that calls it.
# ---------------------------------------------
if (-not ([System.Management.Automation.PSTypeName]'CredentialManager').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class CredentialManager {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDENTIAL {
        public uint   Flags;
        public uint   Type;
        public string TargetName;
        public string Comment;
        public long   LastWritten;
        public uint   CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint   Persist;
        public uint   AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredRead(string target, uint type, int flags, out IntPtr ptr);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredWrite([In] ref CREDENTIAL cred, uint flags);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredDelete(string target, uint type, int flags);

    [DllImport("advapi32.dll")]
    private static extern void CredFree(IntPtr ptr);

    public static string ReadUsername(string target) {
        IntPtr ptr;
        if (!CredRead(target, 1, 0, out ptr)) return null;
        try {
            var c = (CREDENTIAL)Marshal.PtrToStructure(ptr, typeof(CREDENTIAL));
            return c.UserName;
        } finally { CredFree(ptr); }
    }

    public static string ReadPassword(string target) {
        IntPtr ptr;
        if (!CredRead(target, 1, 0, out ptr)) return null;
        try {
            var c = (CREDENTIAL)Marshal.PtrToStructure(ptr, typeof(CREDENTIAL));
            if (c.CredentialBlobSize == 0 || c.CredentialBlob == IntPtr.Zero) return string.Empty;
            return Marshal.PtrToStringUni(c.CredentialBlob, (int)c.CredentialBlobSize / 2);
        } finally { CredFree(ptr); }
    }

    public static bool WriteCredential(string target, string username, string password) {
        byte[] blob = Encoding.Unicode.GetBytes(password);
        IntPtr blobPtr = Marshal.AllocHGlobal(blob.Length);
        try {
            Marshal.Copy(blob, 0, blobPtr, blob.Length);
            CREDENTIAL c = new CREDENTIAL();
            c.Type               = 1;  // CRED_TYPE_GENERIC
            c.TargetName         = target;
            c.UserName           = username;
            c.CredentialBlob     = blobPtr;
            c.CredentialBlobSize = (uint)blob.Length;
            c.Persist            = 2;  // CRED_PERSIST_LOCAL_MACHINE
            return CredWrite(ref c, 0);
        } finally { Marshal.FreeHGlobal(blobPtr); }
    }

    public static bool DeleteCredential(string target) {
        IntPtr ptr;
        if (!CredRead(target, 1, 0, out ptr)) return true;  // already absent — nothing to do
        CredFree(ptr);
        return CredDelete(target, 1, 0);
    }
}
'@ -Language CSharp
}


# ---------------------------------------------
# HELPER FUNCTION: Detect SSH authentication failure from stderr.
# Returns $true when stderr contains a known credential-rejection pattern.
# Timeouts, connectivity errors, and host-key issues do NOT match.
# ---------------------------------------------
function Test-IsAuthFailure {
    param([string]$StdErr)

    # Standard OpenSSH rejection messages
    if ($StdErr -match 'Permission denied|Authentication failed|Too many authentication failures') { return $true }

    # Vendor-agnostic detection for devices (e.g. Cisco IOS) that never emit
    # "Permission denied" but do call SSH_ASKPASS for each password attempt.
    # Two or more read_passphrase calls means the first password was rejected
    # and SSH requested a second attempt — definitive credential failure.
    $askpassCount = ([regex]::Matches($StdErr, 'read_passphrase')).Count
    if ($askpassCount -ge 2) { return $true }

    # Single askpass call followed by the server closing the connection means
    # the device accepted only one attempt before disconnecting (auth rejected).
    if ($askpassCount -ge 1 -and ($StdErr -match 'Connection closed by')) { return $true }

    return $false
}

# ---------------------------------------------
# HELPER FUNCTION: Write/overwrite the SSH_ASKPASS .cmd helper.
# Encapsulates cmd.exe special-character escaping so the same logic
# can be called on initial setup and again after a credential update.
# ---------------------------------------------
function Set-AskPassScript {
    param([string]$ScriptPath, [string]$Password)
    $escaped = $Password
    $escaped = $escaped.Replace('^', '^^')
    $escaped = $escaped.Replace('&', '^&')
    $escaped = $escaped.Replace('|', '^|')
    $escaped = $escaped.Replace('<', '^<')
    $escaped = $escaped.Replace('>', '^>')
    $escaped = $escaped.Replace('!', '^!')
    $escaped = $escaped.Replace('%', '%%')
    Set-Content -Path $ScriptPath -Value "@echo $escaped" -Force
}

# ---------------------------------------------
# CREDENTIAL MANAGEMENT (skip when only compressing)
# Precedence: Windows Credential Manager > interactive prompt.
# Credentials are written to Credential Manager only after a successful
# device connection confirms they work. ClearCredentials forces a fresh
# prompt and removes any stored entry before looking up new ones.
# ---------------------------------------------
if (-not $CompressOnly) {
Write-Host ""

if ($ClearCredentials) {
    [CredentialManager]::DeleteCredential($CredentialLabel) | Out-Null
    Write-Host "Stored credentials for '$CredentialLabel' cleared." -ForegroundColor Yellow
}

$storedUsername = [CredentialManager]::ReadUsername($CredentialLabel)
$storedPassword = [CredentialManager]::ReadPassword($CredentialLabel)

if ($storedUsername -and $null -ne $storedPassword -and -not $ClearCredentials) {
    $username         = $storedUsername
    $password         = $storedPassword
    $credentialsSaved = $true   # already in Credential Manager — no re-save needed
    Write-Host "Using stored credentials for '$username' (label: $CredentialLabel)." -ForegroundColor Cyan
}
else {
    $credential = Get-Credential -Message "Enter SSH credentials for network devices"
    if ($null -eq $credential) {
        Write-Host "Credential prompt cancelled. Aborting." -ForegroundColor Red
        exit 1
    }
    $username         = $credential.UserName
    $password         = $credential.GetNetworkCredential().Password
    $credentialsSaved = $false  # freshly entered — save after first verified success
}

# ---------------------------------------------
# SSH_ASKPASS HELPER
# Creates a temporary .cmd script that ssh.exe calls to retrieve the
# password, avoiding interactive prompts per device. Set-AskPassScript
# handles cmd.exe special-character escaping and is called again
# whenever credentials are updated mid-run.
# ---------------------------------------------
$askPassDir    = Join-Path $env:TEMP "ssh_askpass_$timestamp"
New-Item -ItemType Directory -Path $askPassDir -Force | Out-Null
$askPassScript = Join-Path $askPassDir "askpass.cmd"
Set-AskPassScript -ScriptPath $askPassScript -Password $password
}   # end if (-not $CompressOnly) — credential management

# ---------------------------------------------
# HELPER FUNCTION: Parse device hostname from SSH output
# Matches common network device prompt patterns:
#   Cisco IOS/NX-OS  :  hostname#  hostname>  hostname(config)#
#   Arista EOS       :  hostname#  hostname>  hostname(config)#
#   Juniper JunOS    :  user@hostname>  user@hostname#
#   Palo Alto        :  user@hostname>  user@hostname#
#   HP/Aruba         :  hostname#  hostname>
#   Cisco WLC        :  (any text) >  — hostname from "show sysinfo" System Name field
#   Linux-based NOS  :  user@hostname:~$  [user@hostname ~]$
# ---------------------------------------------
function Get-HostnameFromPrompt {
    param([string]$Output)

    $lines = $Output -split "`r?`n"

    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }

        # Cisco IOS-XR style: RP/0/RSP0/CPU0:hostname# or RP/0/RP0/CPU0:hostname(config)#
        if ($trimmed -match '^[A-Za-z]+(?:/[A-Za-z0-9]+)+:([A-Za-z0-9][A-Za-z0-9._-]*)(?:\([A-Za-z0-9/_-]*\))?[#>]') {
            return $Matches[1]
        }

        # Juniper / PAN style: user@hostname> or user@hostname# or user@hostname:~$
        if ($trimmed -match '^\S*?@([A-Za-z0-9_-]+)[>#:\$%]') {
            return $Matches[1]
        }

        # Cisco / Arista / HP style: hostname# or hostname> or hostname(config-xxx)#
        if ($trimmed -match '^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\([A-Za-z0-9/_-]*\))?[#>]\s*$') {
            $candidate = $Matches[1]
            $falsePositives = @('yes', 'no', 'ok', 'error', 'warning', 'info', 'true', 'false')
            if ($candidate.Length -ge 2 -and $candidate.ToLower() -notin $falsePositives) {
                return $candidate
            }
        }

        # Linux-style: [user@hostname ~]$ or [user@hostname ~]#
        if ($trimmed -match '^\[?\S+?@([A-Za-z0-9_-]+)\s') {
            return $Matches[1]
        }

        # Cisco WLC AireOS: hostname from "show sysinfo" output (System Name field).
        # WLC prompts like "(Cisco Controller) >", "(WLC7) >", etc. are not reliable
        # sources of hostname — always extract from the System Name field instead.
        if ($trimmed -match '^System Name\.+\s+(\S+)') {
            return $Matches[1]
        }
    }

    return $null
}

# ---------------------------------------------
# HELPER FUNCTION: Sanitize strings for filenames
# ---------------------------------------------
function ConvertTo-SafeFileName {
    param([string]$InputString)
    return ($InputString -replace '[\\/:*?"<>|]', '_')
}

# ---------------------------------------------
# HELPER FUNCTION: Read stdout lines from a ConcurrentQueue until a device
# CLI prompt is detected or the timeout expires.
# Returns $true if a prompt was found, $false if the call timed out.
# When a prompt is found it is NOT written to Builder — instead it is returned
# via the [ref] $PromptText parameter so the caller can join it with the
# echoed command that follows, reproducing the natural "hostname#command" layout.
#
# Optional interactive prompt handling:
#   $StdIn            — the process stdin stream (for writing auto-responses)
#   $InteractiveRegex — compiled regex matching mid-command prompts (e.g. WLC
#                       pagination "(y/n)"). When a dequeued line matches, "y"
#                       is written to stdin and the line is discarded (not logged).
# ---------------------------------------------
function Read-UntilPrompt {
    param(
        [System.Collections.Concurrent.ConcurrentQueue[string]]$Queue,
        [System.Text.StringBuilder]$Builder,
        [System.Text.RegularExpressions.Regex]$PromptRegex,
        [int]$TimeoutMs,
        [ref]$PromptText,
        [System.IO.StreamWriter]$StdIn = $null,
        [System.Text.RegularExpressions.Regex]$InteractiveRegex = $null,
        [System.Text.RegularExpressions.Regex]$PagerRegex = $null,
        [System.Text.StringBuilder]$StdErrBuilder = $null
    )

    # Known fatal SSH error patterns — if any appear in stderr, fail immediately
    # instead of waiting the full timeout.
    $fatalSshPatterns = @(
        'Unable to negotiate',
        'no matching cipher found',
        'no matching key exchange method found',
        'no matching host key type found',
        'Connection refused',
        'Connection reset',
        'Connection closed',
        'Connection timed out',
        'No route to host',
        'Network is unreachable',
        'Host key verification failed',
        'kex_exchange_identification.*Connection'
    )
    $fatalSshRegex = ($fatalSshPatterns -join '|')

    # ANSI escape sequence pattern — safety strip for any sequences that
    # leak through the runspace's cleaning pass (e.g. split across reads).
    $ansiPattern = '\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b[()][0-9A-Za-z]|\x1b[\x20-\x2F][\x30-\x7E]|\x1b.'

    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    $line = $null
    $lastStderrCheck = [DateTime]::UtcNow
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($Queue.TryDequeue([ref]$line)) {
            if ($null -eq $line) {
                # Null sentinel: stream closed. Treat as prompt-found so the
                # caller doesn't hang, but leave PromptText empty.
                if ($null -ne $PromptText) { $PromptText.Value = "" }
                return $true
            }
            # Strip any residual ANSI codes the runspace may not have caught
            # (e.g. sequences split across read boundaries).
            $line = $line -replace $ansiPattern, ''
            if ($PromptRegex.IsMatch($line.TrimEnd())) {
                # Hold the prompt — do NOT append it to Builder yet.
                # The caller will prepend it to the echoed command line.
                if ($null -ne $PromptText) { $PromptText.Value = $line.TrimEnd() }
                return $true
            }
            # Auto-respond to pager prompts (bare ":" from more/less pager in login banners).
            # Send a Space to page through, discard the pager line, and keep waiting.
            if ($null -ne $PagerRegex -and $null -ne $StdIn -and $PagerRegex.IsMatch($line.TrimEnd())) {
                $StdIn.Write(" ")
                $StdIn.Flush()
                # Reset deadline since the device is actively sending data.
                $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
                continue
            }
            # Auto-respond to interactive mid-command prompts (e.g. WLC pagination).
            # Send "y", discard the prompt line (don't log it), and keep waiting.
            if ($null -ne $InteractiveRegex -and $null -ne $StdIn -and $InteractiveRegex.IsMatch($line.TrimEnd())) {
                $StdIn.WriteLine("y")
                $StdIn.Flush()
                # Don't append to Builder — keep pagination prompts out of the log.
                # Reset deadline since the device is actively sending data.
                $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
                continue
            }
            $Builder.AppendLine($line) | Out-Null
        }
        else {
            Start-Sleep -Milliseconds 50

            # Periodically check stderr for fatal SSH errors (every ~500ms).
            # This catches connection failures, cipher mismatches, etc. immediately
            # instead of waiting the full timeout.
            if ($null -ne $StdErrBuilder -and ([DateTime]::UtcNow - $lastStderrCheck).TotalMilliseconds -ge 500) {
                $lastStderrCheck = [DateTime]::UtcNow
                $stderrContent = $StdErrBuilder.ToString()
                if ($stderrContent -match $fatalSshRegex) {
                    # Extract the specific fatal error line for the error message.
                    $fatalLine = ($stderrContent -split "`n" | Where-Object { $_ -match $fatalSshRegex } | Select-Object -First 1).Trim()
                    if ($null -ne $PromptText) { $PromptText.Value = "" }
                    throw "SSH connection failed: $fatalLine"
                }
            }
        }
    }
    return $false
}

# ---------------------------------------------
# HELPER FUNCTION: Compress output directories into nested zip archive
# Creates individual zips for each output directory (logs.zip, json.zip, etc.)
# then bundles them into a single outer archive: ssh-session-<timestamp>.zip
# ---------------------------------------------
function Invoke-CompressOutput {
    param(
        [string[]]$OutputDirectories,
        [bool]$Cleanup = $false
    )

    $archiveTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $archiveName = "ssh-session-${archiveTimestamp}.zip"
    $archivePath = Join-Path $_scriptRoot $archiveName

    # Filter to directories that exist and contain at least one file
    $dirsToArchive = @($OutputDirectories) |
        Where-Object {
            (Test-Path $_ -PathType Container) -and
            (Get-ChildItem -LiteralPath $_ -Recurse -File -ErrorAction SilentlyContinue |
             Select-Object -First 1)
        }

    Write-Host ""
    if ($dirsToArchive.Count -eq 0) {
        Write-Host "Compression skipped: no output directories with files found on disk." -ForegroundColor Yellow
        return
    }

    Write-Host "Compressing output directories ..." -ForegroundColor Cyan

    $archiveSuccess = $false
    $tempDir = Join-Path $_scriptRoot ".compress-temp-$archiveTimestamp"
    try {
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

        # Create an individual zip for each output directory
        foreach ($dir in $dirsToArchive) {
            $leafName = (Get-Item $dir).Name
            $innerZip = Join-Path $tempDir "$leafName.zip"
            Compress-Archive -Path (Join-Path $dir '*') -DestinationPath $innerZip -Force
            Write-Host "  Packed: $leafName.zip" -ForegroundColor Gray
        }

        # Bundle individual zips into the final outer archive
        Compress-Archive -Path (Join-Path $tempDir '*') -DestinationPath $archivePath -Force
        $archiveSuccess = (Test-Path $archivePath)
    }
    catch {
        Write-Host "  ERROR: Compression failed - $($_.Exception.Message)" -ForegroundColor Red
    }
    finally {
        # Always clean up the temp directory
        if (Test-Path $tempDir) {
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    if ($archiveSuccess) {
        $archiveItem    = Get-Item $archivePath
        $archiveSizeStr = if ($archiveItem.Length -ge 1MB) {
            "{0:0.0} MB" -f ($archiveItem.Length / 1MB)
        }
        else {
            "{0:0.0} KB" -f ($archiveItem.Length / 1KB)
        }
        Write-Host "  Archive: $archiveName ($archiveSizeStr)" -ForegroundColor Green

        if ($Cleanup) {
            foreach ($dir in $dirsToArchive) {
                try {
                    Remove-Item -Path $dir -Recurse -Force -ErrorAction Stop
                    Write-Verbose "Removed output directory: $dir"
                }
                catch {
                    Write-Warning "Could not remove '$dir': $($_.Exception.Message)"
                }
            }
            Write-Host "  Output directories removed." -ForegroundColor Gray
        }
    }
    else {
        Write-Host "  WARNING: Archive creation failed. Output directories were not removed." -ForegroundColor Red
    }
}

# ---------------------------------------------
# HELPER FUNCTION: Run SSH session against a single device
# ---------------------------------------------
function Invoke-SSHSession {
    param(
        [string]$IPAddress,
        [string]$User,
        [string[]]$CommandList,
        [int]$Timeout,
        [string[]]$SSHOptions = @(),
        [int]$CmdDelayMs = 500,
        [int]$CmdTimeoutSec = 30,
        [int]$InitialCmdTimeoutSec = 60,
        [bool]$AllocatePTY = $false,
        [string[]]$PagingCommands = @(),
        [string[]]$ExitCommands = @('exit'),
        [string]$OSType = "",
        [string]$InteractivePattern = "",
        [bool]$SendInitialNewline = $false
    )

    $result = [PSCustomObject]@{
        IPAddress      = $IPAddress
        DeviceName     = ""
        Status         = "Unknown"
        LogFile        = ""
        Error          = ""
        AuthFailed     = $false   # $true only when SSH returns a credential-rejection error
        Duration       = [TimeSpan]::Zero
        Timestamp      = ""   # completion timestamp, set in finally block
        CommandResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $usePTY = $AllocatePTY

    # Retry loop: first attempt uses -T (unless AllocatePTY is true). If a stty error is
    # detected in stderr, the second attempt automatically retries with -tt (PTY allocated).
    for ($ptyAttempt = 0; $ptyAttempt -lt 2; $ptyAttempt++) {
    $proc = $null
    $readerRunspace = $null
    $errEvent = $null
    $stdOutBuilder = $null
    $stdErrBuilder = $null

    try {
        # Build ssh arguments
        $ptyFlag = if ($usePTY) { "-tt" } else { "-T" }
        $sshArgs = @(
            "-v",
            $ptyFlag,
            "-o", "ConnectTimeout=$Timeout",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "BatchMode=no",
            "-o", "LogLevel=ERROR"
        )

        # Append any extra SSH options (e.g. legacy KexAlgorithms, Ciphers, HostKeyAlgorithms)
        if ($SSHOptions.Count -gt 0) {
            $sshArgs += $SSHOptions
        }

        $sshArgs += @("-l", $User, $IPAddress)

        # Configure process with SSH_ASKPASS for automated password entry
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "ssh.exe"
        $psi.Arguments = $sshArgs -join " "
        $psi.UseShellExecute = $false
        $psi.RedirectStandardInput = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8

        # Set SSH_ASKPASS environment so ssh.exe uses our helper for the password
        $psi.EnvironmentVariables["SSH_ASKPASS"] = $askPassScript
        $psi.EnvironmentVariables["SSH_ASKPASS_REQUIRE"] = "force"
        $psi.EnvironmentVariables["DISPLAY"] = "localhost:0"

        $proc = [System.Diagnostics.Process]::new()
        $proc.StartInfo = $psi

        $stdOutBuilder = [System.Text.StringBuilder]::new()
        $stdErrBuilder = [System.Text.StringBuilder]::new()

        # Stderr stays on async events (SSH diagnostics — ordering doesn't matter)
        $errEvent = Register-ObjectEvent -InputObject $proc -EventName ErrorDataReceived -Action {
            if ($null -ne $EventArgs.Data) {
                $Event.MessageData.AppendLine($EventArgs.Data)
            }
        } -MessageData $stdErrBuilder

        $proc.Start()
        $proc.BeginErrorReadLine()

        # Windows StreamWriter defaults to \r\n line endings. Cisco IOS treats the
        # bare \r as a second Enter press on an empty line. Over multiple commands
        # this causes IOS to close the session early. Force LF-only line endings
        # to match what a Unix SSH client sends.
        $proc.StandardInput.NewLine = "`n"

        # Stdout is read synchronously via a background runspace + ConcurrentQueue.
        # This avoids the race condition where async OutputDataReceived events fire
        # on a background thread while new commands are already being written to stdin,
        # causing output lines to be recorded out of order.
        # A FileStream pipe on Windows does not expose DataAvailable, so a dedicated
        # runspace calling ReadLine() in a loop is the reliable cross-platform approach.
        $promptRegex = [System.Text.RegularExpressions.Regex]::new(
            '(?:^\S*?@[A-Za-z0-9_-]+[>#:\$%])|(?:^[A-Za-z0-9][A-Za-z0-9._-]*(?:\([A-Za-z0-9/_-]*\))?[#>]\s*$)|(?:^\[?\S+?@[A-Za-z0-9_-]+\s)|(?:^\([^)]+\)\s*>)|(?:^[A-Za-z]+(?:/[A-Za-z0-9]+)+:[A-Za-z0-9][A-Za-z0-9._-]*(?:\([A-Za-z0-9/_-]*\))?[#>])',
            [System.Text.RegularExpressions.RegexOptions]::Compiled
        )
        # Compiled interactive prompt regex for auto-responding to mid-command prompts.
        # Only built when the OS type defines an InteractivePattern (e.g. WLC AireOS pagination).
        $interactiveRegex = $null
        if ($InteractivePattern -ne '') {
            $interactiveRegex = [System.Text.RegularExpressions.Regex]::new(
                $InteractivePattern,
                [System.Text.RegularExpressions.RegexOptions]::Compiled
            )
        }
        # Compiled pager prompt regex — detects bare ":" from more/less pager in login banners.
        # When matched during initial prompt wait, sends a Space keypress to page through.
        $pagerRegex = [System.Text.RegularExpressions.Regex]::new(
            '^\s*:\s*$',
            [System.Text.RegularExpressions.RegexOptions]::Compiled
        )
        # Cisco IOS sends the prompt without a trailing newline even without a PTY,
        # so ReadLine() would block indefinitely on the prompt line. The runspace
        # reads one character at a time and flushes to the queue on every newline
        # AND whenever the accumulated buffer matches a device prompt pattern.
        # The prompt-flush regex requires a valid hostname prefix before # or >
        # so that pager strings like "--More--" are never mistaken for a prompt.
        $lineQueue = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
        # Three-element array shared with the reader runspace as mutable regex slots.
        # [0] = device prompt pattern (updated after hostname discovery)
        # [1] = interactive prompt pattern (e.g. WLC pagination "(y/n)")
        # [2] = pager prompt pattern (bare ":" from more/less pager in login banners)
        # The outer scope overwrites these; the runspace reads them on every character.
        # String reference assignment is atomic in .NET.
        $regexHolder = [string[]]::new(3)
        $regexHolder[0] = '(?:^\S*?@[A-Za-z0-9_-]+[>#]|^[A-Za-z0-9][A-Za-z0-9._-]*(?:\([A-Za-z0-9/_-]*\))?[#>]|^\([^)]+\)\s*>|^[A-Za-z]+(?:/[A-Za-z0-9]+)+:[A-Za-z0-9][A-Za-z0-9._-]*(?:\([A-Za-z0-9/_-]*\))?[#>])\s*$'
        $regexHolder[1] = $InteractivePattern   # populated per-OS if interactive prompts are needed
        $regexHolder[2] = '^\s*:\s*$'           # bare ":" pager prompt (more/less)

        $readerRunspace = [PowerShell]::Create()
        $readerRunspace.AddScript({
                param($reader, $queue, $holder)
                # Regex to strip ANSI escape sequences (CSI sequences, OSC sequences,
                # and bare ESC + single char). PTY-allocated sessions often wrap the
                # prompt in escape codes that prevent the prompt regex from matching.
                $ansiPattern = '\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b[()][0-9A-Za-z]|\x1b[\x20-\x2F][\x30-\x7E]|\x1b.'
                try {
                    $buf = [System.Text.StringBuilder]::new()
                    while ($true) {
                        $c = $reader.Read()       # blocks until a char is available or EOS
                        if ($c -eq -1) { break }  # end of stream
                        $ch = [char]$c
                        if ($ch -eq "`r") { continue }   # discard bare CR
                        if ($ch -eq "`n") {
                            # Strip ANSI codes before enqueuing the completed line.
                            $cleaned = $buf.ToString() -replace $ansiPattern, ''
                            $queue.Enqueue($cleaned)
                            $buf.Clear() | Out-Null
                        }
                        else {
                            $buf.Append($ch) | Out-Null
                            # Strip ANSI codes before testing the buffer against prompt patterns.
                            # The raw buffer may contain escape sequences that prevent matching.
                            $stripped = $buf.ToString() -replace $ansiPattern, ''
                            # Flush when the stripped buffer matches the device prompt or an
                            # interactive prompt (e.g. WLC pagination "(y/n)").
                            # After the hostname is discovered the outer scope writes a
                            # tighter hostname-anchored pattern into $holder[0], preventing
                            # table column headers (e.g. "Switch#") from being flushed.
                            if ($stripped -match $holder[0]) {
                                $queue.Enqueue($stripped)
                                $buf.Clear() | Out-Null
                            } elseif ($holder[1] -and $stripped -match $holder[1]) {
                                $queue.Enqueue($stripped)
                                $buf.Clear() | Out-Null
                            } elseif ($holder[2] -and $stripped -match $holder[2]) {
                                $queue.Enqueue($stripped)
                                $buf.Clear() | Out-Null
                            }
                        }
                    }
                    if ($buf.Length -gt 0) {
                        $cleaned = $buf.ToString() -replace $ansiPattern, ''
                        $queue.Enqueue($cleaned)
                    }
                }
                catch { }
                finally { $queue.Enqueue($null) }   # null sentinel signals end of stream
            }).AddArgument($proc.StandardOutput).AddArgument($lineQueue).AddArgument($regexHolder) | Out-Null
        $readerHandle = $readerRunspace.BeginInvoke()

        # Wait for the initial device prompt before sending any commands.
        # This ensures the SSH login sequence (banners, MOTD, etc.) has completed.
        $initialTimeoutMs = $InitialCmdTimeoutSec * 1000
        $perCmdTimeoutMs  = $CmdTimeoutSec * 1000
        $lastPrompt = ""
        $promptFound = $false
        $newlineNudgeSent = $false

        # OS profiles that require an immediate newline get one right away
        # (e.g. WLC AireOS devices that won't display the prompt without a keypress).
        if ($SendInitialNewline) {
            Start-Sleep -Milliseconds 500
            $proc.StandardInput.WriteLine("")
            $proc.StandardInput.Flush()
            Write-Verbose "Sent initial newline (OS profile) to trigger prompt on $IPAddress"
            $newlineNudgeSent = $true
        }

        if (-not $usePTY -and $ptyAttempt -eq 0) {
            # Phase 1: Quick check (up to 3s) — enough for stty error to appear in stderr.
            # If the prompt arrives quickly, we proceed immediately.
            $quickMs = [Math]::Min(3000, $initialTimeoutMs)
            $promptFound = Read-UntilPrompt -Queue $lineQueue -Builder $stdOutBuilder -PromptRegex $promptRegex -TimeoutMs $quickMs -PromptText ([ref]$lastPrompt) `
                -StdIn $proc.StandardInput -PagerRegex $pagerRegex -StdErrBuilder $stdErrBuilder

            if (-not $promptFound) {
                # Check stderr for stty failure — indicates device requires PTY allocation.
                # Different SSH/OS combos produce different error messages:
                #   "stty: ... Inappropriate ioctl for device"  (Linux/macOS)
                #   "stty: standard input: Invalid argument"    (NX-OS, some others)
                if ($stdErrBuilder.ToString() -match "stty.*(?:Inappropriate ioctl|Invalid argument)") {
                    Write-Verbose "stty error detected on $IPAddress - retrying with PTY allocation (-tt)"
                    $usePTY = $true
                    continue   # finally cleans up this attempt, loop retries with -tt
                }

                # Universal newline nudge — some devices (ISR routers, certain IOS-XE
                # platforms) wait for a keypress after the MOTD before showing the prompt.
                # Send a blank line as a nudge, then continue waiting. Harmless on devices
                # that already showed their prompt (IOS just redisplays the prompt).
                if (-not $newlineNudgeSent) {
                    $proc.StandardInput.WriteLine("")
                    $proc.StandardInput.Flush()
                    Write-Verbose "Sent newline nudge to trigger prompt on $IPAddress (no prompt after ${quickMs}ms)"
                    $newlineNudgeSent = $true
                }

                # Continue waiting for the remaining initial timeout.
                $remainingMs = $initialTimeoutMs - $quickMs
                if ($remainingMs -gt 0) {
                    $promptFound = Read-UntilPrompt -Queue $lineQueue -Builder $stdOutBuilder -PromptRegex $promptRegex -TimeoutMs $remainingMs -PromptText ([ref]$lastPrompt) `
                        -StdIn $proc.StandardInput -PagerRegex $pagerRegex -StdErrBuilder $stdErrBuilder
                }
            }
        }
        else {
            # AllocatePTY is true (or this is a PTY retry): use the full initial timeout.
            # First try a short wait in case the prompt arrives immediately.
            $nudgeMs = [Math]::Min(3000, $initialTimeoutMs)
            $promptFound = Read-UntilPrompt -Queue $lineQueue -Builder $stdOutBuilder -PromptRegex $promptRegex -TimeoutMs $nudgeMs -PromptText ([ref]$lastPrompt) `
                -StdIn $proc.StandardInput -PagerRegex $pagerRegex -StdErrBuilder $stdErrBuilder

            if (-not $promptFound) {
                # Send a newline nudge if one hasn't been sent yet, then wait the remaining time.
                if (-not $newlineNudgeSent) {
                    $proc.StandardInput.WriteLine("")
                    $proc.StandardInput.Flush()
                    Write-Verbose "Sent newline nudge to trigger prompt on $IPAddress (PTY, no prompt after ${nudgeMs}ms)"
                    $newlineNudgeSent = $true
                }
                $remainingMs = $initialTimeoutMs - $nudgeMs
                if ($remainingMs -gt 0) {
                    $promptFound = Read-UntilPrompt -Queue $lineQueue -Builder $stdOutBuilder -PromptRegex $promptRegex -TimeoutMs $remainingMs -PromptText ([ref]$lastPrompt) `
                        -StdIn $proc.StandardInput -PagerRegex $pagerRegex -StdErrBuilder $stdErrBuilder
                }
            }
        }

        if (-not $promptFound) {
            # Aggressive fallback: if this was a -T attempt with no meaningful stdout, retry with PTY.
            # Covers devices that need PTY but don't produce the stty error (e.g. libssh servers),
            # and devices that send whitespace-only output (blank lines, newlines) before stalling.
            if (-not $usePTY -and $ptyAttempt -eq 0 -and $stdOutBuilder.ToString().Trim().Length -eq 0) {
                Write-Verbose "No meaningful stdout on $IPAddress after ${InitialCmdTimeoutSec}s - retrying with PTY allocation (-tt)"
                $usePTY = $true
                continue   # finally cleans up, loop retries with -tt
            }
            if (-not $proc.HasExited) { $proc.Kill() }
            throw "Timed out waiting for initial device prompt after ${InitialCmdTimeoutSec}s. Consider increasing -InitialPromptTimeoutSeconds."
        }

        # Now that the initial prompt is captured in $lastPrompt (e.g. "s3850x-1#"),
        # extract the device hostname and replace the broad prompt-detection regex with
        # one anchored to this exact hostname. This prevents output lines that happen to
        # match the broad pattern (e.g. the "Switch#" column header in "show switch")
        # from being misidentified as a device prompt.
        $knownHostname = Get-HostnameFromPrompt -Output $lastPrompt
        if (-not [string]::IsNullOrWhiteSpace($knownHostname)) {
            $hn = [System.Text.RegularExpressions.Regex]::Escape($knownHostname)

            # Update the shared holder so the already-running reader runspace picks up
            # the tighter pattern on its next character iteration.
            # Always include the broad WLC pattern — hostname can't be extracted from
            # WLC prompts, so the parenthesized pattern stays broad throughout the session.
            $regexHolder[0] = "(?:^\S*?@$hn[>#:`$%]|^$hn(?:\([A-Za-z0-9/_-]*\))?[#>]|^\([^)]+\)\s*>|^[A-Za-z]+(?:/[A-Za-z0-9]+)+:$hn(?:\([A-Za-z0-9/_-]*\))?[#>])\s*`$"

            # Replace the compiled Regex used by Read-UntilPrompt for all subsequent calls.
            $promptRegex = [System.Text.RegularExpressions.Regex]::new(
                "(?:^\S*?@$hn[>#:`$%])|(?:^$hn(?:\([A-Za-z0-9/_-]*\))?[#>]\s*`$)|(?:^\([^)]+\)\s*>)|(?:^[A-Za-z]+(?:/[A-Za-z0-9]+)+:$hn(?:\([A-Za-z0-9/_-]*\))?[#>])",
                [System.Text.RegularExpressions.RegexOptions]::Compiled
            )
        }
        # If hostname extraction failed, $promptRegex and $regexHolder[0] remain the
        # broad patterns — behaviour is identical to before, which is the correct fallback.

        # When PTY is allocated, the remote terminal has echo enabled by default.
        # Suppress it now so subsequent commands don't echo back through the PTY,
        # which would confuse prompt detection and pollute captured output.
        if ($usePTY) {
            $proc.StandardInput.WriteLine("stty -echo 2>/dev/null")
            $proc.StandardInput.Flush()
            $sttyDrain = [System.Text.StringBuilder]::new()
            # Drain the echoed prompt prefix that the PTY sends back
            Read-UntilPrompt -Queue $lineQueue -Builder $sttyDrain -PromptRegex $promptRegex -TimeoutMs 2000 -PromptText ([ref]$null) | Out-Null
            # Drain the stty command text echo and wait for the real prompt
            Read-UntilPrompt -Queue $lineQueue -Builder $sttyDrain -PromptRegex $promptRegex -TimeoutMs 2000 -PromptText ([ref]$lastPrompt) | Out-Null
        }

        # Send paging-disable commands silently (output not logged).
        # These are OS-specific (e.g. "terminal length 0" for IOS, "config paging disable"
        # for AireOS) and are sent automatically so users don't need them in command files.
        foreach ($pagingCmd in $PagingCommands) {
            $proc.StandardInput.WriteLine($pagingCmd)
            $proc.StandardInput.Flush()
            $pagingDrain = [System.Text.StringBuilder]::new()
            Read-UntilPrompt -Queue $lineQueue -Builder $pagingDrain `
                -PromptRegex $promptRegex -TimeoutMs 2000 -PromptText ([ref]$lastPrompt) | Out-Null
        }

        # Send each command and wait for the resulting prompt before proceeding.
        # This guarantees all output from a command is collected before the next
        # command is sent, eliminating the out-of-order output race condition.
        foreach ($cmd in $CommandList) {
            # Optional settle delay applied after receiving the previous prompt,
            # before sending the next command. Useful for devices that display
            # the prompt slightly before their output buffer is fully flushed.
            if ($CmdDelayMs -gt 0) { Start-Sleep -Milliseconds $CmdDelayMs }

            # Drain stale prompt lines from the queue BEFORE sending the command.
            # WLC AireOS (and some other devices) echo the prompt multiple times
            # after the previous command completes. These stale prompts arrive
            # after Read-UntilPrompt matched the first prompt and returned.
            # If not drained, Read-UntilPrompt matches one as the "end of command"
            # prompt and returns before any real output arrives, causing output to
            # cascade into the next command's JSON section.
            # The drain must happen BEFORE the command is sent, otherwise the stale
            # prompts race with the command echo and can't be distinguished.
            $drainLine = ""
            while ($lineQueue.TryDequeue([ref]$drainLine)) {
                if ($null -eq $drainLine) { break }   # don't consume the EOS sentinel
                $strippedDrain = $drainLine -replace '\x1b\[[0-9;]*[a-zA-Z]', '' -replace '\x1b\][^\x07]*\x07', ''
                if ($promptRegex.IsMatch($strippedDrain.TrimEnd())) {
                    $stdOutBuilder.AppendLine($drainLine) | Out-Null
                }
                else {
                    # Non-prompt content — shouldn't happen between commands, but
                    # log it so it isn't silently lost.
                    $stdOutBuilder.AppendLine($drainLine) | Out-Null
                }
            }

            $proc.StandardInput.WriteLine($cmd)
            $proc.StandardInput.Flush()

            # Dequeue the command echo. Cisco devices echo the command back as the
            # first line of output. Join it with the held prompt to produce the
            # natural "hostname#show inventory" layout seen in a live session.
            $echoLine = ""
            $echoDeadline = [DateTime]::UtcNow.AddMilliseconds(1500)
            while ([DateTime]::UtcNow -lt $echoDeadline) {
                if ($lineQueue.TryDequeue([ref]$echoLine)) { break }
                Start-Sleep -Milliseconds 20
            }
            $stdOutBuilder.AppendLine("$lastPrompt$echoLine") | Out-Null

            # Use a dedicated per-command builder for structured JSON output capture.
            # $stdOutBuilder continues to receive the formatted log content unchanged.
            $cmdOutputBuilder = [System.Text.StringBuilder]::new()

            # Capture the current prompt before Read-UntilPrompt overwrites $lastPrompt.
            # Stored per-command so the netcortex output can reconstruct the prompt+command
            # echo line (e.g. "cs3850x-1#term len 0") without re-parsing raw output.
            $cmdPrompt = $lastPrompt
            $lastPrompt = ""
            if (-not (Read-UntilPrompt -Queue $lineQueue -Builder $cmdOutputBuilder -PromptRegex $promptRegex -TimeoutMs $perCmdTimeoutMs -PromptText ([ref]$lastPrompt) -StdIn $proc.StandardInput -InteractiveRegex $interactiveRegex)) {
                # Flush any partial output received before the timeout so it appears
                # in the failure log's PARTIAL OUTPUT section for troubleshooting.
                if ($cmdOutputBuilder.Length -gt 0) {
                    $stdOutBuilder.Append($cmdOutputBuilder.ToString()) | Out-Null
                }
                $proc.Kill()
                throw "Timed out waiting for device prompt after command '$cmd'."
            }

            # Forward the per-command output into $stdOutBuilder so the log file
            # format is completely unchanged.
            $stdOutBuilder.Append($cmdOutputBuilder.ToString()) | Out-Null

            # Split the per-command output into an array of strings for JSON.
            # Each array element is one output line; blank lines become empty strings,
            # matching the raw_output format in the example JSON.
            $rawLines = $cmdOutputBuilder.ToString() -split "`r?`n"
            $result.CommandResults.Add([PSCustomObject]@{
                    command    = $cmd
                    prompt     = $cmdPrompt
                    raw_output = [string[]]$rawLines
                })

            # Repeat the prompt twice as visual separators between command blocks.
            # Using the actual prompt (rather than blank lines) means every non-blank
            # line in the output section is either a prompt, a command echo, or device
            # output — making the log straightforward to parse programmatically later.
            $stdOutBuilder.AppendLine($lastPrompt) | Out-Null
            $stdOutBuilder.AppendLine($lastPrompt) | Out-Null
        }

        # Write the final prompt (returned after the last command's output) so
        # the log ends exactly as a real terminal session would.
        if ($lastPrompt -ne "") { $stdOutBuilder.AppendLine($lastPrompt) | Out-Null }

        # With PTY (-tt), closing stdin does NOT cause the remote session to end —
        # the PTY keeps the shell alive indefinitely. Send the OS-specific exit
        # sequence to cleanly close the remote CLI session before closing stdin.
        # For AireOS WLC: "logout" then "n" (decline save-config prompt).
        if ($usePTY -and $ExitCommands.Count -gt 0) {
            foreach ($exitCmd in $ExitCommands) {
                $proc.StandardInput.WriteLine($exitCmd)
                $proc.StandardInput.Flush()
                Start-Sleep -Milliseconds 100
            }
        }
        $proc.StandardInput.Close()

        # Drain any remaining output after stdin is closed (e.g. logout messages).
        Read-UntilPrompt -Queue $lineQueue -Builder $stdOutBuilder -PromptRegex $promptRegex -TimeoutMs ([Math]::Min($perCmdTimeoutMs, 5000)) -PromptText ([ref]$null) | Out-Null

        # Wait for the SSH process to exit. Use a fixed short timeout rather than
        # one proportional to commands — all commands have already completed at this
        # point, so only a brief window is needed for the process to close cleanly.
        $postSessionTimeoutMs = 3000
        $exited = $proc.WaitForExit($postSessionTimeoutMs)

        if (-not $exited) {
            # All commands completed successfully; the process just didn't exit
            # cleanly (common with PTY sessions). Kill it — this is not an error.
            $proc.Kill()
            Write-Verbose "SSH process on $IPAddress did not exit within 3s after session end - killed."
        }

        Unregister-Event -SourceIdentifier $errEvent.Name -ErrorAction SilentlyContinue

        # Wait for the reader runspace to finish draining the stdout stream
        $readerRunspace.EndInvoke($readerHandle) | Out-Null
        $readerRunspace.Dispose()

        $stdOut = $stdOutBuilder.ToString()
        $stdErr = $stdErrBuilder.ToString().Trim()

        # Determine success or failure.
        # A non-zero exit code alone does not mean failure — some devices (e.g. AireOS
        # WLC "logout") close the connection in a way that produces SSH exit code -1
        # even though all commands completed successfully. If every command ran and
        # returned a prompt, the session is successful regardless of SSH exit code.
        $allCommandsRan = ($result.CommandResults.Count -eq $CommandList.Count)
        if ($allCommandsRan) {
            $result.Status = "Success"
            if ($proc.ExitCode -ne 0) {
                Write-Verbose "SSH exit code $($proc.ExitCode) on $IPAddress ignored - all $($CommandList.Count) commands completed."
            }
        } elseif ($proc.ExitCode -ne 0) {
            $result.Status = "Failed"
            if ([string]::IsNullOrWhiteSpace($stdErr)) {
                $result.Error = "SSH exit code $($proc.ExitCode)"
            } else {
                # Parse each line of debug for final error output detail
                $errorLines = $stdErr -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                foreach ($err in $errorLines) {
                    $result.Error = $err
                }
            }
            $result.AuthFailed = Test-IsAuthFailure -StdErr $stdErr
        } else {
            $result.Status = "Success"
        }

        # Parse hostname from the device prompt in captured output
        $deviceName = Get-HostnameFromPrompt -Output $stdOut
        if ([string]::IsNullOrWhiteSpace($deviceName)) {
            $deviceName = "unknown"
            Write-Verbose "Could not parse hostname from prompt for $IPAddress - using 'unknown'"
        }
        $result.DeviceName = $deviceName

        # Build log filename now that we know the hostname
        $safeDevice = ConvertTo-SafeFileName $deviceName
        $safeIP = ConvertTo-SafeFileName $IPAddress
        $logFileName = "${safeDevice}_${safeIP}_${timestamp}.log"
        $logFilePath = Join-Path $LogDirectory $logFileName
        $result.LogFile = $logFilePath

        # Build log content using string array (avoids here-string indentation issues)
        $logLines = @(
            $separator
            " Device    : $deviceName ($IPAddress)"
            " User      : $User"
            " Date      : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            " Status    : $($result.Status)"
            " Conn Tmout: ${Timeout}s"
            " Cmd Tmout : ${CmdTimeoutSec}s"
            " OS Type  : $OSType"
            " PTY      : $ptyFlag"
            $separator
            ""
            "$thinSep COMMANDS SENT $thinSep"
            ($CommandList -join "`r`n")
            ""
            "$thinSep DEVICE OUTPUT $thinSep"
            $stdOut
        )

        if (-not [string]::IsNullOrWhiteSpace($stdErr)) {
            $logLines += ""
            $logLines += "$thinSep SSH ERRORS / DIAGNOSTICS $thinSep"
            $logLines += $stdErr
        }

        if ($LogEnabled) {
            Set-Content -Path $logFilePath -Value ($logLines -join "`r`n") -Encoding UTF8
        }

        break   # Success — exit the PTY retry loop
    }
    catch {
        $result.Status     = "Failed"
        $result.DeviceName = "unknown"

        # Read whatever stderr was collected before the exception was thrown.
        # SSH auth rejection ("Permission denied") appears here even when the
        # exception path is taken instead of the normal exit-code path.
        $catchStdErr = if ($null -ne $stdErrBuilder) { $stdErrBuilder.ToString().Trim() } else { "" }

        # Auth failure takes priority over the exception message for both
        # $result.Error and $result.AuthFailed.
        $result.AuthFailed = Test-IsAuthFailure -StdErr $catchStdErr
        if ($result.AuthFailed) {
            # Use the last non-empty stderr line as the user-facing error.
            $authErrLines = $catchStdErr -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            $result.Error = if ($authErrLines) { $authErrLines[-1] } else { "Authentication failed" }
        }
        else {
            $result.Error = $_.Exception.Message
        }

        # Still write a failure log
        $safeIP      = ConvertTo-SafeFileName $IPAddress
        $logFileName = "unknown_${safeIP}_${timestamp}.log"
        $logFilePath = Join-Path $LogDirectory $logFileName
        $result.LogFile = $logFilePath

        $failLines = @(
            $separator
            " Device    : unknown ($IPAddress)"
            " User      : $User"
            " Date      : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            " Status    : FAILED"
            " Conn Tmout: ${Timeout}s"
            " Cmd Tmout : ${CmdTimeoutSec}s"
            " OS Type  : $OSType"
            " PTY      : $ptyFlag"
            $separator
            ""
            "ERROR: $($result.Error)"
        )

        if ($null -ne $stdOutBuilder -and $stdOutBuilder.Length -gt 0) {
            $failLines += ""
            $failLines += "$thinSep PARTIAL OUTPUT (before failure) $thinSep"
            $failLines += $stdOutBuilder.ToString()
        }

        # Always append SSH diagnostics when available — critical for troubleshooting
        # any failure, including auth failures, host-key errors, and connectivity issues.
        if (-not [string]::IsNullOrWhiteSpace($catchStdErr)) {
            $failLines += ""
            $failLines += "$thinSep SSH ERRORS / DIAGNOSTICS $thinSep"
            $failLines += $catchStdErr
        }

        if ($LogEnabled) {
            Set-Content -Path $logFilePath -Value ($failLines -join "`r`n") -Encoding UTF8
        }

        break   # Error handled — exit the PTY retry loop
    }
    finally {
        # Per-iteration cleanup: release process, event, and runspace resources.
        # On a stty-triggered retry (continue), this runs before the next iteration.
        try {
            if ($null -ne $errEvent) {
                Unregister-Event -SourceIdentifier $errEvent.Name -ErrorAction SilentlyContinue
            }
        }
        catch {}

        try {
            if ($null -ne $proc) {
                if (-not $proc.HasExited) { $proc.Kill() }
                $proc.Dispose()
            }
        }
        catch {
            Write-Verbose "Process cleanup for $IPAddress : $($_.Exception.Message)"
        }

        try {
            if ($null -ne $readerRunspace) { $readerRunspace.Dispose() }
        }
        catch {
            Write-Verbose "Reader runspace cleanup for $IPAddress : $($_.Exception.Message)"
        }
    }
    }   # end of PTY retry loop

    $sw.Stop()
    $result.Duration = $sw.Elapsed
    $result.Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    return $result
}

# ---------------------------------------------
# COMPRESS-ONLY MODE — archive existing output and exit
# Placed after function definitions so Invoke-CompressOutput is available.
# ---------------------------------------------
if ($CompressOnly) {
    Write-Host ""
    Write-Host "Compress-only mode - archiving existing output directories." -ForegroundColor Cyan
    Invoke-CompressOutput -OutputDirectories @($LogDirectory, $JsonDirectory, $NetcortexDirectory) -Cleanup $DeleteAfterCompress
    Write-Host ""
    exit 0
}

# ---------------------------------------------
# MAIN EXECUTION LOOP
# ---------------------------------------------
$devCountStr = "$($devices.Count)".PadRight(37)
$osBreakdownLines = @($uniqueOSTypes | ForEach-Object {
    $osName = $_; "$osName($(@($devices | Where-Object { $_.OS -eq $osName }).Count))"
})
$cmdDirStr = $CommandsDirectory
if ($cmdDirStr.Length -gt 37) { $cmdDirStr = $cmdDirStr.Substring(0, 34) + "..." }
$cmdDirStr = $cmdDirStr.PadRight(37)
$timeoutStr    = "${TimeoutSeconds}s".PadRight(37)
$cmdTimeoutStr = "${CommandTimeoutSeconds}s".PadRight(37)
$iniTimeoutStr = "${InitialPromptTimeoutSeconds}s".PadRight(37)
$ptyStr = if ($AllocatePTY) { "Enabled (-tt)" } else { "Auto (-T, fallback -tt)" }
$ptyStr = $ptyStr.PadRight(37)
$pingStr = if ($PingTest) { "Enabled" } else { "Disabled" }
$pingStr = $pingStr.PadRight(37)
$credLabelStr = $CredentialLabel
if ($credLabelStr.Length -gt 37) { $credLabelStr = $credLabelStr.Substring(0, 34) + "..." }
$credLabelStr = $credLabelStr.PadRight(37)
$compressStr = if ($CompressOutput) { "$CompressWhen$(if ($DeleteAfterCompress) { ' + cleanup' })" } else { "Disabled" }
if ($compressStr.Length -gt 37) { $compressStr = $compressStr.Substring(0, 34) + "..." }
$compressStr = $compressStr.PadRight(37)
if ($LogEnabled) {
    $logDirStr = $LogDirectory
    if ($logDirStr.Length -gt 37) { $logDirStr = $logDirStr.Substring(0, 34) + "..." }
    $logDirStr = $logDirStr.PadRight(37)
} else { $logDirStr = "Disabled".PadRight(37) }
if ($JsonEnabled) {
    $jsonDirStr = $JsonDirectory
    if ($jsonDirStr.Length -gt 37) { $jsonDirStr = $jsonDirStr.Substring(0, 34) + "..." }
    $jsonDirStr = $jsonDirStr.PadRight(37)
} else { $jsonDirStr = "Disabled".PadRight(37) }
if ($NetcortexEnabled) {
    $netcortexDirStr = $NetcortexDirectory
    if ($netcortexDirStr.Length -gt 37) { $netcortexDirStr = $netcortexDirStr.Substring(0, 34) + "..." }
    $netcortexDirStr = $netcortexDirStr.PadRight(37)
} else { $netcortexDirStr = "Disabled".PadRight(37) }

Write-Host ""
Write-Host "+==================================================+" -ForegroundColor Gray
Write-Host "|       SSH Network Command Runner - Starting      |" -ForegroundColor Gray
Write-Host "+==================================================+" -ForegroundColor Gray
Write-Host "|  Devices  : ${devCountStr}|" -ForegroundColor Gray
for ($i = 0; $i -lt $osBreakdownLines.Count; $i++) {
    $label = if ($i -eq 0) { "|  OS Types : " } else { "|             " }
    $value = $osBreakdownLines[$i]
    if ($value.Length -gt 37) { $value = $value.Substring(0, 34) + "..." }
    $value = $value.PadRight(37)
    Write-Host "${label}${value}|" -ForegroundColor Gray
}
Write-Host "|  Cmd Dir  : ${cmdDirStr}|" -ForegroundColor Gray
Write-Host "|  Timeout  : ${timeoutStr}|" -ForegroundColor Gray
Write-Host "|  Cmd Tmout: ${cmdTimeoutStr}|" -ForegroundColor Gray
Write-Host "|  Ini Tmout: ${iniTimeoutStr}|" -ForegroundColor Gray
Write-Host "|  PTY Mode : ${ptyStr}|" -ForegroundColor Gray
Write-Host "|  Ping Test: ${pingStr}|" -ForegroundColor Gray
Write-Host "|  SSH Creds: ${credLabelStr}|" -ForegroundColor Gray
Write-Host "|  Compress : ${compressStr}|" -ForegroundColor Gray
Write-Host "|  Log Dir  : ${logDirStr}|" -ForegroundColor Gray
Write-Host "|  JSON Dir : ${jsonDirStr}|" -ForegroundColor Gray
Write-Host "|  Netcortex: ${netcortexDirStr}|" -ForegroundColor Gray
if ($ExtraSSHOptions.Count -gt 0) {
    $sshOptsStr = ($ExtraSSHOptions -join " ")
    if ($sshOptsStr.Length -gt 37) { $sshOptsStr = $sshOptsStr.Substring(0, 34) + "..." }
    $sshOptsStr = $sshOptsStr.PadRight(37)
    Write-Host "|  SSH Opts : ${sshOptsStr}|" -ForegroundColor Gray
}
Write-Host "+==================================================+" -ForegroundColor Gray
Write-Host ""

$results        = [System.Collections.Generic.List[PSCustomObject]]::new()
$deviceNum      = 0
$authRetryCount = 0
$maxAuthRetries = 3

foreach ($device in $devices) {
    $deviceNum++
    $ip = $device.IP
    $os = $device.OS
    Write-Host "[$deviceNum/$($devices.Count)] Connecting to $ip ($os) ... " -NoNewline

    # Look up commands, paging, PTY, and exit sequence for this device's OS
    $commands = $commandsByOS[$os]
    $osProfile = $validOSTypes[$os]
    $pagingCmds = @($osProfile.PagingCommand)
    $exitCmds = $osProfile.ExitCommands
    $devicePTY = $AllocatePTY -or $osProfile.RequirePTY
    $interactivePattern = $osProfile.InteractivePattern
    $sendNewline = $osProfile.SendInitialNewline

    # Pre-connection ping test: skip unreachable devices immediately.
    if ($PingTest) {
        $pingResult = Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue
        if (-not $pingResult) {
            Write-Host "SKIPPED (no ping response)" -ForegroundColor Yellow
            $results.Add([PSCustomObject]@{
                IPAddress      = $ip
                DeviceName     = "unknown"
                Status         = "Skipped"
                LogFile        = ""
                Error          = "No ping response - device unreachable"
                AuthFailed     = $false
                Duration       = [TimeSpan]::Zero
                Timestamp      = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                CommandResults = [System.Collections.Generic.List[PSCustomObject]]::new()
            })
            continue
        }
    }

    $sessionResult = Invoke-SSHSession `
        -IPAddress             $ip `
        -User                  $username `
        -CommandList           $commands `
        -Timeout               $TimeoutSeconds `
        -SSHOptions            $ExtraSSHOptions `
        -CmdDelayMs            $CommandDelayMs `
        -CmdTimeoutSec         $CommandTimeoutSeconds `
        -InitialCmdTimeoutSec  $InitialPromptTimeoutSeconds `
        -AllocatePTY           $devicePTY `
        -PagingCommands        $pagingCmds `
        -ExitCommands          $exitCmds `
        -OSType                $os `
        -InteractivePattern    $interactivePattern `
        -SendInitialNewline    $sendNewline

    if ($sessionResult.Status -eq "Success") {
        Write-Host "OK " -ForegroundColor Green -NoNewline
        Write-Host "($($sessionResult.DeviceName)) [$($sessionResult.Duration.TotalSeconds.ToString('0.0'))s]"

        # Persist credentials to Credential Manager after the first verified success.
        if (-not $credentialsSaved) {
            if ([CredentialManager]::WriteCredential($CredentialLabel, $username, $password)) {
                Write-Verbose "Credentials saved to Credential Manager (label: $CredentialLabel)."
            }
            $credentialsSaved = $true
        }
        $authRetryCount = 0   # reset consecutive auth failure counter on any success
    }
    elseif ($sessionResult.AuthFailed) {
        $authRetryCount++
        Write-Host "FAILED: " -ForegroundColor Red -NoNewline
        Write-Host "Authentication rejected ($authRetryCount of $maxAuthRetries consecutive)" -ForegroundColor DarkRed

        if ($authRetryCount -ge $maxAuthRetries) {
            $results.Add($sessionResult)
            Write-Host ""
            Write-Host "  ERROR: Authentication rejected on $maxAuthRetries consecutive devices. Aborting." -ForegroundColor Red
            Write-Host "  This usually indicates expired or incorrect credentials." -ForegroundColor Red
            try { Remove-Item -Path $askPassDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}
            $password = $null
            [System.GC]::Collect()
            break   # exit the foreach device loop — proceed to summary
        }
    }
    else {
        Write-Host "FAILED: " -ForegroundColor Red -NoNewline
        Write-Host "$($sessionResult.Error)" -ForegroundColor DarkRed
        # Non-auth failures (timeouts, connectivity) reset the consecutive auth counter
        # since they break the streak of auth rejections.
        $authRetryCount = 0
    }

    $results.Add($sessionResult)
}

# ---------------------------------------------
# OUTPUT AGGREGATES
# ---------------------------------------------
$successResults = @($results | Where-Object { $_.Status -eq "Success" })
$failedIPs      = @($results | Where-Object { $_.Status -eq "Failed" } | ForEach-Object { $_.IPAddress })

# ---------------------------------------------
# NETCORTEX OUTPUT
# ---------------------------------------------
if ($NetcortexEnabled) {
    # Map each device IP to its OS type for Netcortex command list lookup
    $deviceOSMap = @{}
    foreach ($d in $devices) { $deviceOSMap[$d.IP] = $d.OS }

    foreach ($r in $successResults) {
        $safeDevice = ConvertTo-SafeFileName $r.DeviceName
        $safeIP = ConvertTo-SafeFileName $r.IPAddress
        $netcortexFile = Join-Path $NetcortexDirectory "${safeDevice}_${safeIP}_${timestamp}.txt"

        # Determine whether this OS has a dedicated Netcortex command list.
        # If so, filter and reorder results to match the Netcortex file's ordering.
        # If not, fall back to all commands in execution order (original behavior).
        $deviceOS = $deviceOSMap[$r.IPAddress]
        $ncCmds = if ($deviceOS -and $netcortexCommandsByOS.ContainsKey($deviceOS)) {
            $netcortexCommandsByOS[$deviceOS]
        } else { $null }

        if ($ncCmds) {
            # Build case-insensitive lookup from command string -> CommandResult
            $crLookup = @{}
            foreach ($cr in $r.CommandResults) {
                $crLookup[$cr.command.ToLower()] = $cr
            }
            # Select results in Netcortex file order, including only listed commands
            $orderedResults = foreach ($cmd in $ncCmds) {
                $key = $cmd.ToLower()
                if ($crLookup.ContainsKey($key)) { $crLookup[$key] }
            }
        }
        else {
            $orderedResults = $r.CommandResults
        }

        # Build netcortex content: prompt+command echo, raw output, bare prompt separator.
        # Trailing blank lines are stripped from each command's output so the bare
        # prompt lands immediately after the last non-empty output line — giving the
        # downstream ingest a clean prompt-delimited structure with no ambiguous blanks.
        $netcortexLines = [System.Collections.Generic.List[string]]::new()
        foreach ($cr in $orderedResults) {
            $netcortexLines.Add("$($cr.prompt)$($cr.command)")
            $outLines = @($cr.raw_output)
            $trimIdx = $outLines.Count - 1
            while ($trimIdx -ge 0 -and [string]::IsNullOrEmpty($outLines[$trimIdx])) { $trimIdx-- }
            for ($i = 0; $i -le $trimIdx; $i++) { $netcortexLines.Add($outLines[$i]) }
            $netcortexLines.Add($cr.prompt)
        }
        Set-Content -Path $netcortexFile -Value ($netcortexLines -join "`r`n") -Encoding UTF8
    }
}

# ---------------------------------------------
# JSON OUTPUT
# ---------------------------------------------
if ($JsonEnabled) {
    # --- Session summary file (optional) ---
    if ($JsonSessionFileEnabled) {
        $sessionDoc = [ordered]@{
            platform = $osPlatform
            engine   = $psEngine
            date     = $runDate
            result   = [ordered]@{
                total   = $results.Count
                success = $successResults.Count
                failed  = $failedIPs.Count
            }
            devices  = [ordered]@{
                count               = $results.Count
                ip_addresses        = @($results | ForEach-Object { $_.IPAddress })
                failed_ip_addresses = @($failedIPs)
            }
            commands_directory = $CommandsDirectory
            os_types = [ordered]@{}
        }
        foreach ($osKey in $uniqueOSTypes) {
            $sessionDoc.os_types[$osKey] = [ordered]@{
                device_count = @($devices | Where-Object { $_.OS -eq $osKey }).Count
                command_count = $commandsByOS[$osKey].Count
                commands = @($commandsByOS[$osKey])
            }
        }
        $sessionPath = Join-Path $JsonDirectory "ssh-session-${timestamp}.json"
        $sessionDoc | ConvertTo-Json -Depth 10 | Set-Content -Path $sessionPath -Encoding UTF8
    }

    # --- Per-device JSON files (successful connections only) ---
    foreach ($r in $successResults) {
        $safeDevice = ConvertTo-SafeFileName $r.DeviceName
        $safeIP     = ConvertTo-SafeFileName $r.IPAddress
        $devicePath = Join-Path $JsonDirectory "${safeDevice}_${safeIP}_${timestamp}.json"

        $deviceDoc = [ordered]@{
            name      = $r.DeviceName
            ip        = $r.IPAddress
            timestamp = $r.Timestamp
            commands  = @(
                $r.CommandResults | ForEach-Object {
                    [ordered]@{
                        command    = $_.command
                        raw_output = @($_.raw_output)
                    }
                }
            )
        }
        $deviceDoc | ConvertTo-Json -Depth 10 | Set-Content -Path $devicePath -Encoding UTF8
    }
}

# ---------------------------------------------
# SUMMARY REPORT
# ---------------------------------------------
$successCount = @($results | Where-Object { $_.Status -eq "Success" }).Count
$skippedCount = @($results | Where-Object { $_.Status -eq "Skipped" }).Count
$failCount    = @($results | Where-Object { $_.Status -eq "Failed" }).Count
$failColor = if ($failCount -gt 0) { "Red" } else { "Gray" }

$totalStr = "$($results.Count)".PadRight(36)
$successStr = "$successCount".PadRight(36)
$skippedStr = "$skippedCount".PadRight(36)
$failStr = "$failCount".PadRight(36)

Write-Host ""
Write-Host "+==================================================+" -ForegroundColor Gray
Write-Host "|                     SUMMARY                      |" -ForegroundColor Gray
Write-Host "+==================================================+" -ForegroundColor Gray
Write-Host "|  Total     : ${totalStr}|" -ForegroundColor Gray
Write-Host "|  Succeeded : " -NoNewline
Write-Host "${successStr}" -ForegroundColor Green -NoNewline
Write-Host "|"
if ($skippedCount -gt 0) {
    Write-Host "|  Skipped   : " -NoNewline
    Write-Host "${skippedStr}" -ForegroundColor Yellow -NoNewline
    Write-Host "|"
}
Write-Host "|  Failed    : " -NoNewline
Write-Host "${failStr}" -ForegroundColor $failColor -NoNewline
Write-Host "|"
Write-Host "+==================================================+" -ForegroundColor Gray

# ---------------------------------------------
# POST-RUN COMPRESSION
# Creates a timestamped .zip archive with individually-zipped output
# directories (logs.zip, json.zip, netcortex.zip) inside a single outer archive.
# ---------------------------------------------
if ($CompressOutput) {
    $shouldCompress = $true
    if ($CompressWhen -eq 'SuccessOnly' -and $failedIPs.Count -gt 0) {
        $shouldCompress = $false
        Write-Host ""
        Write-Host "Compression skipped: $($failedIPs.Count) device(s) failed (CompressWhen = SuccessOnly)." -ForegroundColor Yellow
    }
    if ($shouldCompress) {
        Invoke-CompressOutput -OutputDirectories @($LogDirectory, $JsonDirectory, $NetcortexDirectory) -Cleanup $DeleteAfterCompress
    }
}

# ---------------------------------------------
# CLEANUP - Remove askpass helper securely
# ---------------------------------------------
try {
    Remove-Item -Path $askPassDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Verbose "Cleaned up SSH_ASKPASS helper."
}
catch {
    Write-Warning "Could not remove temporary askpass script at '$askPassDir'. Please delete manually."
}

# Clear password from memory
$password = $null
[System.GC]::Collect()

# Stop the runtime transcript
try { Stop-Transcript | Out-Null } catch { }
