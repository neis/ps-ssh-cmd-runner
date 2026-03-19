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

.PARAMETER CommandsFile
    Path to a text file containing one command per line to execute on each device.

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
    the device can process them. *Default is 0ms*. Increase for slower
    devices or commands that produce large output.

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

    [Parameter(Mandatory = $false, HelpMessage = "Path to file with one command per line")]
    [string]$CommandsFile = ".\commands.txt",

    [Parameter(Mandatory = $false)]
    [string]$LogDirectory = ".\logs",

    [Parameter(Mandatory = $false)]
    [ValidateRange(5, 120)]
    [int]$TimeoutSeconds = 10,

    [Parameter(Mandatory = $false, HelpMessage = "Additional SSH options for legacy/special devices (e.g. '-o','KexAlgorithms=+diffie-hellman-group1-sha1')")]
    [string[]]$ExtraSSHOptions = @(),

    [Parameter(Mandatory = $false, HelpMessage = "Delay in milliseconds between sending each command to the device (default 500)")]
    [ValidateRange(100, 10000)]
    [int]$CommandDelayMs = 500,

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
    [bool]$DeleteAfterCompress = $false
)

# ---------------------------------------------
# CONFIG FILE LOADING
# Precedence: CLI args > config.json > param() defaults
# ---------------------------------------------
$configPath = Join-Path $PSScriptRoot "config.json"

if (Test-Path $configPath -PathType Leaf) {
    try {
        $config = Get-Content $configPath -Raw | ConvertFrom-Json
    }
    catch {
        Write-Host "ERROR: config.json could not be parsed: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }

    $requiredKeys = @(
        'DeviceListFile', 'CommandsFile', 'LogDirectory', 'TimeoutSeconds',
        'ExtraSSHOptions', 'CommandDelayMs', 'CommandTimeoutSeconds', 'InitialPromptTimeoutSeconds',
        'AllocatePTY', 'PingTest',
        'JsonDirectory', 'NetcortexDirectory', 'LogEnabled', 'JsonEnabled', 'NetcortexEnabled',
        'CredentialLabel', 'ClearCredentials',
        'CompressOutput', 'CompressWhen', 'DeleteAfterCompress'
    )
    $missingKeys = $requiredKeys | Where-Object { $config.PSObject.Properties.Name -notcontains $_ }
    if ($missingKeys.Count -gt 0) {
        Write-Host "ERROR: config.json is missing required parameter(s): $($missingKeys -join ', ')" -ForegroundColor Red
        exit 1
    }

    if (-not $PSBoundParameters.ContainsKey('DeviceListFile'))        { $DeviceListFile        = $config.DeviceListFile }
    if (-not $PSBoundParameters.ContainsKey('CommandsFile'))          { $CommandsFile          = $config.CommandsFile }
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
    if (-not $PSBoundParameters.ContainsKey('JsonEnabled'))           { $JsonEnabled           = [bool]$config.JsonEnabled }
    if (-not $PSBoundParameters.ContainsKey('NetcortexEnabled'))   { $NetcortexEnabled   = [bool]$config.NetcortexEnabled }
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
$runDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$osPlatform = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription.Trim()
$psEngine = "PowerShell $($PSVersionTable.PSVersion.ToString())"
$separator = ("=" * 59)
$thinSep = ("-" * 40)

# Validate input files exist
if (-not (Test-Path $DeviceListFile -PathType Leaf)) {
    Write-Error "Device list file not found: '$DeviceListFile'"
    exit 1
}
if (-not (Test-Path $CommandsFile -PathType Leaf)) {
    Write-Error "Commands file not found: '$CommandsFile'"
    exit 1
}

# Verify ssh.exe is available
$sshPath = Get-Command ssh.exe -ErrorAction SilentlyContinue
if (-not $sshPath) {
    Write-Error "ssh.exe not found in PATH. Install OpenSSH client (Windows Optional Feature) and retry."
    exit 1
}
Write-Verbose "Using SSH client: $($sshPath.Source)"

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

# Read and validate device list (skip blanks and comments)
$devices = Get-Content $DeviceListFile |
ForEach-Object { $_.Trim() } |
Where-Object { $_ -ne "" -and $_ -notmatch "^\s*#" }

if ($devices.Count -eq 0) {
    Write-Error "No device IPs found in '$DeviceListFile'."
    exit 1
}

# Read commands
$commands = Get-Content $CommandsFile |
ForEach-Object { $_.Trim() } |
Where-Object { $_ -ne "" -and $_ -notmatch "^\s*#" }

if ($commands.Count -eq 0) {
    Write-Error "No valid commands found in '$CommandsFile'."
    exit 1
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
# CREDENTIAL MANAGEMENT
# Precedence: Windows Credential Manager > interactive prompt.
# Credentials are written to Credential Manager only after a successful
# device connection confirms they work. ClearCredentials forces a fresh
# prompt and removes any stored entry before looking up new ones.
# ---------------------------------------------
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

# ---------------------------------------------
# HELPER FUNCTION: Parse device hostname from SSH output
# Matches common network device prompt patterns:
#   Cisco IOS/NX-OS  :  hostname#  hostname>  hostname(config)#
#   Arista EOS       :  hostname#  hostname>  hostname(config)#
#   Juniper JunOS    :  user@hostname>  user@hostname#
#   Palo Alto        :  user@hostname>  user@hostname#
#   HP/Aruba         :  hostname#  hostname>
#   Linux-based NOS  :  user@hostname:~$  [user@hostname ~]$
# ---------------------------------------------
function Get-HostnameFromPrompt {
    param([string]$Output)

    $lines = $Output -split "`r?`n"

    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }

        # Juniper / PAN style: user@hostname> or user@hostname# or user@hostname:~$
        if ($trimmed -match '^\S*?@([A-Za-z0-9_-]+)[>#:\$%]') {
            return $Matches[1]
        }

        # Cisco / Arista / HP style: hostname# or hostname> or hostname(config-xxx)#
        if ($trimmed -match '^([A-Za-z][A-Za-z0-9._-]*)(?:\([A-Za-z0-9/_-]*\))?[#>]\s*$') {
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
# ---------------------------------------------
function Read-UntilPrompt {
    param(
        [System.Collections.Concurrent.ConcurrentQueue[string]]$Queue,
        [System.Text.StringBuilder]$Builder,
        [System.Text.RegularExpressions.Regex]$PromptRegex,
        [int]$TimeoutMs,
        [ref]$PromptText
    )
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    $line = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($Queue.TryDequeue([ref]$line)) {
            if ($null -eq $line) {
                # Null sentinel: stream closed. Treat as prompt-found so the
                # caller doesn't hang, but leave PromptText empty.
                if ($null -ne $PromptText) { $PromptText.Value = "" }
                return $true
            }
            if ($PromptRegex.IsMatch($line.TrimEnd())) {
                # Hold the prompt — do NOT append it to Builder yet.
                # The caller will prepend it to the echoed command line.
                if ($null -ne $PromptText) { $PromptText.Value = $line.TrimEnd() }
                return $true
            }
            $Builder.AppendLine($line) | Out-Null
        }
        else {
            Start-Sleep -Milliseconds 50
        }
    }
    return $false
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
        [bool]$AllocatePTY = $false
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
            '(?:^\S*?@[A-Za-z0-9_-]+[>#:\$%])|(?:^[A-Za-z][A-Za-z0-9._-]*(?:\([A-Za-z0-9/_-]*\))?[#>]\s*$)|(?:^\[?\S+?@[A-Za-z0-9_-]+\s)',
            [System.Text.RegularExpressions.RegexOptions]::Compiled
        )
        # Cisco IOS sends the prompt without a trailing newline even without a PTY,
        # so ReadLine() would block indefinitely on the prompt line. The runspace
        # reads one character at a time and flushes to the queue on every newline
        # AND whenever the accumulated buffer matches a device prompt pattern.
        # The prompt-flush regex requires a valid hostname prefix before # or >
        # so that pager strings like "--More--" are never mistaken for a prompt.
        $lineQueue = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
        # Single-element array shared with the reader runspace as a mutable regex slot.
        # The outer scope overwrites [0] once the device hostname is known; the runspace
        # reads it on every character iteration. String reference assignment is atomic in .NET.
        $regexHolder = [string[]]::new(1)
        $regexHolder[0] = '(?:^\S*?@[A-Za-z0-9_-]+[>#]|^[A-Za-z][A-Za-z0-9._-]*(?:\([A-Za-z0-9/_-]*\))?[#>])\s*$'

        $readerRunspace = [PowerShell]::Create()
        $readerRunspace.AddScript({
                param($reader, $queue, $holder)
                try {
                    $buf = [System.Text.StringBuilder]::new()
                    while ($true) {
                        $c = $reader.Read()       # blocks until a char is available or EOS
                        if ($c -eq -1) { break }  # end of stream
                        $ch = [char]$c
                        if ($ch -eq "`r") { continue }   # discard bare CR
                        if ($ch -eq "`n") {
                            $queue.Enqueue($buf.ToString())
                            $buf.Clear() | Out-Null
                        }
                        else {
                            $buf.Append($ch) | Out-Null
                            $s = $buf.ToString()
                            # Flush when the buffer matches the current prompt pattern.
                            # After the hostname is discovered the outer scope writes a
                            # tighter hostname-anchored pattern into $holder[0], preventing
                            # table column headers (e.g. "Switch#") from being flushed.
                            if ($s -match $holder[0]) {
                                $queue.Enqueue($s)
                                $buf.Clear() | Out-Null
                            }
                        }
                    }
                    if ($buf.Length -gt 0) { $queue.Enqueue($buf.ToString()) }
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

        if (-not $usePTY -and $ptyAttempt -eq 0) {
            # Phase 1: Quick check (up to 10s) — enough for stty error to appear in stderr.
            # If the prompt arrives quickly, we proceed immediately.
            $quickMs = [Math]::Min(10000, $initialTimeoutMs)
            $promptFound = Read-UntilPrompt -Queue $lineQueue -Builder $stdOutBuilder -PromptRegex $promptRegex -TimeoutMs $quickMs -PromptText ([ref]$lastPrompt)

            if (-not $promptFound) {
                # Check stderr for stty failure — indicates device requires PTY allocation.
                if ($stdErrBuilder.ToString() -match "stty.*Inappropriate ioctl") {
                    Write-Verbose "stty error detected on $IPAddress - retrying with PTY allocation (-tt)"
                    $usePTY = $true
                    continue   # finally cleans up this attempt, loop retries with -tt
                }

                # No stty error — continue waiting for the remaining initial timeout.
                $remainingMs = $initialTimeoutMs - $quickMs
                if ($remainingMs -gt 0) {
                    $promptFound = Read-UntilPrompt -Queue $lineQueue -Builder $stdOutBuilder -PromptRegex $promptRegex -TimeoutMs $remainingMs -PromptText ([ref]$lastPrompt)
                }
            }
        }
        else {
            # AllocatePTY is true (or this is a PTY retry): use the full initial timeout.
            $promptFound = Read-UntilPrompt -Queue $lineQueue -Builder $stdOutBuilder -PromptRegex $promptRegex -TimeoutMs $initialTimeoutMs -PromptText ([ref]$lastPrompt)
        }

        if (-not $promptFound) {
            # Aggressive fallback: if this was a -T attempt with zero stdout, retry with PTY.
            # Covers devices that need PTY but don't produce the stty error (e.g. libssh servers).
            if (-not $usePTY -and $ptyAttempt -eq 0 -and $stdOutBuilder.Length -eq 0) {
                Write-Verbose "Zero stdout on $IPAddress after ${InitialCmdTimeoutSec}s - retrying with PTY allocation (-tt)"
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
            $regexHolder[0] = "(?:^\S*?@$hn[>#:`$%]|^$hn(?:\([A-Za-z0-9/_-]*\))?[#>])\s*`$"

            # Replace the compiled Regex used by Read-UntilPrompt for all subsequent calls.
            $promptRegex = [System.Text.RegularExpressions.Regex]::new(
                "(?:^\S*?@$hn[>#:`$%])|(?:^$hn(?:\([A-Za-z0-9/_-]*\))?[#>]\s*`$)",
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
            Read-UntilPrompt -Queue $lineQueue -Builder $sttyDrain -PromptRegex $promptRegex -TimeoutMs 5000 -PromptText ([ref]$null) | Out-Null
            # Drain the stty command text echo and wait for the real prompt
            Read-UntilPrompt -Queue $lineQueue -Builder $sttyDrain -PromptRegex $promptRegex -TimeoutMs 5000 -PromptText ([ref]$lastPrompt) | Out-Null
        }

        # Send each command and wait for the resulting prompt before proceeding.
        # This guarantees all output from a command is collected before the next
        # command is sent, eliminating the out-of-order output race condition.
        foreach ($cmd in $CommandList) {
            # Optional settle delay applied after receiving the previous prompt,
            # before sending the next command. Useful for devices that display
            # the prompt slightly before their output buffer is fully flushed.
            if ($CmdDelayMs -gt 0) { Start-Sleep -Milliseconds $CmdDelayMs }

            $proc.StandardInput.WriteLine($cmd)
            $proc.StandardInput.Flush()

            # Cisco IOS echoes the command back as the first line of output.
            # Dequeue that echo and join it with the held prompt to produce the
            # natural "hostname#show inventory" layout seen in a live session.
            $echoLine = ""
            $echoDeadline = [DateTime]::UtcNow.AddMilliseconds(5000)
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
            if (-not (Read-UntilPrompt -Queue $lineQueue -Builder $cmdOutputBuilder -PromptRegex $promptRegex -TimeoutMs $perCmdTimeoutMs -PromptText ([ref]$lastPrompt))) {
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
        $proc.StandardInput.Close()

        # Drain any remaining output after stdin is closed (e.g. logout messages).
        Read-UntilPrompt -Queue $lineQueue -Builder $stdOutBuilder -PromptRegex $promptRegex -TimeoutMs ([Math]::Min($perCmdTimeoutMs, 5000)) -PromptText ([ref]$null) | Out-Null

        # Overall safety-net timeout: initial prompt wait + per-command read time +
        # settle delays + post-drain + 15s margin. Under normal operation the process
        # will have already exited by the time this is reached.
        $overallTimeoutMs = ($Timeout * 1000) +
        ($CommandList.Count * $CmdTimeoutSec * 1000) +
        ($CommandList.Count * $CmdDelayMs) +
        15000
        $exited = $proc.WaitForExit($overallTimeoutMs)

        if (-not $exited) {
            $proc.Kill()
            throw "SSH session timed out after $([math]::Round($overallTimeoutMs / 1000))s (overall timeout)."
        }

        Unregister-Event -SourceIdentifier $errEvent.Name -ErrorAction SilentlyContinue

        # Wait for the reader runspace to finish draining the stdout stream
        $readerRunspace.EndInvoke($readerHandle) | Out-Null
        $readerRunspace.Dispose()

        $stdOut = $stdOutBuilder.ToString()
        $stdErr = $stdErrBuilder.ToString().Trim()

        # Determine success or failure
        if ($proc.ExitCode -ne 0) {
            $result.Status = "Failed"
            if ([string]::IsNullOrWhiteSpace($stdErr)) {
                $result.Error = "SSH exit code $($proc.ExitCode)"
            }
            else {
                # Parse each line of debug for final error output detail
                $errorLines = $stdErr -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                foreach ($err in $errorLines) {
                    $result.Error = $err
                }
            }
            $result.AuthFailed = Test-IsAuthFailure -StdErr $stdErr
        }
        else {
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
# MAIN EXECUTION LOOP
# ---------------------------------------------
$devCountStr = "$($devices.Count)".PadRight(37)
$cmdCountStr = "$($commands.Count)".PadRight(37)
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
Write-Host "|  Commands : ${cmdCountStr}|" -ForegroundColor Gray
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

foreach ($ip in $devices) {
    $deviceNum++
    Write-Host "[$deviceNum/$($devices.Count)] Connecting to $ip ... " -NoNewline

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

    # Auth retry loop — retries the same device when credentials are rejected.
    # Non-auth failures (timeout, connectivity) break out immediately.
    do {
        $sessionResult = Invoke-SSHSession `
            -IPAddress             $ip `
            -User                  $username `
            -CommandList           $commands `
            -Timeout               $TimeoutSeconds `
            -SSHOptions            $ExtraSSHOptions `
            -CmdDelayMs            $CommandDelayMs `
            -CmdTimeoutSec         $CommandTimeoutSeconds `
            -InitialCmdTimeoutSec  $InitialPromptTimeoutSeconds `
            -AllocatePTY           $AllocatePTY

        if ($sessionResult.AuthFailed) {
            $authRetryCount++
            Write-Host ""
            Write-Host "  Authentication rejected by $ip." -ForegroundColor Red

            if ($authRetryCount -ge $maxAuthRetries) {
                Write-Host "  ERROR: Credentials rejected $maxAuthRetries consecutive time(s). Aborting." -ForegroundColor Red
                try { Remove-Item -Path $askPassDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}
                $password = $null
                [System.GC]::Collect()
                exit 1
            }

            Write-Host "  Retry $authRetryCount of $($maxAuthRetries - 1) - please enter updated credentials." -ForegroundColor Yellow
            $credential = Get-Credential -Message "Credentials rejected - enter new credentials (retry $authRetryCount of $($maxAuthRetries - 1))"
            if ($null -eq $credential) {
                Write-Host "  Credential prompt cancelled. Aborting." -ForegroundColor Red
                try { Remove-Item -Path $askPassDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}
                exit 1
            }
            $username         = $credential.UserName
            $password         = $credential.GetNetworkCredential().Password
            $credentialsSaved = $false   # new credentials must be saved after next success
            Set-AskPassScript -ScriptPath $askPassScript -Password $password

            Write-Host "[$deviceNum/$($devices.Count)] Retrying $ip ... " -NoNewline
        }
    } while ($sessionResult.AuthFailed)

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
        $authRetryCount = 0   # reset consecutive failure counter on any successful connection
    }
    else {
        Write-Host "FAILED: " -ForegroundColor Red -NoNewline
        Write-Host "$($sessionResult.Error)" -ForegroundColor DarkRed
        # Non-auth failures (timeouts, connectivity) do not consume the retry budget.
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
    foreach ($r in $successResults) {
        $safeDevice = ConvertTo-SafeFileName $r.DeviceName
        $safeIP = ConvertTo-SafeFileName $r.IPAddress
        $netcortexFile = Join-Path $NetcortexDirectory "${safeDevice}_${safeIP}_${timestamp}.txt"

        # Build netcortex content: prompt+command echo, raw output, bare prompt separator.
        # Trailing blank lines are stripped from each command's output so the bare
        # prompt lands immediately after the last non-empty output line — giving the
        # downstream ingest a clean prompt-delimited structure with no ambiguous blanks.
        $netcortexLines = [System.Collections.Generic.List[string]]::new()
        foreach ($cr in $r.CommandResults) {
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
    # --- Session summary file ---
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
        commands = [ordered]@{
            count = $commands.Count
            list  = @($commands)
        }
    }
    $sessionPath = Join-Path $JsonDirectory "ssh-session-${timestamp}.json"
    $sessionDoc | ConvertTo-Json -Depth 10 | Set-Content -Path $sessionPath -Encoding UTF8

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
# Creates a timestamped .zip archive of all output directories using
# PowerShell's built-in Compress-Archive.
# Source directories are only removed when archive creation is confirmed.
# ---------------------------------------------
if ($CompressOutput) {
    $shouldCompress = $true
    if ($CompressWhen -eq 'SuccessOnly' -and $failedIPs.Count -gt 0) {
        $shouldCompress = $false
        Write-Host ""
        Write-Host "Compression skipped: $($failedIPs.Count) device(s) failed (CompressWhen = SuccessOnly)." -ForegroundColor Yellow
    }

    if ($shouldCompress) {
        $archiveName = "ssh-session-${timestamp}.zip"
        $archivePath = Join-Path $PSScriptRoot $archiveName

        # Collect all configured output directories that exist on disk and contain
        # at least one file. Empty directories are excluded from the archive.
        $dirsToArchive = @($LogDirectory, $JsonDirectory, $NetcortexDirectory) |
            Where-Object {
                (Test-Path $_ -PathType Container) -and
                (Get-ChildItem -LiteralPath $_ -Recurse -File -ErrorAction SilentlyContinue |
                 Select-Object -First 1)
            }

        Write-Host ""
        if ($dirsToArchive.Count -eq 0) {
            Write-Host "Compression skipped: no output directories found on disk." -ForegroundColor Yellow
        }
        else {
            Write-Host "Compressing output via Compress-Archive ..." -ForegroundColor Cyan

            $archiveSuccess = $false
            try {
                Compress-Archive -Path $dirsToArchive -DestinationPath $archivePath -Force
                $archiveSuccess = (Test-Path $archivePath)
            }
            catch {
                Write-Host "  ERROR: Compression failed - $($_.Exception.Message)" -ForegroundColor Red
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

                if ($DeleteAfterCompress) {
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
