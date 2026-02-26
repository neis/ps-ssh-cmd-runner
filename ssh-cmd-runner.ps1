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

    [Parameter(Mandatory = $false, HelpMessage = "Directory where the JSON output file will be saved. Created automatically if it doesn't exist.")]
    [string]$JsonDirectory = ".\json"
)

# ---------------------------------------------
# INITIALIZE
# ---------------------------------------------
$ErrorActionPreference = "Stop"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$runDate   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
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
if (-not (Test-Path $LogDirectory)) {
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    #Write-Host "[INFO] Created log directory: $LogDirectory" -ForegroundColor Cyan
}

# Create JSON output directory
if (-not (Test-Path $JsonDirectory)) {
    New-Item -ItemType Directory -Path $JsonDirectory -Force | Out-Null
}

# Read and validate device list (skip blanks and comments)
$devices = Get-Content $DeviceListFile |
ForEach-Object { $_.Trim() } |
Where-Object { $_ -ne "" -and $_ -notmatch "^\s*#" }

if ($devices.Count -eq 0) {
    Write-Error "No valid device IPs found in '$DeviceListFile'."
    exit 1
}
#Write-Host "[INFO] Loaded $($devices.Count) device(s) from '$DeviceListFile'" -ForegroundColor Cyan

# Read commands
$commands = Get-Content $CommandsFile |
ForEach-Object { $_.Trim() } |
Where-Object { $_ -ne "" -and $_ -notmatch "^\s*#" }

if ($commands.Count -eq 0) {
    Write-Error "No valid commands found in '$CommandsFile'."
    exit 1
}
#Write-Host "[INFO] Loaded $($commands.Count) command(s) from '$CommandsFile'" -ForegroundColor Cyan

# Prompt for credentials (once)
Write-Host ""
$credential = Get-Credential -Message "Enter SSH credentials for network devices"
$username = $credential.UserName
$password = $credential.GetNetworkCredential().Password

# Escape characters that cmd.exe treats as special operators.
# Without this, passwords containing & | < > ^ % ! will be
# misinterpreted by the command shell when the askpass helper runs.
# Caret (^) must be escaped first to avoid double-escaping the others.
$escapedPassword = $password
$escapedPassword = $escapedPassword.Replace('^', '^^')
$escapedPassword = $escapedPassword.Replace('&', '^&')
$escapedPassword = $escapedPassword.Replace('|', '^|')
$escapedPassword = $escapedPassword.Replace('<', '^<')
$escapedPassword = $escapedPassword.Replace('>', '^>')
$escapedPassword = $escapedPassword.Replace('!', '^!')
$escapedPassword = $escapedPassword.Replace('%', '%%')

# ---------------------------------------------
# SSH_ASKPASS HELPER
# Creates a temporary script that ssh.exe calls to retrieve the password
# so we avoid interactive password prompts per device.
# ---------------------------------------------
$askPassDir = Join-Path $env:TEMP "ssh_askpass_$timestamp"
New-Item -ItemType Directory -Path $askPassDir -Force | Out-Null

$askPassScript = Join-Path $askPassDir "askpass.cmd"
Set-Content -Path $askPassScript -Value "@echo $escapedPassword" -Force

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
        [int]$CmdDelayMs = 500
    )

    $result = [PSCustomObject]@{
        IPAddress      = $IPAddress
        DeviceName     = ""
        Status         = "Unknown"
        LogFile        = ""
        Error          = ""
        Duration       = [TimeSpan]::Zero
        Timestamp      = ""   # completion timestamp, set in finally block
        CommandResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        # Build ssh arguments
        $sshArgs = @(
            "-v",
            "-T",
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
        $regexHolder    = [string[]]::new(1)
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
        $perCmdTimeoutMs = $Timeout * 1000
        $lastPrompt = ""
        if (-not (Read-UntilPrompt -Queue $lineQueue -Builder $stdOutBuilder -PromptRegex $promptRegex -TimeoutMs $perCmdTimeoutMs -PromptText ([ref]$lastPrompt))) {
            $proc.Kill()
            throw "Timed out waiting for initial device prompt after ${Timeout}s."
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

            $lastPrompt = ""
            if (-not (Read-UntilPrompt -Queue $lineQueue -Builder $cmdOutputBuilder -PromptRegex $promptRegex -TimeoutMs $perCmdTimeoutMs -PromptText ([ref]$lastPrompt))) {
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
        ($CommandList.Count * $Timeout * 1000) +
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
            " Device  : $deviceName ($IPAddress)"
            " User    : $User"
            " Date    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            " Status  : $($result.Status)"
            " Timeout : ${Timeout}s"
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

        Set-Content -Path $logFilePath -Value ($logLines -join "`r`n") -Encoding UTF8
    }
    catch {
        $result.Status = "Failed"
        $result.Error = $_.Exception.Message
        $result.DeviceName = "unknown"

        # Still write a failure log
        $safeIP = ConvertTo-SafeFileName $IPAddress
        $logFileName = "unknown_${safeIP}_${timestamp}.log"
        $logFilePath = Join-Path $LogDirectory $logFileName
        $result.LogFile = $logFilePath

        $failLines = @(
            $separator
            " Device  : unknown ($IPAddress)"
            " User    : $User"
            " Date    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            " Status  : FAILED"
            " Timeout : ${Timeout}s"
            $separator
            ""
            "ERROR: $($_.Exception.Message)"
        )

        Set-Content -Path $logFilePath -Value ($failLines -join "`r`n") -Encoding UTF8
    }
    finally {
        $sw.Stop()
        $result.Duration  = $sw.Elapsed
        $result.Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

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

    return $result
}

# ---------------------------------------------
# MAIN EXECUTION LOOP
# ---------------------------------------------
$devCountStr = "$($devices.Count)".PadRight(37)
$cmdCountStr = "$($commands.Count)".PadRight(37)
$timeoutStr = "${TimeoutSeconds}s".PadRight(37)
$logDirStr = $LogDirectory
if ($logDirStr.Length -gt 37) { $logDirStr = $logDirStr.Substring(0, 34) + "..." }
$logDirStr = $logDirStr.PadRight(37)

Write-Host ""
Write-Host "+==================================================+" -ForegroundColor Green
Write-Host "|       SSH Network Command Runner - Starting      |" -ForegroundColor Green
Write-Host "+==================================================+" -ForegroundColor Green
Write-Host "|  Devices  : ${devCountStr}|" -ForegroundColor Green
Write-Host "|  Commands : ${cmdCountStr}|" -ForegroundColor Green
Write-Host "|  Timeout  : ${timeoutStr}|" -ForegroundColor Green
Write-Host "|  Log Dir  : ${logDirStr}|" -ForegroundColor Green
if ($ExtraSSHOptions.Count -gt 0) {
    $sshOptsStr = ($ExtraSSHOptions -join " ")
    if ($sshOptsStr.Length -gt 37) { $sshOptsStr = $sshOptsStr.Substring(0, 34) + "..." }
    $sshOptsStr = $sshOptsStr.PadRight(37)
    Write-Host "|  SSH Opts : ${sshOptsStr}|" -ForegroundColor Green
}
Write-Host "+==================================================+" -ForegroundColor Green
Write-Host ""

$results = [System.Collections.Generic.List[PSCustomObject]]::new()
$deviceNum = 0

foreach ($ip in $devices) {
    $deviceNum++
    Write-Host "[$deviceNum/$($devices.Count)] Connecting to $ip ... " -NoNewline

    $sessionResult = Invoke-SSHSession `
        -IPAddress   $ip `
        -User        $username `
        -CommandList $commands `
        -Timeout     $TimeoutSeconds `
        -SSHOptions  $ExtraSSHOptions `
        -CmdDelayMs  $CommandDelayMs

    if ($sessionResult.Status -eq "Success") {
        Write-Host "OK " -ForegroundColor Green -NoNewline
        Write-Host "($($sessionResult.DeviceName)) [$($sessionResult.Duration.TotalSeconds.ToString('0.0'))s]"
    }
    else {
        Write-Host "FAILED: " -ForegroundColor Red -NoNewline
        Write-Host "$($sessionResult.Error)" -ForegroundColor DarkRed
    }

    $results.Add($sessionResult)
}

# ---------------------------------------------
# JSON OUTPUT
# ---------------------------------------------
$successResults = @($results | Where-Object { $_.Status -eq "Success" })
$failedIPs      = @($results | Where-Object { $_.Status -ne "Success" } | ForEach-Object { $_.IPAddress })

$jsonDoc = [ordered]@{
    summary = [ordered]@{
        platform = "Windows"
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
    devices  = @(
        $successResults | ForEach-Object {
            $dev = $_
            [ordered]@{
                name      = $dev.DeviceName
                ip        = $dev.IPAddress
                timestamp = $dev.Timestamp
                commands  = @(
                    $dev.CommandResults | ForEach-Object {
                        [ordered]@{
                            command    = $_.command
                            raw_output = @($_.raw_output)
                        }
                    }
                )
            }
        }
    )
}

$jsonPath = Join-Path $JsonDirectory "output.json"
$jsonDoc | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8
Write-Host ""
Write-Host "JSON output: $jsonPath" -ForegroundColor Cyan

# ---------------------------------------------
# SUMMARY REPORT
# ---------------------------------------------
$successCount = @($results | Where-Object { $_.Status -eq "Success" }).Count
$failCount = @($results | Where-Object { $_.Status -ne "Success" }).Count
$failColor = if ($failCount -gt 0) { "Red" } else { "Green" }

$totalStr = "$($results.Count)".PadRight(36)
$successStr = "$successCount".PadRight(36)
$failStr = "$failCount".PadRight(36)

Write-Host ""
Write-Host "+==================================================+" -ForegroundColor Gray
Write-Host "|                     SUMMARY                      |" -ForegroundColor Gray
Write-Host "+==================================================+" -ForegroundColor Gray
Write-Host "|  Total     : ${totalStr}|" -ForegroundColor Gray
Write-Host "|  Succeeded : " -NoNewline
Write-Host "${successStr}" -ForegroundColor Green -NoNewline
Write-Host "|"
Write-Host "|  Failed    : " -NoNewline
Write-Host "${failStr}" -ForegroundColor $failColor -NoNewline
Write-Host "|"
Write-Host "+==================================================+" -ForegroundColor Gray

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
