# SSH Flow Diagnostic
# Mirrors the exact logic of the main script with trace output at every
# decision point.
#
# Usage: .\ssh-flow-diag.ps1 -IP 10.1.50.1 -User nimda

param(
    [Parameter(Mandatory)]
    [string]$IP,

    [Parameter(Mandatory)]
    [string]$User
)

$Timeout = 5
$divider = "=" * 60

Write-Host $divider
Write-Host "End-to-End Flow Diagnostic"
Write-Host "Target: $IP  User: $User"
Write-Host $divider
Write-Host ""

# =====================================================
# PHASE 1: Invoke-SSHAttempt (simulated)
# =====================================================
Write-Host "PHASE 1: Invoke-SSHAttempt" -ForegroundColor Cyan
Write-Host $divider

$attemptExitCode = -1
$attemptStdOut = ""
$attemptStdErr = ""
$attemptErrorText = ""

# --- Step 1A: Run SSH via .NET Process ---
Write-Host ""
Write-Host "  STEP 1A: Run SSH via .NET Process" -ForegroundColor Yellow

$sshLogFile = Join-Path $env:TEMP ("ssh_flow_" + (Get-Random) + ".log")

$sshArgString = "-E `"$sshLogFile`" -o ConnectTimeout=$Timeout -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o LogLevel=ERROR -l $User $IP exit"

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "ssh.exe"
$psi.Arguments = $sshArgString
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $true

$proc = [System.Diagnostics.Process]::new()
$proc.StartInfo = $psi

try {
    $proc.Start() | Out-Null
    $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
    $stderrTask = $proc.StandardError.ReadToEndAsync()
    try { $proc.StandardInput.Close() } catch {}
    $proc.WaitForExit(15000) | Out-Null

    $attemptExitCode = $proc.ExitCode
    $attemptStdOut = $stdoutTask.GetAwaiter().GetResult()
    $attemptStdErr = $stderrTask.GetAwaiter().GetResult().Trim()
}
finally {
    try { if ($null -ne $proc) { $proc.Dispose() } } catch {}
}

Write-Host "    ExitCode : $attemptExitCode"
Write-Host "    StdOut   : [$($attemptStdOut.Length) chars]"
Write-Host "    StdErr   : [$($attemptStdErr.Length) chars] $attemptStdErr"
Write-Host ""

# --- Step 1B: Read -E log file ---
Write-Host "  STEP 1B: Read -E log file" -ForegroundColor Yellow

$sshLogContent = ""
$logExists = Test-Path $sshLogFile
if ($logExists) {
    $rawContent = Get-Content -Path $sshLogFile -Raw -ErrorAction SilentlyContinue
    if ($null -ne $rawContent) {
        $sshLogContent = $rawContent.Trim()
    }
}
Remove-Item -Path $sshLogFile -Force -ErrorAction SilentlyContinue

Write-Host "    -E file exists : $logExists"
Write-Host "    -E content     : [$($sshLogContent.Length) chars] $sshLogContent"
Write-Host ""

# --- Step 1C: Populate StdErr from -E if needed ---
Write-Host "  STEP 1C: Populate StdErr from -E log" -ForegroundColor Yellow

$stderrEmpty = [string]::IsNullOrWhiteSpace($attemptStdErr)
$logEmpty = [string]::IsNullOrWhiteSpace($sshLogContent)

Write-Host "    StdErr is empty : $stderrEmpty"
Write-Host "    -E log is empty : $logEmpty"

if ($stderrEmpty -and (-not $logEmpty)) {
    $attemptStdErr = $sshLogContent
    Write-Host "    -> Updated StdErr from -E log" -ForegroundColor Green
}
else {
    Write-Host "    -> No update" -ForegroundColor DarkYellow
}
Write-Host "    StdErr now: [$($attemptStdErr.Length) chars] $attemptStdErr"
Write-Host ""

# --- Step 1D: Verbose probe ---
Write-Host "  STEP 1D: Verbose probe check" -ForegroundColor Yellow

$shouldProbe = ($attemptExitCode -ne 0) -and ([string]::IsNullOrWhiteSpace($attemptStdErr))
Write-Host "    ExitCode != 0    : $($attemptExitCode -ne 0)"
Write-Host "    StdErr is empty  : $([string]::IsNullOrWhiteSpace($attemptStdErr))"
Write-Host "    Should probe     : $shouldProbe"

if ($shouldProbe) {
    Write-Host "    Running -v probe..." -ForegroundColor Yellow

    $probeArgs = @(
        "-v",
        "-o", "ConnectTimeout=$Timeout",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "BatchMode=yes",
        "-l", $User, $IP, "exit"
    )

    Write-Host "    Probe cmd: ssh.exe $($probeArgs -join ' ')"

    try {
        $probeOutput = & ssh.exe @probeArgs 2>&1
        $probeLines = @($probeOutput | ForEach-Object { $_.ToString() })

        Write-Host "    Probe total lines: $($probeLines.Count)"

        $matchPattern = "Unable to negotiate|no matching|Their offer|Connection refused|Connection timed out|No route to host|Permission denied|Host key verification failed|Connection closed|Connection reset|kex_exchange"

        $errorLines = @($probeLines | Where-Object { $_ -match $matchPattern })

        Write-Host "    Probe error lines: $($errorLines.Count)"
        foreach ($el in $errorLines) {
            Write-Host "    -> $el" -ForegroundColor Red
        }

        if ($errorLines.Count -gt 0) {
            $attemptStdErr = $errorLines -join "`r`n"
            Write-Host "    -> Updated StdErr from probe" -ForegroundColor Green
        }
        else {
            Write-Host "    -> No error lines matched" -ForegroundColor DarkYellow
            Write-Host "    All probe lines:" -ForegroundColor DarkYellow
            foreach ($pl in $probeLines) {
                Write-Host "      $pl" -ForegroundColor Gray
            }
        }
    }
    catch {
        Write-Host "    PROBE EXCEPTION: $($_.Exception.Message)" -ForegroundColor Red
    }
}
else {
    Write-Host "    Skipped" -ForegroundColor DarkYellow
}
Write-Host "    StdErr now: [$($attemptStdErr.Length) chars] $attemptStdErr"
Write-Host ""

# --- Step 1E: ErrorText assembly ---
Write-Host "  STEP 1E: ErrorText assembly" -ForegroundColor Yellow

$diagPatterns = @(
    "Unable to negotiate",
    "no matching",
    "key exchange method",
    "host key type",
    "cipher",
    "Connection closed by",
    "Connection reset by",
    "kex_exchange_identification",
    "banner exchange",
    "Host key verification failed"
)
$diagJoined = ($diagPatterns | ForEach-Object { [regex]::Escape($_) }) -join "|"
$stdOutDiagLines = ($attemptStdOut -split "`r?`n" | Where-Object { $_ -match $diagJoined }) -join "`r`n"

Write-Host "    StdOut diag lines : [$($stdOutDiagLines.Length) chars]"
Write-Host "    StdErr            : [$($attemptStdErr.Length) chars]"

$allErrorText = @($attemptStdErr, $stdOutDiagLines) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
$attemptErrorText = ($allErrorText -join "`r`n").Trim()

Write-Host "    allErrorText count: $($allErrorText.Count)"
Write-Host "    Final ErrorText   : [$($attemptErrorText.Length) chars] $attemptErrorText"
Write-Host ""

# =====================================================
# PHASE 2: Fallback detection
# =====================================================
Write-Host $divider
Write-Host "PHASE 2: Fallback detection" -ForegroundColor Cyan
Write-Host $divider
Write-Host ""

Write-Host "  Values at this point:" -ForegroundColor Yellow
Write-Host "    ExitCode  : $attemptExitCode"
Write-Host "    StdOut    : [$($attemptStdOut.Length) chars]"
Write-Host "    StdErr    : [$($attemptStdErr.Length) chars]"
Write-Host "    ErrorText : [$($attemptErrorText.Length) chars]"
Write-Host ""

$gateCheck = ($attemptExitCode -ne 0)
Write-Host "  Gate (ExitCode != 0): $gateCheck" -ForegroundColor Yellow

if ($gateCheck) {
    $errorCheck = "$attemptErrorText $attemptStdErr $attemptStdOut"
    Write-Host "  errorCheck length  : $($errorCheck.Length) chars"
    Write-Host "  errorCheck preview : $($errorCheck.Substring(0, [Math]::Min(200, $errorCheck.Length)))"
    Write-Host ""

    Write-Host "  Pattern matching:" -ForegroundColor Yellow

    $fallbackPatterns = @(
        "no matching key exchange method",
        "no matching host key type",
        "no matching cipher",
        "no matching MAC"
    )

    $needsRetry = $false
    foreach ($pat in $fallbackPatterns) {
        $escaped = [regex]::Escape($pat)
        $matched = $errorCheck -match $escaped
        if ($matched) { $needsRetry = $true }
        $color = if ($matched) { "Green" } else { "Gray" }
        Write-Host "    Pattern: '$pat' -> $matched" -ForegroundColor $color
    }

    Write-Host ""
    $retryColor = if ($needsRetry) { "Green" } else { "Red" }
    Write-Host "  needsRetry: $needsRetry" -ForegroundColor $retryColor
}
Write-Host ""

# =====================================================
# PHASE 3: Final message
# =====================================================
Write-Host $divider
Write-Host "PHASE 3: Final error message" -ForegroundColor Cyan
Write-Host $divider
Write-Host ""

$combinedErrorText = $attemptErrorText
$isEmpty = [string]::IsNullOrWhiteSpace($combinedErrorText)

Write-Host "  combinedErrorText length : $($combinedErrorText.Length)"
Write-Host "  IsNullOrWhiteSpace       : $isEmpty"
Write-Host ""

if ($attemptExitCode -ne 0) {
    if ($isEmpty) {
        Write-Host "  RESULT: SSH exited with code $attemptExitCode (no error detail captured)" -ForegroundColor Red
    }
    else {
        Write-Host "  RESULT: SSH exit code ${attemptExitCode}: $combinedErrorText" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host $divider -ForegroundColor Cyan
Write-Host "DIAGNOSTIC COMPLETE" -ForegroundColor Cyan
Write-Host $divider -ForegroundColor Cyan
