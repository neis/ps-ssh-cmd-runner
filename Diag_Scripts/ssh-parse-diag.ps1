# SSH Parse Diagnostic - Traces the exact code path from the main script's
# Invoke-SSHAttempt function to find where the error text gets lost.
#
# Usage: .\ssh-parse-diag.ps1 -IP 10.1.50.1 -User nimda

param(
    [Parameter(Mandatory)]
    [string]$IP,

    [Parameter(Mandatory)]
    [string]$User
)

Write-Host ("=" * 60)
Write-Host "Parse Flow Diagnostic - Tracing data through each step"
Write-Host "Target: $IP  User: $User"
Write-Host ("=" * 60)
Write-Host ""

# Replicate the exact SSH args from the main script
$sshLogFile = Join-Path $env:TEMP "ssh_parse_diag_$(Get-Random).log"

$sshArgs = @(
    "-E", $sshLogFile,
    "-o", "ConnectTimeout=5",
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "BatchMode=yes",
    "-o", "LogLevel=ERROR",
    "-l", $User,
    $IP
)

Write-Host "STEP 1: SSH log file path" -ForegroundColor Yellow
Write-Host "  Path: $sshLogFile"
Write-Host ""

Write-Host "STEP 2: SSH args string (as joined for ProcessStartInfo)" -ForegroundColor Yellow
$argString = $sshArgs -join " "
Write-Host "  Args: $argString"
Write-Host ""

# -----------------------------------------------
# STEP 3: Run SSH exactly as the main script does
# -----------------------------------------------
Write-Host "STEP 3: Running SSH via .NET Process (matching main script)" -ForegroundColor Yellow
Write-Host ("-" * 40)

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName               = "ssh.exe"
$psi.Arguments              = $argString
$psi.UseShellExecute        = $false
$psi.RedirectStandardInput  = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError  = $true
$psi.CreateNoWindow         = $true

$proc = [System.Diagnostics.Process]::new()
$proc.StartInfo = $psi

$stdOut = ""
$stdErr = ""
$exitCode = -1

try {
    $proc.Start() | Out-Null
    Write-Host "  Process started (PID: $($proc.Id))"

    $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
    $stderrTask = $proc.StandardError.ReadToEndAsync()
    Write-Host "  ReadToEndAsync started for stdout and stderr"

    # Try writing to stdin (will likely fail for negotiation failure)
    try {
        $proc.StandardInput.Write("exit`n")
        $proc.StandardInput.Flush()
        $proc.StandardInput.Close()
        Write-Host "  Stdin: write succeeded"
    }
    catch {
        Write-Host "  Stdin: write failed (expected) - $($_.Exception.Message)" -ForegroundColor DarkYellow
        try { $proc.StandardInput.Close() } catch {}
    }

    Write-Host "  Waiting for process to exit..."
    $exited = $proc.WaitForExit(15000)
    Write-Host "  Exited: $exited"

    if ($exited) {
        $exitCode = $proc.ExitCode
        Write-Host "  Exit code: $exitCode"

        Write-Host "  Reading stdout task..."
        try {
            $stdOut = $stdoutTask.GetAwaiter().GetResult()
            Write-Host "  Stdout: [$($stdOut.Length) chars] '$($stdOut.Trim())'"
        }
        catch {
            Write-Host "  Stdout task THREW: $($_.Exception.Message)" -ForegroundColor Red
        }

        Write-Host "  Reading stderr task..."
        try {
            $stdErr = $stderrTask.GetAwaiter().GetResult()
            Write-Host "  Stderr: [$($stdErr.Length) chars] '$($stdErr.Trim())'"
        }
        catch {
            Write-Host "  Stderr task THREW: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "  Process did not exit in time!" -ForegroundColor Red
        $proc.Kill()
    }
}
catch {
    Write-Host "  OUTER EXCEPTION: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  Exception type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
}
finally {
    try {
        if ($null -ne $proc) {
            if (-not $proc.HasExited) { $proc.Kill() }
            $proc.Dispose()
        }
    }
    catch {}
}

Write-Host ""

# -----------------------------------------------
# STEP 4: Check the -E log file
# -----------------------------------------------
Write-Host "STEP 4: SSH -E log file" -ForegroundColor Yellow
Write-Host ("-" * 40)
Write-Host "  File exists: $(Test-Path $sshLogFile)"
if (Test-Path $sshLogFile) {
    $sshLogContent = Get-Content -Path $sshLogFile -Raw -ErrorAction SilentlyContinue
    if ($null -eq $sshLogContent) {
        Write-Host "  Get-Content returned null" -ForegroundColor DarkYellow
        $sshLogContent = ""
    }
    Write-Host "  Raw length: $($sshLogContent.Length) chars"
    Write-Host "  Trimmed length: $($sshLogContent.Trim().Length) chars"
    Write-Host "  Content: '$($sshLogContent.Trim())'"
}
else {
    Write-Host "  FILE NOT FOUND" -ForegroundColor Red
    $sshLogContent = ""
}
Write-Host ""

# -----------------------------------------------
# STEP 5: Simulate the StdErr population logic
# -----------------------------------------------
Write-Host "STEP 5: StdErr population logic" -ForegroundColor Yellow
Write-Host ("-" * 40)
Write-Host "  StdErr is empty: $([string]::IsNullOrWhiteSpace($stdErr))"
Write-Host "  SSH log is empty: $([string]::IsNullOrWhiteSpace($sshLogContent))"

if ([string]::IsNullOrWhiteSpace($stdErr) -and
    -not [string]::IsNullOrWhiteSpace($sshLogContent)) {
    $stdErr = $sshLogContent.Trim()
    Write-Host "  -> Populated StdErr from SSH log file" -ForegroundColor Green
}
else {
    Write-Host "  -> StdErr NOT updated (already has content or log is empty)" -ForegroundColor DarkYellow
}
Write-Host "  Final StdErr: [$($stdErr.Length) chars] '$($stdErr.Trim())'"
Write-Host ""

# -----------------------------------------------
# STEP 6: Simulate the ErrorText assembly
# -----------------------------------------------
Write-Host "STEP 6: ErrorText assembly (diagnostic pattern scanning)" -ForegroundColor Yellow
Write-Host ("-" * 40)

$sshDiagPatterns = @(
    'Unable to negotiate',
    'no matching',
    'key exchange method',
    'host key type',
    'cipher',
    'Connection closed by',
    'Connection reset by',
    'kex_exchange_identification',
    'banner exchange',
    'Host key verification failed',
    'WARNING:'
)
$diagPattern = ($sshDiagPatterns | ForEach-Object { [regex]::Escape($_) }) -join '|'
$stdOutDiagLines = ($stdOut -split "`r?`n" | Where-Object { $_ -match $diagPattern }) -join "`r`n"

Write-Host "  Stdout diag lines: [$($stdOutDiagLines.Length) chars] '$stdOutDiagLines'"

$allErrorText = @($stdErr, $stdOutDiagLines) |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
$errorText = ($allErrorText -join "`r`n").Trim()

Write-Host "  allErrorText count: $($allErrorText.Count)"
Write-Host "  Final ErrorText: [$($errorText.Length) chars] '$errorText'"
Write-Host ""

# -----------------------------------------------
# STEP 7: Simulate the legacy fallback detection
# -----------------------------------------------
Write-Host "STEP 7: Legacy fallback pattern matching" -ForegroundColor Yellow
Write-Host ("-" * 40)

$errorCheck = "$errorText $stdErr $stdOut"
Write-Host "  errorCheck length: $($errorCheck.Length) chars"

$LegacyFallbacks = @(
    @{ Pattern = 'no matching key exchange method'; Label = 'KexAlgorithms' },
    @{ Pattern = 'no matching host key type';      Label = 'HostKeyAlgorithms' },
    @{ Pattern = 'no matching cipher';             Label = 'Ciphers' },
    @{ Pattern = 'no matching MAC';                Label = 'MACs' }
)

foreach ($fb in $LegacyFallbacks) {
    $escaped = [regex]::Escape($fb.Pattern)
    $matched = $errorCheck -match $escaped
    Write-Host "  Pattern '$($fb.Pattern)' -> match: $matched"
}
Write-Host ""

# -----------------------------------------------
# STEP 8: Simulate the final error message
# -----------------------------------------------
Write-Host "STEP 8: Final result message" -ForegroundColor Yellow
Write-Host ("-" * 40)
if ($exitCode -ne 0) {
    if ([string]::IsNullOrWhiteSpace($errorText)) {
        Write-Host "  RESULT: SSH exited with code $exitCode (no error detail captured)" -ForegroundColor Red
    }
    else {
        Write-Host "  RESULT: SSH exit code ${exitCode}: $errorText" -ForegroundColor Green
    }
}
Write-Host ""

# Cleanup
Remove-Item -Path $sshLogFile -Force -ErrorAction SilentlyContinue

Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host "DIAGNOSTIC COMPLETE" -ForegroundColor Cyan
Write-Host "The step that shows empty/unexpected data is where the bug is." -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor Cyan
