# SSH Capture Diagnostic 2 - SSH-native logging
# Tests SSH's own -E (log file) and -v (verbose) flags
#
# Usage: .\ssh-capture-diag2.ps1 -IP 10.1.50.1 -User nimda

param(
    [Parameter(Mandatory)]
    [string]$IP,

    [Parameter(Mandatory)]
    [string]$User
)

Write-Host ("=" * 60)
Write-Host "SSH-Native Capture Methods"
Write-Host "Target: $IP  User: $User"
Write-Host ("=" * 60)
Write-Host ""

$sshBaseArgs = @(
    "-o", "ConnectTimeout=5",
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "BatchMode=yes"
)

# -----------------------------------------------
# TEST A: SSH -E logfile (SSH internal file logging)
# -----------------------------------------------
Write-Host "TEST A: ssh -E logfile (SSH writes directly to a file)" -ForegroundColor Yellow
Write-Host ("-" * 40)
try {
    $logFile = Join-Path $env:TEMP "ssh_diag_E_$(Get-Random).log"

    $args1 = @("-E", $logFile) + $sshBaseArgs + @("-l", $User, $IP, "exit")
    & ssh.exe @args1 2>$null

    $exitCode = $LASTEXITCODE
    $logContent = ""
    if (Test-Path $logFile) {
        $logContent = (Get-Content $logFile -Raw -ErrorAction SilentlyContinue)
        if ($null -eq $logContent) { $logContent = "" }
    }

    Write-Host "  Exit code   : $exitCode"
    Write-Host "  Log file    : $logFile"
    Write-Host "  Log size    : $($logContent.Length) chars"
    Write-Host "  Log content :"
    if ($logContent.Length -gt 0) {
        $logContent -split "`r?`n" | ForEach-Object {
            Write-Host "    $_" -ForegroundColor Gray
        }
    }
    else {
        Write-Host "    (empty)" -ForegroundColor DarkYellow
    }

    Remove-Item $logFile -ErrorAction SilentlyContinue
}
catch {
    Write-Host "  EXCEPTION: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# -----------------------------------------------
# TEST B: SSH -E logfile with -v (verbose)
# -----------------------------------------------
Write-Host "TEST B: ssh -E logfile -v (verbose + file logging)" -ForegroundColor Yellow
Write-Host ("-" * 40)
try {
    $logFile = Join-Path $env:TEMP "ssh_diag_Ev_$(Get-Random).log"

    $args2 = @("-E", $logFile, "-v") + $sshBaseArgs + @("-l", $User, $IP, "exit")
    & ssh.exe @args2 2>$null

    $exitCode = $LASTEXITCODE
    $logContent = ""
    if (Test-Path $logFile) {
        $logContent = (Get-Content $logFile -Raw -ErrorAction SilentlyContinue)
        if ($null -eq $logContent) { $logContent = "" }
    }

    Write-Host "  Exit code   : $exitCode"
    Write-Host "  Log file    : $logFile"
    Write-Host "  Log size    : $($logContent.Length) chars"
    Write-Host "  Log content :"
    if ($logContent.Length -gt 0) {
        # Show full content but highlight key lines
        $logContent -split "`r?`n" | ForEach-Object {
            if ($_ -match 'no matching|Unable to negotiate|Their offer|kex_exchange') {
                Write-Host "    $_" -ForegroundColor Red
            }
            else {
                Write-Host "    $_" -ForegroundColor Gray
            }
        }
    }
    else {
        Write-Host "    (empty)" -ForegroundColor DarkYellow
    }

    Remove-Item $logFile -ErrorAction SilentlyContinue
}
catch {
    Write-Host "  EXCEPTION: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# -----------------------------------------------
# TEST C: SSH -v via PowerShell 2>&1 (verbose may use stderr differently)
# -----------------------------------------------
Write-Host "TEST C: ssh -v via PowerShell 2>&1 (verbose to stderr?)" -ForegroundColor Yellow
Write-Host ("-" * 40)
try {
    $args3 = @("-v") + $sshBaseArgs + @("-l", $User, $IP, "exit")
    $output = & ssh.exe @args3 2>&1

    $exitCode = $LASTEXITCODE
    $allLines = @($output | ForEach-Object { $_.ToString() })

    Write-Host "  Exit code   : $exitCode"
    Write-Host "  Total lines : $($allLines.Count)"
    Write-Host "  Content     :"
    foreach ($line in $allLines) {
        if ($line -match 'no matching|Unable to negotiate|Their offer|kex_exchange') {
            Write-Host "    $line" -ForegroundColor Red
        }
        else {
            Write-Host "    $line" -ForegroundColor Gray
        }
    }

    if ($allLines.Count -eq 0) {
        Write-Host "    (empty)" -ForegroundColor DarkYellow
    }
}
catch {
    Write-Host "  EXCEPTION: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# -----------------------------------------------
# TEST D: SSH -o LogLevel=VERBOSE -E logfile
# -----------------------------------------------
Write-Host "TEST D: ssh -o LogLevel=VERBOSE -E logfile" -ForegroundColor Yellow
Write-Host ("-" * 40)
try {
    $logFile = Join-Path $env:TEMP "ssh_diag_verbose_$(Get-Random).log"

    $args4 = @(
        "-E", $logFile,
        "-o", "ConnectTimeout=5",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "BatchMode=yes",
        "-o", "LogLevel=VERBOSE",
        "-l", $User, $IP, "exit"
    )
    & ssh.exe @args4 2>$null

    $exitCode = $LASTEXITCODE
    $logContent = ""
    if (Test-Path $logFile) {
        $logContent = (Get-Content $logFile -Raw -ErrorAction SilentlyContinue)
        if ($null -eq $logContent) { $logContent = "" }
    }

    Write-Host "  Exit code   : $exitCode"
    Write-Host "  Log size    : $($logContent.Length) chars"
    Write-Host "  Log content :"
    if ($logContent.Length -gt 0) {
        $logContent -split "`r?`n" | ForEach-Object {
            if ($_ -match 'no matching|Unable to negotiate|Their offer|kex_exchange') {
                Write-Host "    $_" -ForegroundColor Red
            }
            else {
                Write-Host "    $_" -ForegroundColor Gray
            }
        }
    }
    else {
        Write-Host "    (empty)" -ForegroundColor DarkYellow
    }

    Remove-Item $logFile -ErrorAction SilentlyContinue
}
catch {
    Write-Host "  EXCEPTION: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# -----------------------------------------------
# SUMMARY
# -----------------------------------------------
Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host "DIAGNOSTIC 2 COMPLETE" -ForegroundColor Cyan
Write-Host "Please share the full output." -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor Cyan
