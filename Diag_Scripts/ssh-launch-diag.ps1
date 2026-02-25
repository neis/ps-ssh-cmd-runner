# SSH Launch Context Diagnostic
# Tests which ProcessStartInfo settings prevent -E from capturing output.
#
# Usage: .\ssh-launch-diag.ps1 -IP 10.1.50.1 -User nimda

param(
    [Parameter(Mandatory)]
    [string]$IP,

    [Parameter(Mandatory)]
    [string]$User
)

Write-Host ("=" * 60)
Write-Host "Launch Context Diagnostic - Which setting kills -E output?"
Write-Host "Target: $IP  User: $User"
Write-Host ("=" * 60)
Write-Host ""

function Test-SSHLaunch {
    param(
        [string]$Label,
        [string]$IP,
        [string]$User,
        [bool]$UseShellExecute,
        [bool]$CreateNoWindow,
        [bool]$RedirectStdIn,
        [bool]$RedirectStdOut,
        [bool]$RedirectStdErr
    )

    $logFile = Join-Path $env:TEMP "ssh_ctx_$(Get-Random).log"

    $sshArgs = @(
        "-E", $logFile,
        "-o", "ConnectTimeout=5",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "BatchMode=yes",
        "-o", "LogLevel=ERROR",
        "-l", $User, $IP, "exit"
    )

    Write-Host "  $Label" -ForegroundColor Yellow
    Write-Host "    UseShellExecute=$UseShellExecute  CreateNoWindow=$CreateNoWindow"
    Write-Host "    RedirectIn=$RedirectStdIn  RedirectOut=$RedirectStdOut  RedirectErr=$RedirectStdErr"

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName        = "ssh.exe"
    $psi.Arguments       = $sshArgs -join " "
    $psi.UseShellExecute = $UseShellExecute

    if (-not $UseShellExecute) {
        $psi.CreateNoWindow         = $CreateNoWindow
        $psi.RedirectStandardInput  = $RedirectStdIn
        $psi.RedirectStandardOutput = $RedirectStdOut
        $psi.RedirectStandardError  = $RedirectStdErr
    }

    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi

    try {
        $proc.Start() | Out-Null

        if ($RedirectStdIn -and -not $UseShellExecute) {
            try { $proc.StandardInput.Close() } catch {}
        }
        if ($RedirectStdOut -and -not $UseShellExecute) {
            try { $proc.StandardOutput.ReadToEnd() | Out-Null } catch {}
        }
        if ($RedirectStdErr -and -not $UseShellExecute) {
            try { $proc.StandardError.ReadToEnd() | Out-Null } catch {}
        }

        $proc.WaitForExit(15000) | Out-Null
        $exitCode = $proc.ExitCode

        $logContent = ""
        if (Test-Path $logFile) {
            $logContent = Get-Content -Path $logFile -Raw -ErrorAction SilentlyContinue
            if ($null -eq $logContent) { $logContent = "" }
            $logContent = $logContent.Trim()
        }

        $hasContent = $logContent.Length -gt 0
        $color = if ($hasContent) { "Green" } else { "Red" }
        $status = if ($hasContent) { "CAPTURED" } else { "EMPTY" }

        Write-Host "    Exit=$exitCode  -E file=$status  [$($logContent.Length) chars]" -ForegroundColor $color
        if ($hasContent) {
            Write-Host "    Content: $logContent" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "    EXCEPTION: $($_.Exception.Message)" -ForegroundColor Red
    }
    finally {
        try {
            if ($null -ne $proc) {
                if (-not $proc.HasExited) { $proc.Kill() }
                $proc.Dispose()
            }
        }
        catch {}
        Remove-Item -Path $logFile -Force -ErrorAction SilentlyContinue
    }
    Write-Host ""
}

# Baseline: matches exactly what the main script does
Write-Host "TEST 1: Main script config (all redirected, no window)" -ForegroundColor Cyan
Test-SSHLaunch -Label "Full redirect + NoWindow" -IP $IP -User $User `
    -UseShellExecute $false -CreateNoWindow $true `
    -RedirectStdIn $true -RedirectStdOut $true -RedirectStdErr $true

# Remove CreateNoWindow
Write-Host "TEST 2: All redirected, CreateNoWindow=false" -ForegroundColor Cyan
Test-SSHLaunch -Label "Full redirect, with window" -IP $IP -User $User `
    -UseShellExecute $false -CreateNoWindow $false `
    -RedirectStdIn $true -RedirectStdOut $true -RedirectStdErr $true

# No redirects at all, just CreateNoWindow
Write-Host "TEST 3: No redirects, CreateNoWindow=true" -ForegroundColor Cyan
Test-SSHLaunch -Label "No redirect + NoWindow" -IP $IP -User $User `
    -UseShellExecute $false -CreateNoWindow $true `
    -RedirectStdIn $false -RedirectStdOut $false -RedirectStdErr $false

# No redirects, no CreateNoWindow
Write-Host "TEST 4: No redirects, CreateNoWindow=false" -ForegroundColor Cyan
Test-SSHLaunch -Label "No redirect, with window" -IP $IP -User $User `
    -UseShellExecute $false -CreateNoWindow $false `
    -RedirectStdIn $false -RedirectStdOut $false -RedirectStdErr $false

# Only redirect stdin (which the main script needs for commands)
Write-Host "TEST 5: Only stdin redirected, CreateNoWindow=true" -ForegroundColor Cyan
Test-SSHLaunch -Label "Stdin only + NoWindow" -IP $IP -User $User `
    -UseShellExecute $false -CreateNoWindow $true `
    -RedirectStdIn $true -RedirectStdOut $false -RedirectStdErr $false

# Only redirect stdout (which the main script reads for device output)
Write-Host "TEST 6: Only stdout redirected, CreateNoWindow=true" -ForegroundColor Cyan
Test-SSHLaunch -Label "Stdout only + NoWindow" -IP $IP -User $User `
    -UseShellExecute $false -CreateNoWindow $true `
    -RedirectStdIn $false -RedirectStdOut $true -RedirectStdErr $false

# Stdin + stdout but NOT stderr, with NoWindow
Write-Host "TEST 7: Stdin + stdout redirected (NOT stderr), CreateNoWindow=true" -ForegroundColor Cyan
Test-SSHLaunch -Label "Stdin+Stdout, no Stderr + NoWindow" -IP $IP -User $User `
    -UseShellExecute $false -CreateNoWindow $true `
    -RedirectStdIn $true -RedirectStdOut $true -RedirectStdErr $false

# Stdin + stdout + stderr, CreateNoWindow=false
Write-Host "TEST 8: All redirected, CreateNoWindow=false (same as Test 2)" -ForegroundColor Cyan
Test-SSHLaunch -Label "Full redirect, no NoWindow" -IP $IP -User $User `
    -UseShellExecute $false -CreateNoWindow $false `
    -RedirectStdIn $true -RedirectStdOut $true -RedirectStdErr $false

Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host "DIAGNOSTIC COMPLETE" -ForegroundColor Cyan
Write-Host "Tests that show CAPTURED tell us which settings allow -E to work." -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor Cyan
