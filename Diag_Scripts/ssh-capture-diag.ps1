# SSH Capture Diagnostic Script
# Tests multiple methods of capturing ssh.exe output to determine
# which approach works in your environment.
#
# Usage: .\ssh-capture-diag.ps1 -IP 10.1.50.1 -User nimda
#
# This will intentionally trigger a negotiation failure and report
# what each capture method was able to retrieve.

param(
    [Parameter(Mandatory)]
    [string]$IP,

    [Parameter(Mandatory)]
    [string]$User
)

$sshPath = (Get-Command ssh.exe -ErrorAction SilentlyContinue).Source
Write-Host "SSH client: $sshPath" -ForegroundColor Cyan
Write-Host "SSH version:" -ForegroundColor Cyan
& ssh.exe -V 2>&1 | Write-Host
Write-Host ""
Write-Host ("=" * 60)
Write-Host "Target: $IP  User: $User"
Write-Host "Each test attempts an SSH connection that should fail."
Write-Host ("=" * 60)
Write-Host ""

$sshBaseArgs = @(
    "-o", "ConnectTimeout=5",
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "BatchMode=yes",
    "-o", "LogLevel=ERROR",
    "-l", $User,
    $IP
)

# -----------------------------------------------
# TEST 1: PowerShell 2>&1 redirection
# -----------------------------------------------
Write-Host "TEST 1: PowerShell 2>&1 operator" -ForegroundColor Yellow
Write-Host ("-" * 40)
try {
    $output = & ssh.exe @sshBaseArgs "exit" 2>&1
    $exitCode = $LASTEXITCODE
    $stdoutLines = @($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] })
    $stderrLines = @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })

    Write-Host "  Exit code  : $exitCode"
    Write-Host "  Stdout     : [$($stdoutLines.Count) lines] $($stdoutLines -join ' | ')"
    Write-Host "  Stderr     : [$($stderrLines.Count) lines] $($stderrLines -join ' | ')"
    Write-Host "  Raw output : [$($output.Count) items]"
    foreach ($item in $output) {
        $type = $item.GetType().Name
        Write-Host "    [$type] $item"
    }
}
catch {
    Write-Host "  EXCEPTION: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# -----------------------------------------------
# TEST 2: Start-Process with RedirectStandard*
# -----------------------------------------------
Write-Host "TEST 2: Start-Process -RedirectStandardError / -RedirectStandardOutput" -ForegroundColor Yellow
Write-Host ("-" * 40)
try {
    $tmpOut = Join-Path $env:TEMP "ssh_diag_stdout_$(Get-Random).txt"
    $tmpErr = Join-Path $env:TEMP "ssh_diag_stderr_$(Get-Random).txt"

    $argString = ($sshBaseArgs + @("exit")) -join " "
    $p = Start-Process -FilePath "ssh.exe" -ArgumentList $argString `
        -RedirectStandardOutput $tmpOut -RedirectStandardError $tmpErr `
        -NoNewWindow -Wait -PassThru

    $stdOut = if (Test-Path $tmpOut) { (Get-Content $tmpOut -Raw) } else { "" }
    $stdErr = if (Test-Path $tmpErr) { (Get-Content $tmpErr -Raw) } else { "" }

    Write-Host "  Exit code  : $($p.ExitCode)"
    Write-Host "  Stdout file: [$(if ($stdOut) { $stdOut.Length } else { 0 }) chars] $stdOut"
    Write-Host "  Stderr file: [$(if ($stdErr) { $stdErr.Length } else { 0 }) chars] $stdErr"

    Remove-Item $tmpOut, $tmpErr -ErrorAction SilentlyContinue
}
catch {
    Write-Host "  EXCEPTION: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# -----------------------------------------------
# TEST 3: .NET Process with pipe redirection
# -----------------------------------------------
Write-Host "TEST 3: .NET Process with RedirectStandard* pipes" -ForegroundColor Yellow
Write-Host ("-" * 40)
try {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "ssh.exe"
    $psi.Arguments = ($sshBaseArgs + @("exit")) -join " "
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $psi.CreateNoWindow = $true

    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    $proc.Start() | Out-Null

    try { $proc.StandardInput.Close() } catch {}
    $proc.WaitForExit(15000) | Out-Null

    $stdOut = $proc.StandardOutput.ReadToEnd()
    $stdErr = $proc.StandardError.ReadToEnd()

    Write-Host "  Exit code  : $($proc.ExitCode)"
    Write-Host "  Stdout pipe: [$(if ($stdOut) { $stdOut.Length } else { 0 }) chars] $stdOut"
    Write-Host "  Stderr pipe: [$(if ($stdErr) { $stdErr.Length } else { 0 }) chars] $stdErr"

    if ($null -ne $proc) { $proc.Dispose() }
}
catch {
    Write-Host "  EXCEPTION: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# -----------------------------------------------
# TEST 4: cmd.exe /c with file redirection
# -----------------------------------------------
Write-Host "TEST 4: cmd.exe /c with shell-level file redirection (1> 2>)" -ForegroundColor Yellow
Write-Host ("-" * 40)
try {
    $tmpOut = Join-Path $env:TEMP "ssh_diag_cmd_stdout_$(Get-Random).txt"
    $tmpErr = Join-Path $env:TEMP "ssh_diag_cmd_stderr_$(Get-Random).txt"

    $argString = ($sshBaseArgs + @("exit")) -join " "
    $cmdLine = "ssh.exe $argString 1>`"$tmpOut`" 2>`"$tmpErr`""

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "cmd.exe"
    $psi.Arguments = "/c `"$cmdLine`""
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $false
    $psi.RedirectStandardError = $false
    $psi.CreateNoWindow = $true

    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    $proc.Start() | Out-Null
    $proc.WaitForExit(15000) | Out-Null

    $stdOut = if (Test-Path $tmpOut) { (Get-Content $tmpOut -Raw) } else { "" }
    $stdErr = if (Test-Path $tmpErr) { (Get-Content $tmpErr -Raw) } else { "" }

    Write-Host "  Exit code    : $($proc.ExitCode)"
    Write-Host "  Stdout (1>)  : [$(if ($stdOut) { $stdOut.Length } else { 0 }) chars] $stdOut"
    Write-Host "  Stderr (2>)  : [$(if ($stdErr) { $stdErr.Length } else { 0 }) chars] $stdErr"

    # Also check combined
    $combined = "$stdOut$stdErr".Trim()
    if ([string]::IsNullOrWhiteSpace($combined)) {
        Write-Host "  COMBINED     : (empty - error may be going to console handle)" -ForegroundColor DarkYellow
    }

    if ($null -ne $proc) { $proc.Dispose() }
    Remove-Item $tmpOut, $tmpErr -ErrorAction SilentlyContinue
}
catch {
    Write-Host "  EXCEPTION: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# -----------------------------------------------
# TEST 5: cmd.exe /c with combined redirect (2>&1)
# -----------------------------------------------
Write-Host "TEST 5: cmd.exe /c with combined redirect (2>&1 > file)" -ForegroundColor Yellow
Write-Host ("-" * 40)
try {
    $tmpCombined = Join-Path $env:TEMP "ssh_diag_cmd_combined_$(Get-Random).txt"

    $argString = ($sshBaseArgs + @("exit")) -join " "
    $cmdLine = "ssh.exe $argString 2>&1 1>`"$tmpCombined`""

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "cmd.exe"
    $psi.Arguments = "/c `"$cmdLine`""
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $false
    $psi.RedirectStandardError = $false
    $psi.CreateNoWindow = $true

    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    $proc.Start() | Out-Null
    $proc.WaitForExit(15000) | Out-Null

    $combined = if (Test-Path $tmpCombined) { (Get-Content $tmpCombined -Raw) } else { "" }

    Write-Host "  Exit code : $($proc.ExitCode)"
    Write-Host "  Combined  : [$(if ($combined) { $combined.Length } else { 0 }) chars] $combined"

    if ($null -ne $proc) { $proc.Dispose() }
    Remove-Item $tmpCombined -ErrorAction SilentlyContinue
}
catch {
    Write-Host "  EXCEPTION: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# -----------------------------------------------
# TEST 6: PowerShell -Command wrapper
# -----------------------------------------------
Write-Host "TEST 6: powershell.exe -Command wrapper capturing via 2>&1" -ForegroundColor Yellow
Write-Host ("-" * 40)
try {
    $tmpOut = Join-Path $env:TEMP "ssh_diag_ps_$(Get-Random).txt"

    $escapedArgs = ($sshBaseArgs + @("exit")) -join " "
    $psCommand = "& ssh.exe $escapedArgs 2>&1 | Out-File -FilePath '$tmpOut' -Encoding UTF8"

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-NoProfile -NonInteractive -Command `"$psCommand`""
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $false
    $psi.RedirectStandardError = $false
    $psi.CreateNoWindow = $true

    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    $proc.Start() | Out-Null
    $proc.WaitForExit(30000) | Out-Null

    $captured = if (Test-Path $tmpOut) { (Get-Content $tmpOut -Raw) } else { "" }

    Write-Host "  Exit code : $($proc.ExitCode)"
    Write-Host "  Captured  : [$(if ($captured) { $captured.Length } else { 0 }) chars] $captured"

    if ($null -ne $proc) { $proc.Dispose() }
    Remove-Item $tmpOut -ErrorAction SilentlyContinue
}
catch {
    Write-Host "  EXCEPTION: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# -----------------------------------------------
# SUMMARY
# -----------------------------------------------
Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host "DIAGNOSTIC COMPLETE" -ForegroundColor Cyan
Write-Host "Please share the full output above so we can determine" -ForegroundColor Cyan
Write-Host "which capture method works in your environment." -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor Cyan
