# SSH Probe Diagnostic
# Confirms that "& ssh.exe -E logfile" works when called from inside a
# nested function, matching the call depth of the main script.
#
# Usage: .\ssh-probe-diag.ps1 -IP 10.1.50.1 -User nimda

param(
    [Parameter(Mandatory)]
    [string]$IP,

    [Parameter(Mandatory)]
    [string]$User
)

Write-Host ("=" * 60)
Write-Host "Probe Diagnostic - Testing & operator inside nested functions"
Write-Host "Target: $IP  User: $User"
Write-Host ("=" * 60)
Write-Host ""

# Simulate the main script's nesting: main script -> Invoke-SSHSession -> probe
function Invoke-FakeSSHSession {
    param([string]$DeviceIP, [string]$DeviceUser)

    function Get-SSHErrorProbe {
        param([string]$ProbeIP, [string]$ProbeUser)

        $probeLog = Join-Path $env:TEMP "ssh_probe_$(Get-Random).log"

        $probeArgs = @(
            "-E", $probeLog,
            "-o", "ConnectTimeout=5",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "BatchMode=yes",
            "-o", "LogLevel=ERROR",
            "-l", $ProbeUser,
            $ProbeIP,
            "exit"
        )

        Write-Host "  Probe args: ssh.exe $($probeArgs -join ' ')"
        Write-Host "  Probe log : $probeLog"

        # Run via PowerShell & operator (not .NET Process)
        & ssh.exe @probeArgs 2>$null

        $probeExit = $LASTEXITCODE
        Write-Host "  Probe exit: $probeExit"

        $probeContent = ""
        if (Test-Path $probeLog) {
            $probeContent = Get-Content -Path $probeLog -Raw -ErrorAction SilentlyContinue
            if ($null -eq $probeContent) { $probeContent = "" }
            $probeContent = $probeContent.Trim()
        }

        Write-Host "  Log exists: $(Test-Path $probeLog)"
        Write-Host "  Log length: $($probeContent.Length) chars"
        Write-Host "  Log content: '$probeContent'"

        Remove-Item -Path $probeLog -Force -ErrorAction SilentlyContinue

        return $probeContent
    }

    Write-Host "TEST 1: Probe from inside nested function" -ForegroundColor Yellow
    Write-Host ("-" * 40)
    $errorText = Get-SSHErrorProbe -ProbeIP $DeviceIP -ProbeUser $DeviceUser
    Write-Host ""
    Write-Host "  Returned to caller: [$($errorText.Length) chars] '$errorText'"
    Write-Host ""

    # Test pattern matching on the result
    if (-not [string]::IsNullOrWhiteSpace($errorText)) {
        Write-Host "  Pattern matching:" -ForegroundColor Yellow
        $patterns = @(
            @{ Pattern = 'no matching key exchange method'; Label = 'KexAlgorithms' },
            @{ Pattern = 'no matching host key type';      Label = 'HostKeyAlgorithms' },
            @{ Pattern = 'no matching cipher';             Label = 'Ciphers' },
            @{ Pattern = 'no matching MAC';                Label = 'MACs' }
        )
        foreach ($p in $patterns) {
            $matched = $errorText -match [regex]::Escape($p.Pattern)
            $color = if ($matched) { "Green" } else { "Gray" }
            Write-Host "    $($p.Label): $matched" -ForegroundColor $color
        }
    }
    else {
        Write-Host "  ERROR: Probe returned empty - & operator did not capture" -ForegroundColor Red
    }
}

Write-Host "Calling from main script -> Invoke-FakeSSHSession -> Get-SSHErrorProbe"
Write-Host ""
Invoke-FakeSSHSession -DeviceIP $IP -DeviceUser $User

Write-Host ""

# Also test with -v + 2>&1 as a backup method
Write-Host "TEST 2: Probe with -v and 2>&1 (backup method)" -ForegroundColor Yellow
Write-Host ("-" * 40)

$probeArgs2 = @(
    "-v",
    "-o", "ConnectTimeout=5",
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "BatchMode=yes",
    "-l", $User,
    $IP,
    "exit"
)

$verboseOutput = & ssh.exe @probeArgs2 2>&1
$probeExit2 = $LASTEXITCODE
$allLines = @($verboseOutput | ForEach-Object { $_.ToString() })
$errorLines = @($allLines | Where-Object {
    $_ -match 'Unable to negotiate|no matching|Their offer'
})

Write-Host "  Exit code  : $probeExit2"
Write-Host "  Total lines: $($allLines.Count)"
Write-Host "  Error lines: $($errorLines.Count)"
foreach ($el in $errorLines) {
    Write-Host "    $el" -ForegroundColor Red
}
Write-Host ""

Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host "DIAGNOSTIC COMPLETE" -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor Cyan
