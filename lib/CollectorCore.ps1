# ---------------------------------------------
# CollectorCore.ps1
#
# Pure functions only. Dot-sourced by ssh-cmd-runner.ps1 and by the Pester
# tests. No I/O, no script-scope state, no side effects. All functions here
# are deterministic given their arguments so they can be unit-tested in
# isolation without an SSH session, filesystem, or credential store.
#
# Windows PowerShell 5.1-compatible (no PS7-only syntax/cmdlets).
# ---------------------------------------------

# Helper: build a device's effective command list from the OS base list by
# removing per-device excluded commands and appending per-device additional
# commands. Matching is case-insensitive and trimmed. Additions that are already
# present (after exclusion) are skipped; the rest are appended in order at the end.
# Returns a [string[]] (always an array, even for a single command).
function Resolve-DeviceCommandList {
    param(
        [string[]]$BaseCommands,
        [string[]]$ExcludeCommands = @(),
        [string[]]$AddCommands = @()
    )
    # Normalize $null to empty arrays. A PSCustomObject property holding @() comes
    # back as $null when passed as an argument, which overrides the parameter default;
    # piping that $null to ForEach-Object would then run once with $_ = $null and throw.
    if ($null -eq $BaseCommands)    { $BaseCommands = @() }
    if ($null -eq $ExcludeCommands) { $ExcludeCommands = @() }
    if ($null -eq $AddCommands)     { $AddCommands = @() }

    $resolved = [System.Collections.Generic.List[string]]::new()
    $excludeSet = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@($ExcludeCommands | ForEach-Object { $_.Trim() }),
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($c in $BaseCommands) {
        if (-not $excludeSet.Contains($c.Trim())) { $resolved.Add($c) }
    }
    $presentSet = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@($resolved | ForEach-Object { $_.Trim() }),
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($a in $AddCommands) {
        $t = $a.Trim()
        if ($t -ne "" -and -not $presentSet.Contains($t)) {
            $resolved.Add($t)
            $presentSet.Add($t) | Out-Null
        }
    }
    return , ([string[]]$resolved.ToArray())
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
# HELPER FUNCTION: Escape a password for a cmd.exe "@echo <password>" line.
# Encapsulates cmd.exe special-character escaping so the same logic can be
# unit-tested in isolation and reused wherever the SSH_ASKPASS helper is
# (re)written. The ^ -> ^^ replacement MUST run first so already-escaped
# metacharacters are not double-escaped.
# ---------------------------------------------
function ConvertTo-CmdEchoEscaped {
    param([string]$Password)
    $escaped = $Password
    $escaped = $escaped.Replace('^', '^^')
    $escaped = $escaped.Replace('&', '^&')
    $escaped = $escaped.Replace('|', '^|')
    $escaped = $escaped.Replace('<', '^<')
    $escaped = $escaped.Replace('>', '^>')
    $escaped = $escaped.Replace('!', '^!')
    $escaped = $escaped.Replace('%', '%%')
    return $escaped
}

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
