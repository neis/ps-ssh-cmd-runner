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

# =============================================================================
# COLLECTION PLAN INPUT (schema_version 1)
# See docs/collection-plan.schema.md. Pure parse/normalize logic for the
# structured JSON collection plan and the transitional CSV device list. Both
# paths emit the SAME normalized device shape so downstream resolution is
# input-agnostic. No file I/O here — callers pass raw text.
# =============================================================================

# Read a property off a PSObject/hashtable, returning $Default when the object is
# $null, the property is absent, or its value is $null. Strict-mode safe (never
# dereferences a missing property).
function Get-PlanProperty {
    param(
        $Object,
        [Parameter(Mandatory = $true)][string]$Name,
        $Default = $null
    )
    if ($null -eq $Object) { return $Default }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $Default }
    if ($null -eq $prop.Value) { return $Default }
    return $prop.Value
}

# Coerce an arbitrary value (scalar, array, or $null) into a trimmed [string[]]
# with empty entries dropped. Always returns an array (comma-unrolling is the
# caller's job — pass a pre-split collection).
function ConvertTo-StringArray {
    param($Value)
    if ($null -eq $Value) { return , ([string[]]@()) }
    $items = @($Value | ForEach-Object { if ($null -ne $_) { ([string]$_).Trim() } } | Where-Object { $_ -ne '' })
    return , ([string[]]$items)
}

# Normalize an ssh_options blob into the four documented fields. Missing fields
# become $null ("collector default / auto").
function ConvertTo-NormalizedSshOptions {
    param($Value)
    return [PSCustomObject]@{
        kex_algorithms      = Get-PlanProperty $Value 'kex_algorithms'
        ciphers             = Get-PlanProperty $Value 'ciphers'
        host_key_algorithms = Get-PlanProperty $Value 'host_key_algorithms'
        pty                 = Get-PlanProperty $Value 'pty'
    }
}

# Build one normalized plan-device object. Shared by the JSON and CSV parsers so
# both inputs produce an identical shape. Throws on a non-integer priority.
function New-CollectionPlanDevice {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ConnectIp,
        [string]$Platform,
        [string]$ProfileName,
        [string[]]$Groups = @(),
        [string[]]$ExcludeCommands = @(),
        [string[]]$AddCommands = @(),
        $SshOptions = $null,
        $Priority = $null,
        [string]$CredentialGroup,
        [string]$Category,
        [string]$PlanId
    )
    $prio = $null
    if ($null -ne $Priority -and "$Priority".Trim() -ne '') {
        $parsed = 0
        if ([int]::TryParse("$Priority".Trim(), [ref]$parsed)) { $prio = $parsed }
        else { throw "Device '$ConnectIp' has a non-integer priority '$Priority'." }
    }
    if ($null -eq $Groups) { $Groups = @() }
    if ($null -eq $ExcludeCommands) { $ExcludeCommands = @() }
    if ($null -eq $AddCommands) { $AddCommands = @() }

    return [PSCustomObject]@{
        connect_ip       = $ConnectIp.Trim()
        platform         = if ([string]::IsNullOrWhiteSpace($Platform)) { $null } else { $Platform.Trim() }
        profile          = if ([string]::IsNullOrWhiteSpace($ProfileName)) { $null } else { $ProfileName.Trim() }
        groups           = [string[]]$Groups
        exclude_commands = [string[]]$ExcludeCommands
        add_commands     = [string[]]$AddCommands
        ssh_options      = $SshOptions
        priority         = $prio
        credential_group = if ([string]::IsNullOrWhiteSpace($CredentialGroup)) { $null } else { $CredentialGroup.Trim() }
        category         = if ([string]::IsNullOrWhiteSpace($Category)) { $null } else { $Category.Trim() }
        plan_id          = if ([string]::IsNullOrWhiteSpace($PlanId)) { $null } else { $PlanId.Trim() }
    }
}

# Parse a structured JSON collection plan (schema_version 1) into a normalized
# object: @{ schema_version; plan_id; devices = [normalized device, ...] }.
# Throws clear errors on malformed JSON, wrong schema_version, a missing/empty
# devices array, or a device missing connect_ip.
function ConvertFrom-CollectionPlanJson {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Json)

    if ([string]::IsNullOrWhiteSpace($Json)) {
        throw "Collection plan JSON is empty."
    }
    try {
        $doc = $Json | ConvertFrom-Json
    }
    catch {
        throw "Collection plan is not valid JSON: $($_.Exception.Message)"
    }
    if ($null -eq $doc) { throw "Collection plan JSON parsed to null." }

    $schemaVersion = Get-PlanProperty $doc 'schema_version' 1
    if ("$schemaVersion" -ne '1') {
        throw "Unsupported collection plan schema_version '$schemaVersion' (this collector supports 1)."
    }

    $planId = Get-PlanProperty $doc 'plan_id'
    $defaults = Get-PlanProperty $doc 'defaults'
    $defaultProfile = Get-PlanProperty $defaults 'profile' 'full'
    $defaultCredGroup = Get-PlanProperty $defaults 'credential_group'
    $defaultSsh = Get-PlanProperty $defaults 'ssh_options'

    # Check the property directly rather than via Get-PlanProperty: an empty array
    # returned from a function collapses to $null in PowerShell, which would make an
    # empty 'devices' indistinguishable from an absent one.
    $devicesProp = $doc.PSObject.Properties['devices']
    if ($null -eq $devicesProp -or $null -eq $devicesProp.Value) {
        throw "Collection plan has no 'devices' array."
    }
    $rawDevices = @($devicesProp.Value)
    if ($rawDevices.Count -eq 0) { throw "Collection plan 'devices' array is empty." }

    $devices = foreach ($d in $rawDevices) {
        $ip = [string](Get-PlanProperty $d 'connect_ip')
        if ([string]::IsNullOrWhiteSpace($ip)) {
            throw "Collection plan device is missing the required 'connect_ip' field."
        }
        $groups = ConvertTo-StringArray (Get-PlanProperty $d 'groups')
        $profileName = [string](Get-PlanProperty $d 'profile')
        if ([string]::IsNullOrWhiteSpace($profileName) -and $groups.Count -eq 0) {
            $profileName = [string]$defaultProfile
        }
        $ssh = Get-PlanProperty $d 'ssh_options' $defaultSsh
        $cred = Get-PlanProperty $d 'credential_group' $defaultCredGroup

        New-CollectionPlanDevice `
            -ConnectIp $ip `
            -Platform ([string](Get-PlanProperty $d 'platform')) `
            -ProfileName $profileName `
            -Groups $groups `
            -ExcludeCommands (ConvertTo-StringArray (Get-PlanProperty $d 'exclude_commands')) `
            -AddCommands (ConvertTo-StringArray (Get-PlanProperty $d 'add_commands')) `
            -SshOptions (ConvertTo-NormalizedSshOptions $ssh) `
            -Priority (Get-PlanProperty $d 'priority') `
            -CredentialGroup ([string]$cred) `
            -PlanId ([string]$planId)
    }

    return [PSCustomObject]@{
        schema_version = 1
        plan_id        = if ([string]::IsNullOrWhiteSpace([string]$planId)) { $null } else { ([string]$planId).Trim() }
        devices        = @($devices)
    }
}

# Parse the transitional CSV device list (IP,Category,OS,ExcludeCommands,
# AddCommands) into the SAME normalized shape as the JSON path, mapping every
# row to the default 'full' profile. Comment (#) and blank lines are ignored.
# Throws on a missing IP/OS column or a row missing the OS field.
function ConvertFrom-CollectionCsv {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$CsvText)

    $lines = @($CsvText -split "`r?`n" | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_) -and -not $_.TrimStart().StartsWith('#')
        })
    if ($lines.Count -le 1) {
        throw "Device CSV has no data rows (need a header row plus at least one device)."
    }
    $rows = @($lines | ConvertFrom-Csv)
    if ($rows.Count -eq 0) {
        throw "Device CSV has no data rows."
    }

    $columns = $rows[0].PSObject.Properties.Name
    if ('IP' -notin $columns -or 'OS' -notin $columns) {
        throw "Device CSV must have 'IP' and 'OS' columns (Category is optional). Found: $($columns -join ', ')"
    }
    $hasCategory = 'Category' -in $columns
    $hasExclude = 'ExcludeCommands' -in $columns
    $hasAdd = 'AddCommands' -in $columns

    $devices = foreach ($row in $rows) {
        $ip = [string](Get-PlanProperty $row 'IP')
        $os = [string](Get-PlanProperty $row 'OS')
        if ([string]::IsNullOrWhiteSpace($ip) -or $ip.TrimStart().StartsWith('#')) { continue }
        if ([string]::IsNullOrWhiteSpace($os)) {
            throw "Device '$($ip.Trim())' in CSV is missing the OS field."
        }

        $exclCell = if ($hasExclude) { [string](Get-PlanProperty $row 'ExcludeCommands') } else { '' }
        $addCell = if ($hasAdd) { [string](Get-PlanProperty $row 'AddCommands') } else { '' }
        $excl = if ($exclCell -ne '') { $exclCell -split ',' } else { @() }
        $add = if ($addCell -ne '') { $addCell -split ',' } else { @() }
        $cat = if ($hasCategory) { [string](Get-PlanProperty $row 'Category') } else { '' }

        New-CollectionPlanDevice `
            -ConnectIp $ip `
            -Platform ($os.Trim().ToLower()) `
            -ProfileName 'full' `
            -ExcludeCommands (ConvertTo-StringArray $excl) `
            -AddCommands (ConvertTo-StringArray $add) `
            -SshOptions (ConvertTo-NormalizedSshOptions $null) `
            -Category $cat
    }

    $devices = @($devices)
    if ($devices.Count -eq 0) {
        throw "Device CSV has no valid device rows."
    }

    return [PSCustomObject]@{
        schema_version = 1
        plan_id        = $null
        devices        = $devices
    }
}
