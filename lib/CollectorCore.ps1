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

# Merge a device's ssh_options blob over a defaults ssh_options blob at the
# SUB-FIELD level: each of the four fields is taken from the device when the
# device supplies it (non-null), otherwise inherited from defaults. This is a
# field-merge, NOT a wholesale replace — a device that sets only 'pty' still
# inherits the plan-wide kex/ciphers/host_key defaults. (Wholesale replace
# silently drops the global crypto defaults, which fails connections to legacy
# gear that relies on them — the C1 contract Reperio validates against.)
# 'pty:false' is a real value (force-suppress PTY allocation), not "absent", so
# it is preserved and not overwritten by the default's pty.
function Merge-SshOptions {
    param($DeviceValue, $DefaultValue)
    $merged = ConvertTo-NormalizedSshOptions $DeviceValue
    $def    = ConvertTo-NormalizedSshOptions $DefaultValue
    foreach ($field in 'kex_algorithms', 'ciphers', 'host_key_algorithms', 'pty') {
        if ($null -eq $merged.$field) { $merged.$field = $def.$field }
    }
    return $merged
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
        # platform is canonicalized to lowercase so the JSON and CSV paths (CSV
        # already lowercases) produce ONE device shape; downstream catalog lookups
        # are then case-stable.
        platform         = if ([string]::IsNullOrWhiteSpace($Platform)) { $null } else { $Platform.Trim().ToLower() }
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
        # Field-merge device ssh_options OVER defaults (see Merge-SshOptions):
        # per-field override, not wholesale replace, so a device that sets only
        # 'pty' keeps the global crypto defaults.
        $ssh = Get-PlanProperty $d 'ssh_options'
        $cred = Get-PlanProperty $d 'credential_group' $defaultCredGroup

        New-CollectionPlanDevice `
            -ConnectIp $ip `
            -Platform ([string](Get-PlanProperty $d 'platform')) `
            -ProfileName $profileName `
            -Groups $groups `
            -ExcludeCommands (ConvertTo-StringArray (Get-PlanProperty $d 'exclude_commands')) `
            -AddCommands (ConvertTo-StringArray (Get-PlanProperty $d 'add_commands')) `
            -SshOptions (Merge-SshOptions $ssh $defaultSsh) `
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

# =============================================================================
# COMMAND GROUPS + PROFILES (task 0b)
# The per-platform command sets are organized into named FEATURE GROUPS; a
# PROFILE is a named composition of groups. A device's profile (or explicit
# group list) resolves to its command set. This replaces the flat, per-OS
# commands/<os>.txt files as the source of truth for *what a profile collects*.
#
# The 'base' group is NON-REMOVABLE: identity commands, running-config, and the
# per-platform sentinel are always collected and cannot be dropped by a profile
# choice or an exclude. Enforced in Resolve-ProfileCommandList.
#
# Forward-compat (task 0c): a group member is a plain string today. A later
# catalog may make it an object { command; min_version; max_version } and the
# resolver will select by firmware. See docs/collection-plan.schema.md.
# =============================================================================

# Per-platform feature-group catalog. Each platform maps to an ORDERED hashtable
# of groupName -> [string[]] commands. Group order here is the canonical output
# order (base first, then groups in declared order). 'base' must be present for
# every platform.
function Get-CommandGroupCatalog {
    return @{
        'cisco-switch-iosxe' = [ordered]@{
            'base'                = @('show version', 'show inventory', 'show interface', 'show interface status', 'show switch', 'show running-config', 'show ip protocols')
            'neighbors'           = @('show cdp neighbors detail', 'show lldp neighbors detail')
            'switching'           = @('show mac address-table', 'show etherchannel summary')
            'power'               = @('show power inline')
            'routing-igp-ospf'    = @('show ip ospf neighbor', 'show ip ospf interface brief')
            'routing-igp-eigrp'   = @('show ip eigrp neighbors', 'show ip eigrp topology')
            'routing-bgp'         = @('show ip bgp summary', 'show ip bgp neighbors')
            'routing-tables-full' = @('show ip route', 'show ip route vrf *')
            # PLACEHOLDER (Phase-2 finalizes; private-prefix longer-prefixes queries TBD).
            'routing-tables-lite' = @('show ip route connected', 'show ip route static', 'show ip route local', 'show ip route summary')
            'vrf'                 = @('show vrf')
            'arp'                 = @('show ip arp', 'show ip arp vrf all')
            'optics-transceiver'  = @('show interface transceiver', 'show interface transceiver detail')
            'collect-only-ops'    = @('show license all', 'show adjacency detail', 'show logging')
        }
        'cisco-router-iosxe' = [ordered]@{
            'base'                = @('show version', 'show inventory', 'show interface', 'show running-config', 'show ip protocols')
            'neighbors'           = @('show cdp neighbors detail', 'show lldp neighbors detail')
            'switching'           = @('show etherchannel summary')
            'routing-igp-ospf'    = @('show ip ospf neighbor', 'show ip ospf interface brief')
            'routing-igp-eigrp'   = @('show ip eigrp neighbors', 'show ip eigrp topology')
            'routing-bgp'         = @('show ip bgp summary', 'show ip bgp neighbors')
            'routing-tables-full' = @('show ip route', 'show ip route vrf *')
            # PLACEHOLDER (Phase-2 finalizes).
            'routing-tables-lite' = @('show ip route connected', 'show ip route static', 'show ip route local', 'show ip route summary')
            'vrf'                 = @('show vrf')
            'arp'                 = @('show ip arp')
            'optics-transceiver'  = @('show interface transceiver')
            # 'show interface description' / 'show ip interface brief' are informative
            # interface views, not needed to key the device — re-homed here out of base.
            'collect-only-ops'    = @('show interface description', 'show ip interface brief', 'show license all', 'show adjacency detail', 'show ip nat translations', 'show ip access-lists', 'show logging last 100')
        }
        'cisco-switch-nxos'  = [ordered]@{
            # NX-OS sentinel is 'show ip route summary' (no 'show ip protocols' on NX-OS).
            'base'                = @('show version', 'show inventory', 'show interface', 'show interface status', 'show running-config', 'show ip route summary')
            'neighbors'           = @('show cdp neighbors detail', 'show lldp neighbors detail')
            'switching'           = @('show mac address-table', 'show port-channel summary')
            'routing-igp-ospf'    = @('show ip ospf neighbor', 'show ip ospf interface brief')
            'routing-igp-eigrp'   = @('show ip eigrp neighbors')
            'routing-bgp'         = @('show ip bgp summary', 'show ip bgp neighbors')
            'routing-tables-full' = @('show ip route vrf all')
            # PLACEHOLDER (Phase-2 finalizes; NX-OS route-type filters differ from IOS).
            'routing-tables-lite' = @('show ip route summary')
            'vrf'                 = @('show vrf')
            'arp'                 = @('show ip arp detail vrf all')
            'optics-transceiver'  = @('show interface transceiver', 'show interface transceiver details')
            'vdc'                 = @('show vdc detail')
            'collect-only-ops'    = @('show logging last 100')
        }
        'cisco-router-iosxr' = [ordered]@{
            # IOS-XR sentinel is 'show route summary'. XR uses 'show interfaces'.
            'base'                = @('show version', 'show inventory', 'show interfaces', 'show running-config', 'show route summary')
            'neighbors'           = @('show cdp neighbors detail', 'show lldp neighbors detail')
            'routing-igp-ospf'    = @('show ospf neighbors', 'show ospf interface')
            'routing-isis'        = @('show isis neighbors', 'show isis interface')
            'routing-bgp'         = @('show bgp summary', 'show bgp neighbors')
            'routing-tables-full' = @('show route', 'show route vrf all')
            # PLACEHOLDER (Phase-2 finalizes).
            'routing-tables-lite' = @('show route summary')
            'vrf'                 = @('show vrf all')
            'arp'                 = @('show arp', 'show arp vrf all')
            # 'show interfaces description' / 'show ipv4 interface brief' are informative
            # interface views, not needed to key the device — re-homed here out of base.
            'collect-only-ops'    = @('show interfaces description', 'show ipv4 interface brief', 'show mpls ldp neighbor', 'show platform', 'show redundancy summary', 'show environment', 'show logging')
        }
        'cisco-wlc-aireos'   = [ordered]@{
            # AireOS identity is 'show sysinfo' + 'show inventory'; run-config equiv is
            # 'show run-config commands'. The interface views ('show interface summary',
            # 'show port summary') feed WLC interface processing, not device keying, so
            # they live in the 'wireless' group rather than base.
            'base'             = @('show sysinfo', 'show inventory', 'show run-config commands')
            'neighbors'        = @('show cdp neighbors detail')
            'wireless'         = @('show interface summary', 'show port summary', 'show ap summary', 'show wlan summary', 'show flexconnect group summary', 'show client summary')
            'collect-only-ops' = @('show redundancy summary', 'show redundancy detail', 'show msglog')
        }
        'cisco-wlc-iosxe'    = [ordered]@{
            # 9800 identity additionally includes 'show wireless client summary'.
            # Hostname keys off 'show version' + 'show running-config' + the live prompt,
            # so 'show startup-config | include hostname' is redundant for keying — it is
            # re-homed to 'collect-only-ops' (retained as informative, out of base).
            'base'             = @('show version', 'show inventory', 'show interface', 'show wireless client summary', 'show running-config')
            'neighbors'        = @('show cdp neighbors detail', 'show lldp neighbors detail')
            'switching'        = @('show etherchannel summary')
            'wireless'         = @('show wireless summary', 'show ap summary', 'show ap cdp neighbors', 'show wlan summary', 'show wireless tag policy summary')
            'collect-only-ops' = @('show startup-config | include hostname', 'show chassis', 'show redundancy', 'show logging last 100')
        }
    }
}

# Named profiles = feature-group compositions applied ON TOP OF base (base is
# always included regardless). The '*' sentinel means "all feature groups the
# platform defines, except routing-tables-lite" (lite is a strict alternative to
# routing-tables-full, so 'full' uses -full and never both). Groups a profile
# names but a platform does not define are silently skipped (e.g. routing-isis
# on non-XR), which is expected, not an error.
function Get-CollectionProfileCatalog {
    return @{
        'full'      = '*'
        'l2-switch' = @('switching', 'power', 'optics-transceiver', 'neighbors')
        'l3-switch' = @('switching', 'routing-igp-ospf', 'routing-igp-eigrp', 'routing-bgp', 'routing-isis', 'routing-tables-full', 'vrf', 'arp', 'optics-transceiver', 'neighbors')
        'router'    = @('switching', 'routing-igp-ospf', 'routing-igp-eigrp', 'routing-bgp', 'routing-isis', 'routing-tables-full', 'vrf', 'arp', 'optics-transceiver', 'neighbors')
        'bgp-heavy' = @('switching', 'routing-igp-ospf', 'routing-igp-eigrp', 'routing-bgp', 'routing-isis', 'routing-tables-lite', 'vrf', 'arp', 'optics-transceiver', 'neighbors')
        'wlc'       = @('wireless', 'neighbors')
    }
}

# =============================================================================
# VERSION-GUARDED COMMAND VARIANTS (task 0c)
# A group member is a plain string today (unversioned, always collected). It MAY
# instead be a version-guarded object so a logical command whose CLI syntax
# changed across a firmware boundary resolves to the correct literal for the
# device's detected version. Two accepted object shapes:
#
#   (a) multi-variant:  @{ variants = @(
#                              @{ command = 'show foo old'; max_version = '17.1' },
#                              @{ command = 'show foo new'; min_version = '17.2' }
#                            ); on_unknown = 'newest' }   # or 'skip'
#   (b) single-variant convenience: @{ command = '...'; min_version; max_version }
#
# Resolution rules (see Resolve-CommandVariant):
#   - a plain string resolves to itself;
#   - with a known, parseable device version, the variant whose [min,max] range
#     contains it wins (newest match on overlap);
#   - with an UNKNOWN/unparseable version, the default is the NEWEST variant (and
#     a note is emitted); a per-command opt-out `on_unknown = 'skip'` hard-skips
#     instead (for commands where guessing wrong is harmful).
#
# All logic here is pure and unit-tested; the resolver never writes/logs — it
# RETURNS a note string that the caller surfaces. Actual per-command variants are
# DATA added to the catalog as discovered; the mechanism ships now, the archetype
# (IOS-XE syntax change at 17.2) is exercised in the tests with a synthetic entry.
# =============================================================================

# Read a field off a variant member that may be a hashtable (catalog style) OR a
# PSCustomObject (JSON-authored). Returns $Default when absent/null. Strict-safe.
function Get-VariantField {
    param(
        $Object,
        [Parameter(Mandatory = $true)][string]$Name,
        $Default = $null
    )
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name) -and $null -ne $Object[$Name]) { return $Object[$Name] }
        return $Default
    }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop -or $null -eq $prop.Value) { return $Default }
    return $prop.Value
}

# Tokenize a vendor version string into an ordered integer component array plus an
# optional trailing alpha suffix (rebuild/maintenance letter). Handles every
# current Cisco scheme: IOS-XE '17.2.1a' / '17.03.04a', NX-OS '9.3(5)',
# IOS-XR '7.3.2', AireOS '8.10.185.0'. Returns $null when no numeric component
# is present (unparseable). Leading train names (e.g. 'Amsterdam-17.2') are
# ignored because only numeric runs and a trailing letter are extracted.
function ConvertTo-VersionTokens {
    param([string]$Version)
    if ([string]::IsNullOrWhiteSpace($Version)) { return $null }
    $numMatches = [regex]::Matches($Version, '\d+')
    if ($numMatches.Count -eq 0) { return $null }
    $numbers = @()
    foreach ($m in $numMatches) { $numbers += [int]$m.Value }
    $suffix = ''
    $suffixMatch = [regex]::Match($Version, '([A-Za-z]+)\s*$')
    if ($suffixMatch.Success) { $suffix = $suffixMatch.Groups[1].Value.ToLower() }
    return [PSCustomObject]@{ Numbers = [int[]]$numbers; Suffix = $suffix }
}

# Compare two firmware versions for a platform. Returns -1 (A<B), 0 (A==B),
# 1 (A>B), or $null when either side is unparseable. The $Platform parameter is
# the documented per-scheme dispatch point: all current vendor schemes tokenize
# identically (numeric components, then a trailing rebuild letter where ''<'a'),
# so they share one tokenizer today, but a future divergent scheme branches here.
function Compare-FirmwareVersion {
    param(
        [string]$Platform,
        [string]$VersionA,
        [string]$VersionB
    )
    $ta = $null
    $tb = $null
    switch -Regex ($Platform) {
        # Reserved for a future scheme that does NOT tokenize like the others.
        default {
            $ta = ConvertTo-VersionTokens $VersionA
            $tb = ConvertTo-VersionTokens $VersionB
        }
    }
    if ($null -eq $ta -or $null -eq $tb) { return $null }

    $maxLen = [Math]::Max($ta.Numbers.Count, $tb.Numbers.Count)
    for ($i = 0; $i -lt $maxLen; $i++) {
        $x = if ($i -lt $ta.Numbers.Count) { $ta.Numbers[$i] } else { 0 }
        $y = if ($i -lt $tb.Numbers.Count) { $tb.Numbers[$i] } else { 0 }
        if ($x -lt $y) { return -1 }
        if ($x -gt $y) { return 1 }
    }
    # Numeric components equal — an empty suffix is OLDER than any lettered rebuild.
    if ($ta.Suffix -eq $tb.Suffix) { return 0 }
    if ($ta.Suffix -eq '') { return -1 }
    if ($tb.Suffix -eq '') { return 1 }
    if ([string]::CompareOrdinal($ta.Suffix, $tb.Suffix) -lt 0) { return -1 }
    return 1
}

# Extract a device's firmware version from its 'show version' (or identity)
# output, per platform. Returns the version literal (e.g. '17.3.4a', '9.3(5)',
# '7.3.2', '8.10.185.0') or $null when it cannot be found.
function Get-DeviceFirmwareVersion {
    param(
        [string]$Platform,
        [string]$ShowVersionOutput
    )
    if ([string]::IsNullOrWhiteSpace($ShowVersionOutput)) { return $null }
    switch -Regex ($Platform) {
        'nxos' {
            # "  NXOS: version 9.3(5)"  or  "  system:    version 9.3(5)"
            $m = [regex]::Match($ShowVersionOutput, '(?im)^\s*(?:NXOS|system):\s+version\s+(\S+)')
            if ($m.Success) { return $m.Groups[1].Value }
            return $null
        }
        'iosxr' {
            # "Cisco IOS XR Software, Version 7.3.2"
            $m = [regex]::Match($ShowVersionOutput, '(?im)IOS\s*XR\s+Software.*?Version\s+([0-9][0-9A-Za-z.]*)')
            if ($m.Success) { return $m.Groups[1].Value.TrimEnd('.', ',') }
            $m2 = [regex]::Match($ShowVersionOutput, '(?im)^\s*Version\s+(\d+\.\d+\.\d+)')
            if ($m2.Success) { return $m2.Groups[1].Value }
            return $null
        }
        'aireos' {
            # AireOS 'show sysinfo': "Product Version..... 8.10.185.0"
            $m = [regex]::Match($ShowVersionOutput, '(?im)Product\s+Version[\.\s]+([0-9][0-9A-Za-z.]*)')
            if ($m.Success) { return $m.Groups[1].Value.TrimEnd('.', ',') }
            return $null
        }
        default {
            # IOS-XE (switch/router/wlc-iosxe): "Cisco IOS XE Software, Version 17.03.04a"
            # or "Cisco IOS Software [Amsterdam], ... Version 17.2.1a"
            $m = [regex]::Match($ShowVersionOutput, '(?im)Cisco\s+IOS.*?Version\s+([0-9][0-9A-Za-z.()]*)')
            if ($m.Success) { return $m.Groups[1].Value.TrimEnd('.', ',') }
            return $null
        }
    }
}

# True when $Version satisfies a variant's [min_version, max_version] guard for a
# platform (absent bound = open). A bound that fails to compare (unparseable) is
# treated as NOT satisfied — conservative, since guard data should be well-formed.
function Test-VariantGuard {
    param(
        $Variant,
        [string]$Platform,
        [string]$Version
    )
    $min = [string](Get-VariantField $Variant 'min_version')
    $max = [string](Get-VariantField $Variant 'max_version')
    if ($min -ne '') {
        $c = Compare-FirmwareVersion -Platform $Platform -VersionA $Version -VersionB $min
        if ($null -eq $c -or $c -lt 0) { return $false }
    }
    if ($max -ne '') {
        $c = Compare-FirmwareVersion -Platform $Platform -VersionA $Version -VersionB $max
        if ($null -eq $c -or $c -gt 0) { return $false }
    }
    return $true
}

# Order two variants by recency (newer = intended for later firmware). Returns
# 1 when $A is newer than $B, -1 when older, 0 when indistinguishable. A variant
# WITH a min_version outranks one without (open-bottom = oldest); when both have
# min_version they compare by it; ties fall through to max_version where an ABSENT
# max (open-top = latest) is the newer.
function Compare-VariantRecency {
    param($A, $B, [string]$Platform)
    $aMin = [string](Get-VariantField $A 'min_version')
    $bMin = [string](Get-VariantField $B 'min_version')
    if ($aMin -ne '' -and $bMin -ne '') {
        $c = Compare-FirmwareVersion -Platform $Platform -VersionA $aMin -VersionB $bMin
        if ($null -ne $c -and $c -ne 0) { return $c }
    }
    elseif ($aMin -ne '' -and $bMin -eq '') { return 1 }
    elseif ($aMin -eq '' -and $bMin -ne '') { return -1 }

    $aMax = [string](Get-VariantField $A 'max_version')
    $bMax = [string](Get-VariantField $B 'max_version')
    if ($aMax -eq '' -and $bMax -ne '') { return 1 }
    if ($aMax -ne '' -and $bMax -eq '') { return -1 }
    if ($aMax -ne '' -and $bMax -ne '') {
        $c = Compare-FirmwareVersion -Platform $Platform -VersionA $aMax -VersionB $bMax
        if ($null -ne $c) { return $c }
    }
    return 0
}

# The newest variant in a set (see Compare-VariantRecency).
function Get-NewestVariant {
    param($Variants, [string]$Platform)
    $arr = @($Variants)
    $newest = $arr[0]
    for ($i = 1; $i -lt $arr.Count; $i++) {
        if ((Compare-VariantRecency -A $arr[$i] -B $newest -Platform $Platform) -gt 0) {
            $newest = $arr[$i]
        }
    }
    return $newest
}

# Resolve a single group MEMBER (string or version-guarded object) to a literal
# command for a device's detected firmware version. Returns a PSCustomObject
# @{ command = <string or $null>; note = <string or $null> } where a $null command
# means "hard-skip this command" and a non-null note is a diagnostic the caller
# should log. Pure: no side effects, no logging.
function Resolve-CommandVariant {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Platform,
        [Parameter(Mandatory = $true)]$Member,
        [string]$DeviceVersion
    )
    # A plain string is an unversioned command — always collected verbatim.
    if ($Member -is [string]) {
        return [PSCustomObject]@{ command = $Member; note = $null }
    }

    # Object member. Gather its variants: either an explicit 'variants' array, or
    # the member itself as a single-variant convenience form.
    $variantsRaw = Get-VariantField $Member 'variants'
    $onUnknown = ([string](Get-VariantField $Member 'on_unknown' 'newest')).Trim().ToLower()
    if ($null -eq $variantsRaw) { $variantsRaw = @($Member) }
    $variants = @($variantsRaw)
    if ($variants.Count -eq 0) {
        return [PSCustomObject]@{ command = $null; note = $null }
    }

    $newest = Get-NewestVariant -Variants $variants -Platform $Platform
    $newestCmd = [string](Get-VariantField $newest 'command')

    # If no variant actually carries a version guard, the member is unconditional.
    $guarded = @($variants | Where-Object {
            (([string](Get-VariantField $_ 'min_version')) -ne '') -or
            (([string](Get-VariantField $_ 'max_version')) -ne '')
        })
    if ($guarded.Count -eq 0) {
        return [PSCustomObject]@{ command = $newestCmd; note = $null }
    }

    # Unknown / unparseable device version: newest (default) or hard-skip (opt-out).
    if ([string]::IsNullOrWhiteSpace($DeviceVersion) -or $null -eq (ConvertTo-VersionTokens $DeviceVersion)) {
        if ($onUnknown -eq 'skip') {
            return [PSCustomObject]@{
                command = $null
                note    = "Device version unknown/unparseable; hard-skipped version-guarded command '$newestCmd' (on_unknown=skip)."
            }
        }
        return [PSCustomObject]@{
            command = $newestCmd
            note    = "Device version unknown/unparseable; defaulted to newest variant '$newestCmd'."
        }
    }

    # Known version: pick the newest variant whose guard the version satisfies.
    $matched = @($variants | Where-Object { Test-VariantGuard -Variant $_ -Platform $Platform -Version $DeviceVersion })
    if ($matched.Count -ge 1) {
        $pick = Get-NewestVariant -Variants $matched -Platform $Platform
        return [PSCustomObject]@{ command = [string](Get-VariantField $pick 'command'); note = $null }
    }

    # Known version but outside every declared range — data gap; use newest + note.
    return [PSCustomObject]@{
        command = $newestCmd
        note    = "Device version '$DeviceVersion' matched no variant range; defaulted to newest '$newestCmd'."
    }
}

# Resolve a device's effective command list from its platform + (profile OR
# explicit groups) + per-device excludes/adds.
#   - base commands always come first and are NON-REMOVABLE (an exclude naming a
#     base command is ignored);
#   - selected feature groups follow in the catalog's declared group order;
#   - commands are deduped case-insensitively (first occurrence wins);
#   - excludes/adds are then applied via the shared Resolve-DeviceCommandList.
# Explicit -Groups (when non-empty) takes precedence over -ProfileName. Groups
# not defined for the platform are skipped. Returns a [string[]].
function Resolve-ProfileCommandList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Platform,
        [string]$ProfileName,
        [string[]]$Groups = @(),
        [string[]]$ExcludeCommands = @(),
        [string[]]$AddCommands = @(),
        $Catalog = $null,
        $ProfileCatalog = $null,
        # Task 0c: the device's detected firmware version. When a catalog member is
        # a version-guarded variant, this selects the literal. $null/empty means
        # "unknown version" (newest-or-skip per the member's on_unknown policy).
        [string]$DeviceVersion,
        # Optional List[string] the resolver appends version-resolution notes to
        # (fallbacks / hard-skips) so the caller can log them. Left $null to ignore.
        $VersionNotes = $null
    )
    if ($null -eq $Catalog) { $Catalog = Get-CommandGroupCatalog }
    if ($null -eq $ProfileCatalog) { $ProfileCatalog = Get-CollectionProfileCatalog }
    if ($null -eq $Groups) { $Groups = @() }
    if ($null -eq $ExcludeCommands) { $ExcludeCommands = @() }
    if ($null -eq $AddCommands) { $AddCommands = @() }

    if (-not $Catalog.Contains($Platform)) {
        throw "Unknown platform '$Platform' — no command-group catalog entry."
    }
    $platGroups = $Catalog[$Platform]

    # Non-base group names this platform defines (canonical order preserved).
    $featureNames = @($platGroups.Keys | Where-Object { $_ -ne 'base' })

    # Determine the selected feature-group list.
    if ($Groups.Count -gt 0) {
        $selected = @($Groups)
    }
    elseif (-not [string]::IsNullOrWhiteSpace($ProfileName)) {
        if (-not $ProfileCatalog.Contains($ProfileName)) {
            throw "Unknown profile '$ProfileName'. Known profiles: $(@($ProfileCatalog.Keys | Sort-Object) -join ', ')."
        }
        $sel = $ProfileCatalog[$ProfileName]
        if (($sel -is [string]) -and ($sel -eq '*')) {
            $selected = @($featureNames | Where-Object { $_ -ne 'routing-tables-lite' })
        }
        else {
            $selected = @($sel)
        }
    }
    else {
        # Neither groups nor profile: default to the 'full' composition.
        $selected = @($featureNames | Where-Object { $_ -ne 'routing-tables-lite' })
    }

    # Local helper: route a raw catalog member through the version-guard resolver,
    # collecting any note. Returns the resolved literal, or $null to hard-skip.
    $resolveMember = {
        param($member)
        $rv = Resolve-CommandVariant -Platform $Platform -Member $member -DeviceVersion $DeviceVersion
        if ($null -ne $rv.note -and $null -ne $VersionNotes) { [void]$VersionNotes.Add($rv.note) }
        return $rv.command
    }

    # Build base + selected-group commands in canonical order, deduped. Each raw
    # member may be a plain string or a version-guarded variant object.
    $ordered = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    $baseCmds = @()
    if ($platGroups.Contains('base')) { $baseCmds = @($platGroups['base']) }

    # Resolve the base literals once — reused for both the ordered set and the
    # non-removable base guard below.
    $resolvedBase = [System.Collections.Generic.List[string]]::new()
    foreach ($member in $baseCmds) {
        $cmd = & $resolveMember $member
        if ($null -ne $cmd) { $resolvedBase.Add($cmd) }
    }
    foreach ($c in $resolvedBase) {
        if ($seen.Add($c.Trim())) { $ordered.Add($c) }
    }
    foreach ($gName in $featureNames) {
        if ($selected -notcontains $gName) { continue }
        foreach ($member in @($platGroups[$gName])) {
            $cmd = & $resolveMember $member
            if ($null -eq $cmd) { continue }
            if ($seen.Add($cmd.Trim())) { $ordered.Add($cmd) }
        }
    }

    # base is NON-REMOVABLE: drop any exclude that targets a base command before
    # applying the shared exclude/add resolver.
    $baseSet = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@($resolvedBase | ForEach-Object { $_.Trim() }),
        [System.StringComparer]::OrdinalIgnoreCase)
    $effectiveExcludes = @($ExcludeCommands | Where-Object { -not $baseSet.Contains(([string]$_).Trim()) })

    return Resolve-DeviceCommandList -BaseCommands ([string[]]$ordered.ToArray()) `
        -ExcludeCommands $effectiveExcludes -AddCommands $AddCommands
}
