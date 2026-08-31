#Requires -Version 5.1

# Phase-0 integration tests: prove the wiring the main script now performs is
# correct and, crucially, LOSES NOTHING versus the pre-integration flat-file path.
#
# ssh-cmd-runner.ps1 replaced flat commands/<os>.txt loading with catalog-based
# resolution. The pure functions it drives (ConvertFrom-CollectionPlanJson /
# ConvertFrom-CollectionCsv -> normalized device; Resolve-ProfileCommandList) live in
# lib/CollectorCore.ps1 and are exercised here exactly as the script calls them. The
# live SSH run itself is not unit-testable; these cover the input + resolution paths.
#
# NOTE: Resolve-ProfileCommandList already returns an array-protected [string[]]
# (via the comma operator), so callers assign its result DIRECTLY - wrapping it in
# @() would nest it as @(@(...)). The main script assigns it directly for the same
# reason; these tests mirror that exactly.

# Discovery-time data. Pester 5 evaluates `It -ForEach` at DISCOVERY, before any
# BeforeAll runs, so the platform list must live at file (discovery) scope - not in
# BeforeAll, or the -ForEach expansion silently produces zero test cases.
$Platforms = @('cisco-switch-iosxe', 'cisco-router-iosxe', 'cisco-switch-nxos',
    'cisco-router-iosxr', 'cisco-wlc-aireos', 'cisco-wlc-iosxe')

BeforeAll {
    . (Join-Path $PSScriptRoot '../lib/CollectorCore.ps1')

    $script:RepoRoot   = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
    $script:CommandDir = Join-Path $RepoRoot 'commands'

    # Read a deprecated flat command file the way the OLD live loader did: strip
    # blank lines and comment (#) lines, trim each remaining line. This is the
    # "what the collector used to run" reference set for the superset check.
    function script:Get-FlatCommandSet {
        param([string]$Platform)
        $path = Join-Path $script:CommandDir "$Platform.txt"
        return @(Get-Content -LiteralPath $path |
                ForEach-Object { $_.Trim() } |
                Where-Object { $_ -ne '' -and $_ -notmatch '^\s*#' })
    }
}

Describe 'Behavior preservation - full profile is a superset of the old flat file' {
    It 'drops no command from <_> that the flat file collected' -ForEach $Platforms {
        $platform = $_
        $flat = script:Get-FlatCommandSet -Platform $platform
        $flat.Count | Should -BeGreaterThan 0 -Because "$platform flat file should have commands"

        $full = Resolve-ProfileCommandList -Platform $platform -ProfileName 'full'
        $fullSet = [System.Collections.Generic.HashSet[string]]::new(
            [string[]]@($full | ForEach-Object { $_.Trim() }),
            [System.StringComparer]::OrdinalIgnoreCase)

        $missing = @($flat | Where-Object { -not $fullSet.Contains($_.Trim()) })
        $missing | Should -BeNullOrEmpty -Because "the 'full' profile must still collect every old $platform command; missing: $($missing -join ', ')"
    }
}

Describe 'Behavior preservation - intentionally-added base sentinels' {
    It 'adds the NX-OS route-summary sentinel under full' {
        $full = Resolve-ProfileCommandList -Platform 'cisco-switch-nxos' -ProfileName 'full'
        $full | Should -Contain 'show ip route summary'
    }
    It 'adds the IOS-XR route-summary sentinel under full' {
        $full = Resolve-ProfileCommandList -Platform 'cisco-router-iosxr' -ProfileName 'full'
        $full | Should -Contain 'show route summary'
    }
    It 'keeps the IOS-XE-switch protocols sentinel under full' {
        $full = Resolve-ProfileCommandList -Platform 'cisco-switch-iosxe' -ProfileName 'full'
        $full | Should -Contain 'show ip protocols'
    }
}

Describe 'Behavior preservation - base-tightening re-homings still collected under full' {
    It 'still collects re-homed IOS-XE router interface views' {
        $full = Resolve-ProfileCommandList -Platform 'cisco-router-iosxe' -ProfileName 'full'
        $full | Should -Contain 'show interface description'
        $full | Should -Contain 'show ip interface brief'
    }
    It 'still collects re-homed IOS-XR interface views' {
        $full = Resolve-ProfileCommandList -Platform 'cisco-router-iosxr' -ProfileName 'full'
        $full | Should -Contain 'show interfaces description'
        $full | Should -Contain 'show ipv4 interface brief'
    }
    It 'still collects the re-homed 9800 startup-config hostname view' {
        $full = Resolve-ProfileCommandList -Platform 'cisco-wlc-iosxe' -ProfileName 'full'
        $full | Should -Contain 'show startup-config | include hostname'
    }
}

Describe 'CSV input path - legacy device maps to full and loses nothing' {
    It 'parses a CSV device to the full profile with plan_id null' {
        $csv = @(
            'IP,Category,OS'
            '10.1.1.1,Switch,cisco-switch-iosxe'
        ) -join "`n"
        $plan = ConvertFrom-CollectionCsv -CsvText $csv

        $plan.plan_id | Should -BeNullOrEmpty
        $plan.devices.Count | Should -Be 1
        $dev = $plan.devices[0]
        $dev.connect_ip | Should -Be '10.1.1.1'
        $dev.platform   | Should -Be 'cisco-switch-iosxe'
        $dev.profile    | Should -Be 'full'

        # Resolve exactly as the script does for a CSV device, then confirm the old
        # flat set is fully contained.
        $resolved = Resolve-ProfileCommandList -Platform $dev.platform `
            -ProfileName $dev.profile -Groups $dev.groups `
            -ExcludeCommands $dev.exclude_commands -AddCommands $dev.add_commands
        $resolvedSet = [System.Collections.Generic.HashSet[string]]::new(
            [string[]]@($resolved | ForEach-Object { $_.Trim() }),
            [System.StringComparer]::OrdinalIgnoreCase)
        $flat = script:Get-FlatCommandSet -Platform 'cisco-switch-iosxe'
        @($flat | Where-Object { -not $resolvedSet.Contains($_.Trim()) }) | Should -BeNullOrEmpty
    }

    It 'honors per-device CSV excludes and adds through resolution' {
        $csv = @(
            'IP,Category,OS,ExcludeCommands,AddCommands'
            '10.1.1.2,Switch,cisco-switch-iosxe,"show power inline","show clock"'
        ) -join "`n"
        $plan = ConvertFrom-CollectionCsv -CsvText $csv
        $dev = $plan.devices[0]

        $resolved = Resolve-ProfileCommandList -Platform $dev.platform `
            -ProfileName $dev.profile -Groups $dev.groups `
            -ExcludeCommands $dev.exclude_commands -AddCommands $dev.add_commands

        $resolved | Should -Not -Contain 'show power inline'   # excluded (non-base)
        $resolved | Should -Contain 'show clock'               # added
        $resolved | Should -Contain 'show running-config'      # base, always present
    }
}

Describe 'JSON plan input path - plan_id round-trip and profile/groups resolution' {
    It 'parses plan_id and connect_ip and resolves a profile device' {
        $json = @'
{
  "schema_version": 1,
  "plan_id": "run-2026-08-17-001",
  "defaults": { "profile": "full" },
  "devices": [
    { "connect_ip": "192.0.2.10", "platform": "cisco-switch-iosxe", "profile": "l2-switch" }
  ]
}
'@
        $plan = ConvertFrom-CollectionPlanJson -Json $json
        $plan.plan_id | Should -Be 'run-2026-08-17-001'
        $dev = $plan.devices[0]
        $dev.connect_ip | Should -Be '192.0.2.10'
        $dev.platform   | Should -Be 'cisco-switch-iosxe'
        $dev.profile    | Should -Be 'l2-switch'

        $resolved = Resolve-ProfileCommandList -Platform $dev.platform `
            -ProfileName $dev.profile -Groups $dev.groups `
            -ExcludeCommands $dev.exclude_commands -AddCommands $dev.add_commands
        # l2-switch selects switching/power/optics/neighbors; base is always present,
        # routing groups are not.
        $resolved | Should -Contain 'show running-config'         # base
        $resolved | Should -Contain 'show mac address-table'      # switching
        $resolved | Should -Not -Contain 'show ip bgp summary'    # routing-bgp not in l2-switch
    }

    It 'resolves an explicit-groups device (groups override profile)' {
        $json = @'
{
  "schema_version": 1,
  "plan_id": "run-groups",
  "devices": [
    { "connect_ip": "192.0.2.11", "platform": "cisco-switch-iosxe", "groups": ["neighbors"] }
  ]
}
'@
        $plan = ConvertFrom-CollectionPlanJson -Json $json
        $dev = $plan.devices[0]
        $dev.groups | Should -Contain 'neighbors'

        $resolved = Resolve-ProfileCommandList -Platform $dev.platform `
            -ProfileName $dev.profile -Groups $dev.groups `
            -ExcludeCommands $dev.exclude_commands -AddCommands $dev.add_commands
        $resolved | Should -Contain 'show cdp neighbors detail'   # neighbors group
        $resolved | Should -Contain 'show version'                # base always present
        $resolved | Should -Not -Contain 'show mac address-table' # switching not selected
    }

    It 'leaves plan_id null when the JSON plan omits it' {
        $json = @'
{
  "schema_version": 1,
  "devices": [ { "connect_ip": "192.0.2.12", "platform": "cisco-switch-nxos" } ]
}
'@
        $plan = ConvertFrom-CollectionPlanJson -Json $json
        $plan.plan_id | Should -BeNullOrEmpty
        $plan.devices[0].profile | Should -Be 'full'   # default applied
    }
}
