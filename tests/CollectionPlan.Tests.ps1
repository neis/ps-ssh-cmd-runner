#Requires -Version 5.1

# Unit tests for the collection-plan input parsers (task 0a) in
# lib/CollectorCore.ps1: ConvertFrom-CollectionPlanJson (structured JSON) and
# ConvertFrom-CollectionCsv (transitional CSV -> default 'full' profile).
# Pure functions, zero mocking: raw text in, normalized object out.

BeforeAll {
    . (Join-Path $PSScriptRoot '../lib/CollectorCore.ps1')
}

Describe 'ConvertTo-StringArray' {
    It 'returns an empty array for $null' {
        $r = ConvertTo-StringArray $null
        @($r).Count | Should -Be 0
    }
    It 'trims and drops empty entries' {
        $r = ConvertTo-StringArray @('  a ', '', '  ', 'b')
        $r | Should -Be @('a', 'b')
    }
    It 'wraps a scalar into a one-element array' {
        $r = ConvertTo-StringArray 'solo'
        @($r).Count | Should -Be 1
        $r[0] | Should -Be 'solo'
    }
}

Describe 'ConvertTo-NormalizedSshOptions' {
    It 'produces all four fields, null when absent' {
        $o = ConvertTo-NormalizedSshOptions ([PSCustomObject]@{ kex_algorithms = '+dh1' })
        $o.kex_algorithms      | Should -Be '+dh1'
        $o.ciphers             | Should -Be $null
        $o.host_key_algorithms | Should -Be $null
        $o.pty                 | Should -Be $null
    }
    It 'handles $null input (all fields null)' {
        $o = ConvertTo-NormalizedSshOptions $null
        $o.kex_algorithms | Should -Be $null
        $o.pty            | Should -Be $null
    }
}

Describe 'ConvertFrom-CollectionPlanJson' {
    It 'parses a full plan and echoes plan_id to every device' {
        $json = @'
{
  "schema_version": 1,
  "plan_id": "acme-001",
  "defaults": { "credential_group": "core", "profile": "full" },
  "devices": [
    { "connect_ip": "10.1.1.1", "platform": "cisco-switch-iosxe", "profile": "l2-switch", "priority": 10 },
    { "connect_ip": "10.1.1.2", "platform": "cisco-router-iosxe",
      "groups": ["neighbors", "routing-bgp"],
      "exclude_commands": ["show running-config"],
      "add_commands": ["show clock"],
      "ssh_options": { "kex_algorithms": "+dh1", "pty": true },
      "credential_group": "legacy" }
  ]
}
'@
        $plan = ConvertFrom-CollectionPlanJson -Json $json
        $plan.schema_version | Should -Be 1
        $plan.plan_id        | Should -Be 'acme-001'
        $plan.devices.Count  | Should -Be 2

        $d1 = $plan.devices[0]
        $d1.connect_ip | Should -Be '10.1.1.1'
        $d1.platform   | Should -Be 'cisco-switch-iosxe'
        $d1.profile    | Should -Be 'l2-switch'
        $d1.priority   | Should -Be 10
        $d1.plan_id    | Should -Be 'acme-001'

        $d2 = $plan.devices[1]
        $d2.groups           | Should -Be @('neighbors', 'routing-bgp')
        $d2.exclude_commands | Should -Be @('show running-config')
        $d2.add_commands     | Should -Be @('show clock')
        $d2.ssh_options.kex_algorithms | Should -Be '+dh1'
        $d2.ssh_options.pty  | Should -Be $true
        $d2.credential_group | Should -Be 'legacy'
    }

    It 'applies defaults.profile when a device gives neither profile nor groups' {
        $json = '{ "defaults": { "profile": "router" }, "devices": [ { "connect_ip": "1.2.3.4" } ] }'
        $plan = ConvertFrom-CollectionPlanJson -Json $json
        $plan.devices[0].profile | Should -Be 'router'
    }

    It 'falls back to built-in full when no defaults and no device profile/groups' {
        $json = '{ "devices": [ { "connect_ip": "1.2.3.4" } ] }'
        $plan = ConvertFrom-CollectionPlanJson -Json $json
        $plan.devices[0].profile | Should -Be 'full'
    }

    It 'inherits defaults.credential_group and defaults.ssh_options' {
        $json = '{ "defaults": { "credential_group": "core", "ssh_options": { "ciphers": "+cbc" } }, "devices": [ { "connect_ip": "1.2.3.4", "profile": "full" } ] }'
        $plan = ConvertFrom-CollectionPlanJson -Json $json
        $plan.devices[0].credential_group    | Should -Be 'core'
        $plan.devices[0].ssh_options.ciphers | Should -Be '+cbc'
    }

    It 'defaults schema_version to 1 when omitted' {
        $json = '{ "devices": [ { "connect_ip": "1.2.3.4" } ] }'
        (ConvertFrom-CollectionPlanJson -Json $json).schema_version | Should -Be 1
    }

    It 'throws on an unsupported schema_version' {
        $json = '{ "schema_version": 2, "devices": [ { "connect_ip": "1.2.3.4" } ] }'
        { ConvertFrom-CollectionPlanJson -Json $json } | Should -Throw -ExpectedMessage '*schema_version*'
    }

    It 'throws on a device missing connect_ip' {
        $json = '{ "devices": [ { "platform": "cisco-switch-iosxe" } ] }'
        { ConvertFrom-CollectionPlanJson -Json $json } | Should -Throw -ExpectedMessage '*connect_ip*'
    }

    It 'throws on an empty devices array' {
        { ConvertFrom-CollectionPlanJson -Json '{ "devices": [] }' } | Should -Throw -ExpectedMessage '*empty*'
    }

    It 'throws when devices is absent' {
        { ConvertFrom-CollectionPlanJson -Json '{ "plan_id": "x" }' } | Should -Throw -ExpectedMessage "*no 'devices'*"
    }

    It 'throws on invalid JSON' {
        { ConvertFrom-CollectionPlanJson -Json 'not json {' } | Should -Throw -ExpectedMessage '*not valid JSON*'
    }

    It 'throws on empty input' {
        { ConvertFrom-CollectionPlanJson -Json '   ' } | Should -Throw -ExpectedMessage '*empty*'
    }

    It 'throws on a non-integer priority' {
        $json = '{ "devices": [ { "connect_ip": "1.2.3.4", "priority": "soon" } ] }'
        { ConvertFrom-CollectionPlanJson -Json $json } | Should -Throw -ExpectedMessage '*priority*'
    }
}

Describe 'ConvertFrom-CollectionCsv' {
    It 'maps every row to the default full profile and preserves category' {
        $csv = @'
IP,Category,OS
10.0.0.1,Access,cisco-switch-iosxe
10.0.0.2,Core,cisco-router-iosxe
'@
        $plan = ConvertFrom-CollectionCsv -CsvText $csv
        $plan.schema_version | Should -Be 1
        $plan.plan_id        | Should -Be $null
        $plan.devices.Count  | Should -Be 2
        $plan.devices[0].profile    | Should -Be 'full'
        $plan.devices[0].platform   | Should -Be 'cisco-switch-iosxe'
        $plan.devices[0].category   | Should -Be 'Access'
        $plan.devices[0].connect_ip | Should -Be '10.0.0.1'
    }

    It 'lowercases the OS into platform' {
        $csv = "IP,OS`n10.0.0.1,Cisco-Switch-IOSXE"
        $plan = ConvertFrom-CollectionCsv -CsvText $csv
        $plan.devices[0].platform | Should -Be 'cisco-switch-iosxe'
    }

    It 'splits comma-separated ExcludeCommands / AddCommands cells' {
        $csv = @'
IP,OS,ExcludeCommands,AddCommands
10.0.0.1,cisco-switch-iosxe,"show running-config, show logging","show clock, show ntp status"
'@
        $plan = ConvertFrom-CollectionCsv -CsvText $csv
        $plan.devices[0].exclude_commands | Should -Be @('show running-config', 'show logging')
        $plan.devices[0].add_commands     | Should -Be @('show clock', 'show ntp status')
    }

    It 'ignores comment and blank lines' {
        $csv = @'
# a comment
IP,OS

10.0.0.1,cisco-switch-iosxe
# trailing comment
'@
        $plan = ConvertFrom-CollectionCsv -CsvText $csv
        $plan.devices.Count | Should -Be 1
    }

    It 'throws when the IP or OS column is missing' {
        { ConvertFrom-CollectionCsv -CsvText "IP,Category`n10.0.0.1,Access" } |
            Should -Throw -ExpectedMessage "*'IP' and 'OS'*"
    }

    It 'throws when a row is missing the OS field' {
        { ConvertFrom-CollectionCsv -CsvText "IP,OS`n10.0.0.1," } |
            Should -Throw -ExpectedMessage '*missing the OS field*'
    }

    It 'throws when there are no data rows' {
        { ConvertFrom-CollectionCsv -CsvText "IP,OS" } |
            Should -Throw -ExpectedMessage '*no data rows*'
    }
}
