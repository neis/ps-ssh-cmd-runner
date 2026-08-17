#Requires -Version 5.1

# Unit tests for the command-group catalog, profiles, and resolver (task 0b) in
# lib/CollectorCore.ps1. Pure logic: platform + profile/groups + excludes/adds
# -> ordered, deduped command set with a non-removable base.

BeforeAll {
    . (Join-Path $PSScriptRoot '../lib/CollectorCore.ps1')
}

Describe 'Get-CommandGroupCatalog' {
    It 'defines a non-empty base group for every platform' {
        $cat = Get-CommandGroupCatalog
        foreach ($plat in $cat.Keys) {
            $cat[$plat].Contains('base') | Should -BeTrue -Because "$plat needs a base group"
            @($cat[$plat]['base']).Count | Should -BeGreaterThan 0
        }
    }

    It 'includes the six known platforms' {
        $cat = Get-CommandGroupCatalog
        foreach ($plat in @('cisco-switch-iosxe', 'cisco-router-iosxe', 'cisco-switch-nxos',
                'cisco-router-iosxr', 'cisco-wlc-aireos', 'cisco-wlc-iosxe')) {
            $cat.Contains($plat) | Should -BeTrue -Because "$plat should be catalogued"
        }
    }

    It 'carries the per-platform sentinel in base' {
        $cat = Get-CommandGroupCatalog
        $cat['cisco-switch-iosxe']['base'] | Should -Contain 'show ip protocols'
        $cat['cisco-switch-nxos']['base']  | Should -Contain 'show ip route summary'
        $cat['cisco-router-iosxr']['base'] | Should -Contain 'show route summary'
    }
}

Describe 'Get-CollectionProfileCatalog' {
    It 'defines the signed-off profiles' {
        $p = Get-CollectionProfileCatalog
        foreach ($name in @('full', 'l2-switch', 'l3-switch', 'router', 'bgp-heavy', 'wlc')) {
            $p.Contains($name) | Should -BeTrue
        }
    }
    It 'marks full as the all-groups sentinel' {
        (Get-CollectionProfileCatalog)['full'] | Should -Be '*'
    }
}

Describe 'Resolve-ProfileCommandList — base is always present and non-removable' {
    It 'includes the whole base for any profile' {
        $r = Resolve-ProfileCommandList -Platform 'cisco-switch-iosxe' -ProfileName 'l2-switch'
        $r | Should -Contain 'show version'
        $r | Should -Contain 'show inventory'
        $r | Should -Contain 'show running-config'
        $r | Should -Contain 'show ip protocols'
    }

    It 'refuses to drop a base command via exclude_commands' {
        $r = Resolve-ProfileCommandList -Platform 'cisco-switch-iosxe' -ProfileName 'full' `
            -ExcludeCommands @('show running-config', 'show version')
        $r | Should -Contain 'show running-config'
        $r | Should -Contain 'show version'
    }

    It 'includes base even when an empty group list is requested' {
        $r = Resolve-ProfileCommandList -Platform 'cisco-switch-iosxe' -Groups @()
        $r | Should -Contain 'show version'
        $r | Should -Contain 'show running-config'
    }
}

Describe 'Resolve-ProfileCommandList — profile composition' {
    It 'full includes routing-tables-full but NOT routing-tables-lite' {
        $r = Resolve-ProfileCommandList -Platform 'cisco-switch-iosxe' -ProfileName 'full'
        $r | Should -Contain 'show ip route'
        $r | Should -Not -Contain 'show ip route connected'
    }

    It 'full spans every feature group the platform defines (minus lite)' {
        $r = Resolve-ProfileCommandList -Platform 'cisco-switch-iosxe' -ProfileName 'full'
        $r | Should -Contain 'show cdp neighbors detail'   # neighbors
        $r | Should -Contain 'show mac address-table'      # switching
        $r | Should -Contain 'show power inline'           # power
        $r | Should -Contain 'show ip bgp summary'         # routing-bgp
        $r | Should -Contain 'show interface transceiver'  # optics
        $r | Should -Contain 'show license all'            # collect-only-ops
    }

    It 'l2-switch excludes routing but keeps switching/power/optics/neighbors' {
        $r = Resolve-ProfileCommandList -Platform 'cisco-switch-iosxe' -ProfileName 'l2-switch'
        $r | Should -Contain 'show mac address-table'
        $r | Should -Contain 'show power inline'
        $r | Should -Contain 'show interface transceiver'
        $r | Should -Contain 'show cdp neighbors detail'
        $r | Should -Not -Contain 'show ip bgp summary'
        $r | Should -Not -Contain 'show ip route'
    }

    It 'bgp-heavy uses routing-tables-lite instead of routing-tables-full' {
        $r = Resolve-ProfileCommandList -Platform 'cisco-switch-iosxe' -ProfileName 'bgp-heavy'
        $r | Should -Contain 'show ip route summary'
        $r | Should -Not -Contain 'show ip route vrf *'
        $r | Should -Contain 'show ip bgp summary'
    }

    It 'router profile pulls routing + arp + vrf' {
        $r = Resolve-ProfileCommandList -Platform 'cisco-router-iosxe' -ProfileName 'router'
        $r | Should -Contain 'show ip route'
        $r | Should -Contain 'show ip arp'
        $r | Should -Contain 'show vrf'
        $r | Should -Contain 'show ip ospf neighbor'
    }

    It 'silently skips profile groups the platform does not define (isis on non-XR)' {
        # router profile names routing-isis, which cisco-router-iosxe lacks -> no throw.
        { Resolve-ProfileCommandList -Platform 'cisco-router-iosxe' -ProfileName 'router' } | Should -Not -Throw
    }
}

Describe 'Resolve-ProfileCommandList — explicit groups + excludes/adds' {
    It 'explicit groups take precedence over profile' {
        $r = Resolve-ProfileCommandList -Platform 'cisco-switch-iosxe' `
            -ProfileName 'full' -Groups @('neighbors')
        $r | Should -Contain 'show cdp neighbors detail'
        $r | Should -Not -Contain 'show mac address-table'   # switching not selected
    }

    It 'a single group resolves to base + that group only' {
        $r = Resolve-ProfileCommandList -Platform 'cisco-switch-iosxe' -Groups @('power')
        $r | Should -Contain 'show power inline'
        $r | Should -Contain 'show version'                  # base
        $r | Should -Not -Contain 'show cdp neighbors detail'
    }

    It 'excludes a non-base feature command and appends adds' {
        $r = Resolve-ProfileCommandList -Platform 'cisco-switch-iosxe' -Groups @('switching') `
            -ExcludeCommands @('show etherchannel summary') -AddCommands @('show clock')
        $r | Should -Contain 'show mac address-table'
        $r | Should -Not -Contain 'show etherchannel summary'
        $r | Should -Contain 'show clock'
        $r[-1] | Should -Be 'show clock'                     # adds land at the end
    }

    It 'places base first and preserves declared group order' {
        $r = Resolve-ProfileCommandList -Platform 'cisco-switch-iosxe' -Groups @('neighbors')
        $r[0] | Should -Be 'show version'
    }

    It 'dedupes overlap between base and a group (case-insensitive)' {
        # NX-OS base carries 'show ip route summary'; routing-tables-lite repeats it.
        $r = Resolve-ProfileCommandList -Platform 'cisco-switch-nxos' -Groups @('routing-tables-lite')
        @($r | Where-Object { $_ -eq 'show ip route summary' }).Count | Should -Be 1
    }
}

Describe 'Resolve-ProfileCommandList — error handling' {
    It 'throws on an unknown platform' {
        { Resolve-ProfileCommandList -Platform 'arista-eos' -ProfileName 'full' } |
            Should -Throw -ExpectedMessage '*Unknown platform*'
    }
    It 'throws on an unknown profile' {
        { Resolve-ProfileCommandList -Platform 'cisco-switch-iosxe' -ProfileName 'nope' } |
            Should -Throw -ExpectedMessage '*Unknown profile*'
    }
}

Describe 'Resolve-ProfileCommandList — wlc profiles' {
    It 'wlc profile pulls wireless + neighbors on AireOS, plus base identity' {
        $r = Resolve-ProfileCommandList -Platform 'cisco-wlc-aireos' -ProfileName 'wlc'
        $r | Should -Contain 'show sysinfo'                  # base identity
        $r | Should -Contain 'show run-config commands'      # base running-config equiv
        $r | Should -Contain 'show ap summary'               # wireless
        $r | Should -Contain 'show cdp neighbors detail'     # neighbors
    }

    It '9800 base carries show wireless client summary' {
        $r = Resolve-ProfileCommandList -Platform 'cisco-wlc-iosxe' -ProfileName 'wlc'
        $r | Should -Contain 'show wireless client summary'
    }
}
