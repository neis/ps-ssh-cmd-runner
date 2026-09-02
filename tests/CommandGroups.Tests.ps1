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

Describe 'Resolve-ProfileCommandList - base is always present and non-removable' {
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

Describe 'Resolve-ProfileCommandList - profile composition' {
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

    It 'l2-switch excludes routing but keeps switching/power/optics/neighbors + vrf' {
        $r = Resolve-ProfileCommandList -Platform 'cisco-switch-iosxe' -ProfileName 'l2-switch'
        $r | Should -Contain 'show mac address-table'
        $r | Should -Contain 'show power inline'
        $r | Should -Contain 'show interface transceiver'
        $r | Should -Contain 'show cdp neighbors detail'
        $r | Should -Contain 'show vrf'                       # vrf now on l2-switch (re-promotion)
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

Describe 'Resolve-ProfileCommandList - vrf collected on every switch/router profile' {
    # Every switch/router profile must resolve the platform's vrf command so a
    # device that later gains VRF-lite still re-runs 'show vrf' and can be
    # re-promoted by Reperio. The vrf command literal is per-platform.
    $vrfCases = @(
        @{ Platform = 'cisco-switch-iosxe'; Vrf = 'show vrf' }
        @{ Platform = 'cisco-router-iosxe'; Vrf = 'show vrf' }
        @{ Platform = 'cisco-switch-nxos';  Vrf = 'show vrf' }
        @{ Platform = 'cisco-router-iosxr'; Vrf = 'show vrf all' }
    )

    It "<Platform>: '<Vrf>' is present on full/l2-switch/l3-switch/router/bgp-heavy" -TestCases $vrfCases {
        param($Platform, $Vrf)
        foreach ($prof in @('full', 'l2-switch', 'l3-switch', 'router', 'bgp-heavy')) {
            $r = Resolve-ProfileCommandList -Platform $Platform -ProfileName $prof
            $r | Should -Contain $Vrf -Because "profile '$prof' on $Platform must collect vrf"
        }
    }

    It 'vrf stays EXCLUDABLE (a normal feature group, not protected) - prunes per-device' {
        # An L2 switch with no VRF support: Reperio drops 'show vrf' via exclude_commands
        # after one '% Invalid input'. Since vrf is NOT base/collector-only, the exclude
        # is honored (unlike a protected command).
        $r = Resolve-ProfileCommandList -Platform 'cisco-switch-iosxe' -ProfileName 'l2-switch' `
            -ExcludeCommands @('show vrf')
        $r | Should -Not -Contain 'show vrf'
    }

    It 'wlc profile does NOT collect vrf (WLCs have no VRFs)' {
        # Neither the wlc profile nor the wlc platform catalogs name/define a vrf group.
        (Resolve-ProfileCommandList -Platform 'cisco-wlc-aireos' -ProfileName 'wlc') |
            Should -Not -Contain 'show vrf'
        (Resolve-ProfileCommandList -Platform 'cisco-wlc-iosxe' -ProfileName 'wlc') |
            Should -Not -Contain 'show vrf'
    }
}

Describe 'Resolve-ProfileCommandList - explicit groups + excludes/adds' {
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

Describe 'Resolve-ProfileCommandList - error handling' {
    It 'throws on an unknown platform' {
        { Resolve-ProfileCommandList -Platform 'arista-eos' -ProfileName 'full' } |
            Should -Throw -ExpectedMessage '*Unknown platform*'
    }
    It 'throws on an unknown profile' {
        { Resolve-ProfileCommandList -Platform 'cisco-switch-iosxe' -ProfileName 'nope' } |
            Should -Throw -ExpectedMessage '*Unknown profile*'
    }
}

Describe 'Resolve-ProfileCommandList - wlc profiles' {
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

Describe 'Profile/catalog consistency (typo guard)' {
    It 'every group named by any profile is defined by at least one platform catalog' {
        $cat = Get-CommandGroupCatalog
        $profiles = Get-CollectionProfileCatalog

        # Union of every group name any platform defines.
        $known = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($plat in $cat.Keys) {
            foreach ($g in $cat[$plat].Keys) { [void]$known.Add($g) }
        }

        foreach ($pName in $profiles.Keys) {
            $sel = $profiles[$pName]
            # The '*' sentinel means "all of this platform's groups" - nothing to typo-check.
            if (($sel -is [string]) -and ($sel -eq '*')) { continue }
            foreach ($g in @($sel)) {
                $known.Contains($g) | Should -BeTrue -Because "profile '$pName' references group '$g', which no platform catalog defines (likely a typo). Cross-platform-only groups such as routing-isis are fine - this only fails when NO platform defines the group at all."
            }
        }
    }
}

Describe 'collector-only category - protected, non-removable, reserved' {
    # Synthetic catalog exercising the reserved 'collector-only' slot. Real
    # platform catalogs deliberately define NO collector-only members yet (asserted
    # below), so behavior is proven against a synthetic entry, mirroring how the
    # version-guard archetype is tested.
    BeforeAll {
        $script:synthCat = @{
            'test-plat' = [ordered]@{
                'base'           = @('show version', 'show running-config')
                'collector-only' = @('show collector-internal')
                'neighbors'      = @('show cdp neighbors')
                'extras'         = @('show extra')
            }
        }
        $script:synthProfiles = @{
            'full'   = '*'
            'narrow' = @('neighbors')
        }
    }

    It 'always includes collector-only commands under the full profile' {
        $r = Resolve-ProfileCommandList -Platform 'test-plat' -ProfileName 'full' `
            -Catalog $script:synthCat -ProfileCatalog $script:synthProfiles
        $r | Should -Contain 'show collector-internal'
    }

    It 'includes collector-only even for a narrow profile that names only one feature group' {
        $r = Resolve-ProfileCommandList -Platform 'test-plat' -ProfileName 'narrow' `
            -Catalog $script:synthCat -ProfileCatalog $script:synthProfiles
        $r | Should -Contain 'show collector-internal'   # protected, not profile-selected
        $r | Should -Contain 'show cdp neighbors'        # the one selected feature group
        $r | Should -Not -Contain 'show extra'           # unselected feature group is absent
    }

    It 'includes collector-only even when only an unrelated explicit group is requested' {
        $r = Resolve-ProfileCommandList -Platform 'test-plat' -Groups @('neighbors') `
            -Catalog $script:synthCat -ProfileCatalog $script:synthProfiles
        $r | Should -Contain 'show collector-internal'
    }

    It 'refuses to drop a collector-only command via exclude_commands' {
        $r = Resolve-ProfileCommandList -Platform 'test-plat' -ProfileName 'full' `
            -ExcludeCommands @('show collector-internal') `
            -Catalog $script:synthCat -ProfileCatalog $script:synthProfiles
        $r | Should -Contain 'show collector-internal'
    }

    It 'emits collector-only after base, ahead of feature groups' {
        $r = Resolve-ProfileCommandList -Platform 'test-plat' -ProfileName 'full' `
            -Catalog $script:synthCat -ProfileCatalog $script:synthProfiles
        $baseIdx      = [array]::IndexOf($r, 'show running-config')
        $collectorIdx = [array]::IndexOf($r, 'show collector-internal')
        $featureIdx   = [array]::IndexOf($r, 'show cdp neighbors')
        $collectorIdx | Should -BeGreaterThan $baseIdx
        $featureIdx   | Should -BeGreaterThan $collectorIdx
    }

    It 'is RESERVED - no real platform catalog defines collector-only members yet' {
        $cat = Get-CommandGroupCatalog
        foreach ($plat in $cat.Keys) {
            # collector-only is either absent or (if ever pre-declared) empty; it must
            # NOT carry members until a real collector-operational command needs one.
            if ($cat[$plat].Contains('collector-only')) {
                @($cat[$plat]['collector-only']).Count | Should -Be 0 `
                    -Because "$plat must keep collector-only reserved/empty for now"
            }
        }
    }
}

Describe 'Base tightening - deliberate extras re-homed OUT of base' {
    BeforeAll { $script:cat = Get-CommandGroupCatalog }

    It 'router-iosxe: interface description / ip interface brief are collect-only, not base' {
        $script:cat['cisco-router-iosxe']['base'] | Should -Not -Contain 'show interface description'
        $script:cat['cisco-router-iosxe']['base'] | Should -Not -Contain 'show ip interface brief'
        $script:cat['cisco-router-iosxe']['collect-only-ops'] | Should -Contain 'show interface description'
        $script:cat['cisco-router-iosxe']['collect-only-ops'] | Should -Contain 'show ip interface brief'
    }

    It 'router-iosxr: interfaces description / ipv4 interface brief are collect-only, not base' {
        $script:cat['cisco-router-iosxr']['base'] | Should -Not -Contain 'show interfaces description'
        $script:cat['cisco-router-iosxr']['base'] | Should -Not -Contain 'show ipv4 interface brief'
        $script:cat['cisco-router-iosxr']['collect-only-ops'] | Should -Contain 'show interfaces description'
        $script:cat['cisco-router-iosxr']['collect-only-ops'] | Should -Contain 'show ipv4 interface brief'
    }

    It 'aireos: interface/port summary live in wireless, not base' {
        $script:cat['cisco-wlc-aireos']['base'] | Should -Not -Contain 'show interface summary'
        $script:cat['cisco-wlc-aireos']['base'] | Should -Not -Contain 'show port summary'
        $script:cat['cisco-wlc-aireos']['wireless'] | Should -Contain 'show interface summary'
        $script:cat['cisco-wlc-aireos']['wireless'] | Should -Contain 'show port summary'
    }

    It 'aireos base is exactly identity + running-config' {
        $script:cat['cisco-wlc-aireos']['base'] |
            Should -Be @('show sysinfo', 'show inventory', 'show run-config commands')
    }

    It 'wlc profile on AireOS still collects the interface views (now via wireless)' {
        $r = Resolve-ProfileCommandList -Platform 'cisco-wlc-aireos' -ProfileName 'wlc'
        $r | Should -Contain 'show interface summary'
        $r | Should -Contain 'show port summary'
    }

    It '9800: startup-config hostname helper is collect-only, not base' {
        $script:cat['cisco-wlc-iosxe']['base'] | Should -Not -Contain 'show startup-config | include hostname'
        $script:cat['cisco-wlc-iosxe']['collect-only-ops'] | Should -Contain 'show startup-config | include hostname'
    }

    It '9800 base still keys off show version + running-config' {
        $script:cat['cisco-wlc-iosxe']['base'] | Should -Contain 'show version'
        $script:cat['cisco-wlc-iosxe']['base'] | Should -Contain 'show running-config'
    }
}
