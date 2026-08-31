#Requires -Version 5.1

# Unit tests for the version-guarded command-variant framework (task 0c) in
# lib/CollectorCore.ps1: firmware-version extraction, per-platform version
# compare, and variant resolution (known / unknown version, newest fallback,
# hard-skip opt-out). Pure logic, zero mocking.

BeforeAll {
    . (Join-Path $PSScriptRoot '../lib/CollectorCore.ps1')
}

Describe 'ConvertTo-VersionTokens' {
    It 'tokenizes an IOS-XE version with a trailing rebuild letter' {
        $t = ConvertTo-VersionTokens '17.2.1a'
        $t.Numbers | Should -Be @(17, 2, 1)
        $t.Suffix  | Should -Be 'a'
    }
    It 'tokenizes an NX-OS parenthesized maintenance version' {
        $t = ConvertTo-VersionTokens '9.3(5)'
        $t.Numbers | Should -Be @(9, 3, 5)
        $t.Suffix  | Should -Be ''
    }
    It 'tokenizes a four-part AireOS version' {
        (ConvertTo-VersionTokens '8.10.185.0').Numbers | Should -Be @(8, 10, 185, 0)
    }
    It 'ignores a leading train name' {
        (ConvertTo-VersionTokens 'Amsterdam-17.2').Numbers | Should -Be @(17, 2)
    }
    It 'returns $null for a string with no digits' {
        ConvertTo-VersionTokens 'unknown' | Should -Be $null
    }
    It 'returns $null for empty input' {
        ConvertTo-VersionTokens '' | Should -Be $null
    }
}

Describe 'Compare-FirmwareVersion' {
    It 'orders IOS-XE versions numerically per component (17.2 < 17.10)' {
        Compare-FirmwareVersion 'cisco-switch-iosxe' '17.2.1' '17.10.1' | Should -Be -1
    }
    It 'treats a lettered rebuild as newer than the bare version (17.2.1 < 17.2.1a)' {
        Compare-FirmwareVersion 'cisco-switch-iosxe' '17.2.1' '17.2.1a' | Should -Be -1
    }
    It 'reports equality' {
        Compare-FirmwareVersion 'cisco-switch-iosxe' '17.2.1' '17.2.1' | Should -Be 0
    }
    It 'compares NX-OS maintenance builds (9.3(5) > 9.3(3))' {
        Compare-FirmwareVersion 'cisco-switch-nxos' '9.3(5)' '9.3(3)' | Should -Be 1
    }
    It 'compares IOS-XR versions' {
        Compare-FirmwareVersion 'cisco-router-iosxr' '7.3.2' '7.3.15' | Should -Be -1
    }
    It 'ignores leading-zero formatting differences (17.03.04 == 17.3.4)' {
        Compare-FirmwareVersion 'cisco-switch-iosxe' '17.03.04' '17.3.4' | Should -Be 0
    }
    It 'returns $null when either side is unparseable' {
        Compare-FirmwareVersion 'cisco-switch-iosxe' 'n/a' '17.2.1' | Should -Be $null
    }
}

Describe 'Get-DeviceFirmwareVersion' {
    It 'extracts an IOS-XE version from show version' {
        $out = @'
Cisco IOS XE Software, Version 17.03.04a
Cisco IOS Software [Amsterdam], Catalyst L3 Switch Software
'@
        Get-DeviceFirmwareVersion 'cisco-switch-iosxe' $out | Should -Be '17.03.04a'
    }
    It 'extracts an NX-OS version' {
        $out = @'
  BIOS: version 07.69
  NXOS: version 9.3(5)
  BIOS compile time:  05/17/2019
'@
        Get-DeviceFirmwareVersion 'cisco-switch-nxos' $out | Should -Be '9.3(5)'
    }
    It 'extracts an IOS-XR version' {
        Get-DeviceFirmwareVersion 'cisco-router-iosxr' 'Cisco IOS XR Software, Version 7.3.2' |
            Should -Be '7.3.2'
    }
    It 'extracts an AireOS Product Version from sysinfo' {
        Get-DeviceFirmwareVersion 'cisco-wlc-aireos' 'Product Version..................... 8.10.185.0' |
            Should -Be '8.10.185.0'
    }
    It 'returns $null when no version is present' {
        Get-DeviceFirmwareVersion 'cisco-switch-iosxe' 'banner with no version line' | Should -Be $null
    }
    It 'returns $null on empty output' {
        Get-DeviceFirmwareVersion 'cisco-switch-iosxe' '' | Should -Be $null
    }
}

Describe 'Resolve-CommandVariant - plain and unconditional members' {
    It 'returns a plain string member verbatim (unversioned)' {
        $r = Resolve-CommandVariant -Platform 'cisco-switch-iosxe' -Member 'show version'
        $r.command | Should -Be 'show version'
        $r.note    | Should -Be $null
    }
    It 'returns an unguarded object member unconditionally (no version note)' {
        $member = [pscustomobject]@{ command = 'show foo' }
        $r = Resolve-CommandVariant -Platform 'cisco-switch-iosxe' -Member $member
        $r.command | Should -Be 'show foo'
        $r.note    | Should -Be $null
    }
}

Describe 'Resolve-CommandVariant - archetype: IOS-XE syntax change at 17.2' {
    BeforeAll {
        # A logical command whose CLI syntax changed at IOS-XE 17.2:
        #   pre-17.2 -> 'show foo old-syntax'   (max_version 17.1)
        #   17.2+    -> 'show foo new-syntax'   (min_version 17.2)
        $script:member = [pscustomobject]@{
            variants   = @(
                [pscustomobject]@{ command = 'show foo old-syntax'; max_version = '17.1' }
                [pscustomobject]@{ command = 'show foo new-syntax'; min_version = '17.2' }
            )
            on_unknown = 'newest'
        }
    }

    It 'selects the pre-17.2 syntax on 16.12.4' {
        (Resolve-CommandVariant -Platform 'cisco-switch-iosxe' -Member $script:member -DeviceVersion '16.12.4').command |
            Should -Be 'show foo old-syntax'
    }
    It 'selects the new syntax at exactly 17.2 (inclusive boundary)' {
        (Resolve-CommandVariant -Platform 'cisco-switch-iosxe' -Member $script:member -DeviceVersion '17.2').command |
            Should -Be 'show foo new-syntax'
    }
    It 'selects the new syntax on 17.6.3' {
        (Resolve-CommandVariant -Platform 'cisco-switch-iosxe' -Member $script:member -DeviceVersion '17.6.3').command |
            Should -Be 'show foo new-syntax'
    }
    It 'still selects the pre-17.2 syntax at 17.1 (inclusive upper boundary)' {
        (Resolve-CommandVariant -Platform 'cisco-switch-iosxe' -Member $script:member -DeviceVersion '17.1').command |
            Should -Be 'show foo old-syntax'
    }

    It 'defaults to the NEWEST variant and emits a note when the version is unknown' {
        $r = Resolve-CommandVariant -Platform 'cisco-switch-iosxe' -Member $script:member -DeviceVersion $null
        $r.command | Should -Be 'show foo new-syntax'
        $r.note    | Should -Match 'unknown'
        $r.note    | Should -Match 'newest'
    }
    It 'defaults to newest when the version string is unparseable' {
        (Resolve-CommandVariant -Platform 'cisco-switch-iosxe' -Member $script:member -DeviceVersion 'garbage').command |
            Should -Be 'show foo new-syntax'
    }
}

Describe 'Resolve-CommandVariant - hard-skip opt-out on unknown version' {
    It 'returns a $null command (hard-skip) with a note when on_unknown=skip' {
        $member = [pscustomobject]@{
            variants   = @(
                [pscustomobject]@{ command = 'show risky old'; max_version = '17.1' }
                [pscustomobject]@{ command = 'show risky new'; min_version = '17.2' }
            )
            on_unknown = 'skip'
        }
        $r = Resolve-CommandVariant -Platform 'cisco-switch-iosxe' -Member $member -DeviceVersion $null
        $r.command | Should -Be $null
        $r.note    | Should -Match 'hard-skipped'
    }
    It 'still resolves normally when the version IS known (skip only applies to unknown)' {
        $member = [pscustomobject]@{
            variants   = @(
                [pscustomobject]@{ command = 'show risky old'; max_version = '17.1' }
                [pscustomobject]@{ command = 'show risky new'; min_version = '17.2' }
            )
            on_unknown = 'skip'
        }
        (Resolve-CommandVariant -Platform 'cisco-switch-iosxe' -Member $member -DeviceVersion '16.9.1').command |
            Should -Be 'show risky old'
    }
}

Describe 'Resolve-CommandVariant - known version outside every declared range' {
    It 'falls back to newest + note when no range covers the version' {
        $member = [pscustomobject]@{
            variants = @(
                [pscustomobject]@{ command = 'show a'; min_version = '17.2'; max_version = '17.5' }
            )
        }
        # 9.9 is below the only variant's min - no range matches.
        $r = Resolve-CommandVariant -Platform 'cisco-switch-iosxe' -Member $member -DeviceVersion '9.9'
        $r.command | Should -Be 'show a'
        $r.note    | Should -Match 'matched no variant range'
    }
}

Describe 'Resolve-ProfileCommandList - version-guarded members via a synthetic catalog' {
    BeforeAll {
        # Minimal synthetic catalog exercising a version-guarded member in a feature
        # group, without disturbing the real command catalog (keeps the command-set
        # sync triangle untouched - variants are DATA added later as discovered).
        $script:cat = @{
            'test-plat' = [ordered]@{
                'base'    = @('show version', 'show running-config')
                'feature' = @(
                    'show static',
                    [pscustomobject]@{
                        variants   = @(
                            [pscustomobject]@{ command = 'show foo old-syntax'; max_version = '17.1' }
                            [pscustomobject]@{ command = 'show foo new-syntax'; min_version = '17.2' }
                        )
                        on_unknown = 'newest'
                    }
                )
            }
        }
        $script:prof = @{ 'full' = '*' }
    }

    It 'resolves the pre-17.2 variant literal into the command set on an old version' {
        $r = Resolve-ProfileCommandList -Platform 'test-plat' -ProfileName 'full' `
            -Catalog $script:cat -ProfileCatalog $script:prof -DeviceVersion '16.12.4'
        $r | Should -Contain 'show foo old-syntax'
        $r | Should -Not -Contain 'show foo new-syntax'
        $r | Should -Contain 'show static'     # sibling plain string unaffected
        $r | Should -Contain 'show version'    # base intact
    }
    It 'resolves the 17.2+ variant literal on a new version' {
        $r = Resolve-ProfileCommandList -Platform 'test-plat' -ProfileName 'full' `
            -Catalog $script:cat -ProfileCatalog $script:prof -DeviceVersion '17.6.1'
        $r | Should -Contain 'show foo new-syntax'
        $r | Should -Not -Contain 'show foo old-syntax'
    }
    It 'collects a version-resolution note into -VersionNotes on unknown version' {
        $notes = [System.Collections.Generic.List[string]]::new()
        $r = Resolve-ProfileCommandList -Platform 'test-plat' -ProfileName 'full' `
            -Catalog $script:cat -ProfileCatalog $script:prof -DeviceVersion $null -VersionNotes $notes
        $r | Should -Contain 'show foo new-syntax'      # newest default
        @($notes).Count | Should -BeGreaterThan 0
        ($notes -join ' ') | Should -Match 'newest'
    }
}
