#Requires -Version 5.1

# Unit tests for the pure functions in lib/CollectorCore.ps1.
# Zero mocking: every function under test is deterministic given its arguments.

BeforeAll {
    . (Join-Path $PSScriptRoot '../lib/CollectorCore.ps1')
}

Describe 'Resolve-DeviceCommandList' {
    It 'returns the base list unchanged when no excludes/adds' {
        $result = Resolve-DeviceCommandList -BaseCommands @('show version', 'show inventory')
        $result | Should -Be @('show version', 'show inventory')
    }

    It 'excludes commands case-insensitively and trimmed' {
        $result = Resolve-DeviceCommandList `
            -BaseCommands @('show version', 'show inventory', 'show run') `
            -ExcludeCommands @('  SHOW INVENTORY ')
        $result | Should -Be @('show version', 'show run')
    }

    It 'appends additions, dedupes against present, and skips empty' {
        $result = Resolve-DeviceCommandList `
            -BaseCommands @('show version') `
            -AddCommands @('show clock', '  SHOW VERSION  ', '', '   ', 'show clock')
        $result | Should -Be @('show version', 'show clock')
    }

    It 'preserves original base order' {
        $result = Resolve-DeviceCommandList -BaseCommands @('c', 'a', 'b')
        $result | Should -Be @('c', 'a', 'b')
    }

    It 'handles $null passed for any argument (PSCustomObject @()->$null case)' {
        $result = Resolve-DeviceCommandList -BaseCommands $null -ExcludeCommands $null -AddCommands $null
        # No throw; empty array back.
        @($result).Count | Should -Be 0
    }

    It 'handles $null excludes/adds with a real base list' {
        $result = Resolve-DeviceCommandList -BaseCommands @('show version') -ExcludeCommands $null -AddCommands $null
        $result | Should -Be @('show version')
    }
}

Describe 'Get-HostnameFromPrompt' {
    It 'parses Cisco IOS-XR exec prompt' {
        Get-HostnameFromPrompt 'RP/0/RSP0/CPU0:host#' | Should -Be 'host'
    }

    It 'parses Cisco IOS-XR config prompt' {
        Get-HostnameFromPrompt 'RP/0/RSP0/CPU0:host(config)#' | Should -Be 'host'
    }

    It 'parses Juniper/PAN user@host prompt' {
        Get-HostnameFromPrompt 'admin@host>' | Should -Be 'host'
    }

    It 'parses Cisco/Arista exec prompt (#)' {
        Get-HostnameFromPrompt 'SW1#' | Should -Be 'SW1'
    }

    It 'parses Cisco/Arista user-exec prompt (>)' {
        Get-HostnameFromPrompt 'SW1>' | Should -Be 'SW1'
    }

    It 'rejects false-positive confirmation token "yes#"' {
        Get-HostnameFromPrompt 'yes#' | Should -Be $null
    }

    It 'parses Linux-style bracketed prompt' {
        Get-HostnameFromPrompt '[user@host ~]$' | Should -Be 'host'
    }

    It 'parses Cisco WLC System Name field' {
        Get-HostnameFromPrompt 'System Name.................. FOO' | Should -Be 'FOO'
    }

    It 'returns first real match across multiple lines' {
        $output = "`n   `nsome banner text`nSW1#`nSW2#"
        Get-HostnameFromPrompt $output | Should -Be 'SW1'
    }

    It 'returns $null for junk with no prompt' {
        Get-HostnameFromPrompt 'this is just banner text with no prompt' | Should -Be $null
    }
}

Describe 'ConvertTo-SafeFileName' {
    It 'replaces each reserved character with underscore' {
        ConvertTo-SafeFileName 'a\b'  | Should -Be 'a_b'
        ConvertTo-SafeFileName 'a/b'  | Should -Be 'a_b'
        ConvertTo-SafeFileName 'a:b'  | Should -Be 'a_b'
        ConvertTo-SafeFileName 'a*b'  | Should -Be 'a_b'
        ConvertTo-SafeFileName 'a?b'  | Should -Be 'a_b'
        ConvertTo-SafeFileName 'a"b'  | Should -Be 'a_b'
        ConvertTo-SafeFileName 'a<b'  | Should -Be 'a_b'
        ConvertTo-SafeFileName 'a>b'  | Should -Be 'a_b'
        ConvertTo-SafeFileName 'a|b'  | Should -Be 'a_b'
    }

    It 'leaves a clean filename unchanged' {
        ConvertTo-SafeFileName 'show_version-2026.txt' | Should -Be 'show_version-2026.txt'
    }
}

Describe 'Test-IsAuthFailure' {
    It 'detects "Permission denied"' {
        Test-IsAuthFailure 'Permission denied (publickey,password).' | Should -BeTrue
    }

    It 'detects "Authentication failed"' {
        Test-IsAuthFailure 'Authentication failed.' | Should -BeTrue
    }

    It 'detects "Too many authentication failures"' {
        Test-IsAuthFailure 'Received disconnect: Too many authentication failures' | Should -BeTrue
    }

    It 'detects two read_passphrase calls as auth failure' {
        Test-IsAuthFailure "debug1: read_passphrase`ndebug1: read_passphrase" | Should -BeTrue
    }

    It 'detects one read_passphrase + connection closed as auth failure' {
        Test-IsAuthFailure "debug1: read_passphrase`nConnection closed by 10.0.0.1 port 22" | Should -BeTrue
    }

    It 'does NOT flag a timeout/connectivity error' {
        Test-IsAuthFailure 'ssh: connect to host 10.0.0.1 port 22: Connection timed out' | Should -BeFalse
    }

    It 'does NOT flag empty stderr' {
        Test-IsAuthFailure '' | Should -BeFalse
    }
}

Describe 'ConvertTo-CmdEchoEscaped' {
    It 'escapes caret ^ first (no double-escape)' {
        ConvertTo-CmdEchoEscaped 'a^b' | Should -Be 'a^^b'
    }

    It 'escapes ampersand &' {
        ConvertTo-CmdEchoEscaped 'a&b' | Should -Be 'a^&b'
    }

    It 'escapes pipe |' {
        ConvertTo-CmdEchoEscaped 'a|b' | Should -Be 'a^|b'
    }

    It 'escapes less-than <' {
        ConvertTo-CmdEchoEscaped 'a<b' | Should -Be 'a^<b'
    }

    It 'escapes greater-than >' {
        ConvertTo-CmdEchoEscaped 'a>b' | Should -Be 'a^>b'
    }

    It 'escapes bang !' {
        ConvertTo-CmdEchoEscaped 'a!b' | Should -Be 'a^!b'
    }

    It 'escapes percent %' {
        ConvertTo-CmdEchoEscaped 'a%b' | Should -Be 'a%%b'
    }

    It 'characterization: full metachar mix in replacement order' {
        # Replacement order: ^ & | < > ! %  (caret first so ^^ is not re-escaped)
        ConvertTo-CmdEchoEscaped 'a^b&c|d<e>f!g%h' | Should -Be 'a^^b^&c^|d^<e^>f^!g%%h'
    }
}
