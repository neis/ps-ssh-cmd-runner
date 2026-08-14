@{
    # PSScriptAnalyzer runs its built-in rule set at Error/Warning severity, PLUS the
    # compatibility rules below. We lint inside a PowerShell 7 container, but the collector
    # runs in the field on Windows PowerShell 5.1 — the compatibility rules flag any syntax
    # or cmdlet that would not work on that target.
    IncludeDefaultRules = $true
    Severity            = @('Error', 'Warning')

    Rules = @{
        # Flag language syntax not available in Windows PowerShell 5.1.
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1')
        }

        # Flag cmdlets / parameters not available on Windows PowerShell 5.1 (Windows).
        # Profile string is the Windows Server 2019 + WinPS 5.1 profile bundled with
        # PSScriptAnalyzer; no network fetch is required at lint time.
        PSUseCompatibleCommands = @{
            Enable         = $true
            TargetProfiles = @(
                'win-8_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework'
            )
        }
    }
}
