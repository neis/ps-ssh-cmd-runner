#Requires -Modules Pester

# Smoke / contract checks for the collector. Deep unit tests are deferred until
# ssh-cmd-runner.ps1 is refactored into dot-sourceable functions (see Reperio's
# powershell-developer notes); these assert the script and its inputs are well-formed.

BeforeAll {
    $script:RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
}

Describe 'Collector smoke checks' {

    It 'ssh-cmd-runner.ps1 parses without syntax errors' {
        $scriptPath = Join-Path $RepoRoot 'ssh-cmd-runner.ps1'
        $tokens = $null
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile(
            $scriptPath, [ref]$tokens, [ref]$errors)
        $errors | Should -BeNullOrEmpty
    }

    It 'has at least one per-OS command file, each non-empty' {
        $cmdDir = Join-Path $RepoRoot 'commands'
        $files = Get-ChildItem -LiteralPath $cmdDir -Filter '*.txt' -File
        $files.Count | Should -BeGreaterThan 0
        foreach ($f in $files) {
            (Get-Content -LiteralPath $f.FullName -Raw).Trim() |
                Should -Not -BeNullOrEmpty -Because "$($f.Name) should contain commands"
        }
    }

    It 'the example config is valid JSON' {
        # Note: the filename contains [ ] (glob metacharacters) - must use -LiteralPath.
        $configPath = Join-Path $RepoRoot 'Examples/[example] config.json'
        { Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json } |
            Should -Not -Throw
    }
}
