#Requires -Version 5.1

# Unit tests for the v2 collection-summary pure helpers (task 0d) in
# lib/CollectorCore.ps1: the failure-category classifier and the v2 top-level
# document builder, plus the load-bearing plan_id round-trip (JSON input ->
# v2 summary).

BeforeAll {
    . (Join-Path $PSScriptRoot '../lib/CollectorCore.ps1')
}

Describe 'Get-FailureCategory - successful / partial runs have no category' {
    It 'returns $null for Success' {
        Get-FailureCategory -Status 'Success' | Should -Be $null
    }
    It 'returns $null for Warning (usable partial bundle)' {
        Get-FailureCategory -Status 'Warning' -ErrorText 'Commands timed out during processing: show foo' |
            Should -Be $null
    }
}

Describe 'Get-FailureCategory - failure mapping' {
    It 'classifies operator cancellation' {
        Get-FailureCategory -Status 'Cancelled' | Should -Be 'cancelled'
    }
    It 'classifies an auth failure from the AuthFailed flag' {
        Get-FailureCategory -Status 'Failed' -AuthFailed $true | Should -Be 'auth_failed'
    }
    It 'classifies an auth failure from the reason text' {
        Get-FailureCategory -Status 'Failed' -ErrorText 'Permission denied (publickey,password).' |
            Should -Be 'auth_failed'
    }
    It 'classifies a skipped (ping) device as unreachable_ping (SSH never attempted)' {
        Get-FailureCategory -Status 'Skipped' -ErrorText 'No ping response' | Should -Be 'unreachable_ping'
    }
    It 'classifies a refused connection (active RST) as connection_refused, NOT connect_timeout' {
        Get-FailureCategory -Status 'Failed' -ErrorText 'ssh: connect to host 10.0.0.1 port 22: Connection refused' |
            Should -Be 'connection_refused'
    }
    It 'classifies an SSH negotiation failure (legacy crypto)' {
        Get-FailureCategory -Status 'Failed' -ErrorText 'Unable to negotiate with 10.0.0.1: no matching key exchange method found.' |
            Should -Be 'ssh_negotiation_failed'
    }
    It 'classifies a host-key-type negotiation failure' {
        Get-FailureCategory -Status 'Failed' -ErrorText 'no matching host key type found. Their offer: ssh-rsa' |
            Should -Be 'ssh_negotiation_failed'
    }
    It 'classifies a device-side command timeout' {
        Get-FailureCategory -Status 'Failed' -ErrorText "Timed out waiting for device prompt after command 'show tech'." |
            Should -Be 'command_timeout'
    }
    It 'classifies a connect-level timeout (SSH attempted) as connect_timeout, NOT a command timeout' {
        Get-FailureCategory -Status 'Failed' -ErrorText 'ssh: connect to host 10.0.0.1 port 22: Connection timed out' |
            Should -Be 'connect_timeout'
    }
    It 'classifies "No route to host" (SSH attempted) as connect_timeout, NOT unreachable_ping' {
        Get-FailureCategory -Status 'Failed' -ErrorText 'ssh: connect to host 10.0.0.1 port 22: No route to host' |
            Should -Be 'connect_timeout'
    }
    It 'classifies a down host (SSH attempted) as connect_timeout' {
        Get-FailureCategory -Status 'Failed' -ErrorText 'ssh: connect to host 10.0.0.1 port 22: Host is down' |
            Should -Be 'connect_timeout'
    }
    It 'keeps a device-side command timeout as command_timeout (not reclassified to connect_timeout)' {
        Get-FailureCategory -Status 'Failed' -ErrorText 'Commands timed out during processing: show tech' |
            Should -Be 'command_timeout'
    }
    It 'returns $null for an unrecognized failure (free-text reason kept by caller)' {
        Get-FailureCategory -Status 'Failed' -ErrorText 'some novel device-specific error' | Should -Be $null
    }
    It 'prioritizes AuthFailed over other signals' {
        Get-FailureCategory -Status 'Failed' -AuthFailed $true -ErrorText 'Connection refused' |
            Should -Be 'auth_failed'
    }
}

Describe 'New-CollectionSummaryDocument' {
    It 'stamps schema_version 3 and echoes plan_id' {
        $doc = New-CollectionSummaryDocument -DevicesMap ([ordered]@{}) -Totals ([ordered]@{ total = 0 }) `
            -PlanId 'acme-001' -Generated '2026-08-17 12:00:00'
        $doc.schema_version | Should -Be 3
        $doc.plan_id        | Should -Be 'acme-001'
        $doc.generated      | Should -Be '2026-08-17 12:00:00'
    }
    It 'trims a padded plan_id' {
        (New-CollectionSummaryDocument -DevicesMap ([ordered]@{}) -Totals ([ordered]@{}) -PlanId '  p1  ').plan_id |
            Should -Be 'p1'
    }
    It 'sets plan_id to $null when absent/blank' {
        (New-CollectionSummaryDocument -DevicesMap ([ordered]@{}) -Totals ([ordered]@{}) -PlanId '   ').plan_id |
            Should -Be $null
    }
    It 'passes the device map and totals through unchanged' {
        $devs = [ordered]@{ '10.0.0.1' = [ordered]@{ status = 'Success' } }
        $doc = New-CollectionSummaryDocument -DevicesMap $devs -Totals ([ordered]@{ total = 1 }) -PlanId 'x'
        $doc.devices['10.0.0.1'].status | Should -Be 'Success'
        $doc.totals.total | Should -Be 1
    }
}

Describe 'plan_id round-trip - JSON input survives into the summary (load-bearing contract)' {
    It 'echoes the input plan plan_id at the summary top level' {
        $json = @'
{
  "schema_version": 1,
  "plan_id": "acme-refresh-2026-08-17-001",
  "devices": [ { "connect_ip": "10.1.1.1", "platform": "cisco-switch-iosxe", "profile": "full" } ]
}
'@
        # Parse the plan (task 0a), then build the summary (task 0d) exactly as the
        # collection loop does: the plan's plan_id must reach the summary top level.
        $plan = ConvertFrom-CollectionPlanJson -Json $json
        $plan.plan_id | Should -Be 'acme-refresh-2026-08-17-001'

        $doc = New-CollectionSummaryDocument -DevicesMap ([ordered]@{}) -Totals ([ordered]@{ total = 0 }) `
            -PlanId $plan.plan_id -Generated '2026-08-17 12:00:00'
        $doc.schema_version | Should -Be 3
        $doc.plan_id        | Should -Be 'acme-refresh-2026-08-17-001'
    }

    It 'yields a null summary plan_id when the input plan omits plan_id' {
        $plan = ConvertFrom-CollectionPlanJson -Json '{ "devices": [ { "connect_ip": "1.2.3.4" } ] }'
        $plan.plan_id | Should -Be $null
        (New-CollectionSummaryDocument -DevicesMap ([ordered]@{}) -Totals ([ordered]@{}) -PlanId ([string]$plan.plan_id)).plan_id |
            Should -Be $null
    }
}
