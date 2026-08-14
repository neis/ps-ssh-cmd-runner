# QA image for the ps-ssh-cmd-runner collector: PowerShell 7 + PSScriptAnalyzer + Pester.
# Used ONLY for containerized lint/test. The production collector runs on Windows
# PowerShell 5.1; the compatibility rules in PSScriptAnalyzerSettings.psd1 enforce
# 5.1 compatibility from this 7.x container.
FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04

SHELL ["pwsh", "-NoProfile", "-Command"]

# Pin module versions for reproducible lint/test.
RUN Set-PSRepository -Name PSGallery -InstallationPolicy Trusted; \
    Install-Module -Name PSScriptAnalyzer -RequiredVersion 1.22.0 -Scope AllUsers -Force; \
    Install-Module -Name Pester -RequiredVersion 5.6.1 -Scope AllUsers -Force

# Fail the build early if either module did not land.
RUN if (-not (Get-Module -ListAvailable PSScriptAnalyzer)) { throw 'PSScriptAnalyzer missing' }; \
    if (-not (Get-Module -ListAvailable Pester)) { throw 'Pester missing' }
