#!/usr/bin/env bash
# collector QA wrapper — Docker-only lint/test for the ps-ssh-cmd-runner collector.
#
# AGENT-READ-ONLY / USER-APPLIED. This script substitutes for the `docker run`
# permission ask-gate (it is allowlisted in Reperio's settings.local.json), so it
# must never be editable by an agent — Reperio denies Edit on the collector's
# tools/** and this file is placed/updated by a human. See Reperio CLAUDE.md
# "Collector / PowerShell workflow".
#
# Hardening: fixed image tag; repo mounted READ-ONLY; no network on lint/test;
# no docker socket; no privileges; the container command is a fixed literal chosen
# by the case statement below and is never taken from this script's arguments.
set -euo pipefail

IMAGE="collector-qa:local"

# Repo root is derived from THIS script's location — never from $PWD or $1.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DOCKERFILE="${SCRIPT_DIR}/qa.Dockerfile"

build() {
  # Build context is the tools/ dir only; the Dockerfile installs modules from PSGallery.
  docker build --pull -f "${DOCKERFILE}" -t "${IMAGE}" "${SCRIPT_DIR}"
}

# Run a FIXED pwsh command in the QA image. Repo is read-only, no network, no socket,
# no new privileges; writable state is an ephemeral tmpfs at /tmp (HOME points there).
run_pwsh() {
  docker run --rm \
    --network none \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=64m \
    --security-opt no-new-privileges \
    -e HOME=/tmp \
    -e POWERSHELL_TELEMETRY_OPTOUT=1 \
    -e POWERSHELL_UPDATECHECK=Off \
    -v "${REPO_DIR}:/repo:ro" \
    -w /repo \
    "${IMAGE}" \
    pwsh -NoProfile -NonInteractive -Command "$1"
}

lint() {
  # Fail fast on any non-ASCII byte in the collector sources. A stray em-dash /
  # smart-quote / arrow mis-decodes under Windows PowerShell 5.1 (ANSI) and breaks
  # the script at runtime — and is INVISIBLE to the pwsh-7 container below, so it
  # must be checked here on the raw bytes. Host-side grep (GNU grep -P).
  if grep -rlP '[^\x00-\x7F]' \
        "${REPO_DIR}/ssh-cmd-runner.ps1" "${REPO_DIR}/lib" "${REPO_DIR}/tests"; then
    echo "ERROR: non-ASCII byte(s) found in the files listed above — WinPS 5.1 mis-decodes these. Convert to ASCII." >&2
    exit 1
  fi

  # Report ALL PSScriptAnalyzer findings, but FAIL the gate only on Error-severity or
  # 5.1-compatibility findings — the whole reason to lint a Windows PowerShell 5.1 script
  # inside a 7.x container. Pre-existing style/quality Warnings on the legacy monolith are
  # advisory and must not fail the gate. (The command is still a fixed literal — no argument
  # from qa.sh reaches it; the container invocation in run_pwsh is unchanged.)
  run_pwsh '$s = Invoke-ScriptAnalyzer -Path /repo/ssh-cmd-runner.ps1 -Settings /repo/PSScriptAnalyzerSettings.psd1; $s | Format-Table -AutoSize | Out-Host; $g = @($s | Where-Object { $_.Severity.ToString() -eq "Error" -or $_.RuleName -like "PSUseCompatible*" }); Write-Host ("Advisory findings: {0}  Gating (Error or 5.1-incompatibility): {1}" -f $s.Count, $g.Count); if ($g.Count) { exit 1 }'
}

run_tests() {
  run_pwsh 'exit [int](Invoke-Pester -Path /repo/tests -Output Detailed -PassThru).FailedCount'
}

case "${1:-}" in
  build) build ;;
  lint)  lint ;;
  test)  run_tests ;;
  all)   build; lint; run_tests ;;
  *) echo "usage: qa.sh {build|lint|test|all}" >&2; exit 2 ;;
esac
