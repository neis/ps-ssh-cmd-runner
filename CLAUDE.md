# CLAUDE.md — ps-ssh-cmd-runner (Reperio data collector)

This repository is the **field data collector** for Reperio (sibling repo at `../reperio`). It is
developed **through Reperio's Claude configuration**, which is the **single source of truth** for
all conventions, workflow, and agent roles that govern work here. When idioms conflict, Reperio wins.

- **Do not add divergent Claude configuration to this repo** — no `.claude/` directory, no competing
  directives. If collector-specific guidance is needed, it belongs in Reperio:
  `reperio/.claude/agents/powershell-developer.md` and the **"Collector / PowerShell workflow"**
  section of `reperio/CLAUDE.md`.
- **Owner agent**: `powershell-developer` (scope-locked to this repo).
- **Target runtime**: **Windows PowerShell 5.1** (`#Requires -Version 5.1`). Write 5.1-compatible code;
  the PSScriptAnalyzer compatibility rules in `PSScriptAnalyzerSettings.psd1` enforce this.
- **QA is Docker-only**: `tools/qa.sh build|lint|test` runs PSScriptAnalyzer + Pester inside a
  `mcr.microsoft.com/powershell` container (there is no host `pwsh`). **`tools/**` is an enforcement
  surface** — it is user-applied and must not be edited by an agent.
- **Command-set sync triangle**: `commands/*.txt` must stay reconciled with Reperio's parser
  (`COMMAND_MAP`) and Help docs (`platformCommands`) per the sync-triangle rules in Reperio's CLAUDE.md.

See `reperio/CLAUDE.md` for the authoritative process.
