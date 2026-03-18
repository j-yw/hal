## hal init

Initialize .hal/ directory

### Synopsis

Initialize the .hal/ directory in the current project.

Repo-local setup (always safe):
  .hal/config.yaml      Configuration settings
  .hal/prompt.md         Agent instructions template
  .hal/progress.txt      Progress log
  .hal/archive/          Archived runs
  .hal/reports/          Analysis reports
  .hal/skills/           Hal-managed skills (prd, hal, autospec, etc.)
  .hal/commands/         Agent-invocable commands
  .hal/standards/        Project standards (committed)

Engine-local links (project-scoped):
  .claude/skills/        Symlinks to .hal/skills/ for Claude Code
  .pi/skills/            Symlinks to .hal/skills/ for Pi

Global links (affects ~/.codex — only for Codex users):
  ~/.codex/skills/       Symlinks for Codex skill discovery
  ~/.codex/commands/     Symlinks for Codex commands

Use 'hal doctor' to check environment health.
Use 'hal status' to check workflow state.

```
hal init [flags]
```

### Examples

```
  hal init
  hal init --json
  hal init --refresh-templates
  hal init --refresh-templates --dry-run
```

### Options

```
      --dry-run             Preview template refresh actions (only applies with --refresh-templates; other init steps still run)
  -h, --help                help for init
      --json                Output machine-readable JSON result
      --refresh-templates   Backup and overwrite core templates with latest embedded versions
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

