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

Global links (active Codex home — only for Codex users):
  $CODEX_HOME/skills/    Symlinks for Codex skill discovery when CODEX_HOME is set
  $CODEX_HOME/commands/  Symlinks for Codex commands when CODEX_HOME is set
  ~/.codex/skills/       Default Codex skill links when CODEX_HOME is unset
  ~/.codex/commands/     Default Codex command links when CODEX_HOME is unset

Set CODEX_HOME before running 'hal init' to isolate Codex global links per
worktree. When CODEX_HOME is unset, Hal uses ~/.codex.

Side effects:
- Creates or preserves .hal/ files and directories.
- Updates .gitignore so .hal/ runtime state is ignored while standards and
  commands remain committable.
- Migrates legacy .goralph/ to .hal/ when present.
- Creates or refreshes project-local engine links under .claude/ and .pi/.
- May update Codex global links under the active Codex home for Codex users.

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
