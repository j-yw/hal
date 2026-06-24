## hal links

Manage engine skill links

### Synopsis

Inspect and manage skill links between .hal/skills/ and engine directories.

Hal creates symlinks from engine-specific directories to .hal/skills/ so
each AI engine can discover project skills. These links are:

  Project-local:
    .claude/skills/  → .hal/skills/   (Claude Code)
    .pi/skills/      → .hal/skills/   (Pi)

  Global (active Codex home):
    $CODEX_HOME/skills/  → .hal/skills/  (Codex, when CODEX_HOME is set)
    ~/.codex/skills/     → .hal/skills/  (Codex default)

Set CODEX_HOME per worktree to isolate Codex global skill and command links.
When CODEX_HOME is unset, Hal uses ~/.codex.

Side effects:
- refresh creates or replaces engine skill and command symlinks in .claude/,
  .pi/, and the active Codex home for Codex.
- clean removes deprecated or broken engine skill symlinks.

Use 'hal links status' to inspect link health.
Use 'hal links refresh' to recreate all links.

```
hal links [flags]
```

### Examples

```
  hal links status
  hal links status --json
  hal links refresh
  hal links refresh codex
```

### Options

```
  -h, --help   help for links
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents
* [hal links clean](hal_links_clean.md)	 - Remove deprecated and broken skill links
* [hal links refresh](hal_links_refresh.md)	 - Refresh skill links for engines
* [hal links status](hal_links_status.md)	 - Show link status for all engines

