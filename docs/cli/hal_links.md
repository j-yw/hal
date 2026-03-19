## hal links

Manage engine skill links

### Synopsis

Inspect and manage skill links between .hal/skills/ and engine directories.

Hal creates symlinks from engine-specific directories to .hal/skills/ so
each AI engine can discover project skills. These links are:

  Project-local:
    .claude/skills/  → .hal/skills/   (Claude Code)
    .pi/skills/      → .hal/skills/   (Pi)

  Global (single-active-repo):
    ~/.codex/skills/  → .hal/skills/  (Codex)

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

