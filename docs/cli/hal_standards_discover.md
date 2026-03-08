## hal standards discover

Discover and document standards from your codebase

### Synopsis

Interactively discover tribal knowledge and coding patterns from your codebase
and document them as standards.

This command guides you to use your AI agent's interactive mode to run the
discover-standards skill, which walks through your codebase area by area,
identifies patterns, and creates standard files in .hal/standards/.

After running 'hal init', the discover-standards command is available in:
  Claude Code:  /hal/discover-standards
  Pi:           Load the discover skill from .hal/skills/

The discovery flow:
  1. Scans your codebase and identifies focus areas
  2. Presents findings for each area
  3. For each standard: asks why, drafts, confirms, writes
  4. Updates the index

```
hal standards discover [flags]
```

### Examples

```
  hal standards discover
```

### Options

```
  -h, --help   help for discover
```

### SEE ALSO

* [hal standards](hal_standards.md)	 - Manage project standards

