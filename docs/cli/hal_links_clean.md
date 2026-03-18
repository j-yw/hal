## hal links clean

Remove deprecated and broken skill links

### Synopsis

Remove deprecated and broken skill links from engine directories.

Removes:
  - .claude/skills/ralph (deprecated alias)
  - .pi/skills/ralph (deprecated alias)
  - Any broken symlinks in engine skill directories

This is a targeted cleanup for link-specific debris.
Use 'hal cleanup' for broader .hal/ file cleanup.

```
hal links clean [flags]
```

### Examples

```
  hal links clean
```

### Options

```
  -h, --help   help for clean
```

### SEE ALSO

* [hal links](hal_links.md)	 - Manage engine skill links

