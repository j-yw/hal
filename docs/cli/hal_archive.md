## hal archive

Archive current feature state

### Synopsis

Archive all feature state files from .hal/ into .hal/archive/<date>-<name>/.

Archives: prd.json, prd-*.md, progress.txt, auto-prd.json, auto-state.json,
and reports/* (non-hidden files).

Never touches: config.yaml, prompt.md, skills/, rules/.

Use --name to set the archive name, or you will be prompted interactively.

```
hal archive [flags]
```

### Examples

```
  hal archive
  hal archive --name checkout-flow
```

### Options

```
  -h, --help          help for archive
      --name string   Archive name (default: derived from branch name)
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents
* [hal archive list](hal_archive_list.md)	 - List all archives
* [hal archive restore](hal_archive_restore.md)	 - Restore an archived feature

