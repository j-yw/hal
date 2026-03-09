## hal init

Initialize .hal/ directory

### Synopsis

Initialize the .hal/ directory in the current project.

If an existing .goralph/ directory is detected and no .hal/ directory exists,
it will be automatically renamed to .hal/ to preserve your configuration.

Also adds .hal/ to .gitignore if not already present.

Creates:
  .hal/
    config.yaml    # Configuration settings
    prompt.md      # Agent instructions template
    progress.txt   # Progress log for learnings
    archive/       # Archived runs
    reports/       # Analysis reports for auto mode
    skills/        # PRD and Hal skills
      prd/         # PRD generation skill
      hal/         # PRD-to-JSON conversion skill

Also creates .claude/skills/ with symlinks to .hal/skills/ for Claude Code
skill discovery.

After init, create a prd.json with your user stories and run 'hal run'.
Or use 'hal plan' to interactively generate a PRD.

```
hal init [flags]
```

### Examples

```
  hal init
  hal init --refresh-templates
  hal init --refresh-templates --dry-run
```

### Options

```
      --dry-run             Preview template refresh actions (only applies with --refresh-templates; other init steps still run)
  -h, --help                help for init
      --refresh-templates   Backup and overwrite core templates with latest embedded versions
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

