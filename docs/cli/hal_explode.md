## hal explode

Break a PRD into granular tasks for autonomous execution

### Synopsis

Explode a Product Requirements Document into 8-15 granular tasks.

Each task is sized to be completable in a single agent iteration with
boolean acceptance criteria suitable for autonomous verification.

The output is written to .hal/auto-prd.json in the userStories format,
and is used by the auto pipeline (not the manual run command).

Examples:
  hal explode .hal/prd-feature.md                    # Explode a PRD
  hal explode .hal/prd-feature.md --branch feature   # Set branch name
  hal explode .hal/prd-feature.md --engine claude     # Use specific engine

```
hal explode [prd-path] [flags]
```

### Examples

```
  hal explode .hal/prd-checkout.md
  hal explode .hal/prd-checkout.md --branch checkout
  hal explode .hal/prd-checkout.md --engine codex
```

### Options

```
  -b, --branch string   Branch name for output auto-prd.json
  -e, --engine string   Engine to use (claude, codex, pi) (default "claude")
  -h, --help            help for explode
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

