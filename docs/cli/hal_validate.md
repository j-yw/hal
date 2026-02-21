## hal validate

Validate a PRD using AI

### Synopsis

Validate a PRD file against the hal skill rules using an AI engine.

Checks:
  - Each story is completable in one iteration (small scope)
  - Stories are ordered by dependency (schema → backend → UI)
  - Every story has "Typecheck passes" as a criterion
  - UI stories have browser verification criteria
  - Acceptance criteria are verifiable (not vague)

Examples:
  hal validate                    # Validate .hal/prd.json
  hal validate path/to/prd.json   # Validate specific file
  hal validate -e claude          # Use Claude engine

```
hal validate [prd-path] [flags]
```

### Examples

```
  hal validate
  hal validate .hal/prd.json
  hal validate ./docs/prd.json --engine codex
```

### Options

```
  -e, --engine string   Engine to use (claude, codex, pi) (default "claude")
  -h, --help            help for validate
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

