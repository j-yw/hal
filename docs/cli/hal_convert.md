## hal convert

Convert markdown PRD to JSON

### Synopsis

Convert a markdown PRD file to prd.json format using the hal skill.

Without arguments, automatically finds prd-*.md files in .hal/ directory.
With a path argument, uses that file directly.

The conversion uses an AI engine to parse the markdown and generate
properly-sized user stories with verifiable acceptance criteria.

If existing feature state exists in .hal/, it will be
archived to .hal/archive/ before the new one is written.

Examples:
  hal convert                                  # Auto-discover PRD in .hal/
  hal convert .hal/prd-auth.md            # Explicit path
  hal convert .hal/prd.md -o custom.json  # Custom output path
  hal convert .hal/prd.md --validate      # Also validate after conversion
  hal convert .hal/prd.md -e claude       # Use Claude engine

```
hal convert [markdown-prd] [flags]
```

### Examples

```
  hal convert
  hal convert .hal/prd-auth.md --validate
  hal convert .hal/prd-auth.md --engine codex
```

### Options

```
  -e, --engine string   Engine to use (claude, codex, pi) (default "claude")
  -h, --help            help for convert
  -o, --output string   Output path (default: .hal/prd.json)
      --validate        Validate PRD after conversion
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

