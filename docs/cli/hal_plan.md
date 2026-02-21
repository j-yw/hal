## hal plan

Generate a PRD interactively

### Synopsis

Generate a Product Requirements Document through an interactive flow.

The plan command uses a two-phase approach:
1. Analyzes your feature description and generates clarifying questions
2. Collects your answers and generates a complete PRD

If no description is provided, your $EDITOR will open for you to write the spec.

By default, the PRD is written as markdown to .hal/prd-[feature-name].md.
Use --format json to output directly to .hal/prd.json for immediate use with 'hal run'.

Examples:
  hal plan                            # Opens editor for full spec
  hal plan "user authentication"      # Interactive PRD generation
  hal plan "add dark mode" -f json    # Output directly to prd.json
  hal plan "notifications" -e claude  # Use Claude engine

```
hal plan [feature-description] [flags]
```

### Examples

```
  hal plan
  hal plan "user authentication"
  hal plan "add dark mode" --format json
  hal plan "notifications" --engine codex
```

### Options

```
  -e, --engine string   Engine to use (claude, codex, pi) (default "claude")
  -f, --format string   Output format: markdown, json (default "markdown")
  -h, --help            help for plan
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

