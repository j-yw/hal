## hal plan

Generate a PRD interactively

### Synopsis

Generate a Product Requirements Document through an interactive flow.

The plan command supports human-friendly interactive planning and agent-safe
non-interactive input.

Human flow:
1. Analyzes your feature description and generates clarifying questions
2. Collects your answers and generates a complete PRD

Agent-safe flow:
- Use --input <path> to read a longer feature brief from a file.
- Use --input - to read from stdin.
- Use --no-questions to skip interactive clarification and place ambiguity in
  Open Questions.
- Use --json with --no-questions and explicit input for machine-readable output.

If no description is provided, your $EDITOR will open for you to write the spec
when stdin is interactive. Editor mode is never used with --json.

By default, the PRD is written as markdown to .hal/prd-[feature-name].md.
Use --format json to output directly to .hal/prd.json for immediate use with 'hal run'.

Examples:
  hal plan                                             # Opens editor for full spec
  hal plan "user authentication"                       # Interactive PRD generation
  hal plan "add dark mode" -f json                     # Output directly to prd.json
  hal plan --input .hal/input/feature.md               # Read a longer brief from file
  hal plan --input .hal/input/feature.md --no-questions --format json --json
  hal plan --input - --no-questions --format json --json < feature.md
  hal plan "notifications" -e claude                   # Use Claude engine

```
hal plan [feature-description] [flags]
```

### Examples

```
  hal plan
  hal plan "user authentication"
  hal plan "add dark mode" --format json
  hal plan --input .hal/input/feature.md
  hal plan --input .hal/input/feature.md --no-questions --format json --json
  hal plan --input - --no-questions --format json --json < feature.md
  hal plan "notifications" --engine codex
```

### Options

```
  -e, --engine string   Engine to use (claude, codex, pi) (default "codex")
  -f, --format string   Output format: markdown, json (default "markdown")
  -h, --help            help for plan
      --input string    Read feature description/spec from file; '-' means stdin
      --json            Output machine-readable JSON result
      --no-questions    Generate directly without interactive clarifying questions
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents

