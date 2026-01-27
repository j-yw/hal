# GoRalph

Autonomous AI coding loop CLI. Feed it a PRD, and it implements each user story one iteration at a time using AI coding agents (Claude Code, Amp).

## How It Works

```
plan → convert → validate → run
```

1. **Plan** -- Generate a PRD interactively with clarifying questions
2. **Convert** -- Transform markdown PRD into structured JSON with right-sized stories
3. **Validate** -- Check stories against quality rules (size, ordering, criteria)
4. **Run** -- Loop through stories autonomously: pick next story, implement, commit, repeat

Each iteration gets a fresh context window. The AI reads `prd.json` and `progress.txt`, implements the highest-priority incomplete story, commits, and updates progress.

## Install

```bash
# Build from source
make build

# Or install to ~/.local/bin
make install
```

Requires Go 1.25+ and one of:
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI
- [Amp](https://amp.dev/) CLI

## Quick Start

```bash
# Initialize project
goralph init

# Generate PRD interactively
goralph plan "add user authentication"

# Or write markdown PRD manually, then convert
goralph convert tasks/prd-auth.md

# Validate the PRD
goralph validate

# Run the loop
goralph run
```

## Commands

| Command | Description |
|---------|-------------|
| `goralph init` | Initialize `.goralph/` directory with skills and templates |
| `goralph plan <description>` | Generate PRD through interactive Q&A |
| `goralph convert <markdown-prd>` | Convert markdown PRD to `.goralph/prd.json` |
| `goralph validate [prd-path]` | Validate PRD against quality rules |
| `goralph run` | Execute stories autonomously in a loop |
| `goralph config` | Show current configuration |
| `goralph version` | Show version info |

### Common Flags

- `-e, --engine` -- Engine to use: `claude` (default) or `amp`
- `--max` -- Max iterations for `run` (default: 10)
- `--json` -- Output PRD directly as JSON (for `plan`)
- `--validate` -- Also validate after conversion (for `convert`)

## PRD Format

GoRalph works with structured PRDs in JSON:

```json
{
  "project": "MyProject",
  "branchName": "ralph/feature-name",
  "description": "Feature description",
  "userStories": [
    {
      "id": "US-001",
      "title": "Add database schema",
      "description": "As a developer, I want the schema defined so that...",
      "acceptanceCriteria": [
        "Migration creates users table",
        "Typecheck passes"
      ],
      "priority": 1,
      "passes": false,
      "notes": ""
    }
  ]
}
```

### Story Rules

- Each story must be completable in **one iteration** (one context window)
- Stories ordered by dependency: schema -> backend -> frontend
- Every story must include "Typecheck passes" as acceptance criteria
- UI stories must include browser verification criteria
- Acceptance criteria must be verifiable, not vague

## Engine Architecture

GoRalph supports multiple AI engines through a pluggable interface:

- **Claude** -- Uses Claude Code CLI with `stream-json` output for live progress display
- **Amp** -- Uses Amp CLI (streaming format TBD)

Engines are registered at import time and selected via the `-e` flag.

## Project Structure

```
.goralph/                  # Project config (created by init)
  prompt.md                # Agent instructions (customizable)
  progress.txt             # Progress log across iterations
  prd.json                 # Current PRD
  skills/                  # Installed skills
```

```
cmd/                       # CLI commands
internal/
  engine/                  # Engine interface + display
    claude/                # Claude Code engine
    amp/                   # Amp engine
  loop/                    # Autonomous execution loop
  prd/                     # PRD generation, conversion, validation
  skills/                  # Embedded skill content
  template/                # Embedded templates
```

## Development

```bash
make build       # Build binary
make test        # Run tests
make vet         # Run go vet
make fmt         # Format code
make lint        # Run golangci-lint
```

## License

Copyright JYW Labs.
