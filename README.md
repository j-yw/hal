# GoRalph

Autonomous AI coding loop CLI. Feed it a PRD, and it implements each user story one iteration at a time using AI coding agents (Claude Code).

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

Requires Go 1.25+ and [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI.

## Quick Start

```bash
# Initialize project
goralph init

# Generate PRD interactively
goralph plan

# Or write markdown PRD manually, then convert
goralph convert tasks/prd-auth.md

# Validate the PRD
goralph validate

# Run the loop
goralph run
```

## Planning a Feature

The `plan` command generates a PRD through a two-phase flow:
1. AI analyzes your description and generates clarifying questions
2. You answer the questions, then AI generates a complete PRD

### Editor mode (recommended)

Run `plan` with no arguments to open your `$EDITOR` with a template:

```bash
goralph plan
```

This opens a markdown file where you can write a detailed feature spec. Write as much or as little as you want, save, and quit. Comment lines (`<!-- ... -->`) are stripped automatically.

The editor is resolved in order: `$EDITOR` > `$VISUAL` > `nano` > `vim` > `vi`.

### Inline mode

Pass the description directly as an argument:

```bash
goralph plan "add user authentication with OAuth"
```

Good for quick, well-defined features. For anything nuanced, prefer the editor.

### Output formats

By default, the PRD is written as markdown to `.goralph/prd-<feature-name>.md`. You can review and edit it before converting.

```bash
# Default: markdown output, then convert separately
goralph plan "notifications"
goralph convert .goralph/prd-notifications.md

# Skip markdown step, output JSON directly for immediate use
goralph plan "notifications" --format json
goralph run
```

### Flags

| Flag | Description |
|------|-------------|
| `-f, --format` | Output format: `markdown` (default) or `json` |
| `-e, --engine` | Engine to use: `claude` (default) |

## Converting a PRD

Convert a markdown PRD to the structured JSON format GoRalph needs:

```bash
goralph convert tasks/prd-auth.md
goralph convert tasks/prd-auth.md -o custom-output.json
goralph convert tasks/prd-auth.md --validate    # also validate after conversion
```

If a `prd.json` already exists for a different feature, it gets archived to `.goralph/archive/` automatically.

## Validating a PRD

Check that stories are right-sized, properly ordered, and have verifiable criteria:

```bash
goralph validate                       # validates .goralph/prd.json
goralph validate path/to/other.json    # validate a specific file
```

## Running the Loop

Execute stories autonomously. Each iteration picks the highest-priority incomplete story, implements it, commits, and updates progress:

```bash
goralph run
goralph run --limit 5             # limit to 5 iterations
goralph run -l 1 -s US-001        # run single specific story
goralph run --dry-run             # show what would execute without running
```

## All Commands

| Command | Description |
|---------|-------------|
| `goralph init` | Initialize `.goralph/` directory with skills and templates |
| `goralph plan [description]` | Generate PRD (editor mode if no args) |
| `goralph convert <markdown-prd>` | Convert markdown PRD to `.goralph/prd.json` |
| `goralph validate [prd-path]` | Validate PRD against quality rules |
| `goralph run` | Execute stories autonomously in a loop |
| `goralph config` | Show current configuration |
| `goralph version` | Show version info |

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

GoRalph supports AI engines through a pluggable interface:

- **Claude** -- Uses Claude Code CLI with `stream-json` output for live progress display

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
