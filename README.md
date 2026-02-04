# Hal

Autonomous AI coding loop CLI. Feed it a PRD, and it implements each user story one iteration at a time using AI coding agents (Claude Code or Codex).

## How It Works

### Manual Flow
```
plan → convert → validate → run
```

1. **Plan** -- Generate a PRD interactively with clarifying questions
2. **Convert** -- Transform markdown PRD into structured JSON with right-sized stories
3. **Validate** -- Check stories against quality rules (size, ordering, criteria)
4. **Run** -- Loop through stories autonomously: pick next story, implement, commit, repeat

### Compound Engineering Flow (Automated)
```
analyze → branch → prd → explode → loop → pr
```

The `auto` command runs the full pipeline unattended:

1. **Analyze** -- Find and analyze the latest report to identify priority item
2. **Branch** -- Create and checkout a new branch for the work
3. **PRD** -- Generate a PRD using the autospec skill (non-interactive)
4. **Explode** -- Break down the PRD into 8-15 granular tasks
5. **Loop** -- Execute the Hal task loop until all tasks pass
6. **PR** -- Push the branch and create a draft pull request

Each iteration gets a fresh context window. In the auto pipeline, the AI reads `auto-prd.json` and `auto-progress.txt`, implements the highest-priority incomplete story, commits, and updates progress.

## Install

```bash
# Build from source
make build

# Or install to ~/.local/bin
make install
```

Requires Go 1.25+ and one of:
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI (default engine)
- [Codex](https://github.com/openai/codex) CLI (alternative engine)

## Quick Start

```bash
# Initialize project
hal init

# === Manual workflow ===
# Generate PRD interactively
hal plan

# Or write markdown PRD manually, then convert
hal convert .hal/prd-auth.md

# Validate the PRD
hal validate

# Run the loop
hal run

# === Compound engineering (automated) ===
# Drop a report in .hal/reports/, then:
hal auto
```

## Planning a Feature

The `plan` command generates a PRD through a two-phase flow:
1. AI analyzes your description and generates clarifying questions
2. You answer the questions, then AI generates a complete PRD

### Editor mode (recommended)

Run `plan` with no arguments to open your `$EDITOR` with a template:

```bash
hal plan
```

This opens a markdown file where you can write a detailed feature spec. Write as much or as little as you want, save, and quit. Comment lines (`<!-- ... -->`) are stripped automatically.

The editor is resolved in order: `$EDITOR` > `$VISUAL` > `nano` > `vim` > `vi`.

### Inline mode

Pass the description directly as an argument:

```bash
hal plan "add user authentication with OAuth"
```

Good for quick, well-defined features. For anything nuanced, prefer the editor.

### Output formats

By default, the PRD is written as markdown to `.hal/prd-<feature-name>.md`. You can review and edit it before converting.

```bash
# Default: markdown output, then convert separately
hal plan "notifications"
hal convert .hal/prd-notifications.md

# Skip markdown step, output JSON directly for immediate use
hal plan "notifications" --format json
hal run
```

### Flags

| Flag | Description |
|------|-------------|
| `-f, --format` | Output format: `markdown` (default) or `json` |
| `-e, --engine` | Engine to use: `claude` (default) or `codex` |

## Converting a PRD

Convert a markdown PRD to the structured JSON format Hal needs:

```bash
hal convert .hal/prd-auth.md
hal convert .hal/prd-auth.md -o custom-output.json
hal convert .hal/prd-auth.md --validate    # also validate after conversion
```

If a `prd.json` already exists for a different feature, it gets archived to `.hal/archive/` automatically.

## Validating a PRD

Check that stories are right-sized, properly ordered, and have verifiable criteria:

```bash
hal validate                       # validates .hal/prd.json
hal validate path/to/other.json    # validate a specific file
```

## Running the Loop

Execute stories autonomously. Each iteration picks the highest-priority incomplete story, implements it, commits, and updates progress:

```bash
hal run                       # run with defaults (10 iterations)
hal run 5                     # run 5 iterations
hal run 1 -s US-001           # run single specific story
hal run -e codex              # use Codex engine
hal run --dry-run             # show what would execute without running
```

## Compound Engineering Pipeline

The `auto` command provides full end-to-end automation. Place analysis reports in `.hal/reports/`, and Hal will find the latest one, identify the priority item, generate a PRD, break it into tasks, implement them, and open a PR.

```bash
hal auto                     # Run full pipeline with latest report
hal auto --report report.md  # Use specific report file
hal auto --dry-run           # Show what would happen without executing
hal auto --resume            # Continue from last saved state
hal auto --skip-pr           # Skip PR creation at the end
```

The pipeline saves state after each step to `.hal/pipeline-state.json`, allowing you to resume from interruptions.

### Individual Pipeline Commands

Each step of the pipeline can be run independently:

```bash
# Analyze reports to find priority item
hal analyze                           # Analyze latest report
hal analyze report.md                 # Analyze specific file
hal analyze --output json             # Output as JSON

# Break a PRD into granular tasks (auto pipeline)
hal explode .hal/prd-feature.md                  # Explode a PRD (writes .hal/auto-prd.json)
hal explode .hal/prd-feature.md --branch feature # Set branch name

# Review completed work
hal review                  # Review and generate report
hal review --skip-agents    # Skip AGENTS.md update
```

## All Commands

| Command | Description |
|---------|-------------|
| `hal init` | Initialize `.hal/` directory with skills and templates |
| `hal plan [description]` | Generate PRD (editor mode if no args) |
| `hal convert <markdown-prd>` | Convert markdown PRD to `.hal/prd.json` |
| `hal validate [prd-path]` | Validate PRD against quality rules |
| `hal run [iterations]` | Execute stories autonomously (default: 10 iterations) |
| `hal auto` | Run full compound engineering pipeline |
| `hal analyze [report]` | Analyze reports to identify priority item |
| `hal explode <prd-path>` | Break PRD into 8-15 granular tasks for the auto pipeline |
| `hal review` | Review completed work and generate a report |
| `hal config` | Show current configuration |
| `hal version` | Show version info |

## PRD Format

Hal works with structured PRDs in JSON:

```json
{
  "project": "MyProject",
  "branchName": "hal/feature-name",
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

Hal supports AI engines through a pluggable interface:

- **Claude** (default) -- Uses Claude Code CLI with `stream-json` output for live progress display
- **Codex** -- Uses OpenAI Codex CLI with JSONL output for live progress display

Engines are registered at import time and selected via the `-e` flag:

```bash
hal run -e claude    # default
hal run -e codex     # use Codex
```

## Project Structure

```
.hal/                  # Project config (created by init)
  config.yaml              # Configuration settings
  prompt.md                # Agent instructions (customizable)
  progress.txt             # Progress log across iterations
  prd.json                 # Current PRD
  archive/                 # Archived PRDs from previous features
  reports/                 # Analysis reports for auto mode
  skills/                  # Installed skills
    prd/                   # PRD generation skill
    hal/                   # PRD-to-JSON conversion skill
    autospec/              # Non-interactive PRD generation
    explode/               # Task breakdown skill
```

```
cmd/                       # CLI commands
internal/
  compound/                # Compound engineering pipeline
  engine/                  # Engine interface + display
    claude/                # Claude Code engine
    codex/                 # OpenAI Codex engine
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
