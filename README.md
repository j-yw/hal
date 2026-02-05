# Hal

Autonomous AI coding loop CLI. Feed it a PRD, and it implements each user story one iteration at a time using AI coding agents.

> "I'm sorry Dave, I'm afraid I can't do that... without a proper PRD."

## Features

- **PRD-driven development** — Generate, convert, and validate Product Requirements Documents
- **Autonomous execution** — Each iteration picks the next story, implements it, commits, and updates progress
- **Fresh context per iteration** — Every story gets a clean context window, no memory pollution
- **Pluggable engines** — Works with Claude Code or OpenAI Codex
- **Archive & restore** — Switch between features without losing state
- **Compound pipeline** — Full automation from analysis to pull request

## Installation

### Homebrew (macOS)

```bash
brew tap j-yw/tap
brew install --cask hal
```

### From Source

```bash
git clone https://github.com/j-yw/hal.git
cd hal
make install    # Installs to ~/.local/bin
```

### Requirements

- Go 1.22+ (for building from source)
- One of the following AI coding agents:
  - [Claude Code](https://claude.ai/code) CLI (default engine)
  - [Codex](https://github.com/openai/codex) CLI

## Quick Start

```bash
# Initialize project
hal init

# Generate a PRD interactively
hal plan "add user authentication"

# Convert markdown PRD to JSON
hal convert .hal/prd-user-authentication.md

# Validate the PRD
hal validate

# Run the autonomous loop
hal run
```

## How It Works

### Manual Workflow

```
hal init → hal plan → hal convert → hal validate → hal run
```

1. **init** — Set up `.hal/` directory with config, templates, and skills
2. **plan** — Generate a PRD through clarifying questions
3. **convert** — Transform markdown PRD to structured JSON
4. **validate** — Check stories against quality rules
5. **run** — Loop through stories: pick next, implement, commit, repeat

### Compound Pipeline (Fully Automated)

```
hal review → hal auto → hal review → hal auto → ...
```

The compound pipeline creates a continuous development cycle:

1. **`hal review`** — After completing work, generates a report analyzing what was done, what's left, and recommended next steps. Saves to `.hal/reports/`.

2. **`hal auto`** — Reads the latest report from `.hal/reports/`, identifies the priority item, and executes the full pipeline:
   - **Analyze** — Parse report to find highest-priority item
   - **Branch** — Create a feature branch
   - **PRD** — Generate a PRD non-interactively
   - **Explode** — Break into 8-15 granular tasks
   - **Loop** — Execute tasks autonomously
   - **PR** — Push and open a draft pull request

3. **Repeat** — After the PR is merged, run `hal review` again to generate a new report, then `hal auto` for the next item.

State is saved after each step — use `--resume` to continue from interruptions.

## Commands

### Core Commands

| Command | Description |
|---------|-------------|
| `hal init` | Initialize `.hal/` directory with config and skills |
| `hal plan [description]` | Generate PRD (opens editor if no args) |
| `hal convert <prd.md>` | Convert markdown PRD to JSON |
| `hal validate [prd.json]` | Validate PRD against quality rules |
| `hal run [iterations]` | Execute stories autonomously (default: 10) |

### Compound Pipeline

| Command | Description |
|---------|-------------|
| `hal review` | Generate report from completed work → `.hal/reports/` |
| `hal auto` | Run full pipeline using latest report |
| `hal analyze [report]` | Analyze a report to find priority item |
| `hal explode <prd.md>` | Break PRD into 8-15 granular tasks |

### Archive Management

| Command | Description |
|---------|-------------|
| `hal archive` | Archive current feature state |
| `hal archive list` | List all archived features |
| `hal archive restore <name>` | Restore an archived feature |

### Utilities

| Command | Description |
|---------|-------------|
| `hal config` | Show current configuration |
| `hal config add-rule <name>` | Create a custom rule template |
| `hal version` | Show version information |

## Planning a Feature

### Editor Mode (Recommended)

```bash
hal plan
```

Opens your editor with a template. Write your feature spec, save, and quit. The AI will ask clarifying questions, then generate a complete PRD.

Editor resolution: `$EDITOR` → `$VISUAL` → `nano` → `vim` → `vi`

### Inline Mode

```bash
hal plan "add dark mode toggle to settings"
```

Good for quick, well-defined features.

### Output Formats

```bash
hal plan "notifications"                    # Outputs .hal/prd-notifications.md
hal plan "notifications" --format json      # Outputs .hal/prd.json directly
```

## Running the Loop

```bash
hal run              # Run 10 iterations (default)
hal run 5            # Run 5 iterations
hal run 1 -s US-001  # Run a specific story
hal run --dry-run    # Preview without executing
hal run -e codex     # Use Codex engine
```

Each iteration:
1. Reads `prd.json` and `progress.txt`
2. Picks highest-priority incomplete story
3. Spawns fresh engine instance
4. Implements the story
5. Commits changes
6. Updates `prd.json` (marks story complete)
7. Appends learnings to `progress.txt`

## PRD Format

```json
{
  "project": "MyProject",
  "branchName": "hal/feature-name",
  "description": "Feature description",
  "userStories": [
    {
      "id": "US-001",
      "title": "Add database schema",
      "description": "As a developer, I want the schema defined...",
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

- Each story completable in **one iteration** (one context window)
- Ordered by dependency: schema → backend → frontend
- Every story includes "Typecheck passes" criterion
- UI stories include browser verification criteria
- Acceptance criteria are verifiable, not vague

## Project Structure

```
.hal/                       # Created by hal init
├── config.yaml             # Engine, retries, auto settings
├── prompt.md               # Agent instructions (customizable)
├── progress.txt            # Append-only progress log
├── prd.json                # Current PRD
├── archive/                # Archived feature states
├── reports/                # Analysis reports for auto mode
└── skills/                 # Installed skills
    ├── prd/                # PRD generation
    ├── hal/                # PRD-to-JSON conversion
    ├── explode/            # Task breakdown
    ├── autospec/           # Non-interactive PRD generation
    └── review/             # Work review and patterns
```

## Configuration

Edit `.hal/config.yaml`:

```yaml
engine: claude              # or codex
maxIterations: 10
retryDelay: 30s
maxRetries: 3

auto:
  reportsDir: .hal/reports
  branchPrefix: hal/
  maxIterations: 25
```

## Engine Architecture

Hal supports pluggable AI engines:

| Engine | CLI | Output Format |
|--------|-----|---------------|
| Claude (default) | `claude` | stream-json |
| Codex | `codex` | JSONL |

Select with the `-e` flag:

```bash
hal run -e claude    # default
hal run -e codex
```

## Archive & Restore

Switch between features without losing state:

```bash
# Archive current feature
hal archive --name auth-feature

# List archives
hal archive list

# Restore a previous feature
hal archive restore 2026-01-15-auth-feature
```

Archives are stored in `.hal/archive/YYYY-MM-DD-name/` and include:
- `prd.json`, `auto-prd.json`
- `progress.txt`, `auto-progress.txt`
- Reports and state files

## Development

```bash
make build       # Build binary with version metadata
make install     # Install to ~/.local/bin
make test        # Run tests
make vet         # Run go vet
make fmt         # Format code
make lint        # Run golangci-lint (if installed)
```

## License

[MIT](LICENSE)

## Links

- [GitHub Repository](https://github.com/j-yw/hal)
- [Releases](https://github.com/j-yw/hal/releases)
- [Homebrew Tap](https://github.com/j-yw/homebrew-tap)
