# Hal

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Release](https://img.shields.io/github/v/release/j-yw/hal)](https://github.com/j-yw/hal/releases)

Autonomous AI coding loop CLI. Feed it a PRD, and it implements each user story one iteration at a time using AI coding agents.

> "I'm sorry Dave, I'm afraid I can't do that... without a proper PRD."

## Features

- **PRD-driven development** — Generate, convert, and validate Product Requirements Documents
- **Autonomous execution** — Each iteration picks the next story, implements it, commits, and updates progress
- **Fresh context per iteration** — Every story gets a clean context window, no memory pollution
- **Pluggable engines** — Works with Claude Code, OpenAI Codex, or Pi
- **Project standards** — Codify patterns into standards that are injected into every agent iteration
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
  - [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI (default engine)
  - [Codex](https://github.com/openai/codex) CLI
  - [Pi](https://github.com/mariozechner/pi-coding-agent) CLI

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

1. **init** — Set up `.hal/` directory with config, templates, skills, and commands
2. **plan** — Generate a PRD through clarifying questions
3. **convert** — Transform markdown PRD to structured JSON
4. **validate** — Check stories against quality rules
5. **run** — Loop through stories: pick next, implement, commit, repeat

### Compound Pipeline (Fully Automated)

```
hal review → hal auto → hal review → hal auto → ...
```

The compound pipeline creates a continuous development cycle:

1. **`hal review`** — Analyzes completed work and generates a report with recommendations for next steps. Saves to `.hal/reports/` and updates `AGENTS.md` with discovered patterns.

2. **`hal auto`** — Reads the latest report, identifies the priority item, and runs the full pipeline:
   - **Analyze** → **Branch** → **PRD** → **Explode** → **Loop** → **PR**

3. **Repeat** — After the PR merges, run `hal review` again to generate the next report.

**Getting started:** Run the manual workflow first (`hal plan` → `hal run`), then `hal review` to generate your first report. Or place a report directly in `.hal/reports/`.

State is saved after each step — use `hal auto --resume` to continue from interruptions.

## Commands

### Core Commands

| Command | Description |
|---------|-------------|
| `hal init` | Initialize `.hal/` directory with config, skills, and commands |
| `hal plan [description]` | Generate PRD (opens editor if no args) |
| `hal convert <prd.md>` | Convert markdown PRD to JSON |
| `hal validate [prd.json]` | Validate PRD against quality rules |
| `hal run [iterations]` | Execute stories autonomously (default: 10) |

### Compound Pipeline

| Command | Description |
|---------|-------------|
| `hal review` | Generate report → `.hal/reports/`, update AGENTS.md |
| `hal auto` | Run full pipeline using latest report |
| `hal analyze [report]` | Analyze a report to find priority item |
| `hal explode <prd.md>` | Break PRD into 8-15 granular tasks |

### Standards

| Command | Description |
|---------|-------------|
| `hal standards list` | List configured standards with index |
| `hal standards discover` | Guide for discovering standards interactively |

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
| `hal cleanup` | Remove orphaned legacy files (supports `--dry-run`) |
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
hal run -e pi        # Use Pi engine
```

Each iteration:
1. Reads `prd.json` and `progress.txt`
2. Loads project standards from `.hal/standards/` and injects them into the prompt
3. Picks highest-priority incomplete story
4. Spawns fresh engine instance
5. Implements the story
6. Commits changes
7. Updates `prd.json` (marks story complete)
8. Appends learnings to `progress.txt`

## Project Standards

Standards are concise, codebase-specific rules stored in `.hal/standards/` as markdown files. They are automatically injected into the agent prompt on every `hal run` iteration, ensuring consistent code quality and pattern adherence across all AI-driven work.

### How Standards Work

1. **`hal init`** creates `.hal/standards/` and installs discovery commands for all engines
2. Standards are `.md` files organized by domain (e.g., `config/`, `engine/`, `testing/`)
3. On every `hal run`, all `.md` files are loaded, concatenated, and injected into the `{{STANDARDS}}` placeholder in `prompt.md`
4. The agent sees them as "## Project Standards — You MUST follow these..."

### Discovering Standards

Standards discovery is interactive — it scans your codebase, identifies patterns, and walks through each one with you:

```bash
# See what's available
hal standards list

# Get instructions for your engine
hal standards discover
```

The discovery commands are installed for all engines during `hal init`:

| Engine | Command |
|--------|---------|
| Claude Code | `/hal/discover-standards` |
| Pi | `/hal/discover-standards` |
| Codex | Ask agent to read `.hal/commands/discover-standards.md` |

### Example Standard

```markdown
# Init Idempotency

`hal init` is safe to run repeatedly. It never destroys existing state.

## Rules

- **Directories**: Use `os.MkdirAll` — idempotent by design
- **Default files**: Only write if file doesn't exist (`os.Stat` check first)
- **Skills**: Reinstalled every init (embedded files overwrite installed copies)
- **Template migrations**: Run every init via `migrateTemplates` (idempotent patches)

## Never Overwrite User Files

User customizations to `config.yaml`, `prompt.md`, and `progress.txt` are sacred.
```

### Standards Index

An optional `index.yml` catalogs all standards with descriptions:

```yaml
config:
  init-idempotency:
    description: hal init never overwrites user files; uses MkdirAll and stat-before-write
  template-constants:
    description: All .hal/ paths defined in internal/template/template.go; never hardcode
engine:
  process-isolation:
    description: Setsid + process group kill for TTY detachment and orphan prevention
```

### Committing Standards

Standards and commands in `.hal/` are committed to git (not ignored), while runtime state (`config.yaml`, `prd.json`, `progress.txt`) stays ignored. This means your team shares the same standards and discovery commands across all clones.

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
├── config.yaml             # Engine, retries, auto settings (gitignored)
├── prompt.md               # Agent instructions (gitignored, customizable)
├── progress.txt            # Append-only progress log (gitignored)
├── prd.json                # Current PRD (gitignored)
├── archive/                # Archived feature states
├── reports/                # Analysis reports for auto mode
├── skills/                 # Installed skills (auto-generated)
│   ├── prd/                # PRD generation
│   ├── hal/                # PRD-to-JSON conversion
│   ├── explode/            # Task breakdown
│   ├── autospec/           # Non-interactive PRD generation
│   └── review/             # Work review and patterns
├── standards/              # Project standards (committed to git)
│   ├── index.yml           # Standards catalog
│   ├── config/             # Config-related standards
│   ├── engine/             # Engine-related standards
│   ├── state/              # State management standards
│   └── testing/            # Testing standards
└── commands/               # Agent commands (committed to git)
    ├── discover-standards.md
    ├── index-standards.md
    └── inject-standards.md
```

Engine-specific symlinks are created during `hal init`:
- `.claude/commands/hal` → `.hal/commands/`
- `.claude/skills/*` → `.hal/skills/*`
- `.pi/commands/hal` → `.hal/commands/`
- `.pi/skills/*` → `.hal/skills/*`
- `~/.codex/commands/hal` → `.hal/commands/` (absolute)
- `~/.codex/skills/*` → `.hal/skills/*` (absolute)

## Configuration

Edit `.hal/config.yaml`:

```yaml
engine: claude              # or codex, pi
maxIterations: 10
retryDelay: 30s
maxRetries: 3

auto:
  reportsDir: .hal/reports
  branchPrefix: compound/
  maxIterations: 25

engines:
  pi:
    model: anthropic/claude-sonnet-4-20250514
    provider: openrouter
```

## Engines

Hal supports multiple AI coding agents:

| Engine | CLI Command | Install |
|--------|-------------|---------|
| Claude (default) | `claude` | [Claude Code docs](https://docs.anthropic.com/en/docs/claude-code) |
| Codex | `codex` | [Codex repo](https://github.com/openai/codex) |
| Pi | `pi` | [Pi repo](https://github.com/mariozechner/pi-coding-agent) |

Switch engines with `-e`:

```bash
hal run -e codex
hal run -e pi
```

## Development

```bash
make build       # Build binary with version metadata
make install     # Install to ~/.local/bin
make test        # Run tests
make vet         # Run go vet
make fmt         # Format code
make lint        # Run golangci-lint (if installed)
```

## Releases

Hal release tags are standardized to **`vX.Y.Z`** (for example, `v0.1.7`).

```bash
# one-time per clone: ensure git-flow tags include "v" prefix
git config gitflow.prefix.versiontag v

# create and finish a release branch
git flow release start 0.1.7
git flow release finish -p 0.1.7
```

Pushing a `v*` tag triggers `.github/workflows/release.yml`, which runs tests and publishes artifacts via GoReleaser.

## License

[MIT](LICENSE)

## Links

- [GitHub Repository](https://github.com/j-yw/hal)
- [Releases](https://github.com/j-yw/hal/releases)
- [Homebrew Tap](https://github.com/j-yw/homebrew-tap)
