# GoRalph Product Specification

**Version:** 0.1.0
**Command:** `goralph`
**License:** MIT

## Overview

GoRalph is an autonomous AI coding loop orchestration CLI that executes AI agents on development tasks until completion. It coordinates 7 AI coding engines to work through task lists (PRDs) automatically.

## Supported Engines

| Engine | CLI Command | Output Format |
|--------|-------------|---------------|
| Claude Code | `claude` | stream-json |
| OpenCode | `opencode` | JSON |
| Cursor Agent | `cursor` | text |
| Codex | `codex` | text |
| Qwen-Code | `qwen` | stream-json |
| Factory Droid | `droid` | text |
| GitHub Copilot | `github-copilot-cli` | text |

## CLI Structure

### Commands

```
goralph run <target>     Run tasks from file or inline
goralph init             Initialize .goralph/ config
goralph config           Show current configuration
goralph config add-rule  Add a rule to config
goralph version          Show version info
```

### Run Command

The primary command. Accepts a file path or inline task string.

```bash
# File sources (auto-detects format by extension)
goralph run tasks.md                    # Markdown PRD
goralph run tasks.yaml                  # YAML tasks

# Inline task
goralph run "add user authentication"

# GitHub issues as source
goralph run --github owner/repo -l "ai-task"

# With options
goralph run tasks.md -e opencode        # Different engine
goralph run tasks.md -j 3               # Parallel with 3 workers
goralph run tasks.md -n                 # Dry run
goralph run tasks.md -v                 # Verbose output
```

### Init Command

Initialize a new GoRalph project.

```bash
goralph init                            # Interactive setup
goralph init --defaults                 # Use defaults, no prompts
```

### Config Command

Manage configuration.

```bash
goralph config                          # Show current config
goralph config add-rule "Always write tests"
```

## Flags Reference

### Global Flags

| Short | Long | Description |
|-------|------|-------------|
| `-v` | `--verbose` | Verbose output |
| `-h` | `--help` | Help for command |

### Run Flags

#### Engine Selection

| Short | Long | Description | Default |
|-------|------|-------------|---------|
| `-e` | `--engine` | Engine to use | `claude` |
| `-m` | `--model` | Override default model | - |

Available engines: `claude`, `opencode`, `cursor`, `codex`, `qwen`, `droid`, `copilot`

#### Task Source

| Short | Long | Description |
|-------|------|-------------|
| | `--github` | GitHub repo (owner/repo) |
| `-l` | `--label` | Filter GitHub issues by label |

#### Execution Control

| Short | Long | Description | Default |
|-------|------|-------------|---------|
| `-n` | `--dry-run` | Show what would run | `false` |
| | `--max-iterations` | Max iterations per task | `0` (unlimited) |
| | `--max-retries` | Max retries on failure | `3` |
| | `--retry-delay` | Base retry delay | `5s` |
| | `--fast` | Skip tests and lint | `false` |
| | `--no-tests` | Skip tests only | `false` |
| | `--no-lint` | Skip lint only | `false` |

#### Parallel Execution

| Short | Long | Description | Default |
|-------|------|-------------|---------|
| `-j` | `--jobs` | Parallel workers (0=sequential) | `0` |
| | `--sandbox` | Use sandboxes instead of worktrees | `false` |

#### Git/Branching

| Short | Long | Description | Default |
|-------|------|-------------|---------|
| `-b` | `--branch` | Base branch | current |
| | `--branch-per-task` | Create branch per task | `false` |
| | `--create-pr` | Create PR after completion | `false` |
| | `--draft-pr` | Create as draft PR | `false` |
| | `--no-commit` | Skip auto-commit | `false` |
| | `--no-merge` | Skip auto-merge | `false` |

#### Browser Automation

| Long | Description | Default |
|------|-------------|---------|
| `--browser` | Enable agent-browser | `false` |
| `--no-browser` | Disable agent-browser | - |

## Configuration

### File: `.goralph/config.yaml`

```yaml
project:
  name: "my-project"
  language: "typescript"
  framework: "next.js"
  description: "Project description"

commands:
  test: "npm test"
  lint: "npm run lint"
  build: "npm run build"

rules:
  - "Use TypeScript strict mode"
  - "Write tests for all new features"

boundaries:
  never_touch:
    - ".env"
    - "node_modules/"

notifications:
  discord_webhook: "https://..."
  slack_webhook: "https://..."
  custom_webhook: "https://..."
```

## Task Formats

### Markdown PRD

```markdown
- [ ] Add login page
- [ ] Add logout button
- [x] Create user model (completed)
```

### Parallel Groups (Markdown)

```markdown
- [ ] [p1] Task A (parallel group 1)
- [ ] [p1] Task B (parallel group 1)
- [ ] [p2] Task C (runs after p1)
```

### YAML Tasks

```yaml
tasks:
  - title: "Add feature"
    completed: false
    parallel_group: 1
    description: "Optional details"
```

## Prompt Construction

GoRalph builds prompts with this structure:

1. **Project Context** — From config `project` section
2. **Rules** — "You MUST follow these"
3. **Boundaries** — "Do NOT modify these files"
4. **Agent Skills** — From `.opencode/skills`, `.claude/skills`, `.skills`
5. **Browser Instructions** — If enabled
6. **Task** — The actual task
7. **Instructions** — Numbered steps (implement, test, lint, commit)
8. **Final Notes** — Don't modify PRD, keep changes focused

## Retry Logic

- **Formula:** `delay = baseDelay * 2^(attempt-1) + jitter`
- **Max delay:** 60 seconds
- **Jitter:** 0-25% of delay

### Retryable Errors

- Rate limits (`429`, `rate limit`, `quota`)
- Network (`timeout`, `connection`, `ECONNRESET`)
- Server (`overloaded`)

## Task Marking

| Source | ID Format | Mark Complete |
|--------|-----------|---------------|
| Markdown | Line number | `[ ]` → `[x]` |
| Markdown-Folder | `file.md:line` | Update specific file |
| YAML | Task title | `completed: true` |
| GitHub | `number:title` | Close issue via API |

## Notifications

### Discord

```json
{"embeds": [{"title": "Session Completed", "color": 2278109}]}
```

### Slack

```json
{"text": "GoRalph session completed: 5/5 tasks succeeded"}
```

### Custom Webhook

```json
{
  "event": "session_complete",
  "status": "completed",
  "tasks_completed": 5,
  "tasks_failed": 0
}
```

## Success/Failure Criteria

### Task Success

- Engine returns `success: true`
- Exit code is 0
- No error patterns in output

### Task Failure

- Engine returns `success: false`
- Non-zero exit code
- Error detected (may retry if retryable)
- Max retries exceeded

### Retryable vs Non-Retryable

| Retryable | Non-Retryable |
|-----------|---------------|
| Rate limits | Syntax errors |
| Timeouts | Missing dependencies |
| Network errors | Permission denied |
| Server overload | Invalid configuration |

## Environment Variables

| Variable | Required For |
|----------|--------------|
| `GITHUB_TOKEN` | `--github` flag |

## Known Limitations

- No PRD JSON format (planned)
- No web dashboard (planned)
- No session persistence (planned)
- No cross-engine cost estimation (planned)
- Single repository only
- Local execution only
