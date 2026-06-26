# Hal

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Hal is a CLI for PRD-driven AI software work. It can plan a feature, convert the PRD into machine-readable runtime state, run isolated agent iterations, review the resulting branch, push through CI, and archive completed feature state.

Hal is designed for both humans and supervising agents:

- Humans get a small set of direct CLI workflows.
- Agents get deterministic status, doctor, continue, review, factory, and JSON contract surfaces.
- Each implementation pass runs with fresh context and explicit repository state.

> "I'm sorry Dave, I'm afraid I can't do that... without a proper PRD."

## What Hal Does

- Generates markdown or JSON PRDs from feature briefs.
- Converts markdown PRDs into canonical `.hal/prd.json` runtime state.
- Runs one story or task at a time through Codex, Claude Code, or pi.
- Tracks progress in `.hal/progress.txt` and marks completed items in `.hal/prd.json`.
- Runs review/fix loops against a base branch.
- Runs CI push/status/fix/merge workflows.
- Supports remote sandbox execution for isolated factory runs.
- Stores durable factory run, queue, log, artifact, and handoff records.
- Exposes stable JSON contracts for automation.

## Installation

### Homebrew

```bash
brew tap j-yw/tap
brew install --cask hal
```

### From Source

```bash
git clone https://github.com/ReScienceLab/hal.git
cd hal
make install
```

`make install` builds `hal` and installs it to `~/.local/bin/hal`.

## Requirements

- Go 1.25.7 or newer when building from source.
- Git.
- At least one supported coding engine:
  - Codex CLI, selected by default.
  - Claude Code CLI.
  - pi CLI.

For sandbox workflows, run `hal sandbox setup` and provide the provider credentials and environment values requested for Daytona, Hetzner, DigitalOcean, or AWS Lightsail.

## First Run

```bash
hal init
hal doctor
hal status
```

`hal init` creates `.hal/`, installs Hal skills and command prompts, and refreshes engine links. `hal doctor` checks whether the current repository is ready to run Hal.

If doctor reports safe remediations:

```bash
hal repair
hal doctor
```

## Core Workflows

### Manual PRD Loop

Use this when you want to inspect each stage.

```bash
hal plan "add user authentication"
hal convert
hal validate
hal run --base develop
hal review --base develop
hal ci push
hal ci status --wait
```

Flow:

1. `hal plan` creates `.hal/prd-*.md`.
2. `hal convert` writes `.hal/prd.json`.
3. `hal validate` checks PRD quality.
4. `hal run` implements incomplete stories.
5. `hal review` runs branch-vs-base review/fix cycles.
6. `hal ci` pushes, checks, fixes, or merges the PR.

### Auto Pipeline

Use this when you want Hal to run the full deterministic pipeline.

```bash
hal auto .hal/prd-feature.md --base develop
```

When no PRD path or report is provided, `hal auto` uses configured source discovery:

1. `auto.sourcePriority=report_first` by default: latest report, then newest `.hal/prd-*.md`.
2. `auto.sourcePriority=markdown_first`: newest `.hal/prd-*.md`, then latest report.

The pipeline order is:

```text
analyze -> spec -> branch -> convert -> validate -> run -> review -> ci -> report -> archive
```

Useful controls:

```bash
hal auto --dry-run
hal auto --resume
hal auto --mode fast
hal auto --mode balanced
hal auto --mode strict
hal auto --no-review
hal auto --no-ci
hal auto --review-streak 2 --review-max 10
hal auto --json
```

### Report and Review

`hal report` analyzes completed work, writes a report under `.hal/reports/`, and can update `AGENTS.md` with discovered project patterns.

```bash
hal report
```

`hal review` is the branch review/fix loop. Use it before merging substantial work.

```bash
hal review --base develop
hal review --base develop --iterations 3 -e codex
```

## Factory Workflows

Factory commands wrap Hal runs in durable records that are easier for supervising agents to inspect, resume, or hand off.

Factory state is stored in Hal's global config directory, separate from the current repository `.hal/` runtime state.

### Run Immediately

Run locally:

```bash
hal factory run .hal/prd-feature.md --base develop --json
```

Run from an analysis report:

```bash
hal factory run --report .hal/reports/report.md --base develop --json
```

Run in a managed sandbox:

```bash
hal factory run .hal/prd-feature.md --sandbox --base develop --json
```

Sandbox mode requires `--base` so the remote workspace can check out the correct integration base deterministically.

### Queue Work

Create queued work without immediately running it:

```bash
hal factory trigger --repo . --prd .hal/prd-feature.md --base develop --json
hal factory queue list --json
```

Process at most one queued item:

```bash
hal factory queue work --json
```

Queue entries can run locally or in a sandbox:

```bash
hal factory trigger --repo . --prd .hal/prd-feature.md --executor sandbox --base develop --json
```

### Inspect Runs

```bash
hal factory list --json
hal factory status <run-id> --json
hal factory logs <run-id>
hal factory artifacts <run-id>
hal factory open <run-id>
```

`hal factory open` prints handoff guidance. With `--exec`, it executes only the generated safe Hal inspection or resume command.

## Sandbox Workflows

Sandboxes provide isolated remote workspaces for factory execution or manual inspection.

```bash
hal sandbox setup
hal sandbox create --name factory-smoke
hal sandbox list
hal sandbox status factory-smoke
hal sandbox ssh factory-smoke
hal sandbox ssh factory-smoke -- hal version
hal sandbox stop factory-smoke
hal sandbox delete factory-smoke
```

`hal sandbox setup` writes global sandbox config under:

1. `$HAL_CONFIG_HOME`
2. `$XDG_CONFIG_HOME/hal`
3. `~/.config/hal`

Human sandbox output redacts public cloud and Tailscale addresses by default. Use `--show-addresses` only when raw addresses are intentionally needed.

### Sandbox Auth

Sync local Codex and pi subscription-login files into a running sandbox:

```bash
hal sandbox auth sync factory-smoke
```

Include known Claude Code auth/settings files when needed:

```bash
hal sandbox auth sync --include-claude factory-smoke
```

This does not copy GitHub CLI credentials, caches, logs, sessions, or entire auth directories. GitHub authentication for sandbox work is handled separately through sandbox token setup and Git credential helpers.

## Verification

`hal verify` runs configured project checks from `.hal/config.yaml`.

```yaml
verify:
  checks:
    - id: test
      name: Go tests
      command: go test ./...
      timeoutSeconds: 120
    - id: lint
      name: Lint
      command: golangci-lint run ./...
      required: false
```

Run checks:

```bash
hal verify
hal verify --json
```

Required checks fail the verification gate when they fail, time out, or are missing. Optional checks produce warnings.

## Health, Links, and Status

```bash
hal status
hal status --json
hal doctor
hal doctor --json
hal continue
hal continue --json
hal links status
hal links refresh
hal links clean
```

- `hal status` classifies the current workflow state.
- `hal doctor` checks readiness and reports safe remediations.
- `hal continue` combines status and doctor to suggest the next command.
- `hal links` manages engine skill links for Claude Code, pi, and Codex.

## PRD and State Files

Runtime files live under `.hal/`:

```text
.hal/
  config.yaml       local Hal configuration
  prd.json          canonical runtime PRD
  progress.txt      append-only run progress
  prompt.md         agent prompt template
  reports/          report output for auto/report workflows
  archive/          archived feature state
  skills/           installed Hal skills
  commands/         installed agent command prompts
```

Important rules:

- `progress.txt` is the single progress log for manual and auto workflows.
- `prd.json` is the active runtime PRD consumed by validate, run, review, CI, report, and archive steps.
- `hal convert --archive` archives existing feature state before writing canonical `.hal/prd.json`.
- `hal convert --force` bypasses the branch mismatch guard without archiving.
- `hal cleanup --dry-run` previews orphaned legacy file cleanup.

## Configuration

`.hal/config.yaml` is project-local. `hal init` preserves existing config files.

Common settings:

```yaml
engine: codex
maxIterations: 10
retryDelay: 30s
maxRetries: 3

auto:
  reportsDir: .hal/reports
  branchPrefix: compound/
  sourcePriority: report_first   # report_first | markdown_first
  convertMode: auto              # auto | standard | granular
  maxIterations: 25
  mode: balanced                 # fast | balanced | strict
  ciEnabled: true
  reviewEnabled: true
  reviewCleanStreak: 1
  reviewMaxIterations: 10

engines:
  codex:
    timeout: 30m
  claude:
    timeout: 30m
  pi:
    timeout: 30m

factory:
  policy:
    sandboxRequired: false
    allowedEngines: [codex, claude, pi]
    maxRunAttempts: 0
    maxReviewFixAttempts: 0
    maxCiFixAttempts: 0
    verificationRequired: false
    prCreationAllowed: true
    mergeAllowed: true
    cleanupBehavior: preserve    # preserve | on_success | always
```

Engine resolution order:

1. Explicit `--engine`.
2. Top-level `engine` in `.hal/config.yaml`.
3. `codex`.

Sandbox provider credentials are managed by `hal sandbox setup` in global sandbox config, not by committing secrets to the repository.

## Machine Contracts

Use JSON contracts when another tool or agent needs stable output.

Primary contracts:

- [`auto-v2`](docs/contracts/auto-v2.md): `hal auto --json`
- [`status-v1`](docs/contracts/status-v1.md): `hal status --json`
- [`doctor-v1`](docs/contracts/doctor-v1.md): `hal doctor --json`
- [`continue-v1`](docs/contracts/continue-v1.md): `hal continue --json`
- [`plan-v1`](docs/contracts/plan-v1.md): `hal plan --json`
- [`verify-v1`](docs/contracts/verify-v1.md): `hal verify --json`
- [`sandbox-list-v1`](docs/contracts/sandbox-list-v1.md): `hal sandbox list --json`
- [`ci-push-v1`](docs/contracts/ci-push-v1.md): `hal ci push --json`
- [`ci-status-v1`](docs/contracts/ci-status-v1.md): `hal ci status --json`
- [`ci-fix-v1`](docs/contracts/ci-fix-v1.md): `hal ci fix --json`
- [`ci-merge-v1`](docs/contracts/ci-merge-v1.md): `hal ci merge --json`
- [`factory-run-v1`](docs/contracts/factory-run-v1.md): `hal factory run --json`
- [`factory-list-v1`](docs/contracts/factory-list-v1.md): `hal factory list --json`
- [`factory-status-v1`](docs/contracts/factory-status-v1.md): `hal factory status --json`
- [`factory-trigger-v1`](docs/contracts/factory-trigger-v1.md): `hal factory trigger --json`
- [`factory-queue-add-v1`](docs/contracts/factory-queue-add-v1.md): `hal factory queue add --json`
- [`factory-queue-list-v1`](docs/contracts/factory-queue-list-v1.md): `hal factory queue list --json`
- [`factory-queue-work-v1`](docs/contracts/factory-queue-work-v1.md): `hal factory queue work --json`
- [`factory-logs-v1`](docs/contracts/factory-logs-v1.md): `hal factory logs <run-id> --json`
- [`factory-artifacts-v1`](docs/contracts/factory-artifacts-v1.md): `hal factory artifacts <run-id> --json`
- [`factory-open-v1`](docs/contracts/factory-open-v1.md): `hal factory open <run-id> --json`

Example payloads live in [`docs/contracts/examples/`](docs/contracts/examples/).

## CLI Reference

Generated command documentation lives in [`docs/cli/`](docs/cli/), starting at [`docs/cli/hal.md`](docs/cli/hal.md).

Regenerate and check docs:

```bash
make docs-cli
make docs-check
```

## Development

```bash
make build       # Build ./hal with version metadata
make install     # Install to ~/.local/bin/hal
make test        # Run unit tests
make vet         # Run go vet
make fmt         # Format Go code
make lint        # Run golangci-lint when installed
make docs-check  # Verify generated CLI docs are current
```

Integration tests that require the Codex CLI:

```bash
go test -tags=integration ./internal/engine/codex/...
```

## Releases

Release tags use `vX.Y.Z`. Pushing a `v*` tag triggers the release workflow and GoReleaser. The Homebrew cask is published through `j-yw/homebrew-tap`.

## License

[MIT](LICENSE)
