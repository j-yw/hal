# Hal Product Specification

**Version:** 0.2.0
**Command:** `hal`
**License:** MIT

## Overview

Hal is a PRD-driven autonomous coding CLI. It plans, validates, executes, reviews, and archives development work with AI coding engines.

## Supported Engines

| Engine | CLI Command | Default |
|--------|-------------|---------|
| Codex | `codex` | ✅ |
| Claude Code | `claude` | |
| Pi | `pi` | |

Engine resolution order for targeted commands:
1. explicit `--engine` (when changed)
2. `.hal/config.yaml` top-level `engine`
3. fallback to `codex`

Explicit blank engine values are rejected (`--engine must not be empty`).

## Exit Codes

- `1`: generic/untyped failure
- `2`: validation/expected user errors
- `3`: `analyze --format json` with no reports found
- `4`: reserved generic expected non-zero
- `sandbox exec`: propagates exact remote non-zero exit code

## Primary Workflows

### Manual

```bash
hal init
hal plan "feature description"
hal convert
hal validate
hal run
```

### Compound

```bash
hal report
hal auto
hal review --base <base-branch> [iterations]
```

## Command Contracts

### `hal run [iterations]`

- Supports positional iterations and `--iterations/-i`
- Positional iterations and `-i` are mutually exclusive
- Iterations must be `> 0`
- Supports `--base/-b`

Examples:

```bash
hal run
hal run 5
hal run -i 5
hal run --base develop
```

### `hal review --base <base-branch> [iterations]`

Canonical syntax:

```bash
hal review --base develop
hal review --base origin/main 5
hal review --base develop --iterations 3 -e codex
```

Deprecated alias (warning emitted once):

```bash
hal review against develop 3
```

Conflicts:
- alias + `--base` => error
- alias + `--iterations/-i` => error
- canonical positional iterations + `--iterations/-i` => error

### `hal analyze [report-path]`

Canonical output flag:

```bash
hal analyze --format text
hal analyze --format json
```

Deprecated alias:

```bash
hal analyze --output json
```

Rules:
- `--format/-f` and `--output/-o` cannot be combined
- JSON mode writes JSON payload only to stdout
- warnings/deprecations/prose go to stderr
- no reports in JSON mode returns exit code `3` with empty stdout

### `hal archive`

- `hal archive` is an alias of `hal archive create`
- `--name/-n` valid only on `hal archive` or `hal archive create`
- `hal archive list` / `hal archive restore` reject `--name/-n`
- if name is missing and stdin is non-interactive, command fails with validation error

Examples:

```bash
hal archive -n my-feature
hal archive create -n my-feature
hal archive list
hal archive restore 2026-02-20-my-feature
```

### Sandbox Naming and Exec Passthrough

`--name/-n` is available on:
- `sandbox start/status/stop/delete/shell/exec`
- `sandbox snapshot create`

Exec usage:

```bash
hal sandbox exec [-n NAME] [--] <command...>
```

Examples:

```bash
hal sandbox exec -n my-box -- npm test
hal sandbox exec -- -n foo
```

### `hal explode <prd-path> --branch <name>`

- `--branch` sets output PRD `branchName`
- short `-b` is removed

## Deprecation Timeline

- deprecated in `v0.2.0`
- removed in `v1.0.0`

Applies to:
- `hal review against ...`
- `hal analyze --output ...`
- `hal config add-rule ...`
