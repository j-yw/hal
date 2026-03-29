# Auto Contract v2

**Command:** `hal auto --json`  
**Contract Version:** 2  
**Stability:** Stable for v2 fields listed below. New optional fields may be added; existing fields and enum values will not be renamed or removed.

## Required Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `contractVersion` | int | Always `2` |
| `ok` | bool | `true` when pipeline completes successfully |
| `entryMode` | string | Entry source: `markdown_path` or `report_discovery` |
| `resumed` | bool | `true` when run started with `--resume` |
| `steps` | object | Fixed step map for pipeline execution |
| `summary` | string | Human-readable summary |

## Optional Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `duration` | string | Total wall-clock duration (for completed/failed runs when available) |
| `error` | string | Top-level failure summary when `ok=false` |
| `nextAction` | object | Recommended next command |

## Step Map (Required Keys)

`steps` always contains these keys:

- `analyze`
- `spec`
- `branch`
- `convert`
- `validate`
- `run`
- `review`
- `report`
- `ci`
- `archive`

Each step object contains:

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | One of `completed`, `skipped`, `failed`, `pending` |

Additional telemetry fields are optional per step, including:

- `reason` (skip/failure reason key)
- `error` (human-readable error)
- `duration`
- `branch`
- `path`
- `tasks`
- `attempts`
- `iterations`
- `issuesFound`
- `fixesApplied`
- `prUrl`

## Next Action Object

When present:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Stable action identifier |
| `command` | string | Suggested command |
| `description` | string | Human-readable guidance |

## Example Artifacts

- `docs/contracts/examples/auto-v2-success.json`
- `docs/contracts/examples/auto-v2-failure.json`
