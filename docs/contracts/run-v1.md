# Run Contract v1

**Command:** `hal run --json`  
**Contract Version:** 1  
**Stability:** Stable for v1 fields listed below. New optional fields may be added; existing fields and enum values will not be renamed or removed.

## Required Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `contractVersion` | int | Always `1` |
| `ok` | bool | `true` when the run command completes without execution failure |
| `iterations` | int | Number of worker/loop iterations completed |
| `complete` | bool | `true` when all PRD stories/tasks are complete |
| `summary` | string | Human-readable summary |

## Optional Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `engine` | string | Engine used for the run |
| `storyId` | string | Requested story ID when `--story` is used |
| `lastStoryId` | string | Last story/task attempted |
| `dryRun` | bool | `true` when `--dry-run` is used |
| `duration` | string | Total wall-clock duration when available |
| `prd` | object | PRD progress snapshot |
| `parallel` | object | Parallel run aggregate telemetry when `--parallel N` is used |
| `nextAction` | object | Recommended next command |
| `error` | string | Human-readable failure summary when `ok=false` |

## PRD Object

When present:

| Field | Type | Description |
|-------|------|-------------|
| `path` | string | PRD path, usually `.hal/prd.json` |
| `completedStories` | int | Completed story/task count |
| `totalStories` | int | Total story/task count |

## Parallel Object

`parallel` appears only for `hal run --parallel N --json`. It contains safe
aggregate telemetry only:

| Field | Type | Description |
|-------|------|-------------|
| `requestedParallelism` | int | Requested maximum worker count |
| `runId` | string | Opaque local parallel run identifier |
| `batches` | int | Number of scheduler batches started |
| `started` | int | Worker tasks started |
| `integrated` | int | Worker results integrated serially |
| `failed` | int | Worker or integration failures |

The contract intentionally does not expose worker worktree paths, prompt text,
raw engine output, credentials, sandbox identifiers, or other local execution
details.

## Next Action Object

When present:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Stable action identifier |
| `command` | string | Suggested command |
| `description` | string | Human-readable guidance |

